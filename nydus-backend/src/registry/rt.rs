//! The shared tokio runtime behind the registry backend, and how an embedding
//! process bounds and pins it.
//!
//! The synchronous [`BlobBackend`](crate::BlobBackend) trait bridges into the
//! async HTTP clients through one process-wide multi-thread runtime. Left to
//! tokio's defaults that runtime spawns one worker per CPU when it is built
//! and keeps them for the life of the process, and every runtime thread
//! inherits the network namespace of whichever thread happened to touch the
//! runtime first. Neither suits a VMM that embeds this crate: the backend
//! drives a handful of connections, so a couple of workers are plenty, and
//! the registry must be reached from the host namespace no matter which
//! thread issues the first read. [`configure_runtime`] lets the embedder fix
//! both before the runtime exists; standalone services get the bounded
//! defaults without calling it.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, OnceLock};
use std::time::Duration;

use tokio::runtime::{Builder, Runtime};
use tracing::{error, info};

/// Async worker threads when [`configure_runtime`] is not called or asks for
/// `0`. The workers only drive socket I/O for the connection pool; the
/// synchronous callers block on their own threads.
pub const DEFAULT_WORKER_THREADS: usize = 2;

/// Upper bound on the on-demand blocking pool when not configured. Only DNS
/// lookups (`getaddrinfo`) run there.
pub const DEFAULT_MAX_BLOCKING_THREADS: usize = 8;

/// Idle blocking threads are released after this long.
const BLOCKING_KEEP_ALIVE: Duration = Duration::from_secs(10);

const THREAD_NAME: &str = "nydus-backend";

/// How the shared backend runtime is built.
#[derive(Debug, Default)]
pub struct RuntimeOptions {
    /// Async worker threads, spawned when the runtime is first used and kept
    /// for the life of the process. `0` selects [`DEFAULT_WORKER_THREADS`].
    pub worker_threads: usize,
    /// Upper bound on the blocking pool. `0` selects
    /// [`DEFAULT_MAX_BLOCKING_THREADS`].
    pub max_blocking_threads: usize,
    /// Network namespace every runtime thread enters before it does any work,
    /// so sockets and DNS queries never depend on the caller's namespace.
    /// `None` keeps tokio's behaviour: threads inherit the namespace of the
    /// thread that first uses the runtime.
    pub netns: Option<OwnedFd>,
}

impl RuntimeOptions {
    fn worker_threads(&self) -> usize {
        match self.worker_threads {
            0 => DEFAULT_WORKER_THREADS,
            n => n,
        }
    }

    fn max_blocking_threads(&self) -> usize {
        match self.max_blocking_threads {
            0 => DEFAULT_MAX_BLOCKING_THREADS,
            n => n,
        }
    }

    /// `(st_dev, st_ino)` of the namespace inode, the identity `setns`
    /// compares by; `None` when no namespace is configured.
    fn netns_identity(&self) -> io::Result<Option<(u64, u64)>> {
        self.netns.as_ref().map(inode_identity).transpose()
    }

    fn same_as(&self, other: &RuntimeOptions) -> bool {
        self.worker_threads() == other.worker_threads()
            && self.max_blocking_threads() == other.max_blocking_threads()
            && match (self.netns_identity(), other.netns_identity()) {
                (Ok(a), Ok(b)) => a == b,
                _ => false,
            }
    }
}

static CONFIG: OnceLock<RuntimeOptions> = OnceLock::new();
static RUNTIME_BUILT: AtomicBool = AtomicBool::new(false);
static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    // Reading the config here seals it: a later configure_runtime() can no
    // longer take effect and reports that instead of silently doing nothing.
    let options = CONFIG.get_or_init(RuntimeOptions::default);
    RUNTIME_BUILT.store(true, Ordering::Release);
    // The builder never fails on a supported platform (the only errors are
    // thread spawn failures) and a backend without its runtime cannot serve
    // any read anyway.
    let runtime =
        build_runtime(options, THREAD_NAME).expect("failed to build backend tokio runtime");
    match options.netns_identity() {
        Ok(Some((dev, ino))) => info!(
            "nydus-backend runtime: {} worker thread(s), up to {} blocking, netns dev {dev} ino {ino}",
            options.worker_threads(),
            options.max_blocking_threads()
        ),
        _ => info!(
            "nydus-backend runtime: {} worker thread(s), up to {} blocking, inherited netns",
            options.worker_threads(),
            options.max_blocking_threads()
        ),
    }
    runtime
});

/// Access the shared backend runtime, building it on first use.
pub(super) fn runtime() -> &'static Runtime {
    &RUNTIME
}

/// Fix how the shared backend runtime is built. Must run before the first
/// backend read in the process; the first call wins, a repeated call with the
/// same options is a no-op, and a call with different options (or one made
/// after the runtime already exists) fails with
/// [`io::ErrorKind::AlreadyExists`] so the caller can log the misconfiguration
/// instead of assuming it took effect.
///
/// When `netns` is given, entering it is probed on a scratch thread first so
/// an unusable descriptor or missing privilege fails here rather than inside
/// the runtime's thread start hook.
pub fn configure_runtime(options: RuntimeOptions) -> io::Result<()> {
    if let Some(netns) = &options.netns {
        probe_netns(netns)?;
    }
    match CONFIG.set(options) {
        Ok(()) => Ok(()),
        Err(options) => {
            // set() only fails when a value is present.
            let current = CONFIG.get().expect("runtime options were just found set");
            if current.same_as(&options) {
                return Ok(());
            }
            let what = if RUNTIME_BUILT.load(Ordering::Acquire) {
                "already running"
            } else {
                "already configured"
            };
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "nydus-backend runtime {what} with {} worker(s), {} blocking, netns {:?}; requested {} worker(s), {} blocking, netns {:?}",
                    current.worker_threads(),
                    current.max_blocking_threads(),
                    current.netns_identity().ok().flatten(),
                    options.worker_threads(),
                    options.max_blocking_threads(),
                    options.netns_identity().ok().flatten(),
                ),
            ))
        }
    }
}

/// Build a runtime from `options`. Separate from the shared static so tests
/// can observe a runtime's threads without touching process-wide state.
fn build_runtime(options: &'static RuntimeOptions, thread_name: &str) -> io::Result<Runtime> {
    let mut builder = Builder::new_multi_thread();
    builder
        .thread_name(thread_name)
        .worker_threads(options.worker_threads())
        .max_blocking_threads(options.max_blocking_threads())
        .thread_keep_alive(BLOCKING_KEEP_ALIVE)
        .enable_all();
    if let Some(netns) = &options.netns {
        let fd = netns.as_raw_fd();
        builder.on_thread_start(move || {
            if let Err(err) = enter_netns(fd) {
                error!("nydus-backend runtime thread cannot enter the configured netns: {err}");
                // configure_runtime() probed this exact descriptor, so this is
                // unreachable in practice; a thread left in the wrong namespace
                // would silently route registry traffic there, which is worse
                // than losing the thread.
                panic!("nydus-backend runtime thread cannot enter the configured netns: {err}");
            }
        });
    }
    builder.build()
}

/// Verify that `netns` can be entered, on a scratch thread whose namespace
/// change dies with it.
fn probe_netns(netns: &OwnedFd) -> io::Result<()> {
    let fd = netns.as_raw_fd();
    std::thread::scope(|scope| {
        scope
            .spawn(move || enter_netns(fd))
            .join()
            .map_err(|_| io::Error::other("netns probe thread panicked"))?
    })
    .map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("cannot enter the configured netns for the backend runtime: {err}"),
        )
    })
}

#[cfg(target_os = "linux")]
fn enter_netns(fd: std::os::fd::RawFd) -> io::Result<()> {
    // SAFETY: setns only takes the descriptor and a flag; the descriptor is
    // owned by the process-wide RuntimeOptions and stays open for the life of
    // the process, so it cannot have been reused for anything else.
    let rc = unsafe { libc::setns(fd, libc::CLONE_NEWNET) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn enter_netns(_fd: std::os::fd::RawFd) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "network namespaces are only supported on linux",
    ))
}

fn inode_identity(fd: &OwnedFd) -> io::Result<(u64, u64)> {
    // SAFETY: fstat writes only into the zeroed stat buffer we hand it and the
    // descriptor is owned (open) for the duration of the call.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd.as_raw_fd(), &mut st) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // Field widths differ across targets; widen them uniformly.
    #[allow(clippy::unnecessary_cast)]
    Ok((st.st_dev as u64, st.st_ino as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_selects_the_bounded_defaults() {
        let options = RuntimeOptions::default();
        assert_eq!(options.worker_threads(), DEFAULT_WORKER_THREADS);
        assert_eq!(options.max_blocking_threads(), DEFAULT_MAX_BLOCKING_THREADS);
        assert!(options.netns.is_none());
    }

    #[test]
    fn configure_runtime_is_first_come_and_idempotent() {
        // Whatever ran before either left the config unset or sealed it with
        // the defaults; both make the default request succeed.
        configure_runtime(RuntimeOptions::default()).unwrap();
        let err = configure_runtime(RuntimeOptions {
            worker_threads: DEFAULT_WORKER_THREADS + 5,
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(err.to_string().contains("worker"), "{err}");
        configure_runtime(RuntimeOptions::default()).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn threads_named(name: &str) -> usize {
        std::fs::read_dir("/proc/self/task")
            .unwrap()
            .filter_map(|entry| std::fs::read_to_string(entry.unwrap().path().join("comm")).ok())
            .filter(|comm| comm.trim_end() == name)
            .count()
    }

    /// Thread names are set by the new thread itself and threads exit
    /// asynchronously, so wait for the count to settle.
    #[cfg(target_os = "linux")]
    fn assert_threads_named(name: &str, expected: usize, what: &str) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let count = threads_named(name);
            if count == expected {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{what}: expected {expected} threads named {name}, found {count}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn runtime_spawns_exactly_the_configured_workers() {
        static OPTIONS: RuntimeOptions = RuntimeOptions {
            worker_threads: 3,
            max_blocking_threads: 2,
            netns: None,
        };
        // Thread names are truncated to 15 bytes in /proc, keep it short.
        let name = "nb-rt-workers";
        assert_eq!(threads_named(name), 0);
        let runtime = build_runtime(&OPTIONS, name).unwrap();
        assert_threads_named(name, 3, "workers are spawned eagerly");
        runtime.block_on(async {
            tokio::task::spawn_blocking(|| ()).await.unwrap();
        });
        assert_threads_named(name, 4, "one blocking thread on demand");
        drop(runtime);
        assert_threads_named(name, 0, "threads exit with the runtime");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn netns_probe_rejects_a_non_namespace_descriptor() {
        let file = tempfile::tempfile().unwrap();
        let err = probe_netns(&OwnedFd::from(file)).unwrap_err();
        assert!(err.to_string().contains("netns"), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn runtime_threads_enter_the_configured_netns() {
        // setns needs CAP_SYS_ADMIN even for the caller's own namespace.
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipped: not root");
            return;
        }
        let own = std::fs::File::open("/proc/thread-self/ns/net").unwrap();
        let expected = inode_identity(&OwnedFd::from(own.try_clone().unwrap())).unwrap();
        // Leaked on purpose: the hook borrows the descriptor for the runtime's
        // lifetime, mirroring the process-wide CONFIG.
        let options: &'static RuntimeOptions = Box::leak(Box::new(RuntimeOptions {
            worker_threads: 1,
            max_blocking_threads: 1,
            netns: Some(OwnedFd::from(own)),
        }));
        probe_netns(options.netns.as_ref().unwrap()).unwrap();
        let runtime = build_runtime(options, "nb-rt-netns").unwrap();
        let seen = runtime.block_on(async {
            tokio::spawn(async {
                let ns = std::fs::File::open("/proc/thread-self/ns/net").unwrap();
                inode_identity(&OwnedFd::from(ns)).unwrap()
            })
            .await
            .unwrap()
        });
        assert_eq!(seen, expected);
    }
}
