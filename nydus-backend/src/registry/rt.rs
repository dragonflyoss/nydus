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
//!
//! Pinning the runtime threads is only half of it: `Runtime::block_on` polls
//! its future on the *calling* thread, and hyper opens the TCP connection
//! inline in the request future, so a request handed straight to `block_on`
//! would still create its socket in the caller's namespace. Requests
//! therefore go through [`block_on_worker`], which spawns the future onto a
//! runtime thread and only waits on the caller.

use std::future::Future;
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

/// The configuration cell the shared runtime is built from. Separate from the
/// static so the first-come/idempotent rules can be tested on a private cell
/// instead of the process-wide one every test in the binary shares.
struct ConfigCell {
    options: OnceLock<RuntimeOptions>,
    /// Set once the runtime has been built from `options`, to tell a caller
    /// whose request lost whether it is merely late or the runtime is live.
    sealed: AtomicBool,
}

impl ConfigCell {
    const fn new() -> Self {
        ConfigCell {
            options: OnceLock::new(),
            sealed: AtomicBool::new(false),
        }
    }

    /// Install `options` unless something is installed already, in which case
    /// the same options are a no-op and different ones are rejected.
    fn configure(&self, options: RuntimeOptions) -> io::Result<()> {
        if let Some(current) = self.options.get() {
            return self.check_installed(current, &options);
        }
        // Only an option that can still win is probed, so a repeated call
        // keeps succeeding after the caller dropped the privilege setns needs.
        if let Some(netns) = &options.netns {
            probe_netns(netns)?;
        }
        match self.options.set(options) {
            Ok(()) => Ok(()),
            // Lost the race with a concurrent first call; judge against it.
            Err(options) => {
                let current = self
                    .options
                    .get()
                    .expect("set() failed, so a value is present");
                self.check_installed(current, &options)
            }
        }
    }

    fn check_installed(
        &self,
        current: &RuntimeOptions,
        requested: &RuntimeOptions,
    ) -> io::Result<()> {
        if current.same_as(requested) {
            return Ok(());
        }
        let what = if self.sealed.load(Ordering::Acquire) {
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
                requested.worker_threads(),
                requested.max_blocking_threads(),
                requested.netns_identity().ok().flatten(),
            ),
        ))
    }

    /// Fix the options for good (defaulting them if nothing was installed)
    /// and hand them out for building the runtime.
    fn seal(&self) -> &RuntimeOptions {
        let options = self.options.get_or_init(RuntimeOptions::default);
        self.sealed.store(true, Ordering::Release);
        options
    }
}

static CONFIG: ConfigCell = ConfigCell::new();
static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    // Sealing here means a later configure_runtime() can no longer take
    // effect and reports that instead of silently doing nothing.
    let options = CONFIG.seal();
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

/// Run `future` on a thread of the shared runtime and wait for its result.
/// `Runtime::block_on` alone would poll it on the calling thread, and hyper
/// connects inline in the request future, so this is what puts DNS and TCP
/// connect on a thread that entered the configured netns.
pub(super) fn block_on_worker<T>(future: impl Future<Output = T> + Send + 'static) -> io::Result<T>
where
    T: Send + 'static,
{
    block_on_worker_of(runtime(), future)
}

fn block_on_worker_of<T>(
    runtime: &Runtime,
    future: impl Future<Output = T> + Send + 'static,
) -> io::Result<T>
where
    T: Send + 'static,
{
    runtime
        .block_on(runtime.spawn(future))
        .map_err(|err| io::Error::other(format!("backend runtime task failed: {err}")))
}

/// Fix how the shared backend runtime is built. Must run before the first
/// registry backend is constructed in the process (a Dragonfly-backed one
/// builds the runtime right there; the others on their first read). The first
/// call wins, a repeated call with the same options is a no-op, and a call
/// with different options fails with [`io::ErrorKind::AlreadyExists`] —
/// whether the runtime has been built yet or not — so the caller can log the
/// misconfiguration instead of assuming it took effect.
///
/// When `netns` is given and can still take effect, entering it is probed on
/// a scratch thread first so an unusable descriptor or missing privilege
/// fails here rather than inside the runtime's thread start hook.
pub fn configure_runtime(options: RuntimeOptions) -> io::Result<()> {
    CONFIG.configure(options)
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

    fn with_workers(worker_threads: usize) -> RuntimeOptions {
        RuntimeOptions {
            worker_threads,
            ..Default::default()
        }
    }

    #[test]
    fn configure_is_first_come_and_idempotent() {
        let cell = ConfigCell::new();
        cell.configure(with_workers(3)).unwrap();
        cell.configure(with_workers(3)).unwrap();
        let err = cell.configure(with_workers(4)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(err.to_string().contains("already configured"), "{err}");
        assert!(err.to_string().contains("3 worker"), "{err}");
        assert!(err.to_string().contains("requested 4 worker"), "{err}");

        assert_eq!(cell.seal().worker_threads(), 3);
        cell.configure(with_workers(3)).unwrap();
        let err = cell.configure(with_workers(4)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(err.to_string().contains("already running"), "{err}");
    }

    #[test]
    fn sealing_an_unconfigured_cell_installs_the_defaults() {
        let cell = ConfigCell::new();
        assert_eq!(cell.seal().worker_threads(), DEFAULT_WORKER_THREADS);
        cell.configure(RuntimeOptions::default()).unwrap();
        cell.configure(with_workers(0)).unwrap();
        let err = cell.configure(with_workers(1)).unwrap_err();
        assert!(err.to_string().contains("already running"), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_losing_configure_is_not_probed() {
        let cell = ConfigCell::new();
        cell.configure(with_workers(3)).unwrap();
        // Not a namespace, so a probe would fail with EINVAL; the installed
        // configuration must be reported instead.
        let err = cell
            .configure(RuntimeOptions {
                worker_threads: 3,
                max_blocking_threads: 0,
                netns: Some(OwnedFd::from(tempfile::tempfile().unwrap())),
            })
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{err}");
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
    fn current_netns() -> (u64, u64) {
        let ns = std::fs::File::open("/proc/thread-self/ns/net").unwrap();
        inode_identity(&OwnedFd::from(ns)).unwrap()
    }

    /// A network namespace of our own, distinguishable from the one the test
    /// process runs in. Needs the same privilege as `setns`, so a
    /// `PermissionDenied` here means the test cannot run in this environment.
    #[cfg(target_os = "linux")]
    fn fresh_netns() -> io::Result<OwnedFd> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    // SAFETY: unshare only affects this scratch thread, which
                    // exits right after; the descriptor keeps the namespace.
                    if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    std::fs::File::open("/proc/thread-self/ns/net").map(OwnedFd::from)
                })
                .join()
                .unwrap()
        })
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn only_worker_polls_run_in_the_configured_netns() {
        let netns = match fresh_netns() {
            Ok(netns) => netns,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipped: cannot create a netns ({err})");
                return;
            }
            Err(err) => panic!("unshare(CLONE_NEWNET): {err}"),
        };
        let configured = inode_identity(&netns).unwrap();
        let caller = current_netns();
        assert_ne!(caller, configured);

        // Leaked on purpose: the hook borrows the descriptor for the runtime's
        // lifetime, mirroring the process-wide CONFIG.
        let options: &'static RuntimeOptions = Box::leak(Box::new(RuntimeOptions {
            worker_threads: 1,
            max_blocking_threads: 1,
            netns: Some(netns),
        }));
        probe_netns(options.netns.as_ref().unwrap()).unwrap();
        let runtime = build_runtime(options, "nb-rt-netns").unwrap();

        // block_on alone polls on this thread, which never entered the
        // namespace: exactly what a request must not do.
        assert_eq!(runtime.block_on(async { current_netns() }), caller);
        // block_on_worker moves the poll onto a runtime thread, and the
        // blocking pool (DNS) enters the namespace too.
        assert_eq!(
            block_on_worker_of(&runtime, async { current_netns() }).unwrap(),
            configured
        );
        assert_eq!(
            block_on_worker_of(&runtime, async {
                tokio::task::spawn_blocking(current_netns).await.unwrap()
            })
            .unwrap(),
            configured
        );
        // The caller is still where it started.
        assert_eq!(current_netns(), caller);
    }
}
