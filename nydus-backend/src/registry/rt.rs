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
//! therefore go through [`SharedRuntime::block_on_worker`], which spawns the
//! future onto a runtime thread and only waits on the caller.

use std::fmt;
use std::future::Future;
use std::io;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::runtime::{Builder, Runtime};
use tracing::{error, info};

use super::netns::Netns;

/// Async worker threads when [`configure_runtime`] is not called or asks for
/// `0`. The workers only drive socket I/O for the connection pool; the
/// synchronous callers block on their own threads.
pub const DEFAULT_WORKER_THREADS: usize = 2;

/// Upper bound on the on-demand blocking pool when not configured. Only DNS
/// lookups (`getaddrinfo`) run there.
pub const DEFAULT_MAX_BLOCKING_THREADS: usize = 8;

/// Idle blocking threads are released after this long.
const BLOCKING_KEEP_ALIVE: Duration = Duration::from_secs(10);

/// The name of the shared runtime's threads.
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
    pub netns: Option<Netns>,
}

impl RuntimeOptions {
    /// The worker thread count with the default applied.
    fn worker_threads(&self) -> usize {
        match self.worker_threads {
            0 => DEFAULT_WORKER_THREADS,
            n => n,
        }
    }

    /// The blocking thread bound with the default applied.
    fn max_blocking_threads(&self) -> usize {
        match self.max_blocking_threads {
            0 => DEFAULT_MAX_BLOCKING_THREADS,
            n => n,
        }
    }

    /// Whether `other` would build the same runtime, defaults applied and
    /// namespaces compared by identity.
    fn same_as(&self, other: &Self) -> bool {
        self.worker_threads() == other.worker_threads()
            && self.max_blocking_threads() == other.max_blocking_threads()
            && self.netns == other.netns
    }

    /// Build a runtime whose threads are named `thread_name`. The options
    /// are borrowed for the whole process because the thread start hook keeps
    /// entering the namespace for as long as the runtime spawns threads.
    fn build(&'static self, thread_name: &str) -> io::Result<Runtime> {
        let mut builder = Builder::new_multi_thread();
        builder
            .thread_name(thread_name)
            .worker_threads(self.worker_threads())
            .max_blocking_threads(self.max_blocking_threads())
            .thread_keep_alive(BLOCKING_KEEP_ALIVE)
            .enable_all();
        if let Some(netns) = &self.netns {
            builder.on_thread_start(move || {
                if let Err(err) = netns.enter() {
                    error!("nydus-backend runtime thread cannot enter the configured netns: {err}");
                    // configure_runtime() probed this exact descriptor, so this
                    // is unreachable in practice; a thread left in the wrong
                    // namespace would silently route registry traffic there,
                    // which is worse than losing the thread.
                    panic!("nydus-backend runtime thread cannot enter the configured netns: {err}");
                }
            });
        }
        builder.build()
    }
}

impl fmt::Display for RuntimeOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} worker(s), {} blocking, ",
            self.worker_threads(),
            self.max_blocking_threads()
        )?;
        match &self.netns {
            Some(netns) => write!(f, "netns {}", netns.id()),
            None => f.write_str("inherited netns"),
        }
    }
}

/// The process-wide runtime: options installed by the first caller, and the
/// tokio runtime built from them on first use.
pub(super) struct SharedRuntime {
    options: OnceLock<RuntimeOptions>,
    runtime: OnceLock<Runtime>,
    thread_name: &'static str,
}

impl SharedRuntime {
    /// An unconfigured, unbuilt runtime whose threads will be named
    /// `thread_name`.
    pub(super) const fn new(thread_name: &'static str) -> Self {
        Self {
            options: OnceLock::new(),
            runtime: OnceLock::new(),
            thread_name,
        }
    }

    /// Install `options` unless some are installed already, in which case
    /// the same options are a no-op and different ones are rejected with
    /// [`io::ErrorKind::AlreadyExists`].
    pub(super) fn configure(&self, options: RuntimeOptions) -> io::Result<()> {
        if let Some(current) = self.options.get() {
            return self.check(current, &options);
        }
        // Only an option that can still win is probed, so a repeated call
        // keeps succeeding after the caller dropped the privilege setns needs.
        if let Some(netns) = &options.netns {
            netns.probe()?;
        }
        match self.options.set(options) {
            Ok(()) => Ok(()),
            // Lost the race with a concurrent first call; judge against it.
            Err(options) => {
                let current = self
                    .options
                    .get()
                    .expect("set() failed, so a value is present");
                self.check(current, &options)
            }
        }
    }

    /// Accept `requested` when it matches the installed `current`, otherwise
    /// say whether the runtime is merely configured or already running.
    fn check(&self, current: &RuntimeOptions, requested: &RuntimeOptions) -> io::Result<()> {
        if current.same_as(requested) {
            return Ok(());
        }
        let what = if self.runtime.get().is_some() {
            "already running"
        } else {
            "already configured"
        };
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("nydus-backend runtime {what} with {current}; requested {requested}"),
        ))
    }

    /// The tokio runtime, built on first use from the installed options or
    /// the defaults. Building it fixes the options for good: a later
    /// [`configure`](Self::configure) can no longer take effect and reports
    /// that instead of silently doing nothing.
    pub(super) fn get(&'static self) -> &'static Runtime {
        self.runtime.get_or_init(|| {
            let options = self.options.get_or_init(RuntimeOptions::default);
            // The builder never fails on a supported platform (the only
            // errors are thread spawn failures) and a backend without its
            // runtime cannot serve any read anyway.
            let runtime = options
                .build(self.thread_name)
                .expect("failed to build backend tokio runtime");
            info!("nydus-backend runtime: {options}");
            runtime
        })
    }

    /// Run `future` on a runtime thread and wait for its result. This is
    /// what puts DNS and TCP connect on a thread that entered the configured
    /// netns, where `Runtime::block_on` alone would poll on the caller.
    pub(super) fn block_on_worker<T>(
        &'static self,
        future: impl Future<Output = T> + Send + 'static,
    ) -> io::Result<T>
    where
        T: Send + 'static,
    {
        let runtime = self.get();
        runtime
            .block_on(runtime.spawn(future))
            .map_err(|err| io::Error::other(format!("backend runtime task failed: {err}")))
    }
}

/// The runtime every registry backend in the process shares.
pub(super) static RUNTIME: SharedRuntime = SharedRuntime::new(THREAD_NAME);

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
    RUNTIME.configure(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_workers(worker_threads: usize) -> RuntimeOptions {
        RuntimeOptions {
            worker_threads,
            ..Default::default()
        }
    }

    /// A private shared runtime with the process lifetime [`SharedRuntime`]
    /// requires, so a test never touches the one every test in the binary
    /// shares. Thread names are truncated to 15 bytes in `/proc`.
    fn leaked(thread_name: &'static str) -> &'static SharedRuntime {
        Box::leak(Box::new(SharedRuntime::new(thread_name)))
    }

    #[test]
    fn zero_selects_the_bounded_defaults() {
        let options = RuntimeOptions::default();
        assert_eq!(options.worker_threads(), DEFAULT_WORKER_THREADS);
        assert_eq!(options.max_blocking_threads(), DEFAULT_MAX_BLOCKING_THREADS);
        assert!(options.netns.is_none());
        assert_eq!(
            options.to_string(),
            "2 worker(s), 8 blocking, inherited netns"
        );
    }

    #[test]
    fn configure_is_first_come_and_idempotent() {
        let shared = leaked("nb-rt-config");
        shared.configure(with_workers(3)).unwrap();
        shared.configure(with_workers(3)).unwrap();
        let err = shared.configure(with_workers(4)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(err.to_string().contains("already configured"), "{err}");
        assert!(err.to_string().contains("3 worker"), "{err}");
        assert!(err.to_string().contains("requested 4 worker"), "{err}");

        shared.get();
        shared.configure(with_workers(3)).unwrap();
        let err = shared.configure(with_workers(4)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(err.to_string().contains("already running"), "{err}");
    }

    #[test]
    fn an_unconfigured_runtime_installs_the_defaults() {
        let shared = leaked("nb-rt-default");
        shared.get();
        shared.configure(RuntimeOptions::default()).unwrap();
        shared.configure(with_workers(0)).unwrap();
        let err = shared.configure(with_workers(1)).unwrap_err();
        assert!(err.to_string().contains("already running"), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_losing_configure_is_not_probed() {
        let shared = SharedRuntime::new("nb-rt-losing");
        shared.configure(with_workers(3)).unwrap();
        // Not a namespace, so a probe would fail with EINVAL; the installed
        // configuration must be reported instead.
        let netns = Netns::new(tempfile::tempfile().unwrap().into()).unwrap();
        let err = shared
            .configure(RuntimeOptions {
                worker_threads: 3,
                max_blocking_threads: 0,
                netns: Some(netns),
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
    fn build_spawns_exactly_the_configured_workers() {
        static OPTIONS: RuntimeOptions = RuntimeOptions {
            worker_threads: 3,
            max_blocking_threads: 2,
            netns: None,
        };
        let name = "nb-rt-workers";
        assert_eq!(threads_named(name), 0);
        let runtime = OPTIONS.build(name).unwrap();
        assert_threads_named(name, 3, "workers are spawned eagerly");
        runtime.block_on(async {
            tokio::task::spawn_blocking(|| ()).await.unwrap();
        });
        assert_threads_named(name, 4, "one blocking thread on demand");
        drop(runtime);
        assert_threads_named(name, 0, "threads exit with the runtime");
    }

    #[cfg(target_os = "linux")]
    fn current_netns() -> super::super::netns::NetnsId {
        Netns::current().unwrap().id()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn only_worker_polls_run_in_the_configured_netns() {
        let netns = match Netns::unshared() {
            Ok(netns) => netns,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipped: cannot create a netns ({err})");
                return;
            }
            Err(err) => panic!("unshare(CLONE_NEWNET): {err}"),
        };
        let configured = netns.id();
        let caller = current_netns();
        assert_ne!(caller, configured);

        let shared = leaked("nb-rt-netns");
        shared
            .configure(RuntimeOptions {
                worker_threads: 1,
                max_blocking_threads: 1,
                netns: Some(netns),
            })
            .unwrap();

        // block_on alone polls on this thread, which never entered the
        // namespace: exactly what a request must not do.
        assert_eq!(shared.get().block_on(async { current_netns() }), caller);
        // block_on_worker moves the poll onto a runtime thread, and the
        // blocking pool (DNS) enters the namespace too.
        assert_eq!(
            shared.block_on_worker(async { current_netns() }).unwrap(),
            configured
        );
        assert_eq!(
            shared
                .block_on_worker(async {
                    tokio::task::spawn_blocking(current_netns).await.unwrap()
                })
                .unwrap(),
            configured
        );
        // The caller is still where it started.
        assert_eq!(current_netns(), caller);
    }
}
