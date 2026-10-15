//! The tokio runtime behind a registry backend, and how an embedding process
//! bounds and pins it.
//!
//! The synchronous [`BlobBackend`](crate::BlobBackend) trait bridges into the
//! async HTTP clients through a multi-thread runtime. Left to tokio's defaults
//! that runtime spawns one worker per CPU and keeps them for the life of the
//! process, and every runtime thread inherits the network namespace of the
//! thread that built it. Neither suits a VMM that embeds this crate: the
//! backend drives a handful of connections, so a couple of workers are
//! plenty, and the registry must be reached from the host namespace no matter
//! which thread builds the backend. [`Runtime::new`] takes both from
//! [`RuntimeOptions`]: a backend built from a config file gets its bounds from
//! the `http` section, and an embedder builds one [`Runtime`] with its
//! namespace and shares it across its backends through
//! [`build_backend_with_runtime`](crate::build_backend_with_runtime).
//!
//! Pinning the runtime threads is only half of it: `Runtime::block_on` polls
//! its future on the *calling* thread, and hyper opens the TCP connection
//! inline in the request future, so a request handed straight to `block_on`
//! would still create its socket in the caller's namespace. Requests
//! therefore go through [`Runtime::block_on_worker`], which spawns the future
//! onto a runtime thread and only waits on the caller.

use std::fmt;
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::runtime::Builder;
use tracing::{error, info};

use nydus_config::{
    default_registry_http_max_blocking_threads, default_registry_http_worker_threads, HttpConfig,
};

use super::netns::Netns;

/// Idle blocking threads are released after this long.
const BLOCKING_KEEP_ALIVE: Duration = Duration::from_secs(10);

/// The name of the runtime's threads.
const THREAD_NAME: &str = "nydus-backend";

/// How a backend runtime is built.
#[derive(Debug, Default)]
pub struct RuntimeOptions {
    /// Async worker threads, spawned when the runtime is built and kept for
    /// its life. `0` selects the configuration default,
    /// [`default_registry_http_worker_threads`].
    pub worker_threads: usize,

    /// Upper bound on the blocking pool. `0` selects the configuration
    /// default, [`default_registry_http_max_blocking_threads`].
    pub max_blocking_threads: usize,

    /// Network namespace every runtime thread enters before it does any work,
    /// so sockets and DNS queries never depend on the caller's namespace.
    /// `None` keeps tokio's behaviour: threads inherit the namespace of the
    /// thread that builds the runtime.
    pub netns: Option<Netns>,
}

impl RuntimeOptions {
    /// The worker thread count with the default applied.
    fn worker_threads(&self) -> usize {
        match self.worker_threads {
            0 => default_registry_http_worker_threads(),
            n => n,
        }
    }

    /// The blocking thread bound with the default applied.
    fn max_blocking_threads(&self) -> usize {
        match self.max_blocking_threads {
            0 => default_registry_http_max_blocking_threads(),
            n => n,
        }
    }
}

/// The thread bounds of a registry's `http` configuration, with no namespace.
impl From<&HttpConfig> for RuntimeOptions {
    fn from(http: &HttpConfig) -> Self {
        Self {
            worker_threads: http.worker_threads,
            max_blocking_threads: http.max_blocking_threads,
            netns: None,
        }
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

/// The runtime a registry backend runs its requests on. One is built per
/// backend from its `http` configuration unless an embedder hands the same
/// one to several backends.
#[derive(Debug)]
pub struct Runtime {
    /// The tokio runtime, its threads pinned to the configured namespace.
    inner: tokio::runtime::Runtime,
}

impl Runtime {
    /// Build a runtime from `options`. A namespace is probed on a scratch
    /// thread first, so an unusable descriptor or a missing privilege fails
    /// here rather than inside a runtime thread.
    pub fn new(options: RuntimeOptions) -> io::Result<Self> {
        Self::with_thread_name(options, THREAD_NAME)
    }

    /// Build a runtime whose threads are named `thread_name`.
    fn with_thread_name(options: RuntimeOptions, thread_name: &str) -> io::Result<Self> {
        let description = options.to_string();
        let mut builder = Builder::new_multi_thread();
        builder
            .thread_name(thread_name)
            .worker_threads(options.worker_threads())
            .max_blocking_threads(options.max_blocking_threads())
            .thread_keep_alive(BLOCKING_KEEP_ALIVE)
            .enable_all();
        if let Some(netns) = options.netns {
            netns.probe()?;
            let netns = Arc::new(netns);
            builder.on_thread_start(move || {
                if let Err(err) = netns.enter() {
                    error!("nydus-backend runtime thread cannot enter the configured netns: {err}");
                    // The probe above entered this exact descriptor, so this
                    // is unreachable in practice; a thread left in the wrong
                    // namespace would silently route registry traffic there,
                    // which is worse than losing the thread.
                    panic!("nydus-backend runtime thread cannot enter the configured netns: {err}");
                }
            });
        }
        let inner = builder.build()?;
        info!("nydus-backend runtime: {description}");
        Ok(Self { inner })
    }

    /// Run `future` on a runtime thread and wait for its result. This is
    /// what puts DNS and TCP connect on a thread that entered the configured
    /// netns, where `Runtime::block_on` alone would poll on the caller.
    pub(crate) fn block_on_worker<T>(
        &self,
        future: impl Future<Output = T> + Send + 'static,
    ) -> io::Result<T>
    where
        T: Send + 'static,
    {
        self.inner
            .block_on(self.inner.spawn(future))
            .map_err(|err| io::Error::other(format!("backend runtime task failed: {err}")))
    }

    /// The tokio runtime itself, for tests that poll a future on the calling
    /// thread.
    #[cfg(test)]
    pub(crate) fn tokio(&self) -> &tokio::runtime::Runtime {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_selects_the_configuration_defaults() {
        let test_cases = vec![
            RuntimeOptions::default(),
            RuntimeOptions::from(&HttpConfig::default()),
        ];

        for options in test_cases {
            assert_eq!(
                options.worker_threads(),
                default_registry_http_worker_threads()
            );
            assert_eq!(
                options.max_blocking_threads(),
                default_registry_http_max_blocking_threads()
            );
            assert!(options.netns.is_none());
            assert_eq!(
                options.to_string(),
                "2 worker(s), 8 blocking, inherited netns"
            );
        }
    }

    #[cfg(target_os = "linux")]
    fn threads_named(name: &str) -> usize {
        std::fs::read_dir("/proc/self/task")
            .unwrap()
            .filter_map(|entry| std::fs::read_to_string(entry.unwrap().path().join("comm")).ok())
            .filter(|comm| comm.trim_end() == name)
            .count()
    }

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
    fn new_spawns_exactly_the_configured_workers() {
        let name = "nb-rt-workers";
        assert_eq!(threads_named(name), 0);
        let runtime = Runtime::with_thread_name(
            RuntimeOptions {
                worker_threads: 3,
                max_blocking_threads: 2,
                netns: None,
            },
            name,
        )
        .unwrap();
        assert_threads_named(name, 3, "workers are spawned eagerly");
        runtime.tokio().block_on(async {
            tokio::task::spawn_blocking(|| ()).await.unwrap();
        });
        assert_threads_named(name, 4, "one blocking thread on demand");
        drop(runtime);
        assert_threads_named(name, 0, "threads exit with the runtime");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn new_rejects_a_namespace_that_cannot_be_entered() {
        let netns = Netns::new(tempfile::tempfile().unwrap().into()).unwrap();
        let err = Runtime::new(RuntimeOptions {
            netns: Some(netns),
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.to_string().contains("netns"), "{err}");
    }

    #[cfg(target_os = "linux")]
    fn current_netns() -> super::super::netns::NetnsId {
        let file = std::fs::File::open("/proc/thread-self/ns/net").unwrap();
        Netns::new(file.into()).unwrap().id()
    }

    #[cfg(target_os = "linux")]
    fn unshared_netns() -> io::Result<Netns> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    // SAFETY: unshare only affects this scratch thread, which
                    // exits right after; the descriptor keeps the namespace.
                    if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Netns::new(std::fs::File::open("/proc/thread-self/ns/net")?.into())
                })
                .join()
                .unwrap()
        })
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn only_worker_polls_run_in_the_configured_netns() {
        let netns = match unshared_netns() {
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

        let runtime = Runtime::with_thread_name(
            RuntimeOptions {
                worker_threads: 1,
                max_blocking_threads: 1,
                netns: Some(netns),
            },
            "nb-rt-netns",
        )
        .unwrap();

        assert_eq!(runtime.tokio().block_on(async { current_netns() }), caller);
        assert_eq!(
            runtime.block_on_worker(async { current_netns() }).unwrap(),
            configured
        );
        assert_eq!(
            runtime
                .block_on_worker(async {
                    tokio::task::spawn_blocking(current_netns).await.unwrap()
                })
                .unwrap(),
            configured
        );
        assert_eq!(current_netns(), caller);
    }
}
