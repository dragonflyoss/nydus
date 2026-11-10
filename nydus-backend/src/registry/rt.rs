//! The tokio runtime behind a registry backend.

use std::future::Future;
use std::io;
use std::sync::Arc;

use tokio::runtime::Builder;
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::Netns;

/// The tokio runtime a registry backend runs every request on.
///
/// Its threads enter the configured network namespace, so requests run on them
/// through [`Runtime::block_on_worker`], never on the caller's thread. Its
/// async workers are capped at [`MAX_WORKER_THREADS`].
#[derive(Debug)]
pub struct Runtime {
    /// The tokio runtime.
    runtime: tokio::runtime::Runtime,
}

/// Most async worker threads a runtime starts, fewer on a host with fewer
/// CPUs. The workers only drive sockets and timers, which a few threads keep
/// up with; tokio's default of one per CPU would grow with the host and add a
/// stack and allocator state per thread for nothing.
pub const MAX_WORKER_THREADS: usize = 4;

/// The async worker count of a runtime on a host with `cpus` CPUs.
fn worker_threads(cpus: usize) -> usize {
    cpus.clamp(1, MAX_WORKER_THREADS)
}

/// Implements the backend runtime.
impl Runtime {
    /// Creates a runtime whose threads enter `netns` first, probed here so an
    /// unusable one fails early.
    pub fn new(netns: Option<Netns>) -> io::Result<Self> {
        let netns = match netns {
            Some(netns) => {
                netns.probe()?;
                Some(Arc::new(netns))
            }
            None => None,
        };
        let namespace = match &netns {
            Some(netns) => format!("netns {}", netns.id()),
            None => "inherited netns".to_string(),
        };

        let cpus = std::thread::available_parallelism().map_or(1, |cpus| cpus.get());
        let mut builder = Builder::new_multi_thread();
        builder
            .thread_name("nydus-backend")
            .worker_threads(worker_threads(cpus))
            .enable_all();
        if let Some(hook) = crate::RUNTIME_IDLE_HOOK.get().copied() {
            builder.on_thread_park(hook);
        }

        if let Some(netns) = netns {
            builder.on_thread_start(move || {
                if let Err(err) = netns.enter() {
                    error!("nydus-backend runtime thread cannot enter the configured netns: {err}");

                    // Abort rather than route registry traffic from the wrong
                    // namespace.
                    panic!("nydus-backend runtime thread cannot enter the configured netns: {err}");
                }
            });
        }

        let runtime = builder.build()?;
        info!("nydus-backend runtime: {namespace}");
        Ok(Self { runtime })
    }

    /// Runs `future` on a runtime thread and waits for its result.
    pub(crate) fn block_on_worker<T>(
        &self,
        future: impl Future<Output = io::Result<T>> + Send + 'static,
    ) -> io::Result<T>
    where
        T: Send + 'static,
    {
        self.wait(self.start(future))
    }

    /// Runs `future` on a runtime thread without waiting for it.
    pub(crate) fn start<T>(
        &self,
        future: impl Future<Output = io::Result<T>> + Send + 'static,
    ) -> JoinHandle<io::Result<T>>
    where
        T: Send + 'static,
    {
        self.runtime.spawn(future)
    }

    /// Waits for a task [`Self::start`] started, a task that panics or is
    /// cancelled failing like the I/O it ran.
    pub(crate) fn wait<T>(&self, task: JoinHandle<io::Result<T>>) -> io::Result<T> {
        self.runtime
            .block_on(task)
            .map_err(|err| io::Error::other(format!("backend runtime task failed: {err}")))?
    }

    /// Runs `future` on a thread of the runtime in the background.
    #[cfg(feature = "dragonfly")]
    pub(crate) fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) {
        self.runtime.spawn(future);
    }

    /// Returns the tokio runtime itself, for tests that poll a future on the
    /// calling thread.
    #[cfg(test)]
    pub(crate) fn tokio(&self) -> &tokio::runtime::Runtime {
        &self.runtime
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_threads_follow_the_cpus_up_to_the_cap() {
        assert_eq!(worker_threads(0), 1);
        assert_eq!(worker_threads(1), 1);
        assert_eq!(worker_threads(3), 3);
        assert_eq!(worker_threads(MAX_WORKER_THREADS), MAX_WORKER_THREADS);
        assert_eq!(worker_threads(192), MAX_WORKER_THREADS);

        let runtime = Runtime::new(None).unwrap();
        let workers = runtime.runtime.metrics().num_workers();
        assert!((1..=MAX_WORKER_THREADS).contains(&workers), "{workers}");
    }

    #[test]
    fn runtime_threads_run_the_idle_hook_when_they_run_out_of_work() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static IDLE: AtomicUsize = AtomicUsize::new(0);
        crate::set_runtime_idle_hook(|| {
            IDLE.fetch_add(1, Ordering::Relaxed);
        });

        let runtime = Runtime::new(None).unwrap();
        runtime.block_on_worker(async { Ok(()) }).unwrap();
        for _ in 0..100 {
            if IDLE.load(Ordering::Relaxed) > 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        assert!(IDLE.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn new_builds_a_runtime_in_the_inherited_netns() {
        let runtime = Runtime::new(None).unwrap();
        assert_eq!(runtime.block_on_worker(async { Ok(7) }).unwrap(), 7);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn new_rejects_a_namespace_that_cannot_be_entered() {
        let netns = Netns::new(tempfile::tempfile().unwrap().into()).unwrap();
        let err = Runtime::new(Some(netns)).unwrap_err();
        assert!(err.to_string().contains("netns"));
    }

    #[cfg(target_os = "linux")]
    fn current_netns() -> crate::NetnsId {
        let file = std::fs::File::open("/proc/thread-self/ns/net").unwrap();
        Netns::new(file.into()).unwrap().id()
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires CAP_SYS_ADMIN to create a netns"]
    fn only_worker_polls_run_in_the_configured_netns() {
        let netns = std::thread::scope(|scope| {
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
        .unwrap();
        let configured = netns.id();
        let caller = current_netns();
        assert_ne!(caller, configured);

        let runtime = Runtime::new(Some(netns)).unwrap();

        assert_eq!(runtime.tokio().block_on(async { current_netns() }), caller);
        assert_eq!(
            runtime
                .block_on_worker(async { Ok(current_netns()) })
                .unwrap(),
            configured
        );
        assert_eq!(
            runtime
                .block_on_worker(async {
                    Ok(tokio::task::spawn_blocking(current_netns).await.unwrap())
                })
                .unwrap(),
            configured
        );
        assert_eq!(current_netns(), caller);
    }
}
