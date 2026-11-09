//! The tokio runtime behind a registry backend.

use std::future::Future;
use std::io;
use std::sync::Arc;

use tokio::runtime::Builder;
use tracing::{error, info};

use crate::Netns;

/// The tokio runtime a registry backend runs every request on.
///
/// Its threads enter the configured network namespace, so requests run on them
/// through [`Runtime::block_on_worker`], never on the caller's thread.
#[derive(Debug)]
pub struct Runtime {
    /// The tokio runtime.
    runtime: tokio::runtime::Runtime,
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

        let mut builder = Builder::new_multi_thread();
        builder.thread_name("nydus-backend").enable_all();

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
        self.runtime
            .block_on(self.runtime.spawn(future))
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
