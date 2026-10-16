//! The tokio runtimes behind a registry backend, one per read kind, and how
//! an embedding process bounds and pins them.
//!
//! The synchronous [`Backend`](crate::Backend) trait bridges into the
//! async HTTP clients through multi-thread runtimes, on-demand reads on one
//! and background prefetch on another so a prefetch burst never queues ahead
//! of a FUSE reader. Left to tokio's defaults a runtime spawns one worker per
//! CPU and keeps them for the life of the process, and every runtime thread
//! inherits the network namespace of the thread that built it. Neither suits
//! a VMM that embeds this crate: the backend drives a handful of connections,
//! so a couple of workers are plenty, and the registry must be reached from
//! the host namespace no matter which thread builds the backend.
//! [`Runtime::new`] takes both: a backend built from a config file gets its
//! bounds from the `http` section and no namespace.
//!
//! Pinning the runtime threads is only half of it: `Runtime::block_on` polls
//! its future on the *calling* thread, and hyper opens the TCP connection
//! inline in the request future, so a request handed straight to `block_on`
//! would still create its socket in the caller's namespace. Requests
//! therefore go through [`Runtime::block_on_worker`], which spawns the future
//! onto a runtime thread and only waits on the caller.

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::runtime::Builder;
use tracing::{error, info};

use super::netns::Netns;
use crate::ReadKind;

/// The time an idle blocking thread is kept before it is released.
const BLOCKING_KEEP_ALIVE: Duration = Duration::from_secs(10);

/// The runtimes a registry backend runs its requests on, one per read kind,
/// so background prefetch never queues ahead of a FUSE reader on the same
/// workers.
///
/// One pair is built per backend from its `http` configuration unless an
/// embedder hands the same pair to several backends.
#[derive(Debug)]
pub struct Runtime {
    /// The runtime of on-demand reads, which a FUSE reader waits on.
    ondemand: tokio::runtime::Runtime,

    /// The runtime of background prefetch reads.
    prefetch: tokio::runtime::Runtime,
}

/// Implements the backend runtimes.
impl Runtime {
    /// Creates a runtime per read kind, each with `worker_threads` async
    /// workers and at most `max_blocking_threads` in its blocking pool, every
    /// thread entering `netns` before it does any work.
    ///
    /// The workers are spawned now and kept for the runtime's life; both
    /// bounds are at least `1` as the configuration guarantees. With a
    /// namespace, sockets and DNS queries never depend on the caller's
    /// namespace; `None` keeps tokio's behaviour, threads inheriting the
    /// namespace of the thread that builds the runtime. A namespace is probed
    /// on a scratch thread first, so an unusable descriptor or a missing
    /// privilege fails here rather than inside a runtime thread.
    pub fn new(
        worker_threads: usize,
        max_blocking_threads: usize,
        netns: Option<Netns>,
    ) -> io::Result<Self> {
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

        let ondemand = Self::build(
            ReadKind::OnDemand,
            worker_threads,
            max_blocking_threads,
            netns.clone(),
        )?;
        let prefetch = Self::build(
            ReadKind::Prefetch,
            worker_threads,
            max_blocking_threads,
            netns,
        )?;
        info!("nydus-backend runtimes: {worker_threads} worker(s) and up to {max_blocking_threads} blocking per read kind, {namespace}");

        Ok(Self { ondemand, prefetch })
    }

    /// Builds the runtime of reads of `kind`, its threads named after the
    /// kind and pinned to `netns` when one is configured.
    fn build(
        kind: ReadKind,
        worker_threads: usize,
        max_blocking_threads: usize,
        netns: Option<Arc<Netns>>,
    ) -> io::Result<tokio::runtime::Runtime> {
        let mut builder = Builder::new_multi_thread();
        builder
            .thread_name(format!("nydus-backend-{kind}"))
            .worker_threads(worker_threads)
            .max_blocking_threads(max_blocking_threads)
            .thread_keep_alive(BLOCKING_KEEP_ALIVE)
            .enable_all();

        // Pin every runtime thread to the namespace, when one is configured.
        if let Some(netns) = netns {
            builder.on_thread_start(move || {
                if let Err(err) = netns.enter() {
                    error!("nydus-backend runtime thread cannot enter the configured netns: {err}");

                    // Abort the thread rather than leave it in the wrong
                    // namespace, where it would silently route registry
                    // traffic. The probe in new() entered this exact
                    // descriptor, so this is unreachable in practice.
                    panic!("nydus-backend runtime thread cannot enter the configured netns: {err}");
                }
            });
        }

        builder.build()
    }

    /// Runs `future` on a thread of the runtime of `kind` and waits for its
    /// result, a task that panics or is cancelled failing like the I/O it ran.
    ///
    /// This is what puts DNS and TCP connect on a thread that entered the
    /// configured netns, where `Runtime::block_on` alone would poll on the
    /// caller.
    pub(crate) fn block_on_worker<T>(
        &self,
        kind: ReadKind,
        future: impl Future<Output = io::Result<T>> + Send + 'static,
    ) -> io::Result<T>
    where
        T: Send + 'static,
    {
        let runtime = match kind {
            ReadKind::OnDemand => &self.ondemand,
            ReadKind::Prefetch => &self.prefetch,
        };
        runtime
            .block_on(runtime.spawn(future))
            .map_err(|err| io::Error::other(format!("backend runtime task failed: {err}")))?
    }

    /// Returns the tokio runtime of `kind` itself, for tests that poll a
    /// future on the calling thread.
    #[cfg(test)]
    pub(crate) fn tokio(&self, kind: ReadKind) -> &tokio::runtime::Runtime {
        match kind {
            ReadKind::OnDemand => &self.ondemand,
            ReadKind::Prefetch => &self.prefetch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_spawns_the_configured_workers_per_read_kind() {
        let test_cases = vec![1, 3];

        for worker_threads in test_cases {
            let runtime = Runtime::new(worker_threads, 1, None).unwrap();
            for kind in [ReadKind::OnDemand, ReadKind::Prefetch] {
                assert_eq!(
                    runtime.tokio(kind).metrics().num_workers(),
                    worker_threads,
                    "{kind}"
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn new_rejects_a_namespace_that_cannot_be_entered() {
        let netns = Netns::new(tempfile::tempfile().unwrap().into()).unwrap();
        let err = Runtime::new(1, 1, Some(netns)).unwrap_err();
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

        let runtime = Runtime::new(1, 1, Some(netns)).unwrap();

        for kind in [ReadKind::OnDemand, ReadKind::Prefetch] {
            assert_eq!(
                runtime.tokio(kind).block_on(async { current_netns() }),
                caller,
                "{kind}"
            );
            assert_eq!(
                runtime
                    .block_on_worker(kind, async { Ok(current_netns()) })
                    .unwrap(),
                configured,
                "{kind}"
            );
            assert_eq!(
                runtime
                    .block_on_worker(kind, async {
                        Ok(tokio::task::spawn_blocking(current_netns).await.unwrap())
                    })
                    .unwrap(),
                configured,
                "{kind}"
            );
        }
        assert_eq!(current_netns(), caller);
    }
}
