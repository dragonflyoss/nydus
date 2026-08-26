//! Post-mount blob prefetch: warms the local caches with the priority blobs
//! declared in the image (and optionally every remaining blob) so on-demand
//! reads hit the cache instead of the backend.

use std::io;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tracing::{info, warn};

use nydus_config::PrefetchScope;

use crate::cache::BlobCaches;

/// Drives blob-level prefetch after a nydus filesystem is mounted.
///
/// Workflow:
/// 1. Prefetch the blobs declared in the root `trusted.nydus.prefetch.blobs`
///    xattr sequentially, in the declared priority order (single thread).
/// 2. When the scope is [`PrefetchScope::All`], prefetch the remaining blobs
///    concurrently with a worker pool; otherwise stop after the priority blobs so the
///    backend bandwidth stays focused on the access-ordered hot set (e.g. an
///    optimized image's "ondemand" redirect blob).
pub struct BlobPrefetcher {
    caches: Arc<BlobCaches>,
    priority: Vec<u16>,
    rest: Vec<u16>,
    threads: usize,
    scope: PrefetchScope,
    /// Per-blob prefetch timeout; `0s` disables the bound.
    timeout: Duration,
}

/// The blob prefetch order: `priority` blobs stream first, sequentially and
/// in declared order; `rest` follows through the worker pool when the scope
/// is [`PrefetchScope::All`].
pub struct PrefetchPlan {
    /// Blob indexes to warm first, in declared order.
    pub priority: Vec<u16>,
    /// The remaining blob indexes, in ascending order.
    pub rest: Vec<u16>,
}

impl BlobPrefetcher {
    /// `plan` is typically the result of `ErofsReader::prefetch_plan`, and
    /// `blobs` the matching cache set (`ErofsReader::blob_caches`).
    pub fn new(
        caches: Arc<BlobCaches>,
        plan: PrefetchPlan,
        threads: usize,
        scope: PrefetchScope,
        timeout: Duration,
    ) -> Self {
        Self {
            caches,
            priority: plan.priority,
            rest: plan.rest,
            threads: threads.max(1),
            scope,
            timeout,
        }
    }

    /// Spawn a background thread that drives the whole prefetch workflow. The
    /// returned handle may be detached by the caller.
    pub fn spawn(self) -> io::Result<JoinHandle<()>> {
        thread::Builder::new()
            .name("nydus_prefetch".to_string())
            .spawn(move || self.run())
    }

    /// Drive the whole prefetch workflow synchronously on the calling thread:
    /// priority blobs sequentially in declared order, then (only when the scope
    /// is [`PrefetchScope::All`]) the remaining blobs through a worker pool.
    /// Per-blob failures are logged and skipped.
    pub fn run(self) {
        if self.scope == PrefetchScope::None {
            return;
        }

        // Phase 1: priority blobs, sequential, in declared order. Under the
        // default "ondemand" scope only the redirect blob is warmed (it
        // streams the access-ordered hot set into the source caches);
        // non-redirect priority blobs are skipped so the backend bandwidth is
        // not spent pulling whole source blobs.
        for blob_index in self.priority {
            if self.scope != PrefetchScope::All {
                match self.caches.is_redirect(blob_index) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(err) => {
                        warn!("failed to inspect priority blob {}: {}", blob_index, err);
                        continue;
                    }
                }
            }
            match self
                .caches
                .prefetch_blob(blob_index, self.threads, self.timeout)
            {
                Ok(()) => info!("prefetched priority blob {}", blob_index),
                Err(err) => warn!("failed to prefetch priority blob {}: {}", blob_index, err),
            }
        }

        // Phase 2: remaining blobs, concurrent worker pool. Skipped unless the
        // scope is "all".
        if self.scope != PrefetchScope::All || self.rest.is_empty() {
            return;
        }
        let worker_count = self.threads.min(self.rest.len());
        let queue = Arc::new(Mutex::new(self.rest));
        let timeout = self.timeout;
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let blobs = self.caches.clone();
            let queue = queue.clone();
            let handle = thread::Builder::new()
                .name("nydus_prefetch_worker".to_string())
                .spawn(move || loop {
                    let blob_index = {
                        let mut guard = queue.lock().unwrap();
                        guard.pop()
                    };
                    match blob_index {
                        Some(blob_index) => match blobs.prefetch_blob(blob_index, 1, timeout) {
                            Ok(()) => info!("prefetched blob {}", blob_index),
                            Err(err) => warn!("failed to prefetch blob {}: {}", blob_index, err),
                        },
                        None => break,
                    }
                });
            match handle {
                Ok(handle) => handles.push(handle),
                Err(err) => warn!("failed to spawn prefetch worker: {}", err),
            }
        }
        for handle in handles {
            let _ = handle.join();
        }
    }
}
