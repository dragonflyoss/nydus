//! Post-mount blob prefetch: warms the local caches with the priority blobs
//! declared in the image (and optionally every remaining blob) so on-demand
//! reads hit the cache instead of the backend.

use std::io;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use tracing::{info, warn};

use crate::storage::cache::BlobCacheSet;

/// Drives blob-level prefetch after a nydus filesystem is mounted.
///
/// Workflow:
/// 1. Prefetch the blobs declared in the root `trusted.nydus.prefetch.blobs`
///    xattr sequentially, in the declared priority order (single thread).
/// 2. When `full` is set, prefetch the remaining blobs concurrently with a
///    worker pool. When `full` is false, stop after the priority blobs so the
///    backend bandwidth stays focused on the access-ordered hot set (e.g. an
///    optimized image's "ondemand" redirect blob).
pub struct BlobPrefetcher {
    blobs: Arc<BlobCacheSet>,
    priority: Vec<u16>,
    rest: Vec<u16>,
    threads: usize,
    full: bool,
}

impl BlobPrefetcher {
    /// `plan` is the `(priority, rest)` blob-index plan, typically the result
    /// of [`crate::fs::ErofsReader::prefetch_plan`], and `blobs` the matching
    /// cache set ([`crate::fs::ErofsReader::blob_cache_set`]).
    pub fn new(
        blobs: Arc<BlobCacheSet>,
        plan: (Vec<u16>, Vec<u16>),
        threads: usize,
        full: bool,
    ) -> Self {
        let (priority, rest) = plan;
        Self {
            blobs,
            priority,
            rest,
            threads: threads.max(1),
            full,
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
    /// priority blobs sequentially in declared order, then (only when `full` is
    /// set) the remaining blobs through a worker pool. Per-blob failures are
    /// logged and skipped.
    pub fn run(self) {
        // Phase 1: priority blobs, sequential, in declared order. When full
        // prefetch is disabled, only the "ondemand" redirect blob is warmed
        // (it streams the access-ordered hot set into the source caches);
        // non-redirect priority blobs are skipped so the backend bandwidth is
        // not spent pulling whole source blobs.
        for blob_index in self.priority {
            if !self.full {
                match self.blobs.is_redirect_blob(blob_index) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(err) => {
                        warn!("failed to inspect priority blob {}: {}", blob_index, err);
                        continue;
                    }
                }
            }
            match self.blobs.prefetch_blob(blob_index, self.threads) {
                Ok(()) => info!("prefetched priority blob {}", blob_index),
                Err(err) => warn!("failed to prefetch priority blob {}: {}", blob_index, err),
            }
        }

        // Phase 2: remaining blobs, concurrent worker pool. Skipped unless full
        // prefetch is requested.
        if !self.full || self.rest.is_empty() {
            return;
        }
        let worker_count = self.threads.min(self.rest.len());
        let queue = Arc::new(Mutex::new(self.rest));
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let blobs = self.blobs.clone();
            let queue = queue.clone();
            let handle = thread::Builder::new()
                .name("nydus_prefetch_worker".to_string())
                .spawn(move || loop {
                    let blob_index = {
                        let mut guard = queue.lock().unwrap();
                        guard.pop()
                    };
                    match blob_index {
                        Some(blob_index) => match blobs.prefetch_blob(blob_index, 1) {
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
