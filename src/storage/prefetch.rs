use std::io;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use tracing::{info, warn};

use crate::fs::ErofsReader;

/// Default number of worker threads used for concurrent blob prefetch.
pub const DEFAULT_PREFETCH_THREADS: usize = 10;

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
    reader: Arc<ErofsReader>,
    threads: usize,
    full: bool,
}

impl BlobPrefetcher {
    pub fn new(reader: Arc<ErofsReader>, threads: usize, full: bool) -> Self {
        Self {
            reader,
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
        let (priority, rest) = self.reader.prefetch_plan();

        // Phase 1: priority blobs, sequential, in declared order. When full
        // prefetch is disabled, only the "ondemand" redirect blob is warmed
        // (it streams the access-ordered hot set into the source caches);
        // non-redirect priority blobs are skipped so the backend bandwidth is
        // not spent pulling whole source blobs.
        for blob_index in priority {
            if !self.full {
                match self.reader.blob_is_redirect(blob_index) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(err) => {
                        warn!("failed to inspect priority blob {}: {}", blob_index, err);
                        continue;
                    }
                }
            }
            match self.reader.prefetch_blob(blob_index, self.threads) {
                Ok(()) => info!("prefetched priority blob {}", blob_index),
                Err(err) => warn!("failed to prefetch priority blob {}: {}", blob_index, err),
            }
        }

        // Phase 2: remaining blobs, concurrent worker pool. Skipped unless full
        // prefetch is requested.
        if !self.full || rest.is_empty() {
            return;
        }
        let worker_count = self.threads.min(rest.len());
        let queue = Arc::new(Mutex::new(rest));
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let reader = self.reader.clone();
            let queue = queue.clone();
            let handle = thread::Builder::new()
                .name("nydus_prefetch_worker".to_string())
                .spawn(move || loop {
                    let blob_index = {
                        let mut guard = queue.lock().unwrap();
                        guard.pop()
                    };
                    match blob_index {
                        Some(blob_index) => match reader.prefetch_blob(blob_index, 1) {
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
