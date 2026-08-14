//! Per-blob lazy cache set: the storage-side companion of an opened image.
//!
//! [`BlobCaches`] owns one lazily opened [`LocalBlobCache`] per blob of the
//! bootstrap device table, plus the blob-level prefetch entry points that only
//! touch those caches. The filesystem reader keeps the metadata half (device
//! table parsing, prefetch xattr) and delegates all cache access here.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tracing::{info, warn};

use crate::access_trace::TraceRecorder;
use nydus_backend::BlobBackend;
use nydus_format::blob::BlobMetadataGroup;
use nydus_format::utils::SHA256_DIGEST_SIZE;

use super::{BlobCache, LocalBlobCache, RemoteBlobCache};

/// A blob referenced by the bootstrap device table. The blob cache is opened
/// lazily on first read or prefetch so mounting does not pay a blob.meta
/// download per blob up front.
struct BlobSlot {
    blob_id: [u8; SHA256_DIGEST_SIZE],
    blob_index: u16,
    /// The local cache directory; `None` selects the diskless
    /// [`RemoteBlobCache`], which serves every read from the backend.
    cache_dir: Option<PathBuf>,
    backend: Arc<dyn BlobBackend>,
    trace_recorder: Option<Arc<TraceRecorder>>,
    /// Double-checked lazy init: reads take the read lock (hot path), a cold
    /// slot takes the write lock and re-checks before opening. A failed open
    /// leaves the slot empty, so it stays retryable.
    cache: RwLock<Option<Arc<dyn BlobCache>>>,
}

impl BlobSlot {
    fn cache(&self) -> io::Result<Arc<dyn BlobCache>> {
        if let Some(cache) = self.cache.read().unwrap().as_ref() {
            return Ok(cache.clone());
        }
        let mut guard = self.cache.write().unwrap();
        if let Some(cache) = guard.as_ref() {
            return Ok(cache.clone());
        }
        let cache: Arc<dyn BlobCache> = match &self.cache_dir {
            Some(cache_dir) => Arc::new(LocalBlobCache::open_with_trace(
                self.blob_id,
                self.blob_index as u32,
                cache_dir,
                self.backend.clone(),
                self.trace_recorder.clone(),
            )?),
            None => Arc::new(RemoteBlobCache::open(self.blob_id, self.backend.clone())?),
        };
        *guard = Some(cache.clone());
        Ok(cache)
    }
}

/// The set of per-blob lazy caches backing an opened image.
pub struct BlobCaches {
    slots: HashMap<u16, BlobSlot>,
}

impl BlobCaches {
    /// An empty set for metadata-only readers: every lookup fails with
    /// `NotFound` and no cache directory is created.
    pub fn empty() -> Self {
        Self {
            slots: HashMap::new(),
        }
    }

    /// Build the set from `(blob_index, blob_id)` pairs. When `cache_dir` is
    /// `None` the blobs run diskless: every read fetches from the backend
    /// directly and nothing is written to disk.
    pub fn new(
        entries: impl IntoIterator<Item = (u16, [u8; SHA256_DIGEST_SIZE])>,
        backend: Arc<dyn BlobBackend>,
        cache_dir: Option<&Path>,
        trace_recorder: Option<Arc<TraceRecorder>>,
    ) -> io::Result<Self> {
        let slots = entries
            .into_iter()
            .map(|(blob_index, blob_id)| {
                (
                    blob_index,
                    BlobSlot {
                        blob_id,
                        blob_index,
                        cache_dir: cache_dir.map(Path::to_path_buf),
                        backend: backend.clone(),
                        trace_recorder: trace_recorder.clone(),
                        cache: RwLock::new(None),
                    },
                )
            })
            .collect();
        Ok(Self { slots })
    }

    /// Whether the set contains the blob identified by `blob_index`.
    pub fn contains(&self, blob_index: u16) -> bool {
        self.slots.contains_key(&blob_index)
    }

    /// The blob indexes in the set, in arbitrary order.
    pub fn indexes(&self) -> impl Iterator<Item = u16> + '_ {
        self.slots.keys().copied()
    }

    /// The (lazily opened) blob cache for the blob identified by `blob_index`.
    pub fn cache(&self, blob_index: u16) -> io::Result<Arc<dyn BlobCache>> {
        self.try_cache(blob_index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("blob {blob_index} not found"),
            )
        })?
    }

    /// Like [`cache`], but distinguishes "unknown blob" (`None`) from a failed
    /// cache open (`Some(Err)`), so callers can attach their own errors.
    ///
    /// [`cache`]: Self::cache
    pub fn try_cache(&self, blob_index: u16) -> Option<io::Result<Arc<dyn BlobCache>>> {
        self.slots.get(&blob_index).map(BlobSlot::cache)
    }

    /// Return whether the blob identified by `blob_index` is an "ondemand"
    /// redirect blob (produced by `nydus optimize`). Opens the blob cache,
    /// which reads the local blob meta but performs no data prefetch.
    pub fn is_redirect_blob(&self, blob_index: u16) -> io::Result<bool> {
        Ok(self.cache(blob_index)?.is_redirect_blob())
    }

    /// Prefetch every group of the blob identified by `blob_index`. An
    /// "ondemand" redirect blob is dispatched group by group into the source
    /// blobs' caches instead of building its own cache file, fetching its
    /// segments concurrently with up to `threads` workers. A non-zero
    /// `timeout` bounds the whole blob's prefetch; on expiry the prefetch
    /// aborts with [`io::ErrorKind::TimedOut`].
    pub fn prefetch_blob(
        &self,
        blob_index: u16,
        threads: usize,
        timeout: Duration,
    ) -> io::Result<()> {
        let deadline = (!timeout.is_zero()).then(|| Instant::now() + timeout);
        let cache = self.cache(blob_index)?;
        // Serialize prefetch of the same blob across processes sharing the
        // cache directory: with many identical instances cold-starting on one
        // node, only the lock owner streams from the backend while the others
        // wait and then find the work already done through the shared
        // group_map. On-demand reads never pass through here, so they are
        // never delayed by the lock. Held (via the guard's file descriptor)
        // until this function returns.
        let _prefetch_lock = cache.prefetch_lock();
        if cache.is_redirect_blob() {
            // Time the ondemand (redirect) blob prefetch and report how many
            // source groups it warmed vs skipped, so operators can tell
            // whether the streaming warmup outran the workload.
            let fill_before = nydus_telemetry::metrics::cache_redirect_fill_group_total();
            let skip_before = nydus_telemetry::metrics::cache_redirect_skip_group_total();
            let bytes_before = nydus_telemetry::metrics::backend_redirect_read_bytes_total();
            let start = Instant::now();
            let result = self.prefetch_redirect_blob(blob_index, cache.as_ref(), threads, deadline);
            let elapsed = start.elapsed();
            info!(
                "ondemand blob {} prefetch finished in {:.3?} ({} workers): filled {} groups, skipped {} groups, fetched {} bytes",
                blob_index,
                elapsed,
                threads.max(1),
                nydus_telemetry::metrics::cache_redirect_fill_group_total() - fill_before,
                nydus_telemetry::metrics::cache_redirect_skip_group_total() - skip_before,
                nydus_telemetry::metrics::backend_redirect_read_bytes_total() - bytes_before,
            );
            result
        } else {
            cache.prefetch_all(deadline)
        }
    }

    /// Phase-0 prefetch for a redirect blob: stream its groups in optimized
    /// order and fill the decoded bytes into the source blobs' caches so early
    /// on-demand reads hit cache. Segments are fetched concurrently with up to
    /// `threads` workers. Per-group failures are logged and skipped so a bad
    /// group can never poison the source caches or abort the warmup.
    fn prefetch_redirect_blob(
        &self,
        blob_index: u16,
        cache: &dyn BlobCache,
        threads: usize,
        deadline: Option<Instant>,
    ) -> io::Result<()> {
        // A redirect group is already done when its bytes are resident in the
        // source blob's cache (readiness is shared across processes through
        // the source group_map). Segments made entirely of done groups are not
        // fetched, so re-running the warmup behind another process's progress
        // does close to zero backend work.
        let skip = |group: &BlobMetadataGroup| -> bool {
            if !group.is_redirect() {
                return false;
            }
            match self.try_cache(group.source_blob_index()) {
                Some(Ok(source_cache)) => {
                    source_cache.is_group_ready(group.source_group_index() as usize)
                }
                _ => false,
            }
        };
        cache.for_each_redirect_group(threads, deadline, &skip, &|group, decoded| {
            if !group.is_redirect() {
                nydus_telemetry::metrics::inc_cache_redirect_skip_group();
                warn!("ondemand blob {blob_index} contains a non-redirect group; skipping");
                return Ok(());
            }
            let source_blob_index = group.source_blob_index();
            let source_index = group.source_group_index() as usize;
            let source_cache = match self.try_cache(source_blob_index) {
                Some(Ok(cache)) => cache,
                Some(Err(err)) => {
                    nydus_telemetry::metrics::inc_cache_redirect_skip_group();
                    warn!("failed to open source blob {source_blob_index} for redirect: {err}");
                    return Ok(());
                }
                None => {
                    nydus_telemetry::metrics::inc_cache_redirect_skip_group();
                    warn!("ondemand blob {blob_index} redirects to unknown blob {source_blob_index}; skipping group");
                    return Ok(());
                }
            };
            if let Err(err) = source_cache.fill_group_from_redirect(source_index, decoded) {
                nydus_telemetry::metrics::inc_cache_redirect_skip_group();
                warn!(
                    "failed to fill blob {source_blob_index} group {source_index} from ondemand blob {blob_index}: {err}"
                );
            }
            Ok(())
        })
    }
}
