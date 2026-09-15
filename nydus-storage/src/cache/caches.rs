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
use nydus_format::blob::BlobMetadataChunkGroup;
use nydus_format::utils::SHA256_DIGEST_SIZE;

use super::{BlobCache, LocalBlobCache, RawDeviceBlobCache, RemoteBlobCache};

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
        // A native layer is read as-is from the backend; only layered blobs
        // carry the blob meta the caching implementations decode with.
        let cache: Arc<dyn BlobCache> = if self.backend.is_raw_device(&self.blob_id)? {
            Arc::new(RawDeviceBlobCache::new(self.blob_id, self.backend.clone()))
        } else {
            match &self.cache_dir {
                Some(cache_dir) => Arc::new(LocalBlobCache::open_with_trace(
                    self.blob_id,
                    self.blob_index as u32,
                    cache_dir,
                    self.backend.clone(),
                    self.trace_recorder.clone(),
                )?),
                None => Arc::new(RemoteBlobCache::open(self.blob_id, self.backend.clone())?),
            }
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
    /// blob (a REDIRECT blob produced by `nydus optimize`). Opens the blob
    /// cache, which reads the local blob meta but performs no data prefetch.
    pub fn is_redirect(&self, blob_index: u16) -> io::Result<bool> {
        Ok(self.cache(blob_index)?.is_redirect())
    }

    /// Prefetch every chunk group of the blob identified by `blob_index`.
    /// An "ondemand" (REDIRECT) blob is streamed group by group into the
    /// source blobs' caches instead of filling its own. Up to `workers`
    /// batches are fetched concurrently. A non-zero `timeout` bounds the
    /// whole blob's prefetch; on expiry the prefetch aborts with
    /// [`io::ErrorKind::TimedOut`].
    pub fn prefetch_blob(
        &self,
        blob_index: u16,
        workers: usize,
        timeout: Duration,
    ) -> io::Result<()> {
        let deadline = (!timeout.is_zero()).then(|| Instant::now() + timeout);
        let cache = self.cache(blob_index)?;
        // Serialize prefetch of the same blob across processes sharing the
        // cache directory: with many identical instances cold-starting on one
        // node, only the lock owner streams from the backend while the others
        // wait and then find the work already done through the shared chunk
        // group map. On-demand reads never pass through here, so they are
        // never delayed by the lock. Held (via the guard's file descriptor)
        // until this function returns.
        let _prefetch_lock = cache.prefetch_lock();
        if !cache.is_redirect() {
            return cache.prefetch_all(workers, deadline);
        }
        // Time the ondemand blob prefetch and report how many source groups
        // it warmed versus skipped, so operators can tell whether the warmup
        // outran the workload.
        let fill_before = nydus_telemetry::metrics::cache_redirect_fill_chunk_group_total();
        let skip_before = nydus_telemetry::metrics::cache_redirect_skip_chunk_group_total();
        let start = Instant::now();
        let result = self.prefetch_redirect_blob(blob_index, cache.as_ref(), workers, deadline);
        info!(
            "ondemand blob {} prefetch finished in {:.3?} ({} workers): filled {} chunk groups, skipped {}",
            blob_index,
            start.elapsed(),
            workers.max(1),
            nydus_telemetry::metrics::cache_redirect_fill_chunk_group_total() - fill_before,
            nydus_telemetry::metrics::cache_redirect_skip_chunk_group_total() - skip_before,
        );
        result
    }

    /// Stream a REDIRECT blob in its packed (first-access) order and write
    /// every decoded group into its source blob's cache, so the workload's
    /// early reads hit cache. Groups whose source is already cached (shared
    /// across processes through the source's chunk group map) are not
    /// fetched. Per-group failures are logged and skipped so a bad group can
    /// neither poison a source cache nor abort the warmup.
    fn prefetch_redirect_blob(
        &self,
        blob_index: u16,
        cache: &dyn BlobCache,
        workers: usize,
        deadline: Option<Instant>,
    ) -> io::Result<()> {
        let source_of = |group: &BlobMetadataChunkGroup| -> Option<Arc<dyn BlobCache>> {
            let redirect = group.redirect()?;
            match self.try_cache(redirect.source_blob_index()) {
                Some(Ok(source)) => Some(source),
                Some(Err(err)) => {
                    warn!(
                        "failed to open source blob {} of ondemand blob {blob_index}: {err}",
                        redirect.source_blob_index()
                    );
                    None
                }
                None => {
                    warn!(
                        "ondemand blob {blob_index} redirects to unknown blob {}",
                        redirect.source_blob_index()
                    );
                    None
                }
            }
        };
        let skip = |group: &BlobMetadataChunkGroup| -> bool {
            match (group.redirect(), source_of(group)) {
                (Some(redirect), Some(source)) => {
                    source.is_chunk_group_ready(redirect.source_chunk_group_index() as usize)
                }
                _ => false,
            }
        };
        cache.for_each_redirect_chunk_group(workers, deadline, &skip, &|group, payload| {
            let (Some(redirect), Some(source)) = (group.redirect(), source_of(group)) else {
                nydus_telemetry::metrics::inc_cache_redirect_skip_chunk_group();
                return Ok(());
            };
            let source_index = redirect.source_chunk_group_index() as usize;
            if let Err(err) = source.fill_chunk_group_from_redirect(source_index, payload) {
                nydus_telemetry::metrics::inc_cache_redirect_skip_chunk_group();
                warn!(
                    "failed to fill chunk group {source_index} of blob {} from ondemand blob {blob_index}: {err}",
                    redirect.source_blob_index()
                );
            }
            Ok(())
        })
    }
}
