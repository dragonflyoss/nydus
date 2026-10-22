//! Per-blob lazy cache set: the storage-side companion of an opened image.
//!
//! [`BlobCaches`] owns one lazily opened [`LocalBlobCache`] per blob of the
//! bootstrap device table, plus the blob-level prefetch entry points that only
//! touch those caches. The filesystem reader keeps the metadata half (device
//! table parsing, prefetch xattr) and delegates all cache access here.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use prometheus::core::{Collector, Desc};
use prometheus::proto::MetricFamily;
use prometheus::{IntGaugeVec, Opts};
use tracing::{info, warn};

use crate::access_trace::TraceRecorder;
use nydus_backend::{Backend, ReadKind};
use nydus_format::blob::BlobMetadataChunkGroupExtent;
use nydus_format::utils::SHA256_DIGEST_SIZE;
use nydus_telemetry::metrics::{CacheMetrics, Metrics, WriteFailureReason, WriteKind};

use super::remote::DecodedGroupCache;
use super::{
    write_failure_reason, BlobCache, CacheOptions, LocalBlobCache, RawDeviceBlobCache,
    RemoteBlobCache,
};

/// The `status` label value of the image bytes the cache holds.
const CACHED: &str = "cached";

/// The `status` label value of the image bytes the cache does not hold yet.
const UNCACHED: &str = "uncached";

/// A blob referenced by the bootstrap device table. The blob cache is opened
/// lazily on first read or prefetch so mounting does not pay a blob.meta
/// download per blob up front.
struct BlobSlot {
    blob_id: [u8; SHA256_DIGEST_SIZE],
    blob_index: u16,
    /// The local cache directory; `None` selects the diskless
    /// [`RemoteBlobCache`], which serves reads from the backend.
    cache_dir: Option<PathBuf>,
    backend: Arc<dyn Backend>,
    /// Decoded chunk groups of the diskless caches, one budget for the set.
    decoded_groups: Arc<DecodedGroupCache>,
    trace_recorder: Option<Arc<TraceRecorder>>,
    /// The options of the image's caches.
    options: CacheOptions,
    /// Double-checked lazy init: reads take the read lock (hot path), a cold
    /// slot takes the write lock and re-checks before opening. A failed open
    /// leaves the slot empty, so it stays retryable.
    cache: RwLock<Option<Arc<dyn BlobCache>>>,
}

impl BlobSlot {
    /// The blob's cache, `kind` attributing the blob metadata fetch a cold
    /// open may need.
    fn cache(&self, kind: ReadKind) -> io::Result<Arc<dyn BlobCache>> {
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
                    kind,
                    self.options,
                )?),
                None => Arc::new(RemoteBlobCache::open(
                    self.blob_id,
                    self.backend.clone(),
                    self.decoded_groups.clone(),
                    kind,
                    self.options.skip_verify_checksums,
                )?),
            }
        };
        *guard = Some(cache.clone());
        Ok(cache)
    }
}

/// The `nydus_cache_bytes{status}` gauge of an image, computed when the
/// registry is gathered the way prometheus' `ProcessCollector` reads
/// `/proc`: the chunk group maps of the blobs opened so far, which every
/// process using the cache directory shares, say which bytes the cache
/// holds, so a group another process filled counts the moment it is ready.
#[derive(Clone)]
struct CacheBytesCollector {
    /// The gauge the collected values are set on.
    bytes: IntGaugeVec,

    /// The blob slots of the set, their caches scanned when opened.
    slots: Arc<HashMap<u16, BlobSlot>>,
}

/// Implements the cache bytes collector.
impl CacheBytesCollector {
    /// Creates the collector over `slots`.
    fn new(slots: Arc<HashMap<u16, BlobSlot>>) -> Self {
        Self {
            bytes: IntGaugeVec::new(
                Opts::new(
                    "bytes",
                    "Gauge of the bytes of the image the cache serves, by cache status.",
                )
                .namespace(nydus_config::NAME)
                .subsystem(CacheMetrics::SUBSYSTEM),
                &["status"],
            )
            .expect("metric can be created"),
            slots,
        }
    }
}

/// Implements the Prometheus collector.
impl Collector for CacheBytesCollector {
    /// Describes the gauge.
    fn desc(&self) -> Vec<&Desc> {
        self.bytes.desc()
    }

    /// Sums the cached and total bytes of the opened blobs and collects the
    /// gauge. A slot being opened holds its write lock while the blob
    /// metadata is fetched, so it is skipped rather than waited for: it is
    /// not open yet.
    fn collect(&self) -> Vec<MetricFamily> {
        let (cached, total) = self
            .slots
            .values()
            .filter_map(|slot| slot.cache.try_read().ok()?.clone())
            .filter_map(|cache| cache.cached_bytes())
            .fold(
                (0u64, 0u64),
                |(cached, total), (blob_cached, blob_total)| {
                    (cached + blob_cached, total + blob_total)
                },
            );
        self.bytes
            .with_label_values(&[CACHED])
            .set(i64::try_from(cached).unwrap_or(i64::MAX));
        self.bytes
            .with_label_values(&[UNCACHED])
            .set(i64::try_from(total.saturating_sub(cached)).unwrap_or(i64::MAX));
        self.bytes.collect()
    }
}

/// The set of per-blob lazy caches backing an opened image.
pub struct BlobCaches {
    slots: Arc<HashMap<u16, BlobSlot>>,
    /// The metrics of the image, the backend's.
    metrics: Arc<Metrics>,
    /// The `nydus_cache_bytes` collector registered in the metrics, `None`
    /// when the registry already had one.
    collector: Option<CacheBytesCollector>,
}

/// Implements the drop of the set.
impl Drop for BlobCaches {
    /// Unregisters the `nydus_cache_bytes` collector, so the gauge stops
    /// with the set and a later set on the same metrics registers its own.
    fn drop(&mut self) {
        if let Some(collector) = self.collector.take() {
            if let Err(err) = self.metrics.registry().unregister(Box::new(collector)) {
                warn!("failed to unregister nydus_cache_bytes: {err}");
            }
        }
    }
}

impl BlobCaches {
    /// An empty set for metadata-only readers: every lookup fails with
    /// `NotFound` and no cache directory is created.
    pub fn empty() -> Self {
        Self {
            slots: Arc::new(HashMap::new()),
            metrics: Arc::new(Metrics::new()),
            collector: None,
        }
    }

    /// Build the set from `(blob_index, blob_id)` pairs with `options`. When
    /// `cache_dir` is `None` the blobs run diskless: reads fetch from the
    /// backend directly, nothing is written to disk, and recently decoded
    /// chunk groups are kept in one bounded in-memory cache shared by the
    /// whole set.
    pub fn new(
        entries: impl IntoIterator<Item = (u16, [u8; SHA256_DIGEST_SIZE])>,
        backend: Arc<dyn Backend>,
        cache_dir: Option<&Path>,
        trace_recorder: Option<Arc<TraceRecorder>>,
        options: CacheOptions,
    ) -> io::Result<Self> {
        let decoded_groups = Arc::new(DecodedGroupCache::default());
        let metrics = backend.metrics().clone();
        let slots: Arc<HashMap<u16, BlobSlot>> = Arc::new(
            entries
                .into_iter()
                .map(|(blob_index, blob_id)| {
                    (
                        blob_index,
                        BlobSlot {
                            blob_id,
                            blob_index,
                            cache_dir: cache_dir.map(Path::to_path_buf),
                            backend: backend.clone(),
                            decoded_groups: decoded_groups.clone(),
                            trace_recorder: trace_recorder.clone(),
                            options,
                            cache: RwLock::new(None),
                        },
                    )
                })
                .collect(),
        );

        // The gauge is computed at gather time from the slots, so it is
        // registered here rather than with the counters the metrics own.
        let collector = CacheBytesCollector::new(slots.clone());
        let collector = match metrics.registry().register(Box::new(collector.clone())) {
            Ok(()) => Some(collector),
            Err(err) => {
                warn!("nydus_cache_bytes is not collected for this image: {err}");
                None
            }
        };
        Ok(Self {
            slots,
            metrics,
            collector,
        })
    }

    /// The metrics of the image, which the caches and the prefetch over them
    /// record into.
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// Whether the set contains the blob identified by `blob_index`.
    pub fn contains(&self, blob_index: u16) -> bool {
        self.slots.contains_key(&blob_index)
    }

    /// The blob indexes in the set, in arbitrary order.
    pub fn indexes(&self) -> impl Iterator<Item = u16> + '_ {
        self.slots.keys().copied()
    }

    /// The (lazily opened) blob cache for the blob identified by `blob_index`,
    /// `kind` attributing the blob metadata fetch a cold open may need.
    pub fn cache(&self, blob_index: u16, kind: ReadKind) -> io::Result<Arc<dyn BlobCache>> {
        self.try_cache(blob_index, kind).ok_or_else(|| {
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
    pub fn try_cache(
        &self,
        blob_index: u16,
        kind: ReadKind,
    ) -> Option<io::Result<Arc<dyn BlobCache>>> {
        self.slots.get(&blob_index).map(|slot| slot.cache(kind))
    }

    /// Return whether the blob identified by `blob_index` is an "ondemand"
    /// blob (a REDIRECT blob produced by `nydus optimize`). Opens the blob
    /// cache, which reads the local blob meta but performs no data prefetch.
    pub fn is_redirect(&self, blob_index: u16) -> io::Result<bool> {
        Ok(self.cache(blob_index, ReadKind::Prefetch)?.is_redirect())
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
        let cache = self.cache(blob_index, ReadKind::Prefetch)?;
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
        let start = Instant::now();
        let filled = AtomicU64::new(0);
        let skipped = AtomicU64::new(0);
        let result = self.prefetch_redirect_blob(
            blob_index,
            cache.as_ref(),
            workers,
            deadline,
            &filled,
            &skipped,
        );
        let (bytes, failed) = match &result {
            Ok(streamed) => *streamed,
            Err(_) => (0, 0),
        };
        info!(
            "ondemand blob {} prefetch finished in {:.3?} ({} workers): filled {} chunk groups, skipped {}, read {} bytes",
            blob_index,
            start.elapsed(),
            workers.max(1),
            filled.into_inner(),
            skipped.into_inner() + failed,
            bytes,
        );
        result.map(|_| ())
    }

    /// Stream a REDIRECT blob in its packed (first-access) order and write
    /// every decoded group into its source blob's cache, so the workload's
    /// early reads hit cache. Groups whose source is already cached (shared
    /// across processes through the source's chunk group map) are not
    /// fetched. Per-group failures are logged and skipped so a bad group can
    /// neither poison a source cache nor abort the warmup; `filled` and
    /// `skipped` count the groups written and the ones that could not be.
    /// Returns what the stream fetched, see
    /// [`BlobCache::for_each_redirect_chunk_group`].
    fn prefetch_redirect_blob(
        &self,
        blob_index: u16,
        cache: &dyn BlobCache,
        workers: usize,
        deadline: Option<Instant>,
        filled: &AtomicU64,
        skipped: &AtomicU64,
    ) -> io::Result<(u64, u64)> {
        let source_of = |group: &BlobMetadataChunkGroupExtent| -> Option<Arc<dyn BlobCache>> {
            let redirect = group.redirect()?;
            match self.try_cache(redirect.source_blob_index(), ReadKind::Prefetch) {
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
        let skip = |group: &BlobMetadataChunkGroupExtent| -> bool {
            match (group.redirect(), source_of(group)) {
                (Some(redirect), Some(source)) => {
                    source.is_chunk_group_ready(redirect.source_chunk_group_index() as usize)
                }
                _ => false,
            }
        };
        cache.for_each_redirect_chunk_group(workers, deadline, &skip, &|group, payload| {
            let (Some(redirect), Some(source)) = (group.redirect(), source_of(group)) else {
                skipped.fetch_add(1, Ordering::Relaxed);
                self.metrics.cache.collect_write_failure_metrics(
                    WriteKind::Redirect,
                    WriteFailureReason::UnknownSource,
                );
                return Ok(());
            };
            let source_index = redirect.source_chunk_group_index() as usize;
            match source.fill_chunk_group_from_redirect(source_index, payload) {
                Ok(()) => filled.fetch_add(1, Ordering::Relaxed),
                Err(err) => {
                    self.metrics.cache.collect_write_failure_metrics(
                        WriteKind::Redirect,
                        write_failure_reason(&err),
                    );
                    warn!(
                        "failed to fill chunk group {source_index} of blob {} from ondemand blob {blob_index}: {err}",
                        redirect.source_blob_index()
                    );
                    skipped.fetch_add(1, Ordering::Relaxed)
                }
            };
            Ok(())
        })
    }
}
