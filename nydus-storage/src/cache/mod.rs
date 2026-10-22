//! The blob caches of an image: the dense decoded block address space of
//! every blob, served from a sparse cache file, from memory, or straight
//! from the backend, behind one [`BlobCache`] per blob and one
//! [`BlobCaches`] set per image.

mod decode;
mod diskless;
mod local;
mod raw_device;

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tracing::{info, warn};

use nydus_backend::Backend;
use nydus_config::StorageConfig;
use nydus_format::blob::{BlobMetadata, BlobMetadataChunkGroupExtent};
use nydus_format::utils::SHA256_DIGEST_SIZE;
use nydus_telemetry::metrics::{CacheMetrics, Metrics, WriteFailureReason, WriteKind};
use nydus_telemetry::prometheus::core::{Collector, Desc};
use nydus_telemetry::prometheus::proto::MetricFamily;
use nydus_telemetry::prometheus::{IntGaugeVec, Opts};

pub use decode::decode_chunk_group;
pub use local::LocalBlobCache;

use self::decode::write_failure_reason;
use self::diskless::{DecodedChunkGroupCache, DisklessBlobCache};
use self::raw_device::RawDeviceBlobCache;
use crate::access_trace::TraceRecorder;

/// A blob's cache: its dense decoded block address space, where the chunks
/// sit on their blocks with zero padding between them, read by absolute
/// offset.
///
/// ```text
/// BlobCache
///   ├─ LocalBlobCache      a sparse cache file in the storage directory, filled
///   │                      chunk group by chunk group and shared across processes
///   ├─ DisklessBlobCache   no storage directory: chunk groups decoded in memory
///   │                      per read, the recent ones kept in a bounded LRU
///   └─ RawDeviceBlobCache  a native erofs-* layer, read as-is from the backend
/// ```
///
/// The file-oriented operations, the ones that hand the cache file to the
/// kernel, default to [`io::ErrorKind::Unsupported`] for caches without a
/// file of their own.
pub trait BlobCache: Send + Sync {
    /// Fills `buf` with the bytes at `offset` of the address space, fetching
    /// the chunk groups it misses.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;

    /// Streams `len` bytes at `offset` into `writer`. The default bounces
    /// through a per-thread buffer; a cache that serves reads from a mapping
    /// overrides it to skip the copy.
    fn write_data_to(&self, offset: u64, len: usize, writer: &mut dyn io::Write) -> io::Result<()> {
        write_data_via_scratch(self, offset, len, writer)
    }

    /// Returns the cache file, shared with the cache, for the kernel-facing
    /// services to map or read at.
    fn cache_file(&self) -> io::Result<Arc<File>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cache_file is not supported by this blob cache",
        ))
    }

    /// Fetches, decodes, verifies, caches and publishes every chunk group of
    /// the blob, up to `workers` batches at a time, failing with
    /// [`io::ErrorKind::TimedOut`] when `deadline` passes between batches.
    /// Used by the blob-level prefetch after a filesystem is mounted.
    fn prefetch_all(&self, workers: usize, deadline: Option<Instant>) -> io::Result<()>;

    /// Creates, or opens, the cache file sized to the padded address space
    /// and returns its path. The file mirrors the decoded block address
    /// space, so it can back a virtio-pmem device whose guest reads land at
    /// `block * 4096`.
    fn prepare(&self) -> io::Result<PathBuf> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "prepare is not supported by this blob cache",
        ))
    }

    /// Ensures every chunk group overlapping `[offset, offset + len)` is
    /// decoded, verified and written to the cache file. Idempotent and safe
    /// to call concurrently.
    fn ensure_range(&self, _offset: u64, _len: u64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ensure_range is not supported by this blob cache",
        ))
    }

    /// Returns the ready byte ranges overlapping `[offset, offset + len)`,
    /// without fetching anything.
    fn ready_ranges(&self, _offset: u64, _len: u64) -> io::Result<Vec<Range<u64>>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ready_ranges is not supported by this blob cache",
        ))
    }

    /// Returns whether the blob is an ondemand blob, the `nydus optimize`
    /// output: a redirect blob whose chunk groups copy other blobs' chunk
    /// groups, which the prefetch streams into those source blobs' caches
    /// first.
    fn is_redirect(&self) -> bool {
        false
    }

    /// Returns whether chunk group `chunk_group_index` is decoded into the
    /// local cache, by the shared chunk group map, `false` for a cache
    /// without one. Never fetches.
    fn is_chunk_group_ready(&self, _chunk_group_index: usize) -> bool {
        false
    }

    /// Streams the chunk groups of a redirect blob: fetches them in batches
    /// of the fetch size through up to `workers` threads, decodes and
    /// verifies each against the blob's metadata, and hands the payload to
    /// `f` in blob order. Chunk groups `skip` accepts are not fetched, a
    /// batch made of them alone costing no backend read; a chunk group that
    /// fails to decode is logged and skipped, while an error of `f` aborts
    /// the stream. Returns the bytes read from the backend and the chunk
    /// groups that failed to decode.
    fn for_each_redirect_chunk_group(
        &self,
        _workers: usize,
        _deadline: Option<Instant>,
        _skip: &(dyn Fn(&BlobMetadataChunkGroupExtent) -> bool + Sync),
        _f: &(dyn Fn(&BlobMetadataChunkGroupExtent, &[u8]) -> io::Result<()> + Sync),
    ) -> io::Result<(u64, u64)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "for_each_redirect_chunk_group is not supported by this blob cache",
        ))
    }

    /// Writes `payload`, the decoded chunk group `chunk_group_index` of the
    /// blob obtained from a redirect blob, into the local cache and marks
    /// the chunk group ready. The payload is verified against the blob's own
    /// metadata first, so a stale or corrupt copy never reaches the cache. A
    /// no-op when the chunk group is already ready.
    fn fill_chunk_group_from_redirect(
        &self,
        _chunk_group_index: usize,
        _payload: &[u8],
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fill_chunk_group_from_redirect is not supported by this blob cache",
        ))
    }

    /// Takes the cross-process prefetch lock of the blob, waiting for its
    /// holder, and returns the guard releasing it on drop or process exit;
    /// `None` when locking is unavailable or unnecessary, the caller then
    /// prefetching without the cross-process dedup. Only the blob-level
    /// prefetch takes the lock; on-demand reads never wait on it.
    fn prefetch_lock(&self) -> Option<File> {
        None
    }

    /// Returns whether every chunk group of the blob is decoded into the
    /// local cache, in O(1), one shared flag load and no bitmap scan, so the
    /// per-event handlers of uffd, fanotify and FUSE can ask on every request
    /// and skip the readiness bookkeeping once a blob is fully warmed.
    /// Sticky: ready chunk groups are never evicted within a cache
    /// generation.
    fn is_all_ready(&self) -> bool {
        false
    }

    /// Returns the uncompressed bytes of the blob the cache file holds, by
    /// the shared chunk group map, and the blob's total; `None` for a cache
    /// without a file of its own, a raw device, a diskless cache or a
    /// redirect blob, whose chunk groups land in their source blobs.
    fn cached_bytes(&self) -> Option<(u64, u64)> {
        None
    }
}

/// Reads `[offset, offset + len)` through `cache.read_at` into a per-thread
/// scratch buffer and copies it into `writer`, the fallback of the caches
/// that cannot serve reads from a mapping.
fn write_data_via_scratch<C: BlobCache + ?Sized>(
    cache: &C,
    offset: u64,
    len: usize,
    writer: &mut dyn io::Write,
) -> io::Result<()> {
    thread_local! {
        static SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    }

    SCRATCH.with(|cell| {
        let mut buf = cell.borrow_mut();
        if buf.len() < len {
            buf.resize(len, 0);
        }

        let buf = &mut buf[..len];
        cache.read_at(offset, buf)?;
        writer.write_all(buf)
    })
}

/// The `status` label value of the image bytes the cache holds.
const CACHED: &str = "cached";

/// The `status` label value of the image bytes the cache does not hold yet.
const UNCACHED: &str = "uncached";

/// A blob of the bootstrap device table, its cache opened on the first read
/// or prefetch so mounting does not pay a blob meta download per blob up
/// front.
struct BlobSlot {
    /// The blob id.
    blob_id: [u8; SHA256_DIGEST_SIZE],

    /// The blob's device index in the merged image.
    blob_index: u16,

    /// The backend serving the blob.
    backend: Arc<dyn Backend>,

    /// The decoded chunk groups of the diskless caches, one budget for the
    /// set.
    decoded_chunk_groups: Arc<DecodedChunkGroupCache>,

    /// The access trace of the image, `None` when accesses are not traced.
    trace_recorder: Option<Arc<TraceRecorder>>,

    /// The `storage` section of the image: the directory, `None` selecting
    /// the diskless [`DisklessBlobCache`], the fetch size and the checksum
    /// verification.
    storage: StorageConfig,

    /// The cache, opened on first use. Double-checked: reads take the read
    /// lock, a cold slot takes the write lock and re-checks before opening.
    /// A failed open leaves the slot empty, so it stays retryable.
    cache: RwLock<Option<Arc<dyn BlobCache>>>,
}

/// Implements the blob slot.
impl BlobSlot {
    /// Returns the blob's cache, a cold slot opened with the blob metadata
    /// read as an on-demand read.
    fn cache(&self) -> io::Result<Arc<dyn BlobCache>> {
        if let Some(cache) = self.cache.read().unwrap().as_ref() {
            return Ok(cache.clone());
        }

        let mut guard = self.cache.write().unwrap();
        if let Some(cache) = guard.as_ref() {
            return Ok(cache.clone());
        }

        let cache = if self.backend.is_raw_device(&self.blob_id)? {
            self.open_raw_device()
        } else {
            let blob_metadata = if self.storage.dir.is_some() {
                LocalBlobCache::read_blob_metadata(self.blob_id, &self.backend, &self.storage)?
            } else {
                self.backend.read_blob_metadata(&self.blob_id)?
            };
            self.open(blob_metadata)?
        };
        *guard = Some(cache.clone());
        Ok(cache)
    }

    /// Returns the blob's cache, a cold slot opened with the blob metadata
    /// read as a prefetch read.
    fn prefetch_cache(&self) -> io::Result<Arc<dyn BlobCache>> {
        if let Some(cache) = self.cache.read().unwrap().as_ref() {
            return Ok(cache.clone());
        }

        let mut guard = self.cache.write().unwrap();
        if let Some(cache) = guard.as_ref() {
            return Ok(cache.clone());
        }

        let cache = if self.backend.is_raw_device(&self.blob_id)? {
            self.open_raw_device()
        } else {
            let blob_metadata = if self.storage.dir.is_some() {
                LocalBlobCache::prefetch_blob_metadata(self.blob_id, &self.backend, &self.storage)?
            } else {
                self.backend.prefetch_blob_metadata(&self.blob_id)?
            };
            self.open(blob_metadata)?
        };
        *guard = Some(cache.clone());
        Ok(cache)
    }

    /// Opens the pass-through cache of a native layer, read as-is from the
    /// backend since it carries no blob meta to decode with.
    fn open_raw_device(&self) -> Arc<dyn BlobCache> {
        Arc::new(RawDeviceBlobCache::new(self.blob_id, self.backend.clone()))
    }

    /// Opens the cache of a layered blob described by `blob_metadata`: the
    /// sparse file cache under the storage directory, the diskless cache
    /// without one.
    fn open(&self, blob_metadata: BlobMetadata) -> io::Result<Arc<dyn BlobCache>> {
        Ok(if self.storage.dir.is_some() {
            Arc::new(LocalBlobCache::open(
                self.blob_id,
                self.blob_index,
                blob_metadata,
                self.backend.clone(),
                &self.storage,
                self.trace_recorder.clone(),
            )?)
        } else {
            Arc::new(DisklessBlobCache::new(
                self.blob_id,
                blob_metadata,
                self.backend.clone(),
                self.decoded_chunk_groups.clone(),
                self.storage.skip_verify_checksums,
            ))
        })
    }
}

/// The `nydus_cache_bytes{status}` gauge of an image, computed when the
/// registry is gathered the way prometheus' `ProcessCollector` reads
/// `/proc`: the chunk group maps of the blobs opened so far, which every
/// process using the cache directory shares, say which bytes the cache
/// holds, so a chunk group another process filled counts the moment it is
/// ready.
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

/// The blob caches of an opened image, one per blob of the bootstrap device
/// table.
pub struct BlobCaches {
    /// The blob slots by device index.
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
                warn!("failed to unregister nydus_cache_bytes: {}", err);
            }
        }
    }
}

/// Implements the empty set, for metadata-only readers: every lookup fails
/// with `NotFound` and no cache directory is created.
impl Default for BlobCaches {
    fn default() -> Self {
        Self {
            slots: Arc::new(HashMap::new()),
            metrics: Arc::new(Metrics::new()),
            collector: None,
        }
    }
}

/// Implements the blob caches.
impl BlobCaches {
    /// Creates the set from the `(blob_index, blob_id)` pairs of `entries`,
    /// served by `backend` under the `storage` section and recording
    /// on-demand accesses into `trace_recorder` when set. Without a
    /// `storage.dir` the blobs run diskless: reads fetch from the backend
    /// directly, nothing is written to disk, and the recently decoded chunk
    /// groups are kept in one bounded in-memory cache shared by the whole
    /// set.
    pub fn new(
        entries: impl IntoIterator<Item = (u16, [u8; SHA256_DIGEST_SIZE])>,
        backend: Arc<dyn Backend>,
        storage: &StorageConfig,
        trace_recorder: Option<Arc<TraceRecorder>>,
    ) -> io::Result<Self> {
        let decoded_chunk_groups = Arc::new(DecodedChunkGroupCache::default());
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
                            backend: backend.clone(),
                            decoded_chunk_groups: decoded_chunk_groups.clone(),
                            trace_recorder: trace_recorder.clone(),
                            storage: storage.clone(),
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
                warn!("nydus_cache_bytes is not collected for this image: {}", err);
                None
            }
        };

        Ok(Self {
            slots,
            metrics,
            collector,
        })
    }

    /// Returns the metrics of the image, which the caches and the prefetch
    /// over them record into.
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// Returns whether the set holds the blob `blob_index`.
    pub fn contains(&self, blob_index: u16) -> bool {
        self.slots.contains_key(&blob_index)
    }

    /// Returns the blob indexes of the set, in arbitrary order.
    pub fn indexes(&self) -> impl Iterator<Item = u16> + '_ {
        self.slots.keys().copied()
    }

    /// Returns the cache of the blob `blob_index` for an on-demand read,
    /// opened on first use with the blob metadata read as an on-demand read.
    pub fn cache(&self, blob_index: u16) -> io::Result<Arc<dyn BlobCache>> {
        self.slot(blob_index)?.cache()
    }

    /// Returns the cache of the blob `blob_index` for a prefetch read, opened
    /// on first use with the blob metadata read as a prefetch read.
    pub(crate) fn prefetch_cache(&self, blob_index: u16) -> io::Result<Arc<dyn BlobCache>> {
        self.slot(blob_index)?.prefetch_cache()
    }

    /// Returns the slot of the blob `blob_index`, failing with `NotFound`
    /// for a blob the set does not hold.
    fn slot(&self, blob_index: u16) -> io::Result<&BlobSlot> {
        self.slots.get(&blob_index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("blob {blob_index} not found"),
            )
        })
    }

    /// Returns whether the blob `blob_index` is an ondemand blob, the
    /// redirect blob `nydus optimize` produces. Opens the blob's cache,
    /// which reads the blob meta but prefetches no data.
    pub fn is_redirect(&self, blob_index: u16) -> io::Result<bool> {
        Ok(self.prefetch_cache(blob_index)?.is_redirect())
    }

    /// Prefetches every chunk group of the blob `blob_index`, up to `workers`
    /// batches at a time, an ondemand blob streamed chunk group by chunk
    /// group into its source blobs' caches instead of filling its own. A
    /// non-zero `timeout` bounds the whole blob's prefetch, which fails with
    /// [`io::ErrorKind::TimedOut`] once it passes.
    ///
    /// The prefetch of one blob is serialized across the processes sharing
    /// the cache directory: with many identical instances cold-starting on
    /// one node, only the lock owner streams from the backend while the
    /// others wait and then find the work done through the shared chunk
    /// group map. On-demand reads never pass through here, so the lock never
    /// delays them.
    pub fn prefetch_blob(
        &self,
        blob_index: u16,
        workers: usize,
        timeout: Duration,
    ) -> io::Result<()> {
        let deadline = (!timeout.is_zero()).then(|| Instant::now() + timeout);
        let cache = self.prefetch_cache(blob_index)?;
        let _prefetch_lock = cache.prefetch_lock();
        if !cache.is_redirect() {
            return cache.prefetch_all(workers, deadline);
        }

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

    /// Streams the redirect blob `blob_index` in its packed, first-access
    /// order and writes every decoded chunk group into its source blob's
    /// cache, so the workload's early reads hit the cache. Chunk groups
    /// whose source is already cached, by the source's chunk group map
    /// shared across processes, are not fetched. A chunk group that fails is
    /// logged and skipped so it can neither poison a source cache nor abort
    /// the warmup; `filled` and `skipped` count the chunk groups written and
    /// the ones that could not be. Returns what the stream fetched, see
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
            self.prefetch_cache(redirect.source_blob_index())
                .inspect_err(|err| {
                    warn!(
                        "failed to open source blob {} of ondemand blob {}: {}",
                        redirect.source_blob_index(),
                        blob_index,
                        err
                    )
                })
                .ok()
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
                        "failed to fill chunk group {} of blob {} from ondemand blob {}: {}",
                        source_index,
                        redirect.source_blob_index(),
                        blob_index,
                        err
                    );
                    skipped.fetch_add(1, Ordering::Relaxed)
                }
            };
            Ok(())
        })
    }
}
