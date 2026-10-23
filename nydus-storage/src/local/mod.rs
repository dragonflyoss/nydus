//! The blob cache over a sparse file in the storage directory, filled chunk
//! group by chunk group from the backend and shared across the processes
//! using the directory.

mod chunk_group_map;
mod chunk_group_notifier;
mod chunk_group_writer;

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::ops::Range;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use tracing::{info, warn};

use nydus_backend::Backend;
use nydus_config::StorageConfig;
use nydus_format::blob::{BlobMetadata, BlobMetadataChunkGroupExtent};
use nydus_format::utils::SHA256_DIGEST_SIZE;
use nydus_telemetry::metrics::WriteKind;

use crate::buffer::ChunkGroupBuffers;
use crate::decoder::ChunkGroupDecoder;
use crate::{BlobCache, OndemandEntry, OndemandRecord};

use self::chunk_group_map::ChunkGroupMap;
use self::chunk_group_notifier::{ChunkGroupNotifier, OwnerGuard};
use self::chunk_group_writer::ChunkGroupWriter;

/// The plaintext blob cache: a sparse file mirroring the blob's padded
/// address space, filled chunk group by chunk group from the backend, with
/// one ready bit per chunk group shared across the processes using the
/// cache directory.
///
/// The cache of a blob is four files in the storage directory, named by the
/// full blob digest:
///
/// ```text
/// {hex}.blob.data      the sparse cache file, the decoded block address space
/// {hex}.blob.meta      the blob metadata fetched once from the backend
/// {hex}.group.map      the ready bit of every chunk group and the claims of their
///                      fetches, shared across processes
/// {hex}.prefetch.lock  the cross-process lock of the blob-level prefetch
/// ```
///
/// A read is served from the cache file once the chunk groups it covers are
/// ready, the missing ones filled by one reader per process and one process
/// per node:
///
/// ```text
/// read_at(offset, buf)
///   ├─ every chunk group ready ───────────────▶ memcpy from the cache file mapping
///   └─ per chunk group of the range
///        ├─ ready in the shared map ──────────────────────────────────────────┐
///        ├─ in flight in this process ─▶ wait for its owner ──────────────────┤
///        └─ missing ─▶ own the fill of its fetch-size window: claim it across │
///                      processes, read the backend, decode, verify, pwritev,  │
///                      set ready ──────────────────────────────────────────────┤
///                                                                             ▼
///                                                      pread the range from the cache file
/// ```
pub struct LocalBlobCache {
    /// The blob id.
    blob_id: [u8; SHA256_DIGEST_SIZE],

    /// The blob's device index in the merged image, attributing its
    /// on-demand chunk group accesses in the ondemand record.
    blob_index: u16,

    /// The ready bit of every chunk group and the claims of their fetches,
    /// the `.group.map` file.
    chunk_group_map: ChunkGroupMap,

    /// The blob's metadata: chunk groups, chunks, digests, compressor.
    blob_metadata: BlobMetadata,

    /// One flag per chunk group, set once the chunk group is in the access
    /// trace, so the hot path takes the record lock once per chunk group.
    recorded_chunk_groups: Box<[AtomicBool]>,

    /// The path of the cache file.
    cache_data_path: PathBuf,

    /// The path of the cross-process prefetch lock.
    prefetch_lock_path: PathBuf,

    /// The cache file, opened on first use. Double-checked: reads take the
    /// read lock, the first opener takes the write lock and re-checks. A
    /// failed open leaves the slot empty and retryable.
    cache_file: RwLock<Option<Arc<File>>>,

    /// The backend serving the blob.
    backend: Arc<dyn Backend>,

    /// The ondemand record of the image, `None` when accesses are not recorded.
    ondemand_record: Option<Arc<OndemandRecord>>,

    /// The notifiers of the in-flight fills, keyed by chunk group index; one
    /// notifier covers every chunk group of its fetch window.
    notifiers: Mutex<HashMap<usize, Arc<ChunkGroupNotifier>>>,

    /// The read-only mapping of the cache file, created once every chunk
    /// group is ready. It serves reads by memcpy from the page cache,
    /// without a pread per request. The bytes never change after
    /// `ALL_READY` latches: rewrites by racing processes are identical.
    cache_mmap: OnceLock<memmap2::Mmap>,

    /// Skip the crc32c check of decoded chunk groups, `storage.skip_verify_checksums`.
    skip_verify_checksums: bool,

    /// The compressed bytes one on-demand backend read covers, `storage.fetch_size`.
    fetch_size: u64,
}

/// Implements the local blob cache.
impl LocalBlobCache {
    /// The interval between two attempts at the cross-process prefetch lock.
    const PREFETCH_LOCK_RETRY_INTERVAL: Duration = Duration::from_secs(1);

    /// Reads the blob's metadata for an on-demand read: from the `.blob.meta`
    /// file in the storage directory when present, otherwise from `backend`,
    /// saving it there for the processes sharing the directory.
    pub fn read_blob_metadata(
        blob_id: [u8; SHA256_DIGEST_SIZE],
        backend: &Arc<dyn Backend>,
        storage: &StorageConfig,
    ) -> io::Result<BlobMetadata> {
        let cache_dir = Self::cache_dir(storage)?;
        let path = Self::blob_metadata_path(blob_id, cache_dir, backend)?;
        if path.is_file() {
            return BlobMetadata::from_path(&path).map_err(io::Error::other);
        }

        let blob_metadata = backend.read_blob_metadata(&blob_id)?;
        Self::save_blob_metadata(&blob_metadata, cache_dir, &path)?;
        Ok(blob_metadata)
    }

    /// Reads the blob's metadata for a prefetch read: from the `.blob.meta`
    /// file in the storage directory when present, otherwise from `backend`,
    /// saving it there for the processes sharing the directory.
    pub fn prefetch_blob_metadata(
        blob_id: [u8; SHA256_DIGEST_SIZE],
        backend: &Arc<dyn Backend>,
        storage: &StorageConfig,
    ) -> io::Result<BlobMetadata> {
        let cache_dir = Self::cache_dir(storage)?;
        let path = Self::blob_metadata_path(blob_id, cache_dir, backend)?;
        if path.is_file() {
            return BlobMetadata::from_path(&path).map_err(io::Error::other);
        }

        let blob_metadata = backend.prefetch_blob_metadata(&blob_id)?;
        Self::save_blob_metadata(&blob_metadata, cache_dir, &path)?;
        Ok(blob_metadata)
    }

    /// Returns the storage directory of `storage`, which a local blob cache
    /// cannot do without.
    fn cache_dir(storage: &StorageConfig) -> io::Result<&Path> {
        storage.dir.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "storage.dir is required for a local blob cache",
            )
        })
    }

    /// Returns the path of the blob's `.blob.meta` file in `cache_dir`.
    fn blob_metadata_path(
        blob_id: [u8; SHA256_DIGEST_SIZE],
        cache_dir: &Path,
        backend: &Arc<dyn Backend>,
    ) -> io::Result<PathBuf> {
        let hex = hex::encode(backend.full_blob_id(&blob_id)?);
        Ok(cache_dir.join(format!("{hex}{}", BlobMetadata::SUFFIX)))
    }

    /// Saves `blob_metadata` at `path` in `cache_dir` through a uniquely
    /// named temporary file, so the processes sharing the directory never
    /// read a half-written one and a failure leaves nothing behind.
    fn save_blob_metadata(
        blob_metadata: &BlobMetadata,
        cache_dir: &Path,
        path: &Path,
    ) -> io::Result<()> {
        fs::create_dir_all(cache_dir)?;
        let tmp = tempfile::Builder::new()
            .prefix(".blob-meta-")
            .suffix(".tmp")
            .tempfile_in(cache_dir)?;
        blob_metadata.save(tmp.path()).map_err(io::Error::other)?;
        tmp.persist(path).map_err(|err| err.error)?;
        Ok(())
    }

    /// Opens the cache of the blob `blob_id` described by `blob_metadata`
    /// under the storage directory, served by `backend` and following the
    /// `storage` section, recording its on-demand accesses as blob
    /// `blob_index` into `ondemand_record` when set.
    ///
    /// The cache file is created sparse and sized to the padded address
    /// space, and the chunk group map opened against it. A map left behind
    /// by a removed cache file would claim chunk groups are ready while
    /// reads hit sparse zeros, so such a map is reset in place.
    pub fn open(
        blob_id: [u8; SHA256_DIGEST_SIZE],
        blob_index: u16,
        blob_metadata: BlobMetadata,
        backend: Arc<dyn Backend>,
        storage: &StorageConfig,
        ondemand_record: Option<Arc<OndemandRecord>>,
    ) -> io::Result<Self> {
        let cache_dir = Self::cache_dir(storage)?;
        fs::create_dir_all(cache_dir)?;
        let hex = hex::encode(backend.full_blob_id(&blob_id)?);
        let cache_data_path = cache_dir.join(format!("{hex}.blob.data"));
        let group_map_path = cache_dir.join(format!("{hex}.group.map"));

        // Note the orphaned map before creating the cache file below, which
        // would otherwise mask it; a map removed while the cache file stays
        // is the safe direction and needs no handling.
        let stale_group_map = group_map_path.exists() && !cache_data_path.exists();

        // Create the cache file before the map, so that "map file exists"
        // implies "cache file exists" and the check above only fires for a
        // genuinely orphaned map.
        let data_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&cache_data_path)?;
        data_file.set_len(blob_metadata.logical_size())?;
        drop(data_file);

        let chunk_group_map =
            ChunkGroupMap::open(&group_map_path, blob_metadata.chunk_group_count())?;
        if stale_group_map {
            chunk_group_map.reset()?;
            warn!(
                "stale chunk group map without cache file, reset: {}",
                group_map_path.display()
            );
        }

        let recorded_chunk_groups = (0..blob_metadata.chunk_group_count())
            .map(|_| AtomicBool::new(false))
            .collect();

        Ok(Self {
            blob_id,
            blob_index,
            chunk_group_map,
            blob_metadata,
            recorded_chunk_groups,
            cache_data_path,
            prefetch_lock_path: cache_dir.join(format!("{hex}.prefetch.lock")),
            cache_file: RwLock::new(None),
            backend,
            ondemand_record,
            notifiers: Mutex::new(HashMap::new()),
            cache_mmap: OnceLock::new(),
            skip_verify_checksums: storage.skip_verify_checksums,
            fetch_size: storage.fetch_size,
        })
    }

    /// Returns chunk group `index` of the blob metadata.
    fn chunk_group(&self, index: usize) -> BlobMetadataChunkGroupExtent {
        self.blob_metadata
            .chunk_group(index)
            .expect("chunk group index within the blob meta")
    }

    /// Returns the decoder of the blob's chunk groups.
    fn decoder(&self) -> ChunkGroupDecoder<'_> {
        ChunkGroupDecoder::new(&self.blob_metadata, self.skip_verify_checksums)
    }

    /// Collects the cache read metrics of the chunk groups of `span` an
    /// on-demand read found in the cache, with their uncompressed bytes.
    fn collect_read_metrics(&self, span: Range<usize>) {
        let metrics = &self.backend.metrics().cache;
        for index in span {
            metrics.collect_read_metrics(u64::from(self.chunk_group(index).uncompressed_size()));
        }
    }

    /// Returns the chunk groups overlapping `[offset, end)`, one blob
    /// metadata lookup per end.
    fn chunk_group_span(&self, offset: u64, end: u64) -> io::Result<Range<usize>> {
        let not_found = || io::Error::new(io::ErrorKind::NotFound, "blob chunk group not found");
        let first = self
            .blob_metadata
            .chunk_group_index(offset)
            .ok_or_else(not_found)?;
        let last = self
            .blob_metadata
            .chunk_group_index(end - 1)
            .ok_or_else(not_found)?;
        Ok(first..last + 1)
    }

    /// Fails when the cache file has been unlinked.
    ///
    /// The descriptor keeps an unlinked inode alive, so writes through it
    /// still succeed, but they land where nobody else can reach while the
    /// shared chunk group map goes on advertising those chunk groups as
    /// ready. Better to stop than to publish readiness for bytes the other
    /// processes cannot see.
    fn ensure_cache_file_linked(&self, cache_file: &File) -> io::Result<()> {
        if cache_file.metadata()?.nlink() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "cache file was removed while in use: {}",
                    self.cache_data_path.display()
                ),
            ));
        }

        Ok(())
    }

    /// Returns the `[offset, offset + len)` slice of the cache file mapping
    /// when every chunk group is ready, `None` while the blob is still
    /// filling, the caller then taking the ensure and pread path.
    fn all_ready_slice(&self, offset: u64, len: usize) -> io::Result<Option<&[u8]>> {
        if !self.chunk_group_map.is_all_ready() {
            return Ok(None);
        }

        let mmap = match self.cache_mmap.get() {
            Some(mmap) => mmap,
            None => {
                let file = self.cache_file()?;
                // SAFETY: the mapping is read-only and its bytes are final
                // once ALL_READY latches; the identical rewrites of racing
                // processes are benign.
                let mmap = unsafe { memmap2::MmapOptions::new().map(file.as_ref())? };
                self.cache_mmap.get_or_init(|| mmap)
            }
        };

        let end = offset
            .checked_add(len as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "blob read overflow"))?;
        if end > mmap.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "blob read beyond cache file",
            ));
        }

        self.collect_read_metrics(self.chunk_group_span(offset, end)?);
        Ok(Some(&mmap[offset as usize..end as usize]))
    }

    /// Records every chunk group overlapping `[offset, offset + len)` in the
    /// ondemand record, once each, hit or miss: the record names what the
    /// workload read, not what a fetch pulled or what was already cached.
    /// Runs ahead of the all-ready fast paths; a range an invalid read would
    /// reject is left to the read itself.
    fn record_ondemand_range(&self, offset: u64, len: usize) {
        let Some(ondemand_record) = &self.ondemand_record else {
            return;
        };
        if self.recorded_chunk_groups.is_empty() || len == 0 {
            return;
        }
        let Some(end) = offset.checked_add(len as u64) else {
            return;
        };
        let Ok(span) = self.chunk_group_span(offset, end) else {
            return;
        };

        for index in span {
            if !self.recorded_chunk_groups[index].swap(true, Ordering::Relaxed) {
                ondemand_record.push(OndemandEntry {
                    blob_index: self.blob_index,
                    chunk_group_index: index as u32,
                });
            }
        }
    }

    /// Returns the window a miss on chunk group `first` fetches: the chunk
    /// groups whose encoded payloads overlap the fetch-size cell of the data
    /// region holding `first`'s payload start, trimmed at the ones ready or
    /// already in flight, so a cell is fetched whole but never re-fetched.
    /// Cells are aligned, so concurrent misses in one cell plan the same
    /// window and the later ones wait for the first fill instead of starting
    /// an overlapping read. A zero fetch size is the missed chunk group
    /// alone. Called with the notifiers locked so the plan and its
    /// registration are one step.
    fn plan_chunk_group_window(
        &self,
        first: usize,
        notifiers: &HashMap<usize, Arc<ChunkGroupNotifier>>,
    ) -> io::Result<Range<usize>> {
        let budget = self.fetch_size;
        if budget == 0 {
            return Ok(first..first + 1);
        }

        let cell_start = self.chunk_group(first).compressed_offset() / budget * budget;
        let cell_end = cell_start + budget;
        let blocked = |index: usize| -> io::Result<bool> {
            Ok(notifiers.contains_key(&index) || self.chunk_group_map.is_ready(index)?)
        };

        let mut start = first;
        while start > 0
            && self.chunk_group(start - 1).compressed_range().end > cell_start
            && !blocked(start - 1)?
        {
            start -= 1;
        }

        let mut end = first + 1;
        while end < self.blob_metadata.chunk_group_count() {
            if self.chunk_group(end).compressed_offset() >= cell_end || blocked(end)? {
                break;
            }
            end += 1;
        }

        Ok(start..end)
    }

    /// Fills chunk group `first`, and its window, into the cache file,
    /// waiting for an in-flight fill that already covers it.
    fn ensure_chunk_group_window(&self, first: usize) -> io::Result<()> {
        let (notifier, window) = {
            let mut notifiers = self.notifiers.lock().unwrap();
            if let Some(notifier) = notifiers.get(&first) {
                let notifier = notifier.clone();
                drop(notifiers);
                return notifier.wait();
            }

            let window = self.plan_chunk_group_window(first, &notifiers)?;
            let notifier = Arc::new(ChunkGroupNotifier::new());
            for index in window.clone() {
                notifiers.insert(index, notifier.clone());
            }
            (notifier, window)
        };

        let _guard = OwnerGuard {
            notifier: notifier.clone(),
            chunk_groups: window.clone(),
            notifiers: &self.notifiers,
        };
        let result = (|| {
            if self.chunk_group_map.is_ready(first)? {
                self.collect_read_metrics(first..first + 1);
                return Ok(());
            }

            // Claim the window across the processes sharing the cache. The
            // notifier above left a single owner per chunk group in this
            // process, which is what makes the descriptor-owned lock
            // meaningful. The
            // claim spans the whole window rather than `first` alone: a peer
            // missing a neighbouring chunk group of the same cell plans the
            // same window, and would otherwise fetch it too. Whoever waited
            // usually finds the chunk groups published on the way out, so
            // the trim below is what removes the duplicate backend traffic.
            let _claim = self.chunk_group_map.claim(window.clone());
            let window = self.trim_ready(window)?;
            if window.is_empty() {
                self.collect_read_metrics(first..first + 1);
                return Ok(());
            }

            let mut buffers = ChunkGroupBuffers::default();
            let (encoded, decoded, base) = self.window_buffers(&window, &mut buffers)?;
            self.backend.read_range_into(&self.blob_id, base, encoded)?;
            self.fill_chunk_group_window(window, WriteKind::Ondemand, base, encoded, decoded)
        })();

        // The guard's drop then finds the result published and does nothing.
        notifier.notify(&result);
        result
    }

    /// Returns `chunk_groups` without the ready chunk groups at either end,
    /// so a window another reader or process has partly covered costs only
    /// the bytes still missing, and one fully covered costs no backend read
    /// at all.
    fn trim_ready(&self, chunk_groups: Range<usize>) -> io::Result<Range<usize>> {
        let mut start = chunk_groups.start;
        let mut end = chunk_groups.end;
        while start < end && self.chunk_group_map.is_ready(start)? {
            start += 1;
        }
        while end > start && self.chunk_group_map.is_ready(end - 1)? {
            end -= 1;
        }

        Ok(start..end)
    }

    /// Fetches and fills one prefetch batch, trimmed to the chunk groups no
    /// other reader or process has published yet.
    fn prefetch_batch(
        &self,
        batch: Range<usize>,
        buffers: &mut ChunkGroupBuffers,
    ) -> io::Result<()> {
        let batch = self.trim_ready(batch)?;
        if batch.is_empty() {
            return Ok(());
        }

        let (encoded, decoded, base) = self.window_buffers(&batch, buffers)?;
        self.backend
            .prefetch_range_into(&self.blob_id, base, encoded)?;
        self.fill_chunk_group_window(batch, WriteKind::Prefetch, base, encoded, decoded)
    }

    /// Returns `buffers` sized for the chunk groups of `window`: the encoded
    /// bytes of one backend read, a decode scratch the size of the largest
    /// chunk group, and the data-region offset the encoded bytes start at.
    fn window_buffers<'b>(
        &self,
        window: &Range<usize>,
        buffers: &'b mut ChunkGroupBuffers,
    ) -> io::Result<(&'b mut [u8], &'b mut [u8], u64)> {
        let head = self.chunk_group(window.start);
        let tail = self.chunk_group(window.end - 1);
        let encoded_len = usize::try_from(tail.compressed_range().end - head.compressed_offset())
            .map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "fetch size exceeds usize")
        })?;
        let decoded_len = self.blob_metadata.max_bytes_per_chunk_group() as usize;
        let (encoded, decoded) = buffers.resize(encoded_len, decoded_len)?;
        Ok((encoded, decoded, head.compressed_offset()))
    }

    /// Decodes, verifies, writes and publishes every chunk group of `window`
    /// still missing out of its fetched window, whose encoded bytes start at
    /// data-region offset `base`, recording each as a `kind` cache write.
    fn fill_chunk_group_window(
        &self,
        window: Range<usize>,
        kind: WriteKind,
        base: u64,
        encoded: &[u8],
        decoded: &mut [u8],
    ) -> io::Result<()> {
        let metrics = &self.backend.metrics().cache;
        for index in window {
            // Another process may have filled a chunk group of the window
            // since it was planned; the owner's own chunk group was
            // re-checked under the claim, so this only costs a bit test.
            if self.chunk_group_map.is_ready(index)? {
                continue;
            }

            let group = self.chunk_group(index);
            self.decoder()
                .decode(&group, base, encoded, decoded)
                .and_then(|payload| self.write_chunk_group(&group, payload))
                .inspect(|()| {
                    metrics
                        .collect_write_finished_metrics(kind, u64::from(group.uncompressed_size()))
                })
                .inspect_err(|err| {
                    metrics.collect_write_failure_metrics(
                        kind,
                        ChunkGroupDecoder::write_failure_reason(err),
                    )
                })?;
        }

        Ok(())
    }

    /// Fetches one ondemand blob batch, trimmed at the chunk groups `skip`
    /// accepts, and hands every decoded chunk group to `f`. A chunk group
    /// that fails to decode or verify is logged and skipped; an error of `f`
    /// aborts the stream. Returns the bytes read from the backend and the
    /// chunk groups that failed.
    fn stream_ondemand_blob_batch(
        &self,
        batch: Range<usize>,
        buffers: &mut ChunkGroupBuffers,
        skip: &(dyn Fn(&BlobMetadataChunkGroupExtent) -> bool + Sync),
        f: &(dyn Fn(&BlobMetadataChunkGroupExtent, &[u8]) -> io::Result<()> + Sync),
    ) -> io::Result<(u64, u64)> {
        let mut start = batch.start;
        let mut end = batch.end;
        while start < end && skip(&self.chunk_group(start)) {
            start += 1;
        }
        while end > start && skip(&self.chunk_group(end - 1)) {
            end -= 1;
        }
        if start == end {
            return Ok((0, 0));
        }

        let (encoded, decoded, base) = self.window_buffers(&(start..end), buffers)?;
        self.backend
            .prefetch_range_into(&self.blob_id, base, encoded)?;
        let mut failed = 0;
        for index in start..end {
            let group = self.chunk_group(index);
            if skip(&group) {
                continue;
            }

            match self.decoder().decode(&group, base, encoded, decoded) {
                Ok(payload) => f(&group, payload)?,
                Err(err) => {
                    failed += 1;
                    self.backend.metrics().cache.collect_write_failure_metrics(
                        WriteKind::Redirect,
                        ChunkGroupDecoder::write_failure_reason(&err),
                    );
                    warn!(
                        "skipping redirect chunk group {} of blob {}: {}",
                        index, self.blob_index, err
                    );
                }
            }
        }

        Ok((encoded.len() as u64, failed))
    }

    /// Plans the prefetch of the blob for `workers`: batches of consecutive
    /// chunk groups whose compressed bytes reach `storage.fetch_size`, one
    /// contiguous backend read each. Every batch holds at least one chunk
    /// group; a zero fetch size yields one chunk group per batch. With more
    /// than one worker the first `workers` chunk groups are one batch each,
    /// so the pool lands the blob's head, the first-accessed data of an
    /// ondemand blob, within one round trip before the full-size batches
    /// stream the rest.
    fn plan_prefetch_batches(&self, workers: usize) -> Vec<Range<usize>> {
        let ramp = if workers > 1 { workers } else { 0 };
        let mut batches: Vec<Range<usize>> = Vec::new();
        let mut base = 0u64;
        for (index, group) in self.blob_metadata.chunk_groups().enumerate() {
            match batches.last_mut() {
                Some(batch)
                    if batch.start >= ramp
                        && group.compressed_range().end - base <= self.fetch_size =>
                {
                    batch.end = index + 1;
                }
                _ => {
                    base = group.compressed_offset();
                    batches.push(index..index + 1);
                }
            }
        }

        batches
    }

    /// Runs `job` over `batches` in blob order, sequentially or through a
    /// pool of `workers` threads each owning its fetch buffers; the deadline
    /// is checked before every batch and the first error stops every worker
    /// after its current batch.
    fn run_batches(
        &self,
        batches: &[Range<usize>],
        workers: usize,
        deadline: Option<Instant>,
        job: &(dyn Fn(&Range<usize>, &mut ChunkGroupBuffers) -> io::Result<()> + Sync),
    ) -> io::Result<()> {
        // Checked between batches, so the overshoot past the deadline is
        // bounded by one backend request, itself bounded by the request
        // timeout.
        let check_deadline = || match deadline {
            Some(deadline) if Instant::now() >= deadline => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "blob prefetch timed out",
            )),
            _ => Ok(()),
        };

        if workers <= 1 || batches.len() == 1 {
            let mut buffers = ChunkGroupBuffers::default();
            for batch in batches {
                check_deadline()?;
                job(batch, &mut buffers)?;
            }
            return Ok(());
        }

        let next = AtomicUsize::new(0);
        let failure: Mutex<Option<io::Error>> = Mutex::new(None);
        thread::scope(|scope| {
            for _ in 0..workers.min(batches.len()) {
                scope.spawn(|| {
                    let mut buffers = ChunkGroupBuffers::default();
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        if index >= batches.len() {
                            break;
                        }

                        let result =
                            check_deadline().and_then(|()| job(&batches[index], &mut buffers));
                        if let Err(err) = result {
                            let mut slot = failure.lock().unwrap();
                            if slot.is_none() {
                                *slot = Some(err);
                            }
                            next.store(batches.len(), Ordering::Relaxed);
                            break;
                        }
                    }
                });
            }
        });

        match failure.into_inner().unwrap() {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Writes a verified decoded chunk group into the cache file and
    /// publishes it.
    fn write_chunk_group(
        &self,
        group: &BlobMetadataChunkGroupExtent,
        payload: &[u8],
    ) -> io::Result<()> {
        let cache_file = self.cache_file()?;
        let mut writer = ChunkGroupWriter::new(&cache_file);
        for (offset, bytes) in group
            .chunks(&self.blob_metadata, payload)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
        {
            writer.write_at(offset, bytes)?;
        }
        writer.flush()?;
        self.chunk_group_map.set_ready(group.index() as usize)
    }

    /// Ensures every chunk group overlapping `[offset, offset + len)` is
    /// decoded and written to the cache file, a missed one fetched together
    /// with the chunk groups of its fetch-size cell; shared by `read_at` and
    /// `ensure_range`.
    fn ensure_byte_range(&self, offset: u64, len: u64) -> io::Result<()> {
        let end = offset.checked_add(len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob read range overflow")
        })?;
        if end > self.blob_metadata.logical_size() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "blob read range beyond the blob",
            ));
        }

        // The sticky all-ready flag says every chunk group is decoded into
        // the cache file, so skip the per-chunk-group walk entirely.
        let span = self.chunk_group_span(offset, end)?;
        if self.chunk_group_map.is_all_ready() {
            self.collect_read_metrics(span);
            return Ok(());
        }

        for index in span {
            if self.chunk_group_map.is_ready(index)? {
                self.collect_read_metrics(index..index + 1);
            } else {
                self.ensure_chunk_group_window(index)?;
            }
        }

        Ok(())
    }
}

/// Implements the blob cache over the cache file.
impl BlobCache for LocalBlobCache {
    /// Fills every chunk group of the blob in batches of the fetch size, the
    /// first `workers` batches single chunk groups so the head of the blob
    /// lands in the first round trip instead of behind a full batch.
    ///
    /// Prefetch owns its decode buffers and takes no chunk group locks, so
    /// it never blocks on-demand reads. The chunk group map is atomic and
    /// `set_ready` idempotent, so racing with a read at worst decodes the
    /// same chunk group twice into identical bytes at the same offset.
    fn prefetch_all(&self, workers: usize, deadline: Option<Instant>) -> io::Result<()> {
        if self.blob_metadata.chunk_group_count() == 0 || self.chunk_group_map.is_all_ready() {
            return Ok(());
        }

        // Prefetch writes the bulk of the cache, so it is worth one stat to
        // make sure the file it fills is still the one other processes read.
        let cache_file = self.cache_file()?;
        self.ensure_cache_file_linked(&cache_file)?;

        let workers = workers.max(1);
        let batches = self.plan_prefetch_batches(workers);
        self.run_batches(&batches, workers, deadline, &|batch, buffers| {
            self.prefetch_batch(batch.clone(), buffers)
        })?;

        // Every chunk group is now ready, decoded here or observed ready
        // from another process, so latch the sticky ALL_READY flag before
        // returning. `set_ready` latches it through the shared ready count,
        // but a writer that crashed between its bit and count updates leaves
        // the count short forever; the bitmap scan latches it regardless.
        self.chunk_group_map.latch_all_ready();
        Ok(())
    }

    /// Fills `buf` from the cache file, the chunk groups it covers filled
    /// first, and records the access in the record.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        self.record_ondemand_range(offset, buf.len());
        if let Some(mapped) = self.all_ready_slice(offset, buf.len())? {
            buf.copy_from_slice(mapped);
            return Ok(());
        }

        // The cache file mirrors the padded address space, so once the
        // covering chunk groups are decoded the absolute offset indexes
        // straight into it for one contiguous read.
        self.ensure_byte_range(offset, buf.len() as u64)?;
        self.cache_file()?.read_exact_at(buf, offset)
    }

    /// Returns the bytes straight from the cache file mapping once every
    /// chunk group is ready, recording the access in the record; `None`
    /// while the blob is still filling.
    fn mapped(&self, offset: u64, len: usize) -> io::Result<Option<&[u8]>> {
        let mapped = self.all_ready_slice(offset, len)?;
        if mapped.is_some() {
            self.record_ondemand_range(offset, len);
        }

        Ok(mapped)
    }

    /// Creates the sparse cache file sized to the padded address space and
    /// returns its path.
    fn create_cache_file(&self) -> io::Result<PathBuf> {
        self.cache_file()?;
        Ok(self.cache_data_path.clone())
    }

    /// Returns the cache file, opened on first use and sized to the padded
    /// address space.
    fn cache_file(&self) -> io::Result<Arc<File>> {
        if let Some(file) = self.cache_file.read().unwrap().as_ref() {
            return Ok(file.clone());
        }

        let mut cache_file = self.cache_file.write().unwrap();
        if let Some(file) = cache_file.as_ref() {
            return Ok(file.clone());
        }

        let file = Arc::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&self.cache_data_path)?,
        );
        file.set_len(self.blob_metadata.logical_size())?;
        *cache_file = Some(file.clone());
        Ok(file)
    }

    /// Fills the chunk groups overlapping the range into the cache file and
    /// records the access in the record.
    fn ensure_range(&self, offset: u64, len: u64) -> io::Result<()> {
        if len == 0 {
            return Ok(());
        }

        self.record_ondemand_range(offset, usize::try_from(len).unwrap_or(usize::MAX));
        self.ensure_byte_range(offset, len)
    }

    /// Returns the ready chunk groups overlapping the range as merged byte
    /// ranges, by the shared chunk group map.
    fn ready_ranges(&self, offset: u64, len: u64) -> io::Result<Vec<Range<u64>>> {
        if len == 0 {
            return Ok(Vec::new());
        }

        let end = offset.checked_add(len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob probe range overflow")
        })?;
        let span = self.chunk_group_span(offset, end)?;
        let mut ready: Vec<Range<u64>> = Vec::new();
        if self.chunk_group_map.is_all_ready() {
            ready.push(offset..end);
            return Ok(ready);
        }

        for index in span {
            if !self.chunk_group_map.is_ready(index)? {
                continue;
            }

            let slot = self.chunk_group(index).logical_range();
            let range = slot.start.max(offset)..slot.end.min(end);
            match ready.last_mut() {
                Some(run) if run.end == range.start => run.end = range.end,
                _ => ready.push(range),
            }
        }

        Ok(ready)
    }

    /// Returns whether the blob meta is a redirect table.
    fn is_ondemand(&self) -> bool {
        self.blob_metadata.is_ondemand()
    }

    /// Returns the chunk group's ready bit of the shared chunk group map.
    fn is_chunk_group_ready(&self, chunk_group_index: usize) -> bool {
        self.chunk_group_map
            .is_ready(chunk_group_index)
            .unwrap_or(false)
    }

    /// Streams the ondemand blob with the batching of a blob's own prefetch:
    /// fetch-size batches with a single-chunk-group ramp at the head, so the
    /// workload's first reads land in the first round trip, the batches made
    /// of chunk groups the sources already hold trimmed away before any
    /// backend read.
    fn for_each_ondemand_blob_chunk_group(
        &self,
        workers: usize,
        deadline: Option<Instant>,
        skip: &(dyn Fn(&BlobMetadataChunkGroupExtent) -> bool + Sync),
        f: &(dyn Fn(&BlobMetadataChunkGroupExtent, &[u8]) -> io::Result<()> + Sync),
    ) -> io::Result<(u64, u64)> {
        if !self.blob_metadata.is_ondemand() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "blob is not an ondemand blob",
            ));
        }
        if self.blob_metadata.chunk_group_count() == 0 {
            return Ok((0, 0));
        }

        let workers = workers.max(1);
        let batches = self.plan_prefetch_batches(workers);
        let bytes = AtomicU64::new(0);
        let failed = AtomicU64::new(0);
        self.run_batches(&batches, workers, deadline, &|batch, buffers| {
            let (batch_bytes, batch_failed) =
                self.stream_ondemand_blob_batch(batch.clone(), buffers, skip, f)?;
            bytes.fetch_add(batch_bytes, Ordering::Relaxed);
            failed.fetch_add(batch_failed, Ordering::Relaxed);
            Ok(())
        })?;

        Ok((bytes.into_inner(), failed.into_inner()))
    }

    /// Verifies `payload` against the blob's own metadata, whose crc32c and
    /// chunk lengths the redirect copied at optimize time, so a stale
    /// optimize artifact or a corrupted transfer is caught before it can
    /// poison the cache, then writes and publishes it.
    fn fill_chunk_group_from_ondemand_blob(
        &self,
        chunk_group_index: usize,
        payload: &[u8],
    ) -> io::Result<()> {
        let group = self
            .blob_metadata
            .chunk_group(chunk_group_index)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "redirect fill chunk group index out of range",
                )
            })?;
        if self.chunk_group_map.is_ready(chunk_group_index)? {
            return Ok(());
        }

        self.decoder().verify(&group, payload)?;
        self.write_chunk_group(&group, payload)?;
        self.backend.metrics().cache.collect_write_finished_metrics(
            WriteKind::Redirect,
            u64::from(group.uncompressed_size()),
        );
        Ok(())
    }

    /// Takes the per-blob cross-process prefetch lock, polling while another
    /// process holds it and giving up, with `None`, once the shared chunk
    /// group map says that process finished everything. A lock that cannot
    /// be opened or taken degrades to `None` too, the prefetch running
    /// without the lock rather than failing. The lock is released when the
    /// returned file is dropped, on process death included, so a crashed
    /// owner's lock is taken over and the map-driven skipping resumes where
    /// it left off.
    fn prefetch_lock(&self) -> Option<File> {
        let file = match OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.prefetch_lock_path)
        {
            Ok(file) => file,
            Err(err) => {
                warn!(
                    "failed to open prefetch lock {}: {} (prefetching without cross-process lock)",
                    self.prefetch_lock_path.display(),
                    err
                );
                return None;
            }
        };

        let mut contention_logged = false;
        loop {
            // SAFETY: flock has no memory preconditions; the descriptor is
            // open for the lifetime of `file`.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc == 0 {
                if contention_logged {
                    info!("acquired prefetch lock for blob {}", self.blob_index);
                }
                return Some(file);
            }

            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EWOULDBLOCK) {
                warn!(
                    "failed to acquire prefetch lock for blob {}: {} (prefetching without cross-process lock)",
                    self.blob_index, err
                );
                return None;
            }

            if self.chunk_group_map.latch_all_ready() {
                return None;
            }

            if !contention_logged {
                info!(
                    "prefetch lock for blob {} is held by another process (waiting)",
                    self.blob_index
                );
                contention_logged = true;
            }
            thread::sleep(Self::PREFETCH_LOCK_RETRY_INTERVAL);
        }
    }

    /// Returns the sticky `ALL_READY` flag of the shared chunk group map.
    fn is_all_ready(&self) -> bool {
        self.chunk_group_map.is_all_ready()
    }

    /// Sums the uncompressed size of the ready chunk groups, `None` for a
    /// ondemand blob whose chunk groups land in their source blobs.
    fn cached_bytes(&self) -> Option<(u64, u64)> {
        if self.blob_metadata.is_ondemand() {
            return None;
        }

        let cached = (0..self.blob_metadata.chunk_group_count())
            .filter(|&index| self.chunk_group_map.is_ready(index).unwrap_or(false))
            .map(|index| u64::from(self.chunk_group(index).uncompressed_size()))
            .sum();
        Some((cached, self.blob_metadata.uncompressed_size()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlobCaches;
    use nydus_backend::Local;
    use nydus_format::blob::{
        BlobMetadataChunkGroup, BlobMetadataChunkLength, BlobMetadataCompressor,
        BlobMetadataDigester,
    };
    use nydus_telemetry::metrics::{Metrics, WriteFailureReason};
    use nydus_test_utils::blob::{uncompressed_data, FullBlob};
    use nydus_test_utils::metadata::{from_chunk_groups, single_chunk_group};
    use sha2::{Digest, Sha256};
    use std::sync::atomic::AtomicUsize;
    use tempfile::tempdir;

    type Groups = Vec<Vec<Vec<u8>>>;

    struct CountingBackend {
        inner: Local,
        reads: AtomicUsize,
    }

    impl CountingBackend {
        fn new(dir: &Path) -> Arc<Self> {
            Arc::new(Self {
                inner: Local::new(dir.to_path_buf(), Arc::new(Metrics::new())),
                reads: AtomicUsize::new(0),
            })
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl Backend for CountingBackend {
        fn metrics(&self) -> &Arc<Metrics> {
            self.inner.metrics()
        }

        fn read_blob_metadata(
            &self,
            blob_id: &[u8; SHA256_DIGEST_SIZE],
        ) -> io::Result<BlobMetadata> {
            self.inner.read_blob_metadata(blob_id)
        }

        fn read_range_into(
            &self,
            blob_id: &[u8; SHA256_DIGEST_SIZE],
            offset: u64,
            buf: &mut [u8],
        ) -> io::Result<()> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.read_range_into(blob_id, offset, buf)
        }
    }

    fn storage(cache_dir: &Path, fetch_size: u64) -> StorageConfig {
        StorageConfig {
            dir: Some(cache_dir.to_path_buf()),
            fetch_size,
            ..StorageConfig::default()
        }
    }

    fn groups_blob() -> (Vec<u8>, BlobMetadata, Groups, Vec<u8>) {
        let groups: Groups = (0..4u8)
            .map(|group| {
                vec![
                    vec![0x10 * (group + 1); 4096],
                    vec![0x10 * (group + 1) + 1; 4096],
                    vec![0x10 * (group + 1) + 2; 4096],
                    vec![0x10 * (group + 1) + 3; 4096 - 100],
                ]
            })
            .collect();
        let (data, blob_metadata) = from_chunk_groups(
            BlobMetadataCompressor::Zstd,
            16384,
            &groups,
            Some(BlobMetadataDigester::Blake3),
        );
        let image = uncompressed_data(&groups);
        (data, blob_metadata, groups, image)
    }

    fn local_backend(dir: &Path) -> Arc<dyn Backend> {
        Arc::new(Local::new(dir.to_path_buf(), Arc::new(Metrics::new())))
    }

    fn open(
        full_blob_id: [u8; SHA256_DIGEST_SIZE],
        backend: Arc<dyn Backend>,
        storage: &StorageConfig,
    ) -> io::Result<LocalBlobCache> {
        let blob_metadata = LocalBlobCache::read_blob_metadata(full_blob_id, &backend, storage)?;
        LocalBlobCache::open(full_blob_id, 1, blob_metadata, backend, storage, None)
    }

    #[test]
    fn plan_prefetch_batches_follows_the_fetch_size_and_the_workers() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let groups: Groups = (0..5u8).map(|i| vec![vec![i; 4096]]).collect();
        let (data, blob_metadata) =
            from_chunk_groups(BlobMetadataCompressor::None, 4096, &groups, None);
        let full_blob_id = FullBlob::new(&data)
            .with_blob_metadata(&blob_metadata)
            .with_blob_metadata_file()
            .save_in(backend_dir.path());
        let backend = local_backend(backend_dir.path());
        let test_cases: Vec<(u64, usize, Vec<Range<usize>>)> = vec![
            (0, 1, vec![0..1, 1..2, 2..3, 3..4, 4..5]),
            (4096, 1, vec![0..1, 1..2, 2..3, 3..4, 4..5]),
            (8192, 1, vec![0..2, 2..4, 4..5]),
            (u64::MAX, 1, std::iter::once(0..5).collect()),
            (u64::MAX, 2, vec![0..1, 1..2, 2..5]),
            (8192, 3, vec![0..1, 1..2, 2..3, 3..5]),
            (u64::MAX, 9, vec![0..1, 1..2, 2..3, 3..4, 4..5]),
        ];

        for (fetch_size, workers, expected) in test_cases {
            let cached = open(
                full_blob_id,
                backend.clone(),
                &storage(cache_dir.path(), fetch_size),
            )
            .unwrap();
            assert_eq!(cached.plan_prefetch_batches(workers), expected);
        }
    }

    #[test]
    fn read_at_fills_the_fetch_window_of_a_miss() {
        let backend_dir = tempdir().unwrap();
        let (data, blob_metadata, _, image) = groups_blob();
        let full_blob_id = FullBlob::new(&data)
            .with_blob_metadata(&blob_metadata)
            .with_blob_metadata_file()
            .save_in(backend_dir.path());

        let cache_dir = tempdir().unwrap();
        let backend = CountingBackend::new(backend_dir.path());
        let cached = open(full_blob_id, backend.clone(), &storage(cache_dir.path(), 0)).unwrap();
        assert_eq!(blob_metadata.chunk_group_count(), 4);

        let mut buf = vec![0u8; 100];
        cached.read_at(16384 + 10, &mut buf).unwrap();
        assert_eq!(buf, image[16394..16494]);
        assert_eq!(backend.reads(), 1);
        assert!(cached.is_chunk_group_ready(1));
        assert!(!cached.is_chunk_group_ready(0));
        assert!(!cached.is_chunk_group_ready(2));

        cached.read_at(16384 + 16383 - 99, &mut buf).unwrap();
        assert!(buf.iter().all(|b| *b == 0));
        assert_eq!(backend.reads(), 1);

        cached.read_at(4096, &mut buf).unwrap();
        assert_eq!(buf, image[4096..4196]);
        assert_eq!(backend.reads(), 2);
        assert!(cached.is_chunk_group_ready(0));
        assert!(!cached.chunk_group_map.is_all_ready());

        let cache_dir = tempdir().unwrap();
        let backend = CountingBackend::new(backend_dir.path());
        let cached = open(
            full_blob_id,
            backend.clone(),
            &storage(cache_dir.path(), 1 << 20),
        )
        .unwrap();
        let mut all = vec![0u8; image.len()];
        cached.read_at(0, &mut all).unwrap();
        assert_eq!(all, image);
        assert_eq!(backend.reads(), 1);
        assert!(cached.chunk_group_map.is_all_ready());
        assert_eq!(fs::read(&cached.cache_data_path).unwrap(), image);
    }

    #[test]
    fn fetch_size_cells_bound_a_miss() {
        let backend_dir = tempdir().unwrap();
        let (data, blob_metadata, _, image) = groups_blob();
        let full_blob_id = FullBlob::new(&data)
            .with_blob_metadata(&blob_metadata)
            .with_blob_metadata_file()
            .save_in(backend_dir.path());
        let cache_dir = tempdir().unwrap();
        let backend = CountingBackend::new(backend_dir.path());
        let two = blob_metadata.chunk_group(1).unwrap().compressed_range().end;
        let cached = open(
            full_blob_id,
            backend.clone(),
            &storage(cache_dir.path(), two),
        )
        .unwrap();

        let mut buf = vec![0u8; 16];
        cached.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, image[..16]);
        assert_eq!(backend.reads(), 1);
        assert!(cached.is_chunk_group_ready(0));
        assert!(cached.is_chunk_group_ready(1));
        assert!(!cached.is_chunk_group_ready(3));
        cached.read_at(16384, &mut buf).unwrap();
        assert_eq!(backend.reads(), 1);
        cached.read_at(3 * 16384, &mut buf).unwrap();
        assert_eq!(buf, image[3 * 16384..3 * 16384 + 16]);
        assert_eq!(backend.reads(), 2);
        assert!(cached.chunk_group_map.is_all_ready());
    }

    #[test]
    fn read_at_rejects_a_bad_checksum_unless_skipped() {
        let backend_dir = tempdir().unwrap();
        let (data, blob_metadata, groups, _) = groups_blob();
        let digests: Vec<_> = blob_metadata.chunk_group_digests().collect();
        let members: Vec<_> = (0..blob_metadata.chunk_count())
            .map(|index| BlobMetadataChunkLength::new(blob_metadata.chunk_length(index).unwrap()))
            .collect();
        let mut specs: Vec<_> = blob_metadata
            .chunk_groups()
            .map(|group| {
                BlobMetadataChunkGroup::new(
                    group.compressed_offset(),
                    group.logical_block_offset() as u32,
                    group.first_chunk_index(),
                    group.uncompressed_size(),
                    if group.index() == 2 {
                        group.uncompressed_crc32() ^ 1
                    } else {
                        group.uncompressed_crc32()
                    },
                )
            })
            .collect();
        specs.push(BlobMetadataChunkGroup::new(
            blob_metadata.compressed_size(),
            blob_metadata.logical_block_count() as u32,
            blob_metadata.chunk_count() as u32,
            0,
            0,
        ));
        let blob_metadata = BlobMetadata::new(
            4,
            1,
            BlobMetadataCompressor::Zstd,
            (!digests.is_empty()).then_some(BlobMetadataDigester::Blake3),
            specs,
            members,
            digests,
            Vec::new(),
        )
        .unwrap();
        let full_blob_id = FullBlob::new(&data)
            .with_blob_metadata(&blob_metadata)
            .with_blob_metadata_file()
            .save_in(backend_dir.path());

        let cache_dir = tempdir().unwrap();
        let backend = CountingBackend::new(backend_dir.path());
        let cached = open(full_blob_id, backend.clone(), &storage(cache_dir.path(), 0)).unwrap();
        let mut buf = vec![0u8; 100];
        cached.read_at(16384, &mut buf).unwrap();
        assert_eq!(buf, groups[1][0][..100]);
        let err = cached.read_at(2 * 16384, &mut buf).unwrap_err();
        assert_eq!(
            ChunkGroupDecoder::write_failure_reason(&err),
            WriteFailureReason::Checksum
        );
        assert!(!cached.is_chunk_group_ready(2));
        cached.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, groups[0][0][..100]);

        let unchecked = open(
            full_blob_id,
            backend,
            &StorageConfig {
                skip_verify_checksums: true,
                ..storage(cache_dir.path(), 0)
            },
        )
        .unwrap();
        unchecked.read_at(2 * 16384, &mut buf).unwrap();
        assert_eq!(buf, groups[2][0][..100]);
        assert!(unchecked.is_chunk_group_ready(2));
        assert!(cached.is_chunk_group_ready(2));
    }

    #[test]
    fn prefetch_all_fills_in_batches_and_skips_ready_chunk_groups() {
        let backend_dir = tempdir().unwrap();
        let (data, blob_metadata, _, image) = groups_blob();
        let full_blob_id = FullBlob::new(&data)
            .with_blob_metadata(&blob_metadata)
            .with_blob_metadata_file()
            .save_in(backend_dir.path());
        let cache_dir = tempdir().unwrap();
        let backend = CountingBackend::new(backend_dir.path());
        let cached = open(full_blob_id, backend.clone(), &storage(cache_dir.path(), 0)).unwrap();

        let mut buf = vec![0u8; 16];
        cached.read_at(2 * 16384, &mut buf).unwrap();
        assert_eq!(backend.reads(), 1);

        cached.prefetch_all(1, None).unwrap();
        assert_eq!(backend.reads(), 4);
        assert!(cached.chunk_group_map.is_all_ready());
        assert_eq!(fs::read(&cached.cache_data_path).unwrap(), image);
        cached.prefetch_all(1, None).unwrap();
        assert_eq!(backend.reads(), 4);

        let cache_dir = tempdir().unwrap();
        let backend = CountingBackend::new(backend_dir.path());
        let cached = open(
            full_blob_id,
            backend.clone(),
            &storage(cache_dir.path(), 1 << 20),
        )
        .unwrap();
        cached.prefetch_all(1, None).unwrap();
        assert_eq!(backend.reads(), 1);
        assert!(cached.is_all_ready());

        let cache_dir = tempdir().unwrap();
        let backend = CountingBackend::new(backend_dir.path());
        let cached = open(
            full_blob_id,
            backend.clone(),
            &storage(cache_dir.path(), 8192),
        )
        .unwrap();
        cached.prefetch_all(2, None).unwrap();
        assert_eq!(backend.reads(), 3);
        assert!(cached.is_all_ready());
        assert_eq!(fs::read(&cached.cache_data_path).unwrap(), image);
    }

    #[test]
    fn read_at_records_every_chunk_group_it_touches_once() {
        let backend_dir = tempdir().unwrap();
        let (data, blob_metadata, _, image) = groups_blob();
        let full_blob_id = FullBlob::new(&data)
            .with_blob_metadata(&blob_metadata)
            .with_blob_metadata_file()
            .save_in(backend_dir.path());
        let cache_dir = tempdir().unwrap();
        let backend = local_backend(backend_dir.path());
        let record = Arc::new(OndemandRecord::default());
        let storage = storage(cache_dir.path(), 1 << 20);
        let cached = LocalBlobCache::open(
            full_blob_id,
            7,
            LocalBlobCache::read_blob_metadata(full_blob_id, &backend, &storage).unwrap(),
            backend,
            &storage,
            Some(record.clone()),
        )
        .unwrap();

        let mut buf = vec![0u8; 8192];
        cached.read_at(16384 + 4096, &mut buf).unwrap();
        assert_eq!(buf, image[16384 + 4096..16384 + 12288]);
        cached.read_at(16384 + 4096, &mut buf).unwrap();
        cached.read_at(3 * 16384, &mut buf[..16]).unwrap();
        cached.read_at(3 * 16384 + 16, &mut buf[..16]).unwrap();
        let entries: Vec<(u16, u32)> = record
            .entries()
            .iter()
            .map(|entry| (entry.blob_index, entry.chunk_group_index))
            .collect();
        assert_eq!(entries, vec![(7, 1), (7, 3)]);
    }

    #[test]
    fn read_at_fetches_from_the_local_backend() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0xceu8; 4096];
        let blob_metadata = single_chunk_group(&payload);
        let full_blob_id = FullBlob::new(&payload)
            .with_blob_metadata(&blob_metadata)
            .with_blob_metadata_file()
            .save_in(backend_dir.path());

        let cached = open(
            full_blob_id,
            local_backend(backend_dir.path()),
            &storage(cache_dir.path(), StorageConfig::default().fetch_size),
        )
        .unwrap();

        let mut buf = vec![0u8; 1024];
        cached.read_at(512, &mut buf).unwrap();

        assert_eq!(buf, payload[512..1536]);
        assert!(cached.is_chunk_group_ready(0));
        assert!(!cached.is_ondemand());
        assert!(cached.read_at(4096, &mut buf).is_err());
    }

    #[test]
    fn cache_bytes_are_read_from_the_shared_chunk_group_map_when_gathered() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let (data, blob_metadata, _, image) = groups_blob();
        let full_blob_id = FullBlob::new(&data)
            .with_blob_metadata(&blob_metadata)
            .with_blob_metadata_file()
            .save_in(backend_dir.path());
        let gauge = |metrics: &Metrics, status: &str| -> Option<f64> {
            metrics
                .registry()
                .gather()
                .iter()
                .filter(|family| family.get_name() == "nydus_cache_bytes")
                .flat_map(|family| family.get_metric())
                .find(|metric| metric.get_label()[0].get_value() == status)
                .map(|metric| metric.get_gauge().get_value())
        };
        let open = |metrics: &Arc<Metrics>| {
            let backend: Arc<dyn Backend> = Arc::new(Local::new(
                backend_dir.path().to_path_buf(),
                metrics.clone(),
            ));
            BlobCaches::new(
                [(1u16, full_blob_id)],
                backend,
                &storage(cache_dir.path(), 0),
                None,
            )
            .unwrap()
        };
        let blob_bytes = blob_metadata.uncompressed_size() as f64;
        let group_bytes = f64::from(blob_metadata.chunk_group(0).unwrap().uncompressed_size());

        let metrics = Arc::new(Metrics::new());
        let caches = open(&metrics);
        assert_eq!(gauge(&metrics, "cached"), Some(0.0));
        assert_eq!(gauge(&metrics, "uncached"), Some(0.0));

        let cache = caches.cache(1).unwrap();
        assert_eq!(gauge(&metrics, "cached"), Some(0.0));
        assert_eq!(gauge(&metrics, "uncached"), Some(blob_bytes));

        let mut buf = vec![0u8; 16];
        cache.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, image[..16]);
        assert_eq!(gauge(&metrics, "cached"), Some(group_bytes));
        assert_eq!(gauge(&metrics, "uncached"), Some(blob_bytes - group_bytes));

        let other = open(&Arc::new(Metrics::new()));
        other.cache(1).unwrap().read_at(16384, &mut buf).unwrap();
        assert_eq!(gauge(&metrics, "cached"), Some(2.0 * group_bytes));
        assert_eq!(
            gauge(&metrics, "uncached"),
            Some(blob_bytes - 2.0 * group_bytes)
        );

        drop(caches);
        assert_eq!(gauge(&metrics, "cached"), None);

        let reopened = open(&metrics);
        reopened.cache(1).unwrap();
        assert_eq!(gauge(&metrics, "cached"), Some(2.0 * group_bytes));
    }

    #[test]
    fn open_resets_a_stale_chunk_group_map_without_a_cache_file() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x3du8; 4096];
        let blob_metadata = single_chunk_group(&payload);
        let full_blob_id = FullBlob::new(&payload)
            .with_blob_metadata(&blob_metadata)
            .with_blob_metadata_file()
            .save_in(backend_dir.path());
        let backend = local_backend(backend_dir.path());

        {
            let cached = open(
                full_blob_id,
                backend.clone(),
                &storage(cache_dir.path(), StorageConfig::default().fetch_size),
            )
            .unwrap();
            let mut buf = vec![0u8; 1024];
            cached.read_at(0, &mut buf).unwrap();
            assert!(cached.chunk_group_map.is_all_ready());
        }

        let prefix = hex::encode(backend.full_blob_id(&full_blob_id).unwrap());
        fs::remove_file(cache_dir.path().join(format!("{prefix}.blob.data"))).unwrap();

        let reopened = open(
            full_blob_id,
            backend,
            &storage(cache_dir.path(), StorageConfig::default().fetch_size),
        )
        .unwrap();
        assert!(!reopened.is_chunk_group_ready(0));
        assert!(!reopened.chunk_group_map.is_all_ready());

        let mut buf = vec![0u8; 1024];
        reopened.read_at(512, &mut buf).unwrap();
        assert_eq!(buf, payload[512..1536]);
    }

    #[test]
    fn the_stale_chunk_group_map_reset_keeps_the_inode() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x2eu8; 4096];
        let blob_metadata = single_chunk_group(&payload);
        let full_blob_id = FullBlob::new(&payload)
            .with_blob_metadata(&blob_metadata)
            .with_blob_metadata_file()
            .save_in(backend_dir.path());
        let backend = local_backend(backend_dir.path());

        let live = open(
            full_blob_id,
            backend.clone(),
            &storage(cache_dir.path(), StorageConfig::default().fetch_size),
        )
        .unwrap();
        let mut buf = vec![0u8; 1024];
        live.read_at(0, &mut buf).unwrap();
        assert!(live.is_chunk_group_ready(0));

        let prefix = hex::encode(backend.full_blob_id(&full_blob_id).unwrap());
        let group_map_path = cache_dir.path().join(format!("{prefix}.group.map"));
        let before = fs::metadata(&group_map_path).unwrap().ino();
        fs::remove_file(cache_dir.path().join(format!("{prefix}.blob.data"))).unwrap();

        let reopened = open(
            full_blob_id,
            backend,
            &storage(cache_dir.path(), StorageConfig::default().fetch_size),
        )
        .unwrap();
        assert_eq!(fs::metadata(&group_map_path).unwrap().ino(), before);
        assert!(!live.is_chunk_group_ready(0));
        assert!(!reopened.is_chunk_group_ready(0));
    }

    #[test]
    fn prefetch_lock_dedups_across_handles() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x5au8; 4096];
        let blob_metadata = single_chunk_group(&payload);
        let full_blob_id = FullBlob::new(&payload)
            .with_blob_metadata(&blob_metadata)
            .with_blob_metadata_file()
            .save_in(backend_dir.path());
        let backend = local_backend(backend_dir.path());

        let owner = open(
            full_blob_id,
            backend.clone(),
            &storage(cache_dir.path(), StorageConfig::default().fetch_size),
        )
        .unwrap();
        let waiter = open(
            full_blob_id,
            backend,
            &storage(cache_dir.path(), StorageConfig::default().fetch_size),
        )
        .unwrap();

        let guard = owner.prefetch_lock().unwrap();
        owner.chunk_group_map.set_ready(0).unwrap();
        assert!(waiter.prefetch_lock().is_none());
        assert!(waiter.is_chunk_group_ready(0));

        drop(guard);
        assert!(waiter.prefetch_lock().is_some());
    }

    #[test]
    fn prefetch_lock_degrades_when_the_lock_file_is_unusable() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x21u8; 4096];
        let blob_metadata = single_chunk_group(&payload);
        let full_blob_id = FullBlob::new(&payload)
            .with_blob_metadata(&blob_metadata)
            .with_blob_metadata_file()
            .save_in(backend_dir.path());
        let cached = open(
            full_blob_id,
            local_backend(backend_dir.path()),
            &storage(cache_dir.path(), StorageConfig::default().fetch_size),
        )
        .unwrap();

        fs::create_dir(&cached.prefetch_lock_path).unwrap();
        assert!(cached.prefetch_lock().is_none());
        let mut buf = vec![0u8; 512];
        cached.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, payload[..512]);
    }

    #[test]
    fn read_at_ignores_a_held_prefetch_lock() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x77u8; 4096];
        let blob_metadata = single_chunk_group(&payload);
        let full_blob_id = FullBlob::new(&payload)
            .with_blob_metadata(&blob_metadata)
            .with_blob_metadata_file()
            .save_in(backend_dir.path());
        let backend = local_backend(backend_dir.path());
        let owner = open(
            full_blob_id,
            backend.clone(),
            &storage(cache_dir.path(), StorageConfig::default().fetch_size),
        )
        .unwrap();
        let reader = open(
            full_blob_id,
            backend,
            &storage(cache_dir.path(), StorageConfig::default().fetch_size),
        )
        .unwrap();

        let _guard = owner.prefetch_lock().unwrap();
        let mut buf = vec![0u8; 1024];
        reader.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, payload[..1024]);
    }

    #[test]
    fn prefetch_all_behind_another_instance_does_no_backend_work() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x42u8; 4096];
        let blob_metadata = single_chunk_group(&payload);
        let full_blob_id = FullBlob::new(&payload)
            .with_blob_metadata(&blob_metadata)
            .with_blob_metadata_file()
            .save_in(backend_dir.path());

        let backend = CountingBackend::new(backend_dir.path());
        let first = open(
            full_blob_id,
            backend.clone(),
            &storage(cache_dir.path(), StorageConfig::default().fetch_size),
        )
        .unwrap();
        let second = open(
            full_blob_id,
            backend.clone(),
            &storage(cache_dir.path(), StorageConfig::default().fetch_size),
        )
        .unwrap();

        let guard = first.prefetch_lock();
        first.prefetch_all(1, None).unwrap();
        let after_owner = backend.reads();
        assert!(after_owner > 0);

        assert!(second.prefetch_lock().is_none());
        drop(guard);

        second.prefetch_all(1, None).unwrap();
        assert_eq!(backend.reads(), after_owner);

        let mut buf = vec![0u8; 4096];
        second.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, payload);
        assert_eq!(backend.reads(), after_owner);
    }

    #[test]
    fn read_blob_metadata_rejects_a_bad_header_crc32_and_saves_nothing() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0xbdu8; 4096];
        let blob_metadata = single_chunk_group(&payload);
        let full_blob_id = FullBlob::new(&payload)
            .with_blob_metadata(&blob_metadata)
            .with_blob_metadata_file()
            .save_in(backend_dir.path());
        let blob_metadata_path = backend_dir
            .path()
            .join(format!("{}.blob.meta", hex::encode(full_blob_id)));
        let mut raw = fs::read(&blob_metadata_path).unwrap();
        raw[16] ^= 0xff;
        fs::write(&blob_metadata_path, raw).unwrap();

        let err = open(
            full_blob_id,
            local_backend(backend_dir.path()),
            &storage(cache_dir.path(), StorageConfig::default().fetch_size),
        )
        .err()
        .unwrap();

        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(err.to_string().contains("crc32"));
        assert!(!cache_dir
            .path()
            .join(format!("{}.blob.meta", hex::encode(full_blob_id)))
            .exists());
    }

    #[test]
    fn prefetch_all_rejects_a_bad_crc32_before_marking_chunk_groups_ready() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0xacu8; 4096];
        let crc32 = single_chunk_group(&payload)
            .chunk_group(0)
            .unwrap()
            .uncompressed_crc32();
        let blob_metadata = BlobMetadata::new(
            1,
            1,
            BlobMetadataCompressor::None,
            None,
            vec![
                BlobMetadataChunkGroup::new(0, 0, 0, 4096, crc32.wrapping_add(1)),
                BlobMetadataChunkGroup::new(4096, 1, 1, 0, 0),
            ],
            vec![BlobMetadataChunkLength::new(4096)],
            vec![],
            vec![],
        )
        .unwrap();
        let full_blob_id = FullBlob::new(&payload)
            .with_blob_metadata(&blob_metadata)
            .with_blob_metadata_file()
            .save_in(backend_dir.path());
        let cached = open(
            full_blob_id,
            local_backend(backend_dir.path()),
            &storage(cache_dir.path(), StorageConfig::default().fetch_size),
        )
        .unwrap();

        let err = cached.prefetch_all(4, None).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("crc32"));
        assert!(!cached.is_chunk_group_ready(0));
    }

    #[test]
    fn the_cache_files_are_named_by_the_full_blob_digest() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x3du8; 4096];
        let data_blob_id: [u8; SHA256_DIGEST_SIZE] = Sha256::digest(&payload).into();
        let blob_metadata = single_chunk_group(&payload);
        let full_blob_id = FullBlob::new(&payload)
            .with_blob_metadata(&blob_metadata)
            .save_in(backend_dir.path());
        let cached = open(
            full_blob_id,
            local_backend(backend_dir.path()),
            &storage(cache_dir.path(), StorageConfig::default().fetch_size),
        )
        .unwrap();

        let mut buf = vec![0u8; 512];
        cached.read_at(256, &mut buf).unwrap();

        assert_eq!(buf, payload[256..768]);
        assert!(cached.is_chunk_group_ready(0));
        for suffix in [".blob.data", ".blob.meta", ".group.map"] {
            assert!(cache_dir
                .path()
                .join(format!("{}{suffix}", hex::encode(full_blob_id)))
                .is_file());
        }
        assert!(!cache_dir
            .path()
            .join(format!("{}.blob.data", hex::encode(data_blob_id)))
            .exists());
    }
}
