use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::ops::Range;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::access_trace::TraceRecorder;
use crate::chunk_group_map::ChunkGroupMap;
use nydus_backend::{BlobBackend, ReadContext, ReadKind};
use nydus_format::blob::{BlobMetadata, BlobMetadataChunkGroup};
use nydus_format::erofs::EROFS_BLOCK_SIZE;
use nydus_format::utils::{hex_string, SHA256_DIGEST_SIZE};

use super::chunk_group_lock::ChunkGroupLocks;
use super::{
    plan_prefetch_batches, validate_chunk_group_with_metrics, BlobCache, ChunkGroupBuffers,
};

#[derive(Clone)]
enum FlightResult {
    Success,
    Failure {
        kind: io::ErrorKind,
        message: Arc<str>,
    },
}

/// One in-process fill in progress: the leader publishes its result, every
/// other reader of the same groups waits for it.
struct Flight {
    result: Mutex<Option<FlightResult>>,
    done: Condvar,
}

impl Flight {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            done: Condvar::new(),
        }
    }

    /// Notify every waiter of the final result. Idempotent: if a previous call
    /// (or the Drop guard) already set the result, this is a no-op.
    fn complete(&self, result: &io::Result<()>) {
        let mut guard = self.result.lock().unwrap();
        if guard.is_some() {
            return;
        }
        let result = match result {
            Ok(()) => FlightResult::Success,
            Err(err) => FlightResult::Failure {
                kind: err.kind(),
                message: Arc::from(err.to_string()),
            },
        };
        *guard = Some(result);
        self.done.notify_all();
    }

    fn wait(&self) -> io::Result<()> {
        let mut result = self.result.lock().unwrap();
        while result.is_none() {
            result = self.done.wait(result).unwrap();
        }
        match result.as_ref().unwrap() {
            FlightResult::Success => Ok(()),
            FlightResult::Failure { kind, message } => {
                Err(io::Error::new(*kind, message.to_string()))
            }
        }
    }
}

/// The plaintext blob cache: a sparse file mirroring the blob's padded
/// address space, filled chunk group by chunk group from the backend, with
/// one ready bit per group shared across the processes using the cache
/// directory.
pub struct LocalBlobCache {
    blob_id: [u8; SHA256_DIGEST_SIZE],
    /// Digest naming this blob's cache files, shared by every image that
    /// references the same blob.
    cache_key: [u8; SHA256_DIGEST_SIZE],
    /// Device/blob index in the merged image, used to attribute on-demand
    /// chunk group accesses in the access trace.
    blob_index: u32,
    /// One ready bit per chunk group (`.group.map`).
    chunk_group_map: ChunkGroupMap,
    blob_metadata: BlobMetadata,
    /// One flag per chunk group: set once the group has been recorded in the
    /// access trace, so the hot path takes the trace lock once per group.
    traced_chunk_groups: Box<[AtomicBool]>,
    cache_data_path: PathBuf,
    prefetch_lock_path: PathBuf,
    /// Lazily opened cache data file. Double-checked: reads take the read
    /// lock (per-I/O hot path), the first opener takes the write lock and
    /// re-checks. A failed open leaves the slot empty and retryable.
    cache_file: RwLock<Option<Arc<File>>>,
    backend: Arc<dyn BlobBackend>,
    trace_recorder: Option<Arc<TraceRecorder>>,
    /// In-process single flight keyed by group index; one flight covers
    /// every group of its fetch window.
    inflight: Mutex<HashMap<usize, Arc<Flight>>>,
    /// Read-only mapping of the cache data file, created once every group
    /// is ready. It serves reads by memcpy from the page cache, without
    /// the pread round-trip per request. Bytes never change after ALL_READY
    /// latches (rewrites by racing processes are byte-identical).
    cache_mmap: OnceLock<memmap2::Mmap>,
    /// Keeps the processes sharing this cache from each fetching the same
    /// cold group.
    chunk_group_locks: ChunkGroupLocks,
}

impl LocalBlobCache {
    pub fn open(
        blob_id: [u8; SHA256_DIGEST_SIZE],
        blob_index: u32,
        cache_dir: &Path,
        backend: Arc<dyn BlobBackend>,
    ) -> io::Result<Self> {
        Self::open_with_trace(blob_id, blob_index, cache_dir, backend, None)
    }

    pub fn open_with_trace(
        blob_id: [u8; SHA256_DIGEST_SIZE],
        blob_index: u32,
        cache_dir: &Path,
        backend: Arc<dyn BlobBackend>,
        trace_recorder: Option<Arc<TraceRecorder>>,
    ) -> io::Result<Self> {
        fs::create_dir_all(cache_dir)?;

        let cache_key = backend.cache_key(&blob_id)?;
        let cache_key_hex = hex_string(&cache_key);
        let blob_metadata_path = cache_dir.join(format!("{cache_key_hex}{}", BlobMetadata::SUFFIX));
        let blob_metadata =
            load_or_fetch_blob_metadata(blob_id, cache_dir, &blob_metadata_path, &backend)?;
        nydus_telemetry::metrics::track_blob_chunk_groups(
            cache_key,
            blob_metadata.chunk_group_count() as u64,
        );

        let cache_data_path = cache_dir.join(format!("{cache_key_hex}.blob.data"));

        let group_map_path = cache_dir.join(format!("{cache_key_hex}.group.map"));
        // The group map is only meaningful together with the cache data file
        // it describes: a leftover map whose data file has been removed would
        // claim groups are ready while reads hit sparse zeros. Note this
        // before creating the data file below, which would otherwise mask it.
        // (Removing the map while keeping the data is the safe direction and
        // needs no handling.)
        let stale_group_map = group_map_path.exists() && !cache_data_path.exists();

        // Create the cache data file eagerly, before the group map, so that
        // "map file exists => data file exists" holds and the check above
        // can only fire for a genuinely orphaned map.
        let data_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&cache_data_path)?;
        data_file.set_len(blob_metadata.uncompressed_size())?;
        drop(data_file);

        let chunk_group_map =
            ChunkGroupMap::open(&group_map_path, blob_metadata.chunk_group_count())?;
        if stale_group_map {
            // Reset in place rather than unlinking: handles already mapping
            // this file observe the reset, whereas a replacement inode would
            // split them off with their readiness invisible to each other.
            chunk_group_map.reset()?;
            warn!(
                "stale group map without cache data file, reset: {}",
                group_map_path.display()
            );
        }

        let prefetch_lock_path = cache_dir.join(format!("{cache_key_hex}.prefetch.lock"));
        // Byte `i` of the group map file stands for group `i` in the
        // cross-process fetch locks; the bytes locked and the bytes the map
        // stores are unrelated, so no second sidecar is needed.
        let chunk_group_locks = ChunkGroupLocks::new(group_map_path);
        let traced_chunk_groups = (0..blob_metadata.chunk_group_count())
            .map(|_| AtomicBool::new(false))
            .collect();

        Ok(Self {
            blob_id,
            cache_key,
            blob_index,
            chunk_group_map,
            blob_metadata,
            traced_chunk_groups,
            cache_data_path,
            prefetch_lock_path,
            cache_file: RwLock::new(None),
            backend,
            trace_recorder,
            inflight: Mutex::new(HashMap::new()),
            cache_mmap: OnceLock::new(),
            chunk_group_locks,
        })
    }

    /// The blob meta backing this cache (chunk groups, chunks, digests,
    /// compressor).
    pub fn blob_metadata(&self) -> &BlobMetadata {
        &self.blob_metadata
    }

    /// Whether chunk group `index` is ready.
    fn chunk_group_ready(&self, index: usize) -> io::Result<bool> {
        self.chunk_group_map.is_ready(index)
    }

    fn chunk_group(&self, index: usize) -> BlobMetadataChunkGroup {
        self.blob_metadata
            .chunk_group(index)
            .expect("chunk group index within the blob meta")
    }

    /// The groups overlapping `[offset, end)`, one blob meta lookup per end.
    fn chunk_group_span(&self, offset: u64, end: u64) -> io::Result<Range<usize>> {
        let not_found = || io::Error::new(io::ErrorKind::NotFound, "blob chunk group not found");
        let first = self
            .blob_metadata
            .chunk_group_index_of(offset)
            .ok_or_else(not_found)?;
        let last = self
            .blob_metadata
            .chunk_group_index_of(end - 1)
            .ok_or_else(not_found)?;
        Ok(first..last + 1)
    }

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
        file.set_len(self.blob_metadata.uncompressed_size())?;
        nydus_telemetry::metrics::inc_cache_opened_files();
        *cache_file = Some(file.clone());
        Ok(file)
    }

    /// Reject work against a cache data file that has been unlinked.
    ///
    /// The descriptor keeps an unlinked inode alive, so writes through it
    /// still succeed — but they land somewhere nobody else can reach, while
    /// the shared group map goes on advertising those groups as ready. Better
    /// to stop than to publish readiness for bytes other processes cannot see.
    fn ensure_data_file_linked(&self, cache_file: &File) -> io::Result<()> {
        if cache_file.metadata()?.nlink() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "cache data file was removed while in use: {}",
                    self.cache_data_path.display()
                ),
            ));
        }
        Ok(())
    }

    /// The `[offset, offset+len)` slice of the cache-file mapping when every
    /// group is ready, `None` when the blob is still filling (callers then
    /// take the ensure + pread path).
    fn all_ready_slice(&self, offset: u64, len: usize) -> io::Result<Option<&[u8]>> {
        if !self.chunk_group_map.is_all_ready() {
            return Ok(None);
        }
        let mmap = if let Some(mmap) = self.cache_mmap.get() {
            mmap
        } else {
            let file = self.cache_file()?;
            // SAFETY: the mapping is read-only and its bytes are final once
            // ALL_READY latches; concurrent identical rewrites are benign.
            let mmap = unsafe { memmap2::MmapOptions::new().map(file.as_ref())? };
            self.cache_mmap.get_or_init(|| mmap)
        };
        let end = offset
            .checked_add(len as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "blob read overflow"))?;
        if end > mmap.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "blob read beyond cache data file",
            ));
        }
        nydus_telemetry::metrics::inc_cache_hit_chunk_group();
        Ok(Some(&mmap[offset as usize..end as usize]))
    }

    /// Record an on-demand access to chunk group `index`. Per-core
    /// isolation: a cache created through NydusCore records into that core's
    /// recorder only, while FUSE-path caches (no recorder) feed the
    /// process-global trace behind the apiserver /trace endpoint.
    fn record_chunk_group_access(&self, index: usize) {
        if let Some(recorder) = self.trace_recorder.as_ref() {
            recorder.record_chunk_group_access(self.blob_index, index as u32);
        } else {
            crate::access_trace::record_chunk_group_access(self.blob_index, index as u32);
        }
    }

    /// Record every chunk group overlapping `[offset, offset + len)` in the
    /// access trace, once each, hit or miss: the trace names what the
    /// workload read, not what a fetch pulled or what was already cached.
    /// Runs ahead of the all-ready fast paths; ranges an invalid read would
    /// reject are left to the read itself.
    fn trace_range(&self, offset: u64, len: usize) {
        if self.traced_chunk_groups.is_empty() || len == 0 {
            return;
        }
        let Some(end) = offset.checked_add(len as u64) else {
            return;
        };
        let Ok(span) = self.chunk_group_span(offset, end) else {
            return;
        };
        for index in span {
            if !self.traced_chunk_groups[index].swap(true, Ordering::Relaxed) {
                self.record_chunk_group_access(index);
            }
        }
    }

    /// Ensure every group overlapping `[offset, end)` is decoded into the
    /// cache file. A missed group is fetched together with the groups of its
    /// fetch-size cell.
    fn ensure_chunk_groups(&self, offset: u64, end: u64, cache_file: &File) -> io::Result<()> {
        for index in self.chunk_group_span(offset, end)? {
            if self.chunk_group_ready(index)? {
                nydus_telemetry::metrics::inc_cache_hit_chunk_group();
            } else {
                self.ensure_chunk_group_window(index, cache_file)?;
            }
        }
        Ok(())
    }

    /// The window a miss on group `first` fetches: the groups whose encoded
    /// payloads overlap the fetch-size cell of the data region that holds
    /// `first`'s payload start, trimmed at groups that are ready or already
    /// in flight (so a cell is fetched whole, but never re-fetched). Cells
    /// are aligned, so concurrent misses in one cell plan the same window
    /// and the later ones join the first flight instead of starting an
    /// overlapping read. A zero fetch size is the missed group alone. Called
    /// with the inflight map locked so the plan and its registration are one
    /// step.
    fn plan_chunk_group_window(
        &self,
        first: usize,
        inflight: &HashMap<usize, Arc<Flight>>,
    ) -> io::Result<Range<usize>> {
        let budget = super::fetch_size();
        if budget == 0 {
            return Ok(first..first + 1);
        }
        let cell_start = self.chunk_group(first).compressed_offset() / budget * budget;
        let cell_end = cell_start + budget;
        let blocked = |index: usize| -> io::Result<bool> {
            Ok(inflight.contains_key(&index) || self.chunk_group_ready(index)?)
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

    /// Fill group `first` (and its window) into the cache file, joining an
    /// in-flight fill that already covers it.
    fn ensure_chunk_group_window(&self, first: usize, cache_file: &File) -> io::Result<()> {
        let (flight, window) = {
            let mut inflight = self.inflight.lock().unwrap();
            if let Some(flight) = inflight.get(&first) {
                let flight = flight.clone();
                drop(inflight);
                return flight.wait();
            }
            let window = self.plan_chunk_group_window(first, &inflight)?;
            let flight = Arc::new(Flight::new());
            for key in window.clone() {
                inflight.insert(key, flight.clone());
            }
            (flight, window)
        };
        // The guard unblocks every follower with an error and frees the
        // inflight slots even when the fill panics; without it a panic in the
        // fetch would leave followers stuck in `flight.wait()` forever.
        let _guard = LeaderGuard {
            flight: flight.clone(),
            keys: window.clone(),
            inflight: &self.inflight,
        };

        let result = (|| {
            if self.chunk_group_ready(first)? {
                nydus_telemetry::metrics::inc_cache_hit_chunk_group();
                return Ok(());
            }
            // Claim the window across the processes sharing this cache. The
            // in-process flight above already left a single leader per
            // group, which is what makes the descriptor-owned lock
            // meaningful here. The claim spans the whole window rather than
            // `first` alone: a peer missing a neighbouring group of the same
            // cell plans the same window, and would otherwise fetch it too.
            // Whoever waited usually finds the groups published on the way
            // out, so the trim below is what removes the duplicate backend
            // traffic.
            let _claim = self.chunk_group_locks.acquire(window.clone());
            let window = self.trim_ready(window)?;
            if window.is_empty() {
                nydus_telemetry::metrics::inc_cache_hit_chunk_group();
                return Ok(());
            }
            let mut buffers = ChunkGroupBuffers::default();
            self.fill_chunk_group_window(
                window.clone(),
                ReadKind::OnDemand,
                &mut buffers,
                cache_file,
            )?;
            for _ in window {
                nydus_telemetry::metrics::inc_cache_ondemand_fill_chunk_group();
            }
            Ok(())
        })();

        // complete() is idempotent: the guard's Drop then no-ops.
        flight.complete(&result);
        result
    }

    /// `groups` without the published groups at either end, so a window
    /// another reader or process has partly covered costs only the bytes
    /// still missing, and one fully covered costs no backend read at all.
    fn trim_ready(&self, groups: Range<usize>) -> io::Result<Range<usize>> {
        let mut start = groups.start;
        let mut end = groups.end;
        while start < end && self.chunk_group_ready(start)? {
            start += 1;
        }
        while end > start && self.chunk_group_ready(end - 1)? {
            end -= 1;
        }
        Ok(start..end)
    }

    /// Fetch and decode one prefetch batch, trimmed to the groups no other
    /// reader or process has published yet.
    fn prefetch_batch(
        &self,
        batch: Range<usize>,
        buffers: &mut ChunkGroupBuffers,
        cache_file: &File,
    ) -> io::Result<()> {
        let batch = self.trim_ready(batch)?;
        if batch.is_empty() {
            return Ok(());
        }
        self.fill_chunk_group_window(batch.clone(), ReadKind::Prefetch, buffers, cache_file)?;
        for _ in batch {
            nydus_telemetry::metrics::inc_cache_fill_chunk_group();
        }
        Ok(())
    }

    /// One backend read for the encoded payloads of the groups of `window`
    /// into `buffers`: the encoded bytes, a decode scratch the size of the
    /// group span (no group's payload is larger), and the data-region offset
    /// the encoded bytes start at.
    fn fetch_window<'b>(
        &self,
        window: &Range<usize>,
        kind: ReadKind,
        buffers: &'b mut ChunkGroupBuffers,
    ) -> io::Result<(&'b mut [u8], &'b mut [u8], u64)> {
        let head = self.chunk_group(window.start);
        let tail = self.chunk_group(window.end - 1);
        let encoded_len = usize::try_from(tail.compressed_range().end - head.compressed_offset())
            .map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "fetch size exceeds usize")
        })?;
        let decoded_len = self.blob_metadata.group_span() as usize;
        let (encoded, decoded) = buffers.resize_pair(encoded_len, decoded_len)?;
        let ctx = ReadContext::chunk_group(
            kind,
            head.uncompressed_offset(),
            tail.uncompressed_range().end - head.uncompressed_offset(),
        );
        self.backend
            .read_range_into(&self.blob_id, head.compressed_offset(), encoded, ctx)?;
        Ok((encoded, decoded, head.compressed_offset()))
    }

    /// Decode and validate `group` out of a fetched window whose encoded
    /// bytes start at data-region offset `base`; a stored-plain group
    /// borrows the window, a compressed one decodes into `decoded`.
    fn decode_group<'p>(
        &self,
        group: &BlobMetadataChunkGroup,
        base: u64,
        encoded: &'p [u8],
        decoded: &'p mut [u8],
    ) -> io::Result<&'p [u8]> {
        let start = (group.compressed_offset() - base) as usize;
        let end = start + group.compressed_size() as usize;
        let payload: &[u8] = if self.blob_metadata.is_plain(group) {
            &encoded[start..end]
        } else {
            let out = &mut decoded[..self.blob_metadata.payload_size(group) as usize];
            super::decode_chunk_group_into(
                self.blob_metadata.compressor(),
                &encoded[start..end],
                out,
            )?;
            out
        };
        validate_chunk_group_with_metrics(&self.backend, &self.blob_metadata, group, payload)?;
        Ok(payload)
    }

    /// One backend read for the groups of `window`, then decode, validate,
    /// write and publish each group that is still missing.
    fn fill_chunk_group_window(
        &self,
        window: Range<usize>,
        kind: ReadKind,
        buffers: &mut ChunkGroupBuffers,
        cache_file: &File,
    ) -> io::Result<()> {
        let (encoded, decoded, base) = self.fetch_window(&window, kind, buffers)?;
        for index in window {
            // Another process may have filled a group of the window since
            // it was planned; the leader's own group was re-checked under
            // the claim, so this only costs a bit test.
            if self.chunk_group_ready(index)? {
                continue;
            }
            let group = self.chunk_group(index);
            let payload = self.decode_group(&group, base, encoded, decoded)?;
            self.write_chunk_group(&group, payload, cache_file)?;
        }
        Ok(())
    }

    /// Fetch one REDIRECT-blob batch, trimmed at the groups `skip` accepts,
    /// and hand every decoded group to `cb`. A group that fails to decode
    /// or validate is logged and skipped; `cb` errors abort the stream.
    fn stream_redirect_batch(
        &self,
        batch: Range<usize>,
        buffers: &mut ChunkGroupBuffers,
        skip: &(dyn Fn(&BlobMetadataChunkGroup) -> bool + Sync),
        cb: &(dyn Fn(&BlobMetadataChunkGroup, &[u8]) -> io::Result<()> + Sync),
    ) -> io::Result<()> {
        let mut start = batch.start;
        let mut end = batch.end;
        while start < end && skip(&self.chunk_group(start)) {
            start += 1;
        }
        while end > start && skip(&self.chunk_group(end - 1)) {
            end -= 1;
        }
        if start == end {
            return Ok(());
        }
        let (encoded, decoded, base) =
            self.fetch_window(&(start..end), ReadKind::Prefetch, buffers)?;
        for index in start..end {
            let group = self.chunk_group(index);
            if skip(&group) {
                continue;
            }
            match self.decode_group(&group, base, encoded, decoded) {
                Ok(payload) => cb(&group, payload)?,
                Err(err) => {
                    nydus_telemetry::metrics::inc_cache_redirect_skip_chunk_group();
                    warn!(
                        "skipping redirect chunk group {index} of blob {}: {err}",
                        self.blob_index
                    );
                }
            }
        }
        Ok(())
    }

    /// Run `job` over `batches` in blob order, sequentially or through a
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
        if workers <= 1 || batches.len() == 1 {
            let mut buffers = ChunkGroupBuffers::default();
            for batch in batches {
                super::check_prefetch_deadline(deadline)?;
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
                        let result = super::check_prefetch_deadline(deadline)
                            .and_then(|()| job(&batches[index], &mut buffers));
                        if let Err(err) = result {
                            let mut slot = failure.lock().unwrap_or_else(|e| e.into_inner());
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
        match failure.into_inner().unwrap_or_else(|e| e.into_inner()) {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Scatter a validated decoded group into the cache file and publish it.
    fn write_chunk_group(
        &self,
        group: &BlobMetadataChunkGroup,
        payload: &[u8],
        cache_file: &File,
    ) -> io::Result<()> {
        let mut batch = ScatterBatch::new(cache_file);
        self.blob_metadata.for_each_decoded_chunk(
            group.index() as usize,
            payload,
            &mut |offset, bytes| batch.push(offset, bytes),
        )?;
        batch.flush()?;
        self.chunk_group_map.set_ready(group.index() as usize)
    }

    /// Ensure every group overlapping `[offset, offset + len)` is decoded and
    /// written to the cache file. Shared by `read_at` and `ensure_range`.
    fn ensure_byte_range(&self, offset: u64, len: u64, cache_file: &File) -> io::Result<()> {
        let end = offset.checked_add(len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob read range overflow")
        })?;
        if end > self.blob_metadata.uncompressed_size() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "blob read range beyond the blob",
            ));
        }

        // Fast path: the sticky all-ready flag says every group is already
        // decoded into the cache file, so skip the per-group walk entirely.
        if self.chunk_group_map.is_all_ready() {
            nydus_telemetry::metrics::inc_cache_hit_chunk_group();
            return Ok(());
        }

        self.ensure_chunk_groups(offset, end, cache_file)
    }
}

impl Drop for LocalBlobCache {
    fn drop(&mut self) {
        // Mirror the gauge updates from `open_with_trace` and `cache_file` so
        // repeatedly opening and dropping caches does not inflate them.
        // Recover from a poisoned lock: panicking in `Drop` during an unwind
        // would abort the process.
        let opened = self
            .cache_file
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some();
        if opened {
            nydus_telemetry::metrics::dec_cache_opened_files();
        }
        nydus_telemetry::metrics::untrack_blob_chunk_groups(&self.cache_key);
    }
}

impl BlobCache for LocalBlobCache {
    fn prefetch_all(&self, workers: usize, deadline: Option<Instant>) -> io::Result<()> {
        if self.blob_metadata.chunk_group_count() == 0 {
            return Ok(());
        }
        // Fast path: another process (or an earlier run) already decoded
        // every group; skip the batch planning and per-group readiness scan.
        if self.chunk_group_map.is_all_ready() {
            return Ok(());
        }

        let cache_file = self.cache_file()?;
        // Prefetch writes the bulk of the cache, so it is worth one stat to
        // make sure the file it fills is still the one other processes read.
        self.ensure_data_file_linked(&cache_file)?;

        // Prefetch owns its decode buffers and takes no group locks, so it
        // never blocks on-demand reads. The chunk group map is atomic and
        // `set_ready` is idempotent, so racing with a read at worst decodes
        // the same group twice into identical bytes at the same cache offset.
        // Batches follow the on-demand fetch size so both paths issue
        // backend reads of the same size; a zero fetch size reads group by
        // group. With several workers the first batches are single groups,
        // so the head of a blob lands in the first round trip instead of
        // behind a full batch.
        let workers = workers.max(1);
        let ramp = if workers > 1 { workers } else { 0 };
        let batches = plan_prefetch_batches(&self.blob_metadata, super::fetch_size(), ramp);
        self.run_batches(&batches, workers, deadline, &|batch, buffers| {
            self.prefetch_batch(batch.clone(), buffers, cache_file.as_ref())
        })?;

        // A successful full prefetch means every group is now ready (decoded
        // here or observed ready from another process), so guarantee the
        // sticky ALL_READY flag is latched before returning. set_ready
        // normally latches it through the shared ready counter, but a
        // historical writer crash between its bit and counter updates leaves
        // the counter short forever; the authoritative bitmap scan inside
        // latch_all_ready() latches the flag regardless.
        self.chunk_group_map.latch_all_ready();
        Ok(())
    }

    fn read_at(&self, offset: u64, dst: &mut [u8]) -> io::Result<()> {
        if dst.is_empty() {
            return Ok(());
        }
        self.trace_range(offset, dst.len());

        if let Some(mapped) = self.all_ready_slice(offset, dst.len())? {
            dst.copy_from_slice(mapped);
            return Ok(());
        }

        let cache_file = self.cache_file()?;
        self.ensure_byte_range(offset, dst.len() as u64, cache_file.as_ref())?;

        // The cache file mirrors the padded address space, so once the
        // covering groups are decoded the absolute offset indexes straight
        // into it for a single contiguous read.
        cache_file.as_ref().read_exact_at(dst, offset)
    }

    fn write_data_to(&self, offset: u64, len: usize, writer: &mut dyn io::Write) -> io::Result<()> {
        if len == 0 {
            return Ok(());
        }
        if let Some(mapped) = self.all_ready_slice(offset, len)? {
            self.trace_range(offset, len);
            return writer.write_all(mapped);
        }
        super::write_data_via_scratch(self, offset, len, writer)
    }

    fn prepare(&self) -> io::Result<PathBuf> {
        // Opening the cache file creates it (sparse) and sizes it to the
        // padded address space.
        self.cache_file()?;
        Ok(self.cache_data_path.clone())
    }

    fn cache_fd(&self) -> io::Result<RawFd> {
        Ok(self.cache_file()?.as_raw_fd())
    }

    fn ensure_range(&self, offset: u64, len: u64) -> io::Result<()> {
        if len == 0 {
            return Ok(());
        }
        self.trace_range(offset, usize::try_from(len).unwrap_or(usize::MAX));
        let cache_file = self.cache_file()?;
        self.ensure_byte_range(offset, len, cache_file.as_ref())
    }

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
            if !self.chunk_group_ready(index)? {
                continue;
            }
            let slot = self.chunk_group(index).uncompressed_range();
            let range = slot.start.max(offset)..slot.end.min(end);
            match ready.last_mut() {
                Some(run) if run.end == range.start => run.end = range.end,
                _ => ready.push(range),
            }
        }
        Ok(ready)
    }

    fn is_redirect(&self) -> bool {
        self.blob_metadata.is_redirect()
    }

    fn is_chunk_group_ready(&self, chunk_group_index: usize) -> bool {
        self.chunk_group_map
            .is_ready(chunk_group_index)
            .unwrap_or(false)
    }

    fn for_each_redirect_chunk_group(
        &self,
        workers: usize,
        deadline: Option<Instant>,
        skip: &(dyn Fn(&BlobMetadataChunkGroup) -> bool + Sync),
        cb: &(dyn Fn(&BlobMetadataChunkGroup, &[u8]) -> io::Result<()> + Sync),
    ) -> io::Result<()> {
        if !self.blob_metadata.is_redirect() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "blob is not a redirect blob",
            ));
        }
        if self.blob_metadata.chunk_group_count() == 0 {
            return Ok(());
        }
        // Same batching as a blob's own prefetch: fetch-size batches with a
        // single-group ramp at the head, so the workload's first reads land
        // in the first round trip. Batches made entirely of groups the
        // sources already hold are trimmed away before any backend read.
        let workers = workers.max(1);
        let ramp = if workers > 1 { workers } else { 0 };
        let batches = plan_prefetch_batches(&self.blob_metadata, super::fetch_size(), ramp);
        self.run_batches(&batches, workers, deadline, &|batch, buffers| {
            self.stream_redirect_batch(batch.clone(), buffers, skip, cb)
        })
    }

    fn fill_chunk_group_from_redirect(
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
        if self.chunk_group_ready(chunk_group_index)? {
            nydus_telemetry::metrics::inc_cache_hit_chunk_group();
            return Ok(());
        }
        // Cross-check against this blob's own metadata: the redirect group's
        // crc32 and chunk lengths were copied from this group at optimize
        // time, so any divergence (stale optimize artifact, corrupted
        // transfer) is caught here before it can poison the cache.
        validate_chunk_group_with_metrics(&self.backend, &self.blob_metadata, &group, payload)?;
        let cache_file = self.cache_file()?;
        self.write_chunk_group(&group, payload, cache_file.as_ref())?;
        nydus_telemetry::metrics::inc_cache_redirect_fill_chunk_group();
        Ok(())
    }

    /// Acquire the per-blob cross-process prefetch lock, blocking (in 1s
    /// polls) while another process holds it. Modeled after the nydus blob
    /// prefetcher: locking failures degrade to prefetching without the lock
    /// rather than failing the prefetch, and the guard is released when the
    /// returned file is dropped — including on process death, so a crashed
    /// owner's lock is taken over and the group-map-driven skip logic resumes
    /// where it left off.
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
                    "failed to open prefetch lock {}: {err} (prefetching without cross-process lock)",
                    self.prefetch_lock_path.display()
                );
                return None;
            }
        };

        let mut contention_logged = false;
        loop {
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
                    "failed to acquire prefetch lock for blob {}: {err} (prefetching without cross-process lock)",
                    self.blob_index
                );
                return None;
            }
            // Another process is prefetching this blob. The shared group map
            // tells us when the owner has finished everything, so we can
            // stop waiting; the caller's prefetch then reduces to a cheap
            // all-ready scan.
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
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    fn is_all_ready(&self) -> bool {
        self.chunk_group_map.is_all_ready()
    }
}

fn load_or_fetch_blob_metadata(
    blob_id: [u8; SHA256_DIGEST_SIZE],
    cache_dir: &Path,
    blob_metadata_path: &Path,
    backend: &Arc<dyn BlobBackend>,
) -> io::Result<BlobMetadata> {
    if !blob_metadata_path.is_file() {
        // `O_EXCL` creation keeps the name unique against other processes
        // sharing this cache dir, and drops the file if we bail out early.
        let tmp = tempfile::Builder::new()
            .prefix(".blob-meta-")
            .suffix(".tmp")
            .tempfile_in(cache_dir)?;
        backend.save_blob_metadata(&blob_id, tmp.path())?;
        if let Err(err) = BlobMetadata::from_path(tmp.path()) {
            return Err(io::Error::other(err));
        }
        tmp.persist(blob_metadata_path).map_err(|err| err.error)?;
    }

    BlobMetadata::from_path(blob_metadata_path).map_err(io::Error::other)
}

/// Drop guard that ensures a leader always signals its flight and cleans up
/// the inflight map, even when the fill body panics.
struct LeaderGuard<'a> {
    flight: Arc<Flight>,
    /// The inflight keys this leader registered: every group of its window.
    keys: Range<usize>,
    inflight: &'a Mutex<HashMap<usize, Arc<Flight>>>,
}

impl<'a> Drop for LeaderGuard<'a> {
    fn drop(&mut self) {
        // complete is idempotent: if the leader called `flight.complete(...)`
        // normally before Drop runs, this is a no-op.
        self.flight.complete(&Err(io::Error::other(
            "chunk group leader panicked or was abandoned",
        )));
        let mut inflight = self.inflight.lock().unwrap();
        for key in self.keys.clone() {
            inflight.remove(&key);
        }
    }
}

static ZERO_BLOCK: [u8; EROFS_BLOCK_SIZE as usize] = [0u8; EROFS_BLOCK_SIZE as usize];

/// Gathers scattered chunks into contiguous `pwritev` runs.
struct ScatterBatch<'a> {
    file: &'a File,
    iov: Vec<libc::iovec>,
    payload: std::marker::PhantomData<&'a [u8]>,
    run_start: u64,
    run_end: u64,
    max_iov: usize,
}

impl<'a> ScatterBatch<'a> {
    fn new(file: &'a File) -> Self {
        // SAFETY: sysconf has no preconditions; a failure returns -1.
        let iov_max = unsafe { libc::sysconf(libc::_SC_IOV_MAX) };
        Self {
            file,
            iov: Vec::new(),
            payload: std::marker::PhantomData,
            run_start: 0,
            run_end: 0,
            max_iov: usize::try_from(iov_max).unwrap_or(1024).clamp(2, 1024),
        }
    }

    fn push(&mut self, offset: u64, bytes: &'a [u8]) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        // Start a new run when this is the first chunk, the chunk is not
        // past the run's end (never happens for a valid layout), the gap
        // spans a whole block or the batch is full (leaving room for the
        // gap and the chunk).
        let gap = offset.saturating_sub(self.run_end);
        if self.iov.is_empty()
            || offset < self.run_end
            || gap >= EROFS_BLOCK_SIZE as u64
            || self.iov.len() + 2 > self.max_iov
        {
            self.flush()?;
            self.run_start = offset;
            self.run_end = offset;
        } else if gap > 0 {
            self.iov.push(libc::iovec {
                iov_base: ZERO_BLOCK.as_ptr() as *mut libc::c_void,
                iov_len: gap as usize,
            });
        }
        self.iov.push(libc::iovec {
            iov_base: bytes.as_ptr() as *mut libc::c_void,
            iov_len: bytes.len(),
        });
        self.run_end = offset + bytes.len() as u64;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut offset = self.run_start;
        let mut iov = std::mem::take(&mut self.iov);
        let mut first = 0usize;
        while first < iov.len() {
            // SAFETY: push borrows all payloads for 'a; every pointer remains valid until flush completes.
            let written = unsafe {
                libc::pwritev(
                    self.file.as_raw_fd(),
                    iov[first..].as_ptr(),
                    (iov.len() - first) as libc::c_int,
                    offset as libc::off_t,
                )
            };
            if written < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "cache file write returned zero",
                ));
            }
            offset += written as u64;
            let mut remaining = written as usize;
            while remaining > 0 {
                let entry = &mut iov[first];
                if remaining >= entry.iov_len {
                    remaining -= entry.iov_len;
                    first += 1;
                } else {
                    // SAFETY: remaining is smaller than this iovec's borrowed slice length.
                    entry.iov_base = unsafe { (entry.iov_base as *mut u8).add(remaining) }.cast();
                    entry.iov_len -= remaining;
                    remaining = 0;
                }
            }
        }
        iov.clear();
        self.iov = iov;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_util::{encode_blob, padded_image};
    use super::*;
    use nydus_backend::Local;
    use nydus_format::blob::BlobMetadataCompressor;
    use nydus_format::utils::write_minimal_full_blob;
    use std::path::Path;
    use std::sync::atomic::AtomicUsize;
    use tempfile::tempdir;

    /// Serializes the tests that set the process-wide fetch size or
    /// verification switch, which would otherwise race across test threads.
    static ENV: Mutex<()> = Mutex::new(());

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Chunk groups as lists of chunks.
    type Groups = Vec<Vec<Vec<u8>>>;

    /// A one-group plain blob of one 4 KiB chunk.
    fn blob_metadata(payload: &[u8]) -> BlobMetadata {
        encode_blob(
            BlobMetadataCompressor::None,
            4096,
            &[vec![payload.to_vec()]],
            false,
        )
        .1
    }

    /// Four zstd groups of 16 KiB chunks, each a pack of three 4 KiB chunks
    /// and one 100 bytes short of a block (so every group ends in a zero
    /// tail), with BLAKE3 digests. Returns the data region, the meta, the
    /// groups and the padded image (the fully filled cache file), in which
    /// group `i` spans `i * 16384..(i + 1) * 16384`.
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
        let (data, meta) = encode_blob(BlobMetadataCompressor::Zstd, 16384, &groups, true);
        let image = padded_image(&groups);
        (data, meta, groups, image)
    }

    fn open(
        full_blob_id: [u8; SHA256_DIGEST_SIZE],
        cache_dir: &Path,
        backend: Arc<CountingBackend>,
    ) -> LocalBlobCache {
        LocalBlobCache::open(full_blob_id, 1, cache_dir, backend as Arc<dyn BlobBackend>).unwrap()
    }

    /// With a zero window a miss fetches its own group only; a window
    /// covering the blob fills every group in one read, and reads within a
    /// ready group cost no backend traffic.
    #[test]
    fn reads_fill_group_windows() {
        let _env = env_lock();
        let backend_dir = tempdir().unwrap();
        let (data, meta, _, image) = groups_blob();
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &data, &meta, true);

        super::super::set_fetch_size(0);
        let cache_dir = tempdir().unwrap();
        let backend = CountingBackend::new(backend_dir.path());
        let cached = open(full_blob_id, cache_dir.path(), backend.clone());
        assert_eq!(cached.blob_metadata().chunk_group_count(), 4);

        let mut buf = vec![0u8; 100];
        cached.read_at(16384 + 10, &mut buf).unwrap();
        assert_eq!(buf, image[16394..16494]);
        assert_eq!(backend.reads(), 1);
        assert!(cached.is_chunk_group_ready(1));
        assert!(!cached.is_chunk_group_ready(0));
        assert!(!cached.is_chunk_group_ready(2));

        // The last chunk's zero tail reads back without a fetch.
        cached.read_at(16384 + 16383 - 99, &mut buf).unwrap();
        assert!(buf.iter().all(|b| *b == 0));
        assert_eq!(backend.reads(), 1);

        cached.read_at(4096, &mut buf).unwrap();
        assert_eq!(buf, image[4096..4196]);
        assert_eq!(backend.reads(), 2);
        assert!(cached.is_chunk_group_ready(0));
        assert!(!cached.chunk_group_map.is_all_ready());

        super::super::set_fetch_size(1 << 20);
        let cache_dir = tempdir().unwrap();
        let backend = CountingBackend::new(backend_dir.path());
        let cached = open(full_blob_id, cache_dir.path(), backend.clone());
        let mut all = vec![0u8; image.len()];
        cached.read_at(0, &mut all).unwrap();
        assert_eq!(all, image);
        assert_eq!(backend.reads(), 1);
        assert!(cached.chunk_group_map.is_all_ready());
        assert_eq!(fs::read(&cached.cache_data_path).unwrap(), image);
    }

    /// The fetch size is measured in compressed bytes and aligned on the
    /// data region: a miss pulls the groups overlapping its cell and no
    /// more, and a later miss in the same cell finds them ready.
    #[test]
    fn fetch_size_cells_bound_a_miss() {
        let _env = env_lock();
        let backend_dir = tempdir().unwrap();
        let (data, meta, _, image) = groups_blob();
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &data, &meta, true);
        let cache_dir = tempdir().unwrap();
        let backend = CountingBackend::new(backend_dir.path());
        let cached = open(full_blob_id, cache_dir.path(), backend.clone());

        // Two groups' worth of compressed bytes: a window from the start of
        // the data region covers groups 0 and 1 (and whatever of group 2
        // overlaps the cell), never the whole blob.
        let two = meta.chunk_group(1).unwrap().compressed_range().end;
        super::super::set_fetch_size(two);
        let mut buf = vec![0u8; 16];
        cached.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, image[..16]);
        assert_eq!(backend.reads(), 1);
        assert!(cached.is_chunk_group_ready(0));
        assert!(cached.is_chunk_group_ready(1));
        assert!(!cached.is_chunk_group_ready(3));
        cached.read_at(16384, &mut buf).unwrap();
        assert_eq!(backend.reads(), 1, "group 1 came with group 0's window");
        cached.read_at(3 * 16384, &mut buf).unwrap();
        assert_eq!(buf, image[3 * 16384..3 * 16384 + 16]);
        assert_eq!(backend.reads(), 2);
        assert!(cached.chunk_group_map.is_all_ready());
    }

    /// With verification on, a group whose chunk digest does not match is
    /// rejected before it is published; a crc mismatch is rejected always.
    #[test]
    fn reads_reject_bad_digests_and_checksums() {
        let _env = env_lock();
        super::super::set_skip_verify_checksums(false);
        super::super::set_fetch_size(0);
        let backend_dir = tempdir().unwrap();
        let (data, meta, groups, _) = groups_blob();
        let mut digests = meta.digests().to_vec();
        digests[1] = nydus_format::blob::BlobMetadataDigest::new([0u8; 32]);
        let members: Vec<u32> = (0..meta.chunk_count())
            .map(|index| meta.chunk_len(index).unwrap())
            .collect();
        let specs: Vec<_> = meta
            .chunk_groups()
            .enumerate()
            .map(|(index, group)| {
                nydus_format::blob::BlobMetadataChunkGroup::new(
                    group.compressed_size(),
                    group.payload_size(),
                    group.chunk_count(),
                    if index == 2 {
                        group.payload_crc32() ^ 1
                    } else {
                        group.payload_crc32()
                    },
                    None,
                )
                .unwrap()
            })
            .collect();
        let meta = BlobMetadata::new(
            BlobMetadataCompressor::Zstd,
            nydus_format::blob::BlobMetadataDigester::Blake3,
            16384,
            4096,
            specs,
            members,
            digests,
        )
        .unwrap();
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &data, &meta, true);

        let cache_dir = tempdir().unwrap();
        let backend = CountingBackend::new(backend_dir.path());
        let cached = open(full_blob_id, cache_dir.path(), backend);
        let mut buf = vec![0u8; 100];
        let err = cached.read_at(16384, &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("chunk group 1 digest mismatch"));
        assert!(!cached.is_chunk_group_ready(1));
        let err = cached.read_at(2 * 16384, &mut buf).unwrap_err();
        assert!(super::super::is_chunk_group_crc_mismatch(&err));
        assert!(!cached.is_chunk_group_ready(2));
        cached.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, groups[0][0][..100]);
    }

    /// Prefetch fills the whole blob in window-sized batches and skips the
    /// groups other readers already published.
    #[test]
    fn prefetch_fills_in_batches_and_skips_ready_groups() {
        let _env = env_lock();
        let backend_dir = tempdir().unwrap();
        let (data, meta, _, image) = groups_blob();
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &data, &meta, true);
        let cache_dir = tempdir().unwrap();
        let backend = CountingBackend::new(backend_dir.path());
        let cached = open(full_blob_id, cache_dir.path(), backend.clone());

        super::super::set_fetch_size(0);
        let mut buf = vec![0u8; 16];
        cached.read_at(2 * 16384, &mut buf).unwrap();
        assert_eq!(backend.reads(), 1);

        // One group per batch: three more reads for the three cold groups.
        cached.prefetch_all(1, None).unwrap();
        assert_eq!(backend.reads(), 4);
        assert!(cached.chunk_group_map.is_all_ready());
        assert_eq!(fs::read(&cached.cache_data_path).unwrap(), image);
        cached.prefetch_all(1, None).unwrap();
        assert_eq!(backend.reads(), 4);

        // A generous window prefetches a cold blob in one read.
        super::super::set_fetch_size(1 << 20);
        let cache_dir = tempdir().unwrap();
        let backend = CountingBackend::new(backend_dir.path());
        let cached = open(full_blob_id, cache_dir.path(), backend.clone());
        cached.prefetch_all(1, None).unwrap();
        assert_eq!(backend.reads(), 1);
        assert!(cached.is_all_ready());

        // A worker pool ramps with single-group batches (one read each for
        // the first `workers` groups), then streams the rest in windows, and
        // still leaves the blob fully and correctly cached.
        super::super::set_fetch_size(8192);
        let cache_dir = tempdir().unwrap();
        let backend = CountingBackend::new(backend_dir.path());
        let cached = open(full_blob_id, cache_dir.path(), backend.clone());
        cached.prefetch_all(2, None).unwrap();
        assert_eq!(backend.reads(), 3, "2 ramp reads + 1 window of 2 groups");
        assert!(cached.is_all_ready());
        assert_eq!(fs::read(&cached.cache_data_path).unwrap(), image);
    }

    /// Every chunk group a read touches lands in the trace once, hit or miss.
    #[test]
    fn reads_trace_the_chunk_groups_they_touch() {
        let _env = env_lock();
        let backend_dir = tempdir().unwrap();
        let (data, meta, _, image) = groups_blob();
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &data, &meta, true);
        let cache_dir = tempdir().unwrap();
        let backend = CountingBackend::new(backend_dir.path());
        let recorder = Arc::new(TraceRecorder::default());
        let cached = LocalBlobCache::open_with_trace(
            full_blob_id,
            7,
            cache_dir.path(),
            backend as Arc<dyn BlobBackend>,
            Some(recorder.clone()),
        )
        .unwrap();
        super::super::set_fetch_size(1 << 20);
        let mut buf = vec![0u8; 8192];
        // Chunks 5 and 6 of group 1 (group offsets 4 KiB and 8 KiB).
        cached.read_at(16384 + 4096, &mut buf).unwrap();
        assert_eq!(buf, image[16384 + 4096..16384 + 12288]);
        // A second read of the same bytes, now all ready, adds nothing.
        cached.read_at(16384 + 4096, &mut buf).unwrap();
        // A read into another group names that group, once.
        cached.read_at(3 * 16384, &mut buf[..16]).unwrap();
        cached.read_at(3 * 16384 + 16, &mut buf[..16]).unwrap();
        let entries: Vec<(u32, u32)> = recorder
            .snapshot()
            .entries
            .iter()
            .map(|entry| (entry.blob_index, entry.chunk_group_index))
            .collect();
        assert_eq!(entries, vec![(7, 1), (7, 3)]);
    }

    /// Scattered chunks reach their padded offsets with zero tail gaps,
    /// whole-block gaps stay unwritten, and runs split at the iovec limit.
    #[test]
    fn scatter_batch_gathers_chunks_into_contiguous_runs() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cache");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let block = EROFS_BLOCK_SIZE as u64;
        // (offset, fill, len): tail gaps below a block between chunks, then a
        // two-block hole before the last chunk.
        let chunks = [
            (0, 0xa1u8, 100usize),
            (block, 0xb2, 5000),
            (3 * block, 0xc3, 40),
            (6 * block, 0xd4, 4096),
            (7 * block, 0xe5, 1),
        ];
        let data: Vec<Vec<u8>> = chunks.iter().map(|(_, b, n)| vec![*b; *n]).collect();
        let mut expected = vec![0u8; 7 * block as usize + 1];
        for ((offset, _, _), bytes) in chunks.iter().zip(&data) {
            expected[*offset as usize..*offset as usize + bytes.len()].copy_from_slice(bytes);
        }

        for max_iov in [2usize, 3, 1024] {
            file.set_len(0).unwrap();
            let mut batch = ScatterBatch::new(&file);
            batch.max_iov = max_iov;
            for ((offset, _, _), bytes) in chunks.iter().zip(&data) {
                batch.push(*offset, bytes).unwrap();
            }
            batch.flush().unwrap();
            let written = fs::read(&path).unwrap();
            assert_eq!(written, expected, "max_iov {max_iov}");
        }

        // The whole-block hole before block 6 is never written: the file is
        // sparse there (best effort, so only the content is asserted above)
        // and the run restarts at the hole's end.
        let mut batch = ScatterBatch::new(&file);
        batch.push(3 * block, &data[2]).unwrap();
        assert_eq!(batch.iov.len(), 1);
        batch.push(6 * block, &data[3]).unwrap();
        assert_eq!(batch.iov.len(), 1, "a whole-block gap starts a new run");
        assert_eq!(batch.run_start, 6 * block);
        batch.push(7 * block, &data[4]).unwrap();
        assert_eq!(batch.iov.len(), 2, "back-to-back blocks share a run");
        batch.flush().unwrap();
    }

    /// Wraps a real backend and counts data-range reads, so tests can assert
    /// that cross-process sharing (group map + prefetch lock + batch skip)
    /// actually eliminates duplicate backend traffic.
    struct CountingBackend {
        inner: Local,
        reads: AtomicUsize,
    }

    impl CountingBackend {
        fn new(dir: &Path) -> Arc<Self> {
            Arc::new(Self {
                inner: Local::new(dir.to_path_buf()),
                reads: AtomicUsize::new(0),
            })
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl BlobBackend for CountingBackend {
        fn blob_metadata(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<BlobMetadata> {
            self.inner.blob_metadata(blob_id)
        }

        fn read_range_into(
            &self,
            blob_id: &[u8; SHA256_DIGEST_SIZE],
            offset: u64,
            dst: &mut [u8],
            ctx: ReadContext,
        ) -> io::Result<()> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.read_range_into(blob_id, offset, dst, ctx)
        }
    }

    #[test]
    fn local_blob_cache_fetches_from_local_backend() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0xceu8; 4096];
        let meta = blob_metadata(&payload);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, true);

        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));
        let cached = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();

        let mut buf = vec![0u8; 1024];
        cached.read_at(512, &mut buf).unwrap();

        assert_eq!(buf, payload[512..1536]);
        assert!(cached.is_chunk_group_ready(0));
        assert!(!cached.is_redirect());
        assert!(cached.read_at(4096, &mut buf).is_err());
    }

    #[test]
    fn stale_group_map_without_data_file_is_reset() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x3du8; 4096];
        let meta = blob_metadata(&payload);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, true);
        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));

        // Warm the cache: data file created, group marked ready, sticky
        // all-ready flag latched.
        {
            let cached =
                LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend.clone()).unwrap();
            let mut buf = vec![0u8; 1024];
            cached.read_at(0, &mut buf).unwrap();
            assert!(cached.chunk_group_map.is_all_ready());
        }

        // Model the operational accident: the data file is removed while the
        // group map survives. Reopening must reset the group map instead of
        // trusting ready bits that now point at sparse holes.
        let cache_key = backend.cache_key(&full_blob_id).unwrap();
        let prefix = hex_string(&cache_key);
        fs::remove_file(cache_dir.path().join(format!("{prefix}.blob.data"))).unwrap();

        let reopened = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();
        assert!(!reopened.is_chunk_group_ready(0));
        assert!(!reopened.chunk_group_map.is_all_ready());

        // The blob still reads correctly end-to-end after the reset.
        let mut buf = vec![0u8; 1024];
        reopened.read_at(512, &mut buf).unwrap();
        assert_eq!(buf, payload[512..1536]);
    }

    #[test]
    fn stale_group_map_reset_keeps_the_same_inode() {
        use std::os::unix::fs::MetadataExt;

        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x2eu8; 4096];
        let meta = blob_metadata(&payload);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, true);
        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));

        // A live handle keeps the group map mapped throughout, standing in for
        // a process that is already running when the accident happens.
        let live =
            LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend.clone()).unwrap();
        let mut buf = vec![0u8; 1024];
        live.read_at(0, &mut buf).unwrap();
        assert!(live.is_chunk_group_ready(0));

        let cache_key = backend.cache_key(&full_blob_id).unwrap();
        let prefix = hex_string(&cache_key);
        let group_map_path = cache_dir.path().join(format!("{prefix}.group.map"));
        let before = fs::metadata(&group_map_path).unwrap().ino();
        fs::remove_file(cache_dir.path().join(format!("{prefix}.blob.data"))).unwrap();

        let reopened = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();
        assert_eq!(
            fs::metadata(&group_map_path).unwrap().ino(),
            before,
            "the reset must not replace the group map file"
        );

        // Because the inode is unchanged, the reset is visible through the
        // mapping the live handle already holds; a replacement inode would
        // have left it advertising readiness nobody else can see.
        assert!(!live.is_chunk_group_ready(0));
        assert!(!reopened.is_chunk_group_ready(0));
    }

    #[test]
    fn prefetch_lock_dedups_across_handles() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x5au8; 4096];
        let meta = blob_metadata(&payload);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, true);

        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));
        // Two handles on the same cache directory model two concurrent
        // processes (flock contention applies across file descriptors even
        // within one process).
        let owner =
            LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend.clone()).unwrap();
        let waiter = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();

        let guard = owner.prefetch_lock().expect("first handle takes the lock");

        // The owner finished all groups: the contender must give up on the
        // lock (returning None) instead of waiting, since the shared group map
        // already reports everything ready.
        owner.chunk_group_map.set_ready(0).unwrap();
        assert!(waiter.prefetch_lock().is_none());
        assert!(waiter.is_chunk_group_ready(0));

        // Once the owner releases the lock, it is acquirable again.
        drop(guard);
        assert!(waiter.prefetch_lock().is_some());
    }

    #[test]
    fn prefetch_lock_degrades_when_lock_file_unusable() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x21u8; 4096];
        let meta = blob_metadata(&payload);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, true);

        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));
        let cached = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();

        // Make the lock path unopenable for writing (it is a directory):
        // locking must degrade to None instead of failing or hanging, and the
        // blob must still be readable.
        fs::create_dir(&cached.prefetch_lock_path).unwrap();
        assert!(cached.prefetch_lock().is_none());
        let mut buf = vec![0u8; 512];
        cached.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, payload[..512]);
    }

    #[test]
    fn on_demand_reads_ignore_a_held_prefetch_lock() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x77u8; 4096];
        let meta = blob_metadata(&payload);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, true);

        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));
        let owner =
            LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend.clone()).unwrap();
        let reader = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();

        // Another instance holds the prefetch lock; the on-demand read path
        // must proceed immediately (fetch the cold group itself) rather than
        // queueing behind the lock.
        let _guard = owner.prefetch_lock().expect("owner takes the lock");
        let mut buf = vec![0u8; 1024];
        reader.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, payload[..1024]);
    }

    #[test]
    fn prefetch_behind_another_instance_does_no_backend_work() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x42u8; 4096];
        let meta = blob_metadata(&payload);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, true);

        let backend = CountingBackend::new(backend_dir.path());
        let first = open(full_blob_id, cache_dir.path(), backend.clone());
        let second = open(full_blob_id, cache_dir.path(), backend.clone());

        // The "owner" instance prefetches everything from the backend.
        let guard = first.prefetch_lock();
        first.prefetch_all(1, None).unwrap();
        let after_owner = backend.reads();
        assert!(after_owner > 0, "owner must stream from the backend");

        // While the owner still holds the lock, a contending instance sees
        // every group ready through the shared group map and gives up on the
        // lock (None) instead of waiting.
        assert!(second.prefetch_lock().is_none());
        drop(guard);

        // Repeating the prefetch afterwards issues zero backend reads: every
        // group is already ready in the shared cache.
        second.prefetch_all(1, None).unwrap();
        assert_eq!(backend.reads(), after_owner, "waiter must not re-download");

        // Cross-handle on-demand reads are also served from the shared cache.
        let mut buf = vec![0u8; 4096];
        second.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, payload);
        assert_eq!(backend.reads(), after_owner);
    }

    #[test]
    fn local_blob_cache_rejects_bad_blob_metadata_header_crc32() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0xbdu8; 4096];
        let meta = blob_metadata(&payload);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, true);
        let blob_metadata_path = backend_dir
            .path()
            .join(format!("{}.blob.meta", hex_string(&full_blob_id)));
        let mut raw = fs::read(&blob_metadata_path).unwrap();
        // Flip a byte of the header crc32 field (offset 16 in the v1 header).
        raw[16] ^= 0xff;
        fs::write(&blob_metadata_path, raw).unwrap();

        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));
        let err = match LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend) {
            Ok(_) => panic!("corrupted blob meta crc32 should be rejected"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(err.to_string().contains("crc32"));
        assert!(!cache_dir
            .path()
            .join(format!("{}.blob.meta", hex_string(&full_blob_id)))
            .exists());
    }

    /// Prefetch validates each decoded group against its crc32 before
    /// publishing it.
    #[test]
    fn prefetch_rejects_bad_crc32_before_marking_groups_ready() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0xacu8; 4096];
        let meta = BlobMetadata::new(
            BlobMetadataCompressor::None,
            nydus_format::blob::BlobMetadataDigester::None,
            4096,
            4096,
            vec![nydus_format::blob::BlobMetadataChunkGroup::new(
                4096,
                4096,
                1,
                crc32c::crc32c(&payload).wrapping_add(1),
                None,
            )
            .unwrap()],
            vec![4096],
            vec![],
        )
        .unwrap();
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, true);

        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));
        let cached = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();

        let err = cached.prefetch_all(4, None).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("crc32"));
        assert!(!cached.is_chunk_group_ready(0));
    }

    #[test]
    fn local_blob_cache_reads_data_region_relative_compressed_offsets() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x3du8; 4096];
        let data_blob_id = nydus_format::utils::sha256_bytes(&payload);
        let meta = blob_metadata(&payload);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, false);

        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));
        let cached = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();

        let mut buf = vec![0u8; 512];
        cached.read_at(256, &mut buf).unwrap();

        assert_eq!(buf, payload[256..768]);
        assert!(cached.is_chunk_group_ready(0));
        for suffix in [".blob.data", ".blob.meta", ".group.map"] {
            assert!(cache_dir
                .path()
                .join(format!("{}{suffix}", hex_string(&full_blob_id)))
                .is_file());
        }
        assert!(!cache_dir
            .path()
            .join(format!("{}.blob.data", hex_string(&data_blob_id)))
            .exists());
    }
}
