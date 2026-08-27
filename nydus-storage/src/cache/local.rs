use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::ops::Range;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::access_trace::TraceRecorder;
use crate::block_group_map::BlockGroupMap;
use nydus_backend::{BlobBackend, ReadContext, ReadKind};
use nydus_format::blob::{
    BlobMetadata, BlobMetadataBlockGroup, DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_SIZE,
    NYDUS_BLOB_METADATA_SUFFIX,
};
use nydus_format::utils::{hex_string, SHA256_DIGEST_SIZE};

use super::block_group_lock::BlockGroupLocks;
use super::{
    decode_block_group_from_window, fetch_decode_validate_block_group_into, plan_prefetch_batches,
    BlobCache, BlockGroupBuffers,
};

#[derive(Clone)]
enum BlockGroupFlightResult {
    Success,
    Failure {
        kind: io::ErrorKind,
        message: Arc<str>,
    },
}

struct BlockGroupFlight {
    result: Mutex<Option<BlockGroupFlightResult>>,
    done: Condvar,
}

impl BlockGroupFlight {
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
            Ok(()) => BlockGroupFlightResult::Success,
            Err(err) => BlockGroupFlightResult::Failure {
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
            BlockGroupFlightResult::Success => Ok(()),
            BlockGroupFlightResult::Failure { kind, message } => {
                Err(io::Error::new(*kind, message.to_string()))
            }
        }
    }
}

pub struct LocalBlobCache {
    blob_id: [u8; SHA256_DIGEST_SIZE],
    /// Digest naming this blob's cache files, shared by every image that
    /// references the same blob.
    cache_key: [u8; SHA256_DIGEST_SIZE],
    /// Device/blob index in the merged image, used to attribute on-demand block group
    /// accesses in the access trace.
    blob_index: u32,
    block_group_map: BlockGroupMap,
    blob_metadata: BlobMetadata,
    cache_data_path: PathBuf,
    prefetch_lock_path: PathBuf,
    /// Lazily opened cache data file. Double-checked: reads take the read
    /// lock (per-I/O hot path), the first opener takes the write lock and
    /// re-checks. A failed open leaves the slot empty and retryable.
    cache_file: RwLock<Option<Arc<File>>>,
    backend: Arc<dyn BlobBackend>,
    trace_recorder: Option<Arc<TraceRecorder>>,
    inflight_block_groups: Mutex<HashMap<usize, Arc<BlockGroupFlight>>>,
    /// Read-only mapping of the cache data file, created once every block
    /// group is ready. It serves reads by memcpy from the page cache, without
    /// the pread round-trip per request. Bytes never change after ALL_READY
    /// latches (rewrites by racing processes are byte-identical).
    cache_mmap: OnceLock<memmap2::Mmap>,
    /// Keeps the processes sharing this cache from each fetching the same
    /// cold block group.
    block_group_locks: BlockGroupLocks,
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
        let blob_metadata_path =
            cache_dir.join(format!("{cache_key_hex}{NYDUS_BLOB_METADATA_SUFFIX}"));
        let blob_metadata =
            load_or_fetch_blob_metadata(blob_id, cache_dir, &blob_metadata_path, &backend)?;
        nydus_telemetry::metrics::track_blob_block_groups(
            cache_key,
            blob_metadata.block_group_count() as u64,
        );

        let cache_data_path = cache_dir.join(format!("{cache_key_hex}.blob.data"));

        let block_group_map_path = cache_dir.join(format!("{cache_key_hex}.group.map"));
        // The block_group_map is only meaningful together with the cache data file it
        // describes: a leftover block_group_map whose data file has been removed
        // would claim block groups are ready while reads hit sparse zeros. Note this
        // before creating the data file below, which would otherwise mask it.
        // (Removing the map while keeping the data is the safe direction and
        // needs no handling.)
        let stale_block_group_map = block_group_map_path.exists() && !cache_data_path.exists();

        // Create the cache data file eagerly, before the block_group_map, so that
        // "block_group_map file exists => data file exists" holds and the check above
        // can only fire for a genuinely orphaned block_group_map.
        let data_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&cache_data_path)?;
        data_file.set_len(blob_metadata.uncompressed_size())?;
        drop(data_file);

        let block_group_map =
            BlockGroupMap::open(&block_group_map_path, blob_metadata.block_group_count())?;
        if stale_block_group_map {
            // Reset in place rather than unlinking: handles already mapping
            // this file observe the reset, whereas a replacement inode would
            // split them off with their readiness invisible to each other.
            block_group_map.reset()?;
            warn!(
                "stale block_group_map without cache data file, reset: {}",
                block_group_map_path.display()
            );
        }

        let prefetch_lock_path = cache_dir.join(format!("{cache_key_hex}.prefetch.lock"));
        let block_group_locks =
            BlockGroupLocks::new(cache_dir.join(format!("{cache_key_hex}.flight.lock")));

        Ok(Self {
            blob_id,
            cache_key,
            blob_index,
            block_group_map,
            blob_metadata,
            cache_data_path,
            prefetch_lock_path,
            cache_file: RwLock::new(None),
            backend,
            trace_recorder,
            inflight_block_groups: Mutex::new(HashMap::new()),
            cache_mmap: OnceLock::new(),
            block_group_locks,
        })
    }

    /// The blob meta backing this cache (block groups, chunks, compressor).
    pub fn blob_metadata(&self) -> &BlobMetadata {
        &self.blob_metadata
    }

    /// Fetch, decode and validate one block group's bytes directly from the
    /// backend, without touching the cache data file or block_group_map. This
    /// is the block-group-granular read used by `nydus optimize` to re-encode
    /// accessed block groups into an ondemand artifact.
    pub fn fetch_block_group(&self, block_group_index: usize) -> io::Result<Vec<u8>> {
        let block_group = *self
            .blob_metadata
            .block_group(block_group_index)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "block group index out of range",
                )
            })?;
        let mut buffers = BlockGroupBuffers::default();
        let decoded = fetch_decode_validate_block_group_into(
            &self.blob_id,
            &self.blob_metadata,
            &self.backend,
            &block_group,
            &mut buffers,
            ReadKind::OnDemand,
        )?;
        Ok(decoded.to_vec())
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
    /// the shared block_group_map goes on advertising those block groups as ready. Better
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
    /// block group is ready, `None` when the blob is still filling (callers
    /// then take the ensure + pread path). Redirect blobs never latch
    /// ALL_READY through this path, so the mapping is only built for dense
    /// blobs.
    fn all_ready_slice(&self, offset: u64, len: usize) -> io::Result<Option<&[u8]>> {
        if !self.block_group_map.is_all_ready() {
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
        nydus_telemetry::metrics::inc_cache_hit_block_group();
        Ok(Some(&mmap[offset as usize..end as usize]))
    }

    fn ensure_block_group(
        &self,
        block_group_index: usize,
        block_group: &BlobMetadataBlockGroup,
        cache_file: &File,
    ) -> io::Result<()> {
        if self.block_group_map.is_ready(block_group_index)? {
            nydus_telemetry::metrics::inc_cache_hit_block_group();
            return Ok(());
        }

        let (flight, leader) = {
            let mut inflight = self.inflight_block_groups.lock().unwrap();
            match inflight.get(&block_group_index) {
                Some(flight) => (flight.clone(), false),
                None => {
                    let flight = Arc::new(BlockGroupFlight::new());
                    inflight.insert(block_group_index, flight.clone());
                    (flight, true)
                }
            }
        };
        if !leader {
            return flight.wait();
        }

        // The leader owns job-local decode buffers. Different cold block groups can be
        // fetched concurrently while callers of this block group join the same flight.
        //
        // LeaderGuard ensures that even when the closure panics, every follower
        // waiting on this block group is unblocked with an error and the inflight slot
        // is freed. Without this, a panic in fetch_decode_validate_block_group_into
        // (or any helper it calls) would leave followers permanently stuck in
        // flight.wait().
        let _guard = LeaderGuard {
            flight: flight.clone(),
            block_group_index,
            inflight: &self.inflight_block_groups,
        };

        let result = (|| {
            if self.block_group_map.is_ready(block_group_index)? {
                nydus_telemetry::metrics::inc_cache_hit_block_group();
                return Ok(());
            }
            // Per-core isolation: a cache created through NydusCore records into
            // that core's recorder only, while FUSE-path caches (no recorder) feed
            // the process-global trace behind the apiserver /trace endpoint.
            if let Some(recorder) = self.trace_recorder.as_ref() {
                recorder.record_block_group_access(self.blob_index, block_group_index as u32);
            } else {
                crate::access_trace::record_block_group_access(
                    self.blob_index,
                    block_group_index as u32,
                );
            }

            // Claim the block group across the processes sharing this cache. The
            // in-process flight above already left a single leader per block group,
            // which is what makes the descriptor-owned lock meaningful here.
            // Whoever waited usually finds the block group published on the way out,
            // so the re-check below is what actually removes the duplicate
            // backend traffic.
            let _claim = self.block_group_locks.acquire(block_group_index);
            if self.block_group_map.is_ready(block_group_index)? {
                nydus_telemetry::metrics::inc_cache_hit_block_group();
                return Ok(());
            }

            let mut buffers = BlockGroupBuffers::default();
            let decoded = fetch_decode_validate_block_group_into(
                &self.blob_id,
                &self.blob_metadata,
                &self.backend,
                block_group,
                &mut buffers,
                ReadKind::OnDemand,
            )?;
            write_all_at(cache_file, block_group.uncompressed_offset(), decoded)?;
            self.block_group_map.set_ready(block_group_index)?;
            nydus_telemetry::metrics::inc_cache_ondemand_fill_block_group();
            Ok(())
        })();

        // Notify followers with the actual result.
        // complete() is idempotent: the guard's Drop then no-ops.
        flight.complete(&result);
        // guard is dropped here: inflight entry removed, complete(Err) no-ops
        result
    }

    /// Ensure every block group overlapping `[offset, offset + len)` is decoded and
    /// written to the cache file. Shared by `read_at` and `ensure_range`.
    fn ensure_byte_range(&self, offset: u64, len: u64, cache_file: &File) -> io::Result<()> {
        // Redirect (ondemand) blobs have a non-uniform block group layout, so the
        // O(1) division-based block group lookup below does not apply; they are
        // consumed exclusively through `stream_redirect`.
        if self.blob_metadata.is_redirect() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "redirect blob has no dense readable address space",
            ));
        }

        let end = offset.checked_add(len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob read range overflow")
        })?;

        // Fast path: the sticky all-ready flag says every block group is already
        // decoded into the cache file, so skip the per-block group walk entirely.
        if self.block_group_map.is_all_ready() {
            nydus_telemetry::metrics::inc_cache_hit_block_group();
            return Ok(());
        }

        let block_groups = self.block_group_span(offset, end)?;
        let (first_block_group, last_block_group) = block_groups.into_inner();

        for block_group_index in first_block_group..=last_block_group {
            let block_group = *self
                .blob_metadata
                .block_group(block_group_index)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "blob meta block_group not found",
                    )
                })?;
            self.ensure_block_group(block_group_index, &block_group, cache_file)?;
        }
        Ok(())
    }

    /// Map the byte range `[offset, end)` of the dense uncompressed address
    /// space to the inclusive span of block group indexes covering it: an O(1)
    /// block group lookup at both ends. Block groups are dense and contiguous, so every
    /// block group between the first and last also overlaps the range.
    fn block_group_span(
        &self,
        offset: u64,
        end: u64,
    ) -> io::Result<std::ops::RangeInclusive<usize>> {
        let first = self
            .blob_metadata
            .block_group_index_from_uncompressed_offset(offset)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "blob meta block_group not found")
            })?;
        let last = self
            .blob_metadata
            .block_group_index_from_uncompressed_offset(end - 1)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "blob meta block_group not found")
            })?;
        Ok(first..=last)
    }

    /// Fetch the contiguous compressed window covering `block_groups[batch]` from
    /// the backend into `window` (resized to fit), returning the window's base
    /// offset within the blob. One backend request covers the whole window (a
    /// contiguous batch of block groups); its uncompressed span is reported for
    /// diagnostics.
    fn fetch_window(
        &self,
        block_groups: &[BlobMetadataBlockGroup],
        batch: &Range<usize>,
        window: &mut Vec<u8>,
    ) -> io::Result<u64> {
        let last_block_group = &block_groups[batch.end - 1];
        let window_base = block_groups[batch.start].compressed_offset();
        let window_end =
            last_block_group.compressed_offset() + last_block_group.compressed_size() as u64;
        let window_len = usize::try_from(window_end - window_base).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "blob block_group window size exceeds usize",
            )
        })?;
        window.resize(window_len, 0);
        let uncompressed_offset = block_groups[batch.start].uncompressed_offset();
        let uncompressed_size = last_block_group.uncompressed_offset()
            + last_block_group.uncompressed_size()
            - uncompressed_offset;
        let ctx =
            ReadContext::block_group(ReadKind::Prefetch, uncompressed_offset, uncompressed_size);
        self.backend
            .read_range_into(&self.blob_id, window_base, window, ctx)?;
        Ok(window_base)
    }

    /// Fetch one redirect-blob batch (a contiguous range of block groups) in a
    /// single backend read, then decode and hand each block group to `cb`. `window`
    /// and `decoded` are caller-owned scratch buffers so a worker thread can
    /// reuse them across batches. Per-block group decode/CRC failures are skipped
    /// with a warning; `cb` errors propagate to abort the stream.
    fn stream_redirect_batch(
        &self,
        block_groups: &[BlobMetadataBlockGroup],
        batch: std::ops::Range<usize>,
        window: &mut Vec<u8>,
        decoded: &mut Vec<u8>,
        cb: &(dyn Fn(&BlobMetadataBlockGroup, &[u8]) -> io::Result<()> + Sync),
    ) -> io::Result<()> {
        let window_base = self.fetch_window(block_groups, &batch, window)?;
        nydus_telemetry::metrics::record_backend_redirect_read(window.len() as u64);

        for index in batch {
            let block_group = &block_groups[index];
            if let Err(err) = decode_block_group_from_window(
                &self.blob_metadata,
                &self.backend,
                block_group,
                window_base,
                window,
                decoded,
            ) {
                nydus_telemetry::metrics::inc_cache_redirect_skip_block_group();
                warn!("skipping redirect block_group {index}: {err}");
                continue;
            }
            cb(block_group, decoded)?;
        }
        Ok(())
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
        nydus_telemetry::metrics::untrack_blob_block_groups(&self.cache_key);
    }
}

impl BlobCache for LocalBlobCache {
    fn prefetch_all(&self, deadline: Option<Instant>) -> io::Result<()> {
        let block_groups = self.blob_metadata.block_groups();
        if block_groups.is_empty() {
            return Ok(());
        }
        // Fast path: another process (or an earlier run) already decoded every
        // block group; skip the batch planning and per-block group readiness scan.
        if !self.blob_metadata.is_redirect() && self.block_group_map.is_all_ready() {
            return Ok(());
        }

        let cache_file = self.cache_file()?;
        // Prefetch writes the bulk of the cache, so it is worth one stat to
        // make sure the file it fills is still the one other processes read.
        self.ensure_data_file_linked(&cache_file)?;

        // Prefetch owns its decode buffers and does not take `fetch_lock`, so it
        // never blocks on-demand FUSE reads. The block_group_map is internally locked
        // and `set_ready` is idempotent, so racing with a read at worst decodes
        // the same block group twice into identical bytes at the same cache offset.
        let mut decoded = Vec::new();
        let mut window = Vec::new();

        for batch in plan_prefetch_batches(
            block_groups,
            DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_SIZE as u64,
        ) {
            super::check_prefetch_deadline(deadline)?;
            if batch
                .clone()
                .map(|index| self.block_group_map.is_ready(index))
                .collect::<io::Result<Vec<_>>>()?
                .into_iter()
                .all(|ready| ready)
            {
                continue;
            }

            let window_base = self.fetch_window(block_groups, &batch, &mut window)?;

            for index in batch {
                if self.block_group_map.is_ready(index)? {
                    continue;
                }
                let block_group = &block_groups[index];
                decode_block_group_from_window(
                    &self.blob_metadata,
                    &self.backend,
                    block_group,
                    window_base,
                    &window,
                    &mut decoded,
                )?;
                write_all_at(
                    cache_file.as_ref(),
                    block_group.uncompressed_offset(),
                    &decoded,
                )?;
                self.block_group_map.set_ready(index)?;
                nydus_telemetry::metrics::inc_cache_fill_block_group();
            }
        }

        // A successful full prefetch means every block group is now ready (decoded
        // here or observed ready from another process), so guarantee the
        // sticky ALL_READY flag is latched before returning. set_ready
        // normally latches it through the shared ready counter, but a
        // historical writer crash between its bit and counter updates leaves
        // the counter short forever; the authoritative bitmap scan inside
        // latch_all_ready() latches the flag regardless.
        if !self.blob_metadata.is_redirect() {
            self.block_group_map.latch_all_ready();
        }

        Ok(())
    }

    fn read_at(&self, offset: u64, dst: &mut [u8]) -> io::Result<()> {
        if dst.is_empty() {
            return Ok(());
        }

        if let Some(mapped) = self.all_ready_slice(offset, dst.len())? {
            dst.copy_from_slice(mapped);
            return Ok(());
        }

        let cache_file = self.cache_file()?;
        self.ensure_byte_range(offset, dst.len() as u64, cache_file.as_ref())?;

        // The cache file mirrors the dense uncompressed address space, so once
        // the covering block groups are decoded the absolute offset indexes straight
        // into it for a single contiguous read.
        cache_file.as_ref().read_exact_at(dst, offset)
    }

    fn write_data_to(&self, offset: u64, len: usize, writer: &mut dyn io::Write) -> io::Result<()> {
        if len == 0 {
            return Ok(());
        }
        if let Some(mapped) = self.all_ready_slice(offset, len)? {
            return writer.write_all(mapped);
        }
        super::write_data_via_scratch(self, offset, len, writer)
    }

    fn prepare(&self) -> io::Result<PathBuf> {
        // Opening the cache file creates it (sparse) and sizes it to the dense
        // uncompressed address space.
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
        let cache_file = self.cache_file()?;
        self.ensure_byte_range(offset, len, cache_file.as_ref())
    }

    fn ready_ranges(&self, offset: u64, len: u64) -> io::Result<Vec<Range<u64>>> {
        if len == 0 || self.blob_metadata.is_redirect() {
            return Ok(Vec::new());
        }
        let end = offset.checked_add(len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob probe range overflow")
        })?;

        let (first, last) = self.block_group_span(offset, end)?.into_inner();

        self.block_group_map
            .ready_block_group_ranges(first, last)?
            .into_iter()
            .map(|block_groups| {
                let first_block_group = self
                    .blob_metadata
                    .block_group(block_groups.start)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "blob meta block_group not found",
                        )
                    })?;
                let last_block_group = self
                    .blob_metadata
                    .block_group(block_groups.end - 1)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "blob meta block_group not found",
                        )
                    })?;
                Ok(first_block_group.uncompressed_offset().max(offset)
                    ..(last_block_group.uncompressed_offset()
                        + last_block_group.uncompressed_size())
                    .min(end))
            })
            .collect()
    }

    fn is_redirect(&self) -> bool {
        self.blob_metadata.is_redirect()
    }

    /// Acquire the per-blob cross-process prefetch lock, blocking (in 1s
    /// polls) while another process holds it. Modeled after the nydus blob
    /// prefetcher: locking failures degrade to prefetching without the lock
    /// rather than failing the prefetch, and the guard is released when the
    /// returned file is dropped — including on process death, so a crashed
    /// owner's lock is taken over and the block_group_map-driven skip logic resumes
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
            // Another process is prefetching this blob. For a regular blob the
            // shared block_group_map tells us when the owner has finished everything,
            // so we can stop waiting; the caller's prefetch then reduces to a
            // cheap all-ready scan. A redirect blob never marks its own map,
            // so keep waiting for the lock and rely on batch skipping.
            if !self.blob_metadata.is_redirect() && self.block_group_map.latch_all_ready() {
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

    fn is_block_group_ready(&self, block_group_index: usize) -> bool {
        self.block_group_map
            .is_ready(block_group_index)
            .unwrap_or(false)
    }

    fn is_all_ready(&self) -> bool {
        // A redirect blob never marks its own block_group_map (its block groups fill other
        // blobs' caches), so the flag is meaningless there.
        !self.blob_metadata.is_redirect() && self.block_group_map.is_all_ready()
    }

    fn for_each_redirect_block_group(
        &self,
        threads: usize,
        deadline: Option<Instant>,
        skip: &(dyn Fn(&BlobMetadataBlockGroup) -> bool + Sync),
        cb: &(dyn Fn(&BlobMetadataBlockGroup, &[u8]) -> io::Result<()> + Sync),
    ) -> io::Result<()> {
        let block_groups = self.blob_metadata.block_groups();
        if block_groups.is_empty() {
            return Ok(());
        }

        // Segments whose block groups are all already done (per `skip`, typically
        // backed by the shared source block_block_group_maps) are not fetched at all, so a
        // process re-running the warmup behind another one does close to zero
        // backend work. Partially-done batches are still fetched whole to
        // keep the backend reads contiguous.
        let batch_done = |batch: &std::ops::Range<usize>| -> bool {
            batch.clone().all(|index| skip(&block_groups[index]))
        };

        // A small ondemand blob (fits in one batch) or a single worker is
        // streamed sequentially with default-sized batches: batching and
        // extra registry connections would add overhead without overlapping any
        // work.
        let total_uncompressed: u64 = block_groups
            .iter()
            .map(|block_group| block_group.uncompressed_size())
            .sum();
        if threads <= 1 || total_uncompressed <= super::REDIRECT_PREFETCH_BATCH_SIZE {
            let mut window = Vec::new();
            let mut decoded = Vec::new();
            for batch in plan_prefetch_batches(block_groups, super::REDIRECT_PREFETCH_BATCH_SIZE) {
                super::check_prefetch_deadline(deadline)?;
                if batch_done(&batch) {
                    continue;
                }
                self.stream_redirect_batch(block_groups, batch, &mut window, &mut decoded, cb)?;
            }
            return Ok(());
        }

        // Larger blob: fetch batches concurrently. The earliest block groups are
        // emitted one per batch (a "ramp") so they land in the first wave of
        // workers within a single round trip, ahead of the workload's first
        // faults; the rest are bundled into REDIRECT_PREFETCH_BATCH_SIZE
        // batches for throughput.
        let batches = super::plan_redirect_batches(
            block_groups,
            super::REDIRECT_PREFETCH_BATCH_SIZE,
            super::REDIRECT_PREFETCH_RAMP_BLOCK_GROUPS,
        );
        let worker_count = threads.min(batches.len());
        let next = AtomicUsize::new(0);
        let first_err: Mutex<Option<io::Error>> = Mutex::new(None);
        std::thread::scope(|scope| {
            for _ in 0..worker_count {
                scope.spawn(|| {
                    let mut window = Vec::new();
                    let mut decoded = Vec::new();
                    loop {
                        if first_err.lock().unwrap().is_some() {
                            break;
                        }
                        if let Err(err) = super::check_prefetch_deadline(deadline) {
                            *first_err.lock().unwrap() = Some(err);
                            break;
                        }
                        let idx = next.fetch_add(1, Ordering::Relaxed);
                        let Some(batch) = batches.get(idx) else {
                            break;
                        };
                        if batch_done(batch) {
                            continue;
                        }
                        if let Err(err) = self.stream_redirect_batch(
                            block_groups,
                            batch.clone(),
                            &mut window,
                            &mut decoded,
                            cb,
                        ) {
                            *first_err.lock().unwrap() = Some(err);
                            break;
                        }
                    }
                });
            }
        });

        match first_err.into_inner() {
            Ok(Some(err)) => Err(err),
            _ => Ok(()),
        }
    }

    fn fill_block_group_from_redirect(
        &self,
        block_group_index: usize,
        decoded: &[u8],
    ) -> io::Result<()> {
        let block_group = self
            .blob_metadata
            .block_group(block_group_index)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "redirect fill block_group index out of range",
                )
            })?;
        // Cross-check against this blob's own block group metadata: the redirect
        // block group's crc32 was copied from this source block group at optimize time, so
        // any divergence (stale optimize artifact, corrupted transfer) is
        // caught here before it can poison the cache.
        if self.block_group_map.is_ready(block_group_index)? {
            nydus_telemetry::metrics::inc_cache_hit_block_group();
            return Ok(());
        }
        super::validate_block_group_with_metrics(&self.backend, block_group, decoded)?;
        let cache_file = self.cache_file()?;
        write_all_at(
            cache_file.as_ref(),
            block_group.uncompressed_offset(),
            decoded,
        )?;
        self.block_group_map.set_ready(block_group_index)?;
        nydus_telemetry::metrics::inc_cache_redirect_fill_block_group();
        Ok(())
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
        if let Err(err) = BlobMetadata::from_path(tmp.path(), true) {
            return Err(io::Error::other(err));
        }
        tmp.persist(blob_metadata_path).map_err(|err| err.error)?;
    }

    BlobMetadata::from_path(blob_metadata_path, true).map_err(io::Error::other)
}

/// Drop guard that ensures a leader always signals its flight and cleans up
/// the inflight map, even when the fetch body panics. Without this, a panic in
/// `fetch_decode_validate_block_group_into` (or any helper it calls) would leave
/// follower threads permanently blocked in `flight.wait()`.
struct LeaderGuard<'a> {
    flight: Arc<BlockGroupFlight>,
    block_group_index: usize,
    inflight: &'a Mutex<HashMap<usize, Arc<BlockGroupFlight>>>,
}

impl<'a> Drop for LeaderGuard<'a> {
    fn drop(&mut self) {
        // complete is idempotent: if the leader called `flight.complete(...)`
        // normally before Drop runs, this is a no-op.
        self.flight.complete(&Err(io::Error::other(
            "block_group leader panicked or was abandoned",
        )));
        self.inflight
            .lock()
            .unwrap()
            .remove(&self.block_group_index);
    }
}

fn write_all_at(file: &File, offset: u64, buf: &[u8]) -> io::Result<()> {
    let mut written = 0usize;
    while written < buf.len() {
        let n = file.write_at(&buf[written..], offset + written as u64)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "cache file write returned zero",
            ));
        }
        written += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_backend::Local;
    use nydus_format::blob::{BlobMetadataBlockGroup, BlobMetadataChunk, BlobMetadataCompressor};
    use nydus_format::utils::sha256_bytes;
    use std::path::Path;
    use tempfile::tempdir;

    fn blob_metadata(payload: &[u8]) -> BlobMetadata {
        blob_metadata_with_crc32(payload, crc32c::crc32c(payload))
    }

    fn blob_metadata_with_crc32(payload: &[u8], crc32: u32) -> BlobMetadata {
        BlobMetadata::new(
            BlobMetadataCompressor::None,
            1,
            vec![BlobMetadataChunk::new(*blake3::hash(payload).as_bytes(), 0, 1).unwrap()],
            vec![BlobMetadataBlockGroup::new(0, 1, 0, 4096, crc32).unwrap()],
        )
        .unwrap()
    }

    use nydus_format::utils::write_minimal_full_blob;

    /// Wraps a real backend and counts data-range reads, so tests can assert
    /// that cross-process sharing (block_group_map + prefetch lock + batch skip)
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
        assert!(cached.block_group_map.is_ready(0).unwrap());
    }

    #[test]
    fn stale_block_block_group_map_without_data_file_is_reset() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x3du8; 4096];
        let meta = blob_metadata(&payload);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, true);
        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));

        // Warm the cache: data file created, block group marked ready, sticky
        // all-ready flag latched.
        {
            let cached =
                LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend.clone()).unwrap();
            let mut buf = vec![0u8; 1024];
            cached.read_at(0, &mut buf).unwrap();
            assert!(cached.block_group_map.is_all_ready());
        }

        // Model the operational accident: the data file is removed while the
        // block_group_map survives. Reopening must reset the block_group_map instead of
        // trusting ready bits that now point at sparse holes.
        let cache_key = backend.cache_key(&full_blob_id).unwrap();
        let prefix = hex_string(&cache_key);
        fs::remove_file(cache_dir.path().join(format!("{prefix}.blob.data"))).unwrap();

        let reopened = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();
        assert!(!reopened.block_group_map.is_ready(0).unwrap());
        assert!(!reopened.block_group_map.is_all_ready());

        // The blob still reads correctly end-to-end after the reset.
        let mut buf = vec![0u8; 1024];
        reopened.read_at(512, &mut buf).unwrap();
        assert_eq!(buf, payload[512..1536]);
    }

    #[test]
    fn stale_block_block_group_map_reset_keeps_the_same_inode() {
        use std::os::unix::fs::MetadataExt;

        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x2eu8; 4096];
        let meta = blob_metadata(&payload);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, true);
        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));

        // A live handle keeps the block_group_map mapped throughout, standing in for
        // a process that is already running when the accident happens.
        let live =
            LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend.clone()).unwrap();
        let mut buf = vec![0u8; 1024];
        live.read_at(0, &mut buf).unwrap();
        assert!(live.block_group_map.is_ready(0).unwrap());

        let cache_key = backend.cache_key(&full_blob_id).unwrap();
        let prefix = hex_string(&cache_key);
        let block_block_group_map_path = cache_dir.path().join(format!("{prefix}.group.map"));
        let before = fs::metadata(&block_block_group_map_path).unwrap().ino();
        fs::remove_file(cache_dir.path().join(format!("{prefix}.blob.data"))).unwrap();

        let reopened = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();
        assert_eq!(
            fs::metadata(&block_block_group_map_path).unwrap().ino(),
            before,
            "the reset must not replace the block_group_map file"
        );

        // Because the inode is unchanged, the reset is visible through the
        // mapping the live handle already holds; a replacement inode would
        // have left it advertising readiness nobody else can see.
        assert!(!live.block_group_map.is_ready(0).unwrap());
        assert!(!reopened.block_group_map.is_ready(0).unwrap());
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

        // The owner finished all block groups: the contender must give up on the
        // lock (returning None) instead of waiting, since the shared block_group_map
        // already reports everything ready.
        owner.block_group_map.set_ready(0).unwrap();
        assert!(waiter.prefetch_lock().is_none());
        assert!(waiter.is_block_group_ready(0));

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
        // must proceed immediately (fetch the cold block group itself) rather than
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
        let first = LocalBlobCache::open(
            full_blob_id,
            1,
            cache_dir.path(),
            backend.clone() as Arc<dyn BlobBackend>,
        )
        .unwrap();
        let second = LocalBlobCache::open(
            full_blob_id,
            1,
            cache_dir.path(),
            backend.clone() as Arc<dyn BlobBackend>,
        )
        .unwrap();

        // The "owner" instance prefetches everything from the backend.
        let guard = first.prefetch_lock();
        first.prefetch_all(None).unwrap();
        let after_owner = backend.reads();
        assert!(after_owner > 0, "owner must stream from the backend");

        // While the owner still holds the lock, a contending instance sees
        // every block group ready through the shared block_group_map and gives up on the
        // lock (None) instead of waiting.
        assert!(second.prefetch_lock().is_none());
        drop(guard);

        // Repeating the prefetch afterwards issues zero backend reads: every
        // block group is already ready in the shared cache.
        second.prefetch_all(None).unwrap();
        assert_eq!(backend.reads(), after_owner, "waiter must not re-download");

        // Cross-handle on-demand reads are also served from the shared cache.
        let mut buf = vec![0u8; 4096];
        second.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, payload);
        assert_eq!(backend.reads(), after_owner);
    }

    #[test]
    fn redirect_stream_skips_fully_done_batches() {
        let backend_dir = tempdir().unwrap();
        let payload = vec![0x9cu8; 4096];
        let crc32 = crc32c::crc32c(&payload);

        // An ondemand (redirect) blob whose single block group redirects to source
        // blob 1 block group 0; its data region carries a copy of the source bytes.
        let redirect_meta = BlobMetadata::new(
            BlobMetadataCompressor::None,
            1,
            Vec::new(),
            vec![BlobMetadataBlockGroup::new_redirect(0, 1, 0, 4096, crc32, 1, 0).unwrap()],
        )
        .unwrap();
        assert!(redirect_meta.is_redirect());
        let redirect_blob_id =
            write_minimal_full_blob(backend_dir.path(), &payload, &redirect_meta, true);

        let run = |skip_all: bool| -> (usize, usize) {
            let cache_dir = tempdir().unwrap();
            let backend = CountingBackend::new(backend_dir.path());
            let cache = LocalBlobCache::open(
                redirect_blob_id,
                2,
                cache_dir.path(),
                backend.clone() as Arc<dyn BlobBackend>,
            )
            .unwrap();
            let baseline = backend.reads();
            let delivered = AtomicUsize::new(0);
            cache
                .for_each_redirect_block_group(
                    1,
                    None,
                    &|_block_group| skip_all,
                    &|block_group, decoded| {
                        assert!(block_group.is_redirect());
                        assert_eq!(decoded, payload);
                        delivered.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    },
                )
                .unwrap();
            (backend.reads() - baseline, delivered.load(Ordering::SeqCst))
        };

        // Nothing done yet: the batch is fetched and the block group delivered.
        let (reads, delivered) = run(false);
        assert!(reads > 0);
        assert_eq!(delivered, 1);

        // Every block group reported done (e.g. resident in the source caches of a
        // faster sibling instance): no backend fetch, no callback at all.
        let (reads, delivered) = run(true);
        assert_eq!(reads, 0, "fully-done batch must not be fetched");
        assert_eq!(delivered, 0);
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

    #[test]
    fn local_blob_cache_rejects_bad_crc32_before_marking_chunk_ready() {
        super::super::set_skip_verify_checksums(false);
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0xacu8; 4096];
        let meta = blob_metadata_with_crc32(&payload, crc32c::crc32c(&payload).wrapping_add(1));
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, true);

        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));
        let cached = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();

        let mut buf = vec![0u8; 1024];
        let err = cached.read_at(512, &mut buf).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("crc32"));
        assert!(!cached.block_group_map.is_ready(0).unwrap());
    }

    #[test]
    fn local_blob_cache_reads_data_region_relative_compressed_offsets() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x3du8; 4096];
        let data_blob_id = sha256_bytes(&payload);
        let meta = blob_metadata(&payload);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, false);

        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));
        let cached = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();

        let mut buf = vec![0u8; 512];
        cached.read_at(256, &mut buf).unwrap();

        assert_eq!(buf, payload[256..768]);
        assert!(cached.block_group_map.is_ready(0).unwrap());
        assert!(cache_dir
            .path()
            .join(format!("{}.blob.data", hex_string(&full_blob_id)))
            .is_file());
        assert!(cache_dir
            .path()
            .join(format!("{}.blob.meta", hex_string(&full_blob_id)))
            .is_file());
        assert!(cache_dir
            .path()
            .join(format!("{}.group.map", hex_string(&full_blob_id)))
            .is_file());
        assert!(!cache_dir
            .path()
            .join(format!("{}.blob.data", hex_string(&data_blob_id)))
            .exists());
    }

    #[test]
    fn fill_block_group_from_redirect_validates_then_caches() {
        super::super::set_skip_verify_checksums(false);
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x6eu8; 4096];
        let meta = blob_metadata(&payload);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, true);

        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));
        let cached = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();
        assert!(!cached.is_redirect());

        // Wrong length is rejected and the block group stays not-ready.
        let err = cached
            .fill_block_group_from_redirect(0, &payload[..1024])
            .unwrap_err();
        assert!(err.to_string().contains("length mismatch"));
        assert!(!cached.block_group_map.is_ready(0).unwrap());

        // Corrupted bytes fail the CRC cross-check.
        let mut corrupted = payload.clone();
        corrupted[0] ^= 0xff;
        let err = cached
            .fill_block_group_from_redirect(0, &corrupted)
            .unwrap_err();
        assert!(super::super::is_block_group_crc_mismatch(&err));
        assert!(!cached.block_group_map.is_ready(0).unwrap());

        // Valid bytes are cached, marked ready, and served without the backend.
        cached.fill_block_group_from_redirect(0, &payload).unwrap();
        assert!(cached.block_group_map.is_ready(0).unwrap());
        let mut buf = vec![0u8; 1024];
        cached.read_at(512, &mut buf).unwrap();
        assert_eq!(buf, payload[512..1536]);

        // Out-of-range index is rejected.
        assert!(cached.fill_block_group_from_redirect(7, &payload).is_err());
    }
}
