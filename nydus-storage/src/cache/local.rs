use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::ops::Range;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::Duration;
use tracing::{info, warn};

use crate::access_trace::TraceRecorder;
use crate::group_map::GroupMap;
use nydus_backend::{BlobBackend, ReadContext, ReadKind};
use nydus_format::blob::{
    BlobMetadata, BlobMetadataGroup, BLOB_METADATA_DEFAULT_CHUNK_SIZE, BLOB_METADATA_SUFFIX,
};
use nydus_format::utils::{hex_string, SHA256_DIGEST_SIZE};

use super::group_lock::GroupLocks;
use super::{
    decode_group_from_window, fetch_decode_validate_group_into, plan_prefetch_batches, BlobCache,
    GroupBuffers,
};

#[derive(Clone)]
enum GroupFlightResult {
    Success,
    Failure {
        kind: io::ErrorKind,
        message: Arc<str>,
    },
}

struct GroupFlight {
    result: Mutex<Option<GroupFlightResult>>,
    done: Condvar,
}

impl GroupFlight {
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
            Ok(()) => GroupFlightResult::Success,
            Err(err) => GroupFlightResult::Failure {
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
            GroupFlightResult::Success => Ok(()),
            GroupFlightResult::Failure { kind, message } => {
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
    /// Device/blob index in the merged image, used to attribute on-demand group
    /// accesses in the access trace.
    blob_index: u32,
    group_map: GroupMap,
    blob_metadata: BlobMetadata,
    cache_data_path: PathBuf,
    prefetch_lock_path: PathBuf,
    /// Lazily opened cache data file. Double-checked: reads take the read
    /// lock (per-I/O hot path), the first opener takes the write lock and
    /// re-checks. A failed open leaves the slot empty and retryable.
    cache_file: RwLock<Option<Arc<File>>>,
    backend: Arc<dyn BlobBackend>,
    trace_recorder: Option<Arc<TraceRecorder>>,
    inflight_groups: Mutex<HashMap<usize, Arc<GroupFlight>>>,
    /// Keeps the processes sharing this cache from each fetching the same
    /// cold group.
    group_locks: GroupLocks,
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
        let blob_metadata_path = cache_dir.join(format!("{cache_key_hex}{BLOB_METADATA_SUFFIX}"));
        let blob_metadata =
            load_or_fetch_blob_metadata(blob_id, cache_dir, &blob_metadata_path, &backend)?;
        nydus_telemetry::metrics::track_blob_groups(cache_key, blob_metadata.group_count() as u64);

        let cache_data_path = cache_dir.join(format!("{cache_key_hex}.blob.data"));

        // CDC blobs track readiness per CDC chunk record (the unit filled into
        // the logical cache space); fixed blobs track readiness per group.
        let readiness_map_path = if blob_metadata.is_cdc() {
            cache_dir.join(format!("{cache_key_hex}.chunk.map"))
        } else {
            cache_dir.join(format!("{cache_key_hex}.group.map"))
        };
        let readiness_count = if blob_metadata.is_cdc() {
            blob_metadata.chunk_count()
        } else {
            blob_metadata.group_count()
        };
        // The group_map is only meaningful together with the cache data file it
        // describes: a leftover group_map whose data file has been removed
        // would claim groups are ready while reads hit sparse zeros. Note this
        // before creating the data file below, which would otherwise mask it.
        // (Removing the map while keeping the data is the safe direction and
        // needs no handling.)
        let stale_groupmap = readiness_map_path.exists() && !cache_data_path.exists();

        // Create the cache data file eagerly, before the group_map, so that
        // "group_map file exists => data file exists" holds and the check above
        // can only fire for a genuinely orphaned group_map.
        let data_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&cache_data_path)?;
        data_file.set_len(blob_metadata.logical_uncompressed_size())?;
        drop(data_file);

        let group_map = GroupMap::open(&readiness_map_path, readiness_count)?;
        if stale_groupmap {
            // Reset in place rather than unlinking: handles already mapping
            // this file observe the reset, whereas a replacement inode would
            // split them off with their readiness invisible to each other.
            group_map.reset()?;
            warn!(
                "stale group_map without cache data file, reset: {}",
                readiness_map_path.display()
            );
        }

        let prefetch_lock_path = cache_dir.join(format!("{cache_key_hex}.prefetch.lock"));
        let group_locks = GroupLocks::new(cache_dir.join(format!("{cache_key_hex}.flight.lock")));

        Ok(Self {
            blob_id,
            cache_key,
            blob_index,
            group_map,
            blob_metadata,
            cache_data_path,
            prefetch_lock_path,
            cache_file: RwLock::new(None),
            backend,
            trace_recorder,
            inflight_groups: Mutex::new(HashMap::new()),
            group_locks,
        })
    }

    /// The blob meta backing this cache (groups, chunks, compressor).
    pub fn blob_metadata(&self) -> &BlobMetadata {
        &self.blob_metadata
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
        file.set_len(self.blob_metadata.logical_uncompressed_size())?;
        nydus_telemetry::metrics::inc_cache_opened_files();
        *cache_file = Some(file.clone());
        Ok(file)
    }

    /// Reject work against a cache data file that has been unlinked.
    ///
    /// The descriptor keeps an unlinked inode alive, so writes through it
    /// still succeed — but they land somewhere nobody else can reach, while
    /// the shared group_map goes on advertising those groups as ready. Better
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

    fn ensure_group(
        &self,
        group_index: usize,
        group: &BlobMetadataGroup,
        cache_file: &File,
    ) -> io::Result<()> {
        if self.group_map.is_ready(group_index)? {
            nydus_telemetry::metrics::inc_cache_hit_group();
            return Ok(());
        }

        let (flight, leader) = {
            let mut inflight = self.inflight_groups.lock().unwrap();
            match inflight.get(&group_index) {
                Some(flight) => (flight.clone(), false),
                None => {
                    let flight = Arc::new(GroupFlight::new());
                    inflight.insert(group_index, flight.clone());
                    (flight, true)
                }
            }
        };
        if !leader {
            return flight.wait();
        }

        // The leader owns job-local decode buffers. Different cold groups can be
        // fetched concurrently while callers of this group join the same flight.
        //
        // LeaderGuard ensures that even when the closure panics, every follower
        // waiting on this group is unblocked with an error and the inflight slot
        // is freed. Without this, a panic in fetch_decode_validate_group_into
        // (or any helper it calls) would leave followers permanently stuck in
        // flight.wait().
        let _guard = LeaderGuard {
            flight: flight.clone(),
            group_index,
            inflight: &self.inflight_groups,
        };

        let result = (|| {
            if self.group_map.is_ready(group_index)? {
                nydus_telemetry::metrics::inc_cache_hit_group();
                return Ok(());
            }
            // Per-core isolation: a cache created through NydusCore records into
            // that core's recorder only, while FUSE-path caches (no recorder) feed
            // the process-global trace behind the apiserver /trace endpoint.
            if let Some(recorder) = self.trace_recorder.as_ref() {
                recorder.record_group_access(self.blob_index, group_index as u32);
            } else {
                crate::access_trace::record_group_access(self.blob_index, group_index as u32);
            }

            // Claim the group across the processes sharing this cache. The
            // in-process flight above already left a single leader per group,
            // which is what makes the descriptor-owned lock meaningful here.
            // Whoever waited usually finds the group published on the way out,
            // so the re-check below is what actually removes the duplicate
            // backend traffic.
            let _claim = self.group_locks.acquire(group_index);
            if self.group_map.is_ready(group_index)? {
                nydus_telemetry::metrics::inc_cache_hit_group();
                return Ok(());
            }

            let mut buffers = GroupBuffers::default();
            let decoded = fetch_decode_validate_group_into(
                &self.blob_id,
                &self.blob_metadata,
                &self.backend,
                group,
                &mut buffers,
                ReadKind::OnDemand,
            )?;
            write_all_at(cache_file, group.uncompressed_byte_offset(), decoded)?;
            self.group_map.set_ready(group_index)?;
            nydus_telemetry::metrics::inc_cache_ondemand_fill_group();
            Ok(())
        })();

        // Notify followers with the actual result.
        // complete() is idempotent: the guard's Drop then no-ops.
        flight.complete(&result);
        // guard is dropped here: inflight entry removed, complete(Err) no-ops
        result
    }

    /// Ensure every CDC chunk record in `records` (indexes into the sorted
    /// record table) has its bytes decoded into the cache file at its logical
    /// offset. `memo` deduplicates group decodes across the records of one
    /// call, since consecutive records usually reference the same group.
    fn ensure_cdc_records(&self, records: Range<usize>, cache_file: &File) -> io::Result<()> {
        let chunks = self.blob_metadata.cdc_chunks();
        let mut memo: HashMap<usize, Vec<u8>> = HashMap::new();
        for index in records {
            self.ensure_cdc_record(index, &chunks[index], cache_file, &mut memo)?;
        }
        Ok(())
    }

    /// The CDC analogue of `ensure_group`: single-flight per record within the
    /// process, cross-process claim per record, then decode + publish.
    fn ensure_cdc_record(
        &self,
        record_index: usize,
        chunk: &nydus_format::blob::BlobMetadataCdcChunk,
        cache_file: &File,
        memo: &mut HashMap<usize, Vec<u8>>,
    ) -> io::Result<()> {
        if self.group_map.is_ready(record_index)? {
            nydus_telemetry::metrics::inc_cache_hit_group();
            return Ok(());
        }

        let (flight, leader) = {
            let mut inflight = self.inflight_groups.lock().unwrap();
            match inflight.get(&record_index) {
                Some(flight) => (flight.clone(), false),
                None => {
                    let flight = Arc::new(GroupFlight::new());
                    inflight.insert(record_index, flight.clone());
                    (flight, true)
                }
            }
        };
        if !leader {
            return flight.wait();
        }

        let _guard = LeaderGuard {
            flight: flight.clone(),
            group_index: record_index,
            inflight: &self.inflight_groups,
        };

        let result = (|| {
            if self.group_map.is_ready(record_index)? {
                nydus_telemetry::metrics::inc_cache_hit_group();
                return Ok(());
            }

            let _claim = self.group_locks.acquire(record_index);
            if self.group_map.is_ready(record_index)? {
                nydus_telemetry::metrics::inc_cache_hit_group();
                return Ok(());
            }

            self.fill_cdc_record(chunk, cache_file, memo, ReadKind::OnDemand)?;
            self.group_map.set_ready(record_index)?;
            nydus_telemetry::metrics::inc_cache_ondemand_fill_group();
            Ok(())
        })();

        flight.complete(&result);
        result
    }

    /// Decode the group(s) covering `chunk`'s unique byte range (through
    /// `memo`) and write the record's bytes into the cache file at the
    /// record's logical byte offset. Does not touch the readiness map.
    fn fill_cdc_record(
        &self,
        chunk: &nydus_format::blob::BlobMetadataCdcChunk,
        cache_file: &File,
        memo: &mut HashMap<usize, Vec<u8>>,
        kind: ReadKind,
    ) -> io::Result<()> {
        let unique_offset = chunk.unique_byte_offset();
        let unique_end = chunk.unique_byte_end();
        let first = self
            .blob_metadata
            .group_index_for_byte_offset(unique_offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "blob meta group not found"))?;
        let last = self
            .blob_metadata
            .group_index_for_byte_offset(unique_end - 1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "blob meta group not found"))?;

        // Callers walk records in (mostly) increasing unique offset order, so
        // groups below the current record's first group are never needed
        // again; dropping them bounds the memo to the record's group span.
        memo.retain(|group_index, _| *group_index >= first);

        let mut bytes = vec![0u8; chunk.size() as usize];
        for group_index in first..=last {
            let group = *self.blob_metadata.group_at(group_index).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "blob meta group not found")
            })?;
            if let std::collections::hash_map::Entry::Vacant(entry) = memo.entry(group_index) {
                if let Some(recorder) = self.trace_recorder.as_ref() {
                    recorder.record_group_access(self.blob_index, group_index as u32);
                } else {
                    crate::access_trace::record_group_access(self.blob_index, group_index as u32);
                }
                let mut buffers = GroupBuffers::default();
                let decoded = fetch_decode_validate_group_into(
                    &self.blob_id,
                    &self.blob_metadata,
                    &self.backend,
                    &group,
                    &mut buffers,
                    kind,
                )?;
                entry.insert(decoded.to_vec());
            }
            let decoded = &memo[&group_index];
            let group_offset = group.uncompressed_byte_offset();
            let copy_start = unique_offset.max(group_offset);
            let copy_end = unique_end.min(group.uncompressed_byte_end());
            bytes[(copy_start - unique_offset) as usize..(copy_end - unique_offset) as usize]
                .copy_from_slice(
                    &decoded
                        [(copy_start - group_offset) as usize..(copy_end - group_offset) as usize],
                );
        }

        write_all_at(cache_file, chunk.logical_byte_offset(), &bytes)
    }

    /// Ensure every group overlapping `[offset, offset + len)` is decoded and
    /// written to the cache file. Shared by `read_at` and `ensure_range`.
    fn ensure_byte_range(&self, offset: u64, len: u64, cache_file: &File) -> io::Result<()> {
        // Redirect (ondemand) blobs have a non-uniform group layout, so the
        // O(1) division-based group lookup below does not apply; they are
        // consumed exclusively through `stream_redirect`.
        if self.blob_metadata.is_redirect_blob() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "redirect blob has no dense readable address space",
            ));
        }

        let end = offset.checked_add(len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob read range overflow")
        })?;

        // Fast path: the sticky all-ready flag says every group is already
        // decoded into the cache file, so skip the per-group walk entirely.
        if self.group_map.is_all_ready() {
            nydus_telemetry::metrics::inc_cache_hit_group();
            return Ok(());
        }

        // CDC blobs are looked up per record: binary-search the records
        // overlapping the logical range; logical gaps between records are
        // padding/holes that read back as zeros from the sparse cache file.
        if self.blob_metadata.is_cdc() {
            let records = self.blob_metadata.cdc_chunks_overlapping(offset, end);
            return self.ensure_cdc_records(records, cache_file);
        }

        let groups = self.group_span(offset, end)?;
        let (first_group, last_group) = groups.into_inner();

        for group_index in first_group..=last_group {
            let group = *self.blob_metadata.group_at(group_index).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "blob meta group not found")
            })?;
            self.ensure_group(group_index, &group, cache_file)?;
        }
        Ok(())
    }

    /// Map the byte range `[offset, end)` of the dense uncompressed address
    /// space to the inclusive span of group indexes covering it: an O(1)
    /// group lookup at both ends. Groups are dense and contiguous, so every
    /// group between the first and last also overlaps the range.
    fn group_span(&self, offset: u64, end: u64) -> io::Result<std::ops::RangeInclusive<usize>> {
        let first = self
            .blob_metadata
            .group_index_for_byte_offset(offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "blob meta group not found"))?;
        let last = self
            .blob_metadata
            .group_index_for_byte_offset(end - 1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "blob meta group not found"))?;
        Ok(first..=last)
    }

    /// Fetch the contiguous compressed window covering `groups[batch]` from
    /// the backend into `window` (resized to fit), returning the window's base
    /// offset within the blob. One backend request covers the whole window (a
    /// contiguous batch of groups); its uncompressed span is reported for
    /// diagnostics.
    fn fetch_window(
        &self,
        groups: &[BlobMetadataGroup],
        batch: &Range<usize>,
        window: &mut Vec<u8>,
    ) -> io::Result<u64> {
        let window_base = groups[batch.start].compressed_byte_offset();
        let window_end = groups[batch.end - 1].compressed_byte_end();
        let window_len = usize::try_from(window_end - window_base).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "blob group window size exceeds usize",
            )
        })?;
        window.resize(window_len, 0);
        let uncompressed_offset = groups[batch.start].uncompressed_byte_offset();
        let uncompressed_size = groups[batch.end - 1].uncompressed_byte_end() - uncompressed_offset;
        let ctx = ReadContext::group(ReadKind::Prefetch, uncompressed_offset, uncompressed_size);
        self.backend
            .read_range_into(&self.blob_id, window_base, window, ctx)?;
        Ok(window_base)
    }

    /// Fetch one redirect-blob batch (a contiguous range of groups) in a
    /// single backend read, then decode and hand each group to `cb`. `window`
    /// and `decoded` are caller-owned scratch buffers so a worker thread can
    /// reuse them across batches. Per-group decode/CRC failures are skipped
    /// with a warning; `cb` errors propagate to abort the stream.
    fn stream_redirect_batch(
        &self,
        groups: &[BlobMetadataGroup],
        batch: std::ops::Range<usize>,
        window: &mut Vec<u8>,
        decoded: &mut Vec<u8>,
        cb: &(dyn Fn(&BlobMetadataGroup, &[u8]) -> io::Result<()> + Sync),
    ) -> io::Result<()> {
        let window_base = self.fetch_window(groups, &batch, window)?;
        nydus_telemetry::metrics::record_backend_redirect_read(window.len() as u64);

        for index in batch {
            let group = &groups[index];
            if let Err(err) = decode_group_from_window(
                &self.blob_metadata,
                &self.backend,
                group,
                window_base,
                window,
                decoded,
            ) {
                nydus_telemetry::metrics::inc_cache_redirect_skip_group();
                warn!("skipping redirect group {index}: {err}");
                continue;
            }
            cb(group, decoded)?;
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
        nydus_telemetry::metrics::untrack_blob_groups(&self.cache_key);
    }
}

impl BlobCache for LocalBlobCache {
    fn prefetch_all(&self) -> io::Result<()> {
        let groups = self.blob_metadata.groups();
        if groups.is_empty() {
            return Ok(());
        }
        // Fast path: another process (or an earlier run) already decoded every
        // group; skip the batch planning and per-group readiness scan.
        if !self.blob_metadata.is_redirect_blob() && self.group_map.is_all_ready() {
            return Ok(());
        }

        let cache_file = self.cache_file()?;
        // Prefetch writes the bulk of the cache, so it is worth one stat to
        // make sure the file it fills is still the one other processes read.
        self.ensure_data_file_linked(&cache_file)?;

        // CDC blobs: walk records in unique-offset order so each group is
        // decoded (roughly) once through the memo, and readiness is tracked
        // per record.
        if self.blob_metadata.is_cdc() {
            let chunks = self.blob_metadata.cdc_chunks();
            let mut order: Vec<usize> = (0..chunks.len()).collect();
            order.sort_by_key(|&index| chunks[index].unique_byte_offset());
            let mut memo: HashMap<usize, Vec<u8>> = HashMap::new();
            for index in order {
                if self.group_map.is_ready(index)? {
                    continue;
                }
                self.fill_cdc_record(&chunks[index], &cache_file, &mut memo, ReadKind::Prefetch)?;
                self.group_map.set_ready(index)?;
                nydus_telemetry::metrics::inc_cache_fill_group();
            }
            self.group_map.latch_all_ready();
            return Ok(());
        }

        // Prefetch owns its decode buffers and does not take `fetch_lock`, so it
        // never blocks on-demand FUSE reads. The group_map is internally locked
        // and `set_ready` is idempotent, so racing with a read at worst decodes
        // the same group twice into identical bytes at the same cache offset.
        let mut decoded = Vec::new();
        let mut window = Vec::new();

        for batch in plan_prefetch_batches(groups, BLOB_METADATA_DEFAULT_CHUNK_SIZE as u64) {
            if batch
                .clone()
                .map(|index| self.group_map.is_ready(index))
                .collect::<io::Result<Vec<_>>>()?
                .into_iter()
                .all(|ready| ready)
            {
                continue;
            }

            let window_base = self.fetch_window(groups, &batch, &mut window)?;

            for index in batch {
                if self.group_map.is_ready(index)? {
                    continue;
                }
                let group = &groups[index];
                decode_group_from_window(
                    &self.blob_metadata,
                    &self.backend,
                    group,
                    window_base,
                    &window,
                    &mut decoded,
                )?;
                write_all_at(
                    cache_file.as_ref(),
                    group.uncompressed_byte_offset(),
                    &decoded,
                )?;
                self.group_map.set_ready(index)?;
                nydus_telemetry::metrics::inc_cache_fill_group();
            }
        }

        // A successful full prefetch means every group is now ready (decoded
        // here or observed ready from another process), so guarantee the
        // sticky ALL_READY flag is latched before returning. set_ready
        // normally latches it through the shared ready counter, but a
        // historical writer crash between its bit and counter updates leaves
        // the counter short forever; the authoritative bitmap scan inside
        // latch_all_ready() latches the flag regardless.
        if !self.blob_metadata.is_redirect_blob() {
            self.group_map.latch_all_ready();
        }

        Ok(())
    }

    fn read_at(&self, offset: u64, dst: &mut [u8]) -> io::Result<()> {
        if dst.is_empty() {
            return Ok(());
        }

        let cache_file = self.cache_file()?;
        self.ensure_byte_range(offset, dst.len() as u64, cache_file.as_ref())?;

        // The cache file mirrors the dense uncompressed address space, so once
        // the covering groups are decoded the absolute offset indexes straight
        // into it for a single contiguous read.
        cache_file.as_ref().read_exact_at(dst, offset)
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
        if len == 0 || self.blob_metadata.is_redirect_blob() {
            return Ok(Vec::new());
        }
        let end = offset.checked_add(len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob probe range overflow")
        })?;

        // CDC blobs: readiness is per record. Logical gaps between records
        // (padding/holes) are always "ready" — the sparse cache file already
        // reads back the correct zeros there.
        if self.blob_metadata.is_cdc() {
            let chunks = self.blob_metadata.cdc_chunks();
            let records = self.blob_metadata.cdc_chunks_overlapping(offset, end);
            let mut ranges: Vec<Range<u64>> = Vec::new();
            let mut push = |start: u64, stop: u64| {
                if start >= stop {
                    return;
                }
                match ranges.last_mut() {
                    Some(last) if last.end == start => last.end = stop,
                    _ => ranges.push(start..stop),
                }
            };
            let mut cursor = offset;
            for index in records {
                let chunk = &chunks[index];
                let chunk_start = chunk.logical_byte_offset().max(offset);
                let chunk_end = chunk.logical_byte_end().min(end);
                // The gap before this record is ready zeros.
                push(cursor, chunk_start);
                if self.group_map.is_ready(index)? {
                    push(chunk_start, chunk_end);
                }
                cursor = chunk_end;
            }
            // The tail gap after the last record is ready zeros.
            push(cursor, end);
            return Ok(ranges);
        }

        let (first, last) = self.group_span(offset, end)?.into_inner();

        self.group_map
            .ready_group_ranges(first, last)?
            .into_iter()
            .map(|groups| {
                let first_group = self.blob_metadata.group_at(groups.start).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "blob meta group not found")
                })?;
                let last_group = self.blob_metadata.group_at(groups.end - 1).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "blob meta group not found")
                })?;
                Ok(first_group.uncompressed_byte_offset().max(offset)
                    ..last_group.uncompressed_byte_end().min(end))
            })
            .collect()
    }

    fn is_redirect_blob(&self) -> bool {
        self.blob_metadata.is_redirect_blob()
    }

    /// Acquire the per-blob cross-process prefetch lock, blocking (in 1s
    /// polls) while another process holds it. Modeled after the nydus blob
    /// prefetcher: locking failures degrade to prefetching without the lock
    /// rather than failing the prefetch, and the guard is released when the
    /// returned file is dropped — including on process death, so a crashed
    /// owner's lock is taken over and the group_map-driven skip logic resumes
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
                    "failed to open prefetch lock {}: {err}; prefetching without cross-process lock",
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
                    "failed to acquire prefetch lock for blob {}: {err}; prefetching without cross-process lock",
                    self.blob_index
                );
                return None;
            }
            // Another process is prefetching this blob. For a regular blob the
            // shared group_map tells us when the owner has finished everything,
            // so we can stop waiting; the caller's prefetch then reduces to a
            // cheap all-ready scan. A redirect blob never marks its own map,
            // so keep waiting for the lock and rely on batch skipping.
            if !self.blob_metadata.is_redirect_blob() && self.group_map.latch_all_ready() {
                return None;
            }
            if !contention_logged {
                info!(
                    "prefetch lock for blob {} is held by another process; waiting",
                    self.blob_index
                );
                contention_logged = true;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    fn is_group_ready(&self, group_index: usize) -> bool {
        self.group_map.is_ready(group_index).unwrap_or(false)
    }

    fn is_all_ready(&self) -> bool {
        // A redirect blob never marks its own group_map (its groups fill other
        // blobs' caches), so the flag is meaningless there.
        !self.blob_metadata.is_redirect_blob() && self.group_map.is_all_ready()
    }

    fn for_each_redirect_group(
        &self,
        threads: usize,
        skip: &(dyn Fn(&BlobMetadataGroup) -> bool + Sync),
        cb: &(dyn Fn(&BlobMetadataGroup, &[u8]) -> io::Result<()> + Sync),
    ) -> io::Result<()> {
        let groups = self.blob_metadata.groups();
        if groups.is_empty() {
            return Ok(());
        }

        // Segments whose groups are all already done (per `skip`, typically
        // backed by the shared source groupmaps) are not fetched at all, so a
        // process re-running the warmup behind another one does close to zero
        // backend work. Partially-done batches are still fetched whole to
        // keep the backend reads contiguous.
        let batch_done = |batch: &std::ops::Range<usize>| -> bool {
            batch.clone().all(|index| skip(&groups[index]))
        };

        // A small ondemand blob (fits in one batch) or a single worker is
        // streamed sequentially with default-sized batches: batching and
        // extra registry connections would add overhead without overlapping any
        // work.
        let total_uncompressed: u64 = groups
            .iter()
            .map(|group| group.uncompressed_byte_size())
            .sum();
        if threads <= 1 || total_uncompressed <= super::REDIRECT_PREFETCH_BATCH_SIZE {
            let mut window = Vec::new();
            let mut decoded = Vec::new();
            for batch in plan_prefetch_batches(groups, super::REDIRECT_PREFETCH_BATCH_SIZE) {
                if batch_done(&batch) {
                    continue;
                }
                self.stream_redirect_batch(groups, batch, &mut window, &mut decoded, cb)?;
            }
            return Ok(());
        }

        // Larger blob: fetch batches concurrently. The earliest groups are
        // emitted one per batch (a "ramp") so they land in the first wave of
        // workers within a single round trip, ahead of the workload's first
        // faults; the rest are bundled into REDIRECT_PREFETCH_BATCH_SIZE
        // batches for throughput.
        let batches = super::plan_redirect_batches(
            groups,
            super::REDIRECT_PREFETCH_BATCH_SIZE,
            super::REDIRECT_PREFETCH_RAMP_GROUPS,
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
                        let idx = next.fetch_add(1, Ordering::Relaxed);
                        let Some(batch) = batches.get(idx) else {
                            break;
                        };
                        if batch_done(batch) {
                            continue;
                        }
                        if let Err(err) = self.stream_redirect_batch(
                            groups,
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

    fn fill_group_from_redirect(&self, group_index: usize, decoded: &[u8]) -> io::Result<()> {
        let group = self.blob_metadata.group_at(group_index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "redirect fill group index out of range",
            )
        })?;
        if self.group_map.is_ready(group_index)? {
            nydus_telemetry::metrics::inc_cache_hit_group();
            return Ok(());
        }
        // Cross-check against this blob's own group metadata: the redirect
        // group's crc32 was copied from this source group at optimize time, so
        // any divergence (stale optimize artifact, corrupted transfer) is
        // caught here before it can poison the cache.
        super::validate_group_with_metrics(&self.backend, group, decoded)?;
        let cache_file = self.cache_file()?;
        write_all_at(
            cache_file.as_ref(),
            group.uncompressed_byte_offset(),
            decoded,
        )?;
        self.group_map.set_ready(group_index)?;
        nydus_telemetry::metrics::inc_cache_redirect_fill_group();
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
        if let Err(err) = BlobMetadata::loader()
            .verify_crc32()
            .blob_id(blob_id)
            .load(tmp.path())
        {
            return Err(io::Error::other(err));
        }
        tmp.persist(blob_metadata_path).map_err(|err| err.error)?;
    }

    BlobMetadata::loader()
        .verify_crc32()
        .blob_id(blob_id)
        .load(blob_metadata_path)
        .map_err(io::Error::other)
}

/// Drop guard that ensures a leader always signals its flight and cleans up
/// the inflight map, even when the fetch body panics. Without this, a panic in
/// `fetch_decode_validate_group_into` (or any helper it calls) would leave
/// follower threads permanently blocked in `flight.wait()`.
struct LeaderGuard<'a> {
    flight: Arc<GroupFlight>,
    group_index: usize,
    inflight: &'a Mutex<HashMap<usize, Arc<GroupFlight>>>,
}

impl<'a> Drop for LeaderGuard<'a> {
    fn drop(&mut self) {
        // complete is idempotent: if the leader called `flight.complete(...)`
        // normally before Drop runs, this is a no-op.
        self.flight.complete(&Err(io::Error::other(
            "group leader panicked or was abandoned",
        )));
        self.inflight.lock().unwrap().remove(&self.group_index);
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
    use nydus_format::blob::{BlobMetadataChunk, BlobMetadataGroup};
    use nydus_format::utils::sha256_bytes;
    use std::path::Path;
    use tempfile::tempdir;

    fn blob_metadata(blob_id: [u8; SHA256_DIGEST_SIZE], payload: &[u8]) -> BlobMetadata {
        blob_metadata_with_crc32(blob_id, payload, crc32c::crc32c(payload))
    }

    fn blob_metadata_with_crc32(
        blob_id: [u8; SHA256_DIGEST_SIZE],
        payload: &[u8],
        crc32: u32,
    ) -> BlobMetadata {
        BlobMetadata::from_parts(
            blob_id,
            1,
            vec![BlobMetadataGroup::new(0, 1, 0, 4096, crc32).unwrap()],
            vec![BlobMetadataChunk::new(*blake3::hash(payload).as_bytes(), 0, 1).unwrap()],
        )
        .unwrap()
    }

    use nydus_format::utils::write_minimal_full_blob;

    /// Wraps a real backend and counts data-range reads, so tests can assert
    /// that cross-process sharing (group_map + prefetch lock + batch skip)
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
        let data_blob_id = sha256_bytes(&payload);
        let meta = blob_metadata(data_blob_id, &payload);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, true);

        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));
        let cached = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();

        let mut buf = vec![0u8; 1024];
        cached.read_at(512, &mut buf).unwrap();

        assert_eq!(buf, payload[512..1536]);
        assert!(cached.group_map.is_ready(0).unwrap());
    }

    /// A CDC blob whose 8 KiB unique stream backs a 16 KiB logical space:
    /// three records, two of which share the same unique bytes (the dedup),
    /// with logical gaps (holes) that must read back as zeros.
    fn cdc_fixture(backend_dir: &Path) -> ([u8; SHA256_DIGEST_SIZE], Vec<u8>) {
        use nydus_format::blob::BlobMetadataCdcChunk;

        let mut unique = vec![0u8; 8192];
        for (index, byte) in unique.iter_mut().enumerate() {
            *byte = (index % 251) as u8 + 1;
        }
        let data_blob_id = sha256_bytes(&unique);
        let records = vec![
            BlobMetadataCdcChunk::new(*blake3::hash(&unique[..5000]).as_bytes(), 0, 0, 5000)
                .unwrap(),
            BlobMetadataCdcChunk::new(*blake3::hash(&unique[..5000]).as_bytes(), 8192, 0, 5000)
                .unwrap(),
            BlobMetadataCdcChunk::new(
                *blake3::hash(&unique[5000..7000]).as_bytes(),
                13500,
                5000,
                2000,
            )
            .unwrap(),
        ];
        let meta = BlobMetadata::from_cdc_parts(
            data_blob_id,
            1,
            nydus_format::blob::BlobMetadataCompressor::None,
            vec![BlobMetadataGroup::new(0, 2, 0, 8192, crc32c::crc32c(&unique)).unwrap()],
            records,
            4,
        )
        .unwrap();
        let full_blob_id = write_minimal_full_blob(backend_dir, &unique, &meta, true);

        // The expected logical space: record bytes at their logical offsets,
        // zeros everywhere else.
        let mut logical = vec![0u8; 4 * 4096];
        logical[..5000].copy_from_slice(&unique[..5000]);
        logical[8192..13192].copy_from_slice(&unique[..5000]);
        logical[13500..15500].copy_from_slice(&unique[5000..7000]);
        (full_blob_id, logical)
    }

    #[test]
    fn cdc_blob_cache_reads_dedup_records_and_holes() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let (full_blob_id, logical) = cdc_fixture(backend_dir.path());
        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));

        let cached = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();
        assert!(cached.blob_metadata().is_cdc());

        // A read spanning a record tail, a hole, and a deduped record.
        let mut buf = vec![0u8; 9000];
        cached.read_at(4000, &mut buf).unwrap();
        assert_eq!(buf, logical[4000..13000]);
        // Records 0 and 1 were needed; record 2 stays cold.
        assert!(cached.group_map.is_ready(0).unwrap());
        assert!(cached.group_map.is_ready(1).unwrap());
        assert!(!cached.group_map.is_ready(2).unwrap());

        // A pure-hole read touches no record.
        let mut hole = vec![0xffu8; 1000];
        cached.read_at(5500, &mut hole).unwrap();
        assert!(hole.iter().all(|byte| *byte == 0));

        // ready_ranges: holes count as ready, cold records do not.
        let ranges = cached.ready_ranges(0, 4 * 4096).unwrap();
        assert_eq!(ranges, vec![0..13500, 15500..4 * 4096]);

        // Whole logical space after warming everything.
        let mut all = vec![0u8; logical.len()];
        cached.read_at(0, &mut all).unwrap();
        assert_eq!(all, logical);
        assert_eq!(cached.ready_ranges(0, 4 * 4096).unwrap(), vec![0..4 * 4096]);
    }

    #[test]
    fn cdc_blob_cache_prefetch_fills_everything() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let (full_blob_id, logical) = cdc_fixture(backend_dir.path());
        let backend = CountingBackend::new(backend_dir.path());

        let cached = LocalBlobCache::open(
            full_blob_id,
            1,
            cache_dir.path(),
            backend.clone() as Arc<dyn BlobBackend>,
        )
        .unwrap();
        let reads_before_prefetch = backend.reads();
        cached.prefetch_all().unwrap();
        // Three records but a single group: the decode memo must keep it to
        // one backend data read.
        assert_eq!(backend.reads() - reads_before_prefetch, 1);
        assert!(cached.group_map.is_all_ready());

        let mut all = vec![0u8; logical.len()];
        cached.read_at(0, &mut all).unwrap();
        assert_eq!(all, logical);
        // Fully prefetched: reading adds no backend traffic.
        assert_eq!(backend.reads() - reads_before_prefetch, 1);
    }

    #[test]
    fn stale_groupmap_without_data_file_is_reset() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x3du8; 4096];
        let data_blob_id = sha256_bytes(&payload);
        let meta = blob_metadata(data_blob_id, &payload);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, true);
        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));

        // Warm the cache: data file created, group marked ready, sticky
        // all-ready flag latched.
        {
            let cached =
                LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend.clone()).unwrap();
            let mut buf = vec![0u8; 1024];
            cached.read_at(0, &mut buf).unwrap();
            assert!(cached.group_map.is_all_ready());
        }

        // Model the operational accident: the data file is removed while the
        // group_map survives. Reopening must reset the group_map instead of
        // trusting ready bits that now point at sparse holes.
        let cache_key = backend.cache_key(&full_blob_id).unwrap();
        let prefix = hex_string(&cache_key);
        fs::remove_file(cache_dir.path().join(format!("{prefix}.blob.data"))).unwrap();

        let reopened = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();
        assert!(!reopened.group_map.is_ready(0).unwrap());
        assert!(!reopened.group_map.is_all_ready());

        // The blob still reads correctly end-to-end after the reset.
        let mut buf = vec![0u8; 1024];
        reopened.read_at(512, &mut buf).unwrap();
        assert_eq!(buf, payload[512..1536]);
    }

    #[test]
    fn stale_groupmap_reset_keeps_the_same_inode() {
        use std::os::unix::fs::MetadataExt;

        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x2eu8; 4096];
        let data_blob_id = sha256_bytes(&payload);
        let meta = blob_metadata(data_blob_id, &payload);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, true);
        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));

        // A live handle keeps the group_map mapped throughout, standing in for
        // a process that is already running when the accident happens.
        let live =
            LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend.clone()).unwrap();
        let mut buf = vec![0u8; 1024];
        live.read_at(0, &mut buf).unwrap();
        assert!(live.group_map.is_ready(0).unwrap());

        let cache_key = backend.cache_key(&full_blob_id).unwrap();
        let prefix = hex_string(&cache_key);
        let groupmap_path = cache_dir.path().join(format!("{prefix}.group.map"));
        let before = fs::metadata(&groupmap_path).unwrap().ino();
        fs::remove_file(cache_dir.path().join(format!("{prefix}.blob.data"))).unwrap();

        let reopened = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();
        assert_eq!(
            fs::metadata(&groupmap_path).unwrap().ino(),
            before,
            "the reset must not replace the group_map file"
        );

        // Because the inode is unchanged, the reset is visible through the
        // mapping the live handle already holds; a replacement inode would
        // have left it advertising readiness nobody else can see.
        assert!(!live.group_map.is_ready(0).unwrap());
        assert!(!reopened.group_map.is_ready(0).unwrap());
    }

    #[test]
    fn prefetch_lock_dedups_across_handles() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x5au8; 4096];
        let data_blob_id = sha256_bytes(&payload);
        let meta = blob_metadata(data_blob_id, &payload);
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
        // lock (returning None) instead of waiting, since the shared group_map
        // already reports everything ready.
        owner.group_map.set_ready(0).unwrap();
        assert!(waiter.prefetch_lock().is_none());
        assert!(waiter.is_group_ready(0));

        // Once the owner releases the lock, it is acquirable again.
        drop(guard);
        assert!(waiter.prefetch_lock().is_some());
    }

    #[test]
    fn prefetch_lock_degrades_when_lock_file_unusable() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x21u8; 4096];
        let data_blob_id = sha256_bytes(&payload);
        let meta = blob_metadata(data_blob_id, &payload);
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
        let data_blob_id = sha256_bytes(&payload);
        let meta = blob_metadata(data_blob_id, &payload);
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
        let data_blob_id = sha256_bytes(&payload);
        let meta = blob_metadata(data_blob_id, &payload);
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
        first.prefetch_all().unwrap();
        let after_owner = backend.reads();
        assert!(after_owner > 0, "owner must stream from the backend");

        // While the owner still holds the lock, a contending instance sees
        // every group ready through the shared group_map and gives up on the
        // lock (None) instead of waiting.
        assert!(second.prefetch_lock().is_none());
        drop(guard);

        // Repeating the prefetch afterwards issues zero backend reads: every
        // group is already ready in the shared cache.
        second.prefetch_all().unwrap();
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

        // An ondemand (redirect) blob whose single group redirects to source
        // blob 1 group 0; its data region carries a copy of the source bytes.
        let redirect_meta = BlobMetadata::from_parts(
            sha256_bytes(&payload),
            1,
            vec![BlobMetadataGroup::new_redirect(0, 1, 0, 4096, crc32, 1, 0).unwrap()],
            Vec::new(),
        )
        .unwrap();
        assert!(redirect_meta.is_redirect_blob());
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
                .for_each_redirect_group(1, &|_group| skip_all, &|group, decoded| {
                    assert!(group.is_redirect());
                    assert_eq!(decoded, payload);
                    delivered.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                .unwrap();
            (backend.reads() - baseline, delivered.load(Ordering::SeqCst))
        };

        // Nothing done yet: the batch is fetched and the group delivered.
        let (reads, delivered) = run(false);
        assert!(reads > 0);
        assert_eq!(delivered, 1);

        // Every group reported done (e.g. resident in the source caches of a
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
        let data_blob_id = sha256_bytes(&payload);
        let meta = blob_metadata(data_blob_id, &payload);
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
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0xacu8; 4096];
        let data_blob_id = sha256_bytes(&payload);
        let meta = blob_metadata_with_crc32(
            data_blob_id,
            &payload,
            crc32c::crc32c(&payload).wrapping_add(1),
        );
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, true);

        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));
        let cached = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();

        let mut buf = vec![0u8; 1024];
        let err = cached.read_at(512, &mut buf).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("crc32"));
        assert!(!cached.group_map.is_ready(0).unwrap());
    }

    #[test]
    fn local_blob_cache_reads_data_region_relative_compressed_offsets() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x3du8; 4096];
        let data_blob_id = sha256_bytes(&payload);
        let meta = blob_metadata(data_blob_id, &payload);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, false);

        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));
        let cached = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();

        let mut buf = vec![0u8; 512];
        cached.read_at(256, &mut buf).unwrap();

        assert_eq!(buf, payload[256..768]);
        assert!(cached.group_map.is_ready(0).unwrap());
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
    fn fill_group_from_redirect_validates_then_caches() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x6eu8; 4096];
        let data_blob_id = sha256_bytes(&payload);
        let meta = blob_metadata(data_blob_id, &payload);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, true);

        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));
        let cached = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();
        assert!(!cached.is_redirect_blob());

        // Wrong length is rejected and the group stays not-ready.
        let err = cached
            .fill_group_from_redirect(0, &payload[..1024])
            .unwrap_err();
        assert!(err.to_string().contains("length mismatch"));
        assert!(!cached.group_map.is_ready(0).unwrap());

        // Corrupted bytes fail the CRC cross-check.
        let mut corrupted = payload.clone();
        corrupted[0] ^= 0xff;
        let err = cached.fill_group_from_redirect(0, &corrupted).unwrap_err();
        assert!(super::super::is_group_crc_mismatch(&err));
        assert!(!cached.group_map.is_ready(0).unwrap());

        // Valid bytes are cached, marked ready, and served without the backend.
        cached.fill_group_from_redirect(0, &payload).unwrap();
        assert!(cached.group_map.is_ready(0).unwrap());
        let mut buf = vec![0u8; 1024];
        cached.read_at(512, &mut buf).unwrap();
        assert_eq!(buf, payload[512..1536]);

        // Out-of-range index is rejected.
        assert!(cached.fill_group_from_redirect(7, &payload).is_err());
    }
}
