use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::ops::Range;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use tracing::{info, warn};
use uuid::Uuid;

use crate::metadata::{BlobMeta, BlobMetaGroup, BLOB_META_DEFAULT_CHUNK_SIZE, EROFS_BLOB_ID_SIZE};
use crate::metrics::trace::TraceRecorder;
use crate::storage::backend::{BlobBackend, ReadContext, RequestSource};
use crate::storage::groupmap::GroupMap;
use crate::utils::hex_string;

use super::{
    decode_group_from_window, fetch_decode_validate_group_into, plan_prefetch_batches, BlobCache,
    BlobCacheBuffers,
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
    blob_id: [u8; EROFS_BLOB_ID_SIZE],
    /// Device/blob index in the merged image, used to attribute on-demand group
    /// accesses in the access trace.
    blob_index: u32,
    groupmap: GroupMap,
    blob_meta: BlobMeta,
    cache_blob_path: PathBuf,
    prefetch_lock_path: PathBuf,
    cache_file: Mutex<Option<Arc<File>>>,
    backend: Arc<dyn BlobBackend>,
    trace_recorder: Option<Arc<TraceRecorder>>,
    inflight_groups: Mutex<HashMap<usize, Arc<GroupFlight>>>,
}

impl LocalBlobCache {
    pub fn open(
        blob_id: [u8; EROFS_BLOB_ID_SIZE],
        blob_index: u32,
        cache_dir: &Path,
        backend: Arc<dyn BlobBackend>,
    ) -> io::Result<Self> {
        Self::open_with_trace(blob_id, blob_index, cache_dir, backend, None)
    }

    pub fn open_with_trace(
        blob_id: [u8; EROFS_BLOB_ID_SIZE],
        blob_index: u32,
        cache_dir: &Path,
        backend: Arc<dyn BlobBackend>,
        trace_recorder: Option<Arc<TraceRecorder>>,
    ) -> io::Result<Self> {
        fs::create_dir_all(cache_dir)?;

        let cache_key = backend.cache_key(&blob_id)?;
        let cache_key_hex = hex_string(&cache_key);
        let blob_meta_path = cache_dir.join(format!("{cache_key_hex}.blob.meta"));
        let blob_meta = load_cached_blob_meta(blob_id, cache_dir, &blob_meta_path, &backend)?;
        crate::metrics::add_cache_total_groups(blob_meta.group_count() as u64);

        let cache_blob_path = cache_dir.join(format!("{cache_key_hex}.blob.data"));

        let groupmap_path = cache_dir.join(format!("{cache_key_hex}.groupmap"));
        let groupmap = GroupMap::open(&groupmap_path, blob_meta.group_count())?;

        let prefetch_lock_path = cache_dir.join(format!("{cache_key_hex}.prefetch.lock"));

        Ok(Self {
            blob_id,
            blob_index,
            groupmap,
            blob_meta,
            cache_blob_path,
            prefetch_lock_path,
            cache_file: Mutex::new(None),
            backend,
            trace_recorder,
            inflight_groups: Mutex::new(HashMap::new()),
        })
    }

    /// The blob meta backing this cache (groups, chunks, compressor).
    pub fn blob_meta(&self) -> &BlobMeta {
        &self.blob_meta
    }

    fn cache_file(&self) -> io::Result<Arc<File>> {
        let mut cache_file = self.cache_file.lock().unwrap();
        if let Some(file) = cache_file.as_ref() {
            return Ok(file.clone());
        }

        let file = Arc::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&self.cache_blob_path)?,
        );
        file.set_len(self.blob_meta.cache_size())?;
        crate::metrics::inc_cache_opened_files();
        *cache_file = Some(file.clone());
        Ok(file)
    }

    fn ensure_group(
        &self,
        group_index: usize,
        group: &BlobMetaGroup,
        cache_file: &File,
    ) -> io::Result<()> {
        if self.groupmap.is_ready(group_index)? {
            crate::metrics::inc_cache_hit_group();
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
            if self.groupmap.is_ready(group_index)? {
                crate::metrics::inc_cache_hit_group();
                return Ok(());
            }
            if let Some(recorder) = self.trace_recorder.as_ref() {
                recorder.record_group_access(self.blob_index, group_index as u32);
            } else {
                crate::metrics::trace::record_group_access(self.blob_index, group_index as u32);
            }

            let mut buffers = BlobCacheBuffers::default();
            let decoded = fetch_decode_validate_group_into(
                &self.blob_id,
                &self.blob_meta,
                &self.backend,
                group,
                &mut buffers,
                RequestSource::OnDemand,
            )?;
            write_all_at(cache_file, group.uncompressed_byte_offset(), decoded)?;
            self.groupmap.set_ready(group_index)
        })();

        // Notify followers with the actual result.
        // complete() is idempotent: the guard's Drop then no-ops.
        flight.complete(&result);
        // guard is dropped here: inflight entry removed, complete(Err) no-ops
        result
    }

    /// Ensure every group overlapping `[offset, offset + len)` is decoded and
    /// written to the cache file. Shared by `read_at` and `ensure_range`.
    fn ensure_byte_range(&self, offset: u64, len: u64, cache_file: &File) -> io::Result<()> {
        // Redirect (ondemand) blobs have a non-uniform group layout, so the
        // O(1) division-based group lookup below does not apply; they are
        // consumed exclusively through `redirect_stream`.
        if self.blob_meta.is_redirect_blob() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "redirect blob has no dense readable address space",
            ));
        }

        let end = offset.checked_add(len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob read range overflow")
        })?;

        // O(1) group lookup at both ends of the range. Groups are dense and
        // contiguous, so every group between the first and last also overlaps
        // the range and must be decoded.
        let first_group = self
            .blob_meta
            .group_index_for_byte_offset(offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "blob meta group not found"))?;
        let last_group = self
            .blob_meta
            .group_index_for_byte_offset(end - 1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "blob meta group not found"))?;

        for group_index in first_group..=last_group {
            let group = *self.blob_meta.group_at(group_index).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "blob meta group not found")
            })?;
            self.ensure_group(group_index, &group, cache_file)?;
        }
        Ok(())
    }

    /// Fetch one redirect-blob segment (a contiguous range of groups) in a
    /// single backend read, then decode and hand each group to `cb`. `window`
    /// and `decoded` are caller-owned scratch buffers so a worker thread can
    /// reuse them across segments. Per-group decode/CRC failures are skipped
    /// with a warning; `cb` errors propagate to abort the stream.
    fn stream_redirect_segment(
        &self,
        groups: &[BlobMetaGroup],
        batch: std::ops::Range<usize>,
        window: &mut Vec<u8>,
        decoded: &mut Vec<u8>,
        cb: &(dyn Fn(&BlobMetaGroup, &[u8]) -> io::Result<()> + Sync),
    ) -> io::Result<()> {
        let window_base = groups[batch.start].compressed_byte_offset();
        let window_end = groups[batch.end - 1].compressed_byte_end();
        let window_len = usize::try_from(window_end - window_base).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "blob redirect window size exceeds usize",
            )
        })?;
        window.resize(window_len, 0);
        let uncompressed_offset = groups[batch.start].uncompressed_byte_offset();
        let uncompressed_size = groups[batch.end - 1].uncompressed_byte_end() - uncompressed_offset;
        let ctx = ReadContext::group(
            RequestSource::Prefetch,
            uncompressed_offset,
            uncompressed_size,
        );
        self.backend
            .read_range_into(&self.blob_id, window_base, window, ctx)?;
        crate::metrics::record_backend_redirect_read(window_len as u64);

        for index in batch {
            let group = &groups[index];
            if let Err(err) =
                decode_group_from_window(&self.blob_meta, group, window_base, window, decoded)
            {
                if super::is_group_crc_mismatch(&err) {
                    crate::metrics::record_backend_crc_error(self.backend.backend_target());
                }
                crate::metrics::inc_cache_redirect_skip_group();
                warn!("skipping redirect group {index}: {err}");
                continue;
            }
            cb(group, decoded)?;
        }
        Ok(())
    }
}

impl BlobCache for LocalBlobCache {
    fn prefetch_all(&self) -> io::Result<()> {
        let groups = self.blob_meta.groups();
        if groups.is_empty() {
            return Ok(());
        }

        let cache_file = self.cache_file()?;
        // Prefetch owns its decode buffers and does not take `fetch_lock`, so it
        // never blocks on-demand FUSE reads. The groupmap is internally locked
        // and `set_ready` is idempotent, so racing with a read at worst decodes
        // the same group twice into identical bytes at the same cache offset.
        let mut decoded = Vec::new();
        let mut window = Vec::new();

        for batch in plan_prefetch_batches(groups, BLOB_META_DEFAULT_CHUNK_SIZE as u64) {
            if batch
                .clone()
                .map(|index| self.groupmap.is_ready(index))
                .collect::<io::Result<Vec<_>>>()?
                .into_iter()
                .all(|ready| ready)
            {
                continue;
            }

            let window_base = groups[batch.start].compressed_byte_offset();
            let window_end = groups[batch.end - 1].compressed_byte_end();
            let window_len = usize::try_from(window_end - window_base).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "blob prefetch window size exceeds usize",
                )
            })?;
            window.resize(window_len, 0);
            // One backend request covers the whole window (a contiguous batch of
            // groups); report its uncompressed span for diagnostics.
            let uncompressed_offset = groups[batch.start].uncompressed_byte_offset();
            let uncompressed_size =
                groups[batch.end - 1].uncompressed_byte_end() - uncompressed_offset;
            let ctx = ReadContext::group(
                RequestSource::Prefetch,
                uncompressed_offset,
                uncompressed_size,
            );
            self.backend
                .read_range_into(&self.blob_id, window_base, &mut window, ctx)?;

            for index in batch {
                if self.groupmap.is_ready(index)? {
                    continue;
                }
                let group = &groups[index];
                if let Err(err) = decode_group_from_window(
                    &self.blob_meta,
                    group,
                    window_base,
                    &window,
                    &mut decoded,
                ) {
                    if super::is_group_crc_mismatch(&err) {
                        crate::metrics::record_backend_crc_error(self.backend.backend_target());
                    }
                    return Err(err);
                }
                write_all_at(
                    cache_file.as_ref(),
                    group.uncompressed_byte_offset(),
                    &decoded,
                )?;
                self.groupmap.set_ready(index)?;
                crate::metrics::inc_cache_fill_group();
            }
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
        read_exact_at(cache_file.as_ref(), offset, dst)
    }

    fn prepare(&self) -> io::Result<PathBuf> {
        // Opening the cache file creates it (sparse) and sizes it to the dense
        // uncompressed address space.
        self.cache_file()?;
        Ok(self.cache_blob_path.clone())
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
        if len == 0 || self.blob_meta.is_redirect_blob() {
            return Ok(Vec::new());
        }
        let end = offset.checked_add(len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob probe range overflow")
        })?;
        let first = self
            .blob_meta
            .group_index_for_byte_offset(offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "blob meta group not found"))?;
        let last = self
            .blob_meta
            .group_index_for_byte_offset(end - 1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "blob meta group not found"))?;

        self.groupmap
            .ready_ranges(first, last)?
            .into_iter()
            .map(|groups| {
                let first_group = self.blob_meta.group_at(groups.start).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "blob meta group not found")
                })?;
                let last_group = self.blob_meta.group_at(groups.end - 1).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "blob meta group not found")
                })?;
                Ok(first_group.uncompressed_byte_offset().max(offset)
                    ..last_group.uncompressed_byte_end().min(end))
            })
            .collect()
    }

    fn is_redirect_blob(&self) -> bool {
        self.blob_meta.is_redirect_blob()
    }

    /// Acquire the per-blob cross-process prefetch lock, blocking (in 1s
    /// polls) while another process holds it. Modeled after the nydus blob
    /// prefetcher: locking failures degrade to prefetching without the lock
    /// rather than failing the prefetch, and the guard is released when the
    /// returned file is dropped — including on process death, so a crashed
    /// owner's lock is taken over and the groupmap-driven skip logic resumes
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
            // shared groupmap tells us when the owner has finished everything,
            // so we can stop waiting; the caller's prefetch then reduces to a
            // cheap all-ready scan. A redirect blob never marks its own map,
            // so keep waiting for the lock and rely on segment skipping.
            if !self.blob_meta.is_redirect_blob() && self.groupmap.all_ready() {
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

    fn group_ready(&self, group_index: usize) -> bool {
        self.groupmap.is_ready(group_index).unwrap_or(false)
    }

    fn redirect_stream(
        &self,
        cb: &mut dyn FnMut(&BlobMetaGroup, &[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let groups = self.blob_meta.groups();
        if groups.is_empty() {
            return Ok(());
        }

        let mut decoded = Vec::new();
        let mut window = Vec::new();

        for batch in plan_prefetch_batches(groups, BLOB_META_DEFAULT_CHUNK_SIZE as u64) {
            let window_base = groups[batch.start].compressed_byte_offset();
            let window_end = groups[batch.end - 1].compressed_byte_end();
            let window_len = usize::try_from(window_end - window_base).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "blob redirect window size exceeds usize",
                )
            })?;
            window.resize(window_len, 0);
            let uncompressed_offset = groups[batch.start].uncompressed_byte_offset();
            let uncompressed_size =
                groups[batch.end - 1].uncompressed_byte_end() - uncompressed_offset;
            let ctx = ReadContext::group(
                RequestSource::Prefetch,
                uncompressed_offset,
                uncompressed_size,
            );
            self.backend
                .read_range_into(&self.blob_id, window_base, &mut window, ctx)?;
            crate::metrics::record_backend_redirect_read(window_len as u64);

            for index in batch {
                let group = &groups[index];
                if let Err(err) = decode_group_from_window(
                    &self.blob_meta,
                    group,
                    window_base,
                    &window,
                    &mut decoded,
                ) {
                    if super::is_group_crc_mismatch(&err) {
                        crate::metrics::record_backend_crc_error(self.backend.backend_target());
                    }
                    crate::metrics::inc_cache_redirect_skip_group();
                    warn!("skipping redirect group {index}: {err}");
                    continue;
                }
                cb(group, &decoded)?;
            }
        }

        Ok(())
    }

    fn redirect_stream_parallel(
        &self,
        threads: usize,
        skip: &(dyn Fn(&BlobMetaGroup) -> bool + Sync),
        cb: &(dyn Fn(&BlobMetaGroup, &[u8]) -> io::Result<()> + Sync),
    ) -> io::Result<()> {
        let groups = self.blob_meta.groups();
        if groups.is_empty() {
            return Ok(());
        }

        // Segments whose groups are all already done (per `skip`, typically
        // backed by the shared source groupmaps) are not fetched at all, so a
        // process re-running the warmup behind another one does close to zero
        // backend work. Partially-done segments are still fetched whole to
        // keep the backend reads contiguous.
        let segment_done = |segment: &std::ops::Range<usize>| -> bool {
            segment.clone().all(|index| skip(&groups[index]))
        };

        // A small ondemand blob (fits in one segment) or a single worker is
        // streamed sequentially with default-sized segments: segmentation and
        // extra registry connections would add overhead without overlapping any
        // work.
        let total_uncompressed: u64 = groups
            .iter()
            .map(|group| group.uncompressed_byte_size())
            .sum();
        if threads <= 1 || total_uncompressed <= super::REDIRECT_PREFETCH_SEGMENT_SIZE {
            let mut window = Vec::new();
            let mut decoded = Vec::new();
            for segment in plan_prefetch_batches(groups, super::REDIRECT_PREFETCH_SEGMENT_SIZE) {
                if segment_done(&segment) {
                    continue;
                }
                self.stream_redirect_segment(groups, segment, &mut window, &mut decoded, cb)?;
            }
            return Ok(());
        }

        // Larger blob: fetch segments concurrently. The earliest groups are
        // emitted one per segment (a "ramp") so they land in the first wave of
        // workers within a single round trip, ahead of the workload's first
        // faults; the rest are bundled into REDIRECT_PREFETCH_SEGMENT_SIZE
        // segments for throughput.
        let segments = super::plan_redirect_segments(
            groups,
            super::REDIRECT_PREFETCH_SEGMENT_SIZE,
            super::REDIRECT_PREFETCH_RAMP_GROUPS,
        );
        let worker_count = threads.min(segments.len());
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
                        let Some(segment) = segments.get(idx) else {
                            break;
                        };
                        if segment_done(segment) {
                            continue;
                        }
                        if let Err(err) = self.stream_redirect_segment(
                            groups,
                            segment.clone(),
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
        let group = self.blob_meta.group_at(group_index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "redirect fill group index out of range",
            )
        })?;
        if self.groupmap.is_ready(group_index)? {
            crate::metrics::inc_cache_hit_group();
            return Ok(());
        }
        // Cross-check against this blob's own group metadata: the redirect
        // group's crc32 was copied from this source group at optimize time, so
        // any divergence (stale optimize artifact, corrupted transfer) is
        // caught here before it can poison the cache.
        super::validate_decoded_group(group, decoded)?;
        let cache_file = self.cache_file()?;
        write_all_at(
            cache_file.as_ref(),
            group.uncompressed_byte_offset(),
            decoded,
        )?;
        self.groupmap.set_ready(group_index)?;
        crate::metrics::inc_cache_redirect_fill_group();
        Ok(())
    }
}

fn load_cached_blob_meta(
    blob_id: [u8; EROFS_BLOB_ID_SIZE],
    cache_dir: &Path,
    blob_meta_path: &Path,
    backend: &Arc<dyn BlobBackend>,
) -> io::Result<BlobMeta> {
    if !blob_meta_path.is_file() {
        let tmp_path = cache_dir.join(format!(".blob-meta-{}.tmp", Uuid::new_v4()));
        backend.download_blob_meta(&blob_id, &tmp_path)?;
        if let Err(err) = BlobMeta::load_checked_crc32_with_blob_id(&tmp_path, blob_id) {
            let _ = fs::remove_file(&tmp_path);
            return Err(io::Error::other(err));
        }
        fs::rename(&tmp_path, blob_meta_path)?;
    }

    BlobMeta::load_checked_crc32_with_blob_id(blob_meta_path, blob_id).map_err(io::Error::other)
}

fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    let mut read_total = 0usize;
    while read_total < buf.len() {
        let read = file.read_at(&mut buf[read_total..], offset + read_total as u64)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "cache file read ended early",
            ));
        }
        read_total += read;
    }
    Ok(())
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
    use crate::metadata::{
        BlobFooter, BlobMetaChunk, BlobMetaGroup, ErofsSuperblock, EROFS_BLOCK_SIZE,
        EROFS_SUPER_OFFSET,
    };
    use crate::storage::backend::LocalBackend;
    use crate::utils::sha256_bytes;
    use std::io::Write;
    use std::path::Path;
    use tempfile::tempdir;

    fn blob_meta(blob_id: [u8; EROFS_BLOB_ID_SIZE], payload: &[u8]) -> BlobMeta {
        blob_meta_with_crc32(blob_id, payload, crc32c::crc32c(payload))
    }

    fn blob_meta_with_crc32(
        blob_id: [u8; EROFS_BLOB_ID_SIZE],
        payload: &[u8],
        crc32: u32,
    ) -> BlobMeta {
        BlobMeta::from_parts(
            blob_id,
            1,
            vec![BlobMetaGroup::new(0, 1, 0, 4096, crc32).unwrap()],
            vec![BlobMetaChunk::new(*blake3::hash(payload).as_bytes(), 0, 1).unwrap()],
        )
        .unwrap()
    }

    fn write_full_blob(
        dir: &Path,
        payload: &[u8],
        blob_meta: &BlobMeta,
        save_sidecar: bool,
    ) -> [u8; EROFS_BLOB_ID_SIZE] {
        let mut bootstrap = vec![0u8; 8192];
        let sb = ErofsSuperblock::new(0, 0, 0, 0, 0, 2, 1, 0, 0, &[0u8; 16]);
        let sb_start = EROFS_SUPER_OFFSET as usize;
        let sb_end = sb_start + sb.as_bytes().len();
        bootstrap[sb_start..sb_end].copy_from_slice(sb.as_bytes());

        let footer = BlobFooter::new(
            0,
            payload.len() as u64,
            payload.len() as u64,
            (bootstrap.len() as u64 / EROFS_BLOCK_SIZE as u64) as u32,
            payload.len() as u64 + bootstrap.len() as u64,
            (blob_meta.metadata_size() / EROFS_BLOCK_SIZE as u64) as u32,
        )
        .unwrap();

        let mut full_blob = Vec::new();
        full_blob.write_all(payload).unwrap();
        full_blob.write_all(&bootstrap).unwrap();
        blob_meta.write_to(&mut full_blob).unwrap();
        footer.write_to(&mut full_blob).unwrap();
        let full_blob_id = sha256_bytes(&full_blob);

        fs::write(dir.join(hex_string(&full_blob_id)), &full_blob).unwrap();
        if save_sidecar {
            blob_meta
                .save(&dir.join(format!("{}.blob.meta", hex_string(&full_blob_id))))
                .unwrap();
        }

        full_blob_id
    }

    /// Wraps a real backend and counts data-range reads, so tests can assert
    /// that cross-process sharing (groupmap + prefetch lock + segment skip)
    /// actually eliminates duplicate backend traffic.
    struct CountingBackend {
        inner: LocalBackend,
        reads: AtomicUsize,
    }

    impl CountingBackend {
        fn new(dir: &Path) -> Arc<Self> {
            Arc::new(Self {
                inner: LocalBackend::new(dir.to_path_buf()),
                reads: AtomicUsize::new(0),
            })
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl BlobBackend for CountingBackend {
        fn load_blob_meta(&self, blob_id: &[u8; EROFS_BLOB_ID_SIZE]) -> io::Result<BlobMeta> {
            self.inner.load_blob_meta(blob_id)
        }

        fn read_range(
            &self,
            blob_id: &[u8; EROFS_BLOB_ID_SIZE],
            offset: u64,
            len: u32,
            ctx: ReadContext,
        ) -> io::Result<Vec<u8>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.read_range(blob_id, offset, len, ctx)
        }
    }

    #[test]
    fn local_blob_cache_fetches_from_local_backend() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0xceu8; 4096];
        let data_blob_id = sha256_bytes(&payload);
        let meta = blob_meta(data_blob_id, &payload);
        let full_blob_id = write_full_blob(backend_dir.path(), &payload, &meta, true);

        let backend: Arc<dyn BlobBackend> =
            Arc::new(LocalBackend::new(backend_dir.path().to_path_buf()));
        let cached = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();

        let mut buf = vec![0u8; 1024];
        cached.read_at(512, &mut buf).unwrap();

        assert_eq!(buf, payload[512..1536]);
        assert!(cached.groupmap.is_ready(0).unwrap());
    }

    #[test]
    fn prefetch_lock_dedups_across_handles() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x5au8; 4096];
        let data_blob_id = sha256_bytes(&payload);
        let meta = blob_meta(data_blob_id, &payload);
        let full_blob_id = write_full_blob(backend_dir.path(), &payload, &meta, true);

        let backend: Arc<dyn BlobBackend> =
            Arc::new(LocalBackend::new(backend_dir.path().to_path_buf()));
        // Two handles on the same cache directory model two concurrent
        // processes (flock contention applies across file descriptors even
        // within one process).
        let owner =
            LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend.clone()).unwrap();
        let waiter = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();

        let guard = owner.prefetch_lock().expect("first handle takes the lock");

        // The owner finished all groups: the contender must give up on the
        // lock (returning None) instead of waiting, since the shared groupmap
        // already reports everything ready.
        owner.groupmap.set_ready(0).unwrap();
        assert!(waiter.prefetch_lock().is_none());
        assert!(waiter.group_ready(0));

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
        let meta = blob_meta(data_blob_id, &payload);
        let full_blob_id = write_full_blob(backend_dir.path(), &payload, &meta, true);

        let backend: Arc<dyn BlobBackend> =
            Arc::new(LocalBackend::new(backend_dir.path().to_path_buf()));
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
        let meta = blob_meta(data_blob_id, &payload);
        let full_blob_id = write_full_blob(backend_dir.path(), &payload, &meta, true);

        let backend: Arc<dyn BlobBackend> =
            Arc::new(LocalBackend::new(backend_dir.path().to_path_buf()));
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
        let meta = blob_meta(data_blob_id, &payload);
        let full_blob_id = write_full_blob(backend_dir.path(), &payload, &meta, true);

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
        // every group ready through the shared groupmap and gives up on the
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
    fn redirect_stream_skips_fully_done_segments() {
        let backend_dir = tempdir().unwrap();
        let payload = vec![0x9cu8; 4096];
        let crc32 = crc32c::crc32c(&payload);

        // An ondemand (redirect) blob whose single group redirects to source
        // blob 1 group 0; its data region carries a copy of the source bytes.
        let redirect_meta = BlobMeta::from_parts(
            sha256_bytes(&payload),
            1,
            vec![BlobMetaGroup::new_redirect(0, 1, 0, 4096, crc32, 1, 0).unwrap()],
            Vec::new(),
        )
        .unwrap();
        assert!(redirect_meta.is_redirect_blob());
        let redirect_blob_id = write_full_blob(backend_dir.path(), &payload, &redirect_meta, true);

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
                .redirect_stream_parallel(1, &|_group| skip_all, &|group, decoded| {
                    assert!(group.is_redirect());
                    assert_eq!(decoded, payload);
                    delivered.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                .unwrap();
            (backend.reads() - baseline, delivered.load(Ordering::SeqCst))
        };

        // Nothing done yet: the segment is fetched and the group delivered.
        let (reads, delivered) = run(false);
        assert!(reads > 0);
        assert_eq!(delivered, 1);

        // Every group reported done (e.g. resident in the source caches of a
        // faster sibling instance): no backend fetch, no callback at all.
        let (reads, delivered) = run(true);
        assert_eq!(reads, 0, "fully-done segment must not be fetched");
        assert_eq!(delivered, 0);
    }

    #[test]
    fn local_blob_cache_rejects_bad_blob_meta_header_crc32() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0xbdu8; 4096];
        let data_blob_id = sha256_bytes(&payload);
        let meta = blob_meta(data_blob_id, &payload);
        let full_blob_id = write_full_blob(backend_dir.path(), &payload, &meta, true);
        let blob_meta_path = backend_dir
            .path()
            .join(format!("{}.blob.meta", hex_string(&full_blob_id)));
        let mut raw = fs::read(&blob_meta_path).unwrap();
        raw[8] ^= 0xff;
        fs::write(&blob_meta_path, raw).unwrap();

        let backend: Arc<dyn BlobBackend> =
            Arc::new(LocalBackend::new(backend_dir.path().to_path_buf()));
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
        let meta = blob_meta_with_crc32(
            data_blob_id,
            &payload,
            crc32c::crc32c(&payload).wrapping_add(1),
        );
        let full_blob_id = write_full_blob(backend_dir.path(), &payload, &meta, true);

        let backend: Arc<dyn BlobBackend> =
            Arc::new(LocalBackend::new(backend_dir.path().to_path_buf()));
        let cached = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();

        let mut buf = vec![0u8; 1024];
        let err = cached.read_at(512, &mut buf).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("crc32"));
        assert!(!cached.groupmap.is_ready(0).unwrap());
    }

    #[test]
    fn local_blob_cache_reads_data_region_relative_compressed_offsets() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x3du8; 4096];
        let data_blob_id = sha256_bytes(&payload);
        let meta = blob_meta(data_blob_id, &payload);
        let full_blob_id = write_full_blob(backend_dir.path(), &payload, &meta, false);

        let backend: Arc<dyn BlobBackend> =
            Arc::new(LocalBackend::new(backend_dir.path().to_path_buf()));
        let cached = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();

        let mut buf = vec![0u8; 512];
        cached.read_at(256, &mut buf).unwrap();

        assert_eq!(buf, payload[256..768]);
        assert!(cached.groupmap.is_ready(0).unwrap());
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
            .join(format!("{}.groupmap", hex_string(&full_blob_id)))
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
        let meta = blob_meta(data_blob_id, &payload);
        let full_blob_id = write_full_blob(backend_dir.path(), &payload, &meta, true);

        let backend: Arc<dyn BlobBackend> =
            Arc::new(LocalBackend::new(backend_dir.path().to_path_buf()));
        let cached = LocalBlobCache::open(full_blob_id, 1, cache_dir.path(), backend).unwrap();
        assert!(!cached.is_redirect_blob());

        // Wrong length is rejected and the group stays not-ready.
        let err = cached
            .fill_group_from_redirect(0, &payload[..1024])
            .unwrap_err();
        assert!(err.to_string().contains("length mismatch"));
        assert!(!cached.groupmap.is_ready(0).unwrap());

        // Corrupted bytes fail the CRC cross-check.
        let mut corrupted = payload.clone();
        corrupted[0] ^= 0xff;
        let err = cached.fill_group_from_redirect(0, &corrupted).unwrap_err();
        assert!(super::super::is_group_crc_mismatch(&err));
        assert!(!cached.groupmap.is_ready(0).unwrap());

        // Valid bytes are cached, marked ready, and served without the backend.
        cached.fill_group_from_redirect(0, &payload).unwrap();
        assert!(cached.groupmap.is_ready(0).unwrap());
        let mut buf = vec![0u8; 1024];
        cached.read_at(512, &mut buf).unwrap();
        assert_eq!(buf, payload[512..1536]);

        // Out-of-range index is rejected.
        assert!(cached.fill_group_from_redirect(7, &payload).is_err());
    }
}
