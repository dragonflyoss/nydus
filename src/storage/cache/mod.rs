pub mod local;

use std::io;
use std::io::Cursor;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;

use crate::metadata::{BlobMeta, BlobMetaCompressor, BlobMetaGroup, EROFS_BLOB_ID_SIZE};
use crate::storage::backend::{BlobBackend, ReadContext, RequestSource};

pub use local::LocalBlobCache;
pub trait BlobCache: Send + Sync {
    fn read_at(&self, offset: u64, dst: &mut [u8]) -> io::Result<()>;

    /// Fetch, decode, validate, cache, and mark ready every group of this blob.
    /// Used by blob-level prefetch after a filesystem is mounted.
    fn prefetch_all(&self) -> io::Result<()>;

    /// Create (or open) this blob's cache data file sized to the dense
    /// uncompressed address space and return its path. The file mirrors the
    /// decoded block address space, so it can directly back a virtio-pmem
    /// device whose guest reads land at `block * 4096`.
    fn prepare(&self) -> io::Result<PathBuf> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "prepare is not supported by this blob cache",
        ))
    }

    /// Ensure every group overlapping `[offset, offset + len)` of the dense
    /// uncompressed address space is decoded, validated, and written to the
    /// cache data file. Idempotent and safe to call concurrently.
    fn ensure_range(&self, _offset: u64, _len: u64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ensure_range is not supported by this blob cache",
        ))
    }

    /// True when this blob is an "ondemand" redirect blob whose groups carry
    /// data belonging to other source blob devices.
    fn is_redirect_blob(&self) -> bool {
        false
    }

    /// Acquire the cross-process prefetch lock for this blob, blocking until
    /// the lock is held. Returns the lock guard (released on drop / process
    /// exit), or `None` when locking is unavailable or unnecessary — in both
    /// cases the caller proceeds with the prefetch, merely without the
    /// cross-process dedup guarantee. Only the blob-level prefetch path takes
    /// this lock; on-demand reads never wait on it.
    fn prefetch_lock(&self) -> Option<std::fs::File> {
        None
    }

    /// True when the group at `group_index` is already decoded and resident in
    /// this blob's cache. Reflects updates from other processes sharing the
    /// same cache directory.
    fn group_ready(&self, _group_index: usize) -> bool {
        false
    }

    /// Stream every group of a redirect blob: fetch, decode, and validate each
    /// group, then hand `(group, decoded_bytes)` to `cb`. This never touches
    /// the blob's own cache file. Groups that fail decode or CRC validation
    /// are skipped with a warning so a single bad group cannot poison the
    /// whole redirect prefetch; `cb` errors abort the stream.
    fn redirect_stream(
        &self,
        _cb: &mut dyn FnMut(&BlobMetaGroup, &[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "redirect stream is not supported by this blob cache",
        ))
    }

    /// Like [`redirect_stream`], but split the redirect blob's groups into
    /// fixed-size segments and fetch/decode them concurrently with up to
    /// `threads` worker threads. A blob small enough to fit in a single segment
    /// (or `threads <= 1`) is streamed sequentially, since segmentation would
    /// add registry connections without overlapping any work. Segments whose
    /// groups are all reported done by `skip` are not fetched at all, so a
    /// process re-running the warmup behind another one's progress does close
    /// to zero backend work. `cb` must be callable concurrently (it fills
    /// distinct source-blob caches, which is safe); per-group decode/CRC
    /// failures are skipped, and the first `cb` or backend error aborts the
    /// stream.
    ///
    /// [`redirect_stream`]: Self::redirect_stream
    fn redirect_stream_parallel(
        &self,
        _threads: usize,
        _skip: &(dyn Fn(&BlobMetaGroup) -> bool + Sync),
        _cb: &(dyn Fn(&BlobMetaGroup, &[u8]) -> io::Result<()> + Sync),
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "redirect stream is not supported by this blob cache",
        ))
    }

    /// Fill one group of this blob's cache with decoded bytes provided by a
    /// redirect blob. Validates length and CRC against this blob's own group
    /// metadata before writing, and is a no-op when the group is already
    /// ready.
    fn fill_group_from_redirect(&self, _group_index: usize, _decoded: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "redirect fill is not supported by this blob cache",
        ))
    }
}

/// Target uncompressed size of one redirect-prefetch segment. The ondemand
/// (redirect) blob's groups are split into segments of about this size and
/// fetched concurrently by [`BlobCache::redirect_stream_parallel`]; a blob that
/// fits within a single segment is streamed sequentially instead.
pub(crate) const REDIRECT_PREFETCH_SEGMENT_SIZE: u64 = 16 * 1024 * 1024;

/// Number of earliest (access-ordered) groups the parallel redirect prefetch
/// fetches one-per-segment instead of bundling into full segments. These are
/// the most latency-critical groups — the workload faults them first — so a
/// small, single-group read lands them within roughly one round trip in the
/// first wave of workers, rather than waiting for a whole segment-sized read.
pub(crate) const REDIRECT_PREFETCH_RAMP_GROUPS: usize = 16;

/// Group together consecutive groups whose accumulated uncompressed size reaches
/// `target_uncompressed`, so each batch can be fetched with a single contiguous
/// read. Each batch always contains at least one group.
pub(crate) fn plan_prefetch_batches(
    groups: &[BlobMetaGroup],
    target_uncompressed: u64,
) -> Vec<Range<usize>> {
    let mut batches = Vec::new();
    let mut start = 0usize;
    while start < groups.len() {
        let mut end = start + 1;
        let mut accumulated = groups[start].uncompressed_byte_size();
        while end < groups.len() && accumulated < target_uncompressed {
            accumulated = accumulated.saturating_add(groups[end].uncompressed_byte_size());
            end += 1;
        }
        batches.push(start..end);
        start = end;
    }
    batches
}

/// Plan the segments for a parallel redirect prefetch: the first `ramp_groups`
/// access-ordered groups are emitted one per segment (small, fast reads that
/// land the earliest groups within a single round trip), and the remaining
/// groups are bundled into `target_uncompressed`-sized segments for throughput.
pub(crate) fn plan_redirect_segments(
    groups: &[BlobMetaGroup],
    target_uncompressed: u64,
    ramp_groups: usize,
) -> Vec<Range<usize>> {
    let ramp = ramp_groups.min(groups.len());
    let mut segments: Vec<Range<usize>> = (0..ramp).map(|i| i..i + 1).collect();
    if ramp < groups.len() {
        for batch in plan_prefetch_batches(&groups[ramp..], target_uncompressed) {
            segments.push((ramp + batch.start)..(ramp + batch.end));
        }
    }
    segments
}

/// Decode and validate a single group from an in-memory window of compressed
/// bytes that starts at blob offset `window_base_offset`, writing the validated
/// uncompressed bytes into `decoded`.
pub(crate) fn decode_group_from_window(
    blob_meta: &BlobMeta,
    group: &BlobMetaGroup,
    window_base_offset: u64,
    window_bytes: &[u8],
    decoded: &mut Vec<u8>,
) -> io::Result<()> {
    let relative_start = group
        .compressed_byte_offset()
        .checked_sub(window_base_offset)
        .and_then(|start| usize::try_from(start).ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "blob meta group offset outside prefetch window",
            )
        })?;
    let relative_end = relative_start + group.compressed_size() as usize;
    let encoded = window_bytes
        .get(relative_start..relative_end)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "blob meta group range outside prefetch window",
            )
        })?;

    let decoded_len = usize::try_from(group.uncompressed_byte_size()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "blob meta group uncompressed size exceeds usize",
        )
    })?;

    decoded.clear();
    if is_stored_plain_group(blob_meta, group) {
        decoded.extend_from_slice(encoded);
    } else {
        decoded.reserve(decoded_len);
        zstd::stream::copy_decode(&mut Cursor::new(encoded), &mut *decoded)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    }

    validate_decoded_group(group, decoded)
}

#[derive(Default)]
pub(crate) struct BlobCacheBuffers {
    encoded: Vec<u8>,
    decoded: Vec<u8>,
}

pub(crate) fn fetch_decode_validate_group_into<'a>(
    blob_id: &[u8; EROFS_BLOB_ID_SIZE],
    blob_meta: &BlobMeta,
    backend: &Arc<dyn BlobBackend>,
    group: &BlobMetaGroup,
    buffers: &'a mut BlobCacheBuffers,
    source: RequestSource,
) -> io::Result<&'a [u8]> {
    let ctx = ReadContext::group(
        source,
        group.uncompressed_byte_offset(),
        group.uncompressed_byte_size(),
    );
    let decoded_len = usize::try_from(group.uncompressed_byte_size()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "blob meta group uncompressed size exceeds usize",
        )
    })?;
    if is_stored_plain_group(blob_meta, group) {
        buffers.decoded.resize(decoded_len, 0);
        backend.read_range_into(
            blob_id,
            group.compressed_byte_offset(),
            &mut buffers.decoded,
            ctx,
        )?;
        validate_group_with_metrics(backend, group, &buffers.decoded)?;
        return Ok(&buffers.decoded);
    }

    buffers.encoded.resize(group.compressed_size() as usize, 0);
    backend.read_range_into(
        blob_id,
        group.compressed_byte_offset(),
        &mut buffers.encoded,
        ctx,
    )?;

    buffers.decoded.clear();
    buffers.decoded.reserve(decoded_len);
    zstd::stream::copy_decode(&mut Cursor::new(&buffers.encoded), &mut buffers.decoded)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    validate_group_with_metrics(backend, group, &buffers.decoded)?;
    Ok(&buffers.decoded)
}

/// Validate a decoded group and, on CRC failure, attribute a CRC error metric to
/// the backend that served the bytes.
pub(crate) fn validate_group_with_metrics(
    backend: &Arc<dyn BlobBackend>,
    group: &BlobMetaGroup,
    decoded: &[u8],
) -> io::Result<()> {
    if let Err(err) = validate_decoded_group(group, decoded) {
        if is_group_crc_mismatch(&err) {
            crate::metrics::record_backend_crc_error(backend.backend_target());
        }
        return Err(err);
    }
    Ok(())
}

fn is_stored_plain_group(blob_meta: &BlobMeta, group: &BlobMetaGroup) -> bool {
    blob_meta.compressor() == BlobMetaCompressor::None
        || u64::from(group.compressed_size()) == group.uncompressed_byte_size()
}

pub(crate) fn validate_decoded_group(group: &BlobMetaGroup, decoded: &[u8]) -> io::Result<()> {
    let expected = group.uncompressed_byte_size();
    if decoded.len() as u64 != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "decoded blob meta group length mismatch: expected {}, got {}",
                expected,
                decoded.len()
            ),
        ));
    }

    let crc32 = crc32c::crc32c(decoded);
    if crc32 != group.crc32() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, GroupCrcMismatch));
    }

    Ok(())
}

/// Marker error wrapped in an [`io::Error`] when a decoded group fails CRC
/// validation, so callers with backend context can attribute the failure to the
/// origin or a proxy via [`is_group_crc_mismatch`].
#[derive(Debug)]
struct GroupCrcMismatch;

impl std::fmt::Display for GroupCrcMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "blob meta group crc32 mismatch")
    }
}

impl std::error::Error for GroupCrcMismatch {}

/// Whether an error denotes a group CRC validation failure.
pub(crate) fn is_group_crc_mismatch(err: &io::Error) -> bool {
    err.get_ref()
        .is_some_and(|inner| inner.is::<GroupCrcMismatch>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{BLOB_META_DEFAULT_CHUNK_SIZE, EROFS_BLOCK_SIZE};

    fn group(uncompressed_block_offset: u64, uncompressed_block_count: u32) -> BlobMetaGroup {
        BlobMetaGroup::new(
            uncompressed_block_offset,
            uncompressed_block_count,
            uncompressed_block_offset * EROFS_BLOCK_SIZE as u64,
            uncompressed_block_count * EROFS_BLOCK_SIZE,
            0,
        )
        .unwrap()
    }

    #[test]
    fn plan_prefetch_batches_keeps_one_group_per_window_at_default_target() {
        let blocks = BLOB_META_DEFAULT_CHUNK_SIZE / EROFS_BLOCK_SIZE;
        let groups = vec![
            group(0, blocks),
            group(blocks as u64, blocks),
            group(2 * blocks as u64, blocks),
        ];
        let batches = plan_prefetch_batches(&groups, BLOB_META_DEFAULT_CHUNK_SIZE as u64);
        assert_eq!(batches, vec![0..1, 1..2, 2..3]);
    }

    #[test]
    fn plan_prefetch_batches_merges_small_groups_and_keeps_tail() {
        let groups = vec![group(0, 1), group(1, 1), group(2, 1)];
        // Target equal to two blocks: first two groups merge, last is its own batch.
        let target = 2 * EROFS_BLOCK_SIZE as u64;
        let batches = plan_prefetch_batches(&groups, target);
        assert_eq!(batches, vec![0..2, 2..3]);
    }

    #[test]
    fn plan_prefetch_batches_isolates_group_larger_than_target() {
        let groups = vec![group(0, 4), group(4, 1)];
        let batches = plan_prefetch_batches(&groups, EROFS_BLOCK_SIZE as u64);
        assert_eq!(batches, vec![0..1, 1..2]);
    }
}
