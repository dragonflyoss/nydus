mod block_group_lock;
mod caches;
pub mod local;
pub mod remote;

use std::io;
use std::io::Cursor;
use std::ops::Range;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use nydus_backend::{BlobBackend, ReadContext, ReadKind};
use nydus_format::blob::{BlobMetadata, BlobMetadataBlockGroup, BlobMetadataCompressor};
use nydus_format::utils::SHA256_DIGEST_SIZE;

/// Fail with [`io::ErrorKind::TimedOut`] once a blob-level prefetch deadline
/// has passed. Checked between batches, so the overshoot is bounded by one
/// backend request (itself bounded by the HTTP timeout).
pub(crate) fn check_prefetch_deadline(deadline: Option<Instant>) -> io::Result<()> {
    match deadline {
        Some(deadline) if Instant::now() >= deadline => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "blob prefetch timed out",
        )),
        _ => Ok(()),
    }
}

pub use caches::BlobCaches;
pub use local::LocalBlobCache;
pub use remote::RemoteBlobCache;

pub trait BlobCache: Send + Sync {
    fn read_at(&self, offset: u64, dst: &mut [u8]) -> io::Result<()>;

    /// Stream `len` bytes at `offset` into `writer`. The default bounces
    /// through a per-thread buffer; implementations that can serve reads from
    /// a mapping should override it to skip the intermediate copy.
    fn write_data_to(&self, offset: u64, len: usize, writer: &mut dyn io::Write) -> io::Result<()> {
        write_data_via_scratch(self, offset, len, writer)
    }

    /// Return the raw fd of the cache data file for mmap use.
    ///
    /// The caller must not close the fd; it remains owned by this cache.
    fn cache_fd(&self) -> io::Result<RawFd> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cache_fd is not supported by this blob cache",
        ))
    }

    /// Fetch, decode, validate, cache, and mark ready every block group of this blob.
    /// Used by blob-level prefetch after a filesystem is mounted. Aborts with
    /// [`io::ErrorKind::TimedOut`] when `deadline` passes between batches.
    fn prefetch_all(&self, deadline: Option<Instant>) -> io::Result<()>;

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

    /// Ensure every block group overlapping `[offset, offset + len)` of the dense
    /// uncompressed address space is decoded, validated, and written to the
    /// cache data file. Idempotent and safe to call concurrently.
    fn ensure_range(&self, _offset: u64, _len: u64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ensure_range is not supported by this blob cache",
        ))
    }

    /// Return ready byte intervals overlapping `[offset, offset + len)`.
    /// This must not trigger backend fetch.
    fn ready_ranges(&self, _offset: u64, _len: u64) -> io::Result<Vec<Range<u64>>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ready_ranges is not supported by this blob cache",
        ))
    }

    /// True when this blob is an "ondemand" redirect blob whose block groups carry
    /// data belonging to other source blob devices.
    fn is_redirect(&self) -> bool {
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

    /// True when the block group at `block_group_index` is already decoded and resident in
    /// this blob's cache. Reflects updates from other processes sharing the
    /// same cache directory.
    fn is_block_group_ready(&self, _block_group_index: usize) -> bool {
        false
    }

    /// True when every block group of this blob is already decoded into the local
    /// cache. Implementations must answer in O(1) (a single shared-flag load,
    /// no bitmap scan), so per-event handlers — uffd page faults, fanotify
    /// pre-content events, FUSE reads — can consult it on every request and
    /// skip readiness bookkeeping entirely once the blob is fully warmed.
    /// Sticky: once true it stays true, since ready block groups are never evicted
    /// within a cache generation.
    fn is_all_ready(&self) -> bool {
        false
    }

    /// Stream every block group of a redirect blob: fetch, decode, and validate
    /// each block group, then hand `(block_group, decoded_bytes)` to `cb`. This never
    /// touches the blob's own cache file. The block groups are split into
    /// fixed-size batches and fetched/decoded concurrently with up to
    /// `threads` worker threads. A blob small enough to fit in a single batch
    /// (or `threads <= 1`) is streamed sequentially, since batching would
    /// add registry connections without overlapping any work. Segments whose
    /// block groups are all reported done by `skip` are not fetched at all, so a
    /// process re-running the warmup behind another one's progress does close
    /// to zero backend work. `cb` must be callable concurrently (it fills
    /// distinct source-blob caches, which is safe); block groups that fail decode
    /// or CRC validation are skipped with a warning so a single bad block group
    /// cannot poison the whole redirect prefetch, and the first `cb` or
    /// backend error aborts the stream. Aborts with
    /// [`io::ErrorKind::TimedOut`] when `deadline` passes between batches.
    fn for_each_redirect_block_group(
        &self,
        _threads: usize,
        _deadline: Option<Instant>,
        _skip: &(dyn Fn(&BlobMetadataBlockGroup) -> bool + Sync),
        _cb: &(dyn Fn(&BlobMetadataBlockGroup, &[u8]) -> io::Result<()> + Sync),
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "redirect stream is not supported by this blob cache",
        ))
    }

    /// Fill one block group of this blob's cache with decoded bytes provided by a
    /// redirect blob. Validates length and CRC against this blob's own block group
    /// metadata before writing, and is a no-op when the block group is already
    /// ready.
    fn fill_block_group_from_redirect(
        &self,
        _block_group_index: usize,
        _decoded: &[u8],
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "redirect fill is not supported by this blob cache",
        ))
    }
}

/// Target uncompressed size of one redirect-prefetch batch. The ondemand
/// (redirect) blob's block groups are split into batches of about this size and
/// fetched concurrently by [`BlobCache::for_each_redirect_block_group`]; a blob that
/// fits within a single batch is streamed sequentially instead.
pub const REDIRECT_PREFETCH_BATCH_SIZE: u64 = 16 * 1024 * 1024;

/// Number of earliest (access-ordered) block groups the parallel redirect prefetch
/// fetches one-per-batch instead of bundling into full batches. These are
/// the most latency-critical block groups — the workload faults them first — so a
/// small, single-block group read lands them within roughly one round trip in the
/// first wave of workers, rather than waiting for a whole batch-sized read.
pub const REDIRECT_PREFETCH_RAMP_BLOCK_GROUPS: usize = 16;

/// Block group together consecutive block groups whose accumulated uncompressed size reaches
/// `target_uncompressed`, so each batch can be fetched with a single contiguous
/// read. Each batch always contains at least one block group.
pub fn plan_prefetch_batches(
    block_groups: &[BlobMetadataBlockGroup],
    target_uncompressed: u64,
) -> Vec<Range<usize>> {
    let mut batches = Vec::new();
    let mut start = 0usize;
    while start < block_groups.len() {
        let mut end = start + 1;
        let mut accumulated = block_groups[start].uncompressed_size();
        while end < block_groups.len() && accumulated < target_uncompressed {
            accumulated = accumulated.saturating_add(block_groups[end].uncompressed_size());
            end += 1;
        }
        batches.push(start..end);
        start = end;
    }
    batches
}

/// Plan the batches for a parallel redirect prefetch: the first `ramp_block_groups`
/// access-ordered block groups are emitted one per batch (small, fast reads that
/// land the earliest block groups within a single round trip), and the remaining
/// block groups are bundled into `target_uncompressed`-sized batches for throughput.
pub fn plan_redirect_batches(
    block_groups: &[BlobMetadataBlockGroup],
    target_uncompressed: u64,
    ramp_block_groups: usize,
) -> Vec<Range<usize>> {
    let ramp = ramp_block_groups.min(block_groups.len());
    let mut batches: Vec<Range<usize>> = (0..ramp).map(|i| i..i + 1).collect();
    if ramp < block_groups.len() {
        for batch in plan_prefetch_batches(&block_groups[ramp..], target_uncompressed) {
            batches.push((ramp + batch.start)..(ramp + batch.end));
        }
    }
    batches
}

/// Decode and validate a single block group from an in-memory window of compressed
/// bytes that starts at blob offset `window_base_offset`, writing the validated
/// uncompressed bytes into `decoded`. CRC failures are attributed to `backend`,
/// which served the window.
pub fn decode_block_group_from_window(
    blob_metadata: &BlobMetadata,
    backend: &Arc<dyn BlobBackend>,
    block_group: &BlobMetadataBlockGroup,
    window_base_offset: u64,
    window_bytes: &[u8],
    decoded: &mut Vec<u8>,
) -> io::Result<()> {
    let relative_start = block_group
        .compressed_offset()
        .checked_sub(window_base_offset)
        .and_then(|start| usize::try_from(start).ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "blob meta block group offset outside prefetch window",
            )
        })?;
    let relative_end = relative_start + block_group.compressed_size() as usize;
    let encoded = window_bytes
        .get(relative_start..relative_end)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "blob meta block group range outside prefetch window",
            )
        })?;

    let decoded_len = usize::try_from(block_group.uncompressed_size()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "blob meta block group uncompressed size exceeds usize",
        )
    })?;

    decoded.clear();
    if is_stored_plain_block_group(blob_metadata, block_group) {
        decoded.extend_from_slice(encoded);
    } else {
        decode_block_group(blob_metadata, encoded, decoded_len, decoded)?;
    }

    validate_block_group_with_metrics(backend, block_group, decoded)
}

#[derive(Default)]
pub struct BlockGroupBuffers {
    encoded: Vec<u8>,
    decoded: Vec<u8>,
}

pub fn fetch_decode_validate_block_group_into<'a>(
    blob_id: &[u8; SHA256_DIGEST_SIZE],
    blob_metadata: &BlobMetadata,
    backend: &Arc<dyn BlobBackend>,
    block_group: &BlobMetadataBlockGroup,
    buffers: &'a mut BlockGroupBuffers,
    kind: ReadKind,
) -> io::Result<&'a [u8]> {
    let ctx = ReadContext::block_group(
        kind,
        block_group.uncompressed_offset(),
        block_group.uncompressed_size(),
    );
    let decoded_len = usize::try_from(block_group.uncompressed_size()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "blob meta block group uncompressed size exceeds usize",
        )
    })?;
    if is_stored_plain_block_group(blob_metadata, block_group) {
        buffers.decoded.resize(decoded_len, 0);
        backend.read_range_into(
            blob_id,
            block_group.compressed_offset(),
            &mut buffers.decoded,
            ctx,
        )?;
        validate_block_group_with_metrics(backend, block_group, &buffers.decoded)?;
        return Ok(&buffers.decoded);
    }

    buffers
        .encoded
        .resize(block_group.compressed_size() as usize, 0);
    backend.read_range_into(
        blob_id,
        block_group.compressed_offset(),
        &mut buffers.encoded,
        ctx,
    )?;

    buffers.decoded.clear();
    decode_block_group(
        blob_metadata,
        &buffers.encoded,
        decoded_len,
        &mut buffers.decoded,
    )?;

    validate_block_group_with_metrics(backend, block_group, &buffers.decoded)?;
    Ok(&buffers.decoded)
}

/// Read `[offset, offset + len)` through `cache.read_at` into a per-thread
/// scratch buffer and copy it into `writer`: the fallback for caches that
/// cannot serve reads from a mapping.
fn write_data_via_scratch<C: BlobCache + ?Sized>(
    cache: &C,
    offset: u64,
    len: usize,
    writer: &mut dyn io::Write,
) -> io::Result<()> {
    thread_local! {
        static SCRATCH: std::cell::RefCell<Vec<u8>> =
            const { std::cell::RefCell::new(Vec::new()) };
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

/// Decompress one encoded block group into `decoded` (cleared by the caller)
/// according to the compressor the blob meta header declares.
fn decode_block_group(
    blob_metadata: &BlobMetadata,
    encoded: &[u8],
    decoded_len: usize,
    decoded: &mut Vec<u8>,
) -> io::Result<()> {
    match blob_metadata.compressor() {
        BlobMetadataCompressor::Zstd => {
            decoded.reserve(decoded_len);
            zstd::stream::copy_decode(&mut Cursor::new(encoded), &mut *decoded)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        }
        BlobMetadataCompressor::Lz4Block => {
            decoded.resize(decoded_len, 0);
            let written = lz4_flex::block::decompress_into(encoded, decoded)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            if written != decoded_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "lz4 block group decompressed to an unexpected size",
                ));
            }
        }
        BlobMetadataCompressor::None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "blob meta declares no compressor but the block group is stored compressed",
            ));
        }
    }
    Ok(())
}

/// Validate a decoded block group and, on CRC failure, attribute a CRC error metric to
/// the backend that served the bytes. A read diverted from the backend's
/// static target (e.g. a Dragonfly fallback to the origin) is attributed to
/// the side that actually served it, via [`nydus_backend::last_read_served_by`].
pub fn validate_block_group_with_metrics(
    backend: &Arc<dyn BlobBackend>,
    block_group: &BlobMetadataBlockGroup,
    decoded: &[u8],
) -> io::Result<()> {
    if let Err(err) = validate_decoded_block_group(block_group, decoded) {
        if is_block_group_crc_mismatch(&err) {
            let target =
                nydus_backend::last_read_served_by().unwrap_or_else(|| backend.backend_target());
            nydus_telemetry::metrics::record_backend_crc_error(target);
        }
        return Err(err);
    }
    Ok(())
}

fn is_stored_plain_block_group(
    blob_metadata: &BlobMetadata,
    block_group: &BlobMetadataBlockGroup,
) -> bool {
    blob_metadata.compressor() == BlobMetadataCompressor::None
        || u64::from(block_group.compressed_size()) == block_group.uncompressed_size()
}

pub fn validate_decoded_block_group(
    block_group: &BlobMetadataBlockGroup,
    decoded: &[u8],
) -> io::Result<()> {
    let expected = block_group.uncompressed_size();
    if decoded.len() as u64 != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "decoded blob meta block group length mismatch: expected {}, got {}",
                expected,
                decoded.len()
            ),
        ));
    }

    if skip_verify_checksums() {
        return Ok(());
    }
    let crc32 = crc32c::crc32c(decoded);
    if crc32 != block_group.crc32() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            BlockGroupCrcMismatch,
        ));
    }

    Ok(())
}

/// Process-wide switch skipping block group checksum verification (the
/// default), set at service startup from `storage.skip_verify_checksums`. A
/// process serves one mount, so a per-cache flag would only thread the same
/// value through every call site.
static SKIP_VERIFY_CHECKSUMS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

/// Skip (or re-enable) block group checksum verification for this process.
pub fn set_skip_verify_checksums(skip: bool) {
    SKIP_VERIFY_CHECKSUMS.store(skip, std::sync::atomic::Ordering::Relaxed);
}

fn skip_verify_checksums() -> bool {
    SKIP_VERIFY_CHECKSUMS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Marker error wrapped in an [`io::Error`] when a decoded block group fails CRC
/// validation, so callers with backend context can attribute the failure to the
/// origin or a proxy via [`is_block_group_crc_mismatch`].
#[derive(Debug)]
struct BlockGroupCrcMismatch;

impl std::fmt::Display for BlockGroupCrcMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "blob meta block group crc32 mismatch")
    }
}

impl std::error::Error for BlockGroupCrcMismatch {}

/// Whether an error denotes a block group CRC validation failure.
pub fn is_block_group_crc_mismatch(err: &io::Error) -> bool {
    err.get_ref()
        .is_some_and(|inner| inner.is::<BlockGroupCrcMismatch>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_format::blob::DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_SIZE;
    use nydus_format::erofs::EROFS_BLOCK_SIZE;

    fn block_group(
        uncompressed_block_offset: u64,
        uncompressed_block_count: u32,
    ) -> BlobMetadataBlockGroup {
        BlobMetadataBlockGroup::new(
            uncompressed_block_offset,
            uncompressed_block_count,
            uncompressed_block_offset * EROFS_BLOCK_SIZE as u64,
            uncompressed_block_count * EROFS_BLOCK_SIZE,
            0,
        )
        .unwrap()
    }

    #[test]
    fn plan_prefetch_batches_keeps_one_block_group_per_window_at_default_target() {
        let blocks = DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_SIZE / EROFS_BLOCK_SIZE;
        let block_groups = vec![
            block_group(0, blocks),
            block_group(blocks as u64, blocks),
            block_group(2 * blocks as u64, blocks),
        ];
        let batches = plan_prefetch_batches(
            &block_groups,
            DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_SIZE as u64,
        );
        assert_eq!(batches, vec![0..1, 1..2, 2..3]);
    }

    #[test]
    fn plan_prefetch_batches_merges_small_block_groups_and_keeps_tail() {
        let block_groups = vec![block_group(0, 1), block_group(1, 1), block_group(2, 1)];
        // Target equal to two blocks: first two block groups merge, last is its own batch.
        let target = 2 * EROFS_BLOCK_SIZE as u64;
        let batches = plan_prefetch_batches(&block_groups, target);
        assert_eq!(batches, vec![0..2, 2..3]);
    }

    #[test]
    fn plan_prefetch_batches_isolates_block_group_larger_than_target() {
        let block_groups = vec![block_group(0, 4), block_group(4, 1)];
        let batches = plan_prefetch_batches(&block_groups, EROFS_BLOCK_SIZE as u64);
        assert_eq!(batches, vec![0..1, 1..2]);
    }

    /// A backend whose reads are never exercised; only its static target matters.
    struct StaticTargetBackend;

    impl BlobBackend for StaticTargetBackend {
        fn backend_target(&self) -> nydus_telemetry::metrics::BackendTarget {
            nydus_telemetry::metrics::BackendTarget::Proxy
        }

        fn blob_metadata(
            &self,
            _blob_id: &[u8; SHA256_DIGEST_SIZE],
        ) -> io::Result<nydus_format::blob::BlobMetadata> {
            Err(io::Error::other("unused"))
        }

        fn read_range_into(
            &self,
            _blob_id: &[u8; SHA256_DIGEST_SIZE],
            _offset: u64,
            _dst: &mut [u8],
            _context: ReadContext,
        ) -> io::Result<()> {
            Err(io::Error::other("unused"))
        }
    }

    #[test]
    fn crc_failure_is_attributed_to_the_static_target_without_an_override() {
        set_skip_verify_checksums(false);
        use nydus_telemetry::metrics::BackendTarget;

        let backend: Arc<dyn BlobBackend> = Arc::new(StaticTargetBackend);
        // A zeroed block has crc32c != 0, so a group declaring crc 0 mismatches.
        let block_group = block_group(0, 1);
        let decoded = vec![0u8; EROFS_BLOCK_SIZE as usize];
        assert!(nydus_backend::last_read_served_by().is_none());

        let proxy_before = nydus_telemetry::metrics::backend_crc_error_total(BackendTarget::Proxy);
        let err = validate_block_group_with_metrics(&backend, &block_group, &decoded)
            .expect_err("crc must mismatch");
        assert!(is_block_group_crc_mismatch(&err));
        assert_eq!(
            nydus_telemetry::metrics::backend_crc_error_total(BackendTarget::Proxy),
            proxy_before + 1
        );
    }
}
