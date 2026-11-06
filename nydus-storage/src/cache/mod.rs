mod caches;
mod chunk_group_lock;
pub mod local;
pub mod raw;
pub mod remote;

use std::io;
use std::ops::Range;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::time::Instant;

use nydus_backend::{Backend, ReadKind};
use nydus_config::{Config, StorageConfig};
use nydus_format::blob::{BlobMetadata, BlobMetadataChunkGroupExtent, BlobMetadataCompressor};
use nydus_format::utils::SHA256_DIGEST_SIZE;
use nydus_telemetry::metrics::WriteFailureReason;

/// Default on-demand fetch size: the compressed bytes one backend read
/// covers around a missed chunk group (see [`CacheOptions::fetch_size`]).
/// 2 MiB.
pub const DEFAULT_FETCH_SIZE: u64 = 2 * 1024 * 1024;

/// Default prefetch batch size: the compressed bytes one prefetch backend
/// read covers (see [`CacheOptions::prefetch_batch_size`]). 2 MiB.
pub const DEFAULT_PREFETCH_BATCH_SIZE: u64 = 2 * 1024 * 1024;

/// The options of the blob caches of one image, the `storage` section of
/// its configuration. Every image carries its own, so two images in one
/// process never share a setting.
#[derive(Debug, Clone, Copy)]
pub struct CacheOptions {
    /// Skip the crc32c check of decoded chunk groups before they are served
    /// or written, `false` by default.
    pub skip_verify_checksums: bool,

    /// Compressed bytes one on-demand backend read covers: the
    /// fetch-size-aligned cell of the blob's data region holding the missed
    /// chunk group, extended to whole groups and trimmed at groups already
    /// cached or in flight. Zero fetches the missed group alone.
    pub fetch_size: u64,

    /// Compressed bytes one prefetch backend read covers, whole groups of a
    /// blob or an ondemand blob back to back; zero reads group by group.
    pub prefetch_batch_size: u64,
}

/// Implements the default options: checksums verified, 2 MiB on-demand
/// fetches and prefetch batches.
impl Default for CacheOptions {
    fn default() -> Self {
        Self {
            skip_verify_checksums: false,
            fetch_size: DEFAULT_FETCH_SIZE,
            prefetch_batch_size: DEFAULT_PREFETCH_BATCH_SIZE,
        }
    }
}

/// Implements the conversion from the `storage` section of a configuration,
/// the prefetch batch size left at its default.
impl From<&StorageConfig> for CacheOptions {
    fn from(storage: &StorageConfig) -> Self {
        Self {
            skip_verify_checksums: storage.skip_verify_checksums,
            fetch_size: storage.fetch_size,
            ..Self::default()
        }
    }
}

/// Implements the conversion from the `storage` and `prefetch` sections of
/// a configuration.
impl From<&Config> for CacheOptions {
    fn from(config: &Config) -> Self {
        Self {
            prefetch_batch_size: config.prefetch.batch_size,
            ..Self::from(&config.storage)
        }
    }
}

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
pub use raw::RawDeviceBlobCache;
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

    /// Fetch, decode, validate, cache, and mark ready every chunk group of
    /// this blob. Used by blob-level prefetch after a filesystem is mounted.
    /// Up to `workers` batches are fetched concurrently. Aborts with
    /// [`io::ErrorKind::TimedOut`] when `deadline` passes between batches.
    fn prefetch_all(&self, workers: usize, deadline: Option<Instant>) -> io::Result<()>;

    /// Create (or open) this blob's cache data file sized to the padded
    /// uncompressed address space and return its path. The file mirrors the
    /// decoded block address space, so it can directly back a virtio-pmem
    /// device whose guest reads land at `block * 4096`.
    fn prepare(&self) -> io::Result<PathBuf> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "prepare is not supported by this blob cache",
        ))
    }

    /// Ensure every chunk group overlapping `[offset, offset + len)` of the
    /// uncompressed address space is decoded, validated, and written to the
    /// cache data file. Idempotent and safe to call concurrently.
    fn ensure_range(&self, _offset: u64, _len: u64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ensure_range is not supported by this blob cache",
        ))
    }

    /// Ensure the range as in [`Self::ensure_range`], returning its complete
    /// logical chunk groups (including padding) for chunked caches, or the exact
    /// request otherwise. Only requested chunk groups are recorded and returned.
    /// Boundaries need not align to host pages. Empty requests do no I/O;
    /// overflow and fetch failures return errors.
    fn ensure_chunk_group_range(&self, offset: u64, len: u64) -> io::Result<Range<u64>> {
        let end = offset.checked_add(len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob read range overflow")
        })?;
        if len != 0 {
            self.ensure_range(offset, len)?;
        }
        Ok(offset..end)
    }

    /// Return ready byte intervals overlapping `[offset, offset + len)`.
    /// This must not trigger backend fetch.
    fn ready_ranges(&self, _offset: u64, _len: u64) -> io::Result<Vec<Range<u64>>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ready_ranges is not supported by this blob cache",
        ))
    }

    /// True when this blob is an `optimize` output: an ondemand blob whose
    /// chunk groups copy other blobs' groups, which `prefetch.scope:
    /// ondemand` streams into those source blobs' caches first.
    fn is_ondemand(&self) -> bool {
        false
    }

    /// Whether chunk group `chunk_group_index` is already decoded into the
    /// local cache, per the shared chunk group map; `false` for caches
    /// without one. Never fetches.
    fn is_chunk_group_ready(&self, _chunk_group_index: usize) -> bool {
        false
    }

    /// Stream an ondemand blob's chunk groups: fetch them in batches of the
    /// fetch size through up to `workers` threads, decode and validate each
    /// against this blob's metadata, and hand the payload to `cb` in blob
    /// order. Groups `skip` accepts are not fetched (a batch made entirely
    /// of them costs no backend read); a group that fails to decode is
    /// logged and skipped, while an error from `cb` aborts the stream.
    /// Returns the bytes fetched from the backend and the groups that failed
    /// to decode.
    fn for_each_ondemand_blob_chunk_group(
        &self,
        _workers: usize,
        _deadline: Option<Instant>,
        _skip: &(dyn Fn(&BlobMetadataChunkGroupExtent) -> bool + Sync),
        _cb: &(dyn Fn(&BlobMetadataChunkGroupExtent, &[u8]) -> io::Result<()> + Sync),
    ) -> io::Result<(u64, u64)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "for_each_ondemand_blob_chunk_group is not supported by this blob cache",
        ))
    }

    /// Write the decoded payload of this blob's chunk group
    /// `chunk_group_index`, obtained from an ondemand blob, into the local
    /// cache and mark the group ready. The payload is validated against this
    /// blob's own metadata first, so a stale or corrupt redirect copy never
    /// reaches the cache. A no-op when the group is already ready.
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

    /// Acquire the cross-process prefetch lock for this blob, blocking until
    /// the lock is held. Returns the lock guard (released on drop / process
    /// exit), or `None` when locking is unavailable or unnecessary — in both
    /// cases the caller proceeds with the prefetch, merely without the
    /// cross-process dedup guarantee. Only the blob-level prefetch path takes
    /// this lock; on-demand reads never wait on it.
    fn prefetch_lock(&self) -> Option<std::fs::File> {
        None
    }

    /// True when every chunk group of this blob is already decoded into the
    /// local cache. Implementations must answer in O(1) (a single shared-flag
    /// load, no bitmap scan), so per-event handlers — uffd page faults,
    /// fanotify pre-content events, FUSE reads — can consult it on every
    /// request and skip readiness bookkeeping entirely once the blob is fully
    /// warmed. Sticky: once true it stays true, since ready chunk groups are
    /// never evicted within a cache generation.
    fn is_all_ready(&self) -> bool {
        false
    }

    /// The uncompressed bytes of the blob the cache file holds, by the shared
    /// chunk group map, and the blob's total; `None` for a cache without a
    /// file of its own, a raw device, a diskless cache or an ondemand blob,
    /// whose chunk groups land in their source blobs.
    fn cached_bytes(&self) -> Option<(u64, u64)> {
        None
    }
}

/// Batch consecutive chunk groups of `blob_metadata` so each batch's
/// compressed bytes reach `target_compressed` (one contiguous backend read
/// each). Every batch holds at least one group; a zero target yields one
/// group per batch. The first `ramp` groups are one batch each, so a worker
/// pool lands the blob's head — the first-accessed data of an ondemand blob —
/// within one round trip before the full-size batches stream the rest.
pub fn plan_prefetch_batches(
    blob_metadata: &BlobMetadata,
    target_compressed: u64,
    ramp: usize,
) -> Vec<Range<usize>> {
    let count = blob_metadata.chunk_group_count();
    let mut batches = Vec::new();
    let mut start = 0usize;
    while start < count && start < ramp {
        batches.push(start..start + 1);
        start += 1;
    }
    while start < count {
        let base = blob_metadata
            .chunk_group(start)
            .expect("group index within the table")
            .compressed_offset();
        let mut end = start + 1;
        while end < count {
            let group = blob_metadata
                .chunk_group(end)
                .expect("group index within the table");
            if group.compressed_range().end - base > target_compressed {
                break;
            }
            end += 1;
        }
        batches.push(start..end);
        start = end;
    }
    batches
}

/// Decode and validate chunk group `group` from an in-memory window of
/// compressed bytes that starts at blob offset `window_base_offset`.
/// Stored-plain groups borrow the window; compressed groups decode into
/// `decoded` as scratch storage. The returned slice contains validated
/// payload bytes, the crc32c check skipped when `skip_verify_checksums`.
pub fn decode_chunk_group_from_window<'a>(
    blob_metadata: &BlobMetadata,
    group: &BlobMetadataChunkGroupExtent,
    window_base_offset: u64,
    window_bytes: &'a [u8],
    decoded: &'a mut Vec<u8>,
    skip_verify_checksums: bool,
) -> io::Result<&'a [u8]> {
    let relative_start = group
        .compressed_offset()
        .checked_sub(window_base_offset)
        .and_then(|start| usize::try_from(start).ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "blob meta chunk group offset outside the fetched window",
            )
        })?;
    let relative_end = relative_start + group.compressed_size() as usize;
    let encoded = window_bytes
        .get(relative_start..relative_end)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "blob meta chunk group range outside the fetched window",
            )
        })?;
    let payload_len = usize::try_from(u64::from(group.uncompressed_size())).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "blob meta chunk group payload size exceeds usize",
        )
    })?;

    let payload = if group.is_uncompressed(blob_metadata) {
        encoded
    } else {
        decoded.clear();
        decoded.resize(payload_len, 0);
        decode_chunk_group_into(blob_metadata.compressor(), encoded, decoded)?;
        decoded.as_slice()
    };

    validate_decoded_chunk_group(group, payload, skip_verify_checksums)?;
    Ok(payload)
}

/// Job-owned buffers of one chunk group at a time: the encoded bytes of a
/// group that arrived split across network pieces, and its decoded payload.
/// Large allocations are unmapped when the job ends.
#[derive(Default)]
pub struct ChunkGroupBuffers {
    encoded: ChunkGroupBuffer,
    decoded: ChunkGroupBuffer,
}

impl ChunkGroupBuffers {
    /// Both buffers, borrowed together so a caller can stream into one and
    /// decode into the other.
    pub(crate) fn split(&mut self) -> (&mut ChunkGroupBuffer, &mut ChunkGroupBuffer) {
        (&mut self.encoded, &mut self.decoded)
    }
}

/// Large transient buffers bypass heap arenas. They are never advised onto
/// huge pages: a buffer touches only the group in hand, and a huge page would
/// make the whole 2 MiB resident for it.
#[derive(Default)]
pub(crate) struct ChunkGroupBuffer {
    heap: Vec<u8>,
    mapping: Option<memmap2::MmapMut>,
}

impl ChunkGroupBuffer {
    fn resize(&mut self, len: usize) -> io::Result<&mut [u8]> {
        if len >= 1024 * 1024 {
            if self
                .mapping
                .as_ref()
                .is_none_or(|mapping| mapping.len() < len)
            {
                self.mapping = Some(memmap2::MmapMut::map_anon(len)?);
            }
            self.heap = Vec::new();
            Ok(&mut self.mapping.as_mut().expect("mapping allocated above")[..len])
        } else {
            self.mapping = None;
            self.heap.resize(len, 0);
            Ok(&mut self.heap)
        }
    }

    /// The first `len` bytes, where `len` is at most the size given to the
    /// last [`Self::resize`].
    fn bytes(&self, len: usize) -> &[u8] {
        match &self.mapping {
            Some(mapping) => &mapping[..len],
            None => &self.heap[..len],
        }
    }

    /// The first `len` bytes, writable, where `len` is at most the size
    /// given to the last [`Self::resize`].
    fn bytes_mut(&mut self, len: usize) -> &mut [u8] {
        match &mut self.mapping {
            Some(mapping) => &mut mapping[..len],
            None => &mut self.heap[..len],
        }
    }
}

/// Streams the encoded payloads of the consecutive chunk groups `groups` of
/// a blob from `backend` in one `kind` range read, handing each group
/// `wanted` accepts to `on_group` as soon as its bytes are in: borrowed from
/// the network piece that carried it whole, or gathered in `scratch` when it
/// came split across pieces. A reader thus holds one group at a time rather
/// than the range, and has decoded and cached a group before the next comes
/// in. A group not wanted is skipped over without a copy. Returns the bytes
/// read.
#[allow(clippy::too_many_arguments)]
pub(crate) fn stream_chunk_groups(
    backend: &dyn Backend,
    blob_id: &[u8; SHA256_DIGEST_SIZE],
    blob_metadata: &BlobMetadata,
    groups: Range<usize>,
    kind: ReadKind,
    scratch: &mut ChunkGroupBuffer,
    wanted: &dyn Fn(usize) -> bool,
    on_group: &mut dyn FnMut(&BlobMetadataChunkGroupExtent, &[u8]) -> io::Result<()>,
) -> io::Result<u64> {
    if groups.is_empty() {
        return Ok(0);
    }
    let extent = |index: usize| {
        blob_metadata
            .chunk_group(index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "blob chunk group not found"))
    };
    let base = extent(groups.start)?.compressed_offset();
    let end = extent(groups.end - 1)?.compressed_range().end;

    // The group the next byte belongs to or precedes, how much of it is in,
    // and whether the caller wants it.
    let mut next = groups.start;
    let mut group = extent(next)?;
    let mut want = wanted(next);
    let mut gathered = 0usize;
    let mut pos = base;
    backend.read_range_with(blob_id, base, end - base, kind, &mut |mut piece| {
        while !piece.is_empty() {
            if next == groups.end {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "blob range read past its last chunk group",
                ));
            }
            let start = group.compressed_offset();
            if pos < start {
                let gap = ((start - pos) as usize).min(piece.len());
                piece = &piece[gap..];
                pos += gap as u64;
                continue;
            }

            let size = group.compressed_size() as usize;
            let take = (size - gathered).min(piece.len());
            if want {
                if gathered == 0 && take == size {
                    on_group(&group, &piece[..size])?;
                } else {
                    if gathered == 0 {
                        scratch.resize(size)?;
                    }
                    scratch.bytes_mut(size)[gathered..gathered + take]
                        .copy_from_slice(&piece[..take]);
                    if gathered + take == size {
                        on_group(&group, scratch.bytes(size))?;
                    }
                }
            }
            gathered += take;
            piece = &piece[take..];
            pos += take as u64;

            if gathered == size {
                next += 1;
                gathered = 0;
                if next < groups.end {
                    group = extent(next)?;
                    want = wanted(next);
                }
            }
        }
        Ok(())
    })?;

    if next != groups.end {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("blob range read ended before chunk group {next}"),
        ));
    }
    Ok(end - base)
}

/// Decodes and validates the encoded bytes of `group`: a stored-plain group
/// is its own payload, a compressed one decodes into `decoded`. The crc32c
/// check is skipped when `skip_verify_checksums`.
pub(crate) fn decode_chunk_group<'a>(
    blob_metadata: &BlobMetadata,
    group: &BlobMetadataChunkGroupExtent,
    encoded: &'a [u8],
    decoded: &'a mut ChunkGroupBuffer,
    skip_verify_checksums: bool,
) -> io::Result<&'a [u8]> {
    let payload: &[u8] = if group.is_uncompressed(blob_metadata) {
        encoded
    } else {
        let out = decoded.resize(group.uncompressed_size() as usize)?;
        decode_chunk_group_into(blob_metadata.compressor(), encoded, out)?;
        out
    };
    validate_decoded_chunk_group(group, payload, skip_verify_checksums)?;
    Ok(payload)
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

/// Decompress one encoded chunk group payload into `decoded`, which must be
/// exactly the payload's length.
pub(crate) fn decode_chunk_group_into(
    compressor: BlobMetadataCompressor,
    encoded: &[u8],
    decoded: &mut [u8],
) -> io::Result<()> {
    let decoded_len = decoded.len();
    match compressor {
        BlobMetadataCompressor::Zstd => {
            let written = zstd::bulk::Decompressor::new()
                .and_then(|mut decoder| decoder.decompress_to_buffer(encoded, decoded))
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            if written != decoded_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "zstd chunk group decompressed to an unexpected size",
                ));
            }
        }
        BlobMetadataCompressor::Lz4Block => {
            let written = lz4_flex::block::decompress_into(encoded, decoded)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            if written != decoded_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "lz4 chunk group decompressed to an unexpected size",
                ));
            }
        }
        BlobMetadataCompressor::None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "blob meta declares no compressor but the chunk group is stored compressed",
            ));
        }
    }
    Ok(())
}

/// Expand a decoded chunk group onto its span of the address space: the
/// chunks scattered onto their blocks with zero padding between them and
/// after the last one.
pub fn inflate_decoded_chunk_group(
    blob_metadata: &BlobMetadata,
    group: &BlobMetadataChunkGroupExtent,
    decoded: &[u8],
) -> io::Result<Vec<u8>> {
    let span = usize::try_from(group.logical_size()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "blob meta max bytes per chunk group exceed usize",
        )
    })?;
    let base = group.logical_offset();
    let mut padded = vec![0u8; span];
    for (offset, bytes) in group
        .chunks(blob_metadata, decoded)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
    {
        let start = (offset - base) as usize;
        padded[start..start + bytes.len()].copy_from_slice(bytes);
    }
    Ok(padded)
}

/// Check a decoded chunk group: its length against the chunk table and,
/// unless `skip_verify_checksums`, its crc32c against the group entry. The
/// blob meta's chunk group digests are content identities, not checked
/// here.
pub fn validate_decoded_chunk_group(
    group: &BlobMetadataChunkGroupExtent,
    decoded: &[u8],
    skip_verify_checksums: bool,
) -> io::Result<()> {
    let expected = u64::from(group.uncompressed_size());
    if decoded.len() as u64 != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "decoded blob meta chunk group length mismatch: expected {}, got {}",
                expected,
                decoded.len()
            ),
        ));
    }
    if skip_verify_checksums {
        return Ok(());
    }
    if crc32c::crc32c(decoded) != group.uncompressed_crc32() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            ChunkGroupCrcMismatch,
        ));
    }
    Ok(())
}

/// Whether `span`, the bytes of `group`'s span of a cache file (its chunks on
/// their blocks), holds the group intact: the chunk lengths add up and the
/// chunks match the group's crc32c and, when the blob meta records one, its
/// digest. The check is unconditional, `skip_verify_checksums` or not: it
/// decides whether bytes found in the cache file, which a power loss may have
/// left partly unwritten, can be published as ready without a fetch.
pub(crate) fn cached_chunk_group_is_intact(
    metadata: &BlobMetadata,
    group: &BlobMetadataChunkGroupExtent,
    span: &[u8],
) -> bool {
    let block = nydus_format::erofs::EROFS_BLOCK_SIZE as usize;
    let mut chunks = Vec::with_capacity(group.chunk_range().len());
    let mut at = 0usize;
    for index in group.chunk_range() {
        let Some(length) = metadata.chunk_length(index) else {
            return false;
        };
        let length = length as usize;
        let Some(chunk) = at.checked_add(length).and_then(|end| span.get(at..end)) else {
            return false;
        };
        chunks.push(chunk);
        at += length.div_ceil(block) * block;
    }
    let length: u64 = chunks.iter().map(|chunk| chunk.len() as u64).sum();
    if length != u64::from(group.uncompressed_size()) {
        return false;
    }
    let crc32 = chunks
        .iter()
        .fold(0, |crc32, chunk| crc32c::crc32c_append(crc32, chunk));
    if crc32 != group.uncompressed_crc32() {
        return false;
    }
    match metadata.chunk_group_digest(group.index() as usize) {
        Some(expected) => {
            nydus_format::blob::BlobMetadataChunkGroupDigest::from_chunks(chunks) == expected
        }
        None => true,
    }
}

/// Marker error wrapped in an [`io::Error`] when a decoded chunk group fails
/// CRC validation, so callers with backend context can attribute the failure
/// to the origin or a proxy via [`is_chunk_group_crc_mismatch`].
#[derive(Debug)]
struct ChunkGroupCrcMismatch;

impl std::fmt::Display for ChunkGroupCrcMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "blob meta chunk group crc32 mismatch")
    }
}

impl std::error::Error for ChunkGroupCrcMismatch {}

/// Whether an error denotes a chunk group CRC validation failure.
pub fn is_chunk_group_crc_mismatch(err: &io::Error) -> bool {
    err.get_ref()
        .is_some_and(|inner| inner.is::<ChunkGroupCrcMismatch>())
}

/// The `reason` a cache write failed with `err`: a crc32c mismatch is
/// `checksum`; any other malformed chunk group, a redirect pointing past
/// its source blob's chunk groups included, `decode`; and everything else,
/// the cache file refusing the write, `io`.
pub(crate) fn write_failure_reason(err: &io::Error) -> WriteFailureReason {
    if is_chunk_group_crc_mismatch(err) {
        WriteFailureReason::Checksum
    } else if matches!(
        err.kind(),
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput
    ) {
        WriteFailureReason::Decode
    } else {
        WriteFailureReason::Io
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_format::blob::BlobMetadataDigester;
    use nydus_format::erofs::EROFS_BLOCK_SIZE;
    use nydus_test_utils::blob::uncompressed_data;
    use nydus_test_utils::metadata::{from_chunk_groups, with_wrong_chunk_group_digest};

    #[test]
    fn group_buffer_reuses_and_releases_large_mappings() {
        let mut buffer = ChunkGroupBuffer::default();
        assert!(buffer.resize(0).unwrap().is_empty());
        buffer.resize(4096).unwrap().fill(1);
        assert!(buffer.mapping.is_none());
        let large = buffer.resize(2 * 1024 * 1024).unwrap();
        assert!(large.iter().all(|byte| *byte == 0));
        large.fill(2);
        let address = large.as_ptr();
        let smaller = buffer.resize(1024 * 1024).unwrap();
        assert_eq!(smaller.as_ptr(), address);
        assert!(smaller.iter().all(|byte| *byte == 2));
        assert_eq!(buffer.heap.capacity(), 0);
        assert_eq!(
            buffer.resize(3 * 1024 * 1024).unwrap().len(),
            3 * 1024 * 1024
        );
        assert_eq!(buffer.resize(4096).unwrap(), &[0; 4096]);
        assert!(buffer.mapping.is_none());
    }

    #[test]
    fn group_buffer_preserves_contents_around_huge_page_size() {
        let mut buffer = ChunkGroupBuffer::default();
        for len in [
            2 * 1024 * 1024 - 1,
            2 * 1024 * 1024,
            2 * 1024 * 1024 + 1,
            4 * 1024 * 1024,
        ] {
            let bytes = buffer.resize(len).unwrap();
            assert!(bytes.iter().all(|byte| *byte == 0));
            bytes.fill(0xa5);
            let address = bytes.as_ptr();
            let bytes = buffer.resize(len).unwrap();
            assert_eq!(bytes.as_ptr(), address);
            assert!(bytes.iter().all(|byte| *byte == 0xa5));
            buffer.resize(0).unwrap();
            assert!(buffer.mapping.is_none());
        }
    }

    #[test]
    fn mapped_output_decodes_and_recovers_after_errors() {
        let payload = vec![0x5a; 2 * 1024 * 1024];
        let mut buffer = ChunkGroupBuffer::default();
        for compressor in [
            BlobMetadataCompressor::Zstd,
            BlobMetadataCompressor::Lz4Block,
        ] {
            let encoded = match compressor {
                BlobMetadataCompressor::Zstd => zstd::bulk::compress(&payload, 0).unwrap(),
                BlobMetadataCompressor::Lz4Block => lz4_flex::block::compress(&payload),
                BlobMetadataCompressor::None => unreachable!(),
            };
            for declared in [payload.len() - 1, payload.len() + 1, payload.len()] {
                let output = buffer.resize(declared).unwrap();
                output.fill(0xa5);
                let result = decode_chunk_group_into(compressor, &encoded, output);
                assert_eq!(result.is_ok(), declared == payload.len());
                if result.is_ok() {
                    assert_eq!(output, payload);
                }
            }
            let output = buffer.resize(payload.len()).unwrap();
            assert!(
                decode_chunk_group_into(compressor, &encoded[..encoded.len() / 2], output).is_err()
            );
            decode_chunk_group_into(compressor, &encoded, output).unwrap();
            assert_eq!(output, payload);
        }
    }

    #[test]
    fn window_decode_borrows_plain_payload_and_preserves_validation() {
        let payload = vec![0x5a; 4096];
        for compressor in [
            BlobMetadataCompressor::None,
            BlobMetadataCompressor::Zstd,
            BlobMetadataCompressor::Lz4Block,
        ] {
            let (data, metadata) =
                from_chunk_groups(compressor, 4096, &[vec![payload.clone()]], None);
            let group = metadata.chunk_group(0).unwrap();
            // The window starts 37 bytes before the group.
            let mut window = vec![0; 37];
            window.extend_from_slice(&data);
            let mut scratch = Vec::new();
            let result = decode_chunk_group_from_window(
                &metadata,
                &group,
                0,
                &window[37..],
                &mut scratch,
                false,
            )
            .unwrap();
            assert_eq!(result, payload);
            if group.is_uncompressed(&metadata) {
                assert_eq!(compressor, BlobMetadataCompressor::None);
                assert_eq!(result.as_ptr(), window[37..].as_ptr());
                assert_eq!(scratch.capacity(), 0);
            } else {
                assert_eq!(scratch, payload);
            }
            // A window that does not reach the group's end is rejected.
            assert!(decode_chunk_group_from_window(
                &metadata,
                &group,
                0,
                &data[..data.len() - 1],
                &mut scratch,
                false,
            )
            .is_err());
            // A window starting past the group's offset is rejected.
            assert!(decode_chunk_group_from_window(
                &metadata,
                &group,
                1,
                &data,
                &mut scratch,
                false
            )
            .is_err());
        }
    }

    #[test]
    fn group_decode_is_bounded_by_the_declared_payload() {
        let mut decoded = vec![0; 4096];
        for size in [4096, 4095, 1024 * 1024] {
            let encoded = zstd::bulk::compress(&vec![0x5a; size], 0).unwrap();
            let result =
                decode_chunk_group_into(BlobMetadataCompressor::Zstd, &encoded, &mut decoded);
            assert_eq!(result.is_ok(), size == 4096);
        }
    }

    #[test]
    fn decoded_groups_are_checked_against_their_length_and_crc() {
        let chunks = vec![vec![1u8; 100], vec![2u8; 5000]];
        let (data, metadata) = from_chunk_groups(
            BlobMetadataCompressor::None,
            16384,
            &[chunks],
            Some(BlobMetadataDigester::Blake3),
        );
        let group = metadata.chunk_group(0).unwrap();
        validate_decoded_chunk_group(&group, &data, false).unwrap();

        // A fetched group is not checked against its digest: the digests name
        // content, the crc guards the transfer.
        let wrong = with_wrong_chunk_group_digest(&metadata, 0);
        let wrong_group = wrong.chunk_group(0).unwrap();
        validate_decoded_chunk_group(&wrong_group, &data, false).unwrap();
        let mut decoded = Vec::new();
        let payload =
            decode_chunk_group_from_window(&wrong, &wrong_group, 0, &data, &mut decoded, false)
                .unwrap();
        assert_eq!(payload, data.as_slice());

        // A corrupted payload fails the crc.
        let mut corrupted = data.clone();
        corrupted[0] ^= 0xff;
        let err = validate_decoded_chunk_group(&group, &corrupted, false).unwrap_err();
        assert!(is_chunk_group_crc_mismatch(&err));
        // A short payload fails the length check.
        assert!(validate_decoded_chunk_group(&group, &data[1..], false).is_err());
    }

    #[test]
    fn inflate_scatters_chunks_onto_their_blocks() {
        let groups = vec![vec![vec![7u8; 100], vec![8u8; 4097]], vec![vec![9u8; 1]]];
        let (data, metadata) =
            from_chunk_groups(BlobMetadataCompressor::None, 16384, &groups, None);
        let image = uncompressed_data(&groups);
        assert_eq!(image.len(), 4 * 4096);
        let group0 = metadata.chunk_group(0).unwrap();
        let group1 = metadata.chunk_group(1).unwrap();
        let payload0 = &data[..group0.compressed_size() as usize];
        let payload1 = &data[group0.compressed_size() as usize..];
        assert_eq!(
            inflate_decoded_chunk_group(&metadata, &group0, payload0).unwrap(),
            image[..3 * 4096]
        );
        assert_eq!(
            inflate_decoded_chunk_group(&metadata, &group1, payload1).unwrap(),
            image[3 * 4096..]
        );
    }

    /// A backend streaming an in-memory data region in pieces of `piece`
    /// bytes, recording the ranges read.
    struct Pieces {
        data: Vec<u8>,
        piece: usize,
        ranges: std::sync::Mutex<Vec<Range<u64>>>,
        metrics: std::sync::Arc<nydus_telemetry::metrics::Metrics>,
    }

    impl Pieces {
        fn new(data: Vec<u8>, piece: usize) -> Self {
            Self {
                data,
                piece,
                ranges: Default::default(),
                metrics: Default::default(),
            }
        }
    }

    impl Backend for Pieces {
        fn metrics(&self) -> &std::sync::Arc<nydus_telemetry::metrics::Metrics> {
            &self.metrics
        }

        fn read_blob_metadata(&self, _: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<BlobMetadata> {
            unimplemented!()
        }

        fn read_range_into(
            &self,
            _: &[u8; SHA256_DIGEST_SIZE],
            offset: u64,
            buf: &mut [u8],
        ) -> io::Result<()> {
            buf.copy_from_slice(&self.data[offset as usize..offset as usize + buf.len()]);
            Ok(())
        }

        fn read_range_with(
            &self,
            _: &[u8; SHA256_DIGEST_SIZE],
            offset: u64,
            len: u64,
            _: ReadKind,
            sink: &mut dyn FnMut(&[u8]) -> io::Result<()>,
        ) -> io::Result<()> {
            self.ranges.lock().unwrap().push(offset..offset + len);
            let end = (offset + len).min(self.data.len() as u64) as usize;
            for piece in self.data[offset as usize..end].chunks(self.piece) {
                sink(piece)?;
            }
            Ok(())
        }
    }

    #[test]
    fn stream_chunk_groups_hands_on_each_wanted_group_as_it_arrives() {
        let groups: Vec<Vec<Vec<u8>>> = (0..5u8)
            .map(|i| vec![(0..9000u32).map(|n| (n % 251) as u8 ^ i).collect()])
            .collect();
        let (data, metadata) =
            from_chunk_groups(BlobMetadataCompressor::Zstd, 16384, &groups, None);
        let encoded = |index: usize| {
            let group = metadata.chunk_group(index).unwrap();
            data[group.compressed_offset() as usize..group.compressed_range().end as usize].to_vec()
        };

        // Pieces smaller than a group gather it in the scratch, larger ones
        // carry it whole; either way every wanted group arrives once, in
        // order, and the unwanted one is skipped.
        for piece in [1, 7, 512, 1 << 20] {
            let backend = Pieces::new(data.clone(), piece);
            let mut scratch = ChunkGroupBuffer::default();
            let mut seen = Vec::new();
            let read = stream_chunk_groups(
                &backend,
                &[0; SHA256_DIGEST_SIZE],
                &metadata,
                1..5,
                ReadKind::Prefetch,
                &mut scratch,
                &|index| index != 3,
                &mut |group, bytes| {
                    seen.push((group.index() as usize, bytes.to_vec()));
                    Ok(())
                },
            )
            .unwrap();

            let start = metadata.chunk_group(1).unwrap().compressed_offset();
            let end = metadata.chunk_group(4).unwrap().compressed_range().end;
            assert_eq!(read, end - start, "{piece}");
            assert_eq!(*backend.ranges.lock().unwrap(), vec![start..end], "{piece}");
            assert_eq!(
                seen,
                vec![(1, encoded(1)), (2, encoded(2)), (4, encoded(4))],
                "{piece}"
            );
            let mut decoded = ChunkGroupBuffer::default();
            for (index, bytes) in &seen {
                let group = metadata.chunk_group(*index).unwrap();
                let payload =
                    decode_chunk_group(&metadata, &group, bytes, &mut decoded, false).unwrap();
                assert_eq!(payload, groups[*index].concat(), "{piece} {index}");
            }
        }
    }

    #[test]
    fn stream_chunk_groups_stops_on_a_group_error_and_a_short_range() {
        let groups: Vec<Vec<Vec<u8>>> = (0..3u8).map(|i| vec![vec![i; 4096]]).collect();
        let (data, metadata) = from_chunk_groups(BlobMetadataCompressor::None, 4096, &groups, None);

        let backend = Pieces::new(data.clone(), 1000);
        let mut calls = 0;
        let err = stream_chunk_groups(
            &backend,
            &[0; SHA256_DIGEST_SIZE],
            &metadata,
            0..3,
            ReadKind::Ondemand,
            &mut ChunkGroupBuffer::default(),
            &|_| true,
            &mut |_, _| {
                calls += 1;
                Err(io::Error::new(io::ErrorKind::InvalidData, "bad group"))
            },
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(calls, 1);

        let backend = Pieces::new(data[..2 * 4096 + 100].to_vec(), 1000);
        let mut seen = 0;
        let err = stream_chunk_groups(
            &backend,
            &[0; SHA256_DIGEST_SIZE],
            &metadata,
            0..3,
            ReadKind::Ondemand,
            &mut ChunkGroupBuffer::default(),
            &|_| true,
            &mut |_, _| {
                seen += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(seen, 2);
    }

    #[test]
    fn prefetch_batches_follow_the_compressed_target() {
        let groups: Vec<Vec<Vec<u8>>> = (0..5u8).map(|i| vec![vec![i; 4096]]).collect();
        let (_, metadata) = from_chunk_groups(BlobMetadataCompressor::None, 4096, &groups, None);
        assert_eq!(
            plan_prefetch_batches(&metadata, 0, 0),
            vec![0..1, 1..2, 2..3, 3..4, 4..5]
        );
        assert_eq!(
            plan_prefetch_batches(&metadata, 4096, 0),
            vec![0..1, 1..2, 2..3, 3..4, 4..5]
        );
        assert_eq!(
            plan_prefetch_batches(&metadata, 8192, 0),
            vec![0..2, 2..4, 4..5]
        );
        assert_eq!(plan_prefetch_batches(&metadata, u64::MAX, 0), vec![0..5]);
        // The ramp peels single groups off the head, then batches resume.
        assert_eq!(
            plan_prefetch_batches(&metadata, u64::MAX, 2),
            vec![0..1, 1..2, 2..5]
        );
        assert_eq!(
            plan_prefetch_batches(&metadata, 8192, 3),
            vec![0..1, 1..2, 2..3, 3..5]
        );
        assert_eq!(
            plan_prefetch_batches(&metadata, u64::MAX, 9),
            vec![0..1, 1..2, 2..3, 3..4, 4..5]
        );
        let (_, empty) = from_chunk_groups(BlobMetadataCompressor::None, 4096, &[], None);
        assert!(plan_prefetch_batches(&empty, 4096, 4).is_empty());
    }

    #[test]
    fn crc_mismatch_fails_the_window_decode() {
        let payload = vec![0u8; EROFS_BLOCK_SIZE as usize];
        let metadata = BlobMetadata::new(
            1,
            1,
            BlobMetadataCompressor::None,
            None,
            vec![
                nydus_format::blob::BlobMetadataChunkGroup::new(0, 0, 0, EROFS_BLOCK_SIZE, 0),
                nydus_format::blob::BlobMetadataChunkGroup::new(
                    u64::from(EROFS_BLOCK_SIZE),
                    1,
                    1,
                    0,
                    0,
                ),
            ],
            vec![nydus_format::blob::BlobMetadataChunkLength::new(
                EROFS_BLOCK_SIZE,
            )],
            vec![],
            vec![],
        )
        .unwrap();
        let group = metadata.chunk_group(0).unwrap();

        let err =
            validate_decoded_chunk_group(&group, &payload, false).expect_err("crc must mismatch");
        assert!(is_chunk_group_crc_mismatch(&err));
        let mut scratch = Vec::new();
        let err =
            decode_chunk_group_from_window(&metadata, &group, 0, &payload, &mut scratch, false)
                .expect_err("borrowed payload must still be validated");
        assert!(is_chunk_group_crc_mismatch(&err));
        assert_eq!(scratch.capacity(), 0);
    }

    #[test]
    fn write_failures_are_classified_by_their_error() {
        let test_cases = vec![
            (
                io::Error::new(io::ErrorKind::InvalidData, ChunkGroupCrcMismatch),
                WriteFailureReason::Checksum,
            ),
            (
                io::Error::new(io::ErrorKind::InvalidData, "short payload"),
                WriteFailureReason::Decode,
            ),
            (
                io::Error::new(io::ErrorKind::InvalidInput, "group out of range"),
                WriteFailureReason::Decode,
            ),
            (
                io::Error::new(io::ErrorKind::StorageFull, "no space"),
                WriteFailureReason::Io,
            ),
            (io::Error::other("pwrite"), WriteFailureReason::Io),
        ];

        for (err, expected) in test_cases {
            assert_eq!(write_failure_reason(&err), expected, "{err}");
        }
    }

    /// A group found in the cache file is intact only when every chunk on its
    /// blocks matches: a lost page of data, a stray byte or a span cut short
    /// is rejected, with or without a digest; a lost page that held zeros
    /// anyway is, correctly, intact. With a digest, the crc alone is not
    /// enough.
    #[test]
    fn cached_chunk_groups_are_intact_only_when_every_chunk_matches() {
        let block = EROFS_BLOCK_SIZE as usize;
        let mut data_page = vec![0x5au8; block];
        data_page[7] = 1;
        let groups = vec![
            // A full chunk spanning a zero page and a data page, then a chunk
            // short of a block (its tail is padding outside the payload).
            vec![
                [vec![0u8; block], data_page.clone()].concat(),
                vec![0x77; 100],
            ],
            vec![vec![0x33; 3 * block]],
        ];
        let image = uncompressed_data(&groups);
        for digester in [Some(BlobMetadataDigester::Blake3), None] {
            let (_, meta) = from_chunk_groups(
                BlobMetadataCompressor::Zstd,
                4 * EROFS_BLOCK_SIZE,
                &groups,
                digester,
            );
            for index in 0..groups.len() {
                let group = meta.chunk_group(index).unwrap();
                let range = group.logical_range();
                let span = &image[range.start as usize..range.end as usize];
                assert!(cached_chunk_group_is_intact(&meta, &group, span), "{index}");

                let mut lost = span.to_vec();
                lost[block..2 * block].fill(0);
                let mut flipped = span.to_vec();
                flipped[block + 9] ^= 0x10;
                assert!(
                    !cached_chunk_group_is_intact(&meta, &group, &lost),
                    "{index}"
                );
                assert!(
                    !cached_chunk_group_is_intact(&meta, &group, &flipped),
                    "{index}"
                );
                assert!(!cached_chunk_group_is_intact(
                    &meta,
                    &group,
                    &span[..span.len() - block]
                ));
                assert!(!cached_chunk_group_is_intact(
                    &meta,
                    &group,
                    &vec![0u8; span.len()]
                ));
            }
            let group = meta.chunk_group(0).unwrap();
            let mut zero_page_lost = image[..group.logical_size() as usize].to_vec();
            zero_page_lost[..block].fill(0);
            assert!(cached_chunk_group_is_intact(&meta, &group, &zero_page_lost));
            // Padding is not part of the payload.
            let mut padding = image[..group.logical_size() as usize].to_vec();
            *padding.last_mut().unwrap() = 0xee;
            assert!(cached_chunk_group_is_intact(&meta, &group, &padding));
            // With a digest, matching the crc is not enough.
            if digester.is_some() {
                let wrong = with_wrong_chunk_group_digest(&meta, 0);
                let span = &image[..group.logical_size() as usize];
                assert!(!cached_chunk_group_is_intact(
                    &wrong,
                    &wrong.chunk_group(0).unwrap(),
                    span
                ));
            }
        }
    }
}
