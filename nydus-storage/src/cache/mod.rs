mod caches;
mod chunk_group_lock;
pub mod local;
pub mod raw;
pub mod remote;

use std::io;
use std::ops::Range;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use nydus_backend::BlobBackend;
use nydus_format::blob::{
    BlobMetadata, BlobMetadataChunkGroup, BlobMetadataChunkGroupDigest, BlobMetadataCompressor,
};

/// Default on-demand fetch size: the compressed bytes one backend read
/// covers around a missed chunk group (see [`set_fetch_size`]). 2 MiB.
pub const DEFAULT_FETCH_SIZE: u64 = 2 * 1024 * 1024;

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

    /// Return ready byte intervals overlapping `[offset, offset + len)`.
    /// This must not trigger backend fetch.
    fn ready_ranges(&self, _offset: u64, _len: u64) -> io::Result<Vec<Range<u64>>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ready_ranges is not supported by this blob cache",
        ))
    }

    /// True when this blob is an `optimize` output: a REDIRECT blob whose
    /// chunk groups copy other blobs' groups, which `prefetch.scope:
    /// ondemand` streams into those source blobs' caches first.
    fn is_redirect(&self) -> bool {
        false
    }

    /// Whether chunk group `chunk_group_index` is already decoded into the
    /// local cache, per the shared chunk group map; `false` for caches
    /// without one. Never fetches.
    fn is_chunk_group_ready(&self, _chunk_group_index: usize) -> bool {
        false
    }

    /// Stream a REDIRECT blob's chunk groups: fetch them in batches of the
    /// fetch size through up to `workers` threads, decode and validate each
    /// against this blob's metadata, and hand the payload to `cb` in blob
    /// order. Groups `skip` accepts are not fetched (a batch made entirely
    /// of them costs no backend read); a group that fails to decode is
    /// logged and skipped, while an error from `cb` aborts the stream.
    fn for_each_redirect_chunk_group(
        &self,
        _workers: usize,
        _deadline: Option<Instant>,
        _skip: &(dyn Fn(&BlobMetadataChunkGroup) -> bool + Sync),
        _cb: &(dyn Fn(&BlobMetadataChunkGroup, &[u8]) -> io::Result<()> + Sync),
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "for_each_redirect_chunk_group is not supported by this blob cache",
        ))
    }

    /// Write the decoded payload of this blob's chunk group
    /// `chunk_group_index`, obtained from a REDIRECT blob, into the local
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
/// payload bytes. Checksum failures are attributed to `backend`, which
/// served the window.
pub fn decode_chunk_group_from_window<'a>(
    blob_metadata: &BlobMetadata,
    backend: &Arc<dyn BlobBackend>,
    group: &BlobMetadataChunkGroup,
    window_base_offset: u64,
    window_bytes: &'a [u8],
    decoded: &'a mut Vec<u8>,
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
    let payload_len = usize::try_from(blob_metadata.payload_size(group)).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "blob meta chunk group payload size exceeds usize",
        )
    })?;

    let payload = if blob_metadata.is_plain(group) {
        encoded
    } else {
        decoded.clear();
        decoded.resize(payload_len, 0);
        decode_chunk_group_into(blob_metadata.compressor(), encoded, decoded)?;
        decoded.as_slice()
    };

    validate_chunk_group_with_metrics(backend, blob_metadata, group, payload)?;
    Ok(payload)
}

/// Job-owned fetch buffers. Large allocations are unmapped when the job ends.
#[derive(Default)]
pub struct ChunkGroupBuffers {
    encoded: ChunkGroupBuffer,
    decoded: ChunkGroupBuffer,
}

impl ChunkGroupBuffers {
    /// Both buffers sized to `encoded_len` and `decoded_len`, borrowed
    /// together so a caller can decode from one into the other.
    pub(crate) fn resize_pair(
        &mut self,
        encoded_len: usize,
        decoded_len: usize,
    ) -> io::Result<(&mut [u8], &mut [u8])> {
        let encoded = self.encoded.resize(encoded_len)?;
        let decoded = self.decoded.resize(decoded_len)?;
        Ok((encoded, decoded))
    }
}

/// Large transient buffers bypass heap arenas and advise huge pages on Linux.
#[derive(Default)]
struct ChunkGroupBuffer {
    heap: Vec<u8>,
    mapping: Option<memmap2::MmapMut>,
}

impl ChunkGroupBuffer {
    fn resize(&mut self, len: usize) -> io::Result<&mut [u8]> {
        if len >= 1024 * 1024 {
            if self
                .mapping
                .as_ref()
                .map_or(true, |mapping| mapping.len() < len)
            {
                let mapping = memmap2::MmapMut::map_anon(len)?;
                #[cfg(target_os = "linux")]
                if len >= 2 * 1024 * 1024 {
                    let _ = mapping.advise(memmap2::Advice::HugePage);
                }
                self.mapping = Some(mapping);
            }
            self.heap = Vec::new();
            Ok(&mut self.mapping.as_mut().expect("mapping allocated above")[..len])
        } else {
            self.mapping = None;
            self.heap.resize(len, 0);
            Ok(&mut self.heap)
        }
    }
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

/// Validate a decoded chunk group and, on a checksum failure, attribute a
/// CRC error metric to the backend that served the bytes. A read diverted
/// from the backend's static target (e.g. a Dragonfly fallback to the
/// origin) is attributed to the side that actually served it, via
/// [`nydus_backend::last_read_served_by`].
pub fn validate_chunk_group_with_metrics(
    backend: &Arc<dyn BlobBackend>,
    blob_metadata: &BlobMetadata,
    group: &BlobMetadataChunkGroup,
    decoded: &[u8],
) -> io::Result<()> {
    if let Err(err) = validate_decoded_chunk_group(blob_metadata, group, decoded) {
        if is_chunk_group_crc_mismatch(&err) {
            let target =
                nydus_backend::last_read_served_by().unwrap_or_else(|| backend.backend_target());
            nydus_telemetry::metrics::record_backend_crc_error(target);
        }
        return Err(err);
    }
    Ok(())
}

/// Expand a decoded chunk group onto its span of the address space: the
/// chunks scattered onto their blocks with zero padding between them and
/// after the last one.
pub fn inflate_decoded_chunk_group(
    blob_metadata: &BlobMetadata,
    group: &BlobMetadataChunkGroup,
    decoded: &[u8],
) -> io::Result<Vec<u8>> {
    let span = usize::try_from(group.uncompressed_size()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "blob meta chunk group span exceeds usize",
        )
    })?;
    let base = group.uncompressed_offset();
    let mut padded = vec![0u8; span];
    blob_metadata.for_each_decoded_chunk(
        group.index() as usize,
        decoded,
        &mut |offset, bytes| {
            let start = (offset - base) as usize;
            padded[start..start + bytes.len()].copy_from_slice(bytes);
            Ok(())
        },
    )?;
    Ok(padded)
}

/// Check a decoded chunk group: its length against the chunk table, its
/// crc32c against the group entry (always — a crc32c over a group is
/// cheap), and, unless checksum verification is skipped, every chunk's
/// BLAKE3 digest when the blob carries digests.
pub fn validate_decoded_chunk_group(
    blob_metadata: &BlobMetadata,
    group: &BlobMetadataChunkGroup,
    decoded: &[u8],
) -> io::Result<()> {
    let expected = blob_metadata.payload_size(group);
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
    if crc32c::crc32c(decoded) != group.payload_crc32() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            ChunkGroupCrcMismatch,
        ));
    }
    if skip_verify_checksums() {
        return Ok(());
    }
    if let Some(algorithm) = blob_metadata.unsupported_digest_algorithm() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("cannot verify chunk groups digested with unsupported algorithm {algorithm}"),
        ));
    }
    if blob_metadata.digest_count() == 0 {
        return Ok(());
    }
    let expected = blob_metadata
        .digest(group.index() as usize)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk group digest missing"))?;
    // Members follow each other in the decoded payload; a lone chunk is the
    // whole payload.
    let mut at = 0usize;
    let mut members = Vec::with_capacity(group.chunk_count() as usize);
    for (_, _, len) in blob_metadata.chunk_group_chunks(group.index() as usize) {
        let len = len as usize;
        members.push(*blake3::hash(&decoded[at..at + len]).as_bytes());
        at += len;
    }
    if BlobMetadataChunkGroupDigest::of_group(&members) != Some(expected) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("blob chunk group {} digest mismatch", group.index()),
        ));
    }
    Ok(())
}

/// Process-wide switch skipping per-chunk digest verification (the
/// default), set at service startup from `storage.skip_verify_checksums`.
/// The per-group crc32c is always checked. A process serves one mount, so a
/// per-cache flag would only thread the same value through every call site.
static SKIP_VERIFY_CHECKSUMS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

/// Skip (or re-enable) per-chunk digest verification for this process.
pub fn set_skip_verify_checksums(skip: bool) {
    SKIP_VERIFY_CHECKSUMS.store(skip, std::sync::atomic::Ordering::Relaxed);
}

pub(crate) fn skip_verify_checksums() -> bool {
    SKIP_VERIFY_CHECKSUMS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Compressed bytes one on-demand backend read covers: the fetch-size-aligned
/// cell of the blob's data region holding the missed chunk group, extended
/// to whole groups and trimmed at groups already cached or in flight. Set
/// at service startup from `storage.fetch_size`; zero means the missed
/// group alone.
static FETCH_SIZE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(DEFAULT_FETCH_SIZE);

/// Set the on-demand fetch size, in compressed bytes.
pub fn set_fetch_size(bytes: u64) {
    FETCH_SIZE.store(bytes, std::sync::atomic::Ordering::Relaxed);
}

pub(crate) fn fetch_size() -> u64 {
    FETCH_SIZE.load(std::sync::atomic::Ordering::Relaxed)
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

#[cfg(test)]
pub(crate) mod test_util {
    use nydus_format::blob::{
        BlobMetadata, BlobMetadataChunkGroup, BlobMetadataChunkGroupDigest, BlobMetadataCompressor,
        BlobMetadataDigester,
    };

    /// Encode `groups` (each a list of chunks) with `compressor` into a data
    /// region and the blob meta describing it, with a `group_span`-byte
    /// group span, a one-block index span and BLAKE3 digests when `digests`
    /// is set. Every group is stored compressed when that shrinks it, plain
    /// otherwise. Groups tile the address space back to back, each chunk on
    /// its own blocks.
    pub(crate) fn encode_blob(
        compressor: BlobMetadataCompressor,
        group_span: u32,
        groups: &[Vec<Vec<u8>>],
        digests: bool,
    ) -> (Vec<u8>, BlobMetadata) {
        let mut data = Vec::new();
        let mut specs = Vec::new();
        let mut members = Vec::new();
        let mut digest_table = Vec::new();
        for group in groups {
            let payload: Vec<u8> = group.concat();
            let encoded = match compressor {
                BlobMetadataCompressor::None => None,
                BlobMetadataCompressor::Zstd => Some(zstd::bulk::compress(&payload, 0).unwrap()),
                BlobMetadataCompressor::Lz4Block => Some(lz4_flex::block::compress(&payload)),
            }
            .filter(|encoded| encoded.len() < payload.len());
            let stored = encoded.as_deref().unwrap_or(&payload);
            data.extend_from_slice(stored);
            members.extend(group.iter().map(|chunk| chunk.len() as u32));
            let chunk_count = group.len() as u32;
            specs.push(
                BlobMetadataChunkGroup::new(
                    stored.len() as u32,
                    payload.len() as u32,
                    chunk_count,
                    crc32c::crc32c(&payload),
                    None,
                )
                .unwrap(),
            );
            let digests: Vec<[u8; 32]> = group
                .iter()
                .map(|chunk| *blake3::hash(chunk).as_bytes())
                .collect();
            digest_table.push(BlobMetadataChunkGroupDigest::of_group(&digests).unwrap());
        }
        if !digests {
            digest_table.clear();
        }
        let meta = BlobMetadata::new(
            compressor,
            if digests {
                BlobMetadataDigester::Blake3
            } else {
                BlobMetadataDigester::None
            },
            group_span,
            4096,
            specs,
            members,
            digest_table,
        )
        .unwrap();
        (data, meta)
    }

    /// The padded address space `groups` occupy: every chunk on its own
    /// blocks, groups back to back — what a fully filled cache file holds.
    pub(crate) fn padded_image(groups: &[Vec<Vec<u8>>]) -> Vec<u8> {
        let blocks: usize = groups
            .iter()
            .flatten()
            .map(|chunk| chunk.len().div_ceil(4096))
            .sum();
        let mut image = vec![0u8; blocks * 4096];
        let mut at = 0;
        for chunk in groups.iter().flatten() {
            image[at..at + chunk.len()].copy_from_slice(chunk);
            at += chunk.len().div_ceil(4096) * 4096;
        }
        image
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::{encode_blob, padded_image};
    use super::*;
    use nydus_backend::ReadContext;
    use nydus_format::blob::BlobMetadataTableType;
    use nydus_format::erofs::EROFS_BLOCK_SIZE;
    use nydus_format::utils::SHA256_DIGEST_SIZE;

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
        let backend: Arc<dyn BlobBackend> = Arc::new(StaticTargetBackend);
        let payload = vec![0x5a; 4096];
        for compressor in [
            BlobMetadataCompressor::None,
            BlobMetadataCompressor::Zstd,
            BlobMetadataCompressor::Lz4Block,
        ] {
            let (data, metadata) = encode_blob(compressor, 4096, &[vec![payload.clone()]], false);
            let group = metadata.chunk_group(0).unwrap();
            // The window starts 37 bytes before the group.
            let mut window = vec![0; 37];
            window.extend_from_slice(&data);
            let mut scratch = Vec::new();
            let result = decode_chunk_group_from_window(
                &metadata,
                &backend,
                &group,
                0,
                &window[37..],
                &mut scratch,
            )
            .unwrap();
            assert_eq!(result, payload);
            if metadata.is_plain(&group) {
                assert_eq!(compressor, BlobMetadataCompressor::None);
                assert_eq!(result.as_ptr(), window[37..].as_ptr());
                assert_eq!(scratch.capacity(), 0);
            } else {
                assert_eq!(scratch, payload);
            }
            // A window that does not reach the group's end is rejected.
            assert!(decode_chunk_group_from_window(
                &metadata,
                &backend,
                &group,
                0,
                &data[..data.len() - 1],
                &mut scratch,
            )
            .is_err());
            // A window starting past the group's offset is rejected.
            assert!(decode_chunk_group_from_window(
                &metadata,
                &backend,
                &group,
                1,
                &data,
                &mut scratch,
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
    fn digests_are_checked_when_verification_is_on() {
        set_skip_verify_checksums(false);
        let chunks = vec![vec![1u8; 100], vec![2u8; 5000]];
        let (data, metadata) = encode_blob(BlobMetadataCompressor::None, 16384, &[chunks], true);
        let group = metadata.chunk_group(0).unwrap();
        validate_decoded_chunk_group(&metadata, &group, &data).unwrap();

        // Same payload and crc, one wrong digest: the digest check fires and
        // is not a crc mismatch.
        let mut digests: Vec<_> = metadata.digests().to_vec();
        digests[0] = nydus_format::blob::BlobMetadataChunkGroupDigest::new([0; 32]);
        let wrong = BlobMetadata::new(
            BlobMetadataCompressor::None,
            nydus_format::blob::BlobMetadataDigester::Blake3,
            16384,
            4096,
            vec![nydus_format::blob::BlobMetadataChunkGroup::new(
                data.len() as u32,
                data.len() as u32,
                2,
                group.payload_crc32(),
                None,
            )
            .unwrap()],
            vec![100, 5000],
            digests,
        )
        .unwrap();
        let wrong_group = wrong.chunk_group(0).unwrap();
        let err = validate_decoded_chunk_group(&wrong, &wrong_group, &data).unwrap_err();
        assert!(err.to_string().contains("chunk group 0 digest mismatch"));
        assert!(!is_chunk_group_crc_mismatch(&err));

        // A corrupted payload fails the crc before any digest is consulted.
        let mut corrupted = data.clone();
        corrupted[0] ^= 0xff;
        let err = validate_decoded_chunk_group(&metadata, &group, &corrupted).unwrap_err();
        assert!(is_chunk_group_crc_mismatch(&err));
        // A short payload fails the length check.
        assert!(validate_decoded_chunk_group(&metadata, &group, &data[1..]).is_err());

        // A ChunkGroupDigestTable algorithm this reader does not know fails verification
        // instead of skipping it.
        let mut raw = Vec::new();
        metadata.write_to(&mut raw).unwrap();
        let digest_table = metadata
            .tables()
            .iter()
            .find(|table| table.table_type() == BlobMetadataTableType::CHUNK_GROUP_DIGEST)
            .unwrap()
            .range();
        raw[digest_table.start + 16] = 9;
        raw[16..20].fill(0);
        let crc = crc32c::crc32c(&raw);
        raw[16..20].copy_from_slice(&crc.to_le_bytes());
        let unknown = BlobMetadata::from_bytes(&raw).unwrap();
        assert_eq!(unknown.digest_count(), 0);
        let err = validate_decoded_chunk_group(&unknown, &group, &data).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("algorithm 9"), "{err}");
    }

    #[test]
    fn inflate_scatters_chunks_onto_their_blocks() {
        let groups = vec![vec![vec![7u8; 100], vec![8u8; 4097]], vec![vec![9u8; 1]]];
        let (data, metadata) = encode_blob(BlobMetadataCompressor::None, 16384, &groups, false);
        let image = padded_image(&groups);
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

    #[test]
    fn prefetch_batches_follow_the_compressed_target() {
        let groups: Vec<Vec<Vec<u8>>> = (0..5u8).map(|i| vec![vec![i; 4096]]).collect();
        let (_, metadata) = encode_blob(BlobMetadataCompressor::None, 4096, &groups, false);
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
        let (_, empty) = encode_blob(BlobMetadataCompressor::None, 4096, &[], false);
        assert!(plan_prefetch_batches(&empty, 4096, 4).is_empty());
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
        use nydus_telemetry::metrics::BackendTarget;

        let backend: Arc<dyn BlobBackend> = Arc::new(StaticTargetBackend);
        let payload = vec![0u8; EROFS_BLOCK_SIZE as usize];
        // A zeroed block has crc32c != 0, so a group declaring crc 0 mismatches.
        let metadata = BlobMetadata::new(
            BlobMetadataCompressor::None,
            nydus_format::blob::BlobMetadataDigester::None,
            4096,
            4096,
            vec![nydus_format::blob::BlobMetadataChunkGroup::new(
                EROFS_BLOCK_SIZE,
                EROFS_BLOCK_SIZE,
                1,
                0,
                None,
            )
            .unwrap()],
            vec![EROFS_BLOCK_SIZE],
            vec![],
        )
        .unwrap();
        let group = metadata.chunk_group(0).unwrap();
        assert!(nydus_backend::last_read_served_by().is_none());

        let proxy_before = nydus_telemetry::metrics::backend_crc_error_total(BackendTarget::Proxy);
        let err = validate_chunk_group_with_metrics(&backend, &metadata, &group, &payload)
            .expect_err("crc must mismatch");
        assert!(is_chunk_group_crc_mismatch(&err));
        assert_eq!(
            nydus_telemetry::metrics::backend_crc_error_total(BackendTarget::Proxy),
            proxy_before + 1
        );
        let mut scratch = Vec::new();
        let err =
            decode_chunk_group_from_window(&metadata, &backend, &group, 0, &payload, &mut scratch)
                .expect_err("borrowed payload must still be validated");
        assert!(is_chunk_group_crc_mismatch(&err));
        assert_eq!(scratch.capacity(), 0);
        assert_eq!(
            nydus_telemetry::metrics::backend_crc_error_total(BackendTarget::Proxy),
            proxy_before + 2
        );
    }
}
