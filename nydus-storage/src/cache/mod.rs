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

use nydus_config::StorageConfig;
use nydus_format::blob::{BlobMetadata, BlobMetadataChunkGroupExtent, BlobMetadataCompressor};
use nydus_telemetry::metrics::WriteFailureReason;

/// Default on-demand fetch size: the compressed bytes one backend read
/// covers around a missed chunk group (see [`CacheOptions::fetch_size`]).
/// 2 MiB.
pub const DEFAULT_FETCH_SIZE: u64 = 2 * 1024 * 1024;

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
}

/// Implements the default options: checksums verified, 2 MiB fetches.
impl Default for CacheOptions {
    fn default() -> Self {
        Self {
            skip_verify_checksums: false,
            fetch_size: DEFAULT_FETCH_SIZE,
        }
    }
}

/// Implements the conversion from the `storage` section of a configuration.
impl From<&StorageConfig> for CacheOptions {
    fn from(storage: &StorageConfig) -> Self {
        Self {
            skip_verify_checksums: storage.skip_verify_checksums,
            fetch_size: storage.fetch_size,
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
    fn for_each_ondemand_chunk_group(
        &self,
        _workers: usize,
        _deadline: Option<Instant>,
        _skip: &(dyn Fn(&BlobMetadataChunkGroupExtent) -> bool + Sync),
        _cb: &(dyn Fn(&BlobMetadataChunkGroupExtent, &[u8]) -> io::Result<()> + Sync),
    ) -> io::Result<(u64, u64)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "for_each_ondemand_chunk_group is not supported by this blob cache",
        ))
    }

    /// Write the decoded payload of this blob's chunk group
    /// `chunk_group_index`, obtained from an ondemand blob, into the local
    /// cache and mark the group ready. The payload is validated against this
    /// blob's own metadata first, so a stale or corrupt ondemand copy never
    /// reaches the cache. A no-op when the group is already ready.
    fn fill_chunk_group_from_ondemand(
        &self,
        _chunk_group_index: usize,
        _payload: &[u8],
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fill_chunk_group_from_ondemand is not supported by this blob cache",
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
                .is_none_or(|mapping| mapping.len() < len)
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

    /// The first `len` bytes, where `len` is at most the size given to the
    /// last [`Self::resize`].
    fn bytes(&self, len: usize) -> &[u8] {
        match &self.mapping {
            Some(mapping) => &mapping[..len],
            None => &self.heap[..len],
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
/// `checksum`; any other malformed chunk group, an ondemand source pointing past
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
    use nydus_test_utils::metadata::from_chunk_groups;

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

        // A wrong digest is not checked: the digests name content, the crc
        // guards it.
        let mut digests: Vec<_> = metadata.chunk_group_digests().collect();
        digests[0] = nydus_format::blob::BlobMetadataChunkGroupDigest::new([0; 32]);
        let wrong = BlobMetadata::new(
            4,
            1,
            BlobMetadataCompressor::None,
            Some(BlobMetadataDigester::Blake3),
            vec![
                nydus_format::blob::BlobMetadataChunkGroup::new(
                    0,
                    0,
                    0,
                    data.len() as u32,
                    group.uncompressed_crc32(),
                ),
                nydus_format::blob::BlobMetadataChunkGroup::new(data.len() as u64, 3, 2, 0, 0),
            ],
            vec![
                nydus_format::blob::BlobMetadataChunkLength::new(100),
                nydus_format::blob::BlobMetadataChunkLength::new(5000),
            ],
            digests,
            Vec::new(),
        )
        .unwrap();
        let wrong_group = wrong.chunk_group(0).unwrap();
        validate_decoded_chunk_group(&wrong_group, &data, false).unwrap();

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
}
