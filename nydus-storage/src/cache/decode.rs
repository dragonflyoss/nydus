//! The decoding of one chunk group out of a fetched window: the buffers a
//! fetch fills, the decode and the verification against the blob meta, and
//! the attribution of a failed cache write.

use std::fmt;
use std::io;

use nydus_format::blob::{BlobMetadata, BlobMetadataChunkGroupExtent};
use nydus_telemetry::metrics::WriteFailureReason;

/// The fetch buffers of one job: the encoded bytes of a window and the
/// decode scratch, released with the job so the large mappings go back to
/// the kernel.
#[derive(Default)]
pub(crate) struct ChunkGroupBuffers {
    /// The encoded bytes of the fetched window.
    encoded: ChunkGroupBuffer,

    /// The decode scratch, the size of the largest chunk group.
    decoded: ChunkGroupBuffer,
}

/// Implements the fetch buffers.
impl ChunkGroupBuffers {
    /// Returns both buffers sized to `encoded_len` and `decoded_len`,
    /// borrowed together so a caller decodes from one into the other.
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

/// A transient buffer that bypasses the heap arenas for large sizes, as an
/// anonymous mapping advised onto huge pages on Linux.
#[derive(Default)]
pub(crate) struct ChunkGroupBuffer {
    /// The heap buffer of a small size.
    heap: Vec<u8>,

    /// The anonymous mapping of a large size.
    mapping: Option<memmap2::MmapMut>,
}

/// Implements the chunk group buffer.
impl ChunkGroupBuffer {
    /// The size from which the buffer is an anonymous mapping rather than a
    /// heap allocation.
    const MAPPING_MIN_SIZE: usize = 1024 * 1024;

    /// The size from which the mapping is advised onto huge pages.
    const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

    /// Returns the buffer resized to `len`, a mapping reused when it is
    /// large enough.
    pub(crate) fn resize(&mut self, len: usize) -> io::Result<&mut [u8]> {
        if len < Self::MAPPING_MIN_SIZE {
            self.mapping = None;
            self.heap.resize(len, 0);
            return Ok(&mut self.heap);
        }

        if self
            .mapping
            .as_ref()
            .is_none_or(|mapping| mapping.len() < len)
        {
            let mapping = memmap2::MmapMut::map_anon(len)?;
            #[cfg(target_os = "linux")]
            if len >= Self::HUGE_PAGE_SIZE {
                if let Err(err) = mapping.advise(memmap2::Advice::HugePage) {
                    tracing::debug!("failed to advise huge pages for a fetch buffer: {}", err);
                }
            }
            self.mapping = Some(mapping);
        }

        self.heap = Vec::new();
        Ok(&mut self.mapping.as_mut().expect("mapping allocated above")[..len])
    }

    /// Returns the first `len` bytes, `len` at most the size of the last
    /// [`resize`](Self::resize).
    pub(crate) fn bytes(&self, len: usize) -> &[u8] {
        match &self.mapping {
            Some(mapping) => &mapping[..len],
            None => &self.heap[..len],
        }
    }
}

/// Decodes and verifies `group` out of `window`, the compressed bytes of
/// the blob's data region starting at `window_offset`. A stored-plain chunk
/// group borrows the window, a compressed one decodes into the head of
/// `decoded`, a scratch at least the chunk group's uncompressed size. The
/// returned slice holds the verified payload, its crc32c check skipped when
/// `skip_verify_checksums`.
pub fn decode_chunk_group<'a>(
    blob_metadata: &BlobMetadata,
    group: &BlobMetadataChunkGroupExtent,
    window_offset: u64,
    window: &'a [u8],
    decoded: &'a mut [u8],
    skip_verify_checksums: bool,
) -> io::Result<&'a [u8]> {
    let start = group
        .compressed_offset()
        .checked_sub(window_offset)
        .and_then(|start| usize::try_from(start).ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "blob meta chunk group offset outside the fetched window",
            )
        })?;
    let encoded = window
        .get(start..start + group.compressed_size() as usize)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "blob meta chunk group range outside the fetched window",
            )
        })?;

    let payload: &[u8] = if group.is_uncompressed(blob_metadata) {
        encoded
    } else {
        let decoded = decoded
            .get_mut(..group.uncompressed_size() as usize)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "decode scratch smaller than the chunk group",
                )
            })?;
        blob_metadata
            .compressor()
            .decompress_into(encoded, decoded)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        decoded
    };

    verify_chunk_group(group, payload, skip_verify_checksums)?;
    Ok(payload)
}

/// Verifies `payload`, the uncompressed bytes of `group`: its length against
/// the blob meta and, unless `skip_verify_checksums`, its crc32c against the
/// chunk group entry. The blob meta's chunk group digests are content
/// identities, not checked here.
pub(crate) fn verify_chunk_group(
    group: &BlobMetadataChunkGroupExtent,
    payload: &[u8],
    skip_verify_checksums: bool,
) -> io::Result<()> {
    if payload.len() != group.uncompressed_size() as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "blob meta chunk group {} length mismatch: expected {}, got {}",
                group.index(),
                group.uncompressed_size(),
                payload.len()
            ),
        ));
    }

    if skip_verify_checksums {
        return Ok(());
    }

    group
        .verify_crc32(payload)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, ChunkGroupCrcMismatch(err)))
}

/// The error wrapped in an [`io::Error`] when a chunk group fails its crc32c
/// check, so a cache write failure is attributed to the checksum through
/// [`is_chunk_group_crc_mismatch`].
#[derive(Debug)]
struct ChunkGroupCrcMismatch(nydus_format::Error);

/// Implements the display of the crc32c mismatch, the blob meta's message.
impl fmt::Display for ChunkGroupCrcMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Implements the crc32c mismatch as an error.
impl std::error::Error for ChunkGroupCrcMismatch {}

/// Returns whether `err` is a chunk group crc32c mismatch.
pub(crate) fn is_chunk_group_crc_mismatch(err: &io::Error) -> bool {
    err.get_ref()
        .is_some_and(|inner| inner.is::<ChunkGroupCrcMismatch>())
}

/// Returns the `reason` a cache write failed with `err`: a crc32c mismatch
/// is `checksum`; any other malformed chunk group, a redirect pointing past
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
    use nydus_format::blob::{
        BlobMetadataChunkGroup, BlobMetadataChunkGroupDigest, BlobMetadataChunkLength,
        BlobMetadataCompressor, BlobMetadataDigester,
    };
    use nydus_format::erofs::EROFS_BLOCK_SIZE;
    use nydus_test_utils::metadata::from_chunk_groups;

    #[test]
    fn chunk_group_buffer_reuses_and_releases_large_mappings() {
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
    fn chunk_group_buffer_preserves_contents_around_the_huge_page_size() {
        let test_cases = vec![
            2 * 1024 * 1024 - 1,
            2 * 1024 * 1024,
            2 * 1024 * 1024 + 1,
            4 * 1024 * 1024,
        ];

        let mut buffer = ChunkGroupBuffer::default();
        for len in test_cases {
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
    fn decode_chunk_group_borrows_plain_payloads_and_checks_the_window() {
        let payload = vec![0x5a; 4096];
        let test_cases = vec![
            BlobMetadataCompressor::None,
            BlobMetadataCompressor::Zstd,
            BlobMetadataCompressor::Lz4Block,
        ];

        for compressor in test_cases {
            let (data, blob_metadata) =
                from_chunk_groups(compressor, 4096, &[vec![payload.clone()]], None);
            let group = blob_metadata.chunk_group(0).unwrap();
            let mut window = vec![0; 37];
            window.extend_from_slice(&data);
            let mut scratch = vec![0u8; 4096];
            let result = decode_chunk_group(
                &blob_metadata,
                &group,
                0,
                &window[37..],
                &mut scratch,
                false,
            )
            .unwrap();
            assert_eq!(result, payload);
            if group.is_uncompressed(&blob_metadata) {
                assert_eq!(compressor, BlobMetadataCompressor::None);
                assert_eq!(result.as_ptr(), window[37..].as_ptr());
            } else {
                assert_eq!(result.as_ptr(), scratch.as_ptr());
            }
            assert!(decode_chunk_group(
                &blob_metadata,
                &group,
                0,
                &data[..data.len() - 1],
                &mut scratch,
                false,
            )
            .is_err());
            assert!(
                decode_chunk_group(&blob_metadata, &group, 1, &data, &mut scratch, false).is_err()
            );
            assert_eq!(
                decode_chunk_group(&blob_metadata, &group, 0, &data, &mut scratch[..1], false)
                    .is_err(),
                compressor != BlobMetadataCompressor::None
            );
        }
    }

    #[test]
    fn decode_chunk_group_verifies_the_payload_it_borrows() {
        let payload = vec![0u8; EROFS_BLOCK_SIZE as usize];
        let blob_metadata = BlobMetadata::new(
            1,
            1,
            BlobMetadataCompressor::None,
            None,
            vec![
                BlobMetadataChunkGroup::new(0, 0, 0, EROFS_BLOCK_SIZE, 0),
                BlobMetadataChunkGroup::new(u64::from(EROFS_BLOCK_SIZE), 1, 1, 0, 0),
            ],
            vec![BlobMetadataChunkLength::new(EROFS_BLOCK_SIZE)],
            vec![],
            vec![],
        )
        .unwrap();
        let group = blob_metadata.chunk_group(0).unwrap();

        let err = verify_chunk_group(&group, &payload, false).unwrap_err();
        assert!(is_chunk_group_crc_mismatch(&err));
        assert!(
            err.to_string().contains("chunk group 0 crc32 mismatch"),
            "{err}"
        );
        let err =
            decode_chunk_group(&blob_metadata, &group, 0, &payload, &mut [], false).unwrap_err();
        assert!(is_chunk_group_crc_mismatch(&err));
        verify_chunk_group(&group, &payload, true).unwrap();
    }

    #[test]
    fn verify_chunk_group_checks_the_length_and_the_crc_but_not_the_digest() {
        let chunks = vec![vec![1u8; 100], vec![2u8; 5000]];
        let (data, blob_metadata) = from_chunk_groups(
            BlobMetadataCompressor::None,
            16384,
            &[chunks],
            Some(BlobMetadataDigester::Blake3),
        );
        let group = blob_metadata.chunk_group(0).unwrap();
        verify_chunk_group(&group, &data, false).unwrap();

        let mut digests: Vec<_> = blob_metadata.chunk_group_digests().collect();
        digests[0] = BlobMetadataChunkGroupDigest::new([0; 32]);
        let wrong = BlobMetadata::new(
            4,
            1,
            BlobMetadataCompressor::None,
            Some(BlobMetadataDigester::Blake3),
            vec![
                BlobMetadataChunkGroup::new(0, 0, 0, data.len() as u32, group.uncompressed_crc32()),
                BlobMetadataChunkGroup::new(data.len() as u64, 3, 2, 0, 0),
            ],
            vec![
                BlobMetadataChunkLength::new(100),
                BlobMetadataChunkLength::new(5000),
            ],
            digests,
            Vec::new(),
        )
        .unwrap();
        verify_chunk_group(&wrong.chunk_group(0).unwrap(), &data, false).unwrap();

        let mut corrupted = data.clone();
        corrupted[0] ^= 0xff;
        let err = verify_chunk_group(&group, &corrupted, false).unwrap_err();
        assert!(is_chunk_group_crc_mismatch(&err));
        assert!(verify_chunk_group(&group, &data[1..], false).is_err());
    }

    #[test]
    fn write_failure_reason_classifies_the_error() {
        let test_cases = vec![
            (
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    ChunkGroupCrcMismatch(nydus_format::Error::InvalidImage(String::new())),
                ),
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
