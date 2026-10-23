//! The decoder of a blob's chunk groups out of their fetched windows: the
//! decode, the verification against the blob meta, and the attribution of a
//! failed cache write.

use std::fmt;
use std::io;

use nydus_format::blob::{BlobMetadata, BlobMetadataChunkGroupExtent};
use nydus_telemetry::metrics::WriteFailureReason;

/// The decoder of the chunk groups of one blob, following its blob meta's
/// compressor and the `storage.skip_verify_checksums` of the caches.
pub struct ChunkGroupDecoder<'a> {
    /// The blob's metadata: chunk groups, chunks, compressor.
    blob_metadata: &'a BlobMetadata,

    /// Skip the crc32c check of decoded chunk groups.
    skip_verify_checksums: bool,
}

/// Implements the chunk group decoder.
impl<'a> ChunkGroupDecoder<'a> {
    /// Creates the decoder of the blob described by `blob_metadata`,
    /// skipping the crc32c check of its chunk groups when
    /// `skip_verify_checksums`.
    pub fn new(blob_metadata: &'a BlobMetadata, skip_verify_checksums: bool) -> Self {
        Self {
            blob_metadata,
            skip_verify_checksums,
        }
    }

    /// Decodes and verifies `group` out of `window`, the compressed bytes of
    /// the blob's data region starting at `window_offset`. A stored-plain
    /// chunk group borrows the window, a compressed one decodes into the
    /// head of `decoded`, a scratch at least the chunk group's uncompressed
    /// size. The returned slice holds the verified payload.
    pub fn decode<'b>(
        &self,
        group: &BlobMetadataChunkGroupExtent,
        window_offset: u64,
        window: &'b [u8],
        decoded: &'b mut [u8],
    ) -> io::Result<&'b [u8]> {
        if group.is_uncompressed(self.blob_metadata) {
            let payload = self.encoded(group, window_offset, window)?;
            self.verify(group, payload)?;
            return Ok(payload);
        }

        self.decode_into(group, window_offset, window, decoded)?;
        Ok(&decoded[..group.uncompressed_size() as usize])
    }

    /// Decodes and verifies `group` out of `window`, the compressed bytes of
    /// the blob's data region starting at `window_offset`, into the head of
    /// `decoded`, a buffer at least the chunk group's uncompressed size; a
    /// stored-plain chunk group is copied there.
    pub(crate) fn decode_into(
        &self,
        group: &BlobMetadataChunkGroupExtent,
        window_offset: u64,
        window: &[u8],
        decoded: &mut [u8],
    ) -> io::Result<()> {
        let encoded = self.encoded(group, window_offset, window)?;
        let decoded = decoded
            .get_mut(..group.uncompressed_size() as usize)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "decode scratch smaller than the chunk group",
                )
            })?;
        if group.is_uncompressed(self.blob_metadata) {
            self.verify(group, encoded)?;
            decoded.copy_from_slice(encoded);
            return Ok(());
        }

        self.blob_metadata
            .compressor()
            .decompress_into(encoded, decoded)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        self.verify(group, decoded)
    }

    /// Returns the compressed bytes of `group` out of `window`, the bytes of
    /// the blob's data region starting at `window_offset`.
    fn encoded<'b>(
        &self,
        group: &BlobMetadataChunkGroupExtent,
        window_offset: u64,
        window: &'b [u8],
    ) -> io::Result<&'b [u8]> {
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
        window
            .get(start..start + group.compressed_size() as usize)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "blob meta chunk group range outside the fetched window",
                )
            })
    }

    /// Verifies `payload`, the uncompressed bytes of `group`: its length
    /// against the blob meta and, unless the checksums are skipped, its
    /// crc32c against the chunk group entry. The blob meta's chunk group
    /// digests are content identities, not checked here.
    pub(crate) fn verify(
        &self,
        group: &BlobMetadataChunkGroupExtent,
        payload: &[u8],
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

        if self.skip_verify_checksums {
            return Ok(());
        }

        group
            .verify_crc32(payload)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, ChunkGroupCrcMismatch(err)))
    }

    /// Returns the `reason` a cache write failed with `err`: a crc32c
    /// mismatch is `checksum`; any other malformed chunk group, a redirect
    /// pointing past its source blob's chunk groups included, `decode`; and
    /// everything else, the cache file refusing the write, `io`.
    pub(crate) fn write_failure_reason(err: &io::Error) -> WriteFailureReason {
        if err
            .get_ref()
            .is_some_and(|inner| inner.is::<ChunkGroupCrcMismatch>())
        {
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
}

/// The error wrapped in an [`io::Error`] when a chunk group fails its crc32c
/// check, so a cache write failure is attributed to the checksum by
/// [`ChunkGroupDecoder::write_failure_reason`].
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
    fn decode_borrows_plain_payloads_and_checks_the_window() {
        let payload = vec![0x5a; 4096];
        let test_cases = vec![
            BlobMetadataCompressor::None,
            BlobMetadataCompressor::Zstd,
            BlobMetadataCompressor::Lz4Block,
        ];

        for compressor in test_cases {
            let (data, blob_metadata) =
                from_chunk_groups(compressor, 4096, &[vec![payload.clone()]], None);
            let decoder = ChunkGroupDecoder::new(&blob_metadata, false);
            let group = blob_metadata.chunk_group(0).unwrap();
            let mut window = vec![0; 37];
            window.extend_from_slice(&data);
            let mut scratch = vec![0u8; 4096];
            let result = decoder
                .decode(&group, 0, &window[37..], &mut scratch)
                .unwrap();
            assert_eq!(result, payload);
            if group.is_uncompressed(&blob_metadata) {
                assert_eq!(compressor, BlobMetadataCompressor::None);
                assert_eq!(result.as_ptr(), window[37..].as_ptr());
            } else {
                assert_eq!(result.as_ptr(), scratch.as_ptr());
            }
            scratch.fill(0);
            decoder.decode_into(&group, 0, &data, &mut scratch).unwrap();
            assert_eq!(scratch, payload);
            assert!(decoder
                .decode(&group, 0, &data[..data.len() - 1], &mut scratch)
                .is_err());
            assert!(decoder
                .decode_into(&group, 0, &data, &mut scratch[..1])
                .is_err());
            assert!(decoder.decode(&group, 1, &data, &mut scratch).is_err());
            assert_eq!(
                decoder.decode(&group, 0, &data, &mut scratch[..1]).is_err(),
                compressor != BlobMetadataCompressor::None
            );
        }
    }

    #[test]
    fn decode_verifies_the_payload_it_borrows() {
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
        let decoder = ChunkGroupDecoder::new(&blob_metadata, false);

        let err = decoder.verify(&group, &payload).unwrap_err();
        assert_eq!(
            ChunkGroupDecoder::write_failure_reason(&err),
            WriteFailureReason::Checksum
        );
        assert!(
            err.to_string().contains("chunk group 0 crc32 mismatch"),
            "{err}"
        );
        let err = decoder.decode(&group, 0, &payload, &mut []).unwrap_err();
        assert_eq!(
            ChunkGroupDecoder::write_failure_reason(&err),
            WriteFailureReason::Checksum
        );
        ChunkGroupDecoder::new(&blob_metadata, true)
            .verify(&group, &payload)
            .unwrap();
    }

    #[test]
    fn verify_checks_the_length_and_the_crc_but_not_the_digest() {
        let chunks = vec![vec![1u8; 100], vec![2u8; 5000]];
        let (data, blob_metadata) = from_chunk_groups(
            BlobMetadataCompressor::None,
            16384,
            &[chunks],
            Some(BlobMetadataDigester::Blake3),
        );
        let decoder = ChunkGroupDecoder::new(&blob_metadata, false);
        let group = blob_metadata.chunk_group(0).unwrap();
        decoder.verify(&group, &data).unwrap();

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
        ChunkGroupDecoder::new(&wrong, false)
            .verify(&wrong.chunk_group(0).unwrap(), &data)
            .unwrap();

        let mut corrupted = data.clone();
        corrupted[0] ^= 0xff;
        let err = decoder.verify(&group, &corrupted).unwrap_err();
        assert_eq!(
            ChunkGroupDecoder::write_failure_reason(&err),
            WriteFailureReason::Checksum
        );
        assert!(decoder.verify(&group, &data[1..]).is_err());
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
            assert_eq!(
                ChunkGroupDecoder::write_failure_reason(&err),
                expected,
                "{err}"
            );
        }
    }
}
