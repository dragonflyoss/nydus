//! Nydus-private blob sidecar formats.
//!
//! These are nydus's own on-disk formats layered next to the EROFS data —
//! the `.blob.meta` sidecar ([`metadata`]) and the trailing blob footer
//! ([`footer`]) — not part of the EROFS metadata format itself.

use crate::erofs::EROFS_BLOCK_SIZE;
use crate::error::{Error, Result};
use crate::utils::{align_up_u64, write_zeros};
use std::io::Write;

pub mod algorithm;
pub mod flag;
pub mod footer;
pub mod metadata;
pub use algorithm::{BlobMetadataCompressor, BlobMetadataDigester};
pub use footer::BlobFooter;
pub use metadata::{
    BlobMetadata, BlobMetadataChunkGroup, BlobMetadataChunkGroupDigest,
    BlobMetadataChunkGroupExtent, BlobMetadataChunkGroupIndex, BlobMetadataChunkGroupRedirect,
    BlobMetadataChunkLength, BlobMetadataHeader, BlobMetadataTable, BlobMetadataTableType,
};

/// Finish a full blob by appending everything behind the data region to
/// `writer`, which already holds the `compressed_data_size` bytes of blob
/// data, and return the sealed footer describing the finished blob.
///
/// ```text
/// ┌─────────────────┬─────┬────────────────────┬────────────────────────┬────────┐
/// │ compressed data │ pad │     bootstrap      │       blob meta        │ footer │
/// └─────────────────┴─────┴────────────────────┴────────────────────────┴────────┘
/// 0                       bootstrap_offset     blob_metadata_offset     footer offset
///
/// compressed data  the chunk group payloads back to back, compressed_data_size
///                  bytes, mapped by the blob meta ChunkGroupTable
/// pad              zeros up to the 4 KiB aligned bootstrap_offset
/// bootstrap        one zstd frame of the metadata-only EROFS image,
///                  bootstrap_compressed_size bytes, zero padded to
///                  bootstrap_size, absent for an ondemand blob
/// blob meta        the NDBLMETA file, a whole number of blocks ending at
///                  the footer offset, absent for a raw device blob
/// footer           the sealed NDFOOTER block, 4 KiB at the tail
/// ```
///
/// `bootstrap` of `None` yields the ondemand layout without a bootstrap
/// region. `blob_metadata` of `None` yields the raw device layout of native
/// `erofs-*` layers, with no blob meta region, the footer's RAW_DEVICE
/// flag set, and a bootstrap required.
pub fn finish_full_blob(
    writer: &mut dyn Write,
    compressed_data_size: u64,
    bootstrap: Option<&[u8]>,
    blob_metadata: Option<&BlobMetadata>,
) -> Result<BlobFooter> {
    let compressed_bootstrap = bootstrap
        .map(|bootstrap| zstd::stream::encode_all(bootstrap, zstd::DEFAULT_COMPRESSION_LEVEL))
        .transpose()?;

    let bootstrap_offset = align_up_u64(compressed_data_size, EROFS_BLOCK_SIZE as u64)
        .ok_or_else(|| Error::Overflow("bootstrap offset overflow".to_string()))?;
    let (bootstrap_size, bootstrap_crc32) = match &compressed_bootstrap {
        None => (0, 0),
        Some(compressed_bootstrap) => {
            let bootstrap_size =
                align_up_u64(compressed_bootstrap.len() as u64, EROFS_BLOCK_SIZE as u64)
                    .ok_or_else(|| Error::Overflow("bootstrap region overflow".to_string()))?;
            let padding = (bootstrap_size - compressed_bootstrap.len() as u64) as usize;
            let bootstrap_crc32 = crc32c::crc32c_append(
                crc32c::crc32c(compressed_bootstrap),
                &[0u8; EROFS_BLOCK_SIZE as usize][..padding],
            );
            (bootstrap_size, bootstrap_crc32)
        }
    };

    write_zeros(writer, bootstrap_offset - compressed_data_size)?;
    if let Some(compressed_bootstrap) = &compressed_bootstrap {
        writer.write_all(compressed_bootstrap)?;
        write_zeros(writer, bootstrap_size - compressed_bootstrap.len() as u64)?;
    }

    if let Some(blob_metadata) = blob_metadata {
        blob_metadata.write_to(writer)?;
    }

    let blob_metadata_offset = bootstrap_offset
        .checked_add(bootstrap_size)
        .ok_or_else(|| Error::Overflow("blob meta offset overflow".to_string()))?;

    let footer = BlobFooter::new(
        0,
        compressed_data_size,
        bootstrap_offset,
        bootstrap_size,
        bootstrap_crc32,
        blob_metadata_offset,
        blob_metadata.map_or(0, BlobMetadata::size),
        compressed_bootstrap
            .as_ref()
            .map(|compressed_bootstrap| compressed_bootstrap.len() as u64),
    )?;

    footer.write_to(writer)?;
    Ok(footer)
}
