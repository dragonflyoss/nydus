//! Nydus-private blob sidecar formats.
//!
//! These are nydus's own on-disk formats layered next to the EROFS data —
//! the `.blob.meta` sidecar ([`metadata`]) and the trailing blob footer
//! ([`footer`]) — not part of the EROFS metadata format itself.

use crate::erofs::bytes_to_blocks;
use crate::error::{Context, Error, Result};
use crate::utils::{align_up_u64, write_zeros};
use std::io::Write;

pub mod algorithm;
pub mod flag;
pub mod footer;
pub mod metadata;
pub use algorithm::{BlobMetadataCompressor, BlobMetadataDigester};
pub use footer::NYDUS_BLOB_FOOTER_ALIGNMENT;
pub use footer::{BlobFooter, NYDUS_BLOB_FOOTER_SIZE};
pub use metadata::{
    BlobMetadata, BlobMetadataBlockGroup, BlobMetadataChunk,
    DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_BLOCK_COUNT,
    DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_SIZE, DEFAULT_NYDUS_BLOB_METADATA_CHUNK_BLOCK_COUNT,
    DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE, NYDUS_BLOB_METADATA_SUFFIX,
};

/// Finish a full blob: append the trailing regions of the layout
/// `[data][pad][bootstrap][pad][blob meta][footer]` to `writer`, which must
/// already hold the `compressed_data_size` bytes of blob data. An empty
/// `bootstrap` yields the ondemand layout (no bootstrap region, zero
/// bootstrap blocks). Returns the footer describing the finished blob.
pub fn finish_full_blob(
    writer: &mut dyn Write,
    compressed_data_size: u64,
    bootstrap: &[u8],
    blob_metadata: &BlobMetadata,
) -> Result<BlobFooter> {
    let bootstrap_size = bootstrap.len() as u64;
    let bootstrap_offset = align_up_u64(compressed_data_size, NYDUS_BLOB_FOOTER_ALIGNMENT)
        .ok_or_else(|| Error::Overflow("bootstrap offset overflow".to_string()))?;
    let blob_metadata_offset = bootstrap_offset
        .checked_add(bootstrap_size)
        .and_then(|bootstrap_end| align_up_u64(bootstrap_end, NYDUS_BLOB_FOOTER_ALIGNMENT))
        .ok_or_else(|| Error::Overflow("blob meta offset overflow".to_string()))?;

    write_zeros(writer, bootstrap_offset - compressed_data_size)?;
    writer
        .write_all(bootstrap)
        .context("failed to write blob bootstrap")?;

    write_zeros(
        writer,
        blob_metadata_offset - bootstrap_offset - bootstrap_size,
    )?;
    blob_metadata
        .write_to(writer)
        .context("failed to write blob meta")?;

    let footer = BlobFooter::new(
        0,
        compressed_data_size,
        bootstrap_offset,
        bytes_to_blocks(bootstrap_size, "bootstrap")?,
        blob_metadata_offset,
        bytes_to_blocks(blob_metadata.padded_size(), "blob meta")?,
    )?;
    footer
        .write_to(writer)
        .context("failed to write blob footer")?;

    Ok(footer)
}
