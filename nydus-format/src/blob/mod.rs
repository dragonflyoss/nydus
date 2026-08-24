//! Nydus-private blob sidecar formats.
//!
//! These are nydus's own on-disk formats layered next to the EROFS data —
//! the `.blob.meta` sidecar ([`metadata`]) and the trailing blob footer
//! ([`footer`]) — not part of the EROFS metadata format itself.

use crate::erofs::bytes_to_blocks;
use crate::error::{Context, Error, Result};
use crate::utils::{align_up, write_zero_padding};
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

/// Append the trailing regions of the full-blob layout
/// `[data][pad][bootstrap][pad][blob meta][footer]` to `writer`, which must
/// already hold the `data_size` bytes of blob data. An empty `bootstrap`
/// yields the ondemand layout (no bootstrap region, zero bootstrap blocks).
/// Returns the footer describing the assembled blob.
pub fn assemble_full_blob(
    writer: &mut dyn Write,
    data_size: u64,
    bootstrap: &[u8],
    blob_metadata: &BlobMetadata,
) -> Result<BlobFooter> {
    let bootstrap_size = u64::try_from(bootstrap.len())
        .map_err(|err| Error::Overflow(format!("bootstrap exceeds u64: {err}")))?;
    let bootstrap_blocks = bytes_to_blocks(bootstrap_size, "bootstrap")?;
    let bootstrap_offset = align_up(data_size, NYDUS_BLOB_FOOTER_ALIGNMENT)
        .ok_or_else(|| Error::Overflow("bootstrap offset overflow".to_string()))?;
    let blob_metadata_offset = align_up(
        bootstrap_offset
            .checked_add(bootstrap_size)
            .ok_or_else(|| Error::Overflow("blob meta offset overflow".to_string()))?,
        NYDUS_BLOB_FOOTER_ALIGNMENT,
    )
    .ok_or_else(|| Error::Overflow("blob meta offset overflow".to_string()))?;
    let blob_metadata_size = blob_metadata.padded_size();
    let blob_metadata_blocks = bytes_to_blocks(blob_metadata_size, "blob meta")?;

    let mut blob_metadata_bytes = Vec::with_capacity(
        usize::try_from(blob_metadata_size)
            .map_err(|err| Error::Overflow(format!("blob meta size exceeds usize: {err}")))?,
    );
    blob_metadata
        .write_to(&mut blob_metadata_bytes)
        .context("failed to serialize blob meta")?;
    if blob_metadata_bytes.len() as u64 != blob_metadata_size {
        return Err(Error::InvalidImage(format!(
            "serialized blob meta size mismatch: expected {}, got {}",
            blob_metadata_size,
            blob_metadata_bytes.len()
        )));
    }

    let footer = BlobFooter::new(
        0,
        data_size,
        bootstrap_offset,
        bootstrap_blocks,
        blob_metadata_offset,
        blob_metadata_blocks,
    )?;

    write_zero_padding(writer, data_size, bootstrap_offset)?;
    writer
        .write_all(bootstrap)
        .context("failed to write blob bootstrap")?;
    write_zero_padding(
        writer,
        bootstrap_offset + bootstrap_size,
        blob_metadata_offset,
    )?;
    writer
        .write_all(&blob_metadata_bytes)
        .context("failed to write blob meta")?;
    footer
        .write_to(writer)
        .context("failed to write blob footer")?;
    Ok(footer)
}
