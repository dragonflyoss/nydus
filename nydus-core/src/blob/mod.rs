//! Nydus-private blob sidecar formats.
//!
//! These are nydus's own on-disk formats layered next to the EROFS data —
//! the `.blob.meta` sidecar ([`metadata`]) and the trailing blob footer
//! ([`footer`]) — not part of the EROFS metadata format itself.

pub mod footer;
pub(crate) mod format;
pub mod metadata;

pub(crate) use footer::NYDUS_BLOB_FOOTER_ALIGNMENT;
pub use footer::{BlobFooter, NYDUS_BLOB_FOOTER_SIZE};
pub use metadata::{
    BlobMeta, BlobMetaChunk, BlobMetaCompressor, BlobMetaDigester, BlobMetaGroup,
    BLOB_META_DEFAULT_CHUNK_BLOCK_COUNT, BLOB_META_DEFAULT_CHUNK_SIZE, BLOB_META_SUFFIX,
};

use std::io::Write;

use anyhow::{bail, Context, Result};

use crate::metadata::bytes_to_blocks;
use crate::utils::{align_up, write_zero_padding};

/// Append the trailing regions of the full-blob layout
/// `[data][pad][bootstrap][pad][blob meta][footer]` to `writer`, which must
/// already hold the `data_size` bytes of blob data. An empty `bootstrap`
/// yields the ondemand layout (no bootstrap region, zero bootstrap blocks).
/// Returns the footer describing the assembled blob.
pub fn assemble_full_blob(
    writer: &mut dyn Write,
    data_size: u64,
    bootstrap: &[u8],
    blob_meta: &BlobMeta,
) -> Result<BlobFooter> {
    let bootstrap_size = u64::try_from(bootstrap.len()).context("bootstrap exceeds u64")?;
    let bootstrap_blocks = bytes_to_blocks(bootstrap_size, "bootstrap")?;
    let bootstrap_offset =
        align_up(data_size, NYDUS_BLOB_FOOTER_ALIGNMENT).context("bootstrap offset overflow")?;
    let blob_meta_offset = align_up(
        bootstrap_offset
            .checked_add(bootstrap_size)
            .context("blob meta offset overflow")?,
        NYDUS_BLOB_FOOTER_ALIGNMENT,
    )
    .context("blob meta offset overflow")?;
    let blob_meta_size = blob_meta.metadata_size();
    let blob_meta_blocks = bytes_to_blocks(blob_meta_size, "blob meta")?;

    let mut blob_meta_bytes = Vec::with_capacity(
        usize::try_from(blob_meta_size).context("blob meta size exceeds usize")?,
    );
    blob_meta
        .write_to(&mut blob_meta_bytes)
        .context("failed to serialize blob meta")?;
    if blob_meta_bytes.len() as u64 != blob_meta_size {
        bail!(
            "serialized blob meta size mismatch: expected {}, got {}",
            blob_meta_size,
            blob_meta_bytes.len()
        );
    }

    let footer = BlobFooter::new(
        0,
        data_size,
        bootstrap_offset,
        bootstrap_blocks,
        blob_meta_offset,
        blob_meta_blocks,
    )?;

    write_zero_padding(writer, data_size, bootstrap_offset)?;
    writer
        .write_all(bootstrap)
        .context("failed to write blob bootstrap")?;
    write_zero_padding(writer, bootstrap_offset + bootstrap_size, blob_meta_offset)?;
    writer
        .write_all(&blob_meta_bytes)
        .context("failed to write blob meta")?;
    footer
        .write_to(writer)
        .context("failed to write blob footer")?;
    Ok(footer)
}
