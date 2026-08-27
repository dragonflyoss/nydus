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
pub use algorithm::BlobMetadataCompressor;
pub use footer::NYDUS_BLOB_FOOTER_ALIGNMENT;
pub use footer::{BlobFooter, NYDUS_BLOB_FOOTER_SIZE};
pub use metadata::{
    BlobMetadata, BlobMetadataBlockGroup, BlobMetadataChunk,
    DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_BLOCK_COUNT,
    DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_SIZE, DEFAULT_NYDUS_BLOB_METADATA_CHUNK_BLOCK_COUNT,
    DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE, NYDUS_BLOB_METADATA_SUFFIX,
};

/// Finish a full blob: append everything behind the data region to `writer`,
/// which must already hold the `compressed_data_size` bytes of blob data.
/// Returns the sealed footer describing the finished blob.
///
/// The finished blob, every region offset 4 KiB aligned:
///
/// ```text
/// ┌─────────────────┬───┬───────────────────────┬──────────────────┬────────┐
/// │ compressed data │pad│ bootstrap             │ blob meta        │ footer │
/// └─────────────────┴───┴───────────────────────┴──────────────────┴────────┘
/// 0                     bootstrap_offset        blob_metadata_offset      EOF
///
/// compressed data  the block group payloads, packed back to back and
///                  byte-exact (compressed_data_size bytes), mapped by the
///                  blob meta block group table
/// pad              zeros up to the 4 KiB aligned bootstrap_offset
/// bootstrap        one zstd frame of the metadata-only EROFS image
///                  (bootstrap_compressed_size bytes), zero tail up to
///                  bootstrap_blocks × 4 KiB, absent for an ondemand blob
/// blob meta        the LPBLMETA bytes (header, chunk table, block group
///                  table), already block-padded, ending exactly at the
///                  footer offset
/// footer           the sealed LPFOOTER block, fixed 4 KiB at the tail
/// ```
///
/// An empty `bootstrap` yields the ondemand layout (no bootstrap region,
/// zero bootstrap blocks).
pub fn finish_full_blob(
    writer: &mut dyn Write,
    compressed_data_size: u64,
    bootstrap: &[u8],
    blob_metadata: &BlobMetadata,
) -> Result<BlobFooter> {
    let compressed_bootstrap = compress_bootstrap(bootstrap)?;
    let blob_footer = new_blob_footer(compressed_data_size, &compressed_bootstrap, blob_metadata)?;
    write_blob_tail(writer, &blob_footer, &compressed_bootstrap, blob_metadata)?;
    Ok(blob_footer)
}

/// Compress the embedded bootstrap. An empty bootstrap (the ondemand layout)
/// stores no bytes at all, since even an empty zstd frame would occupy a
/// whole block-aligned region.
fn compress_bootstrap(bootstrap: &[u8]) -> Result<Vec<u8>> {
    if bootstrap.is_empty() {
        return Ok(Vec::new());
    }

    zstd::stream::encode_all(bootstrap, zstd::DEFAULT_COMPRESSION_LEVEL)
        .context("failed to compress bootstrap")
}

/// Lay the trailing regions out behind the data region, each 4 KiB aligned,
/// and seal the footer describing them. Construction validates the layout,
/// so the sealed footer is the single source of truth the write pass
/// follows.
fn new_blob_footer(
    compressed_data_size: u64,
    compressed_bootstrap: &[u8],
    blob_metadata: &BlobMetadata,
) -> Result<BlobFooter> {
    let bootstrap_compressed_size = compressed_bootstrap.len() as u64;
    let bootstrap_size = align_up_u64(bootstrap_compressed_size, NYDUS_BLOB_FOOTER_ALIGNMENT)
        .ok_or_else(|| Error::Overflow("bootstrap region overflow".to_string()))?;
    let bootstrap_offset = align_up_u64(compressed_data_size, NYDUS_BLOB_FOOTER_ALIGNMENT)
        .ok_or_else(|| Error::Overflow("bootstrap offset overflow".to_string()))?;
    let blob_metadata_offset = bootstrap_offset
        .checked_add(bootstrap_size)
        .ok_or_else(|| Error::Overflow("blob meta offset overflow".to_string()))?;

    BlobFooter::new(
        0,
        compressed_data_size,
        bootstrap_offset,
        bytes_to_blocks(bootstrap_size)?,
        blob_metadata_offset,
        bytes_to_blocks(blob_metadata.padded_size())?,
        (!compressed_bootstrap.is_empty()).then_some(bootstrap_compressed_size),
    )
}

/// Stream everything behind the data region in offset order — bootstrap,
/// blob meta, then the footer itself — zero-padding the alignment gaps the
/// footer declares.
fn write_blob_tail(
    writer: &mut dyn Write,
    footer: &BlobFooter,
    compressed_bootstrap: &[u8],
    blob_metadata: &BlobMetadata,
) -> Result<()> {
    write_zeros(
        writer,
        footer.bootstrap_offset() - footer.compressed_data_size(),
    )?;
    writer
        .write_all(compressed_bootstrap)
        .context("failed to write blob bootstrap")?;

    let bootstrap_end = footer.bootstrap_offset() + compressed_bootstrap.len() as u64;
    write_zeros(writer, footer.blob_metadata_offset() - bootstrap_end)?;
    blob_metadata
        .write_to(writer)
        .context("failed to write blob meta")?;

    footer
        .write_to(writer)
        .context("failed to write blob footer")
}
