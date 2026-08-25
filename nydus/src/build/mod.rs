//! Building nydus images: chunking and compressing file data into blobs
//! ([`blob_chunk`]), constructing the inode tree ([`inode`], [`dir`]), and
//! rendering EROFS bootstraps ([`bootstrap`], [`image`]).
//!
//! [`build_image`] is the high-level entry point that converts a
//! directory tree into a nydus full blob.

pub mod blob_chunk;
pub mod bootstrap;
pub mod dir;
pub mod image;
pub mod inode;
pub mod layout;
pub mod merge;

use std::collections::HashSet;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use blob_chunk::BlobWriter;
use bootstrap::{render_bootstrap, render_flattened_bootstrap};
use inode::{build_tree, set_root_prefetch_blobs_xattr};
use nydus_error::{Context, Error, Result};
use nydus_format::blob::{
    BlobFooter, BlobMetadata, BlobMetadataCompressor, NYDUS_BLOB_FOOTER_SIZE,
};
use nydus_format::erofs::{ErofsDeviceSlot, EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE};
use nydus_format::utils::sha256_bytes;

/// The minimum block group uncompressed size.
pub const MIN_BLOCK_GROUP_SIZE: u32 = 1024 * 1024;

/// Options for [`build_image`].
#[derive(Debug)]
pub struct BuildImageOptions {
    /// Source directory to convert. Should be canonicalized so entries match
    /// against `exclude`.
    source: PathBuf,
    /// File chunk size in bytes (a power of two, >= the block size, and
    /// block-aligned).
    chunk_size: u32,
    /// Block group uncompressed size in bytes (a power of two, >= 1MiB, and >= the
    /// chunk size): the unit of compression and of a single backend read.
    block_group_size: u32,
    /// Algorithm to compress data chunks.
    compressor: BlobMetadataCompressor,
    /// Canonicalized paths inside `source` to omit from the image.
    excludes: HashSet<PathBuf>,
    /// Also render the standalone bootstrap — its device slot references the
    /// full blob digest — for the caller to persist.
    render_standalone_bootstrap: bool,
}

/// The built image as the caller sees it: the digests, blob meta and footer
/// of the full blob whose bytes went into the writer.
pub struct Image {
    /// SHA256 of the compressed data region (the data blob digest).
    pub data_blob_digest: [u8; EROFS_BLOB_ID_SIZE],
    /// SHA256 of the whole full blob file.
    pub full_blob_digest: [u8; EROFS_BLOB_ID_SIZE],
    pub blob_metadata: BlobMetadata,
    pub blob_footer: BlobFooter,
    /// Rendered when requested, for the caller to persist.
    pub standalone_bootstrap: Option<Vec<u8>>,
}

/// Implement BuildImageOptions.
impl BuildImageOptions {
    /// Creates validated build options: the chunk/block-group geometry is
    /// checked here, so a constructed `BuildImageOptions` is valid by definition
    /// and callers fail fast before creating output files.
    pub fn new(
        source: PathBuf,
        chunk_size: u32,
        block_group_size: u32,
        compressor: BlobMetadataCompressor,
        excludes: HashSet<PathBuf>,
        render_standalone_bootstrap: bool,
    ) -> Result<Self> {
        // Validate EROFS file chunk size. BlobMetadata block groups are formed
        // separately and are at least 1MiB even when file chunk indexes are
        // smaller.
        if chunk_size < EROFS_BLOCK_SIZE {
            return Err(Error::InvalidParameter(format!(
                "chunk size {chunk_size} must be >= block size {EROFS_BLOCK_SIZE}"
            )));
        }

        if !chunk_size.is_power_of_two() {
            return Err(Error::InvalidParameter(format!(
                "chunk size {chunk_size} must be a power of two"
            )));
        }

        if chunk_size % EROFS_BLOCK_SIZE != 0 {
            return Err(Error::InvalidParameter(format!(
                "chunk size {chunk_size} must be block aligned"
            )));
        }

        // Validate the block group uncompressed size: a power of two (the
        // blob meta header stores its block count as the log2 exponent
        // `block_group_block_count_bits`), at least 1MiB, and at least the
        // file chunk size so a chunk always fits in a block group.
        if !block_group_size.is_power_of_two() || block_group_size < MIN_BLOCK_GROUP_SIZE {
            return Err(Error::InvalidParameter(format!(
                "block group size {block_group_size} must be a power of two and at least 1MiB"
            )));
        }

        if block_group_size < chunk_size {
            return Err(Error::InvalidParameter(format!(
                "block group size {block_group_size} must be >= chunk size {chunk_size}"
            )));
        }

        Ok(Self {
            source,
            chunk_size,
            block_group_size,
            compressor,
            excludes,
            render_standalone_bootstrap,
        })
    }
}

/// Builds the nydus image described by `options`, streaming the full blob
/// (`[compressed data][bootstrap][blob meta][footer]`) into `writer` strictly
/// in order, and returns the built [`Image`].
pub fn build_image(options: &BuildImageOptions, writer: impl Write) -> Result<Image> {
    let mut blob_writer = BlobWriter::from_writer(
        writer,
        options.chunk_size,
        options.block_group_size,
        options.compressor,
    )?;
    let mut inodes = build_tree(
        &options.source,
        &mut blob_writer,
        options.chunk_size,
        &options.excludes,
    )?;
    blob_writer.finish()?;
    // The root's mtime is dropped to keep builds reproducible, so it would drag
    // the epoch to zero and cost every compact inode the range above 2106. A
    // tree with nothing but a root has no timestamp to anchor to, and reading
    // the clock there would make the image differ on every build.
    let epoch = inodes
        .iter()
        .skip(1)
        .map(|inode| inode.mtime)
        .min()
        .unwrap_or(0);

    let uuid_bytes = [0u8; 16];
    let blob_blocks = blob_writer.total_blocks();
    let blob_id = blob_writer.data_digest();
    let device_slots = [ErofsDeviceSlot::with_blob_id(blob_blocks, &blob_id)];
    set_root_prefetch_blobs_xattr(&mut inodes[0], &[1])?;
    let bootstrap_bytes = render_bootstrap(&mut inodes, epoch, &device_slots, &uuid_bytes)?;

    let compressed_data_size = blob_writer.data_size();
    let blob_metadata = blob_writer.blob_metadata(0)?;
    let (writer, full_blob_hasher) = blob_writer.into_parts();
    let mut blob_writer_stream = HashingWriter::new(BufWriter::new(writer), full_blob_hasher);

    let footer = nydus_format::blob::finish_full_blob(
        &mut blob_writer_stream,
        compressed_data_size,
        &bootstrap_bytes,
        &blob_metadata,
    )?;
    let full_blob_digest = blob_writer_stream
        .finish()
        .context("failed to flush blob")?;

    let standalone_bootstrap = if options.render_standalone_bootstrap {
        let standalone_device_slots = [ErofsDeviceSlot::with_blob_id(
            blob_blocks,
            &full_blob_digest,
        )];
        Some(render_flattened_bootstrap(
            &mut inodes,
            epoch,
            &standalone_device_slots,
            &uuid_bytes,
        )?)
    } else {
        None
    };

    Ok(Image {
        data_blob_digest: blob_id,
        full_blob_digest,
        blob_metadata,
        blob_footer: footer,
        standalone_bootstrap,
    })
}

/// Assemble an ondemand artifact `[block_group data][blob.meta][footer]` (no
/// embedded bootstrap) and return its bytes, full SHA256 digest, and footer.
pub(crate) fn assemble_ondemand_artifact(
    data: &[u8],
    blob_metadata: &BlobMetadata,
) -> Result<(Vec<u8>, [u8; EROFS_BLOB_ID_SIZE], BlobFooter)> {
    let mut artifact = Vec::with_capacity(
        usize::try_from(data.len() as u64 + blob_metadata.padded_size())
            .map_err(|err| Error::Overflow(format!("artifact exceeds usize: {err}")))?
            + NYDUS_BLOB_FOOTER_SIZE,
    );
    artifact.extend_from_slice(data);
    let footer =
        nydus_format::blob::finish_full_blob(&mut artifact, data.len() as u64, &[], blob_metadata)?;

    let digest = sha256_bytes(&artifact);
    Ok((artifact, digest, footer))
}

/// A writer that hashes every byte it forwards to the inner writer.
struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
}

impl<W: Write> HashingWriter<W> {
    fn new(inner: W, hasher: Sha256) -> Self {
        Self { inner, hasher }
    }

    fn finish(mut self) -> io::Result<[u8; EROFS_BLOB_ID_SIZE]> {
        self.inner.flush()?;
        let mut digest = [0u8; EROFS_BLOB_ID_SIZE];
        digest.copy_from_slice(&self.hasher.finalize());
        Ok(digest)
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.hasher.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_image_options_rejects_invalid_geometry() {
        let new = |chunk_size: u32, block_group_size: u32| {
            BuildImageOptions::new(
                PathBuf::from("/tmp/source"),
                chunk_size,
                block_group_size,
                BlobMetadataCompressor::None,
                HashSet::new(),
                false,
            )
        };

        assert!(new(EROFS_BLOCK_SIZE / 2, MIN_BLOCK_GROUP_SIZE).is_err());
        assert!(new(EROFS_BLOCK_SIZE * 3, MIN_BLOCK_GROUP_SIZE).is_err());
        assert!(new(EROFS_BLOCK_SIZE, MIN_BLOCK_GROUP_SIZE / 2).is_err());
        assert!(new(MIN_BLOCK_GROUP_SIZE * 2, MIN_BLOCK_GROUP_SIZE).is_err());
        assert!(new(EROFS_BLOCK_SIZE, MIN_BLOCK_GROUP_SIZE).is_ok());
    }
}
