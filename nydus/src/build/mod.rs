//! Building nydus images: chunking and compressing file data into blobs,
//! constructing the inode tree, and rendering EROFS bootstraps.
//!
//! [`build_image`] is the high-level entry point that converts a directory tree
//! into a nydus full blob. Low-level chunk, inode and bootstrap helpers live in
//! `nydus-core`; this crate keeps the historical CLI build entry points and
//! CLI-only merge helpers.

pub mod merge;

pub use nydus_core::build::{
    assemble_ondemand_artifact, finalize_digest_named_blob, save_blob_metadata_sidecar,
};

use std::collections::HashSet;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use nydus_core::build::blob_chunk::BlobWriter;
use nydus_core::build::bootstrap::{flatten_bootstrap_in_place, render_bootstrap};
use nydus_core::build::inode::{build_tree, set_root_prefetch_blobs_xattr};
use nydus_core::build::validate_chunk_geometry;
use nydus_core::build::HashingWriter;
use nydus_error::{Context, Result};
use nydus_format::blob::{BlobFooter, BlobMetadata, BlobMetadataCompressor};
use nydus_format::erofs::{ErofsDeviceSlot, EROFS_BLOB_ID_SIZE};

/// The minimum block group uncompressed size.
pub const MIN_BLOCK_GROUP_SIZE: u32 = 512 * 1024;

/// Options for [`build_image`].
#[derive(Debug)]
pub struct BuildImageOptions {
    /// Source directory to convert. Should be canonicalized so entries match
    /// against `exclude`.
    source: PathBuf,
    /// File chunk size in bytes (a power of two, >= the block size, and
    /// block-aligned).
    chunk_size: u32,
    /// Block group uncompressed size in bytes (a power of two, >= 512KiB, and >=
    /// the chunk size): the unit of compression and of a single backend read.
    block_group_size: u32,
    /// Algorithm to compress data chunks.
    compressor: BlobMetadataCompressor,
    /// Canonicalized paths inside `source` to omit from the image.
    excludes: HashSet<PathBuf>,
    /// Also render the standalone bootstrap: its device slot references the
    /// full blob digest, for the caller to persist.
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
        validate_chunk_geometry(chunk_size, block_group_size)?;
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
    // Nothing after rendering reads the inode tree (the standalone bootstrap
    // is patched from the rendered bytes), so free its tens of MiB before
    // final assembly.
    drop(inodes);

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

    // The standalone bootstrap differs from the embedded one only in its
    // device table (full-blob id, flattened mapped addresses), so the rendered
    // buffer is retargeted in place instead of rendering a second large copy
    // from the inode tree.
    let standalone_bootstrap = if options.render_standalone_bootstrap {
        let mut standalone = bootstrap_bytes;
        let standalone_device_slots = [ErofsDeviceSlot::with_blob_id(
            blob_blocks,
            &full_blob_digest,
        )];
        flatten_bootstrap_in_place(&mut standalone, &standalone_device_slots)?;
        Some(standalone)
    } else {
        drop(bootstrap_bytes);
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
