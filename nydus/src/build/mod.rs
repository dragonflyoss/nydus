//! Building nydus images: chunking and compressing file data into blobs
//! ([`blob_chunk`]), constructing the inode tree ([`inode`], [`dir`]), and
//! rendering EROFS bootstraps ([`bootstrap`], [`image`]).
//!
//! [`build_dir_image`] is the high-level entry point that converts a
//! directory tree into a nydus full blob.

pub mod blob_chunk;
pub mod bootstrap;
pub mod dir;
pub mod image;
pub mod inode;
pub mod layout;
pub mod merge;

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

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

/// The minimum group uncompressed size.
pub const MIN_COMPRESS_SIZE: u32 = 1024 * 1024;

/// Options for [`build_dir_image`].
pub struct DirImageOptions<'a> {
    /// Source directory to convert. Should be canonicalized so entries match
    /// against `exclude`.
    pub source: &'a Path,
    /// File chunk size in bytes (a power of two, >= the block size, and
    /// block-aligned).
    pub chunk_size: u32,
    /// Group uncompressed size in bytes (a power of two, >= 1MiB, and >= the
    /// chunk size). Controls the uncompressed size of each blob meta group
    /// used for compression.
    pub compress_size: u32,
    /// Algorithm to compress data chunks.
    pub compressor: BlobMetadataCompressor,
    /// Canonicalized paths inside `source` to omit from the image.
    pub exclude: &'a HashSet<PathBuf>,
    /// Also render a standalone bootstrap whose device slot references the
    /// full blob digest, returned in [`DirImage::standalone_bootstrap`].
    pub standalone_bootstrap: bool,
}

/// The result of [`build_dir_image`]: the digests, blob meta and footer of
/// the written full blob, plus the standalone bootstrap when requested.
pub struct DirImage {
    /// SHA256 of the compressed data region (the data blob digest).
    pub data_digest: [u8; EROFS_BLOB_ID_SIZE],
    /// SHA256 of the whole full blob file.
    pub full_blob_digest: [u8; EROFS_BLOB_ID_SIZE],
    pub blob_metadata: BlobMetadata,
    pub footer: BlobFooter,
    pub standalone_bootstrap: Option<Vec<u8>>,
}

impl DirImageOptions<'_> {
    /// Validate the chunk/compress geometry without touching the filesystem,
    /// so callers can fail fast before creating output files.
    pub fn validate(&self) -> Result<()> {
        // Validate EROFS file chunk size. BlobMetadata groups are formed
        // separately and are at least 1MiB even when file chunk indexes are
        // smaller.
        if self.chunk_size < EROFS_BLOCK_SIZE {
            return Err(Error::InvalidParameter(format!(
                "chunk size {} must be >= block size {}",
                self.chunk_size, EROFS_BLOCK_SIZE
            )));
        }
        if !self.chunk_size.is_power_of_two() {
            return Err(Error::InvalidParameter(format!(
                "chunk size {} must be a power of two",
                self.chunk_size
            )));
        }
        if self.chunk_size % EROFS_BLOCK_SIZE != 0 {
            return Err(Error::InvalidParameter(format!(
                "chunk size {} must be block aligned",
                self.chunk_size
            )));
        }

        // Validate compress (group uncompressed) size: a power of two (the
        // blob meta header stores it as the log2 exponent `group_block_bits`),
        // at least 1MiB, and at least the file chunk size so a chunk always
        // fits in a group.
        if !self.compress_size.is_power_of_two() || self.compress_size < MIN_COMPRESS_SIZE {
            return Err(Error::InvalidParameter(format!(
                "compress size {} must be a power of two and at least 1MiB",
                self.compress_size
            )));
        }
        if self.compress_size < self.chunk_size {
            return Err(Error::InvalidParameter(format!(
                "compress size {} must be >= chunk size {}",
                self.compress_size, self.chunk_size
            )));
        }
        Ok(())
    }
}

/// Convert the source directory into a nydus full blob written to `blob_out`
/// (`[compressed data][bootstrap][blob meta][footer]`).
pub fn build_dir_image(options: &DirImageOptions<'_>, blob_out: File) -> Result<DirImage> {
    options.validate()?;

    let mut blob_writer = BlobWriter::from_file(
        blob_out,
        options.chunk_size,
        options.compress_size,
        options.compressor,
    )?;
    let mut inodes = build_tree(
        options.source,
        &mut blob_writer,
        options.chunk_size,
        options.exclude,
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
    let blob_metadata = blob_writer.blob_metadata(blob_id, 0)?;
    let (blob_file, full_blob_hasher) = blob_writer.into_file_and_data_hasher();
    let mut blob_writer_stream = HashingWriter::new(BufWriter::new(blob_file), full_blob_hasher);

    let footer = nydus_format::blob::assemble_full_blob(
        &mut blob_writer_stream,
        compressed_data_size,
        &bootstrap_bytes,
        &blob_metadata,
    )?;
    let full_blob_digest = blob_writer_stream
        .finish()
        .context("failed to flush blob")?;

    let standalone_bootstrap = if options.standalone_bootstrap {
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

    Ok(DirImage {
        data_digest: blob_id,
        full_blob_digest,
        blob_metadata,
        footer,
        standalone_bootstrap,
    })
}

/// Assemble an ondemand artifact `[group data][blob.meta][footer]` (no
/// embedded bootstrap) and return its bytes, full SHA256 digest, and footer.
pub(crate) fn assemble_ondemand_artifact(
    data: &[u8],
    blob_metadata: &BlobMetadata,
) -> Result<(Vec<u8>, [u8; EROFS_BLOB_ID_SIZE], BlobFooter)> {
    let mut artifact = Vec::with_capacity(
        usize::try_from(data.len() as u64 + blob_metadata.metadata_size())
            .map_err(|err| Error::Overflow(format!("artifact exceeds usize: {err}")))?
            + NYDUS_BLOB_FOOTER_SIZE,
    );
    artifact.extend_from_slice(data);
    let footer = nydus_format::blob::assemble_full_blob(
        &mut artifact,
        data.len() as u64,
        &[],
        blob_metadata,
    )?;

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
