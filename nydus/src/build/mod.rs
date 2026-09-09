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
pub mod tar;

use std::collections::HashSet;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use blob_chunk::BlobWriter;
use bootstrap::render_bootstrap;
use inode::{build_tree, choose_epoch, set_root_prefetch_blobs_xattr};
use nydus_error::{Context, Error, Result};
use nydus_format::blob::{
    BlobFooter, BlobMetadata, BlobMetadataCompressor, BlobMetadataDigester, NYDUS_BLOB_FOOTER_SIZE,
};
use nydus_format::erofs::{ErofsDeviceSlot, EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE};
use nydus_format::utils::sha256_bytes;

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
    /// Block group uncompressed size in bytes (a power of two, >= 1MiB, and >= the
    /// chunk size): the unit of compression and of a single backend read.
    block_group_size: u32,
    /// Algorithm to compress data chunks.
    compressor: BlobMetadataCompressor,
    /// Chunk digest algorithm recorded in the blob meta.
    digester: BlobMetadataDigester,
    /// Caller-assigned blob id (device slot tag and store file name). When
    /// set, no sha256 pass is made over the data region or the full blob.
    blob_id: Option<[u8; EROFS_BLOB_ID_SIZE]>,
    /// Canonicalized paths inside `source` to omit from the image.
    excludes: HashSet<PathBuf>,
    /// Also render the standalone bootstrap — its device slot references the
    /// full blob digest — for the caller to persist.
    render_standalone_bootstrap: bool,
    /// z_erofs LZ4 output instead of chunk-based blobs: regular files become
    /// native compressed pclusters the kernel decompresses, small files are
    /// packed into the shared fragment inode, and files of at least
    /// `erofs_data_alignment` bytes start on that boundary of the layer data
    /// (0 disables alignment) so fixed-offset block dedup sees stable
    /// blocks. `compressor`, `digester` and the block group size do not
    /// apply; `blob_id` names the layer data instead of its sha256.
    erofs_lz4: bool,
    erofs_data_alignment: u32,
}

/// The built image as the caller sees it: the digests, blob meta and footer
/// of the full blob whose bytes went into the writer.
pub struct Image {
    /// SHA256 of the compressed data region (the data blob digest), or the
    /// caller-assigned blob id.
    pub data_blob_digest: [u8; EROFS_BLOB_ID_SIZE],
    /// SHA256 of the whole full blob file, or the caller-assigned blob id.
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
                "block group size {block_group_size} must be a power of two and at least 512KiB"
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
            digester: BlobMetadataDigester::Blake3,
            blob_id: None,
            excludes,
            render_standalone_bootstrap,
            erofs_lz4: false,
            erofs_data_alignment: 0,
        })
    }
    /// Selects the chunk digest algorithm; `None` skips chunk hashing.
    pub fn with_digester(mut self, digester: BlobMetadataDigester) -> Self {
        self.digester = digester;
        self
    }

    /// Names the blob up front instead of by its sha256, skipping both
    /// data-region and full-blob hashing. The caller vouches for the id being
    /// unique for this content and build configuration. Only local stores
    /// resolve such a blob: the device slot tag is the file name under
    /// `--blob-dir`, whereas a registry serves blobs by their real digest.
    pub fn with_blob_id(mut self, blob_id: Option<[u8; EROFS_BLOB_ID_SIZE]>) -> Self {
        self.blob_id = blob_id;
        self
    }

    /// The caller-assigned blob id, if any.
    pub fn blob_id(&self) -> Option<[u8; EROFS_BLOB_ID_SIZE]> {
        self.blob_id
    }

    fn configure_writer<W: Write>(&self, blob_writer: &mut BlobWriter<W>) {
        blob_writer.set_digester(self.digester);
        if self.blob_id.is_some() {
            blob_writer.disable_data_digest();
        }
    }

    /// Selects z_erofs LZ4 output (see [`build_erofs_layer_from_tar`]) with the
    /// given data alignment in bytes (a power of two multiple of the block
    /// size; 0 disables aligned placement).
    pub fn with_erofs_lz4(mut self, enabled: bool, data_alignment: u32) -> Self {
        self.erofs_lz4 = enabled;
        self.erofs_data_alignment = data_alignment;
        self
    }

    /// Whether the options select z_erofs LZ4 output.
    pub fn erofs_lz4(&self) -> bool {
        self.erofs_lz4
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
    options.configure_writer(&mut blob_writer);
    let inodes = build_tree(
        &options.source,
        &mut blob_writer,
        options.chunk_size,
        &options.excludes,
    )?;
    finish_image(inodes, blob_writer, options)
}

/// Builds the nydus image by streaming one OCI layer tarball (gzip or plain)
/// straight into `writer`: file data is chunked into the blob as each tar
/// entry is read, so no rootfs is staged on disk.
pub fn build_image_from_tar_layer(
    options: &BuildImageOptions,
    layer: &Path,
    writer: impl Write,
) -> Result<Image> {
    let mut blob_writer = BlobWriter::from_writer(
        writer,
        options.chunk_size,
        options.block_group_size,
        options.compressor,
    )?;
    options.configure_writer(&mut blob_writer);
    let inodes = tar::build_tar_layer_tree(layer, &mut blob_writer, options.chunk_size)?;
    finish_image(inodes, blob_writer, options)
}

/// z_erofs pcluster size: 64KiB, the erofs-utils default and the sweet spot
/// between read amplification and request count for file-backed mounts.
pub const EROFS_PCLUSTER_SIZE: u32 = 64 * 1024;
/// Regular files up to this size are packed into the fragment inode so
/// neighbouring small files share pclusters (one read serves many of them).
pub const EROFS_FRAGMENT_THRESHOLD: u64 = EROFS_PCLUSTER_SIZE as u64;

/// One z_erofs layer of a multi-device image: the raw compressed data was
/// streamed to the caller's writer (it becomes an extra device file, named
/// by `blob_digest`), and `bootstrap` is a complete single-layer image whose
/// device table maps that data past the bootstrap, on a
/// [`bootstrap::FLATTENED_BLOB_ALIGNMENT`] boundary. Whiteout entries are
/// preserved for `merge`.
pub struct ZLayer {
    /// Bootstrap image (`[head | metadata]`); write at offset 0.
    pub bootstrap: Vec<u8>,
    /// Size of the data written to the writer, in blocks.
    pub blob_blocks: u64,
    /// The device slot tag: SHA256 of the data written to the writer, or the
    /// caller-assigned blob id.
    pub blob_digest: [u8; EROFS_BLOB_ID_SIZE],
}

/// Builds a z_erofs layer (see [`ZLayer`]) from one OCI layer tarball,
/// streaming the compressed pclusters to `writer` as the tar is read.
pub fn build_erofs_layer_from_tar(
    options: &BuildImageOptions,
    layer: &Path,
    writer: impl Write,
) -> Result<ZLayer> {
    let mut blob_writer = options.z_blob_writer(writer)?;
    let inodes = tar::build_tar_layer_tree(layer, &mut blob_writer, options.chunk_size)?;
    finish_erofs_layer(inodes, blob_writer, options)
}

/// Builds a z_erofs layer (see [`ZLayer`]) from the source directory of
/// `options`, compressing files as the tree is walked.
pub fn build_erofs_layer_from_dir(
    options: &BuildImageOptions,
    writer: impl Write,
) -> Result<ZLayer> {
    let mut blob_writer = options.z_blob_writer(writer)?;
    let inodes = build_tree(
        &options.source,
        &mut blob_writer,
        options.chunk_size,
        &options.excludes,
    )?;
    finish_erofs_layer(inodes, blob_writer, options)
}

/// Block address the layer data is mapped at in a single-layer image (moved
/// up by [`bootstrap::fit_z_devices_past_bootstrap`] when the bootstrap is
/// larger).
const Z_LAYER_BASE_BLKADDR: u64 = bootstrap::FLATTENED_BLOB_ALIGNMENT / EROFS_BLOCK_SIZE as u64;

impl BuildImageOptions {
    /// A blob writer in z_erofs mode over `writer`: LZ4 pclusters, fragments,
    /// the configured data alignment, and a sha256 pass over the output
    /// unless the blob is named up front.
    fn z_blob_writer<W: Write>(&self, writer: W) -> Result<BlobWriter<HashingWriter<W>>> {
        let hasher = self.blob_id.is_none().then(Sha256::new);
        let mut blob_writer = BlobWriter::from_writer(
            HashingWriter::new(writer, hasher),
            self.chunk_size,
            self.block_group_size,
            BlobMetadataCompressor::None,
        )?;
        blob_writer.set_zlz4(EROFS_PCLUSTER_SIZE, Z_LAYER_BASE_BLKADDR)?;
        blob_writer.set_zlz4_fragments(EROFS_FRAGMENT_THRESHOLD)?;
        blob_writer
            .set_data_alignment(self.erofs_data_alignment, self.erofs_data_alignment as u64)?;
        Ok(blob_writer)
    }
}

/// Common back half of a z_erofs layer build: flushes the packed inode and
/// the data, then renders the single-layer bootstrap around it.
fn finish_erofs_layer<W: Write>(
    mut inodes: Vec<inode::InodeInfo>,
    mut blob_writer: BlobWriter<HashingWriter<W>>,
    options: &BuildImageOptions,
) -> Result<ZLayer> {
    // Same epoch rule as finish_image: the root's mtime is 0, and so is the
    // packed inode's, so neither takes part.
    let epoch = inodes
        .iter()
        .skip(1)
        .map(|inode| inode.mtime)
        .min()
        .unwrap_or(0);
    // The packed inode is a regular compressed file outside the directory
    // tree, reachable only through the superblock's packed_nid.
    let packed_index = match blob_writer.finish_zlz4_packed()? {
        Some((meta, size)) => {
            let mut packed = inode::packed_inode(&inodes, meta.tail, meta.compressed_blocks, size);
            packed.mtime = epoch;
            inodes.push(packed);
            Some(inodes.len() - 1)
        }
        None => None,
    };
    blob_writer.finish()?;

    let blob_blocks = blob_writer.z_end_blkaddr() - Z_LAYER_BASE_BLKADDR;
    let (writer, _) = blob_writer.into_parts();
    let blob_digest = match (
        options.blob_id,
        writer.finish().context("failed to flush layer data")?,
    ) {
        (Some(id), _) => id,
        (None, Some(digest)) => digest,
        (None, None) => unreachable!("hashing is enabled whenever no blob id is given"),
    };
    let mut device_slots = [ErofsDeviceSlot::with_blob_id_and_mapped_blkaddr(
        blob_blocks,
        &blob_digest,
        Z_LAYER_BASE_BLKADDR,
    )?];
    let uuid_bytes = [0u8; 16];
    bootstrap::fit_z_devices_past_bootstrap(&mut inodes, epoch, &mut device_slots)?;
    let bootstrap = bootstrap::render_z_device_bootstrap(
        &mut inodes,
        epoch,
        &uuid_bytes,
        u16::try_from(EROFS_PCLUSTER_SIZE / EROFS_BLOCK_SIZE)
            .expect("pcluster block count fits u16"),
        &device_slots,
        packed_index,
    )?;
    Ok(ZLayer {
        bootstrap,
        blob_blocks,
        blob_digest,
    })
}

/// Common back half of a build: finishes the blob, renders the bootstrap and
/// assembles the full blob around the already-flattened inode table.
fn finish_image<W: Write>(
    mut inodes: Vec<inode::InodeInfo>,
    mut blob_writer: BlobWriter<W>,
    options: &BuildImageOptions,
) -> Result<Image> {
    blob_writer.finish()?;
    let epoch = choose_epoch(&inodes);

    let uuid_bytes = [0u8; 16];
    let blob_blocks = blob_writer.total_blocks();
    let blob_id = match options.blob_id {
        Some(id) => id,
        None => blob_writer.data_digest().ok_or_else(|| {
            Error::InvalidParameter("data digest disabled without blob id".into())
        })?,
    };
    let device_slots = [ErofsDeviceSlot::with_blob_id(blob_blocks, &blob_id)?];
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
        .context("failed to flush blob")?
        .unwrap_or(blob_id);

    // The standalone bootstrap differs from the embedded one only in its
    // device table (full-blob id, flattened mapped addresses), so the
    // rendered buffer is retargeted in place instead of rendering a second
    // 30+ MiB copy from the inode tree.
    let standalone_bootstrap = if options.render_standalone_bootstrap {
        let mut standalone = bootstrap_bytes;
        let standalone_device_slots = [ErofsDeviceSlot::with_blob_id(
            blob_blocks,
            &full_blob_digest,
        )?];
        bootstrap::flatten_bootstrap_in_place(&mut standalone, &standalone_device_slots)?;
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

/// A writer that hashes every byte it forwards to the inner writer, unless
/// hashing was disabled by naming the blob explicitly.
struct HashingWriter<W> {
    inner: W,
    hasher: Option<Sha256>,
}

impl<W: Write> HashingWriter<W> {
    fn new(inner: W, hasher: Option<Sha256>) -> Self {
        Self { inner, hasher }
    }

    fn finish(mut self) -> io::Result<Option<[u8; EROFS_BLOB_ID_SIZE]>> {
        self.inner.flush()?;
        Ok(self.hasher.map(|hasher| {
            let mut digest = [0u8; EROFS_BLOB_ID_SIZE];
            digest.copy_from_slice(&hasher.finalize());
            digest
        }))
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        if let Some(hasher) = self.hasher.as_mut() {
            hasher.update(&buf[..written]);
        }
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

    /// A z_erofs layer built from a directory: every regular file is a
    /// COMPRESSED_FULL inode, small ones live in the packed inode, the layer
    /// data is one device mapped past the bootstrap, and `--blob-id` names it.
    #[test]
    fn build_erofs_layer_from_dir_renders_a_single_device_z_image() {
        use nydus_core::ErofsReader;
        use nydus_format::erofs::{EROFS_INODE_COMPRESSED_FULL, Z_EROFS_MAP_HEADER_SIZE};

        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("src");
        std::fs::create_dir_all(source.join("sub")).unwrap();
        let noise: Vec<u8> = (0..200_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        std::fs::write(source.join("big"), &noise).unwrap();
        std::fs::write(source.join("sub").join("small"), b"tiny").unwrap();
        std::fs::write(source.join("empty"), b"").unwrap();
        std::os::unix::fs::symlink("big", source.join("link")).unwrap();

        let blob_id = [0x42u8; EROFS_BLOB_ID_SIZE];
        let options = BuildImageOptions::new(
            source.clone(),
            EROFS_BLOCK_SIZE,
            1 << 20,
            BlobMetadataCompressor::Zstd,
            HashSet::new(),
            true,
        )
        .unwrap()
        .with_blob_id(Some(blob_id))
        .with_erofs_lz4(true, 8 * EROFS_BLOCK_SIZE);
        let mut data = Vec::new();
        let layer = build_erofs_layer_from_dir(&options, &mut data).unwrap();

        assert_eq!(layer.blob_digest, blob_id, "named, not hashed");
        assert_eq!(
            data.len() as u64,
            layer.blob_blocks * EROFS_BLOCK_SIZE as u64
        );
        let meta_path = dir.path().join("layer.meta");
        std::fs::write(&meta_path, &layer.bootstrap).unwrap();
        let reader = ErofsReader::open_metadata_only(&meta_path).unwrap();
        let [device] = reader.blob_infos().unwrap() else {
            panic!("one device");
        };
        assert_eq!(device.blob_id, blob_id);
        assert_eq!(device.blocks, layer.blob_blocks);
        assert!(device.mapped_blkaddr * EROFS_BLOCK_SIZE as u64 >= layer.bootstrap.len() as u64);

        let root_nid = reader.superblock().root_nid();
        let root = reader.inode(root_nid).unwrap();
        let lookup = |parent: u64, name: &str| {
            let inode = reader.inode(parent).unwrap();
            reader
                .lookup_dir_entry(parent, &inode, name.as_bytes())
                .unwrap()
                .unwrap_or_else(|| panic!("{name} missing"))
        };
        let big = reader.inode(lookup(root_nid, "big")).unwrap();
        assert_eq!(big.data_layout(), EROFS_INODE_COMPRESSED_FULL);
        assert_eq!(big.size(), noise.len() as u64);
        let big_tail = reader
            .read_z_inode_tail(lookup(root_nid, "big"), &big)
            .unwrap();
        // Aligned to 8 blocks of the device data.
        let first = u32::from_le_bytes(
            big_tail[Z_EROFS_MAP_HEADER_SIZE + 12..][..4]
                .try_into()
                .unwrap(),
        );
        assert_eq!((first as u64 - device.mapped_blkaddr) % 8, 0);

        let small_nid = lookup(lookup(root_nid, "sub"), "small");
        let small = reader.inode(small_nid).unwrap();
        assert_eq!(small.data_layout(), EROFS_INODE_COMPRESSED_FULL);
        assert_eq!(
            reader.read_z_inode_tail(small_nid, &small).unwrap().len(),
            Z_EROFS_MAP_HEADER_SIZE,
            "fragment"
        );
        let empty = reader.inode(lookup(root_nid, "empty")).unwrap();
        assert_eq!(empty.data_layout(), EROFS_INODE_COMPRESSED_FULL);
        assert_eq!(empty.size(), 0);
        assert!(reader.superblock().packed_nid().is_some());
        assert!(root.size() > 0);
    }
}
