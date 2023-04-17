// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Display, Formatter, Result as FmtResult};
use std::fs::{self, File};
use std::io::{Read, SeekFrom, Write};
use std::mem::size_of;
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::os::macos::fs::MetadataExt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Error, Result};
use sha2::digest::Digest;

use nydus_rafs::metadata::chunk::ChunkWrapper;
use nydus_rafs::metadata::inode::{new_v6_inode, InodeWrapper};
use nydus_rafs::metadata::layout::v5::RafsV5InodeWrapper;
use nydus_rafs::metadata::layout::v6::{
    align_offset, calculate_nid, RafsV6Dirent, RafsV6InodeChunkAddr, RafsV6InodeChunkHeader,
    RafsV6OndiskInode, EROFS_BLOCK_SIZE, EROFS_INODE_CHUNK_BASED, EROFS_INODE_FLAT_INLINE,
    EROFS_INODE_FLAT_PLAIN,
};
use nydus_rafs::metadata::layout::RafsXAttrs;
use nydus_rafs::metadata::{Inode, RafsStore, RafsVersion};
use nydus_rafs::RafsIoWrite;
use nydus_storage::device::BlobFeatures;
use nydus_storage::meta::{BlobChunkInfoV2Ondisk, BlobMetaChunkInfo};
use nydus_utils::compress;
use nydus_utils::digest::{DigestHasher, RafsDigest};
use nydus_utils::{div_round_up, round_down_4k, round_up, try_round_up_4k, ByteSize};

use super::chunk_dict::{ChunkDict, DigestWithBlobIndex};
use super::context::{ArtifactWriter, BlobContext, BlobManager, BootstrapContext, BuildContext};
use super::tree::Tree;

// Filesystem may have different algorithms to calculate `i_size` for directory entries,
// which may break "repeatable build". To support repeatable build, instead of reuse the value
// provided by the source filesystem, we use our own algorithm to calculate `i_size` for directory
// entries for stable `i_size`.
//
// Rafs v6 already has its own algorithm to calculate `i_size` for directory entries, but we don't
// have directory entries for Rafs v5. So let's generate a pseudo `i_size` for Rafs v5 directory
// inode.
const RAFS_V5_VIRTUAL_ENTRY_SIZE: u64 = 8;

/// Filesystem root path for Unix OSs.
pub const ROOT_PATH_NAME: &[u8] = &[b'/'];

/// Prefix for OCI whiteout file.
pub const OCISPEC_WHITEOUT_PREFIX: &str = ".wh.";
/// Prefix for OCI whiteout opaque.
pub const OCISPEC_WHITEOUT_OPAQUE: &str = ".wh..wh..opq";
/// Extended attribute key for Overlayfs whiteout opaque.
pub const OVERLAYFS_WHITEOUT_OPAQUE: &str = "trusted.overlay.opaque";

// # Overlayfs Whiteout
//
// In order to support rm and rmdir without changing the lower filesystem, an overlay filesystem
// needs to record in the upper filesystem that files have been removed. This is done using
// whiteouts and opaque directories (non-directories are always opaque).
//
// A whiteout is created as a character device with 0/0 device number. When a whiteout is found
// in the upper level of a merged directory, any matching name in the lower level is ignored,
// and the whiteout itself is also hidden.
//
// A directory is made opaque by setting the xattr “trusted.overlay.opaque” to “y”. Where the upper
// filesystem contains an opaque directory, any directory in the lower filesystem with the same
// name is ignored.
//
// # OCI Image Whiteout
// - A whiteout file is an empty file with a special filename that signifies a path should be
//   deleted.
// - A whiteout filename consists of the prefix .wh. plus the basename of the path to be deleted.
// - As files prefixed with .wh. are special whiteout markers, it is not possible to create a
//   filesystem which has a file or directory with a name beginning with .wh..
// - Once a whiteout is applied, the whiteout itself MUST also be hidden.
// - Whiteout files MUST only apply to resources in lower/parent layers.
// - Files that are present in the same layer as a whiteout file can only be hidden by whiteout
//   files in subsequent layers.
// - In addition to expressing that a single entry should be removed from a lower layer, layers
//   may remove all of the children using an opaque whiteout entry.
// - An opaque whiteout entry is a file with the name .wh..wh..opq indicating that all siblings
//   are hidden in the lower layer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum WhiteoutType {
    OciOpaque,
    OciRemoval,
    OverlayFsOpaque,
    OverlayFsRemoval,
}

impl WhiteoutType {
    pub fn is_removal(&self) -> bool {
        *self == WhiteoutType::OciRemoval || *self == WhiteoutType::OverlayFsRemoval
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum WhiteoutSpec {
    /// https://github.com/opencontainers/image-spec/blob/master/layer.md#whiteouts
    Oci,
    /// "whiteouts and opaque directories" in https://www.kernel.org/doc/Documentation/filesystems/overlayfs.txt
    Overlayfs,
    /// No whiteout spec, which will build all `.wh.*` and `.wh..wh..opq` files into bootstrap.
    None,
}

impl Default for WhiteoutSpec {
    fn default() -> Self {
        Self::Oci
    }
}

impl FromStr for WhiteoutSpec {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "oci" => Ok(Self::Oci),
            "overlayfs" => Ok(Self::Overlayfs),
            "none" => Ok(Self::None),
            _ => Err(anyhow!("invalid whiteout spec")),
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq)]
pub enum Overlay {
    Lower,
    UpperAddition,
    UpperOpaque,
    UpperRemoval,
    UpperModification,
}

impl Overlay {
    pub fn is_lower_layer(&self) -> bool {
        self == &Overlay::Lower
    }
}

impl Display for Overlay {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Overlay::Lower => write!(f, "LOWER"),
            Overlay::UpperAddition => write!(f, "ADDED"),
            Overlay::UpperOpaque => write!(f, "OPAQUED"),
            Overlay::UpperRemoval => write!(f, "REMOVED"),
            Overlay::UpperModification => write!(f, "MODIFIED"),
        }
    }
}

#[derive(Clone)]
pub struct NodeChunk {
    pub source: ChunkSource,
    pub inner: ChunkWrapper,
}

impl Display for NodeChunk {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner,)
    }
}

/// Where the chunk data is actually stored.
#[derive(Clone, Hash, PartialEq, Eq)]
pub enum ChunkSource {
    /// Chunk is stored in data blob owned by current image.
    Build,
    /// A reference to a chunk in chunk dictionary.
    Dict,
    /// A reference to a chunk in parent image.
    Parent,
}

impl Display for ChunkSource {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Build => write!(f, "build"),
            Self::Dict => write!(f, "dict"),
            Self::Parent => write!(f, "parent"),
        }
    }
}

/// An in-memory representation of RAFS inode for image building and inspection.
#[derive(Clone)]
pub struct Node {
    /// Assigned RAFS inode number.
    pub index: u64,
    /// Device id associated with the source inode.
    ///
    /// A source directory may contain multiple partitions from different hard disk, so
    /// a pair of (src_ino, src_dev) is needed to uniquely identify an inode from source directory.
    pub src_dev: u64,
    /// Inode number of the source inode, from fs stat().
    pub src_ino: Inode,
    /// Device ID for special files, describing the device that this inode represents.
    pub rdev: u64,
    /// Define a disk inode structure to persist to disk.
    pub inode: InodeWrapper,
    /// Chunks info list of regular file
    pub chunks: Vec<NodeChunk>,
    /// Extended attributes.
    pub xattrs: RafsXAttrs,
    /// Symlink info of symlink file
    pub symlink: Option<OsString>,
    /// Overlay type for layered build
    pub overlay: Overlay,
    /// Whether the explicit UID/GID feature is enabled or not.
    pub explicit_uidgid: bool,
    /// Absolute path of the source root directory.
    pub source: PathBuf,
    /// Absolute path of the source file/directory.
    pub path: PathBuf,
    /// Absolute path within the target RAFS filesystem.
    pub target: PathBuf,
    /// Parsed version of `target`.
    pub target_vec: Vec<OsString>,
    /// Layer index where node is located.
    pub layer_idx: u16,
    /// Last status change time of the file, in nanoseconds.
    pub ctime: i64,

    /// V6: whether it's a compact inode or an extended inode.
    pub v6_compact_inode: bool,
    /// V6: whether it's forced to use an extended inode.
    pub v6_force_extended_inode: bool,
    /// V6: inode data layout.
    pub v6_datalayout: u16,
    /// V6: offset to calculate nid.
    pub v6_offset: u64,
    /// V6: information to build directory entries.
    pub v6_dirents: Vec<(u64, OsString, u32)>,
    /// V6: offset to build directory entries.
    pub v6_dirents_offset: u64,
}

impl Display for Node {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{} {:?}: index {} ino {} real_ino {} i_parent {} child_index {} child_count {} i_nlink {} i_size {} i_blocks {} i_name_size {} i_symlink_size {} has_xattr {} link {:?} i_mtime {} i_mtime_nsec {}",
            self.file_type(),
            self.target(),
            self.index,
            self.inode.ino(),
            self.src_ino,
            self.inode.parent(),
            self.inode.child_index(),
            self.inode.child_count(),
            self.inode.nlink(),
            self.inode.size(),
            self.inode.blocks(),
            self.inode.name_size(),
            self.inode.symlink_size(),
            self.inode.has_xattr(),
            self.symlink,
            self.inode.mtime(),
            self.inode.mtime_nsec(),
        )
    }
}

impl Node {
    pub fn new(
        version: RafsVersion,
        source: PathBuf,
        path: PathBuf,
        overlay: Overlay,
        chunk_size: u32,
        explicit_uidgid: bool,
        v6_force_extended_inode: bool,
    ) -> Result<Node> {
        let target = Self::generate_target(&path, &source);
        let target_vec = Self::generate_target_vec(&target);
        let mut node = Node {
            index: 0,
            src_ino: 0,
            src_dev: u64::MAX,
            rdev: u64::MAX,
            source,
            target,
            path,
            target_vec,
            overlay,
            inode: InodeWrapper::new(version),
            chunks: Vec::new(),
            symlink: None,
            xattrs: RafsXAttrs::default(),
            explicit_uidgid,
            layer_idx: 0,
            ctime: 0,
            v6_offset: 0,
            v6_dirents: Vec::new(),
            v6_datalayout: EROFS_INODE_FLAT_PLAIN,
            v6_force_extended_inode,
            v6_compact_inode: false,
            v6_dirents_offset: 0,
        };

        node.build_inode(chunk_size)
            .context("failed to build inode")?;
        if version.is_v6() {
            node.v6_set_inode_compact();
        }

        Ok(node)
    }

    /// Dump data from the file assoicated with the node into the data blob, and generate chunk
    /// information.
    ///
    /// # Arguments
    /// - blob_writer: optional writer to write data into the data blob.
    /// - data_buf: scratch buffer used to stored data read from the reader.
    pub fn dump_node_data(
        self: &mut Node,
        ctx: &BuildContext,
        blob_mgr: &mut BlobManager,
        blob_writer: &mut ArtifactWriter,
        chunk_data_buf: &mut [u8],
    ) -> Result<u64> {
        let mut reader = if self.is_reg() {
            let file = File::open(&self.path)
                .with_context(|| format!("failed to open node file {:?}", self.path))?;
            Some(file)
        } else {
            None
        };

        self.dump_node_data_with_reader(ctx, blob_mgr, blob_writer, reader.as_mut(), chunk_data_buf)
    }

    /// Dump data from a reader into the data blob, and generate chunk information.
    ///
    /// # Arguments
    /// - blob_writer: optional writer to write data into the data blob.
    /// - reader: reader to provide chunk data
    /// - data_buf: scratch buffer used to stored data read from the reader.
    pub fn dump_node_data_with_reader<R: Read>(
        &mut self,
        ctx: &BuildContext,
        blob_mgr: &mut BlobManager,
        blob_writer: &mut ArtifactWriter,
        reader: Option<&mut R>,
        data_buf: &mut [u8],
    ) -> Result<u64> {
        if self.is_dir() {
            return Ok(0);
        } else if self.is_symlink() {
            if let Some(symlink) = self.symlink.as_ref() {
                self.inode
                    .set_digest(RafsDigest::from_buf(symlink.as_bytes(), ctx.digester));
                return Ok(0);
            } else {
                return Err(Error::msg("inode's symblink is invalid."));
            }
        } else if self.is_special() {
            self.inode
                .set_digest(RafsDigest::hasher(ctx.digester).digest_finalize());
            return Ok(0);
        }

        let mut blob_size = 0u64;
        let reader = reader.ok_or_else(|| anyhow!("missing reader to read file data"))?;
        let mut inode_hasher = if self.inode.is_v5() {
            Some(RafsDigest::hasher(ctx.digester))
        } else {
            None
        };

        // `child_count` of regular file is reused as `chunk_count`.
        for i in 0..self.inode.child_count() {
            let chunk_size = ctx.chunk_size;
            let file_offset = i as u64 * chunk_size as u64;
            let uncompressed_size = if i == self.inode.child_count() - 1 {
                (self.inode.size() - chunk_size as u64 * i as u64) as u32
            } else {
                chunk_size
            };

            let chunk_data = &mut data_buf[0..uncompressed_size as usize];
            let (chunk, chunk_info) = self.read_file_chunk(ctx, reader, chunk_data)?;
            if let Some(h) = inode_hasher.as_mut() {
                h.digest_update(chunk.id().as_ref());
            }

            let mut chunk = match self.deduplicate_chunk(
                ctx,
                blob_mgr,
                file_offset,
                uncompressed_size,
                chunk,
            )? {
                None => continue,
                Some(c) => c,
            };

            let (blob_index, blob_ctx) = blob_mgr.get_or_create_current_blob(ctx)?;
            let chunk_index = blob_ctx.alloc_chunk_index()?;
            chunk.set_blob_index(blob_index);
            chunk.set_index(chunk_index);
            chunk.set_file_offset(file_offset);
            self.dump_file_chunk(ctx, blob_ctx, blob_writer, chunk_data, &mut chunk)?;

            blob_size += chunk.compressed_size() as u64;
            blob_ctx.add_chunk_meta_info(&chunk, chunk_info)?;
            blob_mgr
                .layered_chunk_dict
                .add_chunk(chunk.clone(), ctx.digester);
            self.chunks.push(NodeChunk {
                source: ChunkSource::Build,
                inner: chunk,
            });
        }

        // Finish inode digest calculation
        if let Some(h) = inode_hasher {
            self.inode.set_digest(h.digest_finalize());
        }

        Ok(blob_size)
    }

    fn build_inode_xattr(&mut self) -> Result<()> {
        let file_xattrs = match xattr::list(&self.path) {
            Ok(x) => x,
            Err(e) => {
                if e.raw_os_error() == Some(libc::EOPNOTSUPP) {
                    return Ok(());
                } else {
                    return Err(anyhow!("failed to list xattr of {:?}", self.path));
                }
            }
        };

        for key in file_xattrs {
            let value = xattr::get(&self.path, &key)
                .context(format!("failed to get xattr {:?} of {:?}", key, self.path))?;
            self.xattrs.add(key, value.unwrap_or_default())?;
        }

        if !self.xattrs.is_empty() {
            self.inode.set_has_xattr(true);
        }

        Ok(())
    }

    fn build_inode_stat(&mut self) -> Result<()> {
        let meta = self.meta()?;

        self.src_ino = meta.st_ino();
        self.src_dev = meta.st_dev();
        self.rdev = meta.st_rdev();
        self.ctime = meta.st_ctime();

        self.inode.set_mode(meta.st_mode());
        if self.explicit_uidgid {
            self.inode.set_uid(meta.st_uid());
            self.inode.set_gid(meta.st_gid());
        }

        // Usually the root directory is created by the build tool (nydusify/buildkit/acceld)
        // and the mtime of the root directory is different for each build, which makes it
        // completely impossible to achieve repeatable builds, especially in a tar build scenario
        // (blob + bootstrap in one tar layer), which causes the layer hash to change and wastes
        // registry storage space, so the mtime of the root directory is forced to be ignored here.
        let ignore_mtime = self.is_root();
        if !ignore_mtime {
            self.inode.set_mtime(meta.st_mtime() as u64);
            self.inode.set_mtime_nsec(meta.st_mtime_nsec() as u32);
        }
        self.inode.set_projid(0);
        self.inode.set_rdev(meta.st_rdev() as u32);
        // Ignore actual nlink value and calculate from rootfs directory instead
        self.inode.set_nlink(1);

        // Different filesystem may have different algorithms to calculate size/blocks for
        // directory entries, so let's ignore the value provided by source filesystem and
        // calculate it later by ourself.
        if !self.is_dir() {
            self.inode.set_size(meta.st_size());
            self.set_inode_blocks();
        }

        Ok(())
    }

    fn build_inode(&mut self, chunk_size: u32) -> Result<()> {
        self.inode.set_name_size(self.name().byte_size());

        // NOTE: Always retrieve xattr before attr so that we can know the size of xattr pairs.
        self.build_inode_xattr()?;
        self.build_inode_stat()
            .with_context(|| format!("failed to build inode {:?}", self.path))?;

        if self.is_reg() {
            // Reuse `child_count` to store `chunk_count` for normal files.
            self.inode
                .set_child_count(self.chunk_count(chunk_size as u64));
        } else if self.is_symlink() {
            let target_path = fs::read_link(&self.path)?;
            let symlink: OsString = target_path.into();
            let size = symlink.byte_size();
            self.inode.set_symlink_size(size);
            self.symlink = Some(symlink);
        }

        Ok(())
    }

    fn meta(&self) -> Result<impl MetadataExt> {
        self.path
            .symlink_metadata()
            .with_context(|| format!("failed to get metadata from {:?}", self.path))
    }

    fn read_file_chunk<R: Read>(
        &self,
        ctx: &BuildContext,
        reader: &mut R,
        buf: &mut [u8],
    ) -> Result<(ChunkWrapper, Option<BlobChunkInfoV2Ondisk>)> {
        let mut chunk = self.inode.create_chunk();
        let mut chunk_info = None;
        if let Some(ref zran) = ctx.blob_zran_generator {
            let mut zran = zran.lock().unwrap();
            zran.start_chunk(ctx.chunk_size as u64)?;
            reader
                .read_exact(buf)
                .with_context(|| format!("failed to read node file {:?}", self.path))?;
            let info = zran.finish_chunk()?;
            chunk.set_compressed_offset(info.compressed_offset());
            chunk.set_compressed_size(info.compressed_size());
            chunk.set_compressed(true);
            chunk_info = Some(info);
        } else if let Some(ref tar_reader) = ctx.blob_tar_reader {
            // For `tar-ref` case
            let pos = tar_reader.position();
            chunk.set_compressed_offset(pos);
            chunk.set_compressed_size(buf.len() as u32);
            chunk.set_compressed(false);
            reader
                .read_exact(buf)
                .with_context(|| format!("failed to read node file {:?}", self.path))?;
        } else {
            reader
                .read_exact(buf)
                .with_context(|| format!("failed to read node file {:?}", self.path))?;
        }

        let chunk_id = RafsDigest::from_buf(buf, ctx.digester);
        chunk.set_id(chunk_id);
        Ok((chunk, chunk_info))
    }

    fn dump_file_chunk(
        &self,
        ctx: &BuildContext,
        blob_ctx: &mut BlobContext,
        blob_writer: &mut ArtifactWriter,
        chunk_data: &[u8],
        chunk: &mut ChunkWrapper,
    ) -> Result<()> {
        let uncompressed_size = chunk_data.len() as u32;
        let aligned_chunk_size = if ctx.aligned_chunk {
            // Safe to unwrap because `chunk_size` is much less than u32::MAX.
            try_round_up_4k(uncompressed_size).unwrap()
        } else {
            uncompressed_size
        };
        let pre_uncompressed_offset = blob_ctx.current_uncompressed_offset;
        blob_ctx.uncompressed_blob_size = pre_uncompressed_offset + aligned_chunk_size as u64;
        blob_ctx.current_uncompressed_offset += aligned_chunk_size as u64;
        chunk.set_uncompressed_offset(pre_uncompressed_offset);
        chunk.set_uncompressed_size(uncompressed_size);

        let compressed_size = if ctx.blob_features.contains(BlobFeatures::SEPARATE) {
            // For `tar-ref`, `targz-ref`, `estargz-ref` and `estargzindex-ref`.
            chunk.compressed_size()
        } else {
            // For other case which needs to write chunk data to data blobs.
            let (compressed, is_compressed) = compress::compress(chunk_data, ctx.compressor)
                .with_context(|| format!("failed to compress node file {:?}", self.path))?;
            let compressed_size = compressed.len() as u32;
            let pre_compressed_offset = blob_ctx.current_compressed_offset;
            blob_writer
                .write_all(&compressed)
                .context("failed to write blob")?;
            blob_ctx.blob_hash.update(&compressed);
            blob_ctx.current_compressed_offset += compressed_size as u64;
            blob_ctx.compressed_blob_size += compressed_size as u64;

            chunk.set_compressed_offset(pre_compressed_offset);
            chunk.set_compressed_size(compressed_size);
            chunk.set_compressed(is_compressed);
            compressed_size
        };

        event_tracer!("blob_uncompressed_size", +uncompressed_size);
        event_tracer!("blob_compressed_size", +compressed_size);

        Ok(())
    }

    fn deduplicate_chunk(
        &mut self,
        ctx: &BuildContext,
        blob_mgr: &mut BlobManager,
        file_offset: u64,
        uncompressed_size: u32,
        mut chunk: ChunkWrapper,
    ) -> Result<Option<ChunkWrapper>> {
        let dict = &blob_mgr.global_chunk_dict;
        let mut cached_chunk = dict.get_chunk(chunk.id(), uncompressed_size);
        let from_dict = cached_chunk.is_some();
        if cached_chunk.is_none() {
            cached_chunk = blob_mgr
                .layered_chunk_dict
                .get_chunk(chunk.id(), uncompressed_size);
        }
        let cached_chunk = match cached_chunk {
            Some(v) => v,
            None => return Ok(Some(chunk)),
        };

        // The chunks of hardlink should be always deduplicated.
        if !self.is_hardlink() {
            event_tracer!("dedup_uncompressed_size", +uncompressed_size);
            event_tracer!("dedup_chunks", +1);
        }
        chunk.copy_from(cached_chunk);
        chunk.set_file_offset(file_offset);

        // Only add actually referenced data blobs from chunk dictionary to the blob table.
        if from_dict {
            let blob_index = if let Some(blob_idx) = dict.get_real_blob_idx(chunk.blob_index()) {
                blob_idx
            } else {
                let blob_idx = blob_mgr.alloc_index()?;
                dict.set_real_blob_idx(chunk.blob_index(), blob_idx);
                if let Some(blob) = dict.get_blob_by_inner_idx(chunk.blob_index()) {
                    let ctx = BlobContext::from(ctx, blob, ChunkSource::Dict)?;
                    blob_mgr.add(ctx);
                }
                blob_idx
            };
            chunk.set_blob_index(blob_index);
        }

        trace!(
            "\t\tfound duplicated chunk: {} compressor {}",
            chunk,
            ctx.compressor
        );
        let source = if from_dict {
            ChunkSource::Dict
        } else if Some(chunk.blob_index()) != blob_mgr.get_current_blob().map(|(u, _)| u) {
            ChunkSource::Parent
        } else {
            ChunkSource::Build
        };
        self.chunks.push(NodeChunk {
            source,
            inner: chunk,
        });

        Ok(None)
    }
}

// Access Methods
impl Node {
    pub fn is_root(&self) -> bool {
        self.target() == OsStr::from_bytes(ROOT_PATH_NAME)
    }

    pub fn is_dir(&self) -> bool {
        self.inode.is_dir()
    }

    pub fn is_symlink(&self) -> bool {
        self.inode.is_symlink()
    }

    pub fn is_reg(&self) -> bool {
        self.inode.is_reg()
    }

    pub fn is_hardlink(&self) -> bool {
        self.inode.is_hardlink()
    }

    pub fn is_special(&self) -> bool {
        self.inode.is_special()
    }

    pub fn chunk_count(&self, chunk_size: u64) -> u32 {
        if self.is_reg() {
            let chunks = div_round_up(self.inode.size(), chunk_size);
            debug_assert!(chunks < u32::MAX as u64);
            chunks as u32
        } else {
            0
        }
    }

    /// Get file type of the inode.
    pub fn file_type(&self) -> &str {
        let mut file_type = "";

        if self.is_symlink() {
            file_type = "symlink";
        } else if self.is_dir() {
            file_type = "dir"
        } else if self.is_reg() {
            if self.is_hardlink() {
                file_type = "hardlink";
            } else {
                file_type = "file";
            }
        }

        file_type
    }

    /// Get filename of the inode.
    pub fn name(&self) -> &OsStr {
        if self.path == self.source {
            OsStr::from_bytes(ROOT_PATH_NAME)
        } else {
            // Safe to unwrap because `path` is returned from `path()` which is canonicalized
            self.path.file_name().unwrap()
        }
    }

    /// Get path of the inode
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Generate cached components of the target file path.
    pub fn generate_target_vec(target: &Path) -> Vec<OsString> {
        target
            .components()
            .map(|comp| match comp {
                Component::RootDir => OsString::from("/"),
                Component::Normal(name) => name.to_os_string(),
                _ => panic!("invalid file component pattern!"),
            })
            .collect::<Vec<_>>()
    }

    /// Get cached components of the target file path.
    pub fn target_vec(&self) -> &[OsString] {
        &self.target_vec
    }

    /// Generate target path by stripping the `root` prefix.
    ///
    /// Strip the `root` prefix if `path` starts with `root`, otherwise keep `path` as is.
    /// For example:
    /// root: /absolute/path/to/rootfs
    /// path: /absolute/path/to/rootfs/file => /file
    /// path /not_rootfs_prefix/file => /not_rootfs_prefix/file
    pub fn generate_target(path: &Path, root: &Path) -> PathBuf {
        if let Ok(p) = path.strip_prefix(root) {
            Path::new("/").join(p)
        } else {
            // Compatible with path `/`
            path.to_path_buf()
        }
    }

    /// Get the absolute path of the inode within the RAFS filesystem.
    pub fn target(&self) -> &PathBuf {
        &self.target
    }

    /// Calculate and set `i_blocks` for inode.
    ///
    /// In order to support repeatable build, we can't reuse `i_blocks` from source filesystems,
    /// so let's calculate it by ourself for stable `i_block`.
    ///
    /// Normal filesystem includes the space occupied by Xattr into the directory size,
    /// let's follow the normal behavior.
    pub fn set_inode_blocks(&mut self) {
        // Set inode blocks for RAFS v5 inode, v6 will calculate it at runtime.
        if let InodeWrapper::V5(_) = self.inode {
            self.inode.set_blocks(div_round_up(
                self.inode.size() + self.xattrs.aligned_size_v5() as u64,
                512,
            ));
        }
    }

    /// Delete an extend attribute with id `key`.
    pub fn remove_xattr(&mut self, key: &OsStr) {
        self.xattrs.remove(key);
        if self.xattrs.is_empty() {
            self.inode.set_has_xattr(false);
        }
    }
}

// Rafs v5 dedicated methods
impl Node {
    /// Dump RAFS v5 inode metadata to meta blob.
    pub fn dump_bootstrap_v5(
        &self,
        ctx: &mut BuildContext,
        f_bootstrap: &mut dyn RafsIoWrite,
    ) -> Result<()> {
        debug!("[{}]\t{}", self.overlay, self);

        if let InodeWrapper::V5(raw_inode) = &self.inode {
            // Dump inode info
            let name = self.name();
            let inode = RafsV5InodeWrapper {
                name,
                symlink: self.symlink.as_deref(),
                inode: raw_inode,
            };
            inode
                .store(f_bootstrap)
                .context("failed to dump inode to bootstrap")?;

            // Dump inode xattr
            if !self.xattrs.is_empty() {
                self.xattrs
                    .store_v5(f_bootstrap)
                    .context("failed to dump xattr to bootstrap")?;
                ctx.has_xattr = true;
            }

            // Dump chunk info
            if self.is_reg() && self.inode.child_count() as usize != self.chunks.len() {
                bail!("invalid chunk count {}: {}", self.chunks.len(), self);
            }
            for chunk in &self.chunks {
                chunk
                    .inner
                    .store(f_bootstrap)
                    .context("failed to dump chunk info to bootstrap")?;
                trace!("\t\tchunk: {} compressor {}", chunk, ctx.compressor,);
            }

            Ok(())
        } else {
            bail!("dump_bootstrap_v5() encounters non-v5-inode");
        }
    }

    // Filesystem may have different algorithms to calculate `i_size` for directory entries,
    // which may break "repeatable build". To support repeatable build, instead of reuse the value
    // provided by the source filesystem, we use our own algorithm to calculate `i_size` for
    // directory entries for stable `i_size`.
    //
    // Rafs v6 already has its own algorithm to calculate `i_size` for directory entries, but we
    // don't have directory entries for Rafs v5. So let's generate a pseudo `i_size` for Rafs v5
    // directory inode.
    pub fn v5_set_dir_size(&mut self, fs_version: RafsVersion, children: &[Tree]) {
        if !self.is_dir() || !fs_version.is_v5() {
            return;
        }

        let mut d_size = 0u64;
        for child in children.iter() {
            d_size += child.node.inode.name_size() as u64 + RAFS_V5_VIRTUAL_ENTRY_SIZE;
        }
        if d_size == 0 {
            self.inode.set_size(4096);
        } else {
            // Safe to unwrap() because we have u32 for child count.
            self.inode.set_size(try_round_up_4k(d_size).unwrap());
        }
        self.set_inode_blocks();
    }
}

// Rafs v6 dedicated methods
impl Node {
    /// Dump RAFS v6 inode metadata to meta blob.
    pub fn dump_bootstrap_v6(
        &mut self,
        ctx: &mut BuildContext,
        f_bootstrap: &mut dyn RafsIoWrite,
        orig_meta_addr: u64,
        meta_addr: u64,
        chunk_cache: &mut BTreeMap<DigestWithBlobIndex, ChunkWrapper>,
    ) -> Result<()> {
        let xattr_inline_count = self.xattrs.count_v6();
        ensure!(
            xattr_inline_count <= u16::MAX as usize,
            "size of extended attributes is too big"
        );
        let mut inode = new_v6_inode(
            &self.inode,
            self.v6_datalayout,
            xattr_inline_count as u16,
            self.v6_compact_inode,
        );

        let meta_offset = meta_addr - orig_meta_addr;
        // update all the inodes's offset according to the new 'meta_addr'.
        self.v6_offset += meta_offset;
        // The EROFS_INODE_FLAT_INLINE layout is valid for directory and symlink only, so
        // `dirents_offset` is useful for these two types too, otherwise `dirents_offset` should
        // always be zero. Enforce the check to avoid overflow of `dirents_offset`.
        if self.is_dir() || self.is_symlink() {
            self.v6_dirents_offset += meta_offset;
        }

        if self.is_dir() {
            self.v6_dump_dir(ctx, f_bootstrap, meta_addr, meta_offset, &mut inode)?;
        } else if self.is_reg() {
            self.v6_dump_file(ctx, f_bootstrap, chunk_cache, &mut inode)?;
        } else if self.is_symlink() {
            self.v6_dump_symlink(ctx, f_bootstrap, &mut inode)?;
        } else {
            f_bootstrap
                .seek(SeekFrom::Start(self.v6_offset))
                .context("failed seek for dir inode")?;
            inode.store(f_bootstrap).context("failed to store inode")?;
            self.v6_store_xattrs(ctx, f_bootstrap)?;
        }

        Ok(())
    }

    pub fn v6_dir_d_size(&self, tree: &Tree) -> Result<u64> {
        ensure!(self.is_dir(), "{} is not a directory", self);
        let mut d_size = 0;

        // Sort all children if "." and ".." are not at the head after sorting.
        if !tree.children.is_empty() && tree.children[0].node.name() < ".." {
            let mut children = Vec::with_capacity(tree.children.len() + 2);
            let dot = OsString::from(".");
            let dotdot = OsString::from("..");
            children.push(dot.as_os_str());
            children.push(dotdot.as_os_str());
            for child in tree.children.iter() {
                children.push(child.node.name());
            }
            children.sort_unstable();

            for c in children {
                // Use length in byte, instead of length in character.
                let len = c.as_bytes().len() + size_of::<RafsV6Dirent>();
                // erofs disk format requires dirent to be aligned to block size.
                if (d_size % EROFS_BLOCK_SIZE) + len as u64 > EROFS_BLOCK_SIZE {
                    d_size = round_up(d_size as u64, EROFS_BLOCK_SIZE);
                }
                d_size += len as u64;
            }
        } else {
            // Avoid sorting again if "." and ".." are at the head after sorting due to that
            // `tree.children` has already been sorted.
            d_size = (".".as_bytes().len()
                + size_of::<RafsV6Dirent>()
                + "..".as_bytes().len()
                + size_of::<RafsV6Dirent>()) as u64;
            for child in tree.children.iter() {
                let len = child.node.name().as_bytes().len() + size_of::<RafsV6Dirent>();
                // erofs disk format requires dirent to be aligned to block size.
                if (d_size % EROFS_BLOCK_SIZE) + len as u64 > EROFS_BLOCK_SIZE {
                    d_size = round_up(d_size as u64, EROFS_BLOCK_SIZE);
                }
                d_size += len as u64;
            }
        }

        Ok(d_size)
    }

    /// Set node offset in bootstrap and return the next position.
    pub fn v6_set_offset(
        &mut self,
        bootstrap_ctx: &mut BootstrapContext,
        v6_hardlink_offset: Option<u64>,
    ) {
        if self.is_reg() {
            if let Some(v6_hardlink_offset) = v6_hardlink_offset {
                self.v6_offset = v6_hardlink_offset;
            } else {
                let size = self.v6_size_with_xattr() as u64;
                let unit = size_of::<RafsV6InodeChunkAddr>() as u64;
                // We first try to allocate space from used blocks.
                // If no available used block exists, we allocate sequentially.
                let total_size = round_up(size, unit) + self.inode.child_count() as u64 * unit;
                self.v6_offset = bootstrap_ctx.allocate_available_block(total_size);
                if self.v6_offset == 0 {
                    self.v6_offset = bootstrap_ctx.offset;
                    bootstrap_ctx.offset += size;
                    bootstrap_ctx.align_offset(unit);
                    bootstrap_ctx.offset += self.inode.child_count() as u64 * unit;
                }
            }
            self.v6_datalayout = EROFS_INODE_CHUNK_BASED;
        } else if self.is_symlink() {
            self.v6_set_offset_with_tail(bootstrap_ctx, self.inode.size());
        } else {
            self.v6_offset = bootstrap_ctx.offset;
            bootstrap_ctx.offset += self.v6_size_with_xattr() as u64;
        }
    }

    pub fn v6_set_dir_offset(
        &mut self,
        bootstrap_ctx: &mut BootstrapContext,
        d_size: u64,
    ) -> Result<()> {
        ensure!(self.is_dir(), "{} is not a directory", self);

        // Dir isize is the total bytes of 'dirents + names'.
        self.inode.set_size(d_size);
        self.v6_set_offset_with_tail(bootstrap_ctx, d_size);

        Ok(())
    }

    fn v6_size_with_xattr(&self) -> usize {
        self.inode
            .get_inode_size_with_xattr(&self.xattrs, self.v6_compact_inode)
    }

    // For DIR inode, size is the total bytes of 'dirents + names'.
    // For symlink, size is the length of symlink name.
    fn v6_set_offset_with_tail(&mut self, bootstrap_ctx: &mut BootstrapContext, d_size: u64) {
        // TODO: a hashmap of non-full blocks

        //          |    avail       |
        // +--------+-----------+----+ +-----------------------+
        // |        |inode+tail | free |   dirents+names       |
        // |        |           |    | |                       |
        // +--------+-----------+----+ +-----------------------+
        //
        //          |    avail       |
        // +--------+-----------+----+ +-----------------------+ +---------+-------------+
        // |        |inode      | free |   dirents+names       | | tail    | free        |
        // |        |           |    | |                       | |         |             |
        // +--------+-----------+----+ +-----------------------+ +---------+-------------+
        //
        //
        //          |    avail       |
        // +--------+-----------+----+ +-----------------------+ +---------+-------------+
        // |        |     inode      + |   dirents+names       | | tail    | free        |
        // |        |                | |                       | |         |             |
        // +--------+-----------+----+ +-----------------------+ +---------+-------------+
        //
        //
        //          |    avail       |
        // +--------+----------------+ +--------------+--------+ +-----------------------+
        // |        |     inode      | |  inode+tail  | free   | | dirents+names         |
        // |        |                | |              |        | |                       |
        // +--------+----------------+ +--------------+--------+ +-----------------------+
        //          |         inode                   |
        //
        //          |    avail       |
        // +--------+----------------+ +--------------+--------+ +-----------------------+ +-------+---------------+
        // |        |     inode      | |  inode       | free   | | dirents+names         | | tail  |    free       |
        // |        |                | |              |        | |                       | |       |               |
        // +--------+----------------+ +--------------+--------+ +-----------------------+ +-------+---------------+
        //          |         inode                   |
        //
        //
        let inode_size = self.v6_size_with_xattr() as u64;
        let tail: u64 = d_size % EROFS_BLOCK_SIZE;

        // We use a simple inline strategy here:
        // If the inode size with xattr + tail data size <= EROFS_BLOCK_SIZE,
        // we choose to inline it.
        // Firstly, if it's bigger than EROFS_BLOCK_SIZE,
        // in most cases, we can assume that the tail data size is close to EROFS_BLOCK_SIZE,
        // in this condition, even if we don't inline the tail data, there won't be much waste.
        // Secondly, the `available_blocks` that we maintain in the `BootstrapCtx`,
        // since it contain only single blocks with some unused space, the available space can only
        // be smaller than EROFS_BLOCK_SIZE, therefore we can't use our used blocks to store the
        // inode plus the tail data bigger than EROFS_BLOCK_SIZE.
        let should_inline = tail != 0 && (inode_size + tail) <= EROFS_BLOCK_SIZE;

        // If should inline, we first try to allocate space for the inode together with tail data
        // using used blocks.
        // If no available used block exists, we try to allocate space from current block.
        // If current block doesn't have enough space, we append it to `available_blocks`,
        // and we allocate space from the next block.
        // For the remaining data, we allocate space for it sequentially.
        self.v6_datalayout = if should_inline {
            self.v6_offset = bootstrap_ctx.allocate_available_block(inode_size + tail);
            if self.v6_offset == 0 {
                let available = EROFS_BLOCK_SIZE - bootstrap_ctx.offset % EROFS_BLOCK_SIZE;
                if available < inode_size + tail {
                    bootstrap_ctx.append_available_block(bootstrap_ctx.offset);
                    bootstrap_ctx.align_offset(EROFS_BLOCK_SIZE);
                }

                self.v6_offset = bootstrap_ctx.offset;
                bootstrap_ctx.offset += inode_size + tail;
            }

            if d_size != tail {
                bootstrap_ctx.append_available_block(bootstrap_ctx.offset);
                bootstrap_ctx.align_offset(EROFS_BLOCK_SIZE);
            }
            self.v6_dirents_offset = bootstrap_ctx.offset;
            bootstrap_ctx.offset += round_down_4k(d_size);

            EROFS_INODE_FLAT_INLINE
        } else {
            // Otherwise, we first try to allocate space for the inode from used blocks.
            // If no available used block exists, we allocate space sequentially.
            // Then we allocate space for all data.
            self.v6_offset = bootstrap_ctx.allocate_available_block(inode_size);
            if self.v6_offset == 0 {
                self.v6_offset = bootstrap_ctx.offset;
                bootstrap_ctx.offset += inode_size;
            }

            bootstrap_ctx.append_available_block(bootstrap_ctx.offset);
            bootstrap_ctx.align_offset(EROFS_BLOCK_SIZE);
            self.v6_dirents_offset = bootstrap_ctx.offset;
            bootstrap_ctx.offset += d_size;
            bootstrap_ctx.align_offset(EROFS_BLOCK_SIZE);

            EROFS_INODE_FLAT_PLAIN
        };

        trace!(
            "{:?} inode offset {} ctx offset {} d_size {} dirents_offset {} datalayout {}",
            self.name(),
            self.v6_offset,
            bootstrap_ctx.offset,
            d_size,
            self.v6_dirents_offset,
            self.v6_datalayout
        );
    }

    fn v6_set_inode_compact(&mut self) {
        if self.v6_force_extended_inode
            || self.inode.uid() > u16::MAX as u32
            || self.inode.gid() > u16::MAX as u32
            || self.inode.nlink() > u16::MAX as u32
            || self.inode.size() > u32::MAX as u64
            || self.path.extension() == Some(OsStr::new("pyc"))
        {
            self.v6_compact_inode = false;
        } else {
            self.v6_compact_inode = true;
        }
    }

    fn v6_store_xattrs(
        &mut self,
        ctx: &mut BuildContext,
        f_bootstrap: &mut dyn RafsIoWrite,
    ) -> Result<()> {
        if !self.xattrs.is_empty() {
            self.xattrs
                .store_v6(f_bootstrap)
                .context("failed to dump xattr to bootstrap")?;
            ctx.has_xattr = true;
        }
        Ok(())
    }

    fn v6_dump_dir(
        &mut self,
        ctx: &mut BuildContext,
        f_bootstrap: &mut dyn RafsIoWrite,
        meta_addr: u64,
        meta_offset: u64,
        inode: &mut Box<dyn RafsV6OndiskInode>,
    ) -> Result<()> {
        // the 1st 4k block after dir inode.
        let mut dirent_off = self.v6_dirents_offset;
        inode.set_u((dirent_off / EROFS_BLOCK_SIZE) as u32);

        // Dump inode
        trace!("{:?} dir inode: offset {}", self.target, self.v6_offset);
        f_bootstrap
            .seek(SeekFrom::Start(self.v6_offset))
            .context("failed seek for dir inode")?;
        inode.store(f_bootstrap).context("failed to store inode")?;
        self.v6_store_xattrs(ctx, f_bootstrap)?;

        // Dump dirents
        let mut dir_data: Vec<u8> = Vec::new();
        let mut entry_names = Vec::new();
        let mut dirents: Vec<(RafsV6Dirent, &OsString)> = Vec::new();
        let mut nameoff: u64 = 0;
        let mut used: u64 = 0;

        trace!(
            "{:?} self.dirents.len {}",
            self.target,
            self.v6_dirents.len()
        );
        // fill dir blocks one by one
        for (offset, name, file_type) in self.v6_dirents.iter() {
            let len = name.len() + size_of::<RafsV6Dirent>();
            // write to bootstrap when it will exceed EROFS_BLOCK_SIZE
            if used + len as u64 > EROFS_BLOCK_SIZE {
                for (entry, name) in dirents.iter_mut() {
                    trace!("{:?} nameoff {}", name, nameoff);
                    entry.set_name_offset(nameoff as u16);
                    dir_data.extend(entry.as_ref());
                    entry_names.push(*name);
                    // Use length in byte, instead of length in character.
                    // Because some characters could occupy more than one byte.
                    nameoff += name.as_bytes().len() as u64;
                }
                for name in entry_names.iter() {
                    dir_data.extend(name.as_bytes());
                }

                f_bootstrap
                    .seek(SeekFrom::Start(dirent_off as u64))
                    .context("failed seek for dir inode")?;
                f_bootstrap
                    .write(dir_data.as_slice())
                    .context("failed to store dirents")?;

                dir_data.clear();
                entry_names.clear();
                dirents.clear();
                nameoff = 0;
                used = 0;
                // track where we're going to write.
                dirent_off += EROFS_BLOCK_SIZE;
            }

            trace!(
                "name {:?} file type {} {:?}",
                *name,
                *file_type,
                RafsV6Dirent::file_type(*file_type)
            );
            let entry = RafsV6Dirent::new(
                calculate_nid(*offset + meta_offset, meta_addr),
                0,
                RafsV6Dirent::file_type(*file_type),
            );
            dirents.push((entry, name));

            nameoff += size_of::<RafsV6Dirent>() as u64;
            used += len as u64;
        }

        trace!(
            "{:?} used {} dir size {}",
            self.target,
            used,
            self.inode.size()
        );
        // dump tail part if any
        if used > 0 {
            for (entry, name) in dirents.iter_mut() {
                trace!("{:?} tail nameoff {}", name, nameoff);
                entry.set_name_offset(nameoff as u16);
                dir_data.extend(entry.as_ref());
                entry_names.push(*name);
                nameoff += name.len() as u64;
            }
            for name in entry_names.iter() {
                dir_data.extend(name.as_bytes());
            }

            let tail_off = match self.v6_datalayout {
                EROFS_INODE_FLAT_INLINE => self.v6_offset + self.v6_size_with_xattr() as u64,
                EROFS_INODE_FLAT_PLAIN => dirent_off,
                _ => bail!("unsupported RAFS v6 inode layout for directory"),
            };
            f_bootstrap
                .seek(SeekFrom::Start(tail_off as u64))
                .context("failed seek for dir inode")?;
            f_bootstrap
                .write(dir_data.as_slice())
                .context("failed to store dirents")?;
        }

        Ok(())
    }

    fn v6_dump_file(
        &mut self,
        ctx: &mut BuildContext,
        f_bootstrap: &mut dyn RafsIoWrite,
        chunk_cache: &mut BTreeMap<DigestWithBlobIndex, ChunkWrapper>,
        inode: &mut Box<dyn RafsV6OndiskInode>,
    ) -> Result<()> {
        let mut is_continuous = true;
        let mut prev = None;

        // write chunk indexes, chunk contents has been written to blob file.
        let mut chunks: Vec<u8> = Vec::new();
        for chunk in self.chunks.iter() {
            let uncompressed_offset = chunk.inner.uncompressed_offset();
            let blob_idx = chunk.inner.blob_index();
            let mut v6_chunk = RafsV6InodeChunkAddr::new();
            v6_chunk.set_blob_index(blob_idx);
            v6_chunk.set_blob_ci_index(chunk.inner.index());
            v6_chunk.set_block_addr((uncompressed_offset / EROFS_BLOCK_SIZE) as u32);
            chunks.extend(v6_chunk.as_ref());
            chunk_cache.insert(
                DigestWithBlobIndex(*chunk.inner.id(), chunk.inner.blob_index() + 1),
                chunk.inner.clone(),
            );

            if let Some((prev_idx, prev_pos)) = prev {
                if prev_pos + ctx.chunk_size as u64 != uncompressed_offset || prev_idx != blob_idx {
                    is_continuous = false;
                }
            }
            prev = Some((blob_idx, uncompressed_offset));
        }

        // Special optimization to enable page cache sharing for EROFS.
        let chunk_size = if is_continuous && inode.size() > ctx.chunk_size as u64 {
            inode.size().next_power_of_two()
        } else {
            ctx.chunk_size as u64
        };
        let info = RafsV6InodeChunkHeader::new(chunk_size);
        inode.set_u(info.to_u32());

        f_bootstrap
            .seek(SeekFrom::Start(self.v6_offset))
            .context("failed seek for dir inode")?;
        inode.store(f_bootstrap).context("failed to store inode")?;
        self.v6_store_xattrs(ctx, f_bootstrap)?;

        // Dump chunk indexes
        let unit = size_of::<RafsV6InodeChunkAddr>() as u64;
        let chunk_off = align_offset(self.v6_offset + self.v6_size_with_xattr() as u64, unit);
        f_bootstrap
            .seek(SeekFrom::Start(chunk_off))
            .context("failed seek for dir inode")?;
        f_bootstrap
            .write(chunks.as_slice())
            .context("failed to write chunkindexes")?;

        Ok(())
    }

    fn v6_dump_symlink(
        &mut self,
        ctx: &mut BuildContext,
        f_bootstrap: &mut dyn RafsIoWrite,
        inode: &mut Box<dyn RafsV6OndiskInode>,
    ) -> Result<()> {
        let data_off = self.v6_dirents_offset;
        // TODO: check whether 'i_u' is used at all in case of inline symlink.
        inode.set_u((data_off / EROFS_BLOCK_SIZE) as u32);

        f_bootstrap
            .seek(SeekFrom::Start(self.v6_offset))
            .context("failed seek for symlink inode")?;
        inode.store(f_bootstrap).context("failed to store inode")?;
        self.v6_store_xattrs(ctx, f_bootstrap)?;

        // write symlink.
        if let Some(symlink) = &self.symlink {
            let tail_off = match self.v6_datalayout {
                EROFS_INODE_FLAT_INLINE => self.v6_offset + self.v6_size_with_xattr() as u64,
                EROFS_INODE_FLAT_PLAIN => data_off,
                _ => bail!("unsupported RAFS v5 inode layout for symlink"),
            };
            trace!("symlink write_off {}", tail_off);
            f_bootstrap
                .seek(SeekFrom::Start(tail_off))
                .context("failed seek for dir inode")?;
            f_bootstrap
                .write(symlink.as_bytes())
                .context("filed to store symlink")?;
        }

        Ok(())
    }
}

// OCI and Overlayfs whiteout handling.
impl Node {
    /// Check whether the inode is a special overlayfs whiteout file.
    pub fn is_overlayfs_whiteout(&self, spec: WhiteoutSpec) -> bool {
        if spec != WhiteoutSpec::Overlayfs {
            return false;
        }
        self.inode.is_chrdev()
            && nydus_utils::compact::major_dev(self.rdev) == 0
            && nydus_utils::compact::minor_dev(self.rdev) == 0
    }

    /// Check whether the inode (directory) is a overlayfs whiteout opaque.
    pub fn is_overlayfs_opaque(&self, spec: WhiteoutSpec) -> bool {
        if spec != WhiteoutSpec::Overlayfs || !self.is_dir() {
            return false;
        }

        // A directory is made opaque by setting the xattr "trusted.overlay.opaque" to "y".
        if let Some(v) = self.xattrs.get(&OsString::from(OVERLAYFS_WHITEOUT_OPAQUE)) {
            if let Ok(v) = std::str::from_utf8(v.as_slice()) {
                return v == "y";
            }
        }

        false
    }

    /// Get whiteout type to process the inode.
    pub fn whiteout_type(&self, spec: WhiteoutSpec) -> Option<WhiteoutType> {
        if self.overlay == Overlay::Lower {
            return None;
        }

        match spec {
            WhiteoutSpec::Oci => {
                if let Some(name) = self.name().to_str() {
                    if name == OCISPEC_WHITEOUT_OPAQUE {
                        return Some(WhiteoutType::OciOpaque);
                    } else if name.starts_with(OCISPEC_WHITEOUT_PREFIX) {
                        return Some(WhiteoutType::OciRemoval);
                    }
                }
            }
            WhiteoutSpec::Overlayfs => {
                if self.is_overlayfs_whiteout(spec) {
                    return Some(WhiteoutType::OverlayFsRemoval);
                } else if self.is_overlayfs_opaque(spec) {
                    return Some(WhiteoutType::OverlayFsOpaque);
                }
            }
            WhiteoutSpec::None => {
                return None;
            }
        }

        None
    }

    /// Get original filename from a whiteout filename.
    pub fn origin_name(&self, t: WhiteoutType) -> Option<&OsStr> {
        if let Some(name) = self.name().to_str() {
            if t == WhiteoutType::OciRemoval {
                // the whiteout filename prefixes the basename of the path to be deleted with ".wh.".
                return Some(OsStr::from_bytes(
                    name[OCISPEC_WHITEOUT_PREFIX.len()..].as_bytes(),
                ));
            } else if t == WhiteoutType::OverlayFsRemoval {
                // the whiteout file has the same name as the file to be deleted.
                return Some(name.as_ref());
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{ArtifactStorage, BootstrapContext};
    use nydus_rafs::metadata::layout::v6::{EROFS_INODE_CHUNK_BASED, EROFS_INODE_SLOT_SIZE};
    use nydus_rafs::metadata::RAFS_DEFAULT_CHUNK_SIZE;
    use std::fs::File;
    use vmm_sys_util::{tempdir::TempDir, tempfile::TempFile};

    #[test]
    fn test_set_v6_offset() {
        let pa = TempDir::new().unwrap();
        let pa_aa = TempFile::new_in(pa.as_path()).unwrap();
        let mut node = Node::new(
            RafsVersion::V6,
            pa.as_path().to_path_buf(),
            pa_aa.as_path().to_path_buf(),
            Overlay::UpperAddition,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            false,
            false,
        )
        .unwrap();

        let bootstrap_path = TempFile::new().unwrap();
        let storage = ArtifactStorage::SingleFile(bootstrap_path.as_path().to_path_buf());
        let mut bootstrap_ctx = BootstrapContext::new(Some(storage), false, false).unwrap();
        bootstrap_ctx.offset = 0;

        // reg file.
        // "1" is used only for testing purpose, in practice
        // it's always aligned to 32 bytes.
        node.v6_set_offset(&mut bootstrap_ctx, None);
        assert_eq!(node.v6_offset, 0);
        assert_eq!(node.v6_datalayout, EROFS_INODE_CHUNK_BASED);
        assert!(node.v6_compact_inode);
        assert_eq!(bootstrap_ctx.offset, 32);

        // symlink and dir are handled in the same way.
        let mut dir_node = Node::new(
            RafsVersion::V6,
            pa.as_path().to_path_buf(),
            pa.as_path().to_path_buf(),
            Overlay::UpperAddition,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            false,
            false,
        )
        .unwrap();

        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 4064)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_INLINE);
        assert_eq!(dir_node.v6_offset, 4096);
        assert_eq!(bootstrap_ctx.offset, 8192);

        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 4096)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_PLAIN);
        assert_eq!(dir_node.v6_offset, 32);
        assert_eq!(dir_node.v6_dirents_offset, 8192);
        assert_eq!(bootstrap_ctx.offset, 8192 + 4096);

        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 8160)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_INLINE);
        assert_eq!(dir_node.v6_offset, 8192 + 4096);
        assert_eq!(dir_node.v6_dirents_offset, 8192 + 4096 + 4096);
        assert_eq!(bootstrap_ctx.offset, 8192 + 4096 + 8192);

        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 8161)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_PLAIN);
        assert_eq!(dir_node.v6_offset, 64);
        assert_eq!(dir_node.v6_dirents_offset, 8192 + 4096 + 8192);
        assert_eq!(bootstrap_ctx.offset, 8192 + 4096 + 8192 + 8192);

        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 4096 + 3968)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_INLINE);
        assert_eq!(dir_node.v6_offset, 96);
        assert_eq!(dir_node.v6_dirents_offset, 8192 + 4096 + 8192 + 8192);
        assert_eq!(bootstrap_ctx.offset, 8192 + 4096 + 8192 + 8192 + 4096);

        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 4096 + 2048)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_INLINE);
        assert_eq!(dir_node.v6_offset, 8192 + 4096 + 8192 + 8192 + 4096);
        assert_eq!(
            dir_node.v6_dirents_offset,
            8192 + 4096 + 8192 + 8192 + 4096 + 4096
        );
        assert_eq!(
            bootstrap_ctx.offset,
            8192 + 4096 + 8192 + 8192 + 4096 + 8192
        );

        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 1985)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_INLINE);
        assert_eq!(dir_node.v6_offset, 8192 + 4096 + 8192 + 8192 + 4096 + 8192);
        assert_eq!(
            bootstrap_ctx.offset,
            8192 + 4096 + 8192 + 8192 + 4096 + 8192 + 32 + 1985
        );

        bootstrap_ctx.align_offset(EROFS_INODE_SLOT_SIZE as u64);
        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 1984)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_INLINE);
        assert_eq!(
            dir_node.v6_offset,
            8192 + 4096 + 8192 + 8192 + 4096 + 2048 + 32
        );
        assert_eq!(
            bootstrap_ctx.offset,
            8192 + 4096 + 8192 + 8192 + 4096 + 8192 + round_up(32 + 1985, 32)
        );
    }

    #[test]
    fn test_set_v6_inode_compact() {
        let pa = TempDir::new().unwrap();
        let pa_reg = TempFile::new_in(pa.as_path()).unwrap();
        let pa_pyc = pa.as_path().join("foo.pyc");
        let _ = File::create(&pa_pyc).unwrap();

        let reg_node = Node::new(
            RafsVersion::V6,
            pa.as_path().to_path_buf(),
            pa_reg.as_path().to_path_buf(),
            Overlay::UpperAddition,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            false,
            false,
        )
        .unwrap();

        assert!(reg_node.v6_compact_inode);

        let pyc_node = Node::new(
            RafsVersion::V6,
            pa.as_path().to_path_buf(),
            pa_pyc.as_path().to_path_buf(),
            Overlay::UpperAddition,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            false,
            false,
        )
        .unwrap();

        assert!(!pyc_node.v6_compact_inode);

        std::fs::remove_file(&pa_pyc).unwrap();
    }
}
