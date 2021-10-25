// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! An in-memory RAFS inode for image building and inspection.

use std::ffi::{OsStr, OsString};
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File};
use std::io::Read;
use std::os::linux::fs::MetadataExt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Error, Result};
use nix::sys::stat;
use sha2::digest::Digest;

use nydus_utils::{
    digest::{DigestHasher, RafsDigest},
    div_round_up, try_round_up_4k, ByteSize,
};
use rafs::metadata::cached_v5::{CachedChunkInfoV5, CachedInodeV5};
use rafs::metadata::direct_v5::{DirectChunkInfoV5, OndiskInodeWrapper};
use rafs::metadata::layout::v5::{
    RafsV5ChunkInfo, RafsV5Inode, RafsV5InodeFlags, RafsV5InodeWrapper,
};
use rafs::metadata::layout::RafsXAttrs;
use rafs::metadata::{Inode, RafsInode, RafsStore};
use rafs::RafsIoWriter;
use storage::compress;
use storage::device::v5::BlobV5ChunkInfo;
use storage::device::{BlobChunkFlags, BlobChunkInfo};

use super::chunk_dict::ChunkDict;
use super::context::{BlobContext, BuildContext};
use crate::core::context::RafsVersion;

const ROOT_PATH_NAME: &[u8] = &[b'/'];

/// Prefix for OCI whiteout file.
pub const OCISPEC_WHITEOUT_PREFIX: &str = ".wh.";
/// Prefix for OCI whiteout opaque.
pub const OCISPEC_WHITEOUT_OPAQUE: &str = ".wh..wh..opq";
/// Extended attribute key for Overlayfs whiteout opaque.
pub const OVERLAYFS_WHITEOUT_OPAQUE: &str = "trusted.overlay.opaque";

// # Overlayfs Whiteout
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

/// Rafs inode information to support image building and parsing.
#[derive(Clone)]
pub struct Node {
    /// Assigned RAFS inode number.
    pub index: u64,
    /// Device id associated with the source inode.
    ///
    /// A source directory may contain multiple partitions from different hard disk, so
    /// a pair of (dev, read_ino) is needed to uniquely identify an inode from source directory.
    pub src_dev: u64,
    /// Inode number of the source inode.
    pub src_ino: Inode,
    /// Device ID for special files, describing the device that this inode represents.
    pub rdev: u64,
    /// Define a disk inode structure to persist to disk.
    pub inode: InodeWraper,
    /// Chunks info list of regular file
    pub chunks: Vec<ChunkWrapper>,
    /// Extended attributes.
    pub xattrs: RafsXAttrs,
    /// Symlink info of symlink file
    pub symlink: Option<OsString>,
    /// Overlay type for layered build
    pub overlay: Overlay,
    /// Whether the explicit UID/GID feature is enabled or not.
    pub explicit_uidgid: bool,

    /// Absolute path of the source root directory.
    pub(crate) source: PathBuf,
    /// Absolute path of the source file/directory.
    pub(crate) path: PathBuf,
    /// Absolute path within the target RAFS filesystem.
    pub(crate) target: PathBuf,
    /// Parsed version of `target`.
    pub(crate) target_vec: Vec<OsString>,
}

impl Display for Node {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{} {:?}: index {} ino {} real_ino {} i_parent {} child_index {} child_count {} i_nlink {} i_size {} i_name_size {} i_symlink_size {} has_xattr {} link {:?}",
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
            self.inode.name_size(),
            self.inode.symlink_size(),
            self.inode.has_xattr(),
            self.symlink,
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
            inode: InodeWraper::new(version),
            chunks: Vec::new(),
            symlink: None,
            xattrs: RafsXAttrs::default(),
            explicit_uidgid,
        };

        node.build_inode(chunk_size)
            .context("failed to build inode")?;

        Ok(node)
    }

    /// Delete an extend attribute with id `key`.
    pub fn remove_xattr(&mut self, key: &OsStr) {
        self.xattrs.remove(key);
        if self.xattrs.is_empty() {
            self.inode.set_has_xattr(false);
        }
    }

    pub fn dump_blob<T: ChunkDict>(
        self: &mut Node,
        ctx: &BuildContext,
        blob_ctx: &mut BlobContext,
        blob_index: u32,
        chunk_dict: &mut T,
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

        let mut file = File::open(&self.path)
            .with_context(|| format!("failed to open node file {:?}", self.path))?;
        let mut inode_hasher = RafsDigest::hasher(ctx.digester);
        let mut blob_size = 0u64;

        // `child_count` of regular file is reused as `chunk_count`.
        for i in 0..self.inode.child_count() {
            let chunk_size = blob_ctx.chunk_size;
            let file_offset = i as u64 * chunk_size as u64;
            let chunk_size = if i == self.inode.child_count() - 1 {
                // Safe because size of last chunk is less than or equal to `chunk_size`.
                (self.inode.size() - (chunk_size as u64 * i as u64)) as u32
            } else {
                chunk_size
            };

            let chunk_index = blob_ctx.alloc_index()?;
            let mut chunk_data = &mut blob_ctx.chunk_data_buf[0..chunk_size as usize];
            file.read_exact(&mut chunk_data)
                .with_context(|| format!("failed to read node file {:?}", self.path))?;

            // TODO: check for hole chunks. One possible way is to always save
            // a global hole chunk and check for digest duplication
            let chunk_id = RafsDigest::from_buf(chunk_data, ctx.digester);
            inode_hasher.digest_update(chunk_id.as_ref());

            let mut chunk = self.inode.create_chunk();
            chunk.set_id(chunk_id);

            // Check whether we already have the same chunk data by matching chunk digest.
            let exist_chunk = blob_ctx
                .chunk_dict
                .get_chunk(&chunk_id)
                .or_else(|| chunk_dict.get_chunk(&chunk_id));
            if let Some(cached_chunk) = exist_chunk {
                // TODO: we should also compare the actual data to avoid chunk digest conflicts.
                // hole cached_chunk may have zero uncompressed size
                if cached_chunk.uncompressed_size() == 0
                    || cached_chunk.uncompressed_size() == chunk_size
                {
                    trace!(
                        "\t\tbuilding duplicated chunk: {} compressor {}",
                        chunk,
                        ctx.compressor
                    );
                    // The chunks of hardlink should be always deduplicated.
                    if !self.is_hardlink() {
                        event_tracer!("dedup_decompressed_size", +chunk_size);
                        event_tracer!("dedup_chunks", +1);
                    }

                    chunk.copy_from(cached_chunk);
                    chunk.set_file_offset(file_offset);
                    self.chunks.push(chunk);
                    continue;
                }
            }

            // Compress chunk data
            let (compressed, is_compressed) = compress::compress(&chunk_data, ctx.compressor)
                .with_context(|| format!("failed to compress node file {:?}", self.path))?;
            let compressed_size = compressed.len();

            chunk.set_chunk_info(
                blob_index,
                chunk_index,
                file_offset,
                blob_ctx.decompress_offset,
                blob_ctx.compress_offset,
                compressed_size,
                chunk_size,
                is_compressed,
            )?;

            // Move cursor to offset of next chunk
            let aligned_chunk_size = if ctx.aligned_chunk {
                // Safe to unwrap because `chunk_size` is much less than u32::MAX.
                try_round_up_4k(chunk_size).unwrap()
            } else {
                chunk_size
            };
            blob_ctx.compress_offset += compressed_size as u64;
            blob_ctx.decompressed_blob_size = blob_ctx.decompress_offset + chunk_size as u64;
            blob_ctx.compressed_blob_size += compressed_size as u64;
            blob_ctx.decompress_offset += aligned_chunk_size as u64;
            blob_ctx.blob_hash.update(&compressed);

            // Dump compressed chunk data to blob
            event_tracer!("blob_decompressed_size", +chunk_size);
            event_tracer!("blob_compressed_size", +compressed_size);
            if let Some(writer) = &mut blob_ctx.writer {
                writer
                    .write_all(&compressed)
                    .context("failed to write blob")?;
            }

            trace!(
                "\t\tbuilding chunk: {} compressor {}",
                chunk,
                ctx.compressor,
            );
            blob_ctx.add_chunk_meta_info(&chunk)?;
            chunk_dict.add_chunk(chunk.clone());
            self.chunks.push(chunk);
            blob_size += compressed_size as u64;
        }

        // Finish inode digest calculation
        self.inode.set_digest(inode_hasher.digest_finalize());

        Ok(blob_size)
    }

    pub fn dump_bootstrap_v5(&mut self, f_bootstrap: &mut RafsIoWriter) -> Result<usize> {
        let mut node_size = 0;
        let InodeWraper::V5(raw_inode) = &self.inode;

        // Dump inode info
        let name = self.name();
        let inode = RafsV5InodeWrapper {
            name,
            symlink: self.symlink.as_deref(),
            inode: raw_inode,
        };
        let inode_size = inode
            .store(f_bootstrap)
            .context("failed to dump inode to bootstrap")?;
        node_size += inode_size;

        // Dump inode xattr
        if !self.xattrs.is_empty() {
            let xattr_size = self
                .xattrs
                .store_v5(f_bootstrap)
                .context("failed to dump xattr to bootstrap")?;
            node_size += xattr_size;
        }

        // Dump chunk info
        if self.is_reg() && self.inode.child_count() as usize != self.chunks.len() {
            bail!("invalid chunks count {}: {}", self.chunks.len(), self);
        }

        for chunk in &mut self.chunks {
            let chunk_size = chunk
                .store(f_bootstrap)
                .context("failed to dump chunk info to bootstrap")?;
            node_size += chunk_size;
        }

        Ok(node_size)
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
            self.xattrs.add(key, value.unwrap_or_default());
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
        self.inode
            .set_inode_info(&meta, &self.xattrs, self.explicit_uidgid);

        Ok(())
    }

    fn build_inode(&mut self, chunk_size: u32) -> Result<()> {
        self.inode.set_name_size(self.name().byte_size());

        // NOTE: Always retrieve xattr before attr so that we can know the size of xattr pairs.
        self.build_inode_xattr()?;
        self.build_inode_stat()
            .with_context(|| format!("failed to build inode {:?}", self.path))?;

        if self.is_reg() {
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
}

// OCI and Overlayfs whiteout handling.
impl Node {
    /// Check whether the inode is a special overlayfs whiteout file.
    pub fn is_overlayfs_whiteout(&self, spec: WhiteoutSpec) -> bool {
        if spec != WhiteoutSpec::Overlayfs {
            return false;
        }

        self.inode.is_chrdev() && stat::major(self.rdev) == 0 && stat::minor(self.rdev) == 0
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

#[derive(Clone, Debug)]
pub enum InodeWraper {
    V5(RafsV5Inode),
}

impl InodeWraper {
    pub fn new(version: RafsVersion) -> Self {
        match version {
            RafsVersion::V5 => InodeWraper::V5(RafsV5Inode::new()),
            RafsVersion::V6 => todo!(),
        }
    }

    pub fn from_inode_info(inode: &Arc<dyn RafsInode>) -> Self {
        if let Some(inode) = inode.as_any().downcast_ref::<CachedInodeV5>() {
            InodeWraper::V5(to_rafsv5_inode(inode))
        } else if let Some(inode) = inode.as_any().downcast_ref::<OndiskInodeWrapper>() {
            InodeWraper::V5(to_rafsv5_inode(inode))
        } else {
            panic!("unknown chunk information struct");
        }
    }

    pub fn inode_size(&self) -> usize {
        match self {
            InodeWraper::V5(i) => i.size(),
        }
    }

    pub fn is_dir(&self) -> bool {
        match self {
            InodeWraper::V5(i) => i.is_dir(),
        }
    }

    pub fn is_reg(&self) -> bool {
        match self {
            InodeWraper::V5(i) => i.is_reg(),
        }
    }

    pub fn is_hardlink(&self) -> bool {
        match self {
            InodeWraper::V5(i) => i.is_hardlink(),
        }
    }

    pub fn is_symlink(&self) -> bool {
        match self {
            InodeWraper::V5(i) => i.is_symlink(),
        }
    }

    pub fn is_chrdev(&self) -> bool {
        match self {
            InodeWraper::V5(i) => i.i_mode & libc::S_IFMT == libc::S_IFCHR,
        }
    }

    pub fn is_blkdev(&self) -> bool {
        match self {
            InodeWraper::V5(i) => i.i_mode & libc::S_IFMT == libc::S_IFBLK,
        }
    }

    pub fn is_fifo(&self) -> bool {
        match self {
            InodeWraper::V5(i) => i.i_mode & libc::S_IFMT == libc::S_IFIFO,
        }
    }

    pub fn is_special(&self) -> bool {
        self.is_chrdev() || self.is_blkdev() || self.is_fifo()
    }

    pub fn has_xattr(&self) -> bool {
        match self {
            InodeWraper::V5(i) => i.has_xattr(),
        }
    }

    pub fn set_has_xattr(&mut self, enable: bool) {
        match self {
            InodeWraper::V5(i) => {
                if enable {
                    i.i_flags |= RafsV5InodeFlags::XATTR;
                } else {
                    i.i_flags &= !RafsV5InodeFlags::XATTR;
                }
            }
        }
    }

    pub fn ino(&self) -> Inode {
        match self {
            InodeWraper::V5(i) => i.i_ino,
        }
    }

    pub fn set_ino(&mut self, ino: Inode) {
        match self {
            InodeWraper::V5(i) => i.i_ino = ino,
        }
    }

    pub fn parent(&self) -> Inode {
        match self {
            InodeWraper::V5(i) => i.i_parent,
        }
    }

    pub fn set_parent(&mut self, parent: Inode) {
        match self {
            InodeWraper::V5(i) => i.i_parent = parent,
        }
    }

    pub fn size(&self) -> u64 {
        match self {
            InodeWraper::V5(i) => i.i_size,
        }
    }

    pub fn set_size(&mut self, size: u64) {
        match self {
            InodeWraper::V5(i) => i.i_size = size,
        }
    }

    pub fn nlink(&self) -> u32 {
        match self {
            InodeWraper::V5(i) => i.i_nlink,
        }
    }

    pub fn set_nlink(&mut self, nlink: u32) {
        match self {
            InodeWraper::V5(i) => i.i_nlink = nlink,
        }
    }

    pub fn digest(&self) -> &RafsDigest {
        match self {
            InodeWraper::V5(i) => &i.i_digest,
        }
    }

    pub fn set_digest(&mut self, digest: RafsDigest) {
        match self {
            InodeWraper::V5(i) => i.i_digest = digest,
        }
    }

    pub fn name_size(&self) -> u16 {
        match self {
            InodeWraper::V5(i) => i.i_name_size,
        }
    }

    fn set_name_size(&mut self, size: usize) {
        debug_assert!(size < u16::MAX as usize);
        match self {
            InodeWraper::V5(i) => i.i_name_size = size as u16,
        }
    }

    pub fn symlink_size(&self) -> u16 {
        match self {
            InodeWraper::V5(i) => i.i_symlink_size,
        }
    }

    pub fn set_symlink_size(&mut self, size: usize) {
        debug_assert!(size <= u16::MAX as usize);
        match self {
            InodeWraper::V5(i) => {
                i.i_flags |= RafsV5InodeFlags::SYMLINK;
                i.i_symlink_size = size as u16;
            }
        }
    }

    pub fn child_index(&self) -> u32 {
        match self {
            InodeWraper::V5(i) => i.i_child_index,
        }
    }

    pub fn set_child_index(&mut self, index: u32) {
        match self {
            InodeWraper::V5(i) => i.i_child_index = index,
        }
    }

    pub fn child_count(&self) -> u32 {
        match self {
            InodeWraper::V5(i) => i.i_child_count,
        }
    }

    pub fn set_child_count(&mut self, count: u32) {
        match self {
            InodeWraper::V5(i) => i.i_child_count = count,
        }
    }

    fn set_inode_info<T: MetadataExt>(
        &mut self,
        meta: &T,
        xattrs: &RafsXAttrs,
        explicit_uidgid: bool,
    ) {
        match self {
            InodeWraper::V5(i) => {
                i.i_mode = meta.st_mode();
                if explicit_uidgid {
                    i.i_uid = meta.st_uid();
                    i.i_gid = meta.st_gid();
                }
                i.i_mtime = meta.st_mtime() as u64;
                i.i_mtime_nsec = meta.st_mtime_nsec() as u32;
                i.i_projid = 0;
                i.i_size = meta.st_size();
                i.i_rdev = meta.st_rdev() as u32;
                // Ignore actual nlink value and calculate from rootfs directory instead
                i.i_nlink = 1;

                // Xattr paris are located into bootstrap rather than blob, however, we should
                // also reflect the size they consume like other file system. We don't
                // directly use local file's metadata for `i_block` since we are purchasing
                // "reproducible build" which means nydus image can be built from anywhere with
                // the unique image built.
                i.i_blocks = div_round_up(i.i_size + xattrs.aligned_size_v5() as u64, 512);
            }
        }
    }

    fn create_chunk(&self) -> ChunkWrapper {
        match self {
            InodeWraper::V5(_) => ChunkWrapper::V5(RafsV5ChunkInfo::new()),
        }
    }
}

#[derive(Clone, Debug)]
pub enum ChunkWrapper {
    V5(RafsV5ChunkInfo),
}

impl ChunkWrapper {
    #[cfg(test)]
    pub fn new(version: RafsVersion) -> Self {
        match version {
            RafsVersion::V5 => ChunkWrapper::V5(RafsV5ChunkInfo::default()),
            RafsVersion::V6 => todo!(),
        }
    }

    pub fn from_chunk_info(cki: &Arc<dyn BlobChunkInfo>) -> Self {
        if let Some(cki_v5) = cki.as_any().downcast_ref::<CachedChunkInfoV5>() {
            ChunkWrapper::V5(to_rafsv5_chunk_info(cki_v5))
        } else if let Some(cki_v5) = cki.as_any().downcast_ref::<DirectChunkInfoV5>() {
            ChunkWrapper::V5(to_rafsv5_chunk_info(cki_v5))
        } else {
            panic!("unknown chunk information struct");
        }
    }

    pub fn id(&self) -> &RafsDigest {
        match self {
            ChunkWrapper::V5(c) => &c.block_id,
        }
    }

    pub fn set_id(&mut self, id: RafsDigest) {
        match self {
            ChunkWrapper::V5(c) => c.block_id = id,
        }
    }

    pub fn index(&self) -> u32 {
        match self {
            ChunkWrapper::V5(c) => c.index,
        }
    }

    pub fn set_index(&mut self, index: u32) {
        match self {
            ChunkWrapper::V5(c) => c.index = index,
        }
    }

    pub fn blob_index(&self) -> u32 {
        match self {
            ChunkWrapper::V5(c) => c.blob_index,
        }
    }

    pub fn set_blob_index(&mut self, index: u32) {
        match self {
            ChunkWrapper::V5(c) => c.blob_index = index,
        }
    }

    pub fn compressed_offset(&self) -> u64 {
        match self {
            ChunkWrapper::V5(c) => c.compress_offset,
        }
    }

    pub fn compressed_size(&self) -> u32 {
        match self {
            ChunkWrapper::V5(c) => c.compress_size,
        }
    }

    pub fn uncompressed_offset(&self) -> u64 {
        match self {
            ChunkWrapper::V5(c) => c.uncompress_offset,
        }
    }

    pub fn uncompressed_size(&self) -> u32 {
        match self {
            ChunkWrapper::V5(c) => c.uncompress_size,
        }
    }

    pub fn file_offset(&self) -> u64 {
        match self {
            ChunkWrapper::V5(c) => c.file_offset,
        }
    }

    pub fn set_file_offset(&mut self, offset: u64) {
        match self {
            ChunkWrapper::V5(c) => c.file_offset = offset,
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[inline]
    fn set_chunk_info(
        &mut self,
        blob_index: u32,
        chunk_index: u32,
        file_offset: u64,
        uncompressed_offset: u64,
        compressed_offset: u64,
        compressed_size: usize,
        chunk_size: u32,
        is_compressed: bool,
    ) -> Result<()> {
        match self {
            ChunkWrapper::V5(c) => {
                c.index = chunk_index;
                c.blob_index = blob_index;
                c.file_offset = file_offset;
                c.compress_size = compressed_size as u32;
                c.compress_offset = compressed_offset;
                c.uncompress_size = chunk_size;
                c.uncompress_offset = uncompressed_offset;
                if is_compressed {
                    c.flags |= BlobChunkFlags::COMPRESSED;
                }
            }
        }

        Ok(())
    }

    fn copy_from(&mut self, other: &Self) {
        match (self, other) {
            (ChunkWrapper::V5(s), ChunkWrapper::V5(o)) => {
                s.clone_from(o);
            }
        }
    }

    fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        match self {
            ChunkWrapper::V5(c) => c.store(w).context("failed to store rafs v5 chunk"),
        }
    }
}

impl Display for ChunkWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "id {}, index {}, blob_index {}, file_offset {}, compressed {}/{}, uncompressed {}/{}",
            self.id(),
            self.index(),
            self.blob_index(),
            self.file_offset(),
            self.compressed_offset(),
            self.compressed_size(),
            self.uncompressed_offset(),
            self.uncompressed_size(),
        )
    }
}

/// Construct a `RafsV5Inode` object from a `Arc<dyn RafsInode>` object.
fn to_rafsv5_inode(inode: &dyn RafsInode) -> RafsV5Inode {
    let attr = inode.get_attr();

    RafsV5Inode {
        i_digest: inode.get_digest(),
        i_parent: inode.parent(),
        i_ino: attr.ino,
        i_uid: attr.uid,
        i_gid: attr.gid,
        i_projid: inode.projid(),
        i_mode: attr.mode,
        i_size: attr.size,
        i_blocks: attr.blocks,
        i_flags: RafsV5InodeFlags::from_bits_truncate(inode.flags()),
        i_nlink: attr.nlink,
        i_child_index: inode.get_child_index().unwrap_or(0),
        i_child_count: inode.get_child_count(),
        i_name_size: inode.get_name_size(),
        i_symlink_size: inode.get_symlink_size(),
        i_rdev: attr.rdev,
        i_mtime_nsec: attr.mtimensec,
        i_mtime: attr.mtime,
        i_reserved: [0u8; 8],
    }
}

/// Construct a `RafsV5ChunkInfo` object from a `dyn RafsChunkInfo` object.
fn to_rafsv5_chunk_info(cki: &dyn BlobV5ChunkInfo) -> RafsV5ChunkInfo {
    RafsV5ChunkInfo {
        block_id: *cki.chunk_id(),
        blob_index: cki.blob_index(),
        flags: cki.flags(),
        compress_size: cki.compress_size(),
        uncompress_size: cki.uncompress_size(),
        compress_offset: cki.compress_offset(),
        uncompress_offset: cki.uncompress_offset(),
        file_offset: cki.file_offset(),
        index: cki.index(),
        reserved: 0u32,
    }
}
