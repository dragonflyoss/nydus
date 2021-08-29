// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Node structure to store information for RAFS file system inode.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File};
use std::io::prelude::*;
use std::os::linux::fs::MetadataExt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::str;
use std::str::FromStr;

use anyhow::{Context, Error, Result};
use nix::sys::stat;
use sha2::digest::Digest;

use nydus_utils::{
    digest::{DigestHasher, RafsDigest},
    div_round_up, try_round_up_4k, ByteSize,
};
use rafs::metadata::layout::v5::{
    RafsChunkFlags, RafsV5ChunkInfo, RafsV5Inode, RafsV5InodeFlags, RafsV5InodeWrapper,
    RafsV5XAttrs,
};
use rafs::metadata::{Inode, RafsStore, RAFS_DEFAULT_BLOCK_SIZE};
use rafs::RafsIoWriter;
use storage::compress;

use crate::core::blob::{BlobBufferWriter, BlobCompInfo};
use crate::core::context::BuildContext;

const ROOT_PATH_NAME: &[u8] = &[b'/'];

pub const OCISPEC_WHITEOUT_PREFIX: &str = ".wh.";
pub const OCISPEC_WHITEOUT_OPAQUE: &str = ".wh..wh..opq";
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

impl fmt::Display for Overlay {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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
pub struct Node {
    /// Allocated RAFS inode number.
    pub index: u64,
    /// Inode number in local filesystem
    pub real_ino: Inode,
    /// dev number is required because a source root directory can have multiple
    /// partitions mounted. Files from different partition can have unique inode number.
    pub dev: u64,
    /// device ID (if special file), describes the device that this file (inode) represents.
    pub rdev: u64,
    /// Overlay type for layered build
    pub overlay: Overlay,
    /// Absolute path to root directory where start to build image.
    /// For example: /home/source
    pub source: PathBuf,
    /// Absolute path to each file within target image.
    /// For example: /foo/bar
    pub target: PathBuf,
    /// Absolute path to each file within build context directory.
    /// Together with `source`, we can easily get relative path to `source`.
    /// For example: /home/source/foo/bar
    pub path: PathBuf,
    pub path_vec: Vec<OsString>,
    /// Define a disk inode structure to persist to disk.
    pub inode: RafsV5Inode,
    /// Chunks info list of regular file
    pub chunks: Vec<RafsV5ChunkInfo>,
    /// Xattr list of file
    pub xattrs: RafsV5XAttrs,
    /// Symlink info of symlink file
    pub symlink: Option<OsString>,
    pub explicit_uidgid: bool,
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {:?}: index {} ino {} real_ino {} i_parent {} child_index {} child_count {} i_nlink {} i_size {} i_name_size {} i_symlink_size {} has_xattr {} link {:?}",
            self.file_type(),
            self.target(),
            self.index,
            self.inode.i_ino,
            self.real_ino,
            self.inode.i_parent,
            self.inode.i_child_index,
            self.inode.i_child_count,
            self.inode.i_nlink,
            self.inode.i_size,
            self.inode.i_name_size,
            self.inode.i_symlink_size,
            self.inode.has_xattr(),
            self.symlink,
        )
    }
}

impl Node {
    pub fn new(
        source: PathBuf,
        path: PathBuf,
        overlay: Overlay,
        explicit_uidgid: bool,
    ) -> Result<Node> {
        let target = Self::generate_target(&path, &source);
        let path_vec = Self::generate_path_vec(&target);

        let mut node = Node {
            index: 0,
            real_ino: 0,
            dev: u64::MAX,
            rdev: u64::MAX,
            source,
            target,
            path,
            path_vec,
            overlay,
            inode: RafsV5Inode::new(),
            chunks: Vec::new(),
            symlink: None,
            xattrs: RafsV5XAttrs::default(),
            explicit_uidgid,
        };

        node.build_inode().context("failed to build inode")?;

        Ok(node)
    }

    pub fn remove_xattr(&mut self, key: &OsStr) {
        self.xattrs.remove(key);
        if self.xattrs.is_empty() {
            self.inode.i_flags.remove(RafsV5InodeFlags::XATTR);
        }
    }

    pub fn dump_blob(
        index: usize,
        ctx: &mut BuildContext,
        blob_writer: &mut BlobBufferWriter,
        comp_info: &mut BlobCompInfo,
    ) -> Result<u64> {
        let node = &mut ctx.nodes[index];

        if node.is_dir() {
            return Ok(0);
        } else if node.is_symlink() {
            node.inode.i_digest =
                RafsDigest::from_buf(node.symlink.as_ref().unwrap().as_bytes(), ctx.digester);
            return Ok(0);
        } else if node.is_special() {
            node.inode.i_digest = RafsDigest::hasher(ctx.digester).digest_finalize();
            return Ok(0);
        }

        let mut blob_size = 0u64;
        let mut inode_hasher = RafsDigest::hasher(ctx.digester);
        let mut file = File::open(&node.path)
            .with_context(|| format!("failed to open node file {:?}", node.path))?;

        for i in 0..node.inode.i_child_count {
            // FIXME: Should not assume that block size must be the default one.
            // Use the configured value instead!
            let file_offset = i as u64 * RAFS_DEFAULT_BLOCK_SIZE;
            let chunk_size = if i == node.inode.i_child_count - 1 {
                node.inode.i_size - (RAFS_DEFAULT_BLOCK_SIZE * i as u64)
            } else {
                RAFS_DEFAULT_BLOCK_SIZE
            };
            let mut chunk = RafsV5ChunkInfo::new();

            let mut chunk_data = &mut ctx.chunk_data_buf[0..chunk_size as usize];
            file.read_exact(&mut chunk_data)
                .with_context(|| format!("failed to read node file {:?}", node.path))?;

            // Calculate chunk digest
            // TODO: check for hole chunks. One possible way is to always save
            // a global hole chunk and check for digest duplication
            chunk.block_id = RafsDigest::from_buf(chunk_data, ctx.digester);
            // Calculate inode digest
            inode_hasher.digest_update(chunk.block_id.as_ref());

            // Check whether we already have the same chunk data by matching chunk digest.
            if let Some(cached_chunk) = ctx.chunk_cache.get(&chunk.block_id) {
                // TODO: we should also compare the actual data to avoid chunk digest confliction.
                // hole cached_chunk can have zero decompress size
                if cached_chunk.decompress_size == 0
                    || cached_chunk.decompress_size == chunk_size as u32
                {
                    chunk.clone_from(&cached_chunk);
                    chunk.file_offset = file_offset;
                    node.chunks.push(chunk);
                    trace!(
                        "\t\tbuilding duplicated chunk: {} compressor {}",
                        chunk,
                        ctx.compressor
                    );

                    // The chunks of hardlink should be always deduplicated, so don't
                    // trace this situation here.
                    if !node.is_hardlink() {
                        event_tracer!("dedup_decompressed_size", +chunk_size);
                        event_tracer!("dedup_chunks", +1);
                    }

                    ctx.blob_info_map.inc_ref_count(chunk.blob_index);

                    continue;
                }
            }

            // Compress chunk data
            let (compressed, is_compressed) = compress::compress(&chunk_data, ctx.compressor)
                .with_context(|| format!("failed to compress node file {:?}", node.path))?;
            let compressed_size = compressed.len();
            if is_compressed {
                chunk.flags |= RafsChunkFlags::COMPRESSED;
            }

            chunk.blob_index = ctx.blob_index;
            chunk.file_offset = file_offset;
            chunk.compress_offset = comp_info.compress_offset;
            chunk.decompress_offset = comp_info.decompress_offset;
            chunk.compress_size = compressed_size as u32;
            chunk.decompress_size = chunk_size as u32;
            chunk.index = ctx.blob_info_map.alloc_index(ctx.blob_index)?;
            blob_size += compressed_size as u64;

            // Move cursor to offset of next chunk
            let aligned_chunk_size = if ctx.aligned_chunk {
                // Safe to unwrap since we can't have such a large chunk
                // and conversion between u64 values is safe.
                try_round_up_4k(chunk_size).unwrap()
            } else {
                chunk_size
            };
            comp_info.compress_offset += compressed_size as u64;
            comp_info.decompressed_blob_size = comp_info.decompress_offset + chunk_size;
            comp_info.compressed_blob_size += compressed_size as u64;
            comp_info.decompress_offset += aligned_chunk_size;
            comp_info.blob_hash.update(&compressed);

            // Dump compressed chunk data to blob
            event_tracer!("blob_decompressed_size", +chunk_size);
            event_tracer!("blob_compressed_size", +compressed_size);
            blob_writer
                .write_all(&compressed)
                .context("failed to write blob")?;

            // Cache chunk digest info
            ctx.chunk_cache.insert(chunk.block_id, chunk);
            node.chunks.push(chunk);

            trace!(
                "\t\tbuilding chunk: {} compressor {}",
                chunk,
                ctx.compressor,
            );
        }

        // Finish inode digest calculation
        node.inode.i_digest = inode_hasher.digest_finalize();

        Ok(blob_size)
    }

    pub fn dump_bootstrap_v5(&mut self, f_bootstrap: &mut RafsIoWriter) -> Result<usize> {
        let mut node_size = 0;

        // Dump inode info
        let name = self.name();
        let inode = RafsV5InodeWrapper {
            name,
            symlink: self.symlink.as_deref(),
            inode: &self.inode,
        };
        let inode_size = inode
            .store(f_bootstrap)
            .context("failed to dump inode to bootstrap")?;
        node_size += inode_size;

        // Dump inode xattr
        if !self.xattrs.is_empty() {
            let xattr_size = self
                .xattrs
                .store(f_bootstrap)
                .context("failed to dump xattr to bootstrap")?;
            node_size += xattr_size;
        }

        // Dump chunk info
        if self.is_reg() && self.inode.i_child_count as usize != self.chunks.len() {
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
            self.inode.i_flags |= RafsV5InodeFlags::XATTR;
        }

        Ok(())
    }

    fn build_inode_stat(&mut self) -> Result<()> {
        let meta = self.meta()?;

        self.inode.i_mode = meta.st_mode();
        if self.explicit_uidgid {
            self.inode.i_uid = meta.st_uid();
            self.inode.i_gid = meta.st_gid();
        }
        self.inode.i_mtime = meta.st_mtime() as u64;
        self.inode.i_mtime_nsec = meta.st_mtime_nsec() as u32;
        self.inode.i_projid = 0;
        self.inode.i_size = meta.st_size();
        // Ignore actual nlink value and calculate from rootfs directory instead
        self.inode.i_nlink = 1;

        // Xattr paris are located into bootstrap rather than blob, however, we should
        // also reflect the size they consume like other file system. We don't
        // directly use local file's metadata for `i_block` since we are purchasing
        // "reproducible build" which means nydus image can be built from anywhere with
        // the unique image built.
        // TODO: The real size occupied within blob is compressed. Therefore, the
        // sum of all chunks' size should be more accurate. But we don't know the size
        // right now since compression is not acted yet. Try to make this accurate later.
        self.inode.i_blocks =
            div_round_up(self.inode.i_size + self.xattrs.aligned_size() as u64, 512);
        self.inode.i_rdev = meta.st_rdev() as u32;

        self.real_ino = meta.st_ino();
        self.dev = meta.st_dev();
        self.rdev = meta.st_rdev();

        Ok(())
    }

    fn build_inode(&mut self) -> Result<()> {
        self.inode.set_name_size(self.name().byte_size());

        // NOTE: Always retrieve xattr before attr so that we can know
        // the size of xattr pairs.
        self.build_inode_xattr()?;
        self.build_inode_stat()
            .with_context(|| format!("failed to build inode {:?}", self.path))?;

        if self.is_reg() {
            self.inode.i_child_count = self.chunk_count() as u32;
        } else if self.is_symlink() {
            self.inode.i_flags |= RafsV5InodeFlags::SYMLINK;
            let target_path = fs::read_link(&self.path)?;
            let symlink: OsString = target_path.into();
            let size = symlink.byte_size();
            self.symlink = Some(symlink);
            self.inode.set_symlink_size(size);
        }

        Ok(())
    }

    fn meta(&self) -> Result<impl MetadataExt> {
        self.path
            .symlink_metadata()
            .with_context(|| format!("failed to get metadata from {:?}", self.path))
    }

    pub fn is_dir(&self) -> bool {
        self.inode.i_mode & libc::S_IFMT == libc::S_IFDIR
    }

    pub fn is_symlink(&self) -> bool {
        self.inode.i_mode & libc::S_IFMT == libc::S_IFLNK
    }

    pub fn is_reg(&self) -> bool {
        self.inode.i_mode & libc::S_IFMT == libc::S_IFREG
    }

    pub fn is_special(&self) -> bool {
        self.inode.i_mode & (libc::S_IFBLK | libc::S_IFCHR | libc::S_IFIFO) != 0
    }

    pub fn is_hardlink(&self) -> bool {
        self.inode.i_nlink > 1
    }

    pub fn chunk_count(&self) -> usize {
        if !self.is_reg() {
            return 0;
        }
        div_round_up(self.inode.i_size, RAFS_DEFAULT_BLOCK_SIZE) as usize
    }

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

    /// Generate the path relative to original rootfs.
    /// For example:
    /// `/absolute/path/to/rootfs/file` after converting `/file`
    pub fn generate_target(path: &PathBuf, root: &PathBuf) -> PathBuf {
        if let Ok(p) = path.strip_prefix(root) {
            Path::new("/").join(p)
        } else {
            // Compatible with path `/`
            path.clone()
        }
    }

    pub fn target(&self) -> &PathBuf {
        &self.target
    }

    pub fn name(&self) -> &OsStr {
        if self.path == self.source {
            OsStr::from_bytes(ROOT_PATH_NAME)
        } else {
            // Safe to unwrap because `path` should be returned from `path()` which is canonicalized
            self.path.file_name().unwrap()
        }
    }

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

    pub fn generate_path_vec(target: &PathBuf) -> Vec<OsString> {
        target
            .components()
            .map(|comp| match comp {
                Component::RootDir => OsString::from("/"),
                Component::Normal(name) => name.to_os_string(),
                _ => panic!("invalid file component pattern!"),
            })
            .collect::<Vec<_>>()
    }

    pub fn path_vec(&self) -> &[OsString] {
        &self.path_vec
    }

    pub fn is_overlayfs_whiteout(&self, spec: WhiteoutSpec) -> bool {
        if spec != WhiteoutSpec::Overlayfs {
            return false;
        }

        (self.inode.i_mode & libc::S_IFMT == libc::S_IFCHR)
            && stat::major(self.rdev) == 0
            && stat::minor(self.rdev) == 0
    }

    pub fn is_overlayfs_opaque(&self, spec: WhiteoutSpec) -> bool {
        if spec != WhiteoutSpec::Overlayfs {
            return false;
        }

        // A directory is made opaque by setting the xattr
        // "trusted.overlay.opaque" to "y".
        if let Some(v) = self.xattrs.get(&OsString::from(OVERLAYFS_WHITEOUT_OPAQUE)) {
            if let Ok(v) = std::str::from_utf8(v.as_slice()) {
                return v == "y";
            }
        }

        false
    }

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
}
