// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! An in-memory RAFS inode for image building and inspection.

use std::ffi::{OsStr, OsString};
use std::fmt::{self, Display, Formatter, Result as FmtResult};
use std::fs::{self, File};
use std::io::Read;
use std::io::SeekFrom;
use std::mem::size_of;
use std::os::linux::fs::MetadataExt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Error, Result};
use nix::sys::stat;
use sha2::digest::Digest;

use nydus_utils::{
    compress,
    digest::{DigestHasher, RafsDigest},
    div_round_up, try_round_up_4k, ByteSize,
};
use rafs::metadata::cached_v5::{CachedChunkInfoV5, CachedInodeV5};
use rafs::metadata::direct_v5::{DirectChunkInfoV5, OndiskInodeWrapper};
use rafs::metadata::direct_v6::DirectChunkInfoV6;
use rafs::metadata::layout::v5::{
    RafsV5ChunkInfo, RafsV5Inode, RafsV5InodeFlags, RafsV5InodeWrapper,
};
use rafs::metadata::layout::v6::{
    align_offset, calculate_nid, RafsV6Dirent, RafsV6InodeChunkAddr, RafsV6InodeChunkHeader,
    RafsV6InodeCompact, RafsV6InodeExtended, RafsV6OndiskInode, EROFS_BLOCK_SIZE,
    EROFS_INODE_CHUNK_BASED, EROFS_INODE_FLAT_INLINE, EROFS_INODE_FLAT_PLAIN,
};
use rafs::metadata::layout::RafsXAttrs;
use rafs::metadata::{Inode, RafsInode, RafsStore};
use rafs::RafsIoWrite;
use storage::device::v5::BlobV5ChunkInfo;
use storage::device::{BlobChunkFlags, BlobChunkInfo};

use super::chunk_dict::ChunkDict;
use super::context::{BlobContext, BootstrapContext, BuildContext, RafsVersion};
use super::tree::Tree;

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

/// ChunkSource flags chunk original source in bootstrap.
#[derive(Clone, Hash, PartialEq, Eq)]
pub enum ChunkSource {
    /// Chunk from parent boostrap.
    Parent,
    /// Chunk from this build workflow.
    Build,
    /// Chunk from chunk dict bootstrap.
    Dict,
}

impl Display for ChunkSource {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Parent => write!(f, "parent"),
            Self::Build => write!(f, "build"),
            Self::Dict => write!(f, "dict"),
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
    pub inode: InodeWrapper,
    /// Chunks info list of regular file
    pub chunks: Vec<NodeChunk>,
    /// Extended attributes.
    pub xattrs: RafsXAttrs,
    /// Symlink info of symlink file
    pub symlink: Option<OsString>,
    /// Overlay type for layered build
    pub overlay: Overlay,
    /// Whether it's a compact inode or an extended inode.
    pub v6_compact_inode: bool,
    /// Whether it forcely uses an extended inode.
    pub v6_force_extended_inode: bool,
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
    /// Last status change time of the file, in nanoseconds.
    pub ctime: i64,
    /// Used by rafsv6 inode datalayout
    pub v6_datalayout: u16,
    /// Used by rafsv6 nid calculation
    pub offset: u64,
    /// Used by Rafsv6 to build a Dir inode
    pub dirents: Vec<(u64, OsString, u32)>,
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
            ctime: 0,
            offset: 0,
            dirents: Vec::new(),
            v6_datalayout: EROFS_INODE_FLAT_PLAIN,
            v6_force_extended_inode,
            v6_compact_inode: false,
        };

        node.build_inode(chunk_size)
            .context("failed to build inode")?;

        node.set_v6_inode_compact();
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
                (self.inode.size() as u64)
                    .checked_sub((chunk_size * i) as u64)
                    .ok_or_else(|| {
                        anyhow!("the rest chunk size of inode is bigger than chunk_size")
                    })? as u32
            } else {
                chunk_size
            };

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
            let exist_chunk = match blob_ctx.chunk_dict.get_chunk(&chunk_id) {
                Some(v) => Some((v, true)),
                None => chunk_dict.get_chunk(&chunk_id).map(|v| (v, false)),
            };
            if let Some((cached_chunk, from_dict)) = exist_chunk {
                // TODO: we should also compare the actual data to avoid chunk digest conflicts.
                // hole cached_chunk may have zero uncompressed size
                if cached_chunk.uncompressed_size() == 0
                    || cached_chunk.uncompressed_size() == chunk_size
                {
                    // The chunks of hardlink should be always deduplicated.
                    if !self.is_hardlink() {
                        event_tracer!("dedup_decompressed_size", +chunk_size);
                        event_tracer!("dedup_chunks", +1);
                    }

                    chunk.copy_from(cached_chunk);
                    chunk.set_file_offset(file_offset);
                    if from_dict {
                        let idx = blob_ctx.chunk_dict.get_real_blob_idx(chunk.blob_index());
                        chunk.set_blob_index(idx);
                    }
                    trace!(
                        "\t\tbuilding duplicated chunk: {} compressor {}",
                        chunk,
                        ctx.compressor
                    );

                    let source = if from_dict {
                        ChunkSource::Dict
                    } else {
                        ChunkSource::Build
                    };
                    self.chunks.push(NodeChunk {
                        source,
                        inner: chunk,
                    });

                    continue;
                }
            }

            // Compress chunk data
            let (compressed, is_compressed) = compress::compress(&chunk_data, ctx.compressor)
                .with_context(|| format!("failed to compress node file {:?}", self.path))?;
            let compressed_size = compressed.len();

            // Move cursor to offset of next chunk
            let aligned_chunk_size = if ctx.aligned_chunk {
                // Safe to unwrap because `chunk_size` is much less than u32::MAX.
                try_round_up_4k(chunk_size).unwrap()
            } else {
                chunk_size
            };

            let pre_decompress_offset = blob_ctx.decompress_offset;
            let pre_compress_offset = blob_ctx.compress_offset;

            blob_ctx.compress_offset += compressed_size as u64;
            blob_ctx.decompressed_blob_size =
                blob_ctx.decompress_offset + aligned_chunk_size as u64;
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

            let chunk_index = blob_ctx.alloc_index()?;
            chunk.set_chunk_info(
                blob_index,
                chunk_index,
                file_offset,
                pre_decompress_offset,
                pre_compress_offset,
                compressed_size,
                chunk_size,
                is_compressed,
            )?;

            blob_ctx.add_chunk_meta_info(&chunk)?;
            chunk_dict.add_chunk(chunk.clone());
            self.chunks.push(NodeChunk {
                source: ChunkSource::Build,
                inner: chunk,
            });
            blob_size += compressed_size as u64;
        }

        // Finish inode digest calculation
        self.inode.set_digest(inode_hasher.digest_finalize());

        Ok(blob_size)
    }

    pub fn dump_bootstrap_v5(
        &self,
        ctx: &BuildContext,
        f_bootstrap: &mut dyn RafsIoWrite,
    ) -> Result<usize> {
        debug!("[{}]\t{}", self.overlay, self);

        let mut node_size = 0;
        if let InodeWrapper::V5(raw_inode) = &self.inode {
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

            for chunk in &self.chunks {
                let chunk_size = chunk
                    .inner
                    .store(f_bootstrap)
                    .context("failed to dump chunk info to bootstrap")?;
                node_size += chunk_size;
                trace!("\t\tchunk: {} compressor {}", chunk, ctx.compressor,);
            }

            Ok(node_size)
        } else {
            bail!("dump_bootstrap_v5 should not use v6 inode");
        }
    }

    fn set_v6_inode_compact(&mut self) {
        if self.v6_force_extended_inode
            || self.inode.uid() > std::u16::MAX as u32
            || self.inode.gid() > std::u16::MAX as u32
            || self.inode.nlink() > std::u16::MAX as u32
            || self.inode.size() > std::u32::MAX as u64
            || self.path.extension() == Some(OsStr::new("pyc"))
        {
            self.v6_compact_inode = false;
        } else {
            self.v6_compact_inode = true;
        }
    }

    fn new_rafsv6_inode(&mut self) -> Box<dyn RafsV6OndiskInode> {
        match self.v6_compact_inode {
            true => Box::new(RafsV6InodeCompact::new()),
            false => Box::new(RafsV6InodeExtended::new()),
        }
    }

    pub fn dump_bootstrap_v6(
        &mut self,
        f_bootstrap: &mut dyn RafsIoWrite,
        orig_meta_addr: u64,
        meta_addr: u64,
        ctx: &mut BuildContext,
        chunk_cache: &mut dyn ChunkDict,
    ) -> Result<usize> {
        let mut inode = self.new_rafsv6_inode();

        inode.set_size(self.inode.size());
        // FIXME
        inode.set_ino(self.inode.ino() as u32);
        inode.set_uidgid(self.inode.uid(), self.inode.gid());
        inode.set_mtime(self.inode.mtime(), self.inode.mtime_nsec());
        inode.set_nlink(self.inode.nlink());
        inode.set_mode(self.inode.mode() as u16);
        inode.set_data_layout(self.v6_datalayout);
        inode.set_xattr_inline_count(self.xattrs.count_v6() as u16);

        // update all the inodes's offset according to the new 'meta_addr'.
        self.offset = self.offset - orig_meta_addr + meta_addr;
        if self.is_dir() {
            // the 1st 4k block after dir inode.
            let mut dirent_off = align_offset(
                self.offset + self.size_with_xattr() as u64,
                EROFS_BLOCK_SIZE,
            );

            inode.set_u((dirent_off / EROFS_BLOCK_SIZE) as u32);
            // Dump inode
            f_bootstrap
                .seek(SeekFrom::Start(self.offset))
                .context("failed seek for dir inode")?;
            inode.store(f_bootstrap).context("failed to store inode")?;

            // Dump xattr
            if !self.xattrs.is_empty() {
                self.xattrs
                    .store_v6(f_bootstrap)
                    .context("failed to dump xattr to bootstrap")?;
                ctx.has_xattr = true;
            }

            // Dump dirents
            let mut dir_data: Vec<u8> = Vec::new();
            let mut entry_names = Vec::new();
            let mut nameoff: u64 = 0;
            let mut used: u64 = 0;
            let mut dirents: Vec<(RafsV6Dirent, &OsString)> = Vec::new();

            trace!("self.dirents.len {}", self.dirents.len());
            // fill dir blocks one by one
            for (offset, name, file_type) in self.dirents.iter() {
                let len = name.len() + size_of::<RafsV6Dirent>();
                if used + len as u64 > EROFS_BLOCK_SIZE {
                    // write to bootstrap
                    for (entry, name) in dirents.iter_mut() {
                        trace!("nameoff {}", nameoff);
                        entry.set_name_offset(nameoff as u16);
                        dir_data.extend(entry.as_ref());
                        entry_names.push(*name);

                        nameoff += name.len() as u64;
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
                    // track where we're going to write.
                    dirent_off += EROFS_BLOCK_SIZE;

                    dirents.clear();
                    nameoff = 0;
                    used = 0;
                }

                trace!(
                    "name {:?} file type {} {:?}",
                    *name,
                    *file_type,
                    RafsV6Dirent::file_type(*file_type)
                );
                let entry = RafsV6Dirent::new(
                    calculate_nid(*offset - orig_meta_addr + meta_addr, meta_addr),
                    0,
                    RafsV6Dirent::file_type(*file_type),
                );
                dirents.push((entry, &name));

                nameoff += size_of::<RafsV6Dirent>() as u64;
                used += len as u64;
            }

            // Dump 'non-tail' dirents and names.
            // if !dir_data.is_empty() {
            //     for name in entry_names.iter() {
            //         dir_data.extend(name.as_bytes());
            //     }
            //     f_bootstrap
            //         .seek(SeekFrom::Start(dirent_off as u64))
            //         .context("failed seek for dir inode")?;
            //     f_bootstrap
            //         .write(dir_data.as_slice())
            //         .context("failed to store dirents")?;
            //     dir_data.clear();
            //     entry_names.clear();
            // }

            trace!("used {} dir size {}", used, self.inode.size());
            // dump tail part if any
            if used > 0 {
                for (entry, name) in dirents.iter_mut() {
                    trace!("tail nameoff {}", nameoff);
                    entry.set_name_offset(nameoff as u16);
                    dir_data.extend(entry.as_ref());
                    entry_names.push(*name);

                    nameoff += name.len() as u64;
                }

                for name in entry_names.iter() {
                    dir_data.extend(name.as_bytes());
                }

                let tail_off = match self.v6_datalayout {
                    EROFS_INODE_FLAT_INLINE => self.offset + self.size_with_xattr() as u64,
                    EROFS_INODE_FLAT_PLAIN => dirent_off,
                    _ => unimplemented!(),
                };

                f_bootstrap
                    .seek(SeekFrom::Start(tail_off as u64))
                    .context("failed seek for dir inode")?;
                f_bootstrap
                    .write(dir_data.as_slice())
                    .context("failed to store dirents")?;
            }
        } else if self.is_reg() {
            let info = RafsV6InodeChunkHeader::new(ctx.chunk_size);
            inode.set_u(info.to_u32());

            // write chunk indexes, chunk contents has been written to blob file.
            let mut chunks: Vec<u8> = Vec::new();
            for chunk in self.chunks.iter() {
                let mut v6_chunk = RafsV6InodeChunkAddr::new();
                // for erofs, bump id by 1 since device id 0 is bootstrap.
                v6_chunk.set_blob_index((chunk.inner.blob_index() + 1) as u8);
                v6_chunk.set_blob_comp_index(chunk.inner.index());
                v6_chunk
                    .set_block_addr((chunk.inner.uncompressed_offset() / EROFS_BLOCK_SIZE) as u32);
                trace!("name {:?} chunk {}", self.name(), chunk);

                chunks.extend(v6_chunk.as_ref());

                chunk_cache.add_chunk(chunk.inner.clone());
            }

            f_bootstrap
                .seek(SeekFrom::Start(self.offset))
                .context("failed seek for dir inode")?;
            inode.store(f_bootstrap).context("failed to store inode")?;

            // Dump xattr
            if !self.xattrs.is_empty() {
                self.xattrs
                    .store_v6(f_bootstrap)
                    .context("failed to dump xattr to bootstrap")?;
            }

            let unit = size_of::<RafsV6InodeChunkAddr>() as u64;
            let chunk_off = align_offset(self.offset + self.size_with_xattr() as u64, unit);
            f_bootstrap
                .seek(SeekFrom::Start(chunk_off))
                .context("failed seek for dir inode")?;
            f_bootstrap
                .write(chunks.as_slice())
                .context("failed to write chunkindexes")?;
        } else if self.is_symlink() {
            let data_off = align_offset(
                self.offset + self.size_with_xattr() as u64,
                EROFS_BLOCK_SIZE,
            );

            // TODO: check whether 'i_u' is used at all in case of
            // inline symlink.
            inode.set_u((data_off / EROFS_BLOCK_SIZE) as u32);
            f_bootstrap
                .seek(SeekFrom::Start(self.offset))
                .context("failed seek for dir inode")?;
            inode.store(f_bootstrap).context("failed to store inode")?;

            // Dump xattr
            if !self.xattrs.is_empty() {
                self.xattrs
                    .store_v6(f_bootstrap)
                    .context("failed to dump xattr to bootstrap")?;
            }

            // write symlink.
            if let Some(symlink) = &self.symlink {
                let tail_off = if self.v6_datalayout == EROFS_INODE_FLAT_INLINE {
                    self.offset + self.size_with_xattr() as u64
                } else {
                    assert_eq!(self.v6_datalayout, EROFS_INODE_FLAT_PLAIN);
                    data_off
                };

                trace!("symlink write_off {}", tail_off);
                f_bootstrap
                    .seek(SeekFrom::Start(tail_off))
                    .context("failed seek for dir inode")?;

                f_bootstrap
                    .write(symlink.as_bytes())
                    .context("filed to store symlink")?;
            }
        } else {
            f_bootstrap
                .seek(SeekFrom::Start(self.offset))
                .context("failed seek for dir inode")?;
            inode.store(f_bootstrap).context("failed to store inode")?;

            // Dump xattr
            if !self.xattrs.is_empty() {
                self.xattrs
                    .store_v6(f_bootstrap)
                    .context("failed to dump xattr to bootstrap")?;
            }
        }

        // FIXME: return a real size
        Ok(0)
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
        self.ctime = meta.st_ctime();

        // Usually the root directory is created by the build tool (nydusify/buildkit/acceld)
        // and the mtime of the root directory is different for each build, which makes it
        // completely impossible to achieve repeatable builds, especially in a tar build scenario
        // (blob + bootstrap in one tar layer), which causes the layer hash to change and wastes
        // registry storage space, so the mtime of the root directory is forced to be ignored here.
        let ignore_mtime = self.is_root();
        self.inode
            .set_inode_info(&meta, &self.xattrs, self.explicit_uidgid, ignore_mtime);

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

    pub fn size_with_xattr(&self) -> usize {
        match self.inode {
            // this is not used by v5, put a dummy one.
            InodeWrapper::V5(_i) => 0,
            InodeWrapper::V6(_i) => {
                (if self.v6_compact_inode {
                    size_of::<RafsV6InodeCompact>()
                } else {
                    size_of::<RafsV6InodeExtended>()
                }) + self.xattrs.aligned_size_v6()
            }
        }
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

    /// Set node offset in bootstrap and return the next position.
    pub(crate) fn set_v6_offset(&mut self, bootstrap_ctx: &mut BootstrapContext) {
        if self.is_reg() {
            let size = self.size_with_xattr() as u64;
            let unit = size_of::<RafsV6InodeChunkAddr>() as u64;

            self.offset = bootstrap_ctx.offset;
            bootstrap_ctx.offset += size;
            bootstrap_ctx.align_offset(unit);
            bootstrap_ctx.offset += self.inode.child_count() as u64 * unit;
            self.v6_datalayout = EROFS_INODE_CHUNK_BASED;
        } else if self.is_symlink() {
            self.set_v6_offset_with_tail(bootstrap_ctx, self.inode.size());
        } else {
            self.offset = bootstrap_ctx.offset;
            bootstrap_ctx.offset += self.size_with_xattr() as u64;
        }
    }

    pub(crate) fn get_dir_d_size(&self, tree: &Tree) -> Result<u64> {
        ensure!(self.is_dir(), "{} is not a directory", self);

        let mut d_size: u64 =
            (1 + size_of::<RafsV6Dirent>() + 2 + size_of::<RafsV6Dirent>()) as u64;

        // Safe as we have check tree above.
        for child in tree.children.iter() {
            let len = child.node.name().len() + size_of::<RafsV6Dirent>();
            // erofs disk format requires dirent to be aligned with 4096.
            if (d_size % EROFS_BLOCK_SIZE) + len as u64 > EROFS_BLOCK_SIZE {
                d_size = div_round_up(d_size as u64, EROFS_BLOCK_SIZE) * EROFS_BLOCK_SIZE;
            }
            d_size += len as u64;
        }
        Ok(d_size)
    }

    pub fn dir_set_v6_offset(
        &mut self,
        bootstrap_ctx: &mut BootstrapContext,
        d_size: u64,
    ) -> Result<()> {
        ensure!(self.is_dir(), "{} is not a directory", self);

        // Dir isize is the total bytes of 'dirents + names'.
        self.inode.set_size(d_size);
        self.set_v6_offset_with_tail(bootstrap_ctx, d_size);

        Ok(())
    }

    // For DIR inode, size is the total bytes of 'dirents + names'.
    // For symlink, size is the length of symlink name.
    fn set_v6_offset_with_tail(&mut self, bootstrap_ctx: &mut BootstrapContext, d_size: u64) {
        self.offset = bootstrap_ctx.offset;

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
        let inode_size = self.size_with_xattr() as u64;

        bootstrap_ctx.offset += inode_size;
        let avail: u64 = EROFS_BLOCK_SIZE - bootstrap_ctx.offset % EROFS_BLOCK_SIZE;
        let tail: u64 = d_size % EROFS_BLOCK_SIZE;
        self.v6_datalayout = if tail > 0 {
            if avail >= tail && bootstrap_ctx.offset % EROFS_BLOCK_SIZE as u64 > 0 {
                bootstrap_ctx.offset += tail;
                if d_size > tail {
                    // add remained bytes of 'd_size' in a new 4k.
                    bootstrap_ctx.align_offset(EROFS_BLOCK_SIZE);
                }
                bootstrap_ctx.offset += d_size - tail;
                EROFS_INODE_FLAT_INLINE
            } else {
                bootstrap_ctx.align_offset(EROFS_BLOCK_SIZE);
                bootstrap_ctx.offset += d_size;
                // plain datalayout
                bootstrap_ctx.align_offset(EROFS_BLOCK_SIZE);
                EROFS_INODE_FLAT_PLAIN
            }
        } else {
            bootstrap_ctx.align_offset(EROFS_BLOCK_SIZE);
            bootstrap_ctx.offset += d_size;
            // plain datalayout
            bootstrap_ctx.align_offset(EROFS_BLOCK_SIZE);
            EROFS_INODE_FLAT_PLAIN
        };

        trace!(
            "{:?} dir offset {} ctx offset {} d_size {} datalayout {}",
            self.name(),
            self.offset,
            bootstrap_ctx.offset,
            d_size,
            self.v6_datalayout
        );
    }
}

#[derive(Clone, Debug)]
pub enum InodeWrapper {
    V5(RafsV5Inode),
    // In order to reuse v5 code, we still need to use v5 inode but
    // with a different wrapper.
    V6(RafsV5Inode),
}

impl InodeWrapper {
    pub fn new(version: RafsVersion) -> Self {
        match version {
            RafsVersion::V5 => InodeWrapper::V5(RafsV5Inode::new()),
            RafsVersion::V6 => InodeWrapper::V6(RafsV5Inode::new()),
        }
    }

    pub fn from_inode_info(inode: &Arc<dyn RafsInode>) -> Self {
        if let Some(inode) = inode.as_any().downcast_ref::<CachedInodeV5>() {
            InodeWrapper::V5(to_rafsv5_inode(inode))
        } else if let Some(inode) = inode.as_any().downcast_ref::<OndiskInodeWrapper>() {
            InodeWrapper::V5(to_rafsv5_inode(inode))
        } else {
            panic!("unknown chunk information struct");
        }
    }

    pub fn inode_size(&self) -> usize {
        match self {
            InodeWrapper::V5(i) => i.size(),
            InodeWrapper::V6(i) => i.size(),
        }
    }

    pub fn mode(&self) -> u32 {
        match self {
            InodeWrapper::V5(i) => i.mode(),
            InodeWrapper::V6(i) => i.mode(),
        }
    }

    pub fn is_dir(&self) -> bool {
        match self {
            InodeWrapper::V5(i) => i.is_dir(),
            InodeWrapper::V6(i) => i.is_dir(),
        }
    }

    pub fn is_reg(&self) -> bool {
        match self {
            InodeWrapper::V5(i) => i.is_reg(),
            InodeWrapper::V6(i) => i.is_reg(),
        }
    }

    pub fn is_hardlink(&self) -> bool {
        match self {
            InodeWrapper::V5(i) => i.is_hardlink(),
            InodeWrapper::V6(i) => i.is_hardlink(),
        }
    }

    pub fn is_symlink(&self) -> bool {
        match self {
            InodeWrapper::V5(i) => i.is_symlink(),
            InodeWrapper::V6(i) => i.is_symlink(),
        }
    }

    pub fn is_chrdev(&self) -> bool {
        match self {
            InodeWrapper::V5(i) => i.i_mode & libc::S_IFMT == libc::S_IFCHR,
            InodeWrapper::V6(i) => i.i_mode & libc::S_IFMT == libc::S_IFCHR,
        }
    }

    pub fn is_blkdev(&self) -> bool {
        match self {
            InodeWrapper::V5(i) => i.i_mode & libc::S_IFMT == libc::S_IFBLK,
            InodeWrapper::V6(i) => i.i_mode & libc::S_IFMT == libc::S_IFBLK,
        }
    }

    pub fn is_fifo(&self) -> bool {
        match self {
            InodeWrapper::V5(i) => i.i_mode & libc::S_IFMT == libc::S_IFIFO,
            InodeWrapper::V6(i) => i.i_mode & libc::S_IFMT == libc::S_IFIFO,
        }
    }

    pub fn is_sock(&self) -> bool {
        match self {
            InodeWrapper::V5(i) => i.i_mode & libc::S_IFMT == libc::S_IFSOCK,
            InodeWrapper::V6(i) => i.i_mode & libc::S_IFMT == libc::S_IFSOCK,
        }
    }

    pub fn is_special(&self) -> bool {
        self.is_chrdev() || self.is_blkdev() || self.is_fifo() || self.is_sock()
    }

    pub fn has_xattr(&self) -> bool {
        match self {
            InodeWrapper::V5(i) => i.has_xattr(),
            InodeWrapper::V6(i) => i.has_xattr(),
        }
    }

    pub fn set_has_xattr(&mut self, enable: bool) {
        match self {
            InodeWrapper::V5(i) => {
                if enable {
                    i.i_flags |= RafsV5InodeFlags::XATTR;
                } else {
                    i.i_flags &= !RafsV5InodeFlags::XATTR;
                }
            }
            InodeWrapper::V6(i) => {
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
            InodeWrapper::V5(i) => i.i_ino,
            InodeWrapper::V6(i) => i.i_ino,
        }
    }

    pub fn set_ino(&mut self, ino: Inode) {
        match self {
            InodeWrapper::V5(i) => i.i_ino = ino,
            InodeWrapper::V6(i) => i.i_ino = ino,
        }
    }

    pub fn parent(&self) -> Inode {
        match self {
            InodeWrapper::V5(i) => i.i_parent,
            InodeWrapper::V6(i) => i.i_parent,
        }
    }

    pub fn set_parent(&mut self, parent: Inode) {
        match self {
            InodeWrapper::V5(i) => i.i_parent = parent,
            InodeWrapper::V6(i) => i.i_parent = parent,
        }
    }

    pub fn size(&self) -> u64 {
        match self {
            InodeWrapper::V5(i) => i.i_size,
            InodeWrapper::V6(i) => i.i_size,
        }
    }

    pub fn set_size(&mut self, size: u64) {
        match self {
            InodeWrapper::V5(i) => i.i_size = size,
            InodeWrapper::V6(i) => i.i_size = size,
        }
    }

    pub fn uid(&self) -> u32 {
        match self {
            InodeWrapper::V5(i) => i.i_uid,
            InodeWrapper::V6(i) => i.i_uid,
        }
    }

    pub fn gid(&self) -> u32 {
        match self {
            InodeWrapper::V5(i) => i.i_gid,
            InodeWrapper::V6(i) => i.i_gid,
        }
    }

    pub fn mtime(&self) -> u64 {
        match self {
            InodeWrapper::V5(i) => i.i_mtime,
            InodeWrapper::V6(i) => i.i_mtime,
        }
    }

    pub fn mtime_nsec(&self) -> u32 {
        match self {
            InodeWrapper::V5(i) => i.i_mtime_nsec,
            InodeWrapper::V6(i) => i.i_mtime_nsec,
        }
    }

    pub fn blocks(&self) -> u64 {
        match self {
            InodeWrapper::V5(i) => i.i_blocks,
            InodeWrapper::V6(i) => i.i_blocks,
        }
    }

    pub fn nlink(&self) -> u32 {
        match self {
            InodeWrapper::V5(i) => i.i_nlink,
            InodeWrapper::V6(i) => i.i_nlink,
        }
    }

    pub fn set_nlink(&mut self, nlink: u32) {
        match self {
            InodeWrapper::V5(i) => i.i_nlink = nlink,
            InodeWrapper::V6(i) => i.i_nlink = nlink,
        }
    }

    pub fn digest(&self) -> &RafsDigest {
        match self {
            InodeWrapper::V5(i) => &i.i_digest,
            InodeWrapper::V6(i) => &i.i_digest,
        }
    }

    pub fn set_digest(&mut self, digest: RafsDigest) {
        match self {
            InodeWrapper::V5(i) => i.i_digest = digest,
            InodeWrapper::V6(i) => i.i_digest = digest,
        }
    }

    pub fn name_size(&self) -> u16 {
        match self {
            InodeWrapper::V5(i) => i.i_name_size,
            InodeWrapper::V6(i) => i.i_name_size,
        }
    }

    fn set_name_size(&mut self, size: usize) {
        debug_assert!(size < u16::MAX as usize);
        match self {
            InodeWrapper::V5(i) => i.i_name_size = size as u16,
            InodeWrapper::V6(i) => i.i_name_size = size as u16,
        }
    }

    pub fn symlink_size(&self) -> u16 {
        match self {
            InodeWrapper::V5(i) => i.i_symlink_size,
            InodeWrapper::V6(i) => i.i_symlink_size,
        }
    }

    pub fn set_symlink_size(&mut self, size: usize) {
        debug_assert!(size <= u16::MAX as usize);
        match self {
            InodeWrapper::V5(i) => {
                i.i_flags |= RafsV5InodeFlags::SYMLINK;
                i.i_symlink_size = size as u16;
            }
            InodeWrapper::V6(i) => {
                i.i_flags |= RafsV5InodeFlags::SYMLINK;
                i.i_symlink_size = size as u16;
            }
        }
    }

    pub fn child_index(&self) -> u32 {
        match self {
            InodeWrapper::V5(i) => i.i_child_index,
            InodeWrapper::V6(i) => i.i_child_index,
        }
    }

    pub fn set_child_index(&mut self, index: u32) {
        match self {
            InodeWrapper::V5(i) => i.i_child_index = index,
            InodeWrapper::V6(i) => i.i_child_index = index,
        }
    }

    pub fn child_count(&self) -> u32 {
        match self {
            InodeWrapper::V5(i) => i.i_child_count,
            InodeWrapper::V6(i) => i.i_child_count,
        }
    }

    pub fn set_child_count(&mut self, count: u32) {
        match self {
            InodeWrapper::V5(i) => i.i_child_count = count,
            InodeWrapper::V6(i) => i.i_child_count = count,
        }
    }

    fn set_inode_info<T: MetadataExt>(
        &mut self,
        meta: &T,
        xattrs: &RafsXAttrs,
        explicit_uidgid: bool,
        ignore_mtime: bool,
    ) {
        match self {
            InodeWrapper::V5(i) => {
                i.i_mode = meta.st_mode();
                if explicit_uidgid {
                    i.i_uid = meta.st_uid();
                    i.i_gid = meta.st_gid();
                }
                if !ignore_mtime {
                    i.i_mtime = meta.st_mtime() as u64;
                    i.i_mtime_nsec = meta.st_mtime_nsec() as u32;
                }
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
            InodeWrapper::V6(i) => {
                i.i_mode = meta.st_mode();
                if explicit_uidgid {
                    i.i_uid = meta.st_uid();
                    i.i_gid = meta.st_gid();
                }
                if !ignore_mtime {
                    i.i_mtime = meta.st_mtime() as u64;
                    i.i_mtime_nsec = meta.st_mtime_nsec() as u32;
                }
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
            InodeWrapper::V5(_) => ChunkWrapper::V5(RafsV5ChunkInfo::new()),
            InodeWrapper::V6(_) => ChunkWrapper::V6(RafsV5ChunkInfo::new()),
        }
    }
}

#[derive(Clone, Debug)]
pub enum ChunkWrapper {
    V5(RafsV5ChunkInfo),
    // see InodeWrapper V6.
    V6(RafsV5ChunkInfo),
}

impl ChunkWrapper {
    #[cfg(test)]
    pub fn new(version: RafsVersion) -> Self {
        match version {
            RafsVersion::V5 => ChunkWrapper::V5(RafsV5ChunkInfo::default()),
            RafsVersion::V6 => ChunkWrapper::V6(RafsV5ChunkInfo::default()),
        }
    }

    pub fn from_chunk_info(cki: &dyn BlobChunkInfo) -> Self {
        if let Some(cki_v5) = cki.as_any().downcast_ref::<CachedChunkInfoV5>() {
            ChunkWrapper::V5(to_rafsv5_chunk_info(cki_v5))
        } else if let Some(cki_v5) = cki.as_any().downcast_ref::<DirectChunkInfoV5>() {
            ChunkWrapper::V5(to_rafsv5_chunk_info(cki_v5))
        } else if let Some(cki_v6) = cki.as_any().downcast_ref::<DirectChunkInfoV6>() {
            ChunkWrapper::V6(to_rafsv5_chunk_info(cki_v6))
        } else {
            panic!("unknown chunk information struct");
        }
    }

    pub fn id(&self) -> &RafsDigest {
        match self {
            ChunkWrapper::V5(c) => &c.block_id,
            ChunkWrapper::V6(c) => &c.block_id,
        }
    }

    pub fn set_id(&mut self, id: RafsDigest) {
        match self {
            ChunkWrapper::V5(c) => c.block_id = id,
            ChunkWrapper::V6(c) => c.block_id = id,
        }
    }

    pub fn index(&self) -> u32 {
        match self {
            ChunkWrapper::V5(c) => c.index,
            ChunkWrapper::V6(c) => c.index,
        }
    }

    pub fn set_index(&mut self, index: u32) {
        match self {
            ChunkWrapper::V5(c) => c.index = index,
            ChunkWrapper::V6(c) => c.index = index,
        }
    }

    pub fn blob_index(&self) -> u32 {
        match self {
            ChunkWrapper::V5(c) => c.blob_index,
            ChunkWrapper::V6(c) => c.blob_index,
        }
    }

    pub fn set_blob_index(&mut self, index: u32) {
        match self {
            ChunkWrapper::V5(c) => c.blob_index = index,
            ChunkWrapper::V6(c) => c.blob_index = index,
        }
    }

    pub fn compressed_offset(&self) -> u64 {
        match self {
            ChunkWrapper::V5(c) => c.compress_offset,
            ChunkWrapper::V6(c) => c.compress_offset,
        }
    }

    pub fn set_compressed_offset(&mut self, offset: u64) {
        match self {
            ChunkWrapper::V5(c) => c.compress_offset = offset,
            ChunkWrapper::V6(c) => c.compress_offset = offset,
        }
    }

    pub fn compressed_size(&self) -> u32 {
        match self {
            ChunkWrapper::V5(c) => c.compress_size,
            ChunkWrapper::V6(c) => c.compress_size,
        }
    }

    pub fn uncompressed_offset(&self) -> u64 {
        match self {
            ChunkWrapper::V5(c) => c.uncompress_offset,
            ChunkWrapper::V6(c) => c.uncompress_offset,
        }
    }

    pub fn set_uncompressed_offset(&mut self, offset: u64) {
        match self {
            ChunkWrapper::V5(c) => c.uncompress_offset = offset,
            ChunkWrapper::V6(c) => c.uncompress_offset = offset,
        }
    }

    pub fn uncompressed_size(&self) -> u32 {
        match self {
            ChunkWrapper::V5(c) => c.uncompress_size,
            ChunkWrapper::V6(c) => c.uncompress_size,
        }
    }

    pub fn file_offset(&self) -> u64 {
        match self {
            ChunkWrapper::V5(c) => c.file_offset,
            ChunkWrapper::V6(c) => c.file_offset,
        }
    }

    pub fn set_file_offset(&mut self, offset: u64) {
        match self {
            ChunkWrapper::V5(c) => c.file_offset = offset,
            ChunkWrapper::V6(c) => c.file_offset = offset,
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
            ChunkWrapper::V6(c) => {
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
            (ChunkWrapper::V6(s), ChunkWrapper::V6(o)) => {
                s.clone_from(o);
            }
            (ChunkWrapper::V5(s), ChunkWrapper::V6(o)) => {
                s.clone_from(o);
            }
            (ChunkWrapper::V6(s), ChunkWrapper::V5(o)) => {
                s.clone_from(o);
            }
        }
    }

    pub(crate) fn store(&self, w: &mut dyn RafsIoWrite) -> Result<usize> {
        match self {
            ChunkWrapper::V5(c) => c.store(w).context("failed to store rafs v5 chunk"),
            ChunkWrapper::V6(c) => c.store(w).context("failed to store rafs v5 chunk"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{ArtifactStorage, BootstrapContext};
    use rafs::metadata::layout::v6::EROFS_INODE_CHUNK_BASED;
    use rafs::metadata::RAFS_DEFAULT_CHUNK_SIZE;
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
        let mut bootstrap_ctx = BootstrapContext::new(storage, false).unwrap();
        bootstrap_ctx.offset = 1;

        // reg file.
        // "1" is used only for testing purpose, in practice
        // it's always aligned to 32 bytes.
        node.set_v6_offset(&mut bootstrap_ctx);
        assert_eq!(node.offset, 1);
        assert_eq!(node.v6_datalayout, EROFS_INODE_CHUNK_BASED);
        assert_eq!(node.v6_compact_inode, true);
        assert_eq!(bootstrap_ctx.offset, 40);

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

        // 1. tail = 0
        bootstrap_ctx.offset = 4096 - 32 - 32;
        dir_node
            .dir_set_v6_offset(&mut bootstrap_ctx, 4096)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_PLAIN);
        assert_eq!(bootstrap_ctx.offset, 8192);

        bootstrap_ctx.offset = 4096 - 32 + 32;
        dir_node
            .dir_set_v6_offset(&mut bootstrap_ctx, 4096)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_PLAIN);
        assert_eq!(bootstrap_ctx.offset, 8192 + 4096);

        bootstrap_ctx.offset = 4096 - 32;
        dir_node
            .dir_set_v6_offset(&mut bootstrap_ctx, 4096)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_PLAIN);
        assert_eq!(bootstrap_ctx.offset, 8192);

        // 2. tail = 32
        // avail = 32
        bootstrap_ctx.offset = 4096 - 32 - 32;
        dir_node
            .dir_set_v6_offset(&mut bootstrap_ctx, 4096 + 32)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_INLINE);
        assert_eq!(bootstrap_ctx.offset, 8192);

        // avail = 33
        bootstrap_ctx.offset = 4096 - 32 - 33;
        dir_node
            .dir_set_v6_offset(&mut bootstrap_ctx, 4096 + 32)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_INLINE);
        assert_eq!(bootstrap_ctx.offset, 8192);

        // avail = 31
        bootstrap_ctx.offset = 4096 - 32 - 31;
        dir_node
            .dir_set_v6_offset(&mut bootstrap_ctx, 4096 + 32)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_PLAIN);
        assert_eq!(bootstrap_ctx.offset, 8192 + 4096);

        // avail = 4096
        bootstrap_ctx.offset = 4096 - 32;
        dir_node
            .dir_set_v6_offset(&mut bootstrap_ctx, 4096 + 32)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_PLAIN);
        assert_eq!(bootstrap_ctx.offset, 8192 + 4096);

        // 3. tail = 4095
        // avail = 32
        bootstrap_ctx.offset = 4096 - 32 - 32;
        dir_node
            .dir_set_v6_offset(&mut bootstrap_ctx, 4096 + 4095)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_PLAIN);
        assert_eq!(bootstrap_ctx.offset, 8192 + 4096);

        // avail = 33
        bootstrap_ctx.offset = 4096 - 32 - 33;
        dir_node
            .dir_set_v6_offset(&mut bootstrap_ctx, 4096 + 4095)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_PLAIN);
        assert_eq!(bootstrap_ctx.offset, 8192 + 4096);

        // avail = 31
        bootstrap_ctx.offset = 4096 - 32 - 31;
        dir_node
            .dir_set_v6_offset(&mut bootstrap_ctx, 4096 + 4095)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_PLAIN);
        assert_eq!(bootstrap_ctx.offset, 8192 + 4096);

        // avail = 4096
        bootstrap_ctx.offset = 4096 - 32;
        dir_node
            .dir_set_v6_offset(&mut bootstrap_ctx, 4096 + 4095)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_PLAIN);
        assert_eq!(bootstrap_ctx.offset, 8192 + 4096);
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

        assert_eq!(reg_node.v6_compact_inode, true);

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

        assert_eq!(pyc_node.v6_compact_inode, false);

        std::fs::remove_file(&pa_pyc).unwrap();
    }
}
