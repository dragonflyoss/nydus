// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021-2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
#![allow(unused_variables, unused_imports)]
use std::collections::{BTreeMap, HashMap};
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Display, Formatter, Result as FmtResult};
use std::fs::{self, File};
use std::io::{Read, SeekFrom, Write};
use std::mem::size_of;
use std::ops::Deref;
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::os::macos::fs::MetadataExt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Error, Result};
use nydus_rafs::metadata::chunk::{convert_ref_to_rafs_v5_chunk_info, ChunkWrapper};
use nydus_rafs::metadata::inode::{InodeWrapper, RafsV6Inode};
use nydus_rafs::metadata::layout::v5::{RafsV5ChunkInfo, RafsV5Inode, RafsV5InodeWrapper};
use nydus_rafs::metadata::layout::v6::{
    align_offset, RafsV6InodeChunkAddr, EROFS_BLOCK_SIZE_4096, EROFS_BLOCK_SIZE_512,
    EROFS_INODE_FLAT_PLAIN, EROFS_INODE_SLOT_SIZE,
};
use nydus_rafs::metadata::layout::{RafsXAttrs, RAFS_SUPER_VERSION_V6};
use nydus_rafs::metadata::{Inode, RafsStore, RafsSuperFlags, RafsSuperMeta, RafsVersion};
use nydus_rafs::RafsIoWrite;
use nydus_storage::device::{BlobFeatures, BlobInfo};
use nydus_storage::meta::{BlobChunkInfoV2Ondisk, BlobMetaChunkInfo};
use nydus_utils::cas::CasMgr;
use nydus_utils::digest::{DigestHasher, RafsDigest};
use nydus_utils::{compress, crypt};
use nydus_utils::{div_round_up, event_tracer, root_tracer, try_round_up_4k, ByteSize};
use sha2::digest::Digest;

use crate::{BlobContext, BlobManager, BuildContext, ChunkDict, ConversionType, Overlay};

use super::context::Artifact;

use super::chunk_dict::DigestWithBlobIndex;

/// Filesystem root path for Unix OSs.
const ROOT_PATH_NAME: &[u8] = &[b'/'];

/// Source of chunk data: chunk dictionary, parent filesystem or builder.
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

/// Chunk information for RAFS filesystem builder.
#[derive(Clone)]
pub struct NodeChunk {
    pub source: ChunkSource,
    pub inner: Arc<ChunkWrapper>,
}

impl Display for NodeChunk {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner,)
    }
}

impl NodeChunk {
    /// Copy all chunk information from another `ChunkWrapper` object.
    pub fn copy_from(&mut self, other: &ChunkWrapper) {
        let mut chunk = self.inner.deref().clone();
        chunk.copy_from(other);
        self.inner = Arc::new(chunk);
    }

    /// Set chunk index.
    pub fn set_index(&mut self, index: u32) {
        let mut chunk = self.inner.deref().clone();
        chunk.set_index(index);
        self.inner = Arc::new(chunk);
    }

    /// Set blob index.
    pub fn set_blob_index(&mut self, index: u32) {
        let mut chunk = self.inner.deref().clone();
        chunk.set_blob_index(index);
        self.inner = Arc::new(chunk);
    }

    /// Set chunk compressed size.
    pub fn set_compressed_size(&mut self, size: u32) {
        let mut chunk = self.inner.deref().clone();
        chunk.set_compressed_size(size);
        self.inner = Arc::new(chunk);
    }

    /// Set file offset of chunk.
    pub fn set_file_offset(&mut self, offset: u64) {
        let mut chunk = self.inner.deref().clone();
        chunk.set_file_offset(offset);
        self.inner = Arc::new(chunk);
    }
}

/// Struct to host sharable fields of [Node].
#[derive(Clone, Default, Debug)]
pub struct NodeInfo {
    /// Whether the explicit UID/GID feature is enabled or not.
    pub explicit_uidgid: bool,

    /// Device id associated with the source inode.
    ///
    /// A source directory may contain multiple partitions from different hard disk, so
    /// a pair of (src_ino, src_dev) is needed to uniquely identify an inode from source directory.
    pub src_dev: u64,
    /// Inode number of the source inode, from fs stat().
    pub src_ino: Inode,
    /// Device ID for special files, describing the device that this inode represents.
    pub rdev: u64,
    /// Absolute path of the source root directory.
    pub source: PathBuf,
    /// Absolute path of the source file/directory.
    pub path: PathBuf,
    /// Absolute path within the target RAFS filesystem.
    pub target: PathBuf,
    /// Parsed version of `target`.
    pub target_vec: Vec<OsString>,
    /// Symlink info of symlink file
    pub symlink: Option<OsString>,
    /// Extended attributes.
    pub xattrs: RafsXAttrs,

    /// V6: whether it's forced to use an extended inode.
    pub v6_force_extended_inode: bool,
}

/// An in-memory representation of RAFS inode for image building and inspection.
#[derive(Clone)]
pub struct Node {
    /// Immutable fields of a Node object.
    pub info: Arc<NodeInfo>,
    /// Assigned RAFS inode number.
    pub index: u64,
    /// Define a disk inode structure to persist to disk.
    pub inode: InodeWrapper,
    /// Chunks info list of regular file
    pub chunks: Vec<NodeChunk>,
    /// Layer index where node is located.
    pub layer_idx: u16,
    /// Overlay type for layered build
    pub overlay: Overlay,

    /// V6: whether it's a compact inode or an extended inode.
    pub v6_compact_inode: bool,
    /// V6: inode data layout.
    pub v6_datalayout: u16,
    /// V6: offset to calculate nid.
    pub v6_offset: u64,
    /// V6: offset to build directory entries.
    pub v6_dirents_offset: u64,
    /// V6: information to build directory entries.
    pub v6_dirents: Vec<(u64, OsString, u32)>,
}

impl Display for Node {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{} {:?}: index {} ino {} real_ino {} child_index {} child_count {} i_nlink {} i_size {} i_blocks {} i_name_size {} i_symlink_size {} has_xattr {} link {:?} i_mtime {} i_mtime_nsec {}",
            self.file_type(),
            self.target(),
            self.index,
            self.inode.ino(),
            self.info.src_ino,
            self.inode.child_index(),
            self.inode.child_count(),
            self.inode.nlink(),
            self.inode.size(),
            self.inode.blocks(),
            self.inode.name_size(),
            self.inode.symlink_size(),
            self.inode.has_xattr(),
            self.info.symlink,
            self.inode.mtime(),
            self.inode.mtime_nsec(),
        )
    }
}

impl Node {
    /// Create a new instance of [Node].
    pub fn new(inode: InodeWrapper, info: NodeInfo, layer_idx: u16) -> Self {
        Node {
            info: Arc::new(info),
            index: 0,
            overlay: Overlay::UpperAddition,
            inode,
            chunks: Vec::new(),
            layer_idx,
            v6_offset: 0,
            v6_dirents: Vec::<(u64, OsString, u32)>::new(),
            v6_datalayout: 0,
            v6_compact_inode: false,
            v6_dirents_offset: 0,
        }
    }

    /// Dump node data into the data blob, and generate chunk information.
    ///
    /// # Arguments
    /// - blob_writer: optional writer to write data into the data blob.
    /// - data_buf: scratch buffer used to stored data read from the reader.
    pub fn dump_node_data(
        self: &mut Node,
        ctx: &BuildContext,
        blob_mgr: &mut BlobManager,
        blob_writer: &mut dyn Artifact,
        chunk_data_buf: &mut [u8],
    ) -> Result<u64> {
        let mut reader = if self.is_reg() {
            let file = File::open(&self.path())
                .with_context(|| format!("failed to open node file {:?}", self.path()))?;
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
        blob_writer: &mut dyn Artifact,
        reader: Option<&mut R>,
        data_buf: &mut [u8],
    ) -> Result<u64> {
        if self.is_dir() {
            return Ok(0);
        } else if self.is_symlink() {
            if let Some(symlink) = self.info.symlink.as_ref() {
                if self.inode.is_v5() {
                    self.inode
                        .set_digest(RafsDigest::from_buf(symlink.as_bytes(), ctx.digester));
                }
                return Ok(0);
            } else {
                return Err(Error::msg("inode's symblink is invalid."));
            }
        } else if self.is_special() {
            if self.inode.is_v5() {
                self.inode
                    .set_digest(RafsDigest::hasher(ctx.digester).digest_finalize());
            }
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
            let (mut chunk, mut chunk_info) = self.read_file_chunk(ctx, reader, chunk_data)?;
            if let Some(h) = inode_hasher.as_mut() {
                h.digest_update(chunk.id().as_ref());
            }

            // No need to perform chunk deduplication for tar-tarfs case.
            if ctx.conversion_type != ConversionType::TarToTarfs {
                chunk = match self.deduplicate_chunk(
                    ctx,
                    blob_mgr,
                    file_offset,
                    uncompressed_size,
                    chunk,
                )? {
                    None => continue,
                    Some(c) => c,
                };
            }

            let (blob_index, blob_ctx) = blob_mgr.get_or_create_current_blob(ctx)?;
            let chunk_index = blob_ctx.alloc_chunk_index()?;
            chunk.set_blob_index(blob_index);
            chunk.set_index(chunk_index);
            chunk.set_file_offset(file_offset);
            if ctx.conversion_type == ConversionType::TarToTarfs {
                chunk.set_uncompressed_offset(chunk.compressed_offset());
                chunk.set_uncompressed_size(chunk.compressed_size());
            } else if let Some(info) =
                self.dump_file_chunk(ctx, blob_ctx, blob_writer, chunk_data, &mut chunk)?
            {
                chunk_info = Some(info);
            }

            let chunk = Arc::new(chunk);
            blob_size += chunk.compressed_size() as u64;
            if ctx.conversion_type != ConversionType::TarToTarfs {
                blob_ctx.add_chunk_meta_info(&chunk, chunk_info)?;
                blob_mgr
                    .layered_chunk_dict
                    .add_chunk(chunk.clone(), ctx.digester);
            }
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
                .with_context(|| format!("failed to read node file {:?}", self.path()))?;
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
                .with_context(|| format!("failed to read node file {:?}", self.path()))?;
        } else {
            reader
                .read_exact(buf)
                .with_context(|| format!("failed to read node file {:?}", self.path()))?;
        }

        // For tar-tarfs case, no need to compute chunk id.
        if ctx.conversion_type != ConversionType::TarToTarfs {
            chunk.set_id(RafsDigest::from_buf(buf, ctx.digester));
        }

        if ctx.cipher != crypt::Algorithm::None {
            chunk.set_encrypted(true);
        }

        Ok((chunk, chunk_info))
    }

    /// Dump a chunk from u8 slice into the data blob.
    /// Return `BlobChunkInfoV2Ondisk` when the chunk is added into a batch chunk.
    fn dump_file_chunk(
        &self,
        ctx: &BuildContext,
        blob_ctx: &mut BlobContext,
        blob_writer: &mut dyn Artifact,
        chunk_data: &[u8],
        chunk: &mut ChunkWrapper,
    ) -> Result<Option<BlobChunkInfoV2Ondisk>> {
        let d_size = chunk_data.len() as u32;
        let aligned_d_size = if ctx.aligned_chunk {
            // Safe to unwrap because `chunk_size` is much less than u32::MAX.
            try_round_up_4k(d_size).unwrap()
        } else {
            d_size
        };
        let pre_d_offset = blob_ctx.current_uncompressed_offset;
        blob_ctx.uncompressed_blob_size = pre_d_offset + aligned_d_size as u64;
        blob_ctx.current_uncompressed_offset += aligned_d_size as u64;
        chunk.set_uncompressed_offset(pre_d_offset);
        chunk.set_uncompressed_size(d_size);

        let mut chunk_info = None;
        let encrypted = blob_ctx.blob_cipher != crypt::Algorithm::None;

        if self.inode.child_count() == 1
            && d_size < ctx.batch_size / 2
            && ctx.blob_batch_generator.is_some()
        {
            // This chunk will be added into a batch chunk.
            let mut batch = ctx.blob_batch_generator.as_ref().unwrap().lock().unwrap();

            if batch.chunk_data_buf_len() as u32 + d_size < ctx.batch_size {
                // Add into current batch chunk directly.
                chunk_info = Some(batch.generate_chunk_info(pre_d_offset, d_size, encrypted)?);
                batch.append_chunk_data_buf(chunk_data);
            } else {
                // Dump current batch chunk if exists, and then add into a new batch chunk.
                if !batch.chunk_data_buf_is_empty() {
                    // Dump current batch chunk.
                    let (pre_c_offset, c_size, _) =
                        Self::write_chunk_data(ctx, blob_ctx, blob_writer, batch.chunk_data_buf())?;
                    batch.add_context(pre_c_offset, c_size);
                    batch.clear_chunk_data_buf();
                }

                // Add into a new batch chunk.
                chunk_info = Some(batch.generate_chunk_info(pre_d_offset, d_size, encrypted)?);
                batch.append_chunk_data_buf(chunk_data);
            }
        } else if !ctx.blob_features.contains(BlobFeatures::SEPARATE) {
            // For other case which needs to write chunk data to data blobs.

            // Interrupt and dump buffered batch chunks.
            // TODO: cancel the interruption.
            if let Some(batch) = &ctx.blob_batch_generator {
                let mut batch = batch.lock().unwrap();
                if !batch.chunk_data_buf_is_empty() {
                    // Dump current batch chunk.
                    let (pre_c_offset, c_size, _) =
                        Self::write_chunk_data(ctx, blob_ctx, blob_writer, batch.chunk_data_buf())?;
                    batch.add_context(pre_c_offset, c_size);
                    batch.clear_chunk_data_buf();
                }
            }

            let (pre_c_offset, c_size, is_compressed) =
                Self::write_chunk_data(ctx, blob_ctx, blob_writer, chunk_data)
                    .with_context(|| format!("failed to write chunk data {:?}", self.path()))?;
            chunk.set_compressed_offset(pre_c_offset);
            chunk.set_compressed_size(c_size);
            chunk.set_compressed(is_compressed);
        }

        if let Some(blob_cache) = ctx.blob_cache_generator.as_ref() {
            blob_cache.write_blob_data(chunk_data, chunk, aligned_d_size)?;
        }
        event_tracer!("blob_uncompressed_size", +d_size);

        Ok(chunk_info)
    }

    pub fn write_chunk_data(
        ctx: &BuildContext,
        blob_ctx: &mut BlobContext,
        blob_writer: &mut dyn Artifact,
        chunk_data: &[u8],
    ) -> Result<(u64, u32, bool)> {
        let (compressed, is_compressed) = compress::compress(chunk_data, ctx.compressor)
            .with_context(|| "failed to compress node file".to_string())?;
        let encrypted = crypt::encrypt_with_context(
            &compressed,
            &blob_ctx.cipher_object,
            &blob_ctx.cipher_ctx,
            blob_ctx.blob_cipher != crypt::Algorithm::None,
        )?;
        let compressed_size = encrypted.len() as u32;
        let pre_compressed_offset = blob_ctx.current_compressed_offset;
        blob_writer
            .write_all(&encrypted)
            .context("failed to write blob")?;
        blob_ctx.blob_hash.update(&encrypted);
        blob_ctx.current_compressed_offset += compressed_size as u64;
        blob_ctx.compressed_blob_size += compressed_size as u64;

        Ok((pre_compressed_offset, compressed_size, is_compressed))
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
                    blob_mgr.add_blob(ctx);
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
            inner: Arc::new(chunk),
        });

        Ok(None)
    }
}

// build node object from a filesystem object.
impl Node {
    /// Create a new instance of [Node] from a filesystem object.
    pub fn from_fs_object(
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
        let info = NodeInfo {
            explicit_uidgid,
            src_ino: 0,
            src_dev: u64::MAX,
            rdev: u64::MAX,
            source,
            target,
            path,
            target_vec,
            symlink: None,
            xattrs: RafsXAttrs::default(),
            v6_force_extended_inode,
        };
        let mut node = Node {
            info: Arc::new(info),
            index: 0,
            layer_idx: 0,
            overlay,
            inode: InodeWrapper::new(version),
            chunks: Vec::new(),
            v6_datalayout: EROFS_INODE_FLAT_PLAIN,
            v6_compact_inode: false,
            v6_offset: 0,
            v6_dirents_offset: 0,
            v6_dirents: Vec::new(),
        };

        node.build_inode(chunk_size)
            .context("failed to build Node from fs object")?;
        if version.is_v6() {
            node.v6_set_inode_compact();
        }

        Ok(node)
    }

    fn build_inode_xattr(&mut self) -> Result<()> {
        let file_xattrs = match xattr::list(self.path()) {
            Ok(x) => x,
            Err(e) => {
                if e.raw_os_error() == Some(libc::EOPNOTSUPP) {
                    return Ok(());
                } else {
                    return Err(anyhow!(
                        "failed to list xattr of {}, {}",
                        self.path().display(),
                        e
                    ));
                }
            }
        };

        let mut info = self.info.deref().clone();
        for key in file_xattrs {
            let value = xattr::get(self.path(), &key).with_context(|| {
                format!("failed to get xattr {:?} of {}", key, self.path().display())
            })?;
            info.xattrs.add(key, value.unwrap_or_default())?;
        }
        if !info.xattrs.is_empty() {
            self.inode.set_has_xattr(true);
        }
        self.info = Arc::new(info);

        Ok(())
    }

    fn build_inode_stat(&mut self) -> Result<()> {
        let meta = self
            .meta()
            .with_context(|| format!("failed to get metadata of {}", self.path().display()))?;
        let mut info = self.info.deref().clone();

        info.src_ino = meta.st_ino();
        info.src_dev = meta.st_dev();
        info.rdev = meta.st_rdev();

        self.inode.set_mode(meta.st_mode());
        if info.explicit_uidgid {
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
            self.v5_set_inode_blocks();
        }
        self.info = Arc::new(info);

        Ok(())
    }

    fn build_inode(&mut self, chunk_size: u32) -> Result<()> {
        let size = self.name().byte_size();
        if size > u16::MAX as usize {
            bail!("file name length 0x{:x} is too big", size,);
        }
        self.inode.set_name_size(size);

        // NOTE: Always retrieve xattr before attr so that we can know the size of xattr pairs.
        self.build_inode_xattr()
            .with_context(|| format!("failed to get xattr for {}", self.path().display()))?;
        self.build_inode_stat()
            .with_context(|| format!("failed to build inode {}", self.path().display()))?;

        if self.is_reg() {
            let chunk_count = self.chunk_count(chunk_size as u64).with_context(|| {
                format!("failed to get chunk count for {}", self.path().display())
            })?;
            self.inode.set_child_count(chunk_count);
        } else if self.is_symlink() {
            let target_path = fs::read_link(self.path()).with_context(|| {
                format!(
                    "failed to read symlink target for {}",
                    self.path().display()
                )
            })?;
            let symlink: OsString = target_path.into();
            let size = symlink.byte_size();
            if size > u16::MAX as usize {
                bail!("symlink content size 0x{:x} is too big", size);
            }
            self.inode.set_symlink_size(size);
            self.set_symlink(symlink);
        }

        Ok(())
    }

    fn meta(&self) -> Result<impl MetadataExt> {
        self.path()
            .symlink_metadata()
            .with_context(|| format!("failed to get metadata of {}", self.path().display()))
    }

    fn get_chunk_ofs(&mut self, meta: &RafsSuperMeta) -> Result<(u64, u64)> {
        if meta.version == RAFS_SUPER_VERSION_V6 {
            self.get_chunk_ofs_v6(meta)
        } else {
            self.get_chunk_ofs_v5(meta)
        }
    }

    fn get_chunk_ofs_v5(&mut self, meta: &RafsSuperMeta) -> Result<(u64, u64)> {
        unimplemented!()
    }

    fn get_chunk_ofs_v6(&mut self, meta: &RafsSuperMeta) -> Result<(u64, u64)> {
        let unit = size_of::<RafsV6InodeChunkAddr>() as u64;
        let block_size = if meta.flags.contains(RafsSuperFlags::TARTFS_MODE) {
            EROFS_BLOCK_SIZE_512
        } else {
            EROFS_BLOCK_SIZE_4096
        };
        let meta_offset = meta.meta_blkaddr as usize * block_size as usize;
        let nid = self.info.src_ino;
        let inode_offset = meta_offset
            .checked_add(nid as usize * EROFS_INODE_SLOT_SIZE)
            .unwrap();
        let inode = match self.inode.clone() {
            InodeWrapper::V5(i) => InodeWrapper::V5(i),
            InodeWrapper::V6(i) => InodeWrapper::V6(i),
            InodeWrapper::Ref(i) => {
                if meta.version == RAFS_SUPER_VERSION_V6 {
                    InodeWrapper::V6(RafsV6Inode::from(i.deref()))
                } else {
                    InodeWrapper::V5(RafsV5Inode::from(i.deref()))
                }
            }
        };
        self.inode = inode;
        let base = self.v6_size_with_xattr();
        let chunk_ofs = align_offset(inode_offset as u64 + base, unit);

        Ok((chunk_ofs, unit))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn dedup_chunk_for_node(
        &mut self,
        build_ctx: &BuildContext,
        blob_mgr: &mut BlobManager,
        meta: &RafsSuperMeta,
        writer: &mut dyn RafsIoWrite,
        cache_chunks: &mut HashMap<RafsDigest, ChunkWrapper>,
        insert_chunks: &mut Vec<(String, String, String)>,
        cas_mgr: &CasMgr,
        chunk_cache: &mut BTreeMap<DigestWithBlobIndex, Arc<ChunkWrapper>>,
    ) -> Result<()> {
        let (mut chunk_ofs, chunk_size) = self.get_chunk_ofs(meta)?;

        for chunk in &self.chunks {
            let chunk_id = chunk.inner.id();
            let origin_blob_index = chunk.inner.blob_index() as usize;
            let blob_id = blob_mgr
                .get_blob_id_by_idx(chunk.inner.blob_index() as usize)
                .unwrap();

            writer
                .seek(SeekFrom::Start(chunk_ofs))
                .context("failed seek for chunk_ofs")
                .unwrap();

            match cache_chunks.get(chunk_id) {
                // dedup chunk between layers
                Some(new_chunk) => {
                    // if the chunk is belong to other image's blob
                    let mut new_chunk = new_chunk.deref().clone();
                    let blob_index = new_chunk.blob_index() as usize;
                    if origin_blob_index != blob_index {
                        new_chunk.set_deduped(true);
                    }

                    chunk_cache.insert(
                        DigestWithBlobIndex(*new_chunk.id(), new_chunk.blob_index() + 1),
                        Arc::new(new_chunk.clone()),
                    );
                    self.dedup_bootstrap(build_ctx, &new_chunk, writer)?
                }
                None => match cas_mgr.get_chunk(chunk_id, &blob_id, true)? {
                    Some((new_blob_id, chunk_info)) => {
                        let blob_idx = match blob_mgr.get_blob_idx_by_id(&new_blob_id) {
                            Some(blob_idx) => blob_idx,
                            None => {
                                //Safe to use unwarp since we get blob_id from chunk table
                                let blob_info = cas_mgr.get_blob(&new_blob_id, true)?.unwrap();
                                let blob = serde_json::from_str::<BlobInfo>(&blob_info)?;
                                let blob_idx = blob_mgr.alloc_index()?;
                                blob_mgr.add_blob(BlobContext::from(
                                    build_ctx,
                                    &blob,
                                    ChunkSource::Parent,
                                )?);

                                blob_idx
                            }
                        };

                        let new_chunk = serde_json::from_str::<RafsV5ChunkInfo>(&chunk_info)?;
                        let mut new_chunk = match &build_ctx.fs_version {
                            RafsVersion::V5 => ChunkWrapper::V5(new_chunk),
                            RafsVersion::V6 => ChunkWrapper::V6(new_chunk),
                        };

                        // if this chunk is from other blob, mark it as dedup
                        if origin_blob_index != blob_idx as usize {
                            new_chunk.set_deduped(true);
                        }
                        new_chunk.set_blob_index(blob_idx);
                        chunk_cache.insert(
                            DigestWithBlobIndex(*new_chunk.id(), new_chunk.blob_index() + 1),
                            Arc::new(new_chunk.clone()),
                        );

                        self.dedup_bootstrap(build_ctx, &new_chunk, writer)?;
                        cache_chunks.insert(*chunk_id, new_chunk);
                    }
                    None => {
                        let new_chunk = chunk.inner.as_ref().clone();
                        cache_chunks.insert(*chunk_id, new_chunk.clone());
                        chunk_cache.insert(
                            DigestWithBlobIndex(*new_chunk.id(), new_chunk.blob_index() + 1),
                            Arc::new(new_chunk.clone()),
                        );

                        let chunk_info = match new_chunk.clone() {
                            ChunkWrapper::V5(c) => serde_json::to_string(&c).unwrap(),
                            ChunkWrapper::V6(c) => serde_json::to_string(&c).unwrap(),
                            ChunkWrapper::Ref(c) => {
                                let chunk = convert_ref_to_rafs_v5_chunk_info(c.deref());
                                serde_json::to_string(&chunk).unwrap()
                            }
                        };
                        insert_chunks.push((String::from(*chunk_id), chunk_info, blob_id));
                    }
                },
            }

            chunk_ofs += chunk_size;
        }
        Ok(())
    }

    pub fn dedup_bootstrap(
        &self,
        build_ctx: &BuildContext,
        chunk: &ChunkWrapper,
        writer: &mut dyn RafsIoWrite,
    ) -> Result<()> {
        match chunk {
            ChunkWrapper::V5(_) => self.dedup_bootstrap_v5(build_ctx, chunk, writer),
            ChunkWrapper::V6(_) => self.dedup_bootstrap_v6(build_ctx, chunk, writer),
            ChunkWrapper::Ref(_) => match &build_ctx.fs_version {
                RafsVersion::V5 => self.dedup_bootstrap_v5(build_ctx, chunk, writer),
                RafsVersion::V6 => self.dedup_bootstrap_v6(build_ctx, chunk, writer),
            },
        }
    }

    fn dedup_bootstrap_v5(
        &self,
        build_ctx: &BuildContext,
        chunk: &ChunkWrapper,
        writer: &mut dyn RafsIoWrite,
    ) -> Result<()> {
        chunk
            .store(writer)
            .context("failed to dump chunk info to bootstrap")
            .unwrap();
        anyhow::Ok(())
    }

    fn dedup_bootstrap_v6(
        &self,
        build_ctx: &BuildContext,
        chunk: &ChunkWrapper,
        writer: &mut dyn RafsIoWrite,
    ) -> Result<()> {
        let mut v6_chunk = RafsV6InodeChunkAddr::new();
        // for erofs, bump id by 1 since device id 0 is bootstrap.
        let offset = chunk.uncompressed_offset();
        let blk_addr = build_ctx.v6_block_addr(offset).with_context(|| {
            format!(
                "failed to compute blk_addr for chunk with uncompressed offset 0x{:x}",
                offset
            )
        })?;
        v6_chunk.set_blob_index(chunk.blob_index());
        v6_chunk.set_blob_ci_index(chunk.index());
        v6_chunk.set_block_addr(blk_addr);

        let mut chunks: Vec<u8> = Vec::new();
        chunks.extend(v6_chunk.as_ref());
        writer
            .write(chunks.as_slice())
            .context("failed to write chunkindexes")
            .unwrap();
        anyhow::Ok(())
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

    pub fn chunk_count(&self, chunk_size: u64) -> Result<u32> {
        if self.is_reg() {
            let chunks = div_round_up(self.inode.size(), chunk_size);
            if chunks > u32::MAX as u64 {
                bail!("file size 0x{:x} is too big", self.inode.size())
            } else {
                Ok(chunks as u32)
            }
        } else {
            Ok(0)
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
        let len = self.info.target_vec.len();
        if len != 0 {
            &self.info.target_vec[len - 1]
        } else if self.path() == &self.info.source {
            OsStr::from_bytes(ROOT_PATH_NAME)
        } else {
            // Safe to unwrap because `path` is returned from `path()` which is canonicalized
            self.path().file_name().unwrap()
        }
    }

    /// Get path of the inode
    pub fn path(&self) -> &PathBuf {
        &self.info.path
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
        &self.info.target_vec
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
        &self.info.target
    }

    /// Set symlink target for the node.
    pub fn set_symlink(&mut self, symlink: OsString) {
        let mut info = self.info.deref().clone();
        info.symlink = Some(symlink);
        self.info = Arc::new(info);
    }

    /// Set extended attributes for the node.
    pub fn set_xattr(&mut self, xattr: RafsXAttrs) {
        let mut info = self.info.deref().clone();
        info.xattrs = xattr;
        self.info = Arc::new(info);
    }

    /// Delete an extend attribute with id `key`.
    pub fn remove_xattr(&mut self, key: &OsStr) {
        let mut info = self.info.deref().clone();
        info.xattrs.remove(key);
        if info.xattrs.is_empty() {
            self.inode.set_has_xattr(false);
        }
        self.info = Arc::new(info);
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use nydus_utils::{digest, BufReaderInfo};
    use vmm_sys_util::tempfile::TempFile;

    use crate::{ArtifactWriter, BlobCacheGenerator, HashChunkDict};

    use super::*;

    #[test]
    fn test_node_chunk() {
        let chunk_wrapper1 = ChunkWrapper::new(RafsVersion::V5);
        let mut chunk = NodeChunk {
            source: ChunkSource::Build,
            inner: Arc::new(chunk_wrapper1),
        };
        println!("NodeChunk: {}", chunk);
        matches!(chunk.inner.deref().clone(), ChunkWrapper::V5(_));

        let chunk_wrapper2 = ChunkWrapper::new(RafsVersion::V6);
        chunk.copy_from(&chunk_wrapper2);
        matches!(chunk.inner.deref().clone(), ChunkWrapper::V6(_));

        chunk.set_index(0x10);
        assert_eq!(chunk.inner.index(), 0x10);
        chunk.set_blob_index(0x20);
        assert_eq!(chunk.inner.blob_index(), 0x20);
        chunk.set_compressed_size(0x30);
        assert_eq!(chunk.inner.compressed_size(), 0x30);
        chunk.set_file_offset(0x40);
        assert_eq!(chunk.inner.file_offset(), 0x40);
    }

    #[test]
    fn test_node_dump_node_data() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/blobs/be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef");

        let mut inode = InodeWrapper::new(RafsVersion::V5);
        inode.set_child_count(2);
        inode.set_size(20);
        let info = NodeInfo {
            explicit_uidgid: true,
            src_ino: 1,
            src_dev: u64::MAX,
            rdev: u64::MAX,
            path: source_path.clone(),
            source: PathBuf::from("/"),
            target: source_path.clone(),
            target_vec: vec![OsString::from(source_path)],
            symlink: Some(OsString::from("symlink")),
            xattrs: RafsXAttrs::new(),
            v6_force_extended_inode: false,
        };
        let mut node = Node::new(inode, info, 1);

        let mut ctx = BuildContext::default();
        ctx.set_chunk_size(2);
        ctx.conversion_type = ConversionType::TarToRef;
        ctx.cipher = crypt::Algorithm::Aes128Xts;
        let tmp_file1 = TempFile::new().unwrap();
        std::fs::write(
            tmp_file1.as_path(),
            "This is a test!\n".repeat(32).as_bytes(),
        )
        .unwrap();
        let buf_reader = BufReader::new(tmp_file1.into_file());
        ctx.blob_tar_reader = Some(BufReaderInfo::from_buf_reader(buf_reader));
        let tmp_file2 = TempFile::new().unwrap();
        ctx.blob_cache_generator = Some(
            BlobCacheGenerator::new(crate::ArtifactStorage::SingleFile(PathBuf::from(
                tmp_file2.as_path(),
            )))
            .unwrap(),
        );

        let mut blob_mgr = BlobManager::new(digest::Algorithm::Sha256);
        let mut chunk_dict = HashChunkDict::new(digest::Algorithm::Sha256);
        let mut chunk_wrapper = ChunkWrapper::new(RafsVersion::V5);
        chunk_wrapper.set_id(RafsDigest {
            data: [
                209, 217, 144, 116, 135, 113, 3, 121, 133, 92, 96, 25, 219, 145, 151, 219, 119, 47,
                96, 147, 90, 51, 78, 44, 193, 149, 6, 102, 13, 173, 138, 191,
            ],
        });
        chunk_wrapper.set_uncompressed_size(2);
        chunk_dict.add_chunk(Arc::new(chunk_wrapper), digest::Algorithm::Sha256);
        blob_mgr.set_chunk_dict(Arc::new(chunk_dict));

        let tmp_file3 = TempFile::new().unwrap();
        let mut blob_writer = ArtifactWriter::new(crate::ArtifactStorage::SingleFile(
            PathBuf::from(tmp_file3.as_path()),
        ))
        .unwrap();

        let mut chunk_data_buf = [1u8; 32];

        node.inode.set_mode(0o755 | libc::S_IFDIR as u32);
        let data_size =
            node.dump_node_data(&ctx, &mut blob_mgr, &mut blob_writer, &mut chunk_data_buf);
        assert!(data_size.is_ok());
        assert_eq!(data_size.unwrap(), 0);

        node.inode.set_mode(0o755 | libc::S_IFLNK as u32);
        let data_size =
            node.dump_node_data(&ctx, &mut blob_mgr, &mut blob_writer, &mut chunk_data_buf);
        assert!(data_size.is_ok());
        assert_eq!(data_size.unwrap(), 0);

        node.inode.set_mode(0o755 | libc::S_IFBLK as u32);
        let data_size =
            node.dump_node_data(&ctx, &mut blob_mgr, &mut blob_writer, &mut chunk_data_buf);
        assert!(data_size.is_ok());
        assert_eq!(data_size.unwrap(), 0);

        node.inode.set_mode(0o755 | libc::S_IFREG as u32);
        let data_size =
            node.dump_node_data(&ctx, &mut blob_mgr, &mut blob_writer, &mut chunk_data_buf);
        assert!(data_size.is_ok());
        assert_eq!(data_size.unwrap(), 18);
    }

    #[test]
    fn test_node() {
        let inode = InodeWrapper::new(RafsVersion::V5);
        let info = NodeInfo {
            explicit_uidgid: true,
            src_ino: 1,
            src_dev: u64::MAX,
            rdev: u64::MAX,
            path: PathBuf::new(),
            source: PathBuf::new(),
            target: PathBuf::new(),
            target_vec: vec![OsString::new()],
            symlink: None,
            xattrs: RafsXAttrs::new(),
            v6_force_extended_inode: false,
        };

        let mut inode1 = inode.clone();
        inode1.set_size(1 << 60);
        inode1.set_mode(0o755 | libc::S_IFREG as u32);
        let node = Node::new(inode1, info.clone(), 1);
        assert!(node.chunk_count(2).is_err());

        let mut inode2 = inode.clone();
        inode2.set_mode(0o755 | libc::S_IFCHR as u32);
        let node = Node::new(inode2, info.clone(), 1);
        assert!(node.chunk_count(2).is_ok());
        assert_eq!(node.chunk_count(2).unwrap(), 0);

        let mut inode3 = inode.clone();
        inode3.set_mode(0o755 | libc::S_IFLNK as u32);
        let node = Node::new(inode3, info.clone(), 1);
        assert_eq!(node.file_type(), "symlink");
        let mut inode4 = inode.clone();
        inode4.set_mode(0o755 | libc::S_IFDIR as u32);
        let node = Node::new(inode4, info.clone(), 1);
        assert_eq!(node.file_type(), "dir");
        let mut inode5 = inode.clone();
        inode5.set_mode(0o755 | libc::S_IFREG as u32);
        let node = Node::new(inode5, info.clone(), 1);
        assert_eq!(node.file_type(), "file");

        let mut info1 = info.clone();
        info1.target_vec = vec![OsString::from("1"), OsString::from("2")];
        let node = Node::new(inode.clone(), info1, 1);
        assert_eq!(node.name(), OsString::from("2").as_os_str());
        let mut info2 = info.clone();
        info2.target_vec = vec![];
        info2.path = PathBuf::from("/");
        info2.source = PathBuf::from("/");
        let node = Node::new(inode.clone(), info2, 1);
        assert_eq!(node.name(), OsStr::from_bytes(ROOT_PATH_NAME));
        let mut info3 = info.clone();
        info3.target_vec = vec![];
        info3.path = PathBuf::from("/1");
        info3.source = PathBuf::from("/11");
        let node = Node::new(inode.clone(), info3, 1);
        assert_eq!(node.name(), OsStr::new("1"));

        let target = PathBuf::from("/root/child");
        assert_eq!(
            Node::generate_target_vec(&target),
            vec![
                OsString::from("/"),
                OsString::from("root"),
                OsString::from("child")
            ]
        );

        let mut node = Node::new(inode, info, 1);
        node.set_symlink(OsString::from("symlink"));
        assert_eq!(node.info.deref().symlink, Some(OsString::from("symlink")));

        let mut xatter = RafsXAttrs::new();
        assert!(xatter
            .add(OsString::from("user.key"), [1u8; 16].to_vec())
            .is_ok());
        assert!(xatter
            .add(
                OsString::from("system.posix_acl_default.key"),
                [2u8; 8].to_vec()
            )
            .is_ok());
        node.set_xattr(xatter);
        node.inode.set_has_xattr(true);
        node.remove_xattr(OsStr::new("user.key"));
        assert!(node.inode.has_xattr());
        node.remove_xattr(OsStr::new("system.posix_acl_default.key"));
        assert!(!node.inode.has_xattr());
    }
}
