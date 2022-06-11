// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Struct to maintain context information for the image builder.

use std::any::Any;
use std::collections::{HashMap, VecDeque};
use std::convert::TryFrom;
use std::fs::{remove_file, rename, File, OpenOptions};
use std::io::{BufWriter, Cursor, Write};
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::{EntryType, Header};
use vmm_sys_util::tempfile::TempFile;

use nydus_utils::{compress, digest, div_round_up, round_down_4k};
use rafs::metadata::layout::v5::RafsV5BlobTable;
use rafs::metadata::layout::v6::{RafsV6BlobTable, EROFS_BLOCK_SIZE, EROFS_INODE_SLOT_SIZE};
use rafs::metadata::layout::{RafsBlobTable, RAFS_SUPER_VERSION_V5, RAFS_SUPER_VERSION_V6};
use rafs::metadata::RafsSuperFlags;
use rafs::metadata::{Inode, RAFS_DEFAULT_CHUNK_SIZE, RAFS_MAX_CHUNK_SIZE};
use rafs::{RafsIoReader, RafsIoWrite};
use storage::device::{BlobFeatures, BlobInfo};
use storage::meta::{BlobChunkInfoOndisk, BlobMetaHeaderOndisk};

use super::chunk_dict::{ChunkDict, HashChunkDict};
use super::layout::BlobLayout;
use super::node::{ChunkSource, ChunkWrapper, Node, WhiteoutSpec};
use super::prefetch::{Prefetch, PrefetchPolicy};

// TODO: select BufWriter capacity by performance testing.
pub const BUF_WRITER_CAPACITY: usize = 2 << 17;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RafsVersion {
    V5,
    V6,
}

impl Default for RafsVersion {
    fn default() -> Self {
        RafsVersion::V5
    }
}

impl TryFrom<u32> for RafsVersion {
    type Error = Error;
    fn try_from(version: u32) -> Result<Self, Self::Error> {
        if version == RAFS_SUPER_VERSION_V5 {
            return Ok(RafsVersion::V5);
        } else if version == RAFS_SUPER_VERSION_V6 {
            return Ok(RafsVersion::V6);
        }
        Err(anyhow!("invalid version {}", version))
    }
}

impl RafsVersion {
    #[allow(dead_code)]
    pub fn is_v5(&self) -> bool {
        self == &Self::V5
    }

    pub fn is_v6(&self) -> bool {
        self == &Self::V6
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SourceType {
    Directory,
    StargzIndex,
    Diff,
}

impl Default for SourceType {
    fn default() -> Self {
        Self::Directory
    }
}

impl FromStr for SourceType {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "directory" => Ok(Self::Directory),
            "stargz_index" => Ok(Self::StargzIndex),
            "diff" => Ok(Self::Diff),
            _ => Err(anyhow!("invalid source type")),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ArtifactStorage {
    // Won't rename user's specification
    SingleFile(PathBuf),
    // Will rename it from tmp file as user didn't specify a name.
    FileDir(PathBuf),
}

impl Default for ArtifactStorage {
    fn default() -> Self {
        Self::SingleFile(PathBuf::new())
    }
}

impl ArtifactStorage {
    fn get_path(&self, name: &str) -> PathBuf {
        match self {
            Self::SingleFile(path) => path.to_path_buf(),
            Self::FileDir(base) => base.join(name),
        }
    }
}

/// ArtifactMemoryWriter provides a writer to allow writing bootstrap
/// data to a byte slice in memory.
pub struct ArtifactMemoryWriter(Cursor<Vec<u8>>);

impl RafsIoWrite for ArtifactMemoryWriter {
    fn as_any(&self) -> &dyn Any {
        &self.0
    }

    fn data(&self) -> &[u8] {
        self.0.get_ref()
    }
}

impl std::io::Seek for ArtifactMemoryWriter {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.0.seek(pos)
    }
}

impl std::io::Write for ArtifactMemoryWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

pub struct ArtifactFileWriter(ArtifactWriter);

impl RafsIoWrite for ArtifactFileWriter {
    fn as_any(&self) -> &dyn Any {
        &self.0
    }

    fn finalize(&mut self, name: Option<String>) -> Result<()> {
        self.0.finalize(name)
    }
}

impl std::io::Seek for ArtifactFileWriter {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.0.file.seek(pos)
    }
}

impl std::io::Write for ArtifactFileWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// ArtifactWriter provides a writer to allow writing bootstrap
/// or blob data to a single file or in a directory.
pub struct ArtifactWriter {
    pos: usize,
    file: BufWriter<File>,
    storage: ArtifactStorage,
    // Keep this because tmp file will be removed automatically when it is dropped.
    // But we will rename/link the tmp file before it is removed.
    tmp_file: Option<TempFile>,
}

impl std::io::Write for ArtifactWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let n = self.file.write(bytes)?;
        self.pos += n;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl ArtifactWriter {
    pub fn new(storage: ArtifactStorage, fifo: bool) -> Result<Self> {
        match storage {
            ArtifactStorage::SingleFile(ref p) => {
                let mut opener = &mut OpenOptions::new();
                opener = opener.write(true).create(true);
                // Make it as the writer side of FIFO file, no truncate flag because it has
                // been created by the reader side.
                if !fifo {
                    opener = opener.truncate(true);
                }
                let b = BufWriter::with_capacity(
                    BUF_WRITER_CAPACITY,
                    opener
                        .open(p)
                        .with_context(|| format!("failed to open file {:?}", p))?,
                );
                Ok(Self {
                    pos: 0,
                    file: b,
                    storage,
                    tmp_file: None,
                })
            }
            ArtifactStorage::FileDir(ref p) => {
                // Better we can use open(2) O_TMPFILE, but for compatibility sake, we delay this job.
                // TODO: Blob dir existence?
                let tmp = TempFile::new_in(p)
                    .with_context(|| format!("failed to create temp file in {:?}", p))?;
                let tmp2 = tmp.as_file().try_clone()?;
                Ok(Self {
                    pos: 0,
                    file: BufWriter::with_capacity(BUF_WRITER_CAPACITY, tmp2),
                    storage,
                    tmp_file: Some(tmp),
                })
            }
        }
    }

    // The `inline-bootstrap` option merges the blob and bootstrap into one
    // file. We need some header to index the location of the blob and bootstrap,
    // write_tar_header uses tar header that arranges the data as follows:

    // blob_data | blob_tar_header | bootstrap_data | bootstrap_tar_header

    // This is a tar-like structure, except that we put the tar header after the
    // data. The advantage is that we do not need to determine the size of the data
    // first, so that we can write the blob data by stream without seek to improve
    // the performance of the blob dump by using fifo, if we need to read the bootstrap
    // data quickly, first need to read the 512 bytes tar header from the end of blob
    // file first, and then seek offset to read bootstrap data.
    pub fn write_tar_header(&mut self, name: &str, size: u64) -> Result<()> {
        let mut header = Header::new_gnu();
        header.set_path(Path::new(name))?;
        header.set_entry_type(EntryType::Regular);
        header.set_size(size);
        // The checksum must be set to ensure that the tar reader implementation
        // in golang can correctly parse the header.
        header.set_cksum();
        self.write_all(header.as_bytes())?;
        Ok(())
    }

    pub fn pos(&self) -> Result<u64> {
        Ok(self.pos as u64)
    }

    pub fn finalize(&mut self, name: Option<String>) -> Result<()> {
        self.file.flush()?;

        if let Some(n) = name {
            if let ArtifactStorage::FileDir(s) = &self.storage {
                let might_exist_path = Path::new(s).join(n);
                if might_exist_path.exists() {
                    return Ok(());
                }

                if let Some(tmp_file) = &self.tmp_file {
                    rename(tmp_file.as_path(), &might_exist_path).with_context(|| {
                        format!(
                            "failed to rename blob {:?} to {:?}",
                            tmp_file.as_path(),
                            might_exist_path
                        )
                    })?;
                }
            }
        } else if let ArtifactStorage::SingleFile(s) = &self.storage {
            // `new_name` is None means no blob is really built, perhaps due to dedup.
            // We don't want to puzzle user, so delete it from here.
            // In the future, FIFO could be leveraged, don't remove it then.
            remove_file(s).with_context(|| format!("failed to remove blob {:?}", s))?;
        }

        Ok(())
    }
}

/// BlobContext is used to hold the blob information of a layer during build.
pub struct BlobContext {
    /// Blob id (user specified or sha256(blob)).
    pub blob_id: String,
    pub blob_hash: Sha256,
    pub blob_readahead_size: u64,
    /// Blob data layout manager
    pub blob_layout: BlobLayout,
    /// Data chunks stored in the data blob, for v6.
    pub blob_meta_info: Vec<BlobChunkInfoOndisk>,
    /// Whether to generate blob metadata information.
    pub blob_meta_info_enabled: bool,
    /// Blob metadata header stored in the data blob, for v6
    pub blob_meta_header: BlobMetaHeaderOndisk,

    /// Final compressed blob file size.
    pub compressed_blob_size: u64,
    /// Final expected blob cache file size.
    pub decompressed_blob_size: u64,

    /// Current blob offset cursor for writing to disk file.
    pub compress_offset: u64,
    pub decompress_offset: u64,

    /// The number of counts in a blob by the index of blob table.
    pub chunk_count: u32,
    /// Chunk slice size.
    pub chunk_size: u32,
    /// Scratch data buffer for reading from/writing to disk files.
    pub chunk_data_buf: Vec<u8>,
    /// ChunkDict which would be loaded when builder start
    pub chunk_dict: Arc<dyn ChunkDict>,
    /// Whether the blob is from chunk dict.
    pub chunk_source: ChunkSource,

    // Blob writer for writing to disk file.
    pub writer: Option<ArtifactWriter>,
}

impl Clone for BlobContext {
    fn clone(&self) -> Self {
        Self {
            blob_id: self.blob_id.clone(),
            blob_hash: self.blob_hash.clone(),
            blob_readahead_size: self.blob_readahead_size,
            blob_layout: self.blob_layout.clone(),
            blob_meta_info: self.blob_meta_info.clone(),
            blob_meta_info_enabled: self.blob_meta_info_enabled,
            blob_meta_header: self.blob_meta_header,

            compressed_blob_size: self.compressed_blob_size,
            decompressed_blob_size: self.decompressed_blob_size,

            compress_offset: self.compress_offset,
            decompress_offset: self.decompress_offset,

            chunk_count: self.chunk_count,
            chunk_size: self.chunk_size,
            chunk_data_buf: self.chunk_data_buf.clone(),
            chunk_dict: self.chunk_dict.clone(),
            chunk_source: self.chunk_source.clone(),
            writer: None,
        }
    }
}

impl BlobContext {
    pub fn new(
        blob_id: String,
        blob_stor: Option<ArtifactStorage>,
        blob_offset: u64,
        fifo: bool,
    ) -> Result<Self> {
        let writer = if let Some(blob_stor) = blob_stor {
            Some(ArtifactWriter::new(blob_stor, fifo)?)
        } else {
            None
        };

        Ok(Self::new_with_writer(blob_id, writer, blob_offset))
    }

    pub fn from(ctx: &BuildContext, blob: &BlobInfo, chunk_source: ChunkSource) -> Self {
        let mut blob_ctx = Self::new_with_writer(blob.blob_id().to_owned(), None, 0);

        blob_ctx.blob_readahead_size = blob.readahead_size();
        blob_ctx.chunk_count = blob.chunk_count();
        blob_ctx.decompressed_blob_size = blob.uncompressed_size();
        blob_ctx.compressed_blob_size = blob.compressed_size();
        blob_ctx.chunk_size = blob.chunk_size();
        blob_ctx.chunk_source = chunk_source;
        blob_ctx.blob_meta_header.set_4k_aligned(ctx.aligned_chunk);

        if blob.meta_ci_is_valid() {
            blob_ctx
                .blob_meta_header
                .set_ci_compressor(blob.meta_ci_compressor());
            blob_ctx.blob_meta_header.set_ci_entries(blob.chunk_count());
            blob_ctx
                .blob_meta_header
                .set_ci_compressed_offset(blob.meta_ci_offset());
            blob_ctx
                .blob_meta_header
                .set_ci_compressed_size(blob.meta_ci_compressed_size());
            blob_ctx
                .blob_meta_header
                .set_ci_uncompressed_size(blob.meta_ci_uncompressed_size());
            blob_ctx.blob_meta_header.set_4k_aligned(true);
            blob_ctx.blob_meta_info_enabled = true;
        }

        blob_ctx
    }

    pub fn new_with_writer(
        blob_id: String,
        writer: Option<ArtifactWriter>,
        blob_offset: u64,
    ) -> Self {
        let size = if writer.is_some() {
            RAFS_MAX_CHUNK_SIZE as usize
        } else {
            0
        };

        Self {
            blob_id,
            blob_hash: Sha256::new(),
            blob_readahead_size: 0,
            blob_layout: BlobLayout::new(),
            blob_meta_info_enabled: false,
            blob_meta_info: Vec::new(),
            blob_meta_header: BlobMetaHeaderOndisk::default(),

            compressed_blob_size: 0,
            decompressed_blob_size: 0,

            compress_offset: blob_offset,
            decompress_offset: 0,

            chunk_count: 0,
            chunk_size: RAFS_DEFAULT_CHUNK_SIZE as u32,
            chunk_data_buf: vec![0u8; size],
            chunk_dict: Arc::new(()),
            chunk_source: ChunkSource::Build,

            writer,
        }
    }

    pub fn set_chunk_dict(&mut self, dict: Arc<dyn ChunkDict>) {
        self.chunk_dict = dict;
    }

    pub fn set_chunk_size(&mut self, chunk_size: u32) {
        self.chunk_size = chunk_size;
    }

    pub fn set_blob_readahead_size(&mut self, ctx: &BuildContext) {
        if (self.compressed_blob_size > 0
            || (ctx.source_type == SourceType::StargzIndex && !self.blob_id.is_empty()))
            && ctx.prefetch.policy != PrefetchPolicy::Blob
        {
            self.blob_readahead_size = 0;
        }
    }

    pub fn set_meta_info_enabled(&mut self, enable: bool) {
        self.blob_meta_info_enabled = enable;
    }

    pub fn add_chunk_meta_info(&mut self, chunk: &ChunkWrapper) -> Result<()> {
        if !self.blob_meta_info_enabled {
            return Ok(());
        }

        debug_assert!(chunk.index() as usize == self.blob_meta_info.len());
        let mut meta = BlobChunkInfoOndisk::default();
        meta.set_compressed_offset(chunk.compressed_offset());
        meta.set_compressed_size(chunk.compressed_size());
        meta.set_uncompressed_offset(chunk.uncompressed_offset());
        meta.set_uncompressed_size(chunk.uncompressed_size());
        trace!(
            "chunk uncompressed {} size {}",
            meta.uncompressed_offset(),
            meta.uncompressed_size()
        );
        self.blob_meta_info.push(meta);

        Ok(())
    }

    /// Allocate a count index sequentially in a blob.
    pub fn alloc_index(&mut self) -> Result<u32> {
        let index = self.chunk_count;

        // Rafs v6 only supports 24 bit chunk id.
        if index >= 0xff_ffff {
            Err(Error::msg(
                "the number of chunks in blob exceeds the u32 limit",
            ))
        } else {
            self.chunk_count += 1;
            Ok(index)
        }
    }

    pub fn blob_id(&mut self) -> Option<String> {
        if self.compressed_blob_size > 0 {
            Some(self.blob_id.to_string())
        } else {
            None
        }
    }
}

/// BlobManager stores all blob related information during build.
pub struct BlobManager {
    /// Some layers may not have a blob (only have metadata), so Option
    /// is used here, the vector index will be as the layer index.
    ///
    /// We can get blob index for a layer by using:
    /// `self.blobs.iter().flatten().collect()[layer_index];`
    blobs: Vec<BlobContext>,
    /// Chunk dictionary from reference image or base layer.
    pub chunk_dict_ref: Arc<dyn ChunkDict>,
    /// Chunk dictionary to hold new chunks from the upper layer.
    pub chunk_dict_cache: HashChunkDict,
}

impl BlobManager {
    pub fn new() -> Self {
        Self {
            blobs: Vec::new(),
            chunk_dict_ref: Arc::new(()),
            chunk_dict_cache: HashChunkDict::default(),
        }
    }

    pub fn set_chunk_dict(&mut self, dict: Arc<dyn ChunkDict>) {
        self.chunk_dict_ref = dict
    }

    pub fn get_chunk_dict(&self) -> Arc<dyn ChunkDict> {
        self.chunk_dict_ref.clone()
    }

    /// Allocate a blob index sequentially.
    ///
    /// This should be paired with Self::add() and keep in consistence.
    pub fn alloc_index(&self) -> Result<u32> {
        // Rafs v6 only supports 256 blobs.
        u8::try_from(self.blobs.len())
            .map(|v| v as u32)
            .with_context(|| Error::msg("too many blobs"))
    }

    /// Add a blob context to manager
    ///
    /// This should be paired with Self::alloc_index() and keep in consistence.
    pub fn add(&mut self, blob_ctx: BlobContext) {
        self.blobs.push(blob_ctx);
    }

    pub fn len(&self) -> usize {
        self.blobs.len()
    }

    /// Get all blob contexts (include the blob context that does not have a blob).
    pub fn get_blobs(&self) -> Vec<&BlobContext> {
        self.blobs.iter().collect()
    }

    pub fn get_blob(&self, idx: usize) -> Option<&BlobContext> {
        self.blobs.get(idx)
    }

    pub fn take_blob(&mut self, idx: usize) -> BlobContext {
        self.blobs.remove(idx)
    }

    pub fn get_last_blob(&self) -> Option<&BlobContext> {
        self.blobs.last()
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn from_blob_table(&mut self, ctx: &BuildContext, blob_table: Vec<Arc<BlobInfo>>) {
        self.blobs = blob_table
            .iter()
            .map(|entry| BlobContext::from(ctx, entry.as_ref(), ChunkSource::Parent))
            .collect();
    }

    pub fn get_blob_idx_by_id(&self, id: &str) -> Option<u32> {
        for (idx, blob) in self.blobs.iter().enumerate() {
            if blob.blob_id.eq(id) {
                return Some(idx as u32);
            }
        }
        None
    }

    pub fn get_blob_ids(&self) -> Vec<String> {
        self.blobs.iter().map(|b| b.blob_id.to_owned()).collect()
    }

    /// Extend blobs which belong to ChunkDict and setup real_blob_idx map
    /// should call this function after import parent bootstrap
    /// otherwise will break blobs order
    pub fn extend_blob_table_from_chunk_dict(&mut self, ctx: &BuildContext) -> Result<()> {
        let blobs = self.chunk_dict_ref.get_blobs();

        for blob in blobs.iter() {
            if let Some(real_idx) = self.get_blob_idx_by_id(blob.blob_id()) {
                self.chunk_dict_ref
                    .set_real_blob_idx(blob.blob_index(), real_idx);
            } else {
                let idx = self.alloc_index()?;
                self.add(BlobContext::from(ctx, blob.as_ref(), ChunkSource::Dict));
                self.chunk_dict_ref
                    .set_real_blob_idx(blob.blob_index(), idx);
            }
        }

        Ok(())
    }

    pub fn to_blob_table(&self, build_ctx: &BuildContext) -> Result<RafsBlobTable> {
        let mut blob_table = match build_ctx.fs_version {
            RafsVersion::V5 => RafsBlobTable::V5(RafsV5BlobTable::new()),
            RafsVersion::V6 => RafsBlobTable::V6(RafsV6BlobTable::new()),
        };

        for ctx in &self.blobs {
            let blob_id = ctx.blob_id.clone();
            let blob_readahead_size = u32::try_from(ctx.blob_readahead_size)?;
            let chunk_count = ctx.chunk_count;
            let decompressed_blob_size = ctx.decompressed_blob_size;
            let compressed_blob_size = ctx.compressed_blob_size;
            let blob_features = BlobFeatures::empty();
            let mut flags = RafsSuperFlags::empty();
            match &mut blob_table {
                RafsBlobTable::V5(table) => {
                    flags |= RafsSuperFlags::from(build_ctx.compressor);
                    flags |= RafsSuperFlags::from(build_ctx.digester);
                    table.add(
                        blob_id,
                        0,
                        blob_readahead_size,
                        ctx.chunk_size,
                        chunk_count,
                        decompressed_blob_size,
                        compressed_blob_size,
                        blob_features,
                        flags,
                    );
                }
                RafsBlobTable::V6(table) => {
                    flags |= RafsSuperFlags::from(build_ctx.compressor);
                    flags |= RafsSuperFlags::from(build_ctx.digester);
                    table.add(
                        blob_id,
                        0,
                        blob_readahead_size,
                        ctx.chunk_size,
                        chunk_count,
                        decompressed_blob_size,
                        compressed_blob_size,
                        blob_features,
                        flags,
                        ctx.blob_meta_header,
                    );
                }
            }
        }

        Ok(blob_table)
    }
}

/// BootstrapContext is used to hold inmemory data of bootstrap during build.
pub struct BootstrapContext {
    /// This build has a parent bootstrap.
    pub layered: bool,
    /// Cache node index for hardlinks, HashMap<(layer_index, real_inode, dev), Vec<index>>.
    pub inode_map: HashMap<(u16, Inode, u64), Vec<u64>>,
    /// Store all nodes in ascendant ordor, indexed by (node.index - 1).
    pub nodes: Vec<Node>,
    /// Current position to write in f_bootstrap
    pub offset: u64,
    /// Bootstrap file name, only be used for diff build.
    pub name: String,
    pub blobs: Vec<BuildOutputBlob>,
    /// Not fully used blocks
    pub available_blocks: Vec<VecDeque<u64>>,
    pub writer: Box<dyn RafsIoWrite>,
}

impl BootstrapContext {
    pub fn new(storage: Option<ArtifactStorage>, layered: bool, fifo: bool) -> Result<Self> {
        let writer = if let Some(storage) = storage {
            Box::new(ArtifactFileWriter(ArtifactWriter::new(storage, fifo)?))
                as Box<dyn RafsIoWrite>
        } else {
            Box::new(ArtifactMemoryWriter(Cursor::new(Vec::new()))) as Box<dyn RafsIoWrite>
        };
        Ok(Self {
            layered,
            inode_map: HashMap::new(),
            nodes: Vec::new(),
            offset: EROFS_BLOCK_SIZE,
            name: String::new(),
            blobs: Vec::new(),
            available_blocks: vec![
                VecDeque::new();
                EROFS_BLOCK_SIZE as usize / EROFS_INODE_SLOT_SIZE
            ],
            writer,
        })
    }

    pub fn align_offset(&mut self, align_size: u64) {
        if self.offset % align_size > 0 {
            self.offset = div_round_up(self.offset, align_size) * align_size;
        }
    }

    // Only used to allocate space for metadata(inode / inode + inline data).
    // Try to find an used block with no less than `size` space left.
    // If found it, return the offset where we can store data.
    // If not, return 0.
    pub fn allocate_available_block(&mut self, size: u64) -> u64 {
        if size >= EROFS_BLOCK_SIZE {
            return 0;
        }

        let min_idx = div_round_up(size, EROFS_INODE_SLOT_SIZE as u64) as usize;
        let max_idx = div_round_up(EROFS_BLOCK_SIZE, EROFS_INODE_SLOT_SIZE as u64) as usize;

        for idx in min_idx..max_idx {
            let blocks = &mut self.available_blocks[idx];
            if let Some(mut offset) = blocks.pop_front() {
                offset += EROFS_BLOCK_SIZE - (idx * EROFS_INODE_SLOT_SIZE) as u64;
                self.append_available_block(offset + (min_idx * EROFS_INODE_SLOT_SIZE) as u64);
                return offset;
            }
        }

        0
    }

    // Append the block that `offset` belongs to corresponding deque.
    pub fn append_available_block(&mut self, offset: u64) {
        if offset % EROFS_BLOCK_SIZE == 0 {
            return;
        }
        let avail = EROFS_BLOCK_SIZE - offset % EROFS_BLOCK_SIZE;
        let idx = avail as usize / EROFS_INODE_SLOT_SIZE;
        self.available_blocks[idx].push_back(round_down_4k(offset));
    }
}

/// BootstrapManager is used to hold the parent bootstrap reader and create
/// new bootstrap context.
pub struct BootstrapManager {
    /// Parent bootstrap file reader.
    pub f_parent_bootstrap: Option<RafsIoReader>,
    bootstrap_storage: Option<ArtifactStorage>,
    /// The vector index will be as the layer index.
    /// We can get the bootstrap of a layer by using:
    /// `self.bootstraps[layer_index];`
    bootstraps: Vec<BootstrapContext>,
}

impl BootstrapManager {
    pub fn new(
        bootstrap_storage: Option<ArtifactStorage>,
        f_parent_bootstrap: Option<RafsIoReader>,
    ) -> Self {
        Self {
            f_parent_bootstrap,
            bootstrap_storage,
            bootstraps: Vec::new(),
        }
    }

    pub fn create_ctx(&self, fifo: bool) -> Result<BootstrapContext> {
        BootstrapContext::new(
            self.bootstrap_storage.clone(),
            self.f_parent_bootstrap.is_some(),
            fifo,
        )
    }

    pub fn add(&mut self, bootstrap_ctx: BootstrapContext) {
        self.bootstraps.push(bootstrap_ctx);
    }

    pub fn get_bootstraps(&self) -> &Vec<BootstrapContext> {
        &self.bootstraps
    }

    pub fn get_last_bootstrap(&self) -> Option<String> {
        self.bootstraps.last().map(|b| b.name.to_owned())
    }

    pub fn get_bootstrap_path(&self, name: &str) -> Option<PathBuf> {
        self.bootstrap_storage.as_ref().map(|s| s.get_path(name))
    }
}

#[derive(Clone)]
pub struct BuildContext {
    /// Blob id (user specified or sha256(blob)).
    pub blob_id: String,

    /// When filling local blobcache file, chunks are arranged as per the
    /// `decompress_offset` within chunk info. Therefore, provide a new flag
    /// to image tool thus to align chunks in blob with 4k size.
    pub aligned_chunk: bool,
    /// Add a offset for compressed blob.
    pub blob_offset: u64,
    /// Blob chunk compress flag.
    pub compressor: compress::Algorithm,
    /// Inode and chunk digest algorithm flag.
    pub digester: digest::Algorithm,
    /// Save host uid gid in each inode.
    pub explicit_uidgid: bool,
    /// whiteout spec: overlayfs or oci
    pub whiteout_spec: WhiteoutSpec,
    /// Chunk slice size.
    pub chunk_size: u32,
    /// Version number of output metadata and data blob.
    pub fs_version: RafsVersion,

    /// Type of source to build the image from.
    pub source_type: SourceType,
    /// Path of source to build the image from:
    /// - Directory: `source_path` should be a directory path
    /// - StargzIndex: `source_path` should be a stargz index json file path
    /// - Diff: `source_path` should be a directory path
    pub source_path: PathBuf,

    /// Track file/chunk prefetch state.
    pub prefetch: Prefetch,

    /// Storage writing blob to single file or a directory.
    pub blob_storage: Option<ArtifactStorage>,
    pub blob_meta_storage: Option<ArtifactStorage>,
    pub inline_bootstrap: bool,
    pub has_xattr: bool,
}

impl BuildContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        blob_id: String,
        aligned_chunk: bool,
        blob_offset: u64,
        compressor: compress::Algorithm,
        digester: digest::Algorithm,
        explicit_uidgid: bool,
        whiteout_spec: WhiteoutSpec,
        source_type: SourceType,
        source_path: PathBuf,
        prefetch: Prefetch,
        blob_storage: Option<ArtifactStorage>,
        blob_meta_storage: Option<ArtifactStorage>,
        inline_bootstrap: bool,
    ) -> Self {
        BuildContext {
            blob_id,
            aligned_chunk,
            blob_offset,
            compressor,
            digester,
            explicit_uidgid,
            whiteout_spec,

            chunk_size: RAFS_DEFAULT_CHUNK_SIZE as u32,
            fs_version: RafsVersion::default(),

            source_type,
            source_path,

            prefetch,
            blob_storage,
            blob_meta_storage,
            inline_bootstrap,
            has_xattr: false,
        }
    }

    pub fn set_fs_version(&mut self, fs_version: RafsVersion) {
        self.fs_version = fs_version;
    }

    pub fn set_chunk_size(&mut self, chunk_size: u32) {
        self.chunk_size = chunk_size;
    }
}

impl Default for BuildContext {
    fn default() -> Self {
        Self {
            blob_id: String::new(),
            aligned_chunk: false,
            blob_offset: 0,
            compressor: compress::Algorithm::default(),
            digester: digest::Algorithm::default(),
            explicit_uidgid: true,
            whiteout_spec: WhiteoutSpec::default(),

            chunk_size: RAFS_DEFAULT_CHUNK_SIZE as u32,
            fs_version: RafsVersion::default(),

            source_type: SourceType::default(),
            source_path: PathBuf::new(),

            prefetch: Prefetch::default(),
            blob_storage: None,
            blob_meta_storage: None,
            has_xattr: true,
            inline_bootstrap: false,
        }
    }
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct BuildOutputBlob {
    pub blob_id: String,
    pub blob_size: u64,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct BuildOutputArtifact {
    // Bootstrap file name in this build.
    pub bootstrap_name: String,
    // The blobs in blob table of this bootstrap.
    pub blobs: Vec<BuildOutputBlob>,
}

/// BuildOutput represents the output in this build.
#[derive(Default, Debug, Clone)]
pub struct BuildOutput {
    /// Artifacts (bootstrap + blob) for all layer in this build, vector
    /// index equals layer index.
    pub artifacts: Vec<BuildOutputArtifact>,
    /// Blob ids in the blob table of last bootstrap.
    pub blobs: Vec<String>,
    /// The size of output blob in this build.
    pub last_blob_size: Option<u64>,
    /// The name of output bootstrap in this build, in diff build, it's
    /// the bootstrap of last layer.
    pub last_bootstrap_name: String,
}

impl BuildOutput {
    pub fn new(blob_mgr: &BlobManager, bootstrap_mgr: &BootstrapManager) -> Result<BuildOutput> {
        let bootstraps = bootstrap_mgr.get_bootstraps();
        let mut artifacts = Vec::new();
        for bootstrap in bootstraps {
            artifacts.push(BuildOutputArtifact {
                bootstrap_name: bootstrap.name.clone(),
                blobs: bootstrap.blobs.clone(),
            });
        }
        let blobs = blob_mgr.get_blob_ids();

        let last_blob_size = blob_mgr.get_last_blob().map(|b| b.compressed_blob_size);
        let last_bootstrap_name = bootstrap_mgr
            .get_last_bootstrap()
            .ok_or_else(|| anyhow!("can't get last bootstrap"))?;

        Ok(Self {
            artifacts,
            blobs,
            last_blob_size,
            last_bootstrap_name,
        })
    }
}
