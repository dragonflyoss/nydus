// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Struct to maintain context information for the image builder.

use std::any::Any;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::{remove_file, rename, File, OpenOptions};
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Error, Result};
use nydus_utils::digest;
use nydus_utils::div_round_up;
use rafs::metadata::layout::v5::RafsV5BlobTable;
use rafs::metadata::layout::v6::RafsV6BlobTable;
use rafs::metadata::layout::v6::EROFS_BLOCK_SIZE;
use rafs::metadata::RafsSuperFlags;
use rafs::metadata::{Inode, RAFS_DEFAULT_CHUNK_SIZE, RAFS_MAX_CHUNK_SIZE};
use rafs::{RafsIoReader, RafsIoWrite};
use sha2::{Digest, Sha256};
use storage::compress;
use storage::device::BlobFeatures;
use storage::device::BlobInfo;
use storage::meta::{BlobChunkInfoOndisk, BlobMetaHeaderOndisk};
use vmm_sys_util::tempfile::TempFile;

use super::chunk_dict::{ChunkDict, HashChunkDict};
use super::layout::BlobLayout;
use super::node::{ChunkWrapper, Node, WhiteoutSpec};
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

/// ArtifactBufferWriter provides a writer to allow writing bootstrap
/// or blob data to a single file or in a directory.
pub struct ArtifactBufferWriter {
    file: BufWriter<File>,
    storage: ArtifactStorage,
    // Keep this because tmp file will be removed automatically when it is dropped.
    // But we will rename/link the tmp file before it is removed.
    tmp_file: Option<TempFile>,
}

impl RafsIoWrite for ArtifactBufferWriter {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl std::io::Write for ArtifactBufferWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.file.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl std::io::Seek for ArtifactBufferWriter {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.file.seek(pos)
    }
}

impl ArtifactBufferWriter {
    pub fn new(storage: ArtifactStorage) -> Result<Self> {
        match storage {
            ArtifactStorage::SingleFile(ref p) => {
                let b = BufWriter::with_capacity(
                    BUF_WRITER_CAPACITY,
                    OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(p)
                        .with_context(|| format!("failed to open file {:?}", p))?,
                );
                Ok(Self {
                    file: b,
                    storage,
                    tmp_file: None,
                })
            }
            ArtifactStorage::FileDir(ref p) => {
                // Better we can use open(2) O_TMPFILE, but for compatibility sake, we delay this job.
                // TODO: Blob dir existence?
                let tmp = TempFile::new_in(&p)
                    .with_context(|| format!("failed to create temp file in {:?}", p))?;
                let tmp2 = tmp.as_file().try_clone()?;
                Ok(Self {
                    file: BufWriter::with_capacity(BUF_WRITER_CAPACITY, tmp2),
                    storage,
                    tmp_file: Some(tmp),
                })
            }
        }
    }

    pub fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.file.write_all(buf).map_err(|e| anyhow!(e))
    }

    pub fn get_pos(&mut self) -> Result<u64> {
        let pos = self.file.seek(SeekFrom::Current(0))?;

        Ok(pos)
    }

    pub fn release(self, name: Option<&str>) -> Result<()> {
        let mut f = self.file.into_inner()?;
        f.flush()?;

        if let Some(n) = name {
            if let ArtifactStorage::FileDir(s) = &self.storage {
                // NOTE: File with same name will be deleted ahead of time.
                // So each newly generated blob can be stored.
                let might_exist_path = Path::new(s).join(n);
                if might_exist_path.exists() {
                    remove_file(&might_exist_path)
                        .with_context(|| format!("failed to remove blob {:?}", might_exist_path))?;
                }

                // Safe to unwrap as `FileDir` must have `tmp_file` created.
                let tmp_file = self.tmp_file.unwrap();
                rename(tmp_file.as_path(), &might_exist_path).with_context(|| {
                    format!(
                        "failed to rename blob {:?} to {:?}",
                        tmp_file.as_path(),
                        might_exist_path
                    )
                })?;
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

    // Blob writer for writing to disk file.
    pub writer: Option<ArtifactBufferWriter>,
}

impl BlobContext {
    pub fn new(blob_id: String, blob_stor: Option<ArtifactStorage>) -> Result<Self> {
        let writer = if let Some(blob_stor) = blob_stor {
            Some(ArtifactBufferWriter::new(blob_stor)?)
        } else {
            None
        };

        Ok(Self::new_with_writer(blob_id, writer))
    }

    pub fn new_with_writer(blob_id: String, writer: Option<ArtifactBufferWriter>) -> Self {
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

            compress_offset: 0,
            decompress_offset: 0,

            chunk_count: 0,
            chunk_size: RAFS_DEFAULT_CHUNK_SIZE as u32,
            chunk_data_buf: vec![0u8; size],
            chunk_dict: Arc::new(()),

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
        if self.blob_meta_info_enabled {
            debug_assert!(chunk.index() as usize == self.blob_meta_info.len());
            let mut meta = BlobChunkInfoOndisk::default();
            meta.set_compressed_offset(chunk.compressed_offset());
            meta.set_compressed_size(chunk.compressed_size());
            meta.set_uncompressed_offset(chunk.uncompressed_offset(), self.blob_meta_info_enabled);
            meta.set_uncompressed_size(chunk.uncompressed_size());
            trace!(
                "chunk uncompressed {} size {}",
                meta.uncompressed_offset(),
                meta.uncompressed_size()
            );
            self.blob_meta_info.push(meta);
        }

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

    pub fn flush(&mut self) -> Result<()> {
        let blob_id = if self.compressed_blob_size > 0 {
            Some(self.blob_id.as_str())
        } else {
            None
        };

        if let Some(writer) = self.writer.take() {
            writer.release(blob_id)?;
        }

        Ok(())
    }
}

impl From<&BlobInfo> for BlobContext {
    fn from(blob: &BlobInfo) -> Self {
        let mut ctx = Self::new_with_writer(blob.blob_id().to_owned(), None);

        ctx.blob_readahead_size = blob.readahead_size();
        ctx.chunk_count = blob.chunk_count();
        ctx.decompressed_blob_size = blob.uncompressed_size();
        ctx.compressed_blob_size = blob.compressed_size();

        ctx
    }
}

/// BlobManager stores all blob related information during build.
pub struct BlobManager {
    /// Some layers may not have a blob (only have metadata), so Option
    /// is used here, the vector index will be as the layer index.
    ///
    /// We can get blob index for a layer by using:
    /// self.blobs.iter().flatten().collect()[layer_index];
    blobs: Vec<Option<BlobContext>>,
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
        u8::try_from(self.blobs.iter().flatten().count())
            .map(|v| v as u32)
            .with_context(|| Error::msg("too many blobs"))
    }

    /// Add a blob context to manager
    ///
    /// This should be paired with Self::alloc_index() and keep in consistence.
    pub fn add(&mut self, blob_ctx: Option<BlobContext>) {
        self.blobs.push(blob_ctx);
    }

    pub fn len(&self) -> usize {
        self.blobs.len()
    }

    /// Only get valid (non-empty) blobs.
    pub fn get_blobs(&self) -> Vec<&BlobContext> {
        self.blobs.iter().flatten().collect()
    }

    pub fn get_blobs_from(&self, skip: usize) -> Vec<&BlobContext> {
        self.blobs.iter().skip(skip).flatten().collect()
    }

    pub fn get_last_blob(&self) -> Option<&BlobContext> {
        self.blobs.last().unwrap_or(&None).as_ref()
    }

    pub fn from_blob_table(&mut self, blob_table: Vec<Arc<BlobInfo>>) {
        self.blobs = blob_table
            .iter()
            .map(|entry| Some(BlobContext::from(entry.as_ref())))
            .collect();
    }

    pub fn get_blob_idx_by_id(&self, id: &str) -> Option<u32> {
        for (idx, blob) in self.get_blobs().iter().enumerate() {
            if blob.blob_id.eq(id) {
                return Some(idx as u32);
            }
        }
        None
    }

    pub fn get_blob_idx_by_layer_idx(&self, layer_idx: u32) -> Option<u32> {
        let mut blob_idx = 0u32;
        for (idx, blob) in self.blobs.iter().enumerate() {
            if blob.is_some() {
                if idx == layer_idx as usize {
                    return Some(blob_idx);
                }
                blob_idx += 1;
            }
        }
        None
    }

    /// Extend blobs which belong to ChunkDict and setup real_blob_idx map
    /// should call this function after import parent bootstrap
    /// otherwise will break blobs order
    pub fn extend_blob_table_from_chunk_dict(&mut self) -> Result<()> {
        let blobs = self.chunk_dict_ref.get_blobs();

        for blob in blobs.iter() {
            if let Some(real_idx) = self.get_blob_idx_by_id(blob.blob_id()) {
                self.chunk_dict_ref
                    .set_real_blob_idx(blob.blob_index(), real_idx);
            } else {
                let idx = self.alloc_index()?;
                self.add(Some(BlobContext::from(blob.as_ref())));
                self.chunk_dict_ref
                    .set_real_blob_idx(blob.blob_index(), idx);
            }
        }

        Ok(())
    }

    pub fn to_blob_table_v5(
        &self,
        build_ctx: &BuildContext,
        up_idx: Option<usize>,
    ) -> Result<RafsV5BlobTable> {
        let mut blob_table = RafsV5BlobTable::new();
        let up_idx = up_idx.unwrap_or(self.blobs.len() - 1) as usize;

        for (idx, ctx) in self.blobs.iter().enumerate() {
            if let Some(ctx) = ctx {
                let blob_id = ctx.blob_id.clone();
                let blob_readahead_size = u32::try_from(ctx.blob_readahead_size)?;
                let chunk_count = ctx.chunk_count;
                let decompressed_blob_size = ctx.decompressed_blob_size;
                let compressed_blob_size = ctx.compressed_blob_size;
                let blob_features = BlobFeatures::empty();
                let mut flags = RafsSuperFlags::empty();
                match build_ctx.fs_version {
                    RafsVersion::V5 => {
                        flags |= RafsSuperFlags::from(build_ctx.compressor);
                        flags |= RafsSuperFlags::from(build_ctx.digester);
                    }
                    RafsVersion::V6 => todo!(),
                }
                blob_table.add(
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
            if idx == up_idx {
                break;
            }
        }

        Ok(blob_table)
    }

    pub fn to_blob_table_v6(
        &self,
        build_ctx: &BuildContext,
        up_idx: Option<usize>,
    ) -> Result<RafsV6BlobTable> {
        let mut blob_table = RafsV6BlobTable::new();
        let up_idx = up_idx.unwrap_or(self.blobs.len() - 1) as usize;

        for (idx, ctx) in self.blobs.iter().enumerate() {
            if let Some(ctx) = ctx {
                let blob_id = ctx.blob_id.clone();
                let blob_readahead_size = u32::try_from(ctx.blob_readahead_size)?;
                let chunk_count = ctx.chunk_count;
                let decompressed_blob_size = ctx.decompressed_blob_size;
                let compressed_blob_size = ctx.compressed_blob_size;
                let blob_features = BlobFeatures::empty();
                let mut flags = RafsSuperFlags::empty();
                match build_ctx.fs_version {
                    RafsVersion::V5 => todo!(),
                    RafsVersion::V6 => {
                        flags |= RafsSuperFlags::from(build_ctx.compressor);
                        flags |= RafsSuperFlags::from(build_ctx.digester);
                    }
                }
                blob_table.add(
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
                if idx == up_idx {
                    break;
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
    /// Cache node index for hardlinks, HashMap<(real_inode, dev), Vec<index>>.
    pub lower_inode_map: HashMap<(Inode, u64), Vec<u64>>,
    pub upper_inode_map: HashMap<(Inode, u64), Vec<u64>>,
    /// Store all nodes in ascendant ordor, indexed by (node.index - 1).
    pub nodes: Vec<Node>,
    /// Current position to write in f_bootstrap
    pub offset: u64,
    /// Bootstrap file name, only be used for diff build.
    pub name: String,
    /// Bootstrap file writer.
    storage: ArtifactStorage,
}

impl BootstrapContext {
    pub fn new(storage: ArtifactStorage, layered: bool) -> Result<Self> {
        Ok(Self {
            layered,
            lower_inode_map: HashMap::new(),
            upper_inode_map: HashMap::new(),
            nodes: Vec::new(),
            offset: EROFS_BLOCK_SIZE,
            name: String::new(),
            storage,
        })
    }

    pub fn align_offset(&mut self, align_size: u64) {
        if self.offset % align_size > 0 {
            self.offset = div_round_up(self.offset, align_size) * align_size;
        }
    }

    pub fn create_writer(&self) -> Result<ArtifactBufferWriter> {
        ArtifactBufferWriter::new(self.storage.clone())
    }
}

/// BootstrapManager is used to hold the parent bootstrap reader and create
/// new bootstrap context.
pub struct BootstrapManager {
    /// Parent bootstrap file reader.
    pub f_parent_bootstrap: Option<RafsIoReader>,
    bootstrap_storage: ArtifactStorage,
    /// The vector index will be as the layer index.
    /// We can get the bootstrap of a layer by using:
    /// self.bootstraps[layer_index];
    bootstraps: Vec<BootstrapContext>,
}

impl BootstrapManager {
    pub fn new(
        bootstrap_storage: ArtifactStorage,
        f_parent_bootstrap: Option<RafsIoReader>,
    ) -> Self {
        Self {
            f_parent_bootstrap,
            bootstrap_storage,
            bootstraps: Vec::new(),
        }
    }

    pub fn create_ctx(&self) -> Result<BootstrapContext> {
        BootstrapContext::new(
            self.bootstrap_storage.clone(),
            self.f_parent_bootstrap.is_some(),
        )
    }

    pub fn add(&mut self, bootstrap_ctx: BootstrapContext) {
        self.bootstraps.push(bootstrap_ctx);
    }

    pub fn get_bootstraps(&self) -> Vec<String> {
        self.bootstraps.iter().map(|b| b.name.to_owned()).collect()
    }

    pub fn get_last_bootstrap(&self) -> Option<String> {
        self.bootstraps.last().map(|b| b.name.to_owned())
    }

    pub fn get_bootstrap_path(&self, name: &str) -> PathBuf {
        self.bootstrap_storage.get_path(name)
    }
}

#[derive(Default, Clone)]
pub struct BuildContext {
    /// Blob id (user specified or sha256(blob)).
    pub blob_id: String,

    /// When filling local blobcache file, chunks are arranged as per the
    /// `decompress_offset` within chunk info. Therefore, provide a new flag
    /// to image tool thus to align chunks in blob with 4k size.
    pub aligned_chunk: bool,
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
}

impl BuildContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        blob_id: String,
        aligned_chunk: bool,
        compressor: compress::Algorithm,
        digester: digest::Algorithm,
        explicit_uidgid: bool,
        whiteout_spec: WhiteoutSpec,
        source_type: SourceType,
        source_path: PathBuf,
        prefetch: Prefetch,
        blob_storage: Option<ArtifactStorage>,
    ) -> Self {
        BuildContext {
            blob_id,
            aligned_chunk,
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
        }
    }

    pub fn set_fs_version(&mut self, fs_version: RafsVersion) {
        self.fs_version = fs_version;
    }

    pub fn set_chunk_size(&mut self, chunk_size: u32) {
        self.chunk_size = chunk_size;
    }
}

/// BuildOutput represents the output in this build.
#[derive(Default, Debug, Clone)]
pub struct BuildOutput {
    /// Blob ids for all layer, index equals blob index.
    pub blobs: Vec<String>,
    /// Bootstrap names for all layer in this build, index equals layer index.
    pub bootstraps: Vec<String>,
    /// The size of output blob in this build.
    pub blob_size: Option<u64>,
    /// The name of output bootstrap in this build, for the bootstrap
    /// of last layer in diff build.
    pub bootstrap_name: String,
}

impl BuildOutput {
    pub fn new(
        blob_mgr: &BlobManager,
        bootstrap_mgr: &BootstrapManager,
        skip: usize,
    ) -> Result<BuildOutput> {
        let blobs = blob_mgr
            .get_blobs_from(skip)
            .iter()
            .map(|b| b.blob_id.to_owned())
            .collect();
        let bootstraps = bootstrap_mgr.get_bootstraps();
        let blob_size = blob_mgr.get_last_blob().map(|b| b.compressed_blob_size);
        let bootstrap_name = bootstrap_mgr
            .get_last_bootstrap()
            .ok_or_else(|| anyhow!("can't get last bootstrap"))?;
        Ok(Self {
            blobs,
            bootstraps,
            blob_size,
            bootstrap_name,
        })
    }
}
