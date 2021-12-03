// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Struct to maintain context information for the image builder.

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
use rafs::metadata::layout::v6::EROFS_BLOCK_SIZE;
use rafs::metadata::{Inode, RAFS_DEFAULT_CHUNK_SIZE, RAFS_MAX_CHUNK_SIZE};
use rafs::{RafsIoReader, RafsIoWriter};
use sha2::{Digest, Sha256};
use storage::compress;
use storage::device::BlobInfo;
use storage::meta::{BlobChunkInfoOndisk, BlobMetaHeaderOndisk};
use vmm_sys_util::tempfile::TempFile;

use super::chunk_dict::{ChunkDict, HashChunkDict};
use super::layout::BlobLayout;
use super::node::{ChunkWrapper, Node, WhiteoutSpec};
use super::prefetch::Prefetch;

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
pub enum BlobStorage {
    // Won't rename user's specification
    SingleFile(PathBuf),
    // Will rename it from tmp file as user didn't specify a name.
    BlobsDir(PathBuf),
}

impl Default for BlobStorage {
    fn default() -> Self {
        Self::SingleFile(PathBuf::new())
    }
}

pub struct BlobBufferWriter {
    file: BufWriter<File>,
    blob_stor: BlobStorage,
    // Keep this because tmp file will be removed automatically when it is dropped.
    // But we will rename/link the tmp file before it is removed.
    tmp_file: Option<TempFile>,
}

impl BlobBufferWriter {
    pub fn new(blob_stor: BlobStorage) -> Result<Self> {
        match blob_stor {
            BlobStorage::SingleFile(ref p) => {
                let b = BufWriter::with_capacity(
                    BUF_WRITER_CAPACITY,
                    OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(p)
                        .with_context(|| format!("failed to open blob {:?}", p))?,
                );
                Ok(Self {
                    file: b,
                    blob_stor,
                    tmp_file: None,
                })
            }
            BlobStorage::BlobsDir(ref p) => {
                // Better we can use open(2) O_TMPFILE, but for compatibility sake, we delay this job.
                // TODO: Blob dir existence?
                let tmp = TempFile::new_in(&p)
                    .with_context(|| format!("failed to create temp blob file in {:?}", p))?;
                let tmp2 = tmp.as_file().try_clone()?;
                Ok(Self {
                    file: BufWriter::with_capacity(BUF_WRITER_CAPACITY, tmp2),
                    blob_stor,
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
            if let BlobStorage::BlobsDir(s) = &self.blob_stor {
                // NOTE: File with same name will be deleted ahead of time.
                // So each newly generated blob can be stored.
                let might_exist_path = Path::new(s).join(n);
                if might_exist_path.exists() {
                    remove_file(&might_exist_path)
                        .with_context(|| format!("failed to remove blob {:?}", might_exist_path))?;
                }

                // Safe to unwrap as `BlobsDir` must have `tmp_file` created.
                let tmp_file = self.tmp_file.unwrap();
                rename(tmp_file.as_path(), &might_exist_path).with_context(|| {
                    format!(
                        "failed to rename blob {:?} to {:?}",
                        tmp_file.as_path(),
                        might_exist_path
                    )
                })?;
            }
        } else if let BlobStorage::SingleFile(s) = &self.blob_stor {
            // `new_name` is None means no blob is really built, perhaps due to dedup.
            // We don't want to puzzle user, so delete it from here.
            // In the future, FIFO could be leveraged, don't remove it then.
            remove_file(s).with_context(|| format!("failed to remove blob {:?}", s))?;
        }

        Ok(())
    }
}

impl Write for BlobBufferWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
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
    pub writer: Option<BlobBufferWriter>,
}

impl BlobContext {
    pub fn new(blob_id: String, blob_stor: Option<BlobStorage>) -> Result<Self> {
        let writer = if let Some(blob_stor) = blob_stor {
            Some(BlobBufferWriter::new(blob_stor)?)
        } else {
            None
        };

        Ok(Self::new_with_writer(blob_id, writer))
    }

    pub fn new_with_writer(blob_id: String, writer: Option<BlobBufferWriter>) -> Self {
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

/// BlobManager stores all blob related information during build,
/// the vector index will be as the blob index.
pub struct BlobManager {
    pub blobs: Vec<BlobContext>,
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

    /// Get blob context for current layer
    pub fn current(&mut self) -> Option<&mut BlobContext> {
        self.blobs.last_mut()
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

    pub fn from_blob_table(&mut self, blob_table: Vec<Arc<BlobInfo>>) {
        self.blobs = blob_table
            .iter()
            .map(|entry| BlobContext::from(entry.as_ref()))
            .collect();
    }

    fn get_blob_idx_by_id(&self, id: &str) -> Option<u32> {
        for i in 0..self.blobs.len() {
            if self.blobs[i].blob_id.eq(id) {
                return Some(i as u32);
            }
        }
        None
    }

    /// extend blobs which belong to ChunkDict and setup real_blob_idx map
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
                self.add(BlobContext::from(blob.as_ref()));
                self.chunk_dict_ref
                    .set_real_blob_idx(blob.blob_index(), idx);
            }
        }

        Ok(())
    }
}

/// BootstrapContext is used to hold inmemory data of bootstrap during build.
pub struct BootstrapContext {
    /// Bootstrap file writer.
    pub f_bootstrap: RafsIoWriter,
    /// Parent bootstrap file reader.
    pub f_parent_bootstrap: Option<RafsIoReader>,
    /// Cache node index for hardlinks, HashMap<(real_inode, dev), Vec<index>>.
    pub lower_inode_map: HashMap<(Inode, u64), Vec<u64>>,
    pub upper_inode_map: HashMap<(Inode, u64), Vec<u64>>,
    /// Store all nodes in ascendant ordor, indexed by (node.index - 1).
    pub nodes: Vec<Node>,
    /// current position to write in f_bootstrap
    pub offset: u64,
}

impl BootstrapContext {
    pub fn new(f_bootstrap: RafsIoWriter, f_parent_bootstrap: Option<RafsIoReader>) -> Self {
        Self {
            f_bootstrap,
            f_parent_bootstrap,
            lower_inode_map: HashMap::new(),
            upper_inode_map: HashMap::new(),
            nodes: Vec::new(),
            offset: EROFS_BLOCK_SIZE,
        }
    }

    pub fn align_offset(&mut self, align_size: u64) {
        if self.offset % align_size > 0 {
            self.offset = div_round_up(self.offset, align_size) * align_size;
        }
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
    pub blob_storage: Option<BlobStorage>,
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
        blob_storage: Option<BlobStorage>,
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
