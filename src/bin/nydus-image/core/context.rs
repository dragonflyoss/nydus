// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Struct to maintain context information for the image builder.

use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::{remove_file, rename, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Error, Result};
use sha2::{Digest, Sha256};
use vmm_sys_util::tempfile::TempFile;

use rafs::metadata::layout::v5::RafsV5BlobTable;
use rafs::metadata::layout::v5::RafsV5ChunkInfo;
use rafs::metadata::{Inode, RAFS_MAX_BLOCK_SIZE};
use rafs::{RafsIoReader, RafsIoWriter};
// FIXME: Must image tool depend on storage backend?
use nydus_utils::digest::{self, RafsDigest};
use storage::compress;

use crate::core::layout::BlobLayout;
use crate::core::node::*;
use crate::core::prefetch::Prefetch;

// TODO: select BufWriter capacity by performance testing.
pub const BUF_WRITER_CAPACITY: usize = 2 << 17;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SourceType {
    Directory,
    StargzIndex,
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

    /// Final compressed blob file size.
    pub compressed_blob_size: u64,
    /// Final expected blob cache file size.
    pub decompressed_blob_size: u64,

    /// Current blob offset cursor for writing to disk file.
    pub compress_offset: u64,
    pub decompress_offset: u64,

    /// The number of counts in a blob by the index of blob table.
    pub chunk_count: u32,
    /// Blob data layout manager
    pub blob_layout: BlobLayout,
    /// Scratch data buffer for reading from/writing to disk files.
    pub chunk_data_buf: Vec<u8>,
    /// Store all chunk digest for chunk deduplicate during build.
    pub chunk_cache: HashMap<RafsDigest, RafsV5ChunkInfo>,

    // Blob writer for writing to disk file.
    pub writer: Option<BlobBufferWriter>,
}

impl BlobContext {
    pub fn new_with_writer(blob_id: String, writer: Option<BlobBufferWriter>) -> Self {
        Self {
            blob_id,
            blob_hash: Sha256::new(),
            blob_readahead_size: 0,
            compressed_blob_size: 0,
            compress_offset: 0,
            decompressed_blob_size: 0,
            decompress_offset: 0,
            chunk_count: 0,
            blob_layout: BlobLayout::new(),
            chunk_data_buf: vec![0u8; RAFS_MAX_BLOCK_SIZE as usize],
            chunk_cache: HashMap::new(),
            writer,
        }
    }

    pub fn new(blob_id: String, blob_stor: Option<BlobStorage>) -> Result<Self> {
        let writer = if let Some(blob_stor) = blob_stor {
            Some(BlobBufferWriter::new(blob_stor)?)
        } else {
            None
        };
        Ok(Self::new_with_writer(blob_id, writer))
    }

    /// Allocate a count index sequentially in a blob.
    pub fn alloc_index(&mut self) -> Result<u32> {
        let index = self.chunk_count;
        self.chunk_count = index
            .checked_add(1)
            .ok_or_else(|| Error::msg("the number of chunks in blob exceeds the u32 limit"))?;
        Ok(index)
    }

    pub fn from(
        blob_id: String,
        chunk_count: u32,
        readahead_size: u32,
        blob_cache_size: u64,
        compressed_blob_size: u64,
    ) -> Self {
        let mut blob = Self::new_with_writer(blob_id, None);
        blob.chunk_count = chunk_count;
        blob.blob_readahead_size = readahead_size as u64;
        blob.chunk_count = chunk_count;
        blob.decompressed_blob_size = blob_cache_size;
        blob.compressed_blob_size = compressed_blob_size;
        blob
    }
}

/// BlobManager stores all blob related information during build,
/// the vector index will be as the blob index.
pub struct BlobManager {
    blobs: Vec<BlobContext>,
}

impl BlobManager {
    pub fn new() -> Self {
        Self { blobs: Vec::new() }
    }

    /// Get blob context for current layer
    pub fn current(&mut self) -> Option<&mut BlobContext> {
        self.blobs.last_mut()
    }

    /// Allocate a blob index sequentially
    pub fn alloc_index(&self) -> Result<u32> {
        u32::try_from(self.blobs.len()).with_context(|| Error::msg("too many blobs"))
    }

    /// Add a blob context to manager
    pub fn add(&mut self, blob_ctx: BlobContext) {
        self.blobs.push(blob_ctx);
    }

    pub fn to_blob_table(&self) -> Result<RafsV5BlobTable> {
        let mut blob_table = RafsV5BlobTable::new();
        for ctx in &self.blobs {
            let blob_id = ctx.blob_id.clone();
            let blob_readahead_size = u32::try_from(ctx.blob_readahead_size)?;
            let chunk_count = ctx.chunk_count;
            let decompressed_blob_size = ctx.decompressed_blob_size;
            let compressed_blob_size = ctx.compressed_blob_size;
            blob_table.add(
                blob_id,
                0,
                blob_readahead_size,
                chunk_count,
                decompressed_blob_size,
                compressed_blob_size,
            );
        }
        Ok(blob_table)
    }

    pub fn from_blob_table(&mut self, blob_table: &RafsV5BlobTable) {
        self.blobs = blob_table
            .get_all()
            .iter()
            .map(|entry| {
                BlobContext::from(
                    entry.blob_id.clone(),
                    entry.chunk_count,
                    entry.readahead_size,
                    entry.blob_cache_size,
                    entry.compressed_blob_size,
                )
            })
            .collect();
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
}

impl BootstrapContext {
    pub fn new(f_bootstrap: RafsIoWriter, f_parent_bootstrap: Option<RafsIoReader>) -> Self {
        Self {
            f_bootstrap,
            f_parent_bootstrap,
            lower_inode_map: HashMap::new(),
            upper_inode_map: HashMap::new(),
            nodes: Vec::new(),
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

    /// Type of source to build the image from.
    pub source_type: SourceType,
    /// Path of source to build the image from:
    /// - Directory: `source_path` should be a directory path
    /// - StargzIndex: `source_path` should be a stargz index json file path
    /// - Diff: `source_path` should be a directory path sets
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

            source_type,
            source_path,

            prefetch,
            blob_storage,
        }
    }
}
