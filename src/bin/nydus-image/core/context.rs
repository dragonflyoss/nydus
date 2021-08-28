// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Struct to maintain context information for the image builder.

use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Error, Result};

use rafs::metadata::layout::v5::{RafsV5BlobTable, RafsV5ChunkInfo};
use rafs::metadata::{Inode, RAFS_MAX_BLOCK_SIZE};
use rafs::{RafsIoReader, RafsIoWriter};
// FIXME: Must image tool depend on storage backend?
use nydus_utils::digest::{self, RafsDigest};
use storage::compress;

use super::node::*;
use super::prefetch::Prefetch;

// TODO: select BufWriter capacity by performance testing.
pub const BUF_WRITER_CAPACITY: usize = 2 << 17;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SourceType {
    Directory,
    StargzIndex,
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

pub struct BuildContext {
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
    pub source_path: PathBuf,

    /// Blob id (user specified or sha256(blob)).
    pub blob_id: String,
    /// Index index in to `blob_table` of current blob.
    pub blob_index: u32,
    /// Store all blob id entry during build.
    pub blob_table: RafsV5BlobTable,

    /// Bootstrap file writer.
    pub f_bootstrap: RafsIoWriter,
    /// Parent bootstrap file reader.
    pub f_parent_bootstrap: Option<RafsIoReader>,

    /// Cache node index for hardlinks, HashMap<(real_inode, dev), Vec<index>>.
    pub lower_inode_map: HashMap<(Inode, u64), Vec<u64>>,
    pub upper_inode_map: HashMap<(Inode, u64), Vec<u64>>,

    /// Store all chunk digest for chunk deduplicate during build.
    pub chunk_cache: HashMap<RafsDigest, RafsV5ChunkInfo>,
    /// Mapping `blob_index` to number of chunks in blob file.
    pub chunk_count_map: ChunkCountMap,
    /// Scratch data buffer for reading from/writing to disk files.
    pub chunk_data_buf: Vec<u8>,

    /// Store all nodes in ascendant ordor, indexed by (node.index - 1).
    pub nodes: Vec<Node>,

    /// Track file/chunk prefetch state.
    pub prefetch: Prefetch,
}

impl BuildContext {
    pub fn new(
        blob_id: String,
        source_type: SourceType,
        source_path: PathBuf,
        prefetch: Prefetch,
        f_bootstrap: RafsIoWriter,
    ) -> Self {
        BuildContext {
            aligned_chunk: false,
            compressor: compress::Algorithm::None,
            digester: digest::Algorithm::Blake3,
            explicit_uidgid: false,
            whiteout_spec: WhiteoutSpec::Oci,
            source_type,
            source_path,

            blob_id,
            blob_index: 0,
            blob_table: RafsV5BlobTable::new(),

            f_bootstrap,
            f_parent_bootstrap: None,

            lower_inode_map: HashMap::new(),
            upper_inode_map: HashMap::new(),

            chunk_cache: HashMap::new(),
            chunk_count_map: ChunkCountMap::default(),
            chunk_data_buf: vec![0u8; RAFS_MAX_BLOCK_SIZE as usize],

            nodes: Vec::new(),

            prefetch,
        }
    }
}
