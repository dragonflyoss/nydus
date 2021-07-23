// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Bootstrap and blob file builder for RAFS format

use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Error, Result};

use rafs::metadata::layout::*;
use rafs::metadata::Inode;
use rafs::{RafsIoReader, RafsIoWriter};
// FIXME: Must image tool depend on storage backend?
use storage::compress;

use nydus_utils::digest::{self, RafsDigest};

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
    /// Source type: Directory | StargzIndex
    pub source_type: SourceType,
    /// Source path, for different source type:
    /// Directory: should be a directory path
    /// StargzIndex: should be a stargz index json file path
    pub source_path: PathBuf,
    /// Blob id (user specified or sha256(blob)).
    pub blob_id: String,
    /// Bootstrap file writer.
    pub f_bootstrap: RafsIoWriter,
    /// Parent bootstrap file reader.
    pub f_parent_bootstrap: Option<RafsIoReader>,
    /// Blob chunk compress flag.
    pub compressor: compress::Algorithm,
    /// Inode and chunk digest algorithm flag.
    pub digester: digest::Algorithm,
    /// Save host uid gid in each inode.
    pub explicit_uidgid: bool,
    /// whiteout spec: overlayfs or oci
    pub whiteout_spec: WhiteoutSpec,
    /// Cache node index for hardlinks, HashMap<(real_inode, dev), Vec<index>>.
    pub lower_inode_map: HashMap<(Inode, u64), Vec<u64>>,
    pub upper_inode_map: HashMap<(Inode, u64), Vec<u64>>,
    /// Store all chunk digest for chunk deduplicate during build.
    pub chunk_cache: HashMap<RafsDigest, OndiskChunkInfo>,
    pub chunk_count_map: ChunkCountMap,
    /// Store all blob id entry during build.
    pub blob_table: OndiskBlobTable,
    /// Store all nodes during build, node index of root starting from 1,
    /// so the collection index equal to (node.index - 1).
    pub nodes: Vec<Node>,
    /// When filling local blobcache file, chunks are arranged as per the
    /// `decompress_offset` within chunk info. Therefore, provide a new flag
    /// to image tool thus to align chunks in blob with 4k size.
    pub aligned_chunk: bool,
    pub prefetch: Prefetch,
}
