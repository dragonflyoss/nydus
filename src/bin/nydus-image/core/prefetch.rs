// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Error, Result};
use rafs::metadata::layout::v5::RafsV5PrefetchTable;
use rafs::metadata::layout::v6::{calculate_nid, RafsV6PrefetchTable};

use crate::node::Node;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PrefetchPolicy {
    None,
    /// Readahead will be issued from Fs layer, which leverages inode/chunkinfo to prefetch data
    /// from blob no matter where it resides(OSS/Localfs). Basically, it is willing to cache the
    /// data into blobcache(if exists). It's more nimble. With this policy applied, image builder
    /// currently puts readahead files' data into a continuous region within blob which behaves very
    /// similar to `Blob` policy.
    Fs,
    /// Readahead will be issued directly from backend/blob layer
    Blob,
}

impl Default for PrefetchPolicy {
    fn default() -> Self {
        Self::None
    }
}

impl FromStr for PrefetchPolicy {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "none" => Ok(Self::None),
            "fs" => Ok(Self::Fs),
            "blob" => Ok(Self::Blob),
            _ => Err(anyhow!("invalid prefetch policy")),
        }
    }
}

/// Gather readahead file paths line by line from stdin.
///
/// Input format:
///    printf "/relative/path/to/rootfs/1\n/relative/path/to/rootfs/2"
/// This routine does not guarantee that specified file must exist in local filesystem,
/// this is because we can't guarantee that source rootfs directory of parent bootstrap
/// is located in local file system.
fn gather_readahead_patterns() -> Result<BTreeMap<PathBuf, Option<u64>>> {
    let stdin = std::io::stdin();
    let mut files = BTreeMap::new();

    loop {
        let mut file = String::new();
        let size = stdin
            .read_line(&mut file)
            .context("failed to parse readahead files")?;
        if size == 0 {
            break;
        }

        let file_trimmed: PathBuf = file.trim().into();
        // Sanity check for the list format.
        if !file_trimmed.starts_with(Path::new("/")) {
            warn!(
                "Illegal file path specified. It {:?} must start with '/'",
                file
            );
            continue;
        }

        debug!(
            "readahead file: {}, trimmed file name {:?}",
            file, file_trimmed
        );
        // The inode index is not decided yet, but will do during fs-walk.
        files.insert(file_trimmed, None);
    }

    Ok(files)
}

#[derive(Default, Clone)]
pub struct Prefetch {
    pub policy: PrefetchPolicy,

    pub disabled: bool,

    /// Specify patterns for prefetch.
    /// Their inode numbers will be persist to prefetch table. They could be directory's or regular
    /// file's inode number, by which its inode index of inode table can be calculated.
    readahead_patterns: BTreeMap<PathBuf, Option<u64>>,

    /// Readahead file list, use BTreeMap to keep stable iteration order.
    /// Files from this collection are all regular files and will be persisted to blob following
    /// a certain scheme.
    readahead_files: BTreeMap<PathBuf, u64>,
}

impl Prefetch {
    pub fn new(policy: PrefetchPolicy) -> Result<Self> {
        let readahead_patterns = if policy != PrefetchPolicy::None {
            gather_readahead_patterns().context("failed to get readahead files")?
        } else {
            BTreeMap::new()
        };

        Ok(Self {
            policy,
            disabled: false,
            readahead_patterns,
            readahead_files: BTreeMap::new(),
        })
    }

    pub fn insert_if_need(&mut self, node: &Node) {
        let path = node.target();
        let index = node.index;
        let mut remove_node = false;

        // Newly created root inode of this rafs has zero size
        if self.policy == PrefetchPolicy::None
            || self.disabled
            || (node.inode.is_reg() && node.inode.size() == 0)
        {
            return;
        }

        for (f, v) in self.readahead_patterns.iter_mut() {
            // As path is canonicalized, it should be reliable.
            if path == f {
                if self.policy == PrefetchPolicy::Fs {
                    *v = Some(index);
                }
                self.readahead_files.insert(path.clone(), index);
            } else if path.starts_with(f) {
                // FIXME: path may not exist in prefetch pattern, no need to remove it from readahead_patterns
                remove_node = true;
                debug!("remove path {:?}", path);
                self.readahead_files.insert(path.clone(), index);
            }
        }

        if remove_node {
            // Users can specify hinted parent directory with its child files hinted as well.
            // Only put the parent directory into prefetch table since a hinted directory's
            // all child files will be prefetched after mount.
            self.readahead_patterns.remove(path);
        }
    }

    pub fn contains(&self, node: &Node) -> bool {
        self.readahead_files.contains_key(node.target())
    }

    pub fn get_file_indexes(&self) -> Vec<u64> {
        let mut indexes: Vec<u64> = self.readahead_files.values().copied().collect();

        // Later, we might write chunks of data one by one according to inode number order.
        indexes.sort_unstable();
        indexes
    }

    pub fn get_rafsv5_prefetch_table(&mut self, nodes: &[Node]) -> Option<RafsV5PrefetchTable> {
        if self.policy == PrefetchPolicy::Fs {
            let mut prefetch_table = RafsV5PrefetchTable::new();
            for i in self.readahead_patterns.values().filter_map(|v| *v) {
                // Rafs v5 has inode number equal to index.
                prefetch_table.add_entry(nodes[i as usize - 1].inode.ino() as u32);
            }
            Some(prefetch_table)
        } else {
            None
        }
    }

    pub fn len(&self) -> u32 {
        if self.policy == PrefetchPolicy::Fs {
            self.readahead_patterns.values().len() as u32
        } else {
            0
        }
    }

    pub fn get_rafsv6_prefetch_table(
        &mut self,
        nodes: &[Node],
        meta_addr: u64,
    ) -> Option<RafsV6PrefetchTable> {
        if self.policy == PrefetchPolicy::Fs {
            let mut prefetch_table = RafsV6PrefetchTable::new();
            for i in self.readahead_patterns.values().filter_map(|v| *v) {
                debug_assert!(i > 0);
                // i holds the Node.index, which starts at 1, so it needs to be converted to the
                // index of the Node array to index the corresponding Node
                let array_index = i as usize - 1;
                trace!(
                    "v6 prefetch table: map node index {} to offset {} nid {} path {:?} name {:?}",
                    i,
                    nodes[array_index].v6_offset,
                    calculate_nid(nodes[array_index].v6_offset, meta_addr),
                    nodes[array_index].path(),
                    nodes[array_index].name()
                );
                // 32bit nid can represent 128GB bootstrap, it is large enough, no need
                // to worry about casting here
                prefetch_table
                    .add_entry(calculate_nid(nodes[array_index].v6_offset, meta_addr) as u32);
            }
            Some(prefetch_table)
        } else {
            None
        }
    }

    pub fn disable(&mut self) {
        self.disabled = true;
    }

    pub fn clear(&mut self) {
        self.disabled = false;
        self.readahead_files.clear();
    }
}
