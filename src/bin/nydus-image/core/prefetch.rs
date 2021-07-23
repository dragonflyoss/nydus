// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Error, Result};

use crate::node::*;
use rafs::metadata::layout::PrefetchTable;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PrefetchPolicy {
    None,
    /// Readahead will be issued from Fs layer, which leverages inode/chunkinfo to prefetch data
    /// from blob no mather where it resides(OSS/Localfs). Basically, it is willing to cache the
    /// data into blobcache(if exists). It's more nimble. With this policy applied, image builder
    /// currently puts readahead files' data into a continuous region within blob which behaves very
    /// similar to `Blob` policy.
    Fs,
    /// Readahead will be issued directly from backend/blob layer
    Blob,
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

/// Gather readahead file paths line by line from stdin
/// Input format:
///    printf "/relative/path/to/rootfs/1\n/relative/path/to/rootfs/1"
/// This routine does not guarantee that specified file must exist in local filesystem,
/// this is because we can't guarantee that source rootfs directory of parent bootstrap
/// is located in local file system.
fn gather_readahead_files() -> Result<BTreeMap<PathBuf, Option<u64>>> {
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

pub struct Prefetch {
    pub policy: PrefetchPolicy,
    /// Readahead file list, use BTreeMap to keep stable iteration order, HashMap<path, Option<index>>.
    /// Files from this collection are all regular files and will be persisted to blob following a certain scheme.
    readahead_files: BTreeMap<PathBuf, Option<u64>>,
    /// Specify files or directories which need to prefetch. Their inode numbers will
    /// be persist to prefetch table. They could be directory's or regular file's inode number, by which
    /// its inode index of inode table can be calculated.
    hint_readahead_files: BTreeMap<PathBuf, Option<u64>>,
}

impl Prefetch {
    pub fn new(policy: PrefetchPolicy) -> Result<Self> {
        let hint_readahead_files = if policy != PrefetchPolicy::None {
            gather_readahead_files().context("failed to get readahead files")?
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            policy,
            hint_readahead_files,
            readahead_files: BTreeMap::new(),
        })
    }

    pub fn insert_if_need(&mut self, node: &Node) {
        let path = &node.rootfs();
        let inode = node.inode.i_ino;
        let index = node.index;

        if self.policy == PrefetchPolicy::None || node.inode.i_size == 0 {
            return;
        }

        let keys = self
            .hint_readahead_files
            .keys()
            .cloned()
            .collect::<Vec<_>>();

        for f in &keys {
            // As path is canonicalized, it should be reliable.
            if path == f {
                if self.policy == PrefetchPolicy::Fs {
                    if let Some(i) = self.hint_readahead_files.get_mut(path) {
                        *i = Some(inode);
                    }
                }
                self.readahead_files.insert(path.clone(), Some(index));
            } else if path.starts_with(f) {
                // Users can specify hinted parent directory with its child files hinted as well.
                // Only put the parent directory into ondisk prefetch table since a hinted directory's
                // all child files will be prefetched after mount.
                if self.hint_readahead_files.get(path).is_some() {
                    self.hint_readahead_files.remove(path);
                }
                self.readahead_files.insert(path.clone(), Some(index));
            }
        }
    }

    pub fn contains(&mut self, node: &Node) -> bool {
        self.readahead_files.get(&node.rootfs()).is_some()
    }

    pub fn get_file_indexes(&self) -> Vec<&u64> {
        self.readahead_files
            .values()
            .filter_map(|index| index.as_ref())
            .collect()
    }

    pub fn get_prefetch_table(&mut self) -> Option<PrefetchTable> {
        if self.policy == PrefetchPolicy::Fs {
            let mut prefetch_table = PrefetchTable::new();
            for i in self
                .hint_readahead_files
                .iter()
                .filter_map(|(_, v)| v.as_ref())
            {
                prefetch_table.add_entry(*i as u32);
            }
            Some(prefetch_table)
        } else {
            None
        }
    }

    pub fn clear(&mut self) {
        self.readahead_files.clear();
    }
}
