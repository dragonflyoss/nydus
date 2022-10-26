// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Error, Result};
use indexmap::IndexMap;
use nydus_rafs::metadata::layout::v5::RafsV5PrefetchTable;
use nydus_rafs::metadata::layout::v6::{calculate_nid, RafsV6PrefetchTable};

use crate::node::Node;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PrefetchPolicy {
    None,
    /// Prefetch will be issued from Fs layer, which leverages inode/chunkinfo to prefetch data
    /// from blob no matter where it resides(OSS/Localfs). Basically, it is willing to cache the
    /// data into blobcache(if exists). It's more nimble. With this policy applied, image builder
    /// currently puts prefetch files' data into a continuous region within blob which behaves very
    /// similar to `Blob` policy.
    Fs,
    /// Prefetch will be issued directly from backend/blob layer
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

/// Gather prefetch patterns from STDIN line by line.
///
/// Input format:
///    printf "/relative/path/to/rootfs/1\n/relative/path/to/rootfs/2"
///
/// It does not guarantee that specified path exist in local filesystem because the specified path
/// may exist in parent image/layers.
fn get_patterns() -> Result<IndexMap<PathBuf, Option<u64>>> {
    let stdin = std::io::stdin();
    let mut patterns = Vec::new();

    loop {
        let mut file = String::new();
        let size = stdin
            .read_line(&mut file)
            .context("failed to read prefetch pattern")?;
        if size == 0 {
            return generate_patterns(patterns);
        }
        patterns.push(file);
    }
}

fn generate_patterns(input: Vec<String>) -> Result<IndexMap<PathBuf, Option<u64>>> {
    let mut patterns = IndexMap::new();

    for (idx, file) in input.iter().enumerate() {
        let file_trimmed: PathBuf = file.trim().into();
        // Sanity check for the list format.
        if !file_trimmed.is_absolute() {
            warn!(
                "Illegal file path {} specified, should be absolute path",
                file
            );
            continue;
        }

        let mut skip = false;
        for prefix in input.iter().take(idx) {
            if file_trimmed.starts_with(prefix) {
                skip = true;
            }
        }
        if !skip {
            debug!(
                "prefetch pattern: {}, trimmed file name {:?}",
                file, file_trimmed
            );
            patterns.insert(file_trimmed, None);
        }
    }

    Ok(patterns)
}

#[derive(Default, Clone)]
pub struct Prefetch {
    pub policy: PrefetchPolicy,

    pub disabled: bool,

    // Patterns to generate prefetch inode array, which will be put into the prefetch array
    // in the RAFS bootstrap. It may access directory or file inodes.
    patterns: IndexMap<PathBuf, Option<u64>>,

    // File list to help optimizing layout of data blobs.
    // Files from this list may be put at the head of data blob for better prefetch performance.
    files: BTreeMap<PathBuf, u64>,
}

impl Prefetch {
    pub fn new(policy: PrefetchPolicy) -> Result<Self> {
        let patterns = if policy != PrefetchPolicy::None {
            get_patterns().context("failed to get prefetch patterns")?
        } else {
            IndexMap::new()
        };

        Ok(Self {
            policy,
            disabled: false,
            patterns,
            files: BTreeMap::new(),
        })
    }

    pub fn insert_if_need(&mut self, node: &Node) {
        let path = node.target();
        let index = node.index;

        // Newly created root inode of this rafs has zero size
        if self.policy == PrefetchPolicy::None
            || self.disabled
            || (node.inode.is_reg() && node.inode.size() == 0)
        {
            return;
        }

        for (f, v) in self.patterns.iter_mut() {
            // As path is canonicalized, it should be reliable.
            if path == f {
                if self.policy == PrefetchPolicy::Fs {
                    *v = Some(index);
                }
                if node.is_reg() {
                    self.files.insert(path.clone(), index);
                }
            } else if path.starts_with(f) && node.is_reg() {
                self.files.insert(path.clone(), index);
            }
        }
    }

    pub fn contains(&self, node: &Node) -> bool {
        self.files.contains_key(node.target())
    }

    pub fn get_file_indexes(&self) -> Vec<u64> {
        self.files.values().copied().collect()
    }

    pub fn len(&self) -> u32 {
        if self.policy == PrefetchPolicy::Fs {
            self.patterns.values().len() as u32
        } else {
            0
        }
    }

    /// Generate filesystem layer prefetch list for RAFS v5.
    pub fn get_rafsv5_prefetch_table(&mut self, nodes: &[Node]) -> Option<RafsV5PrefetchTable> {
        if self.policy == PrefetchPolicy::Fs {
            let mut prefetch_table = RafsV5PrefetchTable::new();
            for i in self.patterns.values().filter_map(|v| *v) {
                // Rafs v5 has inode number equal to index if it is not hardlink.
                if i < u32::MAX as u64 {
                    prefetch_table.add_entry(nodes[i as usize - 1].inode.ino() as u32);
                }
            }
            Some(prefetch_table)
        } else {
            None
        }
    }

    /// Generate filesystem layer prefetch list for RAFS v6.
    pub fn get_rafsv6_prefetch_table(
        &mut self,
        nodes: &[Node],
        meta_addr: u64,
    ) -> Option<RafsV6PrefetchTable> {
        if self.policy == PrefetchPolicy::Fs {
            let mut prefetch_table = RafsV6PrefetchTable::new();
            for i in self.patterns.values().filter_map(|v| *v) {
                debug_assert!(i > 0);
                // i holds the Node.index, which starts at 1, so it needs to be converted to the
                // index of the Node array to index the corresponding Node
                let array_index = i as usize - 1;
                let nid = calculate_nid(nodes[array_index].v6_offset, meta_addr);
                trace!(
                    "v6 prefetch table: map node index {} to offset {} nid {} path {:?} name {:?}",
                    i,
                    nodes[array_index].v6_offset,
                    nid,
                    nodes[array_index].path(),
                    nodes[array_index].name()
                );
                // 32bit nid can represent 128GB bootstrap, it is large enough, no need
                // to worry about casting here
                assert!(nid < u32::MAX as u64);
                prefetch_table.add_entry(nid as u32);
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
        self.files.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_pattern() {
        let input = vec![
            "/a/b".to_string(),
            "/a/b/c".to_string(),
            "/a/b/d".to_string(),
            "/a/b/d/e".to_string(),
            "/f".to_string(),
            "/h/i".to_string(),
        ];
        let patterns = generate_patterns(input).unwrap();
        assert_eq!(patterns.len(), 3);
        assert!(patterns.contains_key(&PathBuf::from("/a/b")));
        assert!(patterns.contains_key(&PathBuf::from("/f")));
        assert!(patterns.contains_key(&PathBuf::from("/h/i")));
        assert!(!patterns.contains_key(&PathBuf::from("/")));
        assert!(!patterns.contains_key(&PathBuf::from("/a")));
        assert!(!patterns.contains_key(&PathBuf::from("/a/b/c")));
        assert!(!patterns.contains_key(&PathBuf::from("/a/b/d")));
        assert!(!patterns.contains_key(&PathBuf::from("/a/b/d/e")));
        assert!(!patterns.contains_key(&PathBuf::from("/k")));
    }
}
