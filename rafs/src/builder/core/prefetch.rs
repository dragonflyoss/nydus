// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{anyhow, Context, Error, Result};
use indexmap::IndexMap;

use super::node::Node;
use crate::builder::core::tree::TreeNode;
use crate::metadata::layout::v5::RafsV5PrefetchTable;
use crate::metadata::layout::v6::{calculate_nid, RafsV6PrefetchTable};

/// Filesystem data prefetch policy.
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
fn get_patterns() -> Result<IndexMap<PathBuf, Option<TreeNode>>> {
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

fn generate_patterns(input: Vec<String>) -> Result<IndexMap<PathBuf, Option<TreeNode>>> {
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

/// Manage filesystem data prefetch configuration and state for builder.
#[derive(Default, Clone)]
pub struct Prefetch {
    pub policy: PrefetchPolicy,

    pub disabled: bool,

    // Patterns to generate prefetch inode array, which will be put into the prefetch array
    // in the RAFS bootstrap. It may access directory or file inodes.
    patterns: IndexMap<PathBuf, Option<TreeNode>>,

    // File list to help optimizing layout of data blobs.
    // Files from this list may be put at the head of data blob for better prefetch performance.
    files: BTreeMap<PathBuf, TreeNode>,
}

impl Prefetch {
    /// Create a new instance of [Prefetch].
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

    /// Insert node into the prefetch list if it matches prefetch rules.
    pub fn insert_if_need(&mut self, obj: &TreeNode, node: &Node) {
        // Newly created root inode of this rafs has zero size
        if self.policy == PrefetchPolicy::None
            || self.disabled
            || (node.inode.is_reg() && node.inode.size() == 0)
        {
            return;
        }

        let path = node.target();
        for (f, v) in self.patterns.iter_mut() {
            // As path is canonicalized, it should be reliable.
            if path == f {
                if self.policy == PrefetchPolicy::Fs {
                    *v = Some(obj.clone());
                }
                if node.is_reg() {
                    self.files.insert(path.clone(), obj.clone());
                }
            } else if path.starts_with(f) && node.is_reg() {
                self.files.insert(path.clone(), obj.clone());
            }
        }
    }

    /// Check whether the node is in the prefetch list.
    pub fn contains(&self, node: &Node) -> bool {
        self.files.contains_key(node.target())
    }

    /// Get node index array of files in the prefetch list.
    pub fn get_file_nodes(&self) -> Vec<TreeNode> {
        self.files.values().cloned().collect()
    }

    /// Get number of prefetch rules.
    pub fn fs_prefetch_rule_count(&self) -> u32 {
        if self.policy == PrefetchPolicy::Fs {
            self.patterns.values().len() as u32
        } else {
            0
        }
    }

    /// Generate filesystem layer prefetch list for RAFS v5.
    pub fn get_v5_prefetch_table(&mut self) -> Option<RafsV5PrefetchTable> {
        if self.policy == PrefetchPolicy::Fs {
            let mut prefetch_table = RafsV5PrefetchTable::new();
            for i in self.patterns.values().filter_map(|v| v.clone()) {
                let node = i.lock().unwrap();
                assert!(node.inode.ino() < u32::MAX as u64);
                prefetch_table.add_entry(node.inode.ino() as u32);
            }
            Some(prefetch_table)
        } else {
            None
        }
    }

    /// Generate filesystem layer prefetch list for RAFS v6.
    pub fn get_v6_prefetch_table(&mut self, meta_addr: u64) -> Option<RafsV6PrefetchTable> {
        if self.policy == PrefetchPolicy::Fs {
            let mut prefetch_table = RafsV6PrefetchTable::new();
            for i in self.patterns.values().filter_map(|v| v.clone()) {
                let node = i.lock().unwrap();
                let ino = node.inode.ino();
                debug_assert!(ino > 0);
                let nid = calculate_nid(node.v6_offset, meta_addr);
                // 32bit nid can represent 128GB bootstrap, it is large enough, no need
                // to worry about casting here
                assert!(nid < u32::MAX as u64);
                trace!(
                    "v6 prefetch table: map node index {} to offset {} nid {} path {:?} name {:?}",
                    ino,
                    node.v6_offset,
                    nid,
                    node.path(),
                    node.name()
                );
                prefetch_table.add_entry(nid as u32);
            }
            Some(prefetch_table)
        } else {
            None
        }
    }

    /// Disable filesystem data prefetch.
    pub fn disable(&mut self) {
        self.disabled = true;
    }

    /// Reset to initialization state.
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

    #[test]
    fn test_prefetch_policy() {
        let policy = PrefetchPolicy::from_str("fs").unwrap();
        assert_eq!(policy, PrefetchPolicy::Fs);
        let policy = PrefetchPolicy::from_str("blob").unwrap();
        assert_eq!(policy, PrefetchPolicy::Blob);
        let policy = PrefetchPolicy::from_str("none").unwrap();
        assert_eq!(policy, PrefetchPolicy::None);
        PrefetchPolicy::from_str("").unwrap_err();
        PrefetchPolicy::from_str("invalid").unwrap_err();
    }
}
