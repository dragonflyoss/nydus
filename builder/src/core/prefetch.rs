// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{anyhow, Context, Error, Result};
use indexmap::IndexMap;
use nydus_rafs::metadata::layout::v5::RafsV5PrefetchTable;
use nydus_rafs::metadata::layout::v6::{calculate_nid, RafsV6PrefetchTable};

use super::node::Node;
use crate::core::tree::TreeNode;

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

    for file in &input {
        let file_trimmed: PathBuf = file.trim().into();
        // Sanity check for the list format.
        if !file_trimmed.is_absolute() {
            warn!(
                "Illegal file path {} specified, should be absolute path",
                file
            );
            continue;
        }

        let mut current_path = file_trimmed.clone();
        let mut skip = patterns.contains_key(&current_path);
        while !skip && current_path.pop() {
            if patterns.contains_key(&current_path) {
                skip = true;
                break;
            }
        }

        if skip {
            warn!(
                "prefetch pattern {} is covered by previous pattern and thus omitted",
                file
            );
        } else {
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
    // Files from this list may be put at the head of data blob for better prefetch performance,
    // The index of matched prefetch pattern is stored in `usize`,
    // which will help to sort the prefetch files in the final layout.
    // It only stores regular files.
    files_prefetch: Vec<(TreeNode, usize)>,

    // It stores all non-prefetch files that is not stored in `prefetch_files`,
    // including regular files, dirs, symlinks, etc.,
    // with the same order of BFS traversal of file tree.
    files_non_prefetch: Vec<TreeNode>,
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
            files_prefetch: Vec::with_capacity(10000),
            files_non_prefetch: Vec::with_capacity(10000),
        })
    }

    /// Insert node into the prefetch Vector if it matches prefetch rules,
    /// while recording the index of matched prefetch pattern,
    /// or insert it into non-prefetch Vector.
    pub fn insert(&mut self, obj: &TreeNode, node: &Node) {
        // Newly created root inode of this rafs has zero size
        if self.policy == PrefetchPolicy::None
            || self.disabled
            || (node.inode.is_reg() && node.inode.size() == 0)
        {
            self.files_non_prefetch.push(obj.clone());
            return;
        }

        let mut path = node.target().clone();
        let mut exact_match = true;
        loop {
            if let Some((idx, _, v)) = self.patterns.get_full_mut(&path) {
                if exact_match {
                    *v = Some(obj.clone());
                }
                if node.is_reg() {
                    self.files_prefetch.push((obj.clone(), idx));
                } else {
                    self.files_non_prefetch.push(obj.clone());
                }
                return;
            }
            // If no exact match, try to match parent dir until root.
            if !path.pop() {
                self.files_non_prefetch.push(obj.clone());
                return;
            }
            exact_match = false;
        }
    }

    /// Get node Vector of files in the prefetch list and non-prefetch list.
    /// The order of prefetch files is the same as the order of prefetch patterns.
    /// The order of non-prefetch files is the same as the order of BFS traversal of file tree.
    pub fn get_file_nodes(&self) -> (Vec<TreeNode>, Vec<TreeNode>) {
        let mut p_files = self.files_prefetch.clone();
        p_files.sort_by_key(|k| k.1);

        let p_files = p_files.into_iter().map(|(s, _)| s).collect();

        (p_files, self.files_non_prefetch.clone())
    }

    /// Get the number of ``valid`` prefetch rules.
    pub fn fs_prefetch_rule_count(&self) -> u32 {
        if self.policy == PrefetchPolicy::Fs {
            self.patterns.values().filter(|v| v.is_some()).count() as u32
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
        self.patterns.clear();
        self.files_prefetch.clear();
        self.files_non_prefetch.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::node::NodeInfo;
    use nydus_rafs::metadata::{inode::InodeWrapper, RafsVersion};
    use std::sync::Mutex;

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

    #[test]
    fn test_prefetch() {
        let input = vec![
            "/a/b".to_string(),
            "/f".to_string(),
            "/h/i".to_string(),
            "/k".to_string(),
        ];
        let patterns = generate_patterns(input).unwrap();
        let mut prefetch = Prefetch {
            policy: PrefetchPolicy::Fs,
            disabled: false,
            patterns,
            files_prefetch: Vec::with_capacity(10),
            files_non_prefetch: Vec::with_capacity(10),
        };
        let mut inode = InodeWrapper::new(RafsVersion::V6);
        inode.set_mode(0o755 | libc::S_IFREG as u32);
        inode.set_size(1);

        let info = NodeInfo::default();

        let mut info1 = info.clone();
        info1.target = PathBuf::from("/f");
        let node1 = Node::new(inode.clone(), info1, 1);
        let node1 = TreeNode::new(Mutex::from(node1));
        prefetch.insert(&node1, &node1.lock().unwrap());

        let inode2 = inode.clone();
        let mut info2 = info.clone();
        info2.target = PathBuf::from("/a/b");
        let node2 = Node::new(inode2, info2, 1);
        let node2 = TreeNode::new(Mutex::from(node2));
        prefetch.insert(&node2, &node2.lock().unwrap());

        let inode3 = inode.clone();
        let mut info3 = info.clone();
        info3.target = PathBuf::from("/h/i/j");
        let node3 = Node::new(inode3, info3, 1);
        let node3 = TreeNode::new(Mutex::from(node3));
        prefetch.insert(&node3, &node3.lock().unwrap());

        let inode4 = inode.clone();
        let mut info4 = info.clone();
        info4.target = PathBuf::from("/z");
        let node4 = Node::new(inode4, info4, 1);
        let node4 = TreeNode::new(Mutex::from(node4));
        prefetch.insert(&node4, &node4.lock().unwrap());

        let inode5 = inode.clone();
        inode.set_mode(0o755 | libc::S_IFDIR as u32);
        inode.set_size(0);
        let mut info5 = info;
        info5.target = PathBuf::from("/a/b/d");
        let node5 = Node::new(inode5, info5, 1);
        let node5 = TreeNode::new(Mutex::from(node5));
        prefetch.insert(&node5, &node5.lock().unwrap());

        // node1, node2
        assert_eq!(prefetch.fs_prefetch_rule_count(), 2);

        let (pre, non_pre) = prefetch.get_file_nodes();
        assert_eq!(pre.len(), 4);
        assert_eq!(non_pre.len(), 1);
        let pre_str: Vec<String> = pre
            .iter()
            .map(|n| n.lock().unwrap().target().to_str().unwrap().to_owned())
            .collect();
        assert_eq!(pre_str, vec!["/a/b", "/a/b/d", "/f", "/h/i/j"]);
        let non_pre_str: Vec<String> = non_pre
            .iter()
            .map(|n| n.lock().unwrap().target().to_str().unwrap().to_owned())
            .collect();
        assert_eq!(non_pre_str, vec!["/z"]);

        prefetch.clear();
        assert_eq!(prefetch.fs_prefetch_rule_count(), 0);
        let (pre, non_pre) = prefetch.get_file_nodes();
        assert_eq!(pre.len(), 0);
        assert_eq!(non_pre.len(), 0);
    }
}
