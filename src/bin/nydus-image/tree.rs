// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! File node tree for RAFS format
//!
//! Build a node tree from filesystem directory named FilesystemTree.
//! Build a node tree from metadata file named MetadataTree.
//! Layered build steps:
//! 1. Apply FilesystemTree (from upper layer) to MetadataTree (from lower layer) as overlay node tree;
//! 2. Traverse overlay node tree then dump to bootstrap and blob file according to RAFS format.

use std::collections::HashMap;
use std::fs;
use std::fs::DirEntry;
use std::io::Result;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use rafs::metadata::layout::*;
use rafs::metadata::{Inode, RafsInode, RafsSuper};

use crate::node::*;

const OCISPEC_WHITEOUT_PREFIX: &str = ".wh.";
const OCISPEC_WHITEOUT_OPAQUE: &str = ".wh..wh..opq";

#[derive(Clone)]
pub struct Tree {
    pub node: Node,
    pub children: Vec<Tree>,
}

struct MetadataTreeBuilder<'a> {
    rs: &'a RafsSuper,
}

impl<'a> MetadataTreeBuilder<'a> {
    fn new(rs: &'a RafsSuper) -> Self {
        Self { rs }
    }

    /// Build node tree by loading bootstrap file
    fn load_children(&self, ino: Inode, parent: Option<&PathBuf>) -> Result<Vec<Tree>> {
        let inode = self.rs.get_inode(ino, true)?;
        let child_index = inode.get_child_index()?;
        let child_count = inode.get_child_count();

        let parent_path = if let Some(parent) = parent {
            parent.join(inode.name()?)
        } else {
            PathBuf::from_str("/").unwrap()
        };

        let mut children = Vec::new();
        if inode.is_dir() {
            for idx in child_index..(child_index + child_count) {
                let child = self.rs.get_inode(idx as Inode, true)?;
                let child_path = parent_path.join(child.name()?);
                let child = self.parse_node(child, child_path.clone())?;
                let mut child = Tree::new(child);
                child.children = self.load_children(idx as Inode, Some(&parent_path))?;
                children.push(child);
            }
        }

        Ok(children)
    }

    /// Parse ondisk inode in RAFS to Node in builder
    fn parse_node(&self, inode: Arc<dyn RafsInode>, path: PathBuf) -> Result<Node> {
        // Parse chunks info
        let child_count = inode.get_child_count();
        let mut chunks = Vec::new();
        if inode.is_reg() {
            let chunk_count = child_count;
            for i in 0..chunk_count {
                let chunk = inode.get_chunk_info(i as u32)?.cast_ondisk()?;
                chunks.push(chunk);
            }
        }

        // Parse symlink
        let symlink = if inode.is_symlink() {
            Some(inode.get_symlink()?)
        } else {
            None
        };

        // Parse xattrs
        let mut xattrs = XAttrs {
            pairs: HashMap::new(),
        };
        for name in inode.get_xattrs()? {
            let name = bytes_to_os_str(&name);
            let value = inode.get_xattr(name)?;
            xattrs
                .pairs
                .insert(name.to_os_string(), value.unwrap_or_else(Vec::new));
        }

        // Get OndiskInode
        let ondisk_inode = inode.cast_ondisk()?;

        // Inodes from parent bootstrap can't have nodes with unique inode number.
        // So we assign an invalid dev here.
        Ok(Node {
            index: 0,
            real_ino: ondisk_inode.i_ino,
            dev: u64::MAX,
            overlay: Overlay::Lower,
            explicit_uidgid: self.rs.meta.explicit_uidgid(),
            source: PathBuf::from_str("/").unwrap(),
            path,
            inode: ondisk_inode,
            chunks,
            symlink,
            xattrs,
        })
    }
}

struct FilesystemTreeBuilder {
    root_path: PathBuf,
}

impl FilesystemTreeBuilder {
    fn new(root_path: PathBuf) -> Self {
        Self { root_path }
    }

    /// Walk directory to build node tree by DFS,
    /// support overlay defined in OCI image layer spec (https://github.com/opencontainers/image-spec/blob/master/layer.md)
    fn load_children(&self, parent: &mut Node, overlay: bool) -> Result<Vec<Tree>> {
        let mut result = Vec::new();

        if !parent.is_dir() {
            return Ok(result);
        }

        // Ignore children of the directory including OCISPEC_WHITEOUT_OPAQUE file
        if overlay && parent.path.join(OCISPEC_WHITEOUT_OPAQUE).exists() {
            parent.overlay = Overlay::UpperOpaque;
        }

        let children = fs::read_dir(&parent.path)?;
        let children = children.collect::<Result<Vec<DirEntry>>>()?;

        for child in children {
            let path = child.path();
            let child = Node::new(
                self.root_path.clone(),
                path.clone(),
                Overlay::UpperAddition,
                parent.explicit_uidgid,
            )?;

            // Ignore special file
            if child.file_type() == "" {
                continue;
            }

            let mut child_tree = Tree::new(child);
            let name = child_tree.node.name();

            // Add overlay flag to node
            if overlay {
                // Ignore OCISPEC_WHITEOUT_OPAQUE file
                if name == OCISPEC_WHITEOUT_OPAQUE {
                    continue;
                }
                // Handle whiteout file
                if let Some(n) = name.to_str() {
                    if n.starts_with(OCISPEC_WHITEOUT_PREFIX) {
                        child_tree.node.path =
                            parent.path.join(&n[OCISPEC_WHITEOUT_PREFIX.len()..]);
                        child_tree.node.overlay = Overlay::UpperRemoval;
                        result.insert(0, child_tree);
                        continue;
                    }
                }
            }

            child_tree.children = self.load_children(&mut child_tree.node, overlay)?;

            let child_overlay = &child_tree.node.overlay;
            if overlay
                && (child_overlay == &Overlay::UpperRemoval
                    || child_overlay == &Overlay::UpperOpaque)
            {
                // Put the whiteout file of upper layer in the front,
                // so that it can be applied to the node tree of lower layer first than other files of upper layer.
                result.insert(0, child_tree);
            } else {
                result.push(child_tree);
            }
        }

        Ok(result)
    }
}

impl Tree {
    pub fn new(node: Node) -> Self {
        Tree {
            node,
            children: Vec::new(),
        }
    }

    /// Build node tree from a bootstrap file
    pub fn from_bootstrap(rs: &RafsSuper) -> Result<Self> {
        let tree_builder = MetadataTreeBuilder::new(&rs);

        let root_inode = rs.get_inode(RAFS_ROOT_INODE, true)?;
        let root_node = tree_builder.parse_node(root_inode, PathBuf::from_str("/").unwrap())?;
        let mut tree = Tree::new(root_node);

        tree.children = tree_builder.load_children(RAFS_ROOT_INODE, None)?;

        Ok(tree)
    }

    /// Build node tree from a filesystem directory
    pub fn from_filesystem(
        root_path: &PathBuf,
        overlay: bool,
        explicit_uidgid: bool,
    ) -> Result<Self> {
        let tree_builder = FilesystemTreeBuilder::new(root_path.clone());

        let node = Node::new(
            root_path.clone(),
            root_path.clone(),
            Overlay::UpperAddition,
            explicit_uidgid,
        )?;
        let mut tree = Tree::new(node);

        tree.children = tree_builder.load_children(&mut tree.node, overlay)?;

        Ok(tree)
    }

    /// Apply new node (upper layer) to node tree (lower layer),
    /// include change types Additions, Modifications, Removals and Opaques
    pub fn apply(&mut self, target: &Node) -> Result<Overlay> {
        if target.overlay == Overlay::UpperRemoval {
            return self.remove(target, false);
        }

        if target.overlay == Overlay::UpperOpaque {
            self.remove(target, true)?;
            // Continue to handle child nodes
        }

        let target_paths = target.path_vec();
        let target_paths_len = target_paths.len();
        let depth = self.node.path_vec().len();

        // Don't search if path recursive depth out of target path
        if depth < target_paths_len {
            // TODO: Search child by binary search
            for child in self.children.iter_mut() {
                // Skip if path component name not match
                if target_paths[depth] != child.node.name() {
                    continue;
                }
                // Modifications: Replace the node
                if depth == target_paths_len - 1 {
                    let mut node = target.clone();
                    node.overlay = Overlay::UpperModification;
                    *child = Tree {
                        node,
                        children: child.children.clone(),
                    };
                    return Ok(Overlay::UpperModification);
                }
                if child.node.is_dir() {
                    // Search the node recursively
                    let overlay = child.apply(target)?;
                    if overlay != Overlay::Lower {
                        return Ok(overlay);
                    }
                }
            }
        }

        // Additions: Add new node to children
        if depth == target_paths_len - 1 && target_paths[depth - 1] == self.node.name() {
            let mut node = target.clone();
            node.overlay = Overlay::UpperAddition;
            self.children.push(Tree {
                node,
                children: Vec::new(),
            });
            return Ok(Overlay::UpperAddition);
        }

        Ok(Overlay::Lower)
    }

    /// Remove node from node tree
    fn remove(&mut self, target: &Node, children_only: bool) -> Result<Overlay> {
        let target_paths = target.path_vec();
        let target_paths_len = target_paths.len();
        let depth = self.node.path_vec().len();

        // Opaques for root(/) path
        if children_only && depth == target_paths_len && target_paths[depth - 1] == self.node.name()
        {
            self.node.overlay = Overlay::UpperOpaque;
            self.children.clear();
            return Ok(Overlay::UpperOpaque);
        }

        // Don't search if path recursive depth out of target path
        if depth < target_paths_len {
            // TODO: Search child by binary search
            for idx in 0..self.children.len() {
                let child = &mut self.children[idx];
                // Skip if path component name not match
                if target_paths[depth] != child.node.name() {
                    continue;
                }
                if depth == target_paths_len - 1 {
                    // Opaques: Remove children of the node
                    if children_only {
                        child.node.overlay = Overlay::UpperOpaque;
                        // Remove child nodes of lower layer
                        child.children.clear();
                        return Ok(Overlay::UpperOpaque);
                    }
                    // Removals: Remove the whole lower node
                    self.children.remove(idx);
                    return Ok(Overlay::UpperRemoval);
                }
                if child.node.is_dir() {
                    // Search the node recursively
                    let overlay = child.remove(target, children_only)?;
                    if overlay != Overlay::Lower {
                        return Ok(overlay);
                    }
                }
            }
        }

        Ok(Overlay::Lower)
    }
}
