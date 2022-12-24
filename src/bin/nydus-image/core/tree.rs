// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! An in-memory tree structure to maintain information for filesystem metadata.
//!
//! Steps to build the first layer for a Rafs image:
//! - Build the upper tree (FileSystemTree) from the source directory.
//! - Traverse the upper tree (FileSystemTree) to dump bootstrap and data blobs.
//!
//! Steps to build the second and following on layers for a Rafs image:
//! - Build the upper tree (FileSystemTree) from the source directory.
//! - Load the lower tree (MetadataTree) from a metadata blob.
//! - Merge the final tree (OverlayTree) by applying the upper tree (FileSystemTree) to the
//!   lower tree (MetadataTree).
//! - Traverse the merged tree (OverlayTree) to dump bootstrap and data blobs.

use std::ffi::OsStr;
use std::ffi::OsString;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use anyhow::Result;
use nydus_rafs::metadata::chunk::ChunkWrapper;
use nydus_rafs::metadata::inode::InodeWrapper;
use nydus_rafs::metadata::layout::{bytes_to_os_str, RafsXAttrs};
use nydus_rafs::metadata::{Inode, RafsInodeExt, RafsSuper};

use super::chunk_dict::ChunkDict;
use super::node::{ChunkSource, Node, NodeChunk, Overlay, WhiteoutSpec, WhiteoutType};

/// An in-memory tree structure to maintain information and topology of filesystem nodes.
#[derive(Clone)]
pub struct Tree {
    /// Filesystem node.
    pub node: Node,
    /// Children tree nodes.
    pub children: Vec<Tree>,
}

impl Tree {
    /// Create a new instance of `Tree` from a filesystem node.
    pub fn new(node: Node) -> Self {
        Tree {
            node,
            children: Vec::new(),
        }
    }

    /// Load a `Tree` from a bootstrap file, and optionally caches chunk information.
    pub fn from_bootstrap<T: ChunkDict>(rs: &RafsSuper, chunk_dict: &mut T) -> Result<Self> {
        let tree_builder = MetadataTreeBuilder::new(rs);
        let root_inode = rs.get_extended_inode(rs.superblock.root_ino(), true)?;
        let root_node =
            MetadataTreeBuilder::parse_node(rs, root_inode.deref(), PathBuf::from("/"))?;
        let mut tree = Tree::new(root_node);

        tree.children = timing_tracer!(
            { tree_builder.load_children(rs.superblock.root_ino(), None, chunk_dict, true) },
            "load_tree_from_bootstrap"
        )?;

        Ok(tree)
    }

    /// Walk all nodes in deep first mode.
    pub fn iterate<F>(&self, cb: &mut F) -> Result<()>
    where
        F: FnMut(&Node) -> bool,
    {
        if !cb(&self.node) {
            return Ok(());
        }
        for child in &self.children {
            child.iterate(cb)?;
        }

        Ok(())
    }

    /// Apply new node (upper layer) to node tree (lower layer).
    ///
    /// Support overlay defined in OCI image layer spec
    /// (https://github.com/opencontainers/image-spec/blob/master/layer.md),
    /// include change types Additions, Modifications, Removals and Opaques, return true if applied
    pub fn apply(
        &mut self,
        target: &Node,
        handle_whiteout: bool,
        whiteout_spec: WhiteoutSpec,
    ) -> Result<bool> {
        // Handle whiteout file
        if handle_whiteout {
            if let Some(whiteout_type) = target.whiteout_type(whiteout_spec) {
                let origin_name = target.origin_name(whiteout_type);
                let parent_name = if let Some(parent_path) = target.path().parent() {
                    parent_path.file_name()
                } else {
                    None
                };

                event_tracer!("whiteout_files", +1);
                if whiteout_type == WhiteoutType::OverlayFsOpaque {
                    self.remove(target, whiteout_type, origin_name, parent_name)?;
                    return self.apply(target, false, whiteout_spec);
                }
                return self.remove(target, whiteout_type, origin_name, parent_name);
            }
        }

        let target_paths = target.target_vec();
        let target_paths_len = target_paths.len();
        let depth = self.node.target_vec().len();

        // Handle root node modification
        if target.path() == Path::new("/") {
            let mut node = target.clone();
            node.overlay = Overlay::UpperModification;
            self.node = node;
            return Ok(true);
        }

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
                    child.node = node;
                    return Ok(true);
                }
                if child.node.is_dir() {
                    // Search the node recursively
                    let found = child.apply(target, handle_whiteout, whiteout_spec)?;
                    if found {
                        return Ok(true);
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
            return Ok(true);
        }

        Ok(false)
    }

    /// Remove node from node tree, return true if removed
    fn remove(
        &mut self,
        target: &Node,
        whiteout_type: WhiteoutType,
        origin_name: Option<&OsStr>,
        parent_name: Option<&OsStr>,
    ) -> Result<bool> {
        let target_paths = target.target_vec();
        let target_paths_len = target_paths.len();
        let node_paths = self.node.target_vec();
        let depth = node_paths.len();

        // Don't continue to search if current path not matched with target path or recursive depth
        // out of target path
        if depth >= target_paths_len || node_paths[depth - 1] != target_paths[depth - 1] {
            return Ok(false);
        }

        // Handle Opaques for root path (/)
        if depth == 1
            && (whiteout_type == WhiteoutType::OciOpaque && target_paths_len == 2
                || whiteout_type == WhiteoutType::OverlayFsOpaque && target_paths_len == 1)
        {
            self.node.overlay = Overlay::UpperOpaque;
            self.children.clear();
            return Ok(true);
        }

        // TODO: Search child by binary search
        for idx in 0..self.children.len() {
            let child = &mut self.children[idx];

            // Handle Removals
            if depth == target_paths_len - 1
                && whiteout_type.is_removal()
                && origin_name == Some(child.node.name())
            {
                // Remove the whole lower node
                self.children.remove(idx);
                return Ok(true);
            }

            // Handle Opaques
            if whiteout_type == WhiteoutType::OciOpaque
                && target_paths_len >= 2
                && depth == target_paths_len - 2
            {
                if let Some(parent_name) = parent_name {
                    if parent_name == child.node.name() {
                        child.node.overlay = Overlay::UpperOpaque;
                        // Remove children of the lower node
                        child.children.clear();
                        return Ok(true);
                    }
                }
            } else if whiteout_type == WhiteoutType::OverlayFsOpaque
                && depth == target_paths_len - 1
                && target.name() == child.node.name()
            {
                // Remove all children under the opaque directory
                child.node.overlay = Overlay::UpperOpaque;
                child.children.clear();
                return Ok(true);
            }

            if child.node.is_dir() {
                // Search the node recursively
                let found = child.remove(target, whiteout_type, origin_name, parent_name)?;
                if found {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

pub struct MetadataTreeBuilder<'a> {
    rs: &'a RafsSuper,
}

impl<'a> MetadataTreeBuilder<'a> {
    fn new(rs: &'a RafsSuper) -> Self {
        Self { rs }
    }

    /// Build node tree by loading bootstrap file
    fn load_children<T: ChunkDict>(
        &self,
        ino: Inode,
        parent: Option<&PathBuf>,
        chunk_dict: &mut T,
        validate_digest: bool,
    ) -> Result<Vec<Tree>> {
        let inode = self.rs.get_extended_inode(ino, validate_digest)?;
        if !inode.is_dir() {
            return Ok(Vec::new());
        }

        let parent_path = if let Some(parent) = parent {
            parent.join(inode.name())
        } else {
            PathBuf::from("/")
        };

        let blobs = self.rs.superblock.get_blob_infos();
        let child_count = inode.get_child_count();
        let mut children = Vec::with_capacity(child_count as usize);
        event_tracer!("load_from_parent_bootstrap", +child_count);
        // TODO(chge): Implement `Iterator` for both V5 and V6 Inodes. Then we don't need
        // `get_child_count` and `get_child_by_index` thus to get rid of concept `index`.
        for idx in 0..child_count {
            let child = inode.get_child_by_index(idx)?;
            let child_ino = child.ino();
            let child_path = parent_path.join(child.name());
            let child = Self::parse_node(self.rs, child.deref(), child_path)?;

            if child.is_reg() {
                for chunk in &child.chunks {
                    let blob_idx = chunk.inner.blob_index();
                    if let Some(blob) = blobs.get(blob_idx as usize) {
                        chunk_dict.add_chunk(chunk.inner.clone(), blob.digester());
                    }
                }
            }

            let mut child = Tree::new(child);
            if child.node.is_dir() {
                child.children =
                    self.load_children(child_ino, Some(&parent_path), chunk_dict, validate_digest)?;
            }
            children.push(child);
        }

        Ok(children)
    }

    /// Convert a `RafsInode` object to an in-memory `Node` object.
    pub fn parse_node(rs: &RafsSuper, inode: &dyn RafsInodeExt, path: PathBuf) -> Result<Node> {
        let chunks = if inode.is_reg() {
            let chunk_count = inode.get_chunk_count();
            let mut chunks = Vec::with_capacity(chunk_count as usize);
            for i in 0..chunk_count {
                let cki = inode.get_chunk_info(i)?;
                chunks.push(NodeChunk {
                    source: ChunkSource::Parent,
                    inner: ChunkWrapper::from_chunk_info(cki.as_ref()),
                });
            }
            chunks
        } else {
            Vec::new()
        };

        let symlink = if inode.is_symlink() {
            Some(inode.get_symlink()?)
        } else {
            None
        };

        let mut xattrs = RafsXAttrs::new();
        for name in inode.get_xattrs()? {
            let name = bytes_to_os_str(&name);
            let value = inode.get_xattr(name)?;
            xattrs.add(name.to_os_string(), value.unwrap_or_default())?;
        }

        // Nodes loaded from bootstrap will only be used as `Overlay::Lower`, so make `dev` invalid
        // to avoid breaking hardlink detecting logic.
        let src_dev = u64::MAX;

        let inode_wrapper = InodeWrapper::from_inode_info(inode);
        let source = PathBuf::from("/");
        let target = Node::generate_target(&path, &source);
        let target_vec = Node::generate_target_vec(&target);

        Ok(Node {
            index: 0,
            src_ino: inode_wrapper.ino(),
            src_dev,
            rdev: inode.rdev() as u64,
            overlay: Overlay::Lower,
            explicit_uidgid: rs.meta.explicit_uidgid(),
            source,
            target,
            path,
            target_vec,
            inode: inode_wrapper,
            chunks,
            symlink,
            xattrs,
            layer_idx: 0,
            ctime: 0,
            v6_offset: 0,
            v6_dirents: Vec::<(u64, OsString, u32)>::new(),
            v6_datalayout: 0,
            v6_compact_inode: false,
            v6_force_extended_inode: false,
            v6_dirents_offset: 0,
        })
    }
}
