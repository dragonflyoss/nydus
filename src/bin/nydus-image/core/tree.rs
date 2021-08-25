// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! A tree structure to maintain information for filesystem directories and files in memory.
//!
//! Steps to build RAFS image for the first layer:
//! - Build the upper tree (FileSystemTree) from filesystem directory.
//! - Traverse the upper tree (FileSystemTree) to dump bootstrap and blob file.
//!
//! Steps to build RAFS image for second and following on layers:
//! - Build the upper tree (FileSystemTree) from filesystem directory.
//! - Build the lower tree (MetadataTree) from metadata file.
//! - Generate the merged tree (OverlayTree) by applying the upper tree (FileSystemTree) to the
//!   lower tree (MetadataTree).
//! - Traverse the merged tree (OverlayTree) to dump bootstrap and blob file.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;

use nydus_utils::digest::RafsDigest;
use rafs::metadata::layout::v5::{
    RafsChunkInfo, RafsV5ChunkInfo, RafsV5Inode, RafsV5InodeFlags, RafsV5XAttrs,
};
use rafs::metadata::layout::{bytes_to_os_str, RAFS_ROOT_INODE};
use rafs::metadata::{Inode, RafsInode, RafsSuper};

use crate::node::*;

/// Construct a `RafsV5ChunkInfo` object from a `dyn RafsChunkInfo` object.
fn cast_rafsv5_chunk_info(cki: &dyn RafsChunkInfo) -> RafsV5ChunkInfo {
    RafsV5ChunkInfo {
        block_id: *cki.block_id(),
        blob_index: cki.blob_index(),
        flags: cki.flags(),
        compress_size: cki.compress_size(),
        decompress_size: cki.decompress_size(),
        compress_offset: cki.compress_offset(),
        decompress_offset: cki.decompress_offset(),
        file_offset: cki.file_offset(),
        index: cki.index(),
        reserved: 0u32,
    }
}

/// Construct a `RafsV5Inode` object from a `Arc<dyn RafsInode>` object.
fn cast_rafsv5_inode(inode: &Arc<dyn RafsInode>) -> RafsV5Inode {
    let attr = inode.get_attr();

    RafsV5Inode {
        i_digest: inode.get_digest(),
        i_parent: inode.parent(),
        i_ino: attr.ino,
        i_uid: attr.uid,
        i_gid: attr.gid,
        i_projid: inode.projid(),
        i_mode: attr.mode,
        i_size: attr.size,
        i_blocks: attr.blocks,
        i_flags: RafsV5InodeFlags::from_bits_truncate(inode.flags()),
        i_nlink: attr.nlink,
        i_child_index: inode.get_child_index().unwrap_or(0),
        i_child_count: inode.get_child_count(),
        i_name_size: inode.get_name_size(),
        i_symlink_size: inode.get_symlink_size(),
        i_rdev: attr.rdev,
        i_mtime_nsec: attr.mtimensec,
        i_mtime: attr.mtime,
        i_reserved: [0u8; 8],
    }
}

/// A simple tree structure to maintain information for filesystem directories and files in memory.
#[derive(Clone)]
pub struct Tree {
    pub node: Node,
    pub children: Vec<Tree>,
}

impl Tree {
    pub fn new(node: Node) -> Self {
        Tree {
            node,
            children: Vec::new(),
        }
    }

    pub fn iterate<F>(&self, cb: &F) -> Result<()>
    where
        F: Fn(&Node) -> bool,
    {
        if !cb(&self.node) {
            return Ok(());
        }
        for child in &self.children {
            child.iterate(cb)?;
        }
        Ok(())
    }

    /// Build node tree from a bootstrap file
    pub fn from_bootstrap(
        rs: &RafsSuper,
        mut chunk_cache: Option<&mut HashMap<RafsDigest, RafsV5ChunkInfo>>,
    ) -> Result<Self> {
        let tree_builder = MetadataTreeBuilder::new(&rs);
        let root_inode = rs.get_inode(RAFS_ROOT_INODE, true)?;
        let root_node = tree_builder.parse_node(root_inode, PathBuf::from("/"))?;
        let mut tree = Tree::new(root_node);

        tree.children = timing_tracer!(
            { tree_builder.load_children(RAFS_ROOT_INODE, None, &mut chunk_cache, true) },
            "load_from_parent_bootstrap"
        )?;

        Ok(tree)
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
        whiteout_spec: &WhiteoutSpec,
    ) -> Result<bool> {
        // Handle whiteout file
        if handle_whiteout {
            if let Some(whiteout_type) = target.whiteout_type(whiteout_spec) {
                event_tracer!("whiteout_files", +1);
                if whiteout_type == WhiteoutType::OverlayFsOpaque {
                    self.remove(target, whiteout_spec)?;
                    return self.apply(target, false, whiteout_spec);
                }
                return self.remove(target, whiteout_spec);
            }
        }

        let target_paths = target.path_vec();
        let target_paths_len = target_paths.len();
        let depth = self.node.path_vec().len();

        // Handle root node modification
        if target.path == PathBuf::from("/") {
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
                    *child = Tree {
                        node,
                        children: child.children.clone(),
                    };
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
    fn remove(&mut self, target: &Node, whiteout_spec: &WhiteoutSpec) -> Result<bool> {
        let target_paths = target.path_vec();
        let target_paths_len = target_paths.len();
        let node_paths = self.node.path_vec();
        let depth = node_paths.len();

        // Don't continue to search if current path not matched with target path or recursive depth out of target path
        if depth >= target_paths_len || node_paths[depth - 1] != target_paths[depth - 1] {
            return Ok(false);
        }

        // safe because it's checked before calling into here
        let whiteout_type = target.whiteout_type(whiteout_spec).unwrap();

        // Handle Opaques for root path (/)
        if depth == 1
            && (whiteout_type == WhiteoutType::OciOpaque && target_paths_len == 2
                || whiteout_type == WhiteoutType::OverlayFsOpaque && target_paths_len == 1)
        {
            self.node.overlay = Overlay::UpperOpaque;
            self.children.clear();
            return Ok(true);
        }

        let mut parent_name = None;
        if let Some(parent_path) = target.path.parent() {
            if let Some(file_name) = parent_path.file_name() {
                parent_name = Some(file_name);
            }
        }
        let origin_name = target.origin_name(whiteout_type);

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
                let found = child.remove(target, whiteout_spec)?;
                if found {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

struct MetadataTreeBuilder<'a> {
    rs: &'a RafsSuper,
}

impl<'a> MetadataTreeBuilder<'a> {
    fn new(rs: &'a RafsSuper) -> Self {
        Self { rs }
    }

    /// Build node tree by loading bootstrap file
    fn load_children(
        &self,
        ino: Inode,
        parent: Option<&PathBuf>,
        chunk_cache: &mut Option<&mut HashMap<RafsDigest, RafsV5ChunkInfo>>,
        validate_digest: bool,
    ) -> Result<Vec<Tree>> {
        let mut children = Vec::new();
        let inode = self.rs.get_inode(ino, validate_digest)?;

        if !inode.is_dir() {
            return Ok(children);
        }

        let child_count = inode.get_child_count();
        event_tracer!("load_from_parent_bootstrap", +child_count);

        let parent_path = if let Some(parent) = parent {
            parent.join(inode.name())
        } else {
            PathBuf::from("/")
        };

        for idx in 0..child_count {
            let child = inode.get_child_by_index(idx as Inode)?;
            let child_ino = child.ino();
            let child_path = parent_path.join(child.name());
            let child = self.parse_node(child, child_path)?;

            if let Some(chunk_cache) = chunk_cache {
                if child.is_reg() {
                    for chunk in &child.chunks {
                        chunk_cache.insert(chunk.block_id, *chunk);
                    }
                }
            }

            let mut child = Tree::new(child);
            if child.node.is_dir() {
                child.children = self.load_children(
                    child_ino,
                    Some(&parent_path),
                    chunk_cache,
                    validate_digest,
                )?;
            }
            children.push(child);
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
                let cki = inode.get_chunk_info(i)?;
                let chunk = cast_rafsv5_chunk_info(cki.as_ref());
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
        let mut xattrs = RafsV5XAttrs::new();
        for name in inode.get_xattrs()? {
            let name = bytes_to_os_str(&name);
            let value = inode.get_xattr(name)?;
            xattrs.add(name.to_os_string(), value.unwrap_or_else(Vec::new));
        }

        // Get OndiskInode
        let ondisk_inode = cast_rafsv5_inode(&inode);

        // Inodes from parent bootstrap can't have nodes with unique inode number.
        // So we assign an invalid dev here.
        Ok(Node {
            index: 0,
            real_ino: ondisk_inode.i_ino,
            dev: u64::MAX,
            rdev: inode.rdev() as u64,
            overlay: Overlay::Lower,
            explicit_uidgid: self.rs.meta.explicit_uidgid(),
            source: PathBuf::from("/"),
            path,
            inode: ondisk_inode,
            chunks,
            symlink,
            xattrs,
        })
    }
}
