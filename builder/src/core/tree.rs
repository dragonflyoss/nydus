// Copyright 2020 Ant Group. All rights reserved.
// Copyright 2023 Alibaba Cloud. All rights reserved.
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

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{bail, Result};
use nydus_rafs::metadata::chunk::ChunkWrapper;
use nydus_rafs::metadata::inode::InodeWrapper;
use nydus_rafs::metadata::layout::{bytes_to_os_str, RafsXAttrs};
use nydus_rafs::metadata::{Inode, RafsInodeExt, RafsSuper};
use nydus_utils::{lazy_drop, root_tracer, timing_tracer};

use super::node::{ChunkSource, Node, NodeChunk, NodeInfo};
use super::overlay::{Overlay, WhiteoutType};
use crate::core::overlay::OVERLAYFS_WHITEOUT_OPAQUE;
use crate::{BuildContext, ChunkDict};

/// Type alias for tree internal node.
pub type TreeNode = Arc<Mutex<Node>>;

/// An in-memory tree structure to maintain information and topology of filesystem nodes.
#[derive(Clone)]
pub struct Tree {
    /// Filesystem node.
    pub node: TreeNode,
    /// Cached base name.
    name: Vec<u8>,
    /// Children tree nodes.
    pub children: Vec<Tree>,
}

impl Tree {
    /// Create a new instance of `Tree` from a filesystem node.
    pub fn new(node: Node) -> Self {
        let name = node.name().as_bytes().to_vec();
        Tree {
            node: Arc::new(Mutex::new(node)),
            name,
            children: Vec::new(),
        }
    }

    /// Load a `Tree` from a bootstrap file, and optionally caches chunk information.
    pub fn from_bootstrap<T: ChunkDict>(rs: &RafsSuper, chunk_dict: &mut T) -> Result<Self> {
        let tree_builder = MetadataTreeBuilder::new(rs);
        let root_ino = rs.superblock.root_ino();
        let root_inode = rs.get_extended_inode(root_ino, true)?;
        let root_node = MetadataTreeBuilder::parse_node(rs, root_inode, PathBuf::from("/"))?;
        let mut tree = Tree::new(root_node);

        tree.children = timing_tracer!(
            { tree_builder.load_children(root_ino, Option::<PathBuf>::None, chunk_dict, true,) },
            "load_tree_from_bootstrap"
        )?;

        Ok(tree)
    }

    /// Get name of the tree node.
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Set `Node` associated with the tree node.
    pub fn set_node(&mut self, node: Node) {
        self.node = Arc::new(Mutex::new(node));
    }

    /// Get mutex guard to access the associated `Node` object.
    pub fn lock_node(&self) -> MutexGuard<Node> {
        self.node.lock().unwrap()
    }

    /// Walk all nodes in DFS mode.
    pub fn walk_dfs<F1, F2>(&self, pre: &mut F1, post: &mut F2) -> Result<()>
    where
        F1: FnMut(&Tree) -> Result<()>,
        F2: FnMut(&Tree) -> Result<()>,
    {
        pre(self)?;
        for child in &self.children {
            child.walk_dfs(pre, post)?;
        }
        post(self)?;

        Ok(())
    }

    /// Walk all nodes in pre DFS mode.
    pub fn walk_dfs_pre<F>(&self, cb: &mut F) -> Result<()>
    where
        F: FnMut(&Tree) -> Result<()>,
    {
        self.walk_dfs(cb, &mut |_t| Ok(()))
    }

    /// Walk all nodes in post DFS mode.
    pub fn walk_dfs_post<F>(&self, cb: &mut F) -> Result<()>
    where
        F: FnMut(&Tree) -> Result<()>,
    {
        self.walk_dfs(&mut |_t| Ok(()), cb)
    }

    /// Walk the tree in BFS mode.
    pub fn walk_bfs<F>(&self, handle_self: bool, cb: &mut F) -> Result<()>
    where
        F: FnMut(&Tree) -> Result<()>,
    {
        if handle_self {
            cb(self)?;
        }

        let mut dirs = Vec::with_capacity(32);
        for child in &self.children {
            cb(child)?;
            if child.lock_node().is_dir() {
                dirs.push(child);
            }
        }
        for dir in dirs {
            dir.walk_bfs(false, cb)?;
        }

        Ok(())
    }

    /// Insert a new child node into the tree.
    pub fn insert_child(&mut self, child: Tree) {
        if let Err(idx) = self
            .children
            .binary_search_by_key(&&child.name, |n| &n.name)
        {
            self.children.insert(idx, child);
        }
    }

    /// Get index of child node with specified `name`.
    pub fn get_child_idx(&self, name: &[u8]) -> Option<usize> {
        self.children.binary_search_by_key(&name, |n| &n.name).ok()
    }

    /// Get the tree node corresponding to the path.
    pub fn get_node(&self, path: &Path) -> Option<&Tree> {
        let target_vec = Node::generate_target_vec(path);
        assert!(!target_vec.is_empty());
        let mut tree = self;
        for name in &target_vec[1..] {
            match tree.get_child_idx(name.as_bytes()) {
                Some(idx) => tree = &tree.children[idx],
                None => return None,
            }
        }
        Some(tree)
    }

    /// Merge the upper layer tree into the lower layer tree, applying whiteout rules.
    pub fn merge_overaly(&mut self, ctx: &BuildContext, upper: Tree) -> Result<()> {
        assert_eq!(self.name, "/".as_bytes());
        assert_eq!(upper.name, "/".as_bytes());

        // Handle the root node.
        upper.lock_node().overlay = Overlay::UpperModification;
        self.node = upper.node.clone();
        self.merge_children(ctx, &upper)?;
        lazy_drop(upper);

        Ok(())
    }

    fn merge_children(&mut self, ctx: &BuildContext, upper: &Tree) -> Result<()> {
        // Handle whiteout nodes in the first round, and handle other nodes in the second round.
        let mut modified = Vec::with_capacity(upper.children.len());
        for u in upper.children.iter() {
            let mut u_node = u.lock_node();
            match u_node.whiteout_type(ctx.whiteout_spec) {
                Some(WhiteoutType::OciRemoval) => {
                    if let Some(origin_name) = u_node.origin_name(WhiteoutType::OciRemoval) {
                        if let Some(idx) = self.get_child_idx(origin_name.as_bytes()) {
                            self.children.remove(idx);
                        }
                    }
                }
                Some(WhiteoutType::OciOpaque) => {
                    self.children.clear();
                }
                Some(WhiteoutType::OverlayFsRemoval) => {
                    if let Some(idx) = self.get_child_idx(&u.name) {
                        self.children.remove(idx);
                    }
                }
                Some(WhiteoutType::OverlayFsOpaque) => {
                    if let Some(idx) = self.get_child_idx(&u.name) {
                        self.children[idx].children.clear();
                    }
                    u_node.remove_xattr(&OsString::from(OVERLAYFS_WHITEOUT_OPAQUE));
                    modified.push(u);
                }
                None => modified.push(u),
            }
        }

        let mut dirs = Vec::new();
        for u in modified {
            let mut u_node = u.lock_node();
            if let Some(idx) = self.get_child_idx(&u.name) {
                u_node.overlay = Overlay::UpperModification;
                self.children[idx].node = u.node.clone();
            } else {
                u_node.overlay = Overlay::UpperAddition;
                self.insert_child(Tree {
                    node: u.node.clone(),
                    name: u.name.clone(),
                    children: vec![],
                });
            }
            if u_node.is_dir() {
                dirs.push(u);
            }
        }
        for dir in dirs {
            if let Some(idx) = self.get_child_idx(&dir.name) {
                self.children[idx].merge_children(ctx, dir)?;
            } else {
                bail!("builder: can not find directory in merged tree");
            }
        }

        Ok(())
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
    fn load_children<T: ChunkDict, P: AsRef<Path>>(
        &self,
        ino: Inode,
        parent: Option<P>,
        chunk_dict: &mut T,
        validate_digest: bool,
    ) -> Result<Vec<Tree>> {
        let inode = self.rs.get_extended_inode(ino, validate_digest)?;
        if !inode.is_dir() {
            return Ok(Vec::new());
        }

        let parent_path = if let Some(parent) = parent {
            parent.as_ref().join(inode.name())
        } else {
            PathBuf::from("/")
        };

        let blobs = self.rs.superblock.get_blob_infos();
        let child_count = inode.get_child_count();
        let mut children = Vec::with_capacity(child_count as usize);
        for idx in 0..child_count {
            let child = inode.get_child_by_index(idx)?;
            let child_path = parent_path.join(child.name());
            let child = Self::parse_node(self.rs, child.clone(), child_path)?;

            if child.is_reg() {
                for chunk in &child.chunks {
                    let blob_idx = chunk.inner.blob_index();
                    if let Some(blob) = blobs.get(blob_idx as usize) {
                        chunk_dict.add_chunk(chunk.inner.clone(), blob.digester());
                    }
                }
            }

            let child = Tree::new(child);
            children.push(child);
        }
        children.sort_unstable_by(|a, b| a.name.cmp(&b.name));

        for child in children.iter_mut() {
            let child_node = child.lock_node();
            if child_node.is_dir() {
                let child_ino = child_node.inode.ino();
                drop(child_node);
                child.children =
                    self.load_children(child_ino, Some(&parent_path), chunk_dict, validate_digest)?;
            }
        }

        Ok(children)
    }

    /// Convert a `RafsInode` object to an in-memory `Node` object.
    pub fn parse_node(rs: &RafsSuper, inode: Arc<dyn RafsInodeExt>, path: PathBuf) -> Result<Node> {
        let chunks = if inode.is_reg() {
            let chunk_count = inode.get_chunk_count();
            let mut chunks = Vec::with_capacity(chunk_count as usize);
            for i in 0..chunk_count {
                let cki = inode.get_chunk_info(i)?;
                chunks.push(NodeChunk {
                    source: ChunkSource::Parent,
                    inner: Arc::new(ChunkWrapper::from_chunk_info(cki)),
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
        let rdev = inode.rdev() as u64;
        let inode = InodeWrapper::from_inode_info(inode.clone());
        let source = PathBuf::from("/");
        let target = Node::generate_target(&path, &source);
        let target_vec = Node::generate_target_vec(&target);
        let info = NodeInfo {
            explicit_uidgid: rs.meta.explicit_uidgid(),
            src_ino: inode.ino(),
            src_dev,
            rdev,
            path,
            source,
            target,
            target_vec,
            symlink,
            xattrs,
            v6_force_extended_inode: false,
        };

        Ok(Node {
            info: Arc::new(info),
            index: 0,
            layer_idx: 0,
            overlay: Overlay::Lower,
            inode,
            chunks,
            v6_offset: 0,
            v6_dirents: Vec::new(),
            v6_datalayout: 0,
            v6_compact_inode: false,
            v6_dirents_offset: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_rafs::metadata::RafsVersion;
    use nydus_storage::RAFS_DEFAULT_CHUNK_SIZE;
    use vmm_sys_util::tempdir::TempDir;
    use vmm_sys_util::tempfile::TempFile;

    #[test]
    fn test_set_lock_node() {
        let tmpdir = TempDir::new().unwrap();
        let tmpfile = TempFile::new_in(tmpdir.as_path()).unwrap();
        let node = Node::from_fs_object(
            RafsVersion::V6,
            tmpdir.as_path().to_path_buf(),
            tmpfile.as_path().to_path_buf(),
            Overlay::UpperAddition,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            true,
            false,
        )
        .unwrap();
        let mut tree = Tree::new(node);
        assert_eq!(tree.name, tmpfile.as_path().file_name().unwrap().as_bytes());
        let node1 = tree.lock_node();
        drop(node1);

        let tmpfile = TempFile::new_in(tmpdir.as_path()).unwrap();
        let node = Node::from_fs_object(
            RafsVersion::V6,
            tmpdir.as_path().to_path_buf(),
            tmpfile.as_path().to_path_buf(),
            Overlay::UpperAddition,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            true,
            false,
        )
        .unwrap();
        tree.set_node(node);
        let node2 = tree.lock_node();
        assert_eq!(node2.name(), tmpfile.as_path().file_name().unwrap());
    }

    #[test]
    fn test_walk_tree() {
        let tmpdir = TempDir::new().unwrap();
        let tmpfile = TempFile::new_in(tmpdir.as_path()).unwrap();
        let node = Node::from_fs_object(
            RafsVersion::V6,
            tmpdir.as_path().to_path_buf(),
            tmpfile.as_path().to_path_buf(),
            Overlay::UpperAddition,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            true,
            false,
        )
        .unwrap();
        let mut tree = Tree::new(node);

        let tmpfile2 = TempFile::new_in(tmpdir.as_path()).unwrap();
        let node = Node::from_fs_object(
            RafsVersion::V6,
            tmpdir.as_path().to_path_buf(),
            tmpfile2.as_path().to_path_buf(),
            Overlay::UpperAddition,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            true,
            false,
        )
        .unwrap();
        let tree2 = Tree::new(node);
        tree.insert_child(tree2);

        let tmpfile3 = TempFile::new_in(tmpdir.as_path()).unwrap();
        let node = Node::from_fs_object(
            RafsVersion::V6,
            tmpdir.as_path().to_path_buf(),
            tmpfile3.as_path().to_path_buf(),
            Overlay::UpperAddition,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            true,
            false,
        )
        .unwrap();
        let tree3 = Tree::new(node);
        tree.insert_child(tree3);

        let mut count = 0;
        tree.walk_bfs(true, &mut |_n| -> Result<()> {
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 3);

        let mut count = 0;
        tree.walk_bfs(false, &mut |_n| -> Result<()> {
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 2);

        let mut count = 0;
        tree.walk_bfs(true, &mut |_n| -> Result<()> {
            count += 1;
            bail!("test")
        })
        .unwrap_err();
        assert_eq!(count, 1);

        let idx = tree
            .get_child_idx(tmpfile2.as_path().file_name().unwrap().as_bytes())
            .unwrap();
        assert!(idx == 0 || idx == 1);
        let idx = tree
            .get_child_idx(tmpfile3.as_path().file_name().unwrap().as_bytes())
            .unwrap();
        assert!(idx == 0 || idx == 1);
    }
}
