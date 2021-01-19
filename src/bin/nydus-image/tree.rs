// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! File node tree for RAFS format
//!
//! Build a node tree from filesystem directory named FilesystemTree.
//! Build a node tree from metadata file named MetadataTree.
//! Layered build steps:
//! 1. Apply FilesystemTree (from upper layer) to MetadataTree (from lower layer) as overlay node tree;
//! 2. Traverse overlay node tree then dump to bootstrap and blob file according to RAFS format.

use anyhow::{anyhow, bail, Context, Result};

use rafs::metadata::digest::RafsDigest;
use std::collections::HashMap;
use std::fs;
use std::fs::DirEntry;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use rafs::metadata::layout::*;
use rafs::metadata::{Inode, RafsInode, RafsSuper};

use crate::node::*;
use crate::stargz::{self, TocEntry};

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
    fn load_children(
        &self,
        ino: Inode,
        parent: Option<&PathBuf>,
        chunk_cache: &mut Option<&mut HashMap<RafsDigest, OndiskChunkInfo>>,
    ) -> Result<Vec<Tree>> {
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
                if let Some(chunk_cache) = chunk_cache {
                    if child.is_reg() {
                        for chunk in &child.chunks {
                            chunk_cache.insert(chunk.block_id, *chunk);
                        }
                    }
                }
                let mut child = Tree::new(child);
                child.children =
                    self.load_children(idx as Inode, Some(&parent_path), chunk_cache)?;
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
        let mut xattrs = XAttrs::new();
        for name in inode.get_xattrs()? {
            let name = bytes_to_os_str(&name);
            let value = inode.get_xattr(name)?;
            xattrs.add(name.to_os_string(), value.unwrap_or_else(Vec::new));
        }

        // Get OndiskInode
        let ondisk_inode = inode.cast_ondisk()?;

        // Inodes from parent bootstrap can't have nodes with unique inode number.
        // So we assign an invalid dev here.
        Ok(Node {
            index: 0,
            real_ino: ondisk_inode.i_ino,
            dev: u64::MAX,
            rdev: u64::MAX,
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

struct StargzIndexTreeBuilder {
    stargz_index_path: PathBuf,
    path_inode_map: HashMap<PathBuf, Inode>,
    blob_id: String,
}

impl StargzIndexTreeBuilder {
    fn new(stargz_index_path: PathBuf, blob_id: &str) -> Self {
        Self {
            stargz_index_path,
            path_inode_map: HashMap::new(),
            blob_id: blob_id.to_owned(),
        }
    }

    // Create middle directory nodes which is not in entry list,
    // for example `/a/b/c`, we need to create `/a`, `/a/b` nodes first.
    fn make_lost_dirs(&mut self, entry: &TocEntry, dirs: &mut Vec<TocEntry>) -> Result<()> {
        if let Some(parent_path) = entry.path()?.parent() {
            let parent_path = parent_path.to_path_buf();
            if self.path_inode_map.get(&parent_path).is_none() {
                let dir_entry = TocEntry::new_dir(parent_path);
                self.make_lost_dirs(&dir_entry, dirs)?;
                dirs.push(dir_entry);
            }
        }
        Ok(())
    }

    fn build(&mut self, explicit_uidgid: bool, whiteout_spec: &WhiteoutSpec) -> Result<Tree> {
        // Parse stargz TOC index from a file
        let toc_index = stargz::parse_index(&self.stargz_index_path)?;

        if toc_index.entries.is_empty() {
            bail!("the stargz index has no toc entry");
        }

        let mut tree: Option<Tree> = None;

        // Map hardlink path to linked path: HashMap<<hardlink_path>, <linked_path>>
        let mut hardlink_map: HashMap<PathBuf, PathBuf> = HashMap::new();

        // Map regular file path to chunks: HashMap<<file_path>, <(file_size, chunks)>>
        let mut file_chunk_map: HashMap<PathBuf, (u64, Vec<OndiskChunkInfo>)> = HashMap::new();
        let mut nodes = Vec::new();

        let mut last_reg_entry: Option<&TocEntry> = None;
        for entry in toc_index.entries.iter() {
            if !entry.is_supported() {
                continue;
            }

            // Figure out decompress_size for the last chunk entry of regular file
            let mut decompress_size = entry.chunk_size;
            if entry.is_chunk() && entry.chunk_size == 0 {
                if let Some(reg_entry) = last_reg_entry {
                    decompress_size = reg_entry.size - entry.chunk_offset;
                }
            }
            // Figure out decompress_size for regular file entry
            if entry.chunk_size == 0 && entry.size != 0 {
                decompress_size = entry.size;
            }

            if (entry.is_reg() || entry.is_chunk()) && decompress_size != 0 {
                let block_id = entry.block_id(&self.blob_id)?;
                let chunk = OndiskChunkInfo {
                    block_id,
                    // Will be set later
                    blob_index: 0,
                    flags: RafsChunkFlags::COMPRESSED,
                    // No available data on entry
                    compress_size: 0,
                    decompress_size: decompress_size as u32,
                    compress_offset: entry.offset as u64,
                    // No available data on entry
                    decompress_offset: 0,
                    file_offset: entry.chunk_offset as u64,
                    reserved: 0u64,
                };
                if let Some((size, chunks)) = file_chunk_map.get_mut(&entry.path()?) {
                    chunks.push(chunk);
                    if entry.is_reg() {
                        *size = entry.size;
                    }
                } else {
                    let size = if entry.is_reg() { entry.size } else { 0 };
                    file_chunk_map.insert(entry.path()?, (size, vec![chunk]));
                }
            }
            if entry.is_reg() {
                last_reg_entry = Some(&entry);
            }
            if entry.is_chunk() {
                continue;
            }

            let mut lost_dirs = Vec::new();
            self.make_lost_dirs(&entry, &mut lost_dirs)?;
            for dir in &lost_dirs {
                let node = self.parse_node(dir, explicit_uidgid)?;
                nodes.push(node);
            }

            if entry.is_hardlink() {
                hardlink_map.insert(entry.path()?, entry.hardlink_link_path());
            }

            let node = self.parse_node(entry, explicit_uidgid)?;
            if entry.path()? == PathBuf::from("/") {
                tree = Some(Tree::new(node.clone()));
            }
            nodes.push(node);
        }

        // Set chunks and i_size to nodes
        for node in &mut nodes {
            let link_path = hardlink_map.get(&node.path).unwrap_or(&node.path);
            if let Some((size, chunks)) = file_chunk_map.get(link_path) {
                node.chunks = chunks.clone();
                node.inode.i_child_count = node.chunks.len() as u32;
                node.inode.i_size = *size;
            }
            if let Some(tree) = &mut tree {
                tree.apply(node, false, whiteout_spec)?;
            }
        }

        tree.ok_or_else(|| anyhow!("the stargz index has no root toc entry"))
    }

    /// Parse stargz toc entry to Node in builder
    fn parse_node(&mut self, entry: &TocEntry, explicit_uidgid: bool) -> Result<Node> {
        let chunks = Vec::new();
        let entry_path = entry.path()?;
        let symlink_link_path = entry.symlink_link_path();

        let mut flags = RafsInodeFlags::default();

        // Parse symlink
        let mut file_size = entry.size;
        let mut symlink_size = 0;
        let symlink = if entry.is_symlink() {
            flags |= RafsInodeFlags::SYMLINK;
            symlink_size = symlink_link_path.as_os_str().as_bytes().len() as u16;
            file_size = symlink_size.into();
            Some(symlink_link_path.as_os_str().to_owned())
        } else {
            None
        };

        // Parse xattrs
        let mut xattrs = XAttrs::new();
        if entry.has_xattr() {
            for (name, value) in entry.xattrs.iter() {
                flags |= RafsInodeFlags::XATTR;
                let value = base64::decode(value).with_context(|| {
                    format!(
                        "parse xattr name {:?} of file {:?} failed",
                        entry_path, name,
                    )
                })?;
                xattrs.add(name.into(), value);
            }
        }

        // Handle hardlink ino
        let mut ino = (self.path_inode_map.len() + 1) as Inode;
        if entry.is_hardlink() {
            flags |= RafsInodeFlags::HARDLINK;
            if let Some(_ino) = self.path_inode_map.get(&entry.hardlink_link_path()) {
                ino = *_ino;
            } else {
                self.path_inode_map.insert(entry.path()?, ino);
            }
        } else {
            self.path_inode_map.insert(entry.path()?, ino);
        }

        // Get file name size
        let name_size = entry.name()?.as_os_str().as_bytes().len() as u16;

        let uid = if explicit_uidgid { entry.uid } else { 0 };
        let gid = if explicit_uidgid { entry.gid } else { 0 };

        // Parse inode info
        let inode = OndiskInode {
            i_digest: RafsDigest::default(),
            i_parent: 0,
            i_ino: ino,
            i_projid: 0,
            i_uid: uid,
            i_gid: gid,
            i_mode: entry.mode(),
            i_size: file_size,
            i_nlink: entry.num_link,
            i_blocks: 0,
            i_flags: flags,
            i_child_index: 0,
            i_child_count: 0,
            i_name_size: name_size,
            i_symlink_size: symlink_size,
            i_reserved: [0; 24],
        };

        Ok(Node {
            index: 0,
            real_ino: ino,
            dev: u64::MAX,
            rdev: u64::MAX,
            overlay: Overlay::UpperAddition,
            explicit_uidgid,
            source: PathBuf::from_str("/").unwrap(),
            path: entry.path()?,
            inode,
            chunks,
            symlink,
            xattrs,
        })
    }
}

struct FilesystemTreeBuilder {
    root_path: PathBuf,
    layered: bool,
}

impl FilesystemTreeBuilder {
    fn new(root_path: PathBuf, layered: bool) -> Self {
        Self { root_path, layered }
    }

    /// Walk directory to build node tree by DFS,
    fn load_children(&self, parent: &mut Node, whiteout_spec: &WhiteoutSpec) -> Result<Vec<Tree>> {
        let mut result = Vec::new();

        if !parent.is_dir() {
            return Ok(result);
        }

        let children = fs::read_dir(&parent.path)
            .with_context(|| format!("failed to read dir {:?}", parent.path))?;
        let children = children.collect::<Result<Vec<DirEntry>, std::io::Error>>()?;

        for child in children {
            let path = child.path();

            let child = Node::new(
                self.root_path.clone(),
                path.clone(),
                Overlay::UpperAddition,
                parent.explicit_uidgid,
            )
            .with_context(|| format!("failed to create node {:?}", path))?;

            // Per as to OCI spec, whiteout file should not be present within final image
            // or filesystem, only existed in layers.
            if child.whiteout_type(whiteout_spec).is_some()
                && !child.is_overlayfs_opaque(whiteout_spec)
                && !self.layered
            {
                continue;
            }

            // Ignore special file, except overlayfs whiteout file
            // which is a char device with major:minor(0:0).
            if child.file_type() == "" && !child.is_overlayfs_whiteout(whiteout_spec) {
                continue;
            }

            let mut child = Tree::new(child);
            child.children = self.load_children(&mut child.node, whiteout_spec)?;
            result.push(child);
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

    /// Build node tree from stargz index json file
    pub fn from_stargz_index(
        stargz_index_path: &PathBuf,
        blob_id: &str,
        explicit_uidgid: bool,
        whiteout_spec: &WhiteoutSpec,
    ) -> Result<Self> {
        let mut tree_builder = StargzIndexTreeBuilder::new(stargz_index_path.clone(), blob_id);
        tree_builder.build(explicit_uidgid, whiteout_spec)
    }

    /// Build node tree from a bootstrap file
    pub fn from_bootstrap(
        rs: &RafsSuper,
        mut chunk_cache: Option<&mut HashMap<RafsDigest, OndiskChunkInfo>>,
    ) -> Result<Self> {
        let tree_builder = MetadataTreeBuilder::new(&rs);

        let root_inode = rs.get_inode(RAFS_ROOT_INODE, true)?;
        let root_node = tree_builder.parse_node(root_inode, PathBuf::from_str("/").unwrap())?;
        let mut tree = Tree::new(root_node);

        tree.children = tree_builder.load_children(RAFS_ROOT_INODE, None, &mut chunk_cache)?;

        Ok(tree)
    }

    /// Build node tree from a filesystem directory
    pub fn from_filesystem(
        root_path: &PathBuf,
        explicit_uidgid: bool,
        layered: bool,
        whiteout_spec: &WhiteoutSpec,
    ) -> Result<Self> {
        let tree_builder = FilesystemTreeBuilder::new(root_path.clone(), layered);

        let node = Node::new(
            root_path.clone(),
            root_path.clone(),
            Overlay::UpperAddition,
            explicit_uidgid,
        )?;
        let mut tree = Tree::new(node);

        tree.children = tree_builder.load_children(&mut tree.node, whiteout_spec)?;

        Ok(tree)
    }

    /// Apply new node (upper layer) to node tree (lower layer),
    /// support overlay defined in OCI image layer spec (https://github.com/opencontainers/image-spec/blob/master/layer.md),
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
                if whiteout_type == WhiteoutType::OverlayFSOpaque {
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
            && (whiteout_type == WhiteoutType::OCIOpaque && target_paths_len == 2
                || whiteout_type == WhiteoutType::OverlayFSOpaque && target_paths_len == 1)
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
        let origin_name = target.origin_name(&whiteout_type);

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
            if whiteout_type == WhiteoutType::OCIOpaque
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
            } else if whiteout_type == WhiteoutType::OverlayFSOpaque
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
