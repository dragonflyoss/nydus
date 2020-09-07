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
use std::ffi::OsString;
use std::fs;
use std::fs::DirEntry;
use std::io::Result;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use nydus_utils::einval;
use rafs::metadata::digest::RafsDigest;
use rafs::metadata::layout::*;
use rafs::metadata::{Inode, RafsInode, RafsSuper};

use crate::node::*;
use crate::stargz::{self, TocEntry};

pub type ChunkMap = HashMap<PathBuf, Vec<OndiskChunkInfo>>;

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
        digest_validate: bool,
    ) -> Result<Vec<Tree>> {
        let inode = self.rs.get_inode(ino, digest_validate)?;
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
                let child = self.rs.get_inode(idx as Inode, digest_validate)?;
                let child_path = parent_path.join(child.name()?);
                let child = self.parse_node(child, child_path.clone())?;
                let mut child = Tree::new(child);
                child.children =
                    self.load_children(idx as Inode, Some(&parent_path), digest_validate)?;
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

struct StargzIndexTreeBuilder {
    stargz_index_path: PathBuf,
    path_inode_map: HashMap<PathBuf, Inode>,
}

impl StargzIndexTreeBuilder {
    fn new(stargz_index_path: PathBuf) -> Self {
        Self {
            stargz_index_path,
            path_inode_map: HashMap::new(),
        }
    }

    fn make_lost_dirs(&mut self, entry: &TocEntry, dirs: &mut Vec<TocEntry>) {
        if let Some(parent_path) = entry.path().parent() {
            let parent_path = parent_path.to_path_buf();
            if self.path_inode_map.get(&parent_path).is_none() {
                let dir_entry = TocEntry::new_dir(parent_path);
                self.make_lost_dirs(&dir_entry, dirs);
                dirs.push(dir_entry);
            }
        }
    }

    fn build(&mut self) -> Result<(Tree, ChunkMap)> {
        let toc_index = stargz::parse_index(&self.stargz_index_path)?;

        if toc_index.entries.is_empty() {
            return Err(einval!("the stargz index has no toc entry"));
        }

        let root_entry = TocEntry::new_dir(PathBuf::from("/"));
        let root_node = self.parse_node(&root_entry)?;
        let mut tree = Tree::new(root_node);

        let mut chunk_map: ChunkMap = HashMap::new();

        for entry in toc_index.entries.iter() {
            if !entry.is_supported() {
                continue;
            }
            let decompress_size = if entry.chunk_size == 0 {
                entry.size as u32
            } else {
                entry.chunk_size as u32
            };
            if (entry.is_reg() || entry.is_chunk()) && decompress_size != 0 {
                let chunk = OndiskChunkInfo {
                    block_id: RafsDigest::default(),
                    blob_index: 0,
                    flags: RafsChunkFlags::COMPRESSED,
                    // No available data on entry
                    compress_size: 0,
                    decompress_size,
                    compress_offset: entry.offset as u64,
                    // No available data on entry
                    decompress_offset: 0,
                    file_offset: entry.chunk_offset as u64,
                    reserved: 0u64,
                };
                let path = entry.path();
                if let Some(chunks) = chunk_map.get_mut(&path) {
                    chunks.push(chunk);
                } else {
                    chunk_map.insert(path, vec![chunk]);
                }
            }
            if entry.is_chunk() {
                continue;
            }

            let mut lost_dirs = Vec::new();
            self.make_lost_dirs(&entry, &mut lost_dirs);
            for dir in &lost_dirs {
                let node = self.parse_node(dir)?;
                tree.apply(&node, false)?;
            }

            let node = self.parse_node(entry)?;
            tree.apply(&node, false)?;
        }

        Ok((tree, chunk_map))
    }

    /// Parse stargz toc entry to Node in builder
    fn parse_node(&mut self, entry: &TocEntry) -> Result<Node> {
        let mut flags = RafsInodeFlags::default();

        // Parse chunks info
        let chunks = Vec::new();

        let link_path = entry.link_path();

        // Parse symlink
        let mut file_size = entry.size;
        let mut symlink_size = 0;
        let symlink = if entry.is_symlink() {
            flags |= RafsInodeFlags::SYMLINK;
            symlink_size = link_path.as_os_str().as_bytes().len() as u16;
            file_size = symlink_size.into();
            Some(link_path.as_os_str().to_owned())
        } else {
            None
        };

        // TOTO: parse xattrs
        let xattrs = XAttrs {
            pairs: HashMap::new(),
        };
        if entry.has_xattr() {
            flags |= RafsInodeFlags::XATTR;
        }

        if entry.is_hardlink() {
            flags |= RafsInodeFlags::HARDLINK;
        }

        let name_size = entry.name()?.as_os_str().as_bytes().len() as u16;

        let mut ino = (self.path_inode_map.len() + 1) as Inode;
        if entry.is_hardlink() {
            if let Some(_ino) = self.path_inode_map.get(&entry.link_path()) {
                ino = *_ino;
            } else {
                self.path_inode_map.insert(entry.path(), ino);
            }
        } else {
            self.path_inode_map.insert(entry.path(), ino);
        }

        // Parse inode info
        let inode = OndiskInode {
            i_digest: RafsDigest::default(),
            i_parent: 0,
            i_ino: ino,
            i_projid: 0,
            i_uid: entry.uid,
            i_gid: entry.gid,
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

        // TODO: dev number
        Ok(Node {
            index: 0,
            real_ino: ino,
            dev: u64::MAX,
            overlay: Overlay::UpperAddition,
            explicit_uidgid: false,
            source: PathBuf::from_str("/").unwrap(),
            path: entry.path(),
            inode,
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
    fn load_children(&self, parent: &mut Node) -> Result<Vec<Tree>> {
        let mut result = Vec::new();

        if !parent.is_dir() {
            return Ok(result);
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
            child_tree.children = self.load_children(&mut child_tree.node)?;
            result.push(child_tree);
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
    pub fn from_stargz_index(stargz_index_path: &PathBuf) -> Result<(Self, ChunkMap)> {
        let mut tree_builder = StargzIndexTreeBuilder::new(stargz_index_path.clone());
        tree_builder.build()
    }

    /// Build node tree from a bootstrap file
    pub fn from_bootstrap(rs: &RafsSuper, digest_validate: bool) -> Result<Self> {
        let tree_builder = MetadataTreeBuilder::new(&rs);

        let root_inode = rs.get_inode(RAFS_ROOT_INODE, digest_validate)?;
        let root_node = tree_builder.parse_node(root_inode, PathBuf::from_str("/").unwrap())?;
        let mut tree = Tree::new(root_node);

        tree.children = tree_builder.load_children(RAFS_ROOT_INODE, None, digest_validate)?;

        Ok(tree)
    }

    /// Build node tree from a filesystem directory
    pub fn from_filesystem(root_path: &PathBuf, explicit_uidgid: bool) -> Result<Self> {
        let tree_builder = FilesystemTreeBuilder::new(root_path.clone());

        let node = Node::new(
            root_path.clone(),
            root_path.clone(),
            Overlay::UpperAddition,
            explicit_uidgid,
        )?;
        let mut tree = Tree::new(node);

        tree.children = tree_builder.load_children(&mut tree.node)?;

        Ok(tree)
    }

    /// Apply new node (upper layer) to node tree (lower layer),
    /// support overlay defined in OCI image layer spec (https://github.com/opencontainers/image-spec/blob/master/layer.md),
    /// include change types Additions, Modifications, Removals and Opaques
    pub fn apply(&mut self, target: &Node, handle_whiteout: bool) -> Result<Overlay> {
        // Handle whiteout file
        if handle_whiteout && target.whiteout_type().is_some() {
            return self.remove(target);
        }

        let target_paths = target.path_vec();
        let target_paths_len = target_paths.len();
        let depth = self.node.path_vec().len();

        // Handle root node modification
        if target.path == PathBuf::from("/") {
            let mut node = target.clone();
            node.overlay = Overlay::UpperModification;
            self.node = node;
            return Ok(Overlay::UpperModification);
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
                    return Ok(Overlay::UpperModification);
                }
                if child.node.is_dir() {
                    // Search the node recursively
                    let overlay = child.apply(target, handle_whiteout)?;
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
    fn remove(&mut self, target: &Node) -> Result<Overlay> {
        let target_paths = target.path_vec();
        let target_paths_len = target_paths.len();
        let depth = self.node.path_vec().len();
        let whiteout_type = target.whiteout_type();

        // Opaques for root(/) path
        if whiteout_type == Some(WhiteoutType::Opaque)
            && depth == target_paths_len
            && target_paths[depth - 1] == self.node.name()
        {
            self.node.overlay = Overlay::UpperOpaque;
            self.children.clear();
            return Ok(Overlay::UpperOpaque);
        }

        let mut origin_name = target.name().to_os_string();
        if whiteout_type == Some(WhiteoutType::Removal) {
            if let Some(_origin_name) = origin_name.to_str() {
                origin_name = OsString::from(&_origin_name[OCISPEC_WHITEOUT_PREFIX.len()..]);
            }
        }

        let mut parent_name = None;
        if let Some(parent_path) = target.path.parent() {
            if let Some(file_name) = parent_path.file_name() {
                parent_name = Some(file_name);
            }
        }

        // Don't search if path recursive depth out of target path
        if depth < target_paths_len {
            let current_name = target_paths[depth].clone();
            // TODO: Search child by binary search
            for idx in 0..self.children.len() {
                let child = &mut self.children[idx];

                // Skip if path component name not match
                if current_name != child.node.name() && whiteout_type.is_none() {
                    continue;
                }

                // Handle Removals
                if depth == target_paths_len - 1
                    && whiteout_type == Some(WhiteoutType::Removal)
                    && origin_name == child.node.name()
                {
                    // Remove the whole lower node
                    self.children.remove(idx);
                    return Ok(Overlay::UpperRemoval);
                }

                // Handle Opaques
                if target_paths_len >= 2
                    && depth == target_paths_len - 2
                    && whiteout_type == Some(WhiteoutType::Opaque)
                {
                    if let Some(parent_name) = parent_name {
                        if parent_name == child.node.name() {
                            child.node.overlay = Overlay::UpperOpaque;
                            // Remove children of the lower node
                            child.children.clear();
                            return Ok(Overlay::UpperOpaque);
                        }
                    }
                }

                if child.node.is_dir() {
                    // Search the node recursively
                    let overlay = child.remove(target)?;
                    if overlay != Overlay::Lower {
                        return Ok(overlay);
                    }
                }
            }
        }

        Ok(Overlay::Lower)
    }
}
