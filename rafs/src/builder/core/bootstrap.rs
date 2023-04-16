// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::ffi::OsString;

use anyhow::{Context, Error, Result};
use nydus_utils::digest::{self, RafsDigest};
use nydus_utils::{root_tracer, timing_tracer};

use super::node::Node;
use super::overlay::{WhiteoutType, OVERLAYFS_WHITEOUT_OPAQUE};
use crate::builder::{
    ArtifactStorage, BlobManager, BootstrapContext, BootstrapManager, BuildContext, Tree,
};
use crate::metadata::layout::{RafsBlobTable, RAFS_V5_ROOT_INODE};
use crate::metadata::{RafsSuper, RafsSuperConfig, RafsSuperFlags};

pub(crate) const STARGZ_DEFAULT_BLOCK_SIZE: u32 = 4 << 20;

/// RAFS bootstrap/meta blob builder.
pub struct Bootstrap {}

impl Bootstrap {
    /// Create a new instance of [Bootstrap].
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }

    /// Generate inode array with all information, such as ino, child index/count etc, filled.
    ///
    /// The generated inode array is stored in `bootstrap_ctx.nodes`.
    ///
    /// When used to prepare diff operations for merging, the `tree` object is built from the upper
    /// layer, which will be merged with the lower layer by `apply()` to form the final filesystem
    /// view. So the upper layer `tree` is converted into an array of diff-apply operations.
    /// The diff operation arrays contains two parts:
    /// - files/directories to be removed from the lower layer, at the head of the array. The order
    ///   of removal operations are bottom-up, that means child files/directories is in front of its
    ///   parent.
    /// - files/directories to added/modified into the lower layer, at the tail of the array.
    ///   The order of addition/modification operations are top-down, that means directories is
    ///   ahead its children.
    ///
    /// It may also be used to generate the final inode array for an RAFS filesystem.
    pub fn build(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        mut tree: Tree,
    ) -> Result<()> {
        // used to compute nid(ino) for v6
        let root_offset = bootstrap_ctx.offset;
        let mut nodes = VecDeque::with_capacity(0x10000);

        // Special handling of the root inode
        assert!(tree.node.is_dir());
        // 0 is reserved and 1 also matches RAFS_V5_ROOT_INODE.
        tree.node.index = 1;
        // Rafs v6 root inode number can't be decided until the end of dumping.
        if ctx.fs_version.is_v5() {
            tree.node.inode.set_ino(RAFS_V5_ROOT_INODE);
        }
        ctx.prefetch.insert_if_need(&tree.node);
        nodes.push_back(tree.node.clone());

        Self::build_rafs(ctx, bootstrap_ctx, &mut tree, &mut nodes)?;
        if ctx.fs_version.is_v6() && !bootstrap_ctx.layered {
            // generate on-disk metadata layout for v6
            Self::v6_update_dirents(&mut nodes, &tree, root_offset);
        }
        bootstrap_ctx.nodes = nodes;

        Ok(())
    }

    /// Apply diff operations to the base tree (lower layer) and return the merged `Tree` object.
    ///
    /// If `tree` is none, the base tree will be loaded from the parent bootstrap.
    pub fn apply(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        bootstrap_mgr: &mut BootstrapManager,
        blob_mgr: &mut BlobManager,
        tree: Option<Tree>,
    ) -> Result<Tree> {
        let mut tree = match tree {
            Some(v) => v,
            None => self.load_parent_bootstrap(ctx, bootstrap_mgr, blob_mgr)?,
        };

        // Apply new node (upper layer) to node tree (lower layer)
        timing_tracer!(
            {
                for node in &bootstrap_ctx.nodes {
                    tree.apply(node, true, ctx.whiteout_spec)
                        .context("failed to apply tree")?;
                }
                Ok(true)
            },
            "apply_tree",
            Result<bool>
        )?;

        // Clear all cached states for next upper layer build.
        bootstrap_ctx.inode_map.clear();
        bootstrap_ctx.nodes.clear();
        bootstrap_ctx
            .v6_available_blocks
            .iter_mut()
            .for_each(|v| v.clear());
        ctx.prefetch.clear();

        Ok(tree)
    }

    /// Dump the RAFS filesystem meta information to meta blob.
    pub fn dump(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_storage: &mut Option<ArtifactStorage>,
        bootstrap_ctx: &mut BootstrapContext,
        blob_table: &RafsBlobTable,
    ) -> Result<()> {
        match blob_table {
            RafsBlobTable::V5(table) => self.v5_dump(ctx, bootstrap_ctx, table)?,
            RafsBlobTable::V6(table) => self.v6_dump(ctx, bootstrap_ctx, table)?,
        }

        if let Some(ArtifactStorage::FileDir(p)) = bootstrap_storage {
            let bootstrap_data = bootstrap_ctx.writer.as_bytes()?;
            let digest = RafsDigest::from_buf(&bootstrap_data, digest::Algorithm::Sha256);
            let name = digest.to_string();
            bootstrap_ctx.writer.finalize(Some(name.clone()))?;
            *bootstrap_storage = Some(ArtifactStorage::SingleFile(p.join(name)));
            Ok(())
        } else {
            bootstrap_ctx.writer.finalize(Some(String::default()))
        }
    }

    /// Traverse node tree, set inode index, ino, child_index and child_count etc according to the
    /// RAFS metadata format, then store to nodes collection.
    fn build_rafs(
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        tree: &mut Tree,
        nodes: &mut VecDeque<Node>,
    ) -> Result<()> {
        let index = nodes.len() as u32 + 1;
        let parent = &mut nodes[tree.node.index as usize - 1];
        let parent_ino = parent.inode.ino();
        let block_size = ctx.v6_block_size();

        // Maybe the parent is not a directory in multi-layers build scenario, so we check here.
        if parent.is_dir() {
            // Sort children list by name, so that we can improve performance in fs read_dir using
            // binary search.
            tree.children
                .sort_by_key(|child| child.node.name().to_os_string());
            parent.inode.set_child_count(tree.children.len() as u32);
            if ctx.fs_version.is_v5() {
                parent.inode.set_child_index(index);
            } else if ctx.fs_version.is_v6() {
                let d_size = tree.node.v6_dirent_size(ctx, tree)?;
                parent.v6_set_dir_offset(bootstrap_ctx, d_size, block_size)?;
            }
        }

        if ctx.fs_version.is_v6() {
            tree.node.v6_offset = parent.v6_offset;
        }

        // Cache dir tree for BFS walk
        let mut dirs: Vec<&mut Tree> = Vec::new();
        for child in tree.children.iter_mut() {
            let index = nodes.len() as u64 + 1;
            child.node.index = index;
            if ctx.fs_version.is_v5() {
                child.node.inode.set_parent(parent_ino);
            }

            // Handle hardlink.
            // All hardlink nodes' ino and nlink should be the same.
            // We need to find hardlink node index list in the layer where the node is located
            // because the real_ino may be different among different layers,
            let mut v6_hardlink_offset: Option<u64> = None;
            if let Some(indexes) = bootstrap_ctx.inode_map.get_mut(&(
                child.node.layer_idx,
                child.node.info.src_ino,
                child.node.info.src_dev,
            )) {
                let nlink = indexes.len() as u32 + 1;
                let first_index = indexes[0];
                child.node.inode.set_ino(first_index);
                child.node.inode.set_nlink(nlink);
                // Update nlink for previous hardlink inodes
                for idx in indexes.iter() {
                    nodes[*idx as usize - 1].inode.set_nlink(nlink);
                }
                indexes.push(index);
                // set offset for rafs v6 hardlinks
                v6_hardlink_offset = Some(nodes[first_index as usize - 1].v6_offset);
            } else {
                child.node.inode.set_ino(index);
                child.node.inode.set_nlink(1);
                // Store inode real ino
                bootstrap_ctx.inode_map.insert(
                    (
                        child.node.layer_idx,
                        child.node.info.src_ino,
                        child.node.info.src_dev,
                    ),
                    vec![child.node.index],
                );
            }

            // update bootstrap_ctx.offset for rafs v6.
            if !child.node.is_dir() && ctx.fs_version.is_v6() {
                child
                    .node
                    .v6_set_offset(bootstrap_ctx, v6_hardlink_offset, block_size)?;
            }

            // Store node for bootstrap & blob dump.
            // Put the whiteout file of upper layer in the front of node list for layered build,
            // so that it can be applied to the node tree of lower layer first than other files of upper layer.
            match (
                bootstrap_ctx.layered,
                child.node.whiteout_type(ctx.whiteout_spec),
            ) {
                (true, Some(whiteout_type)) => {
                    // Insert removal operations at the head, so they will be handled first when
                    // applying to lower layer.
                    nodes.push_front(child.node.clone());
                    if whiteout_type == WhiteoutType::OverlayFsOpaque {
                        // For the overlayfs opaque, we need to remove the lower node that has the
                        // same name first, then apply upper node to the node tree of lower layer.
                        child
                            .node
                            .remove_xattr(&OsString::from(OVERLAYFS_WHITEOUT_OPAQUE));
                        nodes.push_back(child.node.clone());
                    }
                }
                (false, Some(whiteout_type)) => {
                    // Remove overlayfs opaque xattr for single layer build
                    if whiteout_type == WhiteoutType::OverlayFsOpaque {
                        child
                            .node
                            .remove_xattr(&OsString::from(OVERLAYFS_WHITEOUT_OPAQUE));
                    }
                    nodes.push_back(child.node.clone());
                }
                _ => nodes.push_back(child.node.clone()),
            }

            ctx.prefetch.insert_if_need(&child.node);

            if child.node.is_dir() {
                dirs.push(child);
            }
        }

        // According to filesystem semantics, a parent dir should have nlink equal to
        // 2 plus the number of its child directory. And in case of layered build,
        // updating parent directory's nlink here is reliable since builder re-constructs
        // the entire tree and intends to layout all inodes into a plain array fetching
        // from the previously applied tree.
        let parent = &mut nodes[tree.node.index as usize - 1];
        if parent.is_dir() {
            parent.inode.set_nlink((2 + dirs.len()) as u32);
        }
        for dir in dirs {
            Self::build_rafs(ctx, bootstrap_ctx, dir, nodes)?;
        }

        Ok(())
    }

    fn load_parent_bootstrap(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_mgr: &mut BootstrapManager,
        blob_mgr: &mut BlobManager,
    ) -> Result<Tree> {
        let rs = if let Some(path) = bootstrap_mgr.f_parent_path.as_ref() {
            RafsSuper::load_from_file(path, ctx.configuration.clone(), false).map(|(rs, _)| rs)?
        } else {
            return Err(Error::msg("bootstrap context's parent bootstrap is null"));
        };

        let config = RafsSuperConfig {
            compressor: ctx.compressor,
            digester: ctx.digester,
            chunk_size: ctx.chunk_size,
            batch_size: ctx.batch_size,
            explicit_uidgid: ctx.explicit_uidgid,
            version: ctx.fs_version,
            is_tarfs_mode: rs.meta.flags.contains(RafsSuperFlags::TARTFS_MODE),
        };
        config.check_compatibility(&rs.meta)?;

        // Reuse lower layer blob table,
        // we need to append the blob entry of upper layer to the table
        blob_mgr.extend_from_blob_table(ctx, rs.superblock.get_blob_infos())?;

        // Build node tree of lower layer from a bootstrap file, and add chunks
        // of lower node to layered_chunk_dict for chunk deduplication on next.
        let tree = Tree::from_bootstrap(&rs, &mut blob_mgr.layered_chunk_dict)
            .context("failed to build tree from bootstrap")?;

        Ok(tree)
    }
}
