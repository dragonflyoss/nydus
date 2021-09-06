// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::convert::TryFrom;
use std::ffi::OsString;
use std::mem::size_of;

use anyhow::{Context, Result};

use nydus_utils::digest::{DigestHasher, RafsDigest};
use rafs::metadata::layout::v5::{
    RafsV5ChunkInfo, RafsV5InodeTable, RafsV5SuperBlock, RafsV5XAttrsTable,
};
use rafs::metadata::layout::RAFS_ROOT_INODE;
use rafs::metadata::{RafsMode, RafsStore, RafsSuper};

use crate::core::context::{BlobManager, BootstrapContext, BuildContext, SourceType};
use crate::core::node::*;
use crate::core::prefetch::PrefetchPolicy;
use crate::core::tree::Tree;

pub const STARGZ_DEFAULT_BLOCK_SIZE: u32 = 4 << 20;

pub struct Bootstrap {}

impl Bootstrap {
    /// Create a new instance of `BootStrap`.
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }

    /// Traverse node tree, set inode index, ino, child_index and
    /// child_count etc according to RAFS format, then store to nodes collection.
    fn build_rafs(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        tree: &mut Tree,
        nodes: &mut Vec<Node>,
    ) {
        // FIX: Insert parent inode to inode map to keep correct inodes count in superblock.
        let inode_map = if tree.node.overlay.is_lower_layer() {
            &mut bootstrap_ctx.lower_inode_map
        } else {
            &mut bootstrap_ctx.upper_inode_map
        };
        inode_map.insert((tree.node.real_ino, tree.node.dev), vec![tree.node.index]);

        let index = nodes.len() as u32 + 1;
        let parent = &mut nodes[tree.node.index as usize - 1];
        if parent.is_dir() {
            parent.inode.i_child_index = index;
            parent.inode.i_child_count = tree.children.len() as u32;

            // Sort children list by name, so that we can improve performance in fs read_dir using
            // binary search.
            tree.children
                .sort_by_key(|child| child.node.name().to_os_string());
        }

        // Cache dir tree for BFS walk
        let mut dirs: Vec<&mut Tree> = Vec::new();
        let parent_ino = parent.inode.i_ino;

        for child in tree.children.iter_mut() {
            let index = nodes.len() as u64 + 1;
            child.node.index = index;
            child.node.inode.i_parent = parent_ino;

            // Hardlink handle, all hardlink nodes' ino, nlink should be the same,
            // because the real_ino may be conflicted between different layers,
            // so we need to find hardlink node index list in the layer where the node is located.
            let inode_map = if child.node.overlay.is_lower_layer() {
                &mut bootstrap_ctx.lower_inode_map
            } else {
                &mut bootstrap_ctx.upper_inode_map
            };
            if let Some(indexes) = inode_map.get_mut(&(child.node.real_ino, child.node.dev)) {
                let nlink = indexes.len() as u32 + 1;
                let first_index = indexes[0];
                child.node.inode.i_ino = first_index;
                child.node.inode.i_nlink = nlink;
                // Update nlink for previous hardlink inodes
                for idx in indexes.iter() {
                    nodes[*idx as usize - 1].inode.i_nlink = nlink;
                }
                indexes.push(index);
            } else {
                child.node.inode.i_ino = index;
                child.node.inode.i_nlink = 1;
                // Store inode real ino
                inode_map.insert(
                    (child.node.real_ino, child.node.dev),
                    vec![child.node.index],
                );
            }

            // Store node for bootstrap & blob dump.
            // Put the whiteout file of upper layer in the front of node list for layered build,
            // so that it can be applied to the node tree of lower layer first than other files of upper layer.
            match (
                &bootstrap_ctx.f_parent_bootstrap,
                child.node.whiteout_type(ctx.whiteout_spec),
            ) {
                (Some(_), Some(whiteout_type)) => {
                    // For the overlayfs opaque, we need to remove the lower node that has the same
                    // name first, then apply upper node to the node tree of lower layer.
                    nodes.insert(0, child.node.clone());
                    if whiteout_type == WhiteoutType::OverlayFsOpaque {
                        child
                            .node
                            .remove_xattr(&OsString::from(OVERLAYFS_WHITEOUT_OPAQUE));
                        nodes.push(child.node.clone());
                    }
                }
                (None, Some(whiteout_type)) => {
                    // Remove overlayfs opaque xattr for single layer build
                    if whiteout_type == WhiteoutType::OverlayFsOpaque {
                        child
                            .node
                            .remove_xattr(&OsString::from(OVERLAYFS_WHITEOUT_OPAQUE));
                    }
                    nodes.push(child.node.clone());
                }
                _ => {
                    nodes.push(child.node.clone());
                }
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
        if tree.node.is_dir() {
            let parent_dir = &mut nodes[tree.node.index as usize - 1];
            parent_dir.inode.i_nlink = (2 + dirs.len()) as u32;
        }

        for dir in dirs {
            self.build_rafs(ctx, bootstrap_ctx, dir, nodes);
        }
    }

    /// Calculate inode digest
    fn digest_node(
        &self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        index: usize,
    ) {
        let node = &bootstrap_ctx.nodes[index];

        // We have set digest for non-directory inode in the previous dump_blob workflow.
        if node.is_dir() {
            let child_index = node.inode.i_child_index;
            let child_count = node.inode.i_child_count;
            let mut inode_hasher = RafsDigest::hasher(ctx.digester);

            for idx in child_index..child_index + child_count {
                let child = &bootstrap_ctx.nodes[(idx - 1) as usize];
                inode_hasher.digest_update(child.inode.i_digest.as_ref());
            }

            bootstrap_ctx.nodes[index].inode.i_digest = inode_hasher.digest_finalize();
        }
    }

    fn load_parent_bootstrap(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        blob_mgr: &mut BlobManager,
    ) -> Result<Tree> {
        let mut rs = RafsSuper {
            mode: RafsMode::Direct,
            validate_digest: true,
            ..Default::default()
        };

        rs.load(bootstrap_ctx.f_parent_bootstrap.as_mut().unwrap())
            .context("failed to load superblock from bootstrap")?;

        let lower_compressor = rs.meta.get_compressor();
        if ctx.compressor != lower_compressor {
            bail!(
                "inconsistent compressor with the lower layer, current {}, lower: {}.",
                ctx.compressor,
                lower_compressor
            );
        }

        // Reuse lower layer blob table,
        // we need to append the blob entry of upper layer to the table
        blob_mgr.from_blob_table(rs.superblock.get_blob_table().as_ref());
        let mut chunk_cache = HashMap::new();

        // Build node tree of lower layer from a bootstrap file, drop by to add
        // chunks of lower node to chunk_cache for chunk deduplication on next.
        let tree = Tree::from_bootstrap(&rs, Some(&mut chunk_cache))
            .context("failed to build tree from bootstrap")?;

        Ok(tree)
    }

    /// Build an in-memory tree, representing the source file system.
    pub fn build(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        tree: &mut Tree,
    ) {
        let index = RAFS_ROOT_INODE;

        tree.node.index = index;
        tree.node.inode.i_ino = index;
        // Filesystem walking skips root inode within subsequent while loop, however, we allow
        // user to pass the source root as prefetch hint. Check it here.
        ctx.prefetch.insert_if_need(&tree.node);

        let mut nodes = vec![tree.node.clone()];
        self.build_rafs(ctx, bootstrap_ctx, tree, &mut nodes);
        bootstrap_ctx.nodes = nodes;
    }

    /// Apply the diff tree (upper layer) to the base tree (lower layer).
    ///
    /// If `tree` is none, the base tree will be loaded from the parent bootstrap.
    pub fn apply(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        blob_mgr: &mut BlobManager,
        tree: Option<Tree>,
    ) -> Result<Tree> {
        let mut tree = match tree {
            Some(v) => v,
            None => self.load_parent_bootstrap(ctx, bootstrap_ctx, blob_mgr)?,
        };

        // Apply new node (upper layer) to node tree (lower layer)
        timing_tracer!(
            {
                for node in &bootstrap_ctx.nodes {
                    tree.apply(&node, true, ctx.whiteout_spec)
                        .context("failed to apply tree")?;
                }
                Ok(true)
            },
            "apply_tree",
            Result<bool>
        )?;

        // Clear all cached states for next upper layer build.
        bootstrap_ctx.lower_inode_map.clear();
        bootstrap_ctx.upper_inode_map.clear();
        ctx.prefetch.clear();

        Ok(tree)
    }

    /// Dump bootstrap and blob file, return (Vec<blob_id>, blob_size)
    pub fn dump_rafsv5(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        blob_mgr: &mut BlobManager,
    ) -> Result<(Vec<String>, u64)> {
        let blob_ctx = blob_mgr.current();

        let blob_size = if let Some(blob_ctx) = blob_ctx {
            if (blob_ctx.compressed_blob_size > 0
                || (ctx.source_type == SourceType::StargzIndex && !blob_ctx.blob_id.is_empty()))
                && ctx.prefetch.policy != PrefetchPolicy::Blob
            {
                blob_ctx.blob_readahead_size = 0;
            }
            blob_ctx.compressed_blob_size
        } else {
            0
        };

        // Set inode digest, use reverse iteration order to reduce repeated digest calculations.
        for idx in (0..bootstrap_ctx.nodes.len()).rev() {
            self.digest_node(ctx, bootstrap_ctx, idx);
        }

        // Set inode table
        let super_block_size = size_of::<RafsV5SuperBlock>();
        let inode_table_entries = bootstrap_ctx.nodes.len() as u32;
        let mut inode_table = RafsV5InodeTable::new(inode_table_entries as usize);
        let inode_table_size = inode_table.size();

        // Set prefetch table
        let (prefetch_table_size, prefetch_table_entries) =
            if let Some(prefetch_table) = ctx.prefetch.get_rafsv5_prefetch_table() {
                (prefetch_table.size(), prefetch_table.len() as u32)
            } else {
                (0, 0u32)
            };

        // Set blob table, use sha256 string (length 64) as blob id if not specified
        let blob_table = blob_mgr.to_blob_table()?;
        let prefetch_table_offset = super_block_size + inode_table_size;
        let blob_table_offset = prefetch_table_offset + prefetch_table_size;
        let blob_table_size = blob_table.size();
        let extended_blob_table_offset = blob_table_offset + blob_table_size;
        let extended_blob_table_size = blob_table.extended.size();
        let extended_blob_table_entries = blob_table.extended.entries();

        // Set super block
        let mut super_block = RafsV5SuperBlock::new();
        let inodes_count =
            (bootstrap_ctx.lower_inode_map.len() + bootstrap_ctx.upper_inode_map.len()) as u64;
        super_block.set_inodes_count(inodes_count);
        super_block.set_inode_table_offset(super_block_size as u64);
        super_block.set_inode_table_entries(inode_table_entries);
        super_block.set_blob_table_offset(blob_table_offset as u64);
        super_block.set_blob_table_size(blob_table_size as u32);
        super_block.set_extended_blob_table_offset(extended_blob_table_offset as u64);
        super_block.set_extended_blob_table_entries(u32::try_from(extended_blob_table_entries)?);
        super_block.set_prefetch_table_offset(prefetch_table_offset as u64);
        super_block.set_compressor(ctx.compressor);
        super_block.set_digester(ctx.digester);
        if ctx.explicit_uidgid {
            super_block.set_explicit_uidgid();
        }
        if ctx.source_type == SourceType::StargzIndex {
            super_block.set_block_size(STARGZ_DEFAULT_BLOCK_SIZE);
        }
        super_block.set_prefetch_table_entries(prefetch_table_entries);

        // Set inodes and chunks
        let mut inode_offset = (super_block_size
            + inode_table_size
            + prefetch_table_size
            + blob_table_size
            + extended_blob_table_size) as u32;

        let mut has_xattr = false;
        for node in &mut bootstrap_ctx.nodes {
            inode_table.set(node.index, inode_offset)?;
            // Add inode size
            inode_offset += node.inode.size() as u32;
            if node.inode.has_xattr() {
                has_xattr = true;
                if !node.xattrs.is_empty() {
                    inode_offset +=
                        (size_of::<RafsV5XAttrsTable>() + node.xattrs.aligned_size()) as u32;
                }
            }
            // Add chunks size
            if node.is_reg() {
                inode_offset +=
                    (node.inode.i_child_count as usize * size_of::<RafsV5ChunkInfo>()) as u32;
            }
        }
        if has_xattr {
            super_block.set_has_xattr();
        }

        // Dump super block
        super_block
            .store(&mut bootstrap_ctx.f_bootstrap)
            .context("failed to store superblock")?;

        // Dump inode table
        inode_table
            .store(&mut bootstrap_ctx.f_bootstrap)
            .context("failed to store inode table")?;

        // Dump prefetch table
        if let Some(mut prefetch_table) = ctx.prefetch.get_rafsv5_prefetch_table() {
            prefetch_table
                .store(&mut bootstrap_ctx.f_bootstrap)
                .context("failed to store prefetch table")?;
        }

        // Dump blob table
        blob_table
            .store(&mut bootstrap_ctx.f_bootstrap)
            .context("failed to store blob table")?;

        // Dump extended blob table
        blob_table
            .store_extended(&mut bootstrap_ctx.f_bootstrap)
            .context("failed to store extended blob table")?;

        // Dump inodes and chunks
        timing_tracer!(
            {
                for node in &mut bootstrap_ctx.nodes {
                    if ctx.source_type == SourceType::StargzIndex {
                        debug!("[{}]\t{}", node.overlay, node);
                        if log::max_level() >= log::LevelFilter::Debug {
                            for chunk in node.chunks.iter_mut() {
                                trace!("\t\tbuilding chunk: {}", chunk);
                            }
                        }
                    }
                    node.dump_bootstrap_v5(&mut bootstrap_ctx.f_bootstrap)
                        .context("failed to dump bootstrap")?;
                }

                Ok(())
            },
            "dump_bootstrap",
            Result<()>
        )?;

        // Flush remaining data in BufWriter to file
        bootstrap_ctx.f_bootstrap.flush()?;

        let blob_ids: Vec<String> = blob_table
            .entries
            .iter()
            .map(|entry| entry.blob_id.clone())
            .collect();

        Ok((blob_ids, blob_size))
    }
}
