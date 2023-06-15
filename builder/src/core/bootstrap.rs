// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Error, Result};
use nydus_utils::digest::{self, RafsDigest};
use std::ops::Deref;

use nydus_rafs::metadata::layout::{RafsBlobTable, RAFS_V5_ROOT_INODE};
use nydus_rafs::metadata::{RafsSuper, RafsSuperConfig, RafsSuperFlags};

use crate::{ArtifactStorage, BlobManager, BootstrapContext, BootstrapManager, BuildContext, Tree};

/// RAFS bootstrap/meta builder.
pub struct Bootstrap {
    pub(crate) tree: Tree,
}

impl Bootstrap {
    /// Create a new instance of [Bootstrap].
    pub fn new(tree: Tree) -> Result<Self> {
        Ok(Self { tree })
    }

    /// Build the final view of the RAFS filesystem meta from the hierarchy `tree`.
    pub fn build(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
    ) -> Result<()> {
        // Special handling of the root inode
        let mut root_node = self.tree.lock_node();
        assert!(root_node.is_dir());
        let index = bootstrap_ctx.generate_next_ino();
        // 0 is reserved and 1 also matches RAFS_V5_ROOT_INODE.
        assert_eq!(index, RAFS_V5_ROOT_INODE);
        root_node.index = index;
        root_node.inode.set_ino(index);
        ctx.prefetch
            .insert_if_need(&self.tree.node, root_node.deref());
        bootstrap_ctx.inode_map.insert(
            (
                root_node.layer_idx,
                root_node.info.src_ino,
                root_node.info.src_dev,
            ),
            vec![self.tree.node.clone()],
        );
        drop(root_node);

        Self::build_rafs(ctx, bootstrap_ctx, &mut self.tree)?;
        if ctx.fs_version.is_v6() {
            let root_offset = self.tree.node.lock().unwrap().v6_offset;
            Self::v6_update_dirents(&self.tree, root_offset);
        }

        Ok(())
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
    ) -> Result<()> {
        let parent_node = tree.node.clone();
        let mut parent_node = parent_node.lock().unwrap();
        let parent_ino = parent_node.inode.ino();
        let block_size = ctx.v6_block_size();

        // In case of multi-layer building, it's possible that the parent node is not a directory.
        if parent_node.is_dir() {
            parent_node
                .inode
                .set_child_count(tree.children.len() as u32);
            if ctx.fs_version.is_v5() {
                parent_node
                    .inode
                    .set_child_index(bootstrap_ctx.get_next_ino() as u32);
            } else if ctx.fs_version.is_v6() {
                // Layout directory entries for v6.
                let d_size = parent_node.v6_dirent_size(ctx, tree)?;
                parent_node.v6_set_dir_offset(bootstrap_ctx, d_size, block_size)?;
            }
        }

        let mut dirs: Vec<&mut Tree> = Vec::new();
        for child in tree.children.iter_mut() {
            let child_node = child.node.clone();
            let mut child_node = child_node.lock().unwrap();
            let index = bootstrap_ctx.generate_next_ino();
            child_node.index = index;
            if ctx.fs_version.is_v5() {
                child_node.inode.set_parent(parent_ino);
            }

            // Handle hardlink.
            // All hardlink nodes' ino and nlink should be the same.
            // We need to find hardlink node index list in the layer where the node is located
            // because the real_ino may be different among different layers,
            let mut v6_hardlink_offset: Option<u64> = None;
            let key = (
                child_node.layer_idx,
                child_node.info.src_ino,
                child_node.info.src_dev,
            );
            if let Some(indexes) = bootstrap_ctx.inode_map.get_mut(&key) {
                let nlink = indexes.len() as u32 + 1;
                // Update nlink for previous hardlink inodes
                for n in indexes.iter() {
                    n.lock().unwrap().inode.set_nlink(nlink);
                }

                let (first_ino, first_offset) = {
                    let first_node = indexes[0].lock().unwrap();
                    (first_node.inode.ino(), first_node.v6_offset)
                };
                // set offset for rafs v6 hardlinks
                v6_hardlink_offset = Some(first_offset);
                child_node.inode.set_nlink(nlink);
                child_node.inode.set_ino(first_ino);
                indexes.push(child.node.clone());
            } else {
                child_node.inode.set_ino(index);
                child_node.inode.set_nlink(1);
                // Store inode real ino
                bootstrap_ctx
                    .inode_map
                    .insert(key, vec![child.node.clone()]);
            }

            // update bootstrap_ctx.offset for rafs v6 non-dir nodes.
            if !child_node.is_dir() && ctx.fs_version.is_v6() {
                child_node.v6_set_offset(bootstrap_ctx, v6_hardlink_offset, block_size)?;
            }
            ctx.prefetch.insert_if_need(&child.node, child_node.deref());
            if child_node.is_dir() {
                dirs.push(child);
            }
        }

        // According to filesystem semantics, a parent directory should have nlink equal to
        // the number of its child directories plus 2.
        if parent_node.is_dir() {
            parent_node.inode.set_nlink((2 + dirs.len()) as u32);
        }
        for dir in dirs {
            Self::build_rafs(ctx, bootstrap_ctx, dir)?;
        }

        Ok(())
    }

    /// Load a parent RAFS bootstrap and return the `Tree` object representing the filesystem.
    pub fn load_parent_bootstrap(
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
        Tree::from_bootstrap(&rs, &mut blob_mgr.layered_chunk_dict)
            .context("failed to build tree from bootstrap")
    }
}
