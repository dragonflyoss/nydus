// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use std::mem::size_of;

use anyhow::{bail, Context, Result};
use nydus_rafs::metadata::inode::InodeWrapper;
use nydus_rafs::metadata::layout::v5::{
    RafsV5BlobTable, RafsV5ChunkInfo, RafsV5InodeTable, RafsV5InodeWrapper, RafsV5SuperBlock,
    RafsV5XAttrsTable,
};
use nydus_rafs::metadata::{RafsStore, RafsVersion};
use nydus_rafs::RafsIoWrite;
use nydus_utils::digest::{DigestHasher, RafsDigest};
use nydus_utils::{div_round_up, root_tracer, timing_tracer, try_round_up_4k};

use super::node::Node;
use crate::{Bootstrap, BootstrapContext, BuildContext, Tree};

// Filesystem may have different algorithms to calculate `i_size` for directory entries,
// which may break "repeatable build". To support repeatable build, instead of reuse the value
// provided by the source filesystem, we use our own algorithm to calculate `i_size` for directory
// entries for stable `i_size`.
//
// Rafs v6 already has its own algorithm to calculate `i_size` for directory entries, but we don't
// have directory entries for Rafs v5. So let's generate a pseudo `i_size` for Rafs v5 directory
// inode.
const RAFS_V5_VIRTUAL_ENTRY_SIZE: u64 = 8;

impl Node {
    /// Dump RAFS v5 inode metadata to meta blob.
    pub fn dump_bootstrap_v5(
        &self,
        ctx: &mut BuildContext,
        f_bootstrap: &mut dyn RafsIoWrite,
    ) -> Result<()> {
        if let InodeWrapper::V5(raw_inode) = &self.inode {
            // Dump inode info
            let name = self.name();
            let inode = RafsV5InodeWrapper {
                name,
                symlink: self.info.symlink.as_deref(),
                inode: raw_inode,
            };
            inode
                .store(f_bootstrap)
                .context("failed to dump inode to bootstrap")?;

            // Dump inode xattr
            if !self.info.xattrs.is_empty() {
                self.info
                    .xattrs
                    .store_v5(f_bootstrap)
                    .context("failed to dump xattr to bootstrap")?;
                ctx.has_xattr = true;
            }

            // Dump chunk info
            if self.is_reg() && self.inode.child_count() as usize != self.chunks.len() {
                bail!("invalid chunk count {}: {}", self.chunks.len(), self);
            }
            for chunk in &self.chunks {
                chunk
                    .inner
                    .store(f_bootstrap)
                    .context("failed to dump chunk info to bootstrap")?;
                trace!("\t\tchunk: {} compressor {}", chunk, ctx.compressor,);
            }

            Ok(())
        } else {
            bail!("dump_bootstrap_v5() encounters non-v5-inode");
        }
    }

    // Filesystem may have different algorithms to calculate `i_size` for directory entries,
    // which may break "repeatable build". To support repeatable build, instead of reuse the value
    // provided by the source filesystem, we use our own algorithm to calculate `i_size` for
    // directory entries for stable `i_size`.
    //
    // Rafs v6 already has its own algorithm to calculate `i_size` for directory entries, but we
    // don't have directory entries for Rafs v5. So let's generate a pseudo `i_size` for Rafs v5
    // directory inode.
    pub fn v5_set_dir_size(&mut self, fs_version: RafsVersion, children: &[Tree]) {
        if !self.is_dir() || !fs_version.is_v5() {
            return;
        }

        let mut d_size = 0u64;
        for child in children.iter() {
            d_size += child.lock_node().inode.name_size() as u64 + RAFS_V5_VIRTUAL_ENTRY_SIZE;
        }
        if d_size == 0 {
            self.inode.set_size(4096);
        } else {
            // Safe to unwrap() because we have u32 for child count.
            self.inode.set_size(try_round_up_4k(d_size).unwrap());
        }
        self.v5_set_inode_blocks();
    }

    /// Calculate and set `i_blocks` for inode.
    ///
    /// In order to support repeatable build, we can't reuse `i_blocks` from source filesystems,
    /// so let's calculate it by ourself for stable `i_block`.
    ///
    /// Normal filesystem includes the space occupied by Xattr into the directory size,
    /// let's follow the normal behavior.
    pub fn v5_set_inode_blocks(&mut self) {
        // Set inode blocks for RAFS v5 inode, v6 will calculate it at runtime.
        if let InodeWrapper::V5(_) = self.inode {
            self.inode.set_blocks(div_round_up(
                self.inode.size() + self.info.xattrs.aligned_size_v5() as u64,
                512,
            ));
        }
    }
}

impl Bootstrap {
    /// Calculate inode digest for directory.
    fn v5_digest_node(&self, ctx: &mut BuildContext, tree: &Tree) {
        let mut node = tree.lock_node();

        // We have set digest for non-directory inode in the previous dump_blob workflow.
        if node.is_dir() {
            let mut inode_hasher = RafsDigest::hasher(ctx.digester);
            for child in tree.children.iter() {
                let child = child.lock_node();
                inode_hasher.digest_update(child.inode.digest().as_ref());
            }
            node.inode.set_digest(inode_hasher.digest_finalize());
        }
    }

    /// Dump bootstrap and blob file, return (Vec<blob_id>, blob_size)
    pub(crate) fn v5_dump(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        blob_table: &RafsV5BlobTable,
    ) -> Result<()> {
        // Set inode digest, use reverse iteration order to reduce repeated digest calculations.
        self.tree.walk_dfs_post(&mut |t| {
            self.v5_digest_node(ctx, t);
            Ok(())
        })?;

        // Set inode table
        let super_block_size = size_of::<RafsV5SuperBlock>();
        let inode_table_entries = bootstrap_ctx.get_next_ino() as u32 - 1;
        let mut inode_table = RafsV5InodeTable::new(inode_table_entries as usize);
        let inode_table_size = inode_table.size();

        // Set prefetch table
        let (prefetch_table_size, prefetch_table_entries) =
            if let Some(prefetch_table) = ctx.prefetch.get_v5_prefetch_table() {
                (prefetch_table.size(), prefetch_table.len() as u32)
            } else {
                (0, 0u32)
            };

        // Set blob table, use sha256 string (length 64) as blob id if not specified
        let prefetch_table_offset = super_block_size + inode_table_size;
        let blob_table_offset = prefetch_table_offset + prefetch_table_size;
        let blob_table_size = blob_table.size();
        let extended_blob_table_offset = blob_table_offset + blob_table_size;
        let extended_blob_table_size = blob_table.extended.size();
        let extended_blob_table_entries = blob_table.extended.entries();

        // Set super block
        let mut super_block = RafsV5SuperBlock::new();
        let inodes_count = bootstrap_ctx.inode_map.len() as u64;
        super_block.set_inodes_count(inodes_count);
        super_block.set_inode_table_offset(super_block_size as u64);
        super_block.set_inode_table_entries(inode_table_entries);
        super_block.set_blob_table_offset(blob_table_offset as u64);
        super_block.set_blob_table_size(blob_table_size as u32);
        super_block.set_extended_blob_table_offset(extended_blob_table_offset as u64);
        super_block.set_extended_blob_table_entries(u32::try_from(extended_blob_table_entries)?);
        super_block.set_prefetch_table_offset(prefetch_table_offset as u64);
        super_block.set_prefetch_table_entries(prefetch_table_entries);
        super_block.set_compressor(ctx.compressor);
        super_block.set_digester(ctx.digester);
        super_block.set_chunk_size(ctx.chunk_size);
        if ctx.explicit_uidgid {
            super_block.set_explicit_uidgid();
        }

        // Set inodes and chunks
        let mut inode_offset = (super_block_size
            + inode_table_size
            + prefetch_table_size
            + blob_table_size
            + extended_blob_table_size) as u32;

        let mut has_xattr = false;
        self.tree.walk_dfs_pre(&mut |t| {
            let node = t.lock_node();
            inode_table.set(node.index, inode_offset)?;
            // Add inode size
            inode_offset += node.inode.inode_size() as u32;
            if node.inode.has_xattr() {
                has_xattr = true;
                if !node.info.xattrs.is_empty() {
                    inode_offset += (size_of::<RafsV5XAttrsTable>()
                        + node.info.xattrs.aligned_size_v5())
                        as u32;
                }
            }
            // Add chunks size
            if node.is_reg() {
                inode_offset += node.inode.child_count() * size_of::<RafsV5ChunkInfo>() as u32;
            }
            Ok(())
        })?;
        if has_xattr {
            super_block.set_has_xattr();
        }

        // Dump super block
        super_block
            .store(bootstrap_ctx.writer.as_mut())
            .context("failed to store superblock")?;

        // Dump inode table
        inode_table
            .store(bootstrap_ctx.writer.as_mut())
            .context("failed to store inode table")?;

        // Dump prefetch table
        if let Some(mut prefetch_table) = ctx.prefetch.get_v5_prefetch_table() {
            prefetch_table
                .store(bootstrap_ctx.writer.as_mut())
                .context("failed to store prefetch table")?;
        }

        // Dump blob table
        blob_table
            .store(bootstrap_ctx.writer.as_mut())
            .context("failed to store blob table")?;

        // Dump extended blob table
        blob_table
            .store_extended(bootstrap_ctx.writer.as_mut())
            .context("failed to store extended blob table")?;

        // Dump inodes and chunks
        timing_tracer!(
            {
                self.tree.walk_dfs_pre(&mut |t| {
                    t.lock_node()
                        .dump_bootstrap_v5(ctx, bootstrap_ctx.writer.as_mut())
                        .context("failed to dump bootstrap")
                })
            },
            "dump_bootstrap"
        )?;

        Ok(())
    }
}
