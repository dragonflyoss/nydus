// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
#![allow(unused_variables, unused_imports)]
use anyhow::{bail, Context, Error, Result};
use nydus_rafs::metadata::chunk::ChunkWrapper;
use nydus_rafs::metadata::layout::v5::{
    dedup_rafsv5_align, RafsV5BlobTable, RafsV5ExtBlobEntry, RafsV5SuperBlock,
};
use nydus_rafs::metadata::layout::v6::{
    align_offset, RafsV6BlobTable, RafsV6Device, RafsV6SuperBlock, RafsV6SuperBlockExt,
    EROFS_BLOCK_SIZE_4096, EROFS_SUPER_BLOCK_SIZE, EROFS_SUPER_OFFSET,
};
use nydus_rafs::{RafsIoReader, RafsIoWrite};
use nydus_storage::device::BlobFeatures;
use nydus_utils::digest::{self, RafsDigest};

use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;
use std::io::SeekFrom;
use std::mem::size_of;
use std::ops::Deref;
use std::sync::Arc;

use nydus_rafs::metadata::layout::{RafsBlobTable, RAFS_V5_ROOT_INODE};
use nydus_rafs::metadata::{RafsStore, RafsSuper, RafsSuperConfig, RafsSuperFlags};

use crate::{ArtifactStorage, BlobManager, BootstrapContext, BootstrapManager, BuildContext, Tree};

use super::chunk_dict::DigestWithBlobIndex;

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
        ctx.prefetch.insert(&self.tree.node, root_node.deref());
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
            ctx.prefetch.insert(&child.node, child_node.deref());
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

    pub fn dedup(
        &mut self,
        build_ctx: &BuildContext,
        rs: &RafsSuper,
        reader: &mut RafsIoReader,
        writer: &mut dyn RafsIoWrite,
        blob_table: &RafsBlobTable,
        chunk_cache: &BTreeMap<DigestWithBlobIndex, Arc<ChunkWrapper>>,
    ) -> Result<()> {
        match blob_table {
            RafsBlobTable::V5(table) => {
                self.rafsv5_dedup(build_ctx, rs, reader, writer, table, chunk_cache)?
            }
            RafsBlobTable::V6(table) => {
                self.rafsv6_dedup(build_ctx, rs, reader, writer, table, chunk_cache)?
            }
        }

        Ok(())
    }

    fn rafsv5_dedup(
        &mut self,
        build_ctx: &BuildContext,
        _rs: &RafsSuper,
        reader: &mut RafsIoReader,
        writer: &mut dyn RafsIoWrite,
        blob_table: &RafsV5BlobTable,
        chunk_cache: &BTreeMap<DigestWithBlobIndex, Arc<ChunkWrapper>>,
    ) -> Result<()> {
        reader.seek_to_offset(0)?;
        let mut sb = RafsV5SuperBlock::new();
        reader.read_exact(sb.as_mut())?;

        let old_blob_table_offset = sb.blob_table_offset();
        let old_table_size = sb.blob_table_size()
            + dedup_rafsv5_align(
                size_of::<RafsV5ExtBlobEntry>() * sb.extended_blob_table_entries() as usize,
            ) as u32;
        let blob_table_size = blob_table.size() as u32;
        let bootstrap_end = writer
            .seek_to_end()
            .context("failed to seek to bootstrap's end for devtable")?;

        let (blob_table_offset, ext_blob_table_offset) = if blob_table_size > old_table_size {
            (bootstrap_end, bootstrap_end + blob_table_size as u64)
        } else {
            (old_blob_table_offset, bootstrap_end)
        };
        //write rs
        sb.set_blob_table_offset(blob_table_offset as u64);
        sb.set_blob_table_size(blob_table_size as u32);
        sb.set_extended_blob_table_offset(ext_blob_table_offset as u64);
        sb.set_extended_blob_table_entries(u32::try_from(blob_table.extended.entries())?);
        writer.seek(SeekFrom::Start(0))?;
        sb.store(writer).context("failed to store superblock")?;
        //rewrite blob table
        writer
            .seek_offset(blob_table_offset)
            .context("failed seek for extended blob table offset")?;
        blob_table
            .store(writer)
            .context("failed to store blob table")?;
        writer
            .seek_offset(ext_blob_table_offset)
            .context("failed seek for extended blob table offset")?;
        blob_table
            .store_extended(writer)
            .context("failed to store extended blob table")?;
        writer.finalize(Some(String::default()))?;

        Ok(())
    }

    fn rafsv6_dedup(
        &mut self,
        build_ctx: &BuildContext,
        rs: &RafsSuper,
        reader: &mut RafsIoReader,
        writer: &mut dyn RafsIoWrite,
        blob_table: &RafsV6BlobTable,
        chunk_cache: &BTreeMap<DigestWithBlobIndex, Arc<ChunkWrapper>>,
    ) -> Result<()> {
        let mut sb = RafsV6SuperBlock::new();
        sb.load(reader)?;
        let mut ext_sb = RafsV6SuperBlockExt::new();
        ext_sb.load(reader)?;

        let blobs = blob_table.get_all();
        let devtable_len = (blobs.len() * size_of::<RafsV6Device>()) as u64;
        let blob_table_size = blob_table.size() as u64;
        let old_devtable_offset = sb.s_devt_slotoff as u64 * size_of::<RafsV6Device>() as u64;
        let old_blob_table_offset = rs.meta.blob_table_offset as u64;
        let old_blob_table_size = rs.meta.blob_table_size as u64;
        let old_table_size =
            old_blob_table_offset + old_blob_table_size as u64 - old_devtable_offset;
        let chunk_table_offset = ext_sb.chunk_table_offset();
        let chunk_table_size = ext_sb.chunk_table_size();

        let bootstrap_end = writer
            .seek_to_end()
            .context("failed to seek to bootstrap's end for devtable")?;

        let (dev_table_offset, blob_table_offset) = if devtable_len > old_table_size {
            (
                bootstrap_end,
                align_offset(bootstrap_end + devtable_len, EROFS_BLOCK_SIZE_4096 as u64),
            )
        } else {
            (old_devtable_offset, bootstrap_end)
        };

        // Dump super block
        writer.seek(SeekFrom::Start(0))?;
        sb.set_devt_slotoff(dev_table_offset);
        sb.store(writer).context("failed to store rs")?;

        // Dump ext_sb
        ext_sb.set_blob_table_offset(blob_table_offset);
        ext_sb.set_blob_table_size(blob_table_size as u32);
        writer
            .seek_offset((EROFS_SUPER_OFFSET + EROFS_SUPER_BLOCK_SIZE) as u64)
            .context("failed to seek for extended super block")?;
        ext_sb
            .store(writer)
            .context("failed to store extended super block")?;

        // Dump chunk info array.
        writer
            .seek_offset(chunk_table_offset)
            .context("failed to seek to bootstrap's end for chunk table")?;
        for (_, chunk) in chunk_cache.iter() {
            chunk.store(writer).context("failed to dump chunk table")?;
        }

        // Dump blob table
        writer
            .seek_offset(blob_table_offset)
            .context("failed seek for extended blob table offset")?;
        blob_table
            .store(writer)
            .context("failed to store extended blob table")?;

        // Dump padding
        writer.flush().context("failed to flush bootstrap")?;

        let pos = writer
            .seek_to_end()
            .context("failed to seek to bootstrap's end")?;
        let padding = align_offset(pos, EROFS_BLOCK_SIZE_4096 as u64) - pos;
        let padding_data: [u8; 4096] = [0u8; 4096];
        writer
            .write_all(&padding_data[0..padding as usize])
            .context("failed to write 0 to padding of bootstrap's end")?;
        writer.flush().context("failed to flush bootstrap")?;

        //prepare devtable
        let block_size = build_ctx.v6_block_size();
        let mut devtable: Vec<RafsV6Device> = Vec::new();
        let mut pos = writer
            .seek_to_end()
            .context("failed to seek to bootstrap's end for chunk table")?;
        assert_eq!(pos % block_size, 0);
        let mut block_count = 0u32;
        for entry in blobs.iter() {
            let mut devslot = RafsV6Device::new();
            // blob id is String, which is processed by sha256.finalize().
            if entry.blob_id().is_empty() {
                bail!(" blob id is empty");
            } else if entry.blob_id().len() > 64 {
                bail!(format!(
                    "blob id length is bigger than 64 bytes, blob id {:?}",
                    entry.blob_id()
                ));
            } else if entry.uncompressed_size() / block_size > u32::MAX as u64 {
                bail!(format!(
                    "uncompressed blob size (0x:{:x}) is too big",
                    entry.uncompressed_size()
                ));
            }

            let cnt = (entry.uncompressed_size() / block_size) as u32;
            if block_count.checked_add(cnt).is_none() {
                bail!("Too many data blocks in RAFS filesystem, block size 0x{:x}, block count 0x{:x}", block_size, block_count as u64 + cnt as u64);
            }
            let mapped_blkaddr = Self::v6_align_mapped_blkaddr(block_size, pos)?;
            pos = (mapped_blkaddr + cnt) as u64 * block_size;
            block_count += cnt;

            let id = entry.blob_id();
            let id = id.as_bytes();
            let mut blob_id = [0u8; 64];
            blob_id[..id.len()].copy_from_slice(id);
            devslot.set_blob_id(&blob_id);
            devslot.set_blocks(cnt);
            devslot.set_mapped_blkaddr(mapped_blkaddr);
            devtable.push(devslot);
        }

        // Dump devslot table
        writer
            .seek_offset(dev_table_offset)
            .context("failed to seek devtslot")?;

        for slot in devtable.iter() {
            slot.store(writer).context("failed to store device slot")?;
        }

        Ok(())
    }
}
