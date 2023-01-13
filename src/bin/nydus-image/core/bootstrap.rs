// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::ffi::OsString;
use std::io::SeekFrom;
use std::mem::size_of;

use anyhow::{Context, Error, Result};
use nydus_rafs::metadata::layout::v5::{
    RafsV5BlobTable, RafsV5ChunkInfo, RafsV5InodeTable, RafsV5SuperBlock, RafsV5XAttrsTable,
};
use nydus_rafs::metadata::layout::v6::{
    align_offset, calculate_nid, RafsV6BlobTable, RafsV6Device, RafsV6SuperBlock,
    RafsV6SuperBlockExt, EROFS_BLOCK_SIZE, EROFS_DEVTABLE_OFFSET, EROFS_INODE_SLOT_SIZE,
};
use nydus_rafs::metadata::layout::{RafsBlobTable, RAFS_V5_ROOT_INODE};
use nydus_rafs::metadata::{RafsStore, RafsSuper, RafsSuperConfig};
use nydus_storage::device::BlobFeatures;
use nydus_utils::digest::{self, DigestHasher, RafsDigest};

use super::context::{
    ArtifactStorage, BlobManager, BootstrapContext, BootstrapManager, BuildContext, ConversionType,
};
use super::node::{Node, WhiteoutType, OVERLAYFS_WHITEOUT_OPAQUE};
use super::tree::Tree;

pub(crate) const STARGZ_DEFAULT_BLOCK_SIZE: u32 = 4 << 20;
const WRITE_PADDING_DATA: [u8; 4096] = [0u8; 4096];

pub(crate) struct Bootstrap {}

impl Bootstrap {
    /// Create a new instance of `Bootstrap`.
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
    /// - files/directories to added/modified in into the lower layer, at the tail of the array.
    ///   The order of addition/modification operations are top-down, that means directories is
    ///   ahead its children.
    ///
    /// It may also be used to generate the final inode array for an RAFS filesystem.
    pub fn build(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        tree: &mut Tree,
    ) -> Result<()> {
        // used to compute nid(ino) for v6
        let root_offset = bootstrap_ctx.offset;
        let mut nodes = Vec::with_capacity(0x10000);

        // Special handling of the root inode
        assert!(tree.node.is_dir());
        // 0 is reserved and 1 also matches RAFS_V5_ROOT_INODE.
        tree.node.index = 1;
        // Rafs v6 root inode number can't be decided until the end of dumping.
        if ctx.fs_version.is_v5() {
            tree.node.inode.set_ino(RAFS_V5_ROOT_INODE);
        }
        ctx.prefetch.insert_if_need(&tree.node);
        nodes.push(tree.node.clone());

        self.build_rafs(ctx, bootstrap_ctx, tree, &mut nodes)?;
        if ctx.fs_version.is_v6() && !bootstrap_ctx.layered {
            // generate on-disk metadata layout for v6
            self.rafsv6_update_dirents(&mut nodes, tree, root_offset);
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

    #[allow(clippy::only_used_in_recursion)]
    /// Traverse node tree, set inode index, ino, child_index and child_count etc according to the
    /// RAFS metadata format, then store to nodes collection.
    fn build_rafs(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        tree: &mut Tree,
        nodes: &mut Vec<Node>,
    ) -> Result<()> {
        let index = nodes.len() as u32 + 1;
        let parent = &mut nodes[tree.node.index as usize - 1];

        // Maybe the parent is not a directory in multi-layers build scenario, so we check here.
        if parent.is_dir() {
            // Sort children list by name, so that we can improve performance in fs read_dir using
            // binary search.
            tree.children
                .sort_by_key(|child| child.node.name().to_os_string());
            parent.inode.set_child_index(index);
            parent.inode.set_child_count(tree.children.len() as u32);
            if ctx.fs_version.is_v6() {
                parent.v6_set_dir_offset(bootstrap_ctx, tree.node.v6_dir_d_size(tree)?)?;
            }
        }

        if ctx.fs_version.is_v6() {
            tree.node.v6_offset = parent.v6_offset;
            // alignment for inode, which is 32 bytes;
            bootstrap_ctx.align_offset(EROFS_INODE_SLOT_SIZE as u64);
        }

        // Cache dir tree for BFS walk
        let mut dirs: Vec<&mut Tree> = Vec::new();
        let parent_ino = parent.inode.ino();

        for child in tree.children.iter_mut() {
            let index = nodes.len() as u64 + 1;
            child.node.index = index;
            child.node.inode.set_parent(parent_ino);

            // Hardlink handle, all hardlink nodes' ino, nlink should be the same,
            // because the real_ino may be conflicted between different layers,
            // so we need to find hardlink node index list in the layer where the node is located.
            let mut v6_hardlink_offset: Option<u64> = None;
            if let Some(indexes) = bootstrap_ctx.inode_map.get_mut(&(
                child.node.layer_idx,
                child.node.src_ino,
                child.node.src_dev,
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
                    (child.node.layer_idx, child.node.src_ino, child.node.src_dev),
                    vec![child.node.index],
                );
            }

            // update bootstrap_ctx.offset for rafs v6.
            if !child.node.is_dir() && ctx.fs_version.is_v6() {
                child.node.v6_set_offset(bootstrap_ctx, v6_hardlink_offset);
                bootstrap_ctx.align_offset(EROFS_INODE_SLOT_SIZE as u64);
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
                    nodes.insert(0, child.node.clone());
                    if whiteout_type == WhiteoutType::OverlayFsOpaque {
                        // For the overlayfs opaque, we need to remove the lower node that has the
                        // same name first, then apply upper node to the node tree of lower layer.
                        child
                            .node
                            .remove_xattr(&OsString::from(OVERLAYFS_WHITEOUT_OPAQUE));
                        nodes.push(child.node.clone());
                    }
                }
                (false, Some(whiteout_type)) => {
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
        let parent_dir = &mut nodes[tree.node.index as usize - 1];
        parent_dir.inode.set_nlink((2 + dirs.len()) as u32);

        for dir in dirs {
            self.build_rafs(ctx, bootstrap_ctx, dir, nodes)?;
        }

        Ok(())
    }

    #[allow(clippy::only_used_in_recursion)]
    /// Rafsv6 update offset
    fn rafsv6_update_dirents(&self, nodes: &mut Vec<Node>, tree: &mut Tree, parent_offset: u64) {
        let node = &mut nodes[tree.node.index as usize - 1];
        let node_offset = node.v6_offset;
        if !node.is_dir() {
            return;
        }

        // dot & dotdot
        // Type of libc::S_IFDIR is u16 on macos, so it need a conversion
        // but compiler will report useless conversion on linux platform,
        // so we add an allow annotation here.
        #[allow(clippy::useless_conversion)]
        {
            node.v6_dirents
                .push((node_offset, OsString::from("."), libc::S_IFDIR.into()));
            node.v6_dirents
                .push((parent_offset, OsString::from(".."), libc::S_IFDIR.into()));
        }

        let mut dirs: Vec<&mut Tree> = Vec::new();
        for child in tree.children.iter_mut() {
            trace!(
                "{:?} child {:?} offset {}, mode {}",
                node.name(),
                child.node.name(),
                child.node.v6_offset,
                child.node.inode.mode()
            );
            node.v6_dirents.push((
                child.node.v6_offset,
                child.node.name().to_os_string(),
                child.node.inode.mode(),
            ));
            if child.node.is_dir() {
                dirs.push(child);
            }
        }
        node.v6_dirents
            .sort_unstable_by(|a, b| a.1.as_os_str().cmp(b.1.as_os_str()) as std::cmp::Ordering);

        for dir in dirs {
            self.rafsv6_update_dirents(nodes, dir, node_offset);
        }
    }

    fn load_parent_bootstrap(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_mgr: &mut BootstrapManager,
        blob_mgr: &mut BlobManager,
    ) -> Result<Tree> {
        let rs = if let Some(path) = bootstrap_mgr.f_parent_path.as_ref() {
            RafsSuper::load_from_file(path, ctx.configuration.clone(), true, false)
                .map(|(rs, _)| rs)?
        } else {
            return Err(Error::msg("bootstrap context's parent bootstrap is null"));
        };

        let config = RafsSuperConfig {
            compressor: ctx.compressor,
            digester: ctx.digester,
            chunk_size: ctx.chunk_size,
            explicit_uidgid: ctx.explicit_uidgid,
            version: ctx.fs_version,
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

    /// Calculate inode digest for directory.
    fn rafsv5_digest_node(
        &self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        index: usize,
    ) {
        let node = &bootstrap_ctx.nodes[index];

        // We have set digest for non-directory inode in the previous dump_blob workflow.
        if node.is_dir() {
            let child_index = node.inode.child_index();
            let child_count = node.inode.child_count();
            let mut inode_hasher = RafsDigest::hasher(ctx.digester);

            for idx in child_index..child_index + child_count {
                let child = &bootstrap_ctx.nodes[(idx - 1) as usize];
                inode_hasher.digest_update(child.inode.digest().as_ref());
            }

            bootstrap_ctx.nodes[index]
                .inode
                .set_digest(inode_hasher.digest_finalize());
        }
    }

    pub fn dump(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_storage: &mut Option<ArtifactStorage>,
        bootstrap_ctx: &mut BootstrapContext,
        blob_table: &RafsBlobTable,
    ) -> Result<()> {
        match blob_table {
            RafsBlobTable::V5(table) => self.rafsv5_dump(ctx, bootstrap_ctx, table)?,
            RafsBlobTable::V6(table) => self.rafsv6_dump(ctx, bootstrap_ctx, table)?,
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

    /// Dump bootstrap and blob file, return (Vec<blob_id>, blob_size)
    fn rafsv5_dump(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        blob_table: &RafsV5BlobTable,
    ) -> Result<()> {
        // Set inode digest, use reverse iteration order to reduce repeated digest calculations.
        for idx in (0..bootstrap_ctx.nodes.len()).rev() {
            self.rafsv5_digest_node(ctx, bootstrap_ctx, idx);
        }

        // Set inode table
        let super_block_size = size_of::<RafsV5SuperBlock>();
        let inode_table_entries = bootstrap_ctx.nodes.len() as u32;
        let mut inode_table = RafsV5InodeTable::new(inode_table_entries as usize);
        let inode_table_size = inode_table.size();

        // Set prefetch table
        let (prefetch_table_size, prefetch_table_entries) = if let Some(prefetch_table) =
            ctx.prefetch.get_rafsv5_prefetch_table(&bootstrap_ctx.nodes)
        {
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
        if ctx.conversion_type == ConversionType::EStargzIndexToRef {
            super_block.set_block_size(STARGZ_DEFAULT_BLOCK_SIZE);
        }

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
            inode_offset += node.inode.inode_size() as u32;
            if node.inode.has_xattr() {
                has_xattr = true;
                if !node.xattrs.is_empty() {
                    inode_offset +=
                        (size_of::<RafsV5XAttrsTable>() + node.xattrs.aligned_size_v5()) as u32;
                }
            }
            // Add chunks size
            if node.is_reg() {
                inode_offset += node.inode.child_count() * size_of::<RafsV5ChunkInfo>() as u32;
            }
        }
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
        if let Some(mut prefetch_table) =
            ctx.prefetch.get_rafsv5_prefetch_table(&bootstrap_ctx.nodes)
        {
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
                for node in &bootstrap_ctx.nodes {
                    node.dump_bootstrap_v5(ctx, bootstrap_ctx.writer.as_mut())
                        .context("failed to dump bootstrap")?;
                }

                Ok(())
            },
            "dump_bootstrap",
            Result<()>
        )?;

        Ok(())
    }

    /// Dump bootstrap and blob file, return (Vec<blob_id>, blob_size)
    fn rafsv6_dump(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        blob_table: &RafsV6BlobTable,
    ) -> Result<()> {
        // Rafs v6 disk layout
        //
        //  EROFS_SUPER_OFFSET
        //     |
        // +---+---------+------------+-------------+----------------------------------------------+
        // |   |         |            |             |                 |         |                  |
        // |1k |super    |extended    | blob table  |  prefetch table | inodes  | chunk info table |
        // |   |block    |superblock+ |             |                 |         |                  |
        // |   |         |devslot     |             |                 |         |                  |
        // +---+---------+------------+-------------+----------------------------------------------+

        // get devt_slotoff
        let mut devtable: Vec<RafsV6Device> = Vec::new();
        let blobs = blob_table.get_all();
        let mut block_count = 0u32;
        let mut inlined_chunk_digest = true;
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
            } else if entry.uncompressed_size() / EROFS_BLOCK_SIZE > u32::MAX as u64 {
                bail!(format!(
                    "uncompressed blob size (0x:{:x}) is too big",
                    entry.uncompressed_size()
                ));
            }
            if !entry.has_feature(BlobFeatures::INLINED_CHUNK_DIGEST) {
                inlined_chunk_digest = false;
            }
            let cnt = (entry.uncompressed_size() / EROFS_BLOCK_SIZE) as u32;
            assert!(block_count.checked_add(cnt).is_some());
            block_count += cnt;
            let id = entry.blob_id();
            let id = id.as_bytes();
            let mut blob_id = [0u8; 64];
            blob_id[..id.len()].copy_from_slice(id);
            devslot.set_blob_id(&blob_id);
            devslot.set_blocks(cnt);
            devslot.set_mapped_blkaddr(0);
            devtable.push(devslot);
        }

        let devtable_len = devtable.len() * size_of::<RafsV6Device>();
        let blob_table_size = blob_table.size() as u64;
        let blob_table_offset = align_offset(
            (EROFS_DEVTABLE_OFFSET as u64) + devtable_len as u64,
            EROFS_BLOCK_SIZE as u64,
        );
        let blob_table_entries = blobs.len();
        assert!(blob_table_entries < u16::MAX as usize);
        trace!(
            "devtable len {} blob table offset {} blob table size {}",
            devtable_len,
            blob_table_offset,
            blob_table_size
        );

        let (prefetch_table_offset, prefetch_table_size) =
            // If blob_table_size equal to 0, there is no prefetch.
            if ctx.prefetch.len() > 0 && blob_table_size > 0 {
                // Prefetch table is very close to blob devices table
                let offset = blob_table_offset + blob_table_size;
                // Each prefetched file has is nid of `u32` filled into prefetch table.
                let size = ctx.prefetch.len() * size_of::<u32>() as u32;
                trace!("prefetch table locates at offset {} size {}", offset, size);
                (offset, size)
            } else {
                (0, 0)
            };

        // Make the superblock's meta_blkaddr one block ahead of the inode table,
        // to avoid using 0 as root nid.
        // inode offset = meta_blkaddr * block_size + 32 * nid
        // When using nid 0 as root nid,
        // the root directory will not be shown by glibc's getdents/readdir.
        // Because in some OS, ino == 0 represents corresponding file is deleted.
        let orig_meta_addr = bootstrap_ctx.nodes[0].v6_offset - EROFS_BLOCK_SIZE;
        let meta_addr = if blob_table_size > 0 {
            align_offset(
                blob_table_offset + blob_table_size + prefetch_table_size as u64,
                EROFS_BLOCK_SIZE as u64,
            )
        } else {
            orig_meta_addr
        };

        let root_nid = calculate_nid(
            bootstrap_ctx.nodes[0].v6_offset + (meta_addr - orig_meta_addr),
            meta_addr,
        );

        // Dump superblock
        let mut sb = RafsV6SuperBlock::new();
        sb.set_inos(bootstrap_ctx.nodes.len() as u64);
        sb.set_blocks(block_count);
        sb.set_root_nid(root_nid as u16);
        sb.set_meta_addr(meta_addr);
        sb.set_extra_devices(blob_table_entries as u16);
        sb.store(bootstrap_ctx.writer.as_mut())
            .context("failed to store SB")?;

        // Dump extended superblock
        let ext_sb_offset = bootstrap_ctx.writer.seek_current(0)?;
        let mut ext_sb = RafsV6SuperBlockExt::new();
        ext_sb.set_compressor(ctx.compressor);
        ext_sb.set_digester(ctx.digester);
        ext_sb.set_chunk_size(ctx.chunk_size);
        ext_sb.set_blob_table_offset(blob_table_offset);
        ext_sb.set_blob_table_size(blob_table_size as u32);
        // we need to write extended_sb until chunk table is dumped.
        if ctx.explicit_uidgid {
            ext_sb.set_explicit_uidgid();
        }
        if inlined_chunk_digest {
            ext_sb.set_inlined_chunk_digest();
        }

        // dump devtslot
        bootstrap_ctx
            .writer
            .seek_offset(EROFS_DEVTABLE_OFFSET as u64)
            .context("failed to seek devtslot")?;
        for slot in devtable.iter() {
            slot.store(bootstrap_ctx.writer.as_mut())
                .context("failed to store device slot")?;
        }

        // Dump blob table
        bootstrap_ctx
            .writer
            .seek_offset(blob_table_offset as u64)
            .context("failed seek for extended blob table offset")?;
        blob_table
            .store(bootstrap_ctx.writer.as_mut())
            .context("failed to store extended blob table")?;

        // collect all chunks in this bootstrap.
        // HashChunkDict cannot be used here, because there will be duplicate chunks between layers,
        // but there is no deduplication during the actual construction.
        // Each layer uses the corresponding chunk in the blob of its own layer.
        // If HashChunkDict is used here, it will cause duplication. The chunks are removed, resulting in incomplete chunk info.
        let mut chunk_cache = BTreeMap::new();

        // Dump bootstrap
        timing_tracer!(
            {
                for node in &mut bootstrap_ctx.nodes {
                    node.dump_bootstrap_v6(
                        ctx,
                        bootstrap_ctx.writer.as_mut(),
                        orig_meta_addr,
                        meta_addr,
                        &mut chunk_cache,
                    )
                    .context("failed to dump bootstrap")?;
                }

                Ok(())
            },
            "dump_bootstrap",
            Result<()>
        )?;

        // `Node` offset might be updated during above inodes dumping. So `get_prefetch_table` after it.
        let prefetch_table = ctx
            .prefetch
            .get_rafsv6_prefetch_table(&bootstrap_ctx.nodes, meta_addr);
        if let Some(mut pt) = prefetch_table {
            // Device slots are very close to extended super block.
            ext_sb.set_prefetch_table_offset(prefetch_table_offset);
            ext_sb.set_prefetch_table_size(prefetch_table_size);
            bootstrap_ctx
                .writer
                .seek_offset(prefetch_table_offset as u64)
                .context("failed seek prefetch table offset")?;
            pt.store(bootstrap_ctx.writer.as_mut()).unwrap();
        }

        // append chunk info table.
        // align chunk table to EROFS_BLOCK_SIZE firstly.
        let pos = bootstrap_ctx
            .writer
            .seek_to_end()
            .context("failed to seek to bootstrap's end for chunk table")?;
        let padding = align_offset(pos, EROFS_BLOCK_SIZE as u64) - pos;
        bootstrap_ctx
            .writer
            .write_all(&WRITE_PADDING_DATA[0..padding as usize])
            .context("failed to write 0 to padding of bootstrap's end for chunk table")?;
        let chunk_table_offset = pos + padding;
        let mut chunk_table_size: u64 = 0;
        for (_, chunk) in chunk_cache.iter() {
            let chunk_size = chunk
                .store(bootstrap_ctx.writer.as_mut())
                .context("failed to dump chunk table")?;
            chunk_table_size += chunk_size as u64;
        }
        ext_sb.set_chunk_table(chunk_table_offset, chunk_table_size);
        debug!(
            "chunk_table offset {} size {}",
            chunk_table_offset, chunk_table_size
        );

        // EROFS does not have inode table, so we lose the chance to decide if this
        // image has xattr. So we have to rewrite extended super block.
        if ctx.has_xattr {
            ext_sb.set_has_xattr();
        }
        bootstrap_ctx.writer.seek(SeekFrom::Start(ext_sb_offset))?;
        ext_sb
            .store(bootstrap_ctx.writer.as_mut())
            .context("failed to store extended SB")?;

        // Flush remaining data in BufWriter to file
        bootstrap_ctx
            .writer
            .flush()
            .context("failed to flush bootstrap")?;
        let pos = bootstrap_ctx
            .writer
            .seek_to_end()
            .context("failed to seek to bootstrap's end")?;
        debug!(
            "align bootstrap to 4k {}",
            align_offset(pos, EROFS_BLOCK_SIZE as u64)
        );
        let padding = align_offset(pos, EROFS_BLOCK_SIZE as u64) - pos;
        bootstrap_ctx
            .writer
            .write_all(&WRITE_PADDING_DATA[0..padding as usize])
            .context("failed to write 0 to padding of bootstrap's end")?;
        bootstrap_ctx
            .writer
            .flush()
            .context("failed to flush bootstrap")?;

        Ok(())
    }
}
