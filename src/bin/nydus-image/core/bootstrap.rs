// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use std::ffi::OsString;
use std::mem::size_of;

use anyhow::{Context, Error, Result};
use nydus_utils::digest::{DigestHasher, RafsDigest};
use rafs::metadata::layout::v5::{
    RafsV5BlobTable, RafsV5ChunkInfo, RafsV5InodeTable, RafsV5SuperBlock, RafsV5XAttrsTable,
};
use rafs::metadata::layout::v6::{lookup_nid, RafsV6SuperBlock, EROFS_BLKSIZE, EROFS_SLOTSIZE};
use rafs::metadata::layout::RAFS_ROOT_INODE;
use rafs::metadata::{RafsMode, RafsStore, RafsSuper, RafsSuperFlags};
use storage::device::BlobFeatures;

use super::context::{BlobManager, BootstrapContext, BuildContext, RafsVersion, SourceType};
use super::node::{Node, WhiteoutType, OVERLAYFS_WHITEOUT_OPAQUE};
use super::prefetch::PrefetchPolicy;
use super::tree::Tree;

pub(crate) const STARGZ_DEFAULT_BLOCK_SIZE: u32 = 4 << 20;

pub(crate) struct Bootstrap {}

impl Bootstrap {
    /// Create a new instance of `BootStrap`.
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
    ) {
        tree.node.index = RAFS_ROOT_INODE;
        tree.node.inode.set_ino(RAFS_ROOT_INODE);
        // Filesystem walking skips root inode within subsequent while loop, however, we allow
        // user to pass the source root as prefetch hint. Check it here.
        ctx.prefetch.insert_if_need(&tree.node);

        let inode_map = if tree.node.overlay.is_lower_layer() {
            &mut bootstrap_ctx.lower_inode_map
        } else {
            &mut bootstrap_ctx.upper_inode_map
        };
        inode_map.insert(
            (tree.node.src_ino, tree.node.src_dev),
            vec![tree.node.index],
        );

        // indicates where v6's meta_addr starts
        let root_offset = bootstrap_ctx.offset;
        let mut nodes = Vec::with_capacity(0x10000);
        nodes.push(tree.node.clone());
        self.build_rafs(ctx, bootstrap_ctx, tree, &mut nodes);

        self.update_dirents(&mut nodes, tree, root_offset);
        bootstrap_ctx.nodes = nodes;
    }

    /// Apply diff operations to the base tree (lower layer) and return the merged `Tree` object.
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

    /// Traverse node tree, set inode index, ino, child_index and child_count etc according to the
    /// RAFS metadata format, then store to nodes collection.
    fn build_rafs(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        tree: &mut Tree,
        nodes: &mut Vec<Node>,
    ) {
        let index = nodes.len() as u32 + 1;
        let parent = &mut nodes[tree.node.index as usize - 1];

        parent.inode.set_child_index(index);
        parent.inode.set_child_count(tree.children.len() as u32);

        // Sort children list by name, so that we can improve performance in fs read_dir using
        // binary search.
        tree.children
            .sort_by_key(|child| child.node.name().to_os_string());

        parent.dir_set_v6_offset(bootstrap_ctx, tree.node.get_dir_d_size(tree));
        tree.node.offset = parent.offset;
        // alignment for inode, which is 32 bytes;
        bootstrap_ctx.align_offset(EROFS_SLOTSIZE as u64);

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
            let inode_map = if child.node.overlay.is_lower_layer() {
                &mut bootstrap_ctx.lower_inode_map
            } else {
                &mut bootstrap_ctx.upper_inode_map
            };
            if let Some(indexes) = inode_map.get_mut(&(child.node.src_ino, child.node.src_dev)) {
                let nlink = indexes.len() as u32 + 1;
                let first_index = indexes[0];
                child.node.inode.set_ino(first_index);
                child.node.inode.set_nlink(nlink);
                // Update nlink for previous hardlink inodes
                for idx in indexes.iter() {
                    nodes[*idx as usize - 1].inode.set_nlink(nlink);
                }
                indexes.push(index);
            } else {
                child.node.inode.set_ino(index);
                child.node.inode.set_nlink(1);
                // Store inode real ino
                inode_map.insert(
                    (child.node.src_ino, child.node.src_dev),
                    vec![child.node.index],
                );
            }

            // update bootstrap_ctx.offset for rafs v6.
            if child.node.is_reg() || child.node.is_symlink() {
                child.node.set_v6_offset(bootstrap_ctx);
                bootstrap_ctx.align_offset(EROFS_SLOTSIZE as u64);
                // println!("ctx.offset {}", bootstrap_ctx.offset);
            }

            // Store node for bootstrap & blob dump.
            // Put the whiteout file of upper layer in the front of node list for layered build,
            // so that it can be applied to the node tree of lower layer first than other files of upper layer.
            match (
                &bootstrap_ctx.f_parent_bootstrap,
                child.node.whiteout_type(ctx.whiteout_spec),
            ) {
                (Some(_), Some(whiteout_type)) => {
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
        let parent_dir = &mut nodes[tree.node.index as usize - 1];
        parent_dir.inode.set_nlink((2 + dirs.len()) as u32);

        for dir in dirs {
            self.build_rafs(ctx, bootstrap_ctx, dir, nodes);
        }
    }

    /// Rafsv6 update offset
    fn update_dirents(&self, nodes: &mut Vec<Node>, tree: &mut Tree, parent_offset: u64) {
        let node = &mut nodes[tree.node.index as usize - 1];
        if !node.is_dir() {
            return;
        }

        // dot & dotdot
        node.dirents
            .push((node.offset, OsString::from("."), libc::S_IFDIR));
        node.dirents
            .push((parent_offset, OsString::from(".."), libc::S_IFDIR));

        let mut dirs: Vec<&mut Tree> = Vec::new();
        for child in tree.children.iter_mut() {
            trace!(
                "{:?} child {:?} offset {}, mode {}",
                tree.node.name(),
                child.node.name(),
                child.node.offset,
                child.node.inode.mode()
            );
            node.dirents.push((
                child.node.offset,
                child.node.name().to_os_string(),
                child.node.inode.mode(),
            ));

            if child.node.is_dir() {
                dirs.push(child);
            }
        }

        for dir in dirs {
            self.update_dirents(nodes, dir, tree.node.offset);
        }
    }

    fn load_parent_bootstrap(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        blob_mgr: &mut BlobManager,
    ) -> Result<Tree> {
        let rs = if let Some(r) = bootstrap_ctx.f_parent_bootstrap.as_mut() {
            let mut rs = RafsSuper {
                mode: RafsMode::Direct,
                validate_digest: true,
                ..Default::default()
            };
            rs.load(r)
                .context("failed to load superblock from bootstrap")?;
            rs
        } else {
            return Err(Error::msg("bootstrap context's parent bootstrap is null"));
        };

        let lower_compressor = rs.meta.get_compressor();
        if ctx.compressor != lower_compressor {
            return Err(Error::msg(format!(
                "inconsistent compressor with the lower layer, current {}, lower: {}.",
                ctx.compressor, lower_compressor
            )));
        }

        // Reuse lower layer blob table,
        // we need to append the blob entry of upper layer to the table
        blob_mgr.from_blob_table(rs.superblock.get_blob_infos());

        // Build node tree of lower layer from a bootstrap file, drop by to add
        // chunks of lower node to chunk_cache for chunk deduplication on next.
        let tree = Tree::from_bootstrap(&rs, &mut blob_mgr.chunk_dict_cache)
            .context("failed to build tree from bootstrap")?;

        Ok(tree)
    }

    /// Calculate inode digest for directory.
    fn digest_node(
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
        let blob_table = blob_mgr.to_blob_table_v5(ctx)?;
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
        super_block.set_prefetch_table_entries(prefetch_table_entries);
        super_block.set_compressor(ctx.compressor);
        super_block.set_digester(ctx.digester);
        super_block.set_chunk_size(ctx.chunk_size);
        if ctx.explicit_uidgid {
            super_block.set_explicit_uidgid();
        }
        if ctx.source_type == SourceType::StargzIndex {
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
            .map(|entry| entry.blob_id().to_owned())
            .collect();

        Ok((blob_ids, blob_size))
    }

    /// Dump bootstrap and blob file, return (Vec<blob_id>, blob_size)
    pub fn dump_rafsv6(
        &mut self,
        ctx: &mut BuildContext,
        bootstrap_ctx: &mut BootstrapContext,
        _blob_mgr: &mut BlobManager,
    ) -> Result<(Vec<String>, u64)> {
        let meta_addr = bootstrap_ctx.nodes[0].offset;
        let root_nid = lookup_nid(bootstrap_ctx.nodes[0].offset, meta_addr);
        // Dump superblock
        let mut sb = RafsV6SuperBlock::new();
        sb.s_inos = u64::to_le(bootstrap_ctx.nodes.len() as u64);
        // FIXME
        sb.s_blocks = 0;
        sb.s_root_nid = u16::to_le(root_nid as u16);
        sb.s_meta_blkaddr = u32::to_le((meta_addr / EROFS_BLKSIZE as u64) as u32);
        // only support one extra device.
        sb.s_extra_devices = u16::to_le(1);

        // bootstrap_ctx
        //     .f_bootstrap
        //     .seek(SeekFrom::Start(EROFS_SUPER_OFFSET as u64))
        //     .context("failed seek for EROFS_SUPER_OFFSET")?;
        sb.store(&mut bootstrap_ctx.f_bootstrap)
            .context("failed to store SB")?;

        // Dump bootstrap
        timing_tracer!(
            {
                for node in &mut bootstrap_ctx.nodes {
                    node.dump_bootstrap_v6(&mut bootstrap_ctx.f_bootstrap, meta_addr, ctx)
                        .context("failed to dump bootstrap")?;
                }

                Ok(())
            },
            "dump_bootstrap",
            Result<()>
        )?;

        // Flush remaining data in BufWriter to file
        bootstrap_ctx.f_bootstrap.flush()?;

        let blob_ids: Vec<String> = Vec::new();
        let blob_size = 0;
        Ok((blob_ids, blob_size))
    }
}

impl BlobManager {
    pub fn to_blob_table_v5(&self, build_ctx: &BuildContext) -> Result<RafsV5BlobTable> {
        let mut blob_table = RafsV5BlobTable::new();

        for ctx in &self.blobs {
            let blob_id = ctx.blob_id.clone();
            let blob_readahead_size = u32::try_from(ctx.blob_readahead_size)?;
            let chunk_count = ctx.chunk_count;
            let decompressed_blob_size = ctx.decompressed_blob_size;
            let compressed_blob_size = ctx.compressed_blob_size;
            let blob_features = BlobFeatures::empty();

            let mut flags = RafsSuperFlags::empty();
            match build_ctx.fs_version {
                RafsVersion::V5 => {
                    flags |= RafsSuperFlags::from(build_ctx.compressor);
                    flags |= RafsSuperFlags::from(build_ctx.digester);
                }
                RafsVersion::V6 => todo!(),
            }

            blob_table.add(
                blob_id,
                0,
                blob_readahead_size,
                ctx.chunk_size,
                chunk_count,
                decompressed_blob_size,
                compressed_blob_size,
                blob_features,
                flags,
            );
        }

        Ok(blob_table)
    }
}
