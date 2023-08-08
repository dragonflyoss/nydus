// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::SeekFrom;
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;

use anyhow::{bail, ensure, Context, Result};
use nydus_rafs::metadata::chunk::ChunkWrapper;
use nydus_rafs::metadata::layout::v6::{
    align_offset, calculate_nid, new_v6_inode, RafsV6BlobTable, RafsV6Device, RafsV6Dirent,
    RafsV6InodeChunkAddr, RafsV6InodeChunkHeader, RafsV6OndiskInode, RafsV6SuperBlock,
    RafsV6SuperBlockExt, EROFS_BLOCK_BITS_9, EROFS_BLOCK_SIZE_4096, EROFS_BLOCK_SIZE_512,
    EROFS_DEVTABLE_OFFSET, EROFS_INODE_CHUNK_BASED, EROFS_INODE_FLAT_INLINE,
    EROFS_INODE_FLAT_PLAIN, EROFS_INODE_SLOT_SIZE, EROFS_SUPER_BLOCK_SIZE, EROFS_SUPER_OFFSET,
};
use nydus_rafs::metadata::RafsStore;
use nydus_rafs::RafsIoWrite;
use nydus_storage::device::BlobFeatures;
use nydus_utils::{root_tracer, round_down, round_up, timing_tracer};

use super::chunk_dict::DigestWithBlobIndex;
use super::node::Node;
use crate::{Bootstrap, BootstrapContext, BuildContext, ConversionType, Tree};

const WRITE_PADDING_DATA: [u8; 4096] = [0u8; 4096];
const V6_BLOCK_SEG_ALIGNMENT: u64 = 0x8_0000;

// Rafs v6 dedicated methods
impl Node {
    /// Dump RAFS v6 inode metadata to meta blob.
    pub fn dump_bootstrap_v6(
        &mut self,
        ctx: &mut BuildContext,
        f_bootstrap: &mut dyn RafsIoWrite,
        orig_meta_addr: u64,
        meta_addr: u64,
        chunk_cache: &mut BTreeMap<DigestWithBlobIndex, Arc<ChunkWrapper>>,
    ) -> Result<()> {
        let xattr_inline_count = self.info.xattrs.count_v6();
        ensure!(
            xattr_inline_count <= u16::MAX as usize,
            "size of extended attributes is too big"
        );
        let mut inode = new_v6_inode(
            &self.inode,
            self.v6_datalayout,
            xattr_inline_count as u16,
            self.v6_compact_inode,
        );

        let meta_offset = meta_addr - orig_meta_addr;
        // update all the inodes's offset according to the new 'meta_addr'.
        self.v6_offset += meta_offset;
        // The EROFS_INODE_FLAT_INLINE layout is valid for directory and symlink only,
        // so `dirents_offset` is useful for these two types too, otherwise `dirents_offset`
        // should always be zero.
        // Enforce the check to avoid overflow of `dirents_offset`.
        if self.is_dir() || self.is_symlink() {
            self.v6_dirents_offset += meta_offset;
        }
        let nid = calculate_nid(self.v6_offset, meta_addr);
        self.inode.set_ino(nid);

        if self.is_dir() {
            self.v6_dump_dir(ctx, f_bootstrap, meta_addr, meta_offset, &mut inode)?;
        } else if self.is_reg() {
            self.v6_dump_file(ctx, f_bootstrap, chunk_cache, &mut inode)?;
        } else if self.is_symlink() {
            self.v6_dump_symlink(ctx, f_bootstrap, &mut inode)?;
        } else {
            f_bootstrap
                .seek(SeekFrom::Start(self.v6_offset))
                .context("failed seek for dir inode")?;
            inode.store(f_bootstrap).context("failed to store inode")?;
            self.v6_store_xattrs(ctx, f_bootstrap)?;
        }

        Ok(())
    }

    /// Update whether compact mode can be used for this inode or not.
    pub fn v6_set_inode_compact(&mut self) {
        if self.info.v6_force_extended_inode
            || self.inode.uid() > u16::MAX as u32
            || self.inode.gid() > u16::MAX as u32
            || self.inode.nlink() > u16::MAX as u32
            || self.inode.size() > u32::MAX as u64
            || self.path().extension() == Some(OsStr::new("pyc"))
        {
            self.v6_compact_inode = false;
        } else {
            self.v6_compact_inode = true;
        }
    }

    /// Layout the normal inode (except directory inode) into the meta blob.
    pub fn v6_set_offset(
        &mut self,
        bootstrap_ctx: &mut BootstrapContext,
        v6_hardlink_offset: Option<u64>,
        block_size: u64,
    ) -> Result<()> {
        ensure!(!self.is_dir(), "{} is a directory", self.path().display());
        if self.is_reg() {
            if let Some(v6_hardlink_offset) = v6_hardlink_offset {
                self.v6_offset = v6_hardlink_offset;
            } else {
                let size = self.v6_size_with_xattr();
                let unit = size_of::<RafsV6InodeChunkAddr>() as u64;
                let total_size = round_up(size, unit) + self.inode.child_count() as u64 * unit;
                // First try to allocate from fragments of dirent pages.
                self.v6_offset = bootstrap_ctx.allocate_available_block(total_size, block_size);
                if self.v6_offset == 0 {
                    self.v6_offset = bootstrap_ctx.offset;
                    bootstrap_ctx.offset += total_size;
                }
            }
            self.v6_datalayout = EROFS_INODE_CHUNK_BASED;
        } else if self.is_symlink() {
            self.v6_set_offset_with_tail(bootstrap_ctx, self.inode.size(), block_size);
        } else {
            self.v6_offset = bootstrap_ctx.offset;
            bootstrap_ctx.offset += self.v6_size_with_xattr();
        }
        bootstrap_ctx.align_offset(EROFS_INODE_SLOT_SIZE as u64);

        Ok(())
    }

    /// Layout the directory inode and its dirents into meta blob.
    pub fn v6_set_dir_offset(
        &mut self,
        bootstrap_ctx: &mut BootstrapContext,
        d_size: u64,
        block_size: u64,
    ) -> Result<()> {
        ensure!(
            self.is_dir(),
            "{} is not a directory",
            self.path().display()
        );

        // Dir isize is the total bytes of 'dirents + names'.
        self.inode.set_size(d_size);
        self.v6_set_offset_with_tail(bootstrap_ctx, d_size, block_size);
        bootstrap_ctx.align_offset(EROFS_INODE_SLOT_SIZE as u64);

        Ok(())
    }

    /// Calculate space needed to store dirents of the directory inode.
    pub fn v6_dirent_size(&self, ctx: &mut BuildContext, tree: &Tree) -> Result<u64> {
        ensure!(self.is_dir(), "{} is not a directory", self);
        let block_size = ctx.v6_block_size();
        let mut d_size = 0;

        // Sort all children if "." and ".." are not at the head after sorting.
        if !tree.children.is_empty() && tree.children[0].name() < "..".as_bytes() {
            let mut children = Vec::with_capacity(tree.children.len() + 2);
            children.push(".".as_bytes());
            children.push("..".as_bytes());
            for child in tree.children.iter() {
                children.push(child.name());
            }
            children.sort_unstable();

            for c in children {
                // Use length in byte, instead of length in character.
                let len = c.len() + size_of::<RafsV6Dirent>();
                // erofs disk format requires dirent to be aligned to block size.
                if (d_size % block_size) + len as u64 > block_size {
                    d_size = round_up(d_size as u64, block_size);
                }
                d_size += len as u64;
            }
        } else {
            // Avoid sorting again if "." and ".." are at the head after sorting due to that
            // `tree.children` has already been sorted.
            d_size = (".".as_bytes().len()
                + size_of::<RafsV6Dirent>()
                + "..".as_bytes().len()
                + size_of::<RafsV6Dirent>()) as u64;
            for child in tree.children.iter() {
                let len = child.name().len() + size_of::<RafsV6Dirent>();
                // erofs disk format requires dirent to be aligned to block size.
                if (d_size % block_size) + len as u64 > block_size {
                    d_size = round_up(d_size as u64, block_size);
                }
                d_size += len as u64;
            }
        }

        Ok(d_size)
    }

    pub fn v6_size_with_xattr(&self) -> u64 {
        self.inode
            .get_inode_size_with_xattr(&self.info.xattrs, self.v6_compact_inode) as u64
    }

    // Layout symlink or directory inodes into the meta blob.
    //
    // For DIR inode, size is the total bytes of 'dirents + names'.
    // For symlink, size is the length of symlink name.
    fn v6_set_offset_with_tail(
        &mut self,
        bootstrap_ctx: &mut BootstrapContext,
        d_size: u64,
        block_size: u64,
    ) {
        //          |    avail       |
        // +--------+-----------+----+ +-----------------------+
        // |        |inode+tail | free |   dirents+names       |
        // |        |           |    | |                       |
        // +--------+-----------+----+ +-----------------------+
        //
        //          |    avail       |
        // +--------+-----------+----+ +-----------------------+ +---------+-------------+
        // |        |inode      | free |   dirents+names       | | tail    | free        |
        // |        |           |    | |                       | |         |             |
        // +--------+-----------+----+ +-----------------------+ +---------+-------------+
        //
        //
        //          |    avail       |
        // +--------+-----------+----+ +-----------------------+ +---------+-------------+
        // |        |     inode      + |   dirents+names       | | tail    | free        |
        // |        |                | |                       | |         |             |
        // +--------+-----------+----+ +-----------------------+ +---------+-------------+
        //
        //
        //          |    avail       |
        // +--------+----------------+ +--------------+--------+ +-----------------------+
        // |        |     inode      | |  inode+tail  | free   | | dirents+names         |
        // |        |                | |              |        | |                       |
        // +--------+----------------+ +--------------+--------+ +-----------------------+
        //          |         inode                   |
        //
        //          |    avail       |
        // +--------+----------------+ +--------------+--------+ +-----------------------+ +-------+---------------+
        // |        |     inode      | |  inode       | free   | | dirents+names         | | tail  |    free       |
        // |        |                | |              |        | |                       | |       |               |
        // +--------+----------------+ +--------------+--------+ +-----------------------+ +-------+---------------+
        //          |         inode                   |
        //
        //
        let inode_size = self.v6_size_with_xattr();
        let tail: u64 = d_size % block_size;

        // We use a simple inline strategy here:
        // If the inode size with xattr + tail data size <= EROFS_BLOCK_SIZE,
        // we choose to inline it.
        // Firstly, if it's bigger than EROFS_BLOCK_SIZE,
        // in most cases, we can assume that the tail data size is close to EROFS_BLOCK_SIZE,
        // in this condition, even if we don't inline the tail data, there won't be much waste.
        // Secondly, the `available_blocks` that we maintain in the `BootstrapCtx`,
        // since it contain only single blocks with some unused space, the available space can only
        // be smaller than EROFS_BLOCK_SIZE, therefore we can't use our used blocks to store the
        // inode plus the tail data bigger than EROFS_BLOCK_SIZE.
        let should_inline = tail != 0 && (inode_size + tail) <= block_size;

        // If should inline, we first try to allocate space for the inode together with tail data
        // using used blocks.
        // If no available used block exists, we try to allocate space from current block.
        // If current block doesn't have enough space, we append it to `available_blocks`,
        // and we allocate space from the next block.
        // For the remaining data, we allocate space for it sequentially.
        self.v6_datalayout = if should_inline {
            self.v6_offset = bootstrap_ctx.allocate_available_block(inode_size + tail, block_size);
            if self.v6_offset == 0 {
                let available = block_size - bootstrap_ctx.offset % block_size;
                if available < inode_size + tail {
                    bootstrap_ctx.append_available_block(bootstrap_ctx.offset, block_size);
                    bootstrap_ctx.align_offset(block_size);
                }

                self.v6_offset = bootstrap_ctx.offset;
                bootstrap_ctx.offset += inode_size + tail;
            }

            if d_size != tail {
                bootstrap_ctx.append_available_block(bootstrap_ctx.offset, block_size);
                bootstrap_ctx.align_offset(block_size);
            }
            self.v6_dirents_offset = bootstrap_ctx.offset;
            bootstrap_ctx.offset += round_down(d_size, block_size);

            EROFS_INODE_FLAT_INLINE
        } else {
            // Otherwise, we first try to allocate space for the inode from used blocks.
            // If no available used block exists, we allocate space sequentially.
            // Then we allocate space for all data.
            self.v6_offset = bootstrap_ctx.allocate_available_block(inode_size, block_size);
            if self.v6_offset == 0 {
                self.v6_offset = bootstrap_ctx.offset;
                bootstrap_ctx.offset += inode_size;
            }

            bootstrap_ctx.append_available_block(bootstrap_ctx.offset, block_size);
            bootstrap_ctx.align_offset(block_size);
            self.v6_dirents_offset = bootstrap_ctx.offset;
            bootstrap_ctx.offset += d_size;
            bootstrap_ctx.align_offset(block_size);

            EROFS_INODE_FLAT_PLAIN
        };

        trace!(
            "{:?} inode offset {} ctx offset {} d_size {} dirents_offset {} datalayout {}",
            self.name(),
            self.v6_offset,
            bootstrap_ctx.offset,
            d_size,
            self.v6_dirents_offset,
            self.v6_datalayout
        );
    }

    fn v6_store_xattrs(
        &mut self,
        ctx: &mut BuildContext,
        f_bootstrap: &mut dyn RafsIoWrite,
    ) -> Result<()> {
        if !self.info.xattrs.is_empty() {
            self.info
                .xattrs
                .store_v6(f_bootstrap)
                .context("failed to dump xattr to bootstrap")?;
            ctx.has_xattr = true;
        }
        Ok(())
    }

    fn v6_dump_dir(
        &mut self,
        ctx: &mut BuildContext,
        f_bootstrap: &mut dyn RafsIoWrite,
        meta_addr: u64,
        meta_offset: u64,
        inode: &mut Box<dyn RafsV6OndiskInode>,
    ) -> Result<()> {
        // the 1st 4k block after dir inode.
        let mut dirent_off = self.v6_dirents_offset;
        let blk_addr = ctx
            .v6_block_addr(dirent_off)
            .with_context(|| format!("failed to compute blk_addr for offset 0x{:x}", dirent_off))?;
        inode.set_u(blk_addr);
        self.v6_dump_inode(ctx, f_bootstrap, inode)
            .context("failed to dump inode for directory")?;

        // Dump dirents
        let mut dir_data: Vec<u8> = Vec::new();
        let mut entry_names = Vec::new();
        let mut dirents: Vec<(RafsV6Dirent, &OsString)> = Vec::new();
        let mut nameoff: u64 = 0;
        let mut used: u64 = 0;
        let block_size = ctx.v6_block_size();

        trace!(
            "{:?} self.dirents.len {}",
            self.target(),
            self.v6_dirents.len()
        );
        // fill dir blocks one by one
        for (offset, name, file_type) in self.v6_dirents.iter() {
            let len = name.as_bytes().len() + size_of::<RafsV6Dirent>();
            // write to bootstrap when it will exceed EROFS_BLOCK_SIZE
            if used + len as u64 > block_size {
                for (entry, name) in dirents.iter_mut() {
                    trace!("{:?} nameoff {}", name, nameoff);
                    entry.set_name_offset(nameoff as u16);
                    dir_data.extend(entry.as_ref());
                    entry_names.push(*name);
                    // Use length in byte, instead of length in character.
                    // Because some characters could occupy more than one byte.
                    nameoff += name.as_bytes().len() as u64;
                }
                for name in entry_names.iter() {
                    dir_data.extend(name.as_bytes());
                }

                f_bootstrap
                    .seek(SeekFrom::Start(dirent_off as u64))
                    .context("failed seek file position for writing dirent")?;
                f_bootstrap
                    .write(dir_data.as_slice())
                    .context("failed to write dirent data to meta blob")?;

                // track where we're going to write.
                dirent_off += round_up(used, block_size);
                used = 0;
                nameoff = 0;
                dir_data.clear();
                entry_names.clear();
                dirents.clear();
            }

            trace!(
                "name {:?} file type {} {:?}",
                *name,
                *file_type,
                RafsV6Dirent::file_type(*file_type)
            );
            let entry = RafsV6Dirent::new(
                calculate_nid(*offset + meta_offset, meta_addr),
                0,
                RafsV6Dirent::file_type(*file_type),
            );
            dirents.push((entry, name));

            nameoff += size_of::<RafsV6Dirent>() as u64;
            used += len as u64;
        }

        trace!(
            "{:?} used {} dir size {}",
            self.target(),
            used,
            self.inode.size()
        );
        // dump tail part if any
        if used > 0 {
            for (entry, name) in dirents.iter_mut() {
                trace!("{:?} tail nameoff {}", name, nameoff);
                entry.set_name_offset(nameoff as u16);
                dir_data.extend(entry.as_ref());
                entry_names.push(*name);
                nameoff += name.as_bytes().len() as u64;
            }
            for name in entry_names.iter() {
                dir_data.extend(name.as_bytes());
            }

            let tail_off = match self.v6_datalayout {
                EROFS_INODE_FLAT_INLINE => self.v6_offset + self.v6_size_with_xattr(),
                EROFS_INODE_FLAT_PLAIN => dirent_off,
                _ => bail!("unsupported RAFS v6 inode layout for directory"),
            };
            f_bootstrap
                .seek(SeekFrom::Start(tail_off as u64))
                .context("failed seek for dir inode")?;
            f_bootstrap
                .write(dir_data.as_slice())
                .context("failed to store dirents")?;
        }

        Ok(())
    }

    fn v6_dump_file(
        &mut self,
        ctx: &mut BuildContext,
        f_bootstrap: &mut dyn RafsIoWrite,
        chunk_cache: &mut BTreeMap<DigestWithBlobIndex, Arc<ChunkWrapper>>,
        inode: &mut Box<dyn RafsV6OndiskInode>,
    ) -> Result<()> {
        let mut is_continuous = true;
        let mut prev = None;

        // write chunk indexes, chunk contents has been written to blob file.
        let mut chunks: Vec<u8> = Vec::new();
        for chunk in self.chunks.iter() {
            let offset = chunk.inner.uncompressed_offset();
            let blk_addr = ctx.v6_block_addr(offset).with_context(|| {
                format!(
                    "failed to compute blk_addr for chunk with uncompressed offset 0x{:x}",
                    offset
                )
            })?;
            let blob_idx = chunk.inner.blob_index();
            let mut v6_chunk = RafsV6InodeChunkAddr::new();
            v6_chunk.set_blob_index(blob_idx);
            v6_chunk.set_blob_ci_index(chunk.inner.index());
            v6_chunk.set_block_addr(blk_addr);

            chunks.extend(v6_chunk.as_ref());
            chunk_cache.insert(
                DigestWithBlobIndex(*chunk.inner.id(), chunk.inner.blob_index() + 1),
                chunk.inner.clone(),
            );
            if let Some((prev_idx, prev_pos)) = prev {
                if prev_pos + ctx.chunk_size as u64 != offset || prev_idx != blob_idx {
                    is_continuous = false;
                }
            }
            prev = Some((blob_idx, offset));
        }

        // Special optimization to enable page cache sharing for EROFS.
        let chunk_size = if is_continuous && inode.size() > ctx.chunk_size as u64 {
            inode.size().next_power_of_two()
        } else {
            ctx.chunk_size as u64
        };
        let info = RafsV6InodeChunkHeader::new(chunk_size, ctx.v6_block_size());
        inode.set_u(info.to_u32());
        self.v6_dump_inode(ctx, f_bootstrap, inode)
            .context("failed to dump inode for file")?;

        let unit = size_of::<RafsV6InodeChunkAddr>() as u64;
        let offset = align_offset(self.v6_offset + self.v6_size_with_xattr(), unit);
        f_bootstrap
            .seek(SeekFrom::Start(offset))
            .with_context(|| format!("failed to seek to 0x{:x} for writing chunk data", offset))?;
        f_bootstrap
            .write(chunks.as_slice())
            .context("failed to write chunk data for file")?;

        Ok(())
    }

    fn v6_dump_symlink(
        &mut self,
        ctx: &mut BuildContext,
        f_bootstrap: &mut dyn RafsIoWrite,
        inode: &mut Box<dyn RafsV6OndiskInode>,
    ) -> Result<()> {
        let blk_addr = ctx.v6_block_addr(self.v6_dirents_offset)?;
        inode.set_u(blk_addr);
        self.v6_dump_inode(ctx, f_bootstrap, inode)
            .context("failed to dump inode for symlink")?;

        if let Some(symlink) = &self.info.symlink {
            let tail_off = match self.v6_datalayout {
                EROFS_INODE_FLAT_INLINE => self.v6_offset + self.v6_size_with_xattr(),
                EROFS_INODE_FLAT_PLAIN => self.v6_dirents_offset,
                _ => bail!("unsupported RAFS v5 inode layout for symlink"),
            };
            f_bootstrap
                .seek(SeekFrom::Start(tail_off))
                .context("failed seek for dir inode")?;
            f_bootstrap
                .write(symlink.as_bytes())
                .context("filed to store symlink")?;
        }

        Ok(())
    }

    fn v6_dump_inode(
        &mut self,
        ctx: &mut BuildContext,
        f_bootstrap: &mut dyn RafsIoWrite,
        inode: &mut Box<dyn RafsV6OndiskInode>,
    ) -> Result<()> {
        f_bootstrap
            .seek(SeekFrom::Start(self.v6_offset))
            .context("failed to seek file position for writing inode")?;
        inode
            .store(f_bootstrap)
            .context("failed to write inode to meta blob")?;
        self.v6_store_xattrs(ctx, f_bootstrap)
            .context("failed to write extended attributes for inode")
    }
}

impl BuildContext {
    pub fn v6_block_size(&self) -> u64 {
        if self.conversion_type == ConversionType::TarToTarfs {
            // Tar stream is 512-byte aligned.
            EROFS_BLOCK_SIZE_512
        } else {
            EROFS_BLOCK_SIZE_4096
        }
    }

    pub fn v6_block_addr(&self, offset: u64) -> Result<u32> {
        let blk_addr = offset / self.v6_block_size();
        if blk_addr > u32::MAX as u64 {
            bail!("v6 block address 0x{:x} is too big", blk_addr)
        } else {
            Ok(blk_addr as u32)
        }
    }
}

impl Bootstrap {
    pub(crate) fn v6_update_dirents(parent: &Tree, parent_offset: u64) {
        let mut node = parent.lock_node();
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

        let mut dirs: Vec<&Tree> = Vec::new();
        for child in parent.children.iter() {
            let child_node = child.lock_node();
            let entry = (
                child_node.v6_offset,
                OsStr::from_bytes(child.name()).to_owned(),
                child_node.inode.mode(),
            );
            node.v6_dirents.push(entry);
            if child_node.is_dir() {
                dirs.push(child);
            }
        }
        node.v6_dirents
            .sort_unstable_by(|a, b| a.1.as_os_str().cmp(b.1.as_os_str()));

        for dir in dirs {
            Self::v6_update_dirents(dir, node_offset);
        }
    }

    /// Dump bootstrap and blob file, return (Vec<blob_id>, blob_size)
    pub(crate) fn v6_dump(
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

        let block_size = ctx.v6_block_size();
        let blobs = blob_table.get_all();
        let devtable_len = blobs.len() * size_of::<RafsV6Device>();
        let blob_table_size = blob_table.size() as u64;
        let blob_table_offset = align_offset(
            (EROFS_DEVTABLE_OFFSET as u64) + devtable_len as u64,
            EROFS_BLOCK_SIZE_4096,
        );
        let blob_table_entries = blobs.len();
        assert!(blob_table_entries < u8::MAX as usize);
        trace!(
            "devtable len {} blob table offset {} blob table size {}",
            devtable_len,
            blob_table_offset,
            blob_table_size
        );

        let fs_prefetch_rule_count = ctx.prefetch.fs_prefetch_rule_count();
        let (prefetch_table_offset, prefetch_table_size) =
            // If blob_table_size equal to 0, there is no prefetch.
            if fs_prefetch_rule_count > 0 && blob_table_size > 0 {
                // Prefetch table is very close to blob devices table
                let offset = blob_table_offset + blob_table_size;
                // Each prefetched file has is nid of `u32` filled into prefetch table.
                let size = fs_prefetch_rule_count * size_of::<u32>() as u32;
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
        let root_node_offset = self.tree.lock_node().v6_offset;
        let orig_meta_addr = root_node_offset - EROFS_BLOCK_SIZE_4096;
        let meta_addr = if blob_table_size > 0 {
            align_offset(
                blob_table_offset + blob_table_size + prefetch_table_size as u64,
                EROFS_BLOCK_SIZE_4096,
            )
        } else {
            orig_meta_addr
        };
        let meta_offset = meta_addr - orig_meta_addr;
        let root_nid = calculate_nid(root_node_offset + meta_offset, meta_addr);

        // Prepare extended super block
        let mut ext_sb = RafsV6SuperBlockExt::new();
        ext_sb.set_compressor(ctx.compressor);
        ext_sb.set_digester(ctx.digester);
        ext_sb.set_cipher(ctx.cipher);
        ext_sb.set_chunk_size(ctx.chunk_size);
        ext_sb.set_blob_table_offset(blob_table_offset);
        ext_sb.set_blob_table_size(blob_table_size as u32);

        // collect all chunks in this bootstrap.
        // HashChunkDict cannot be used here, because there will be duplicate chunks between layers,
        // but there is no deduplication during the actual construction.
        // Each layer uses the corresponding chunk in the blob of its own layer.
        // If HashChunkDict is used here, it will cause duplication. The chunks are removed,
        // resulting in incomplete chunk info.
        let mut chunk_cache = BTreeMap::new();

        // Dump bootstrap
        timing_tracer!(
            {
                self.tree.walk_bfs(true, &mut |n| {
                    n.lock_node().dump_bootstrap_v6(
                        ctx,
                        bootstrap_ctx.writer.as_mut(),
                        orig_meta_addr,
                        meta_addr,
                        &mut chunk_cache,
                    )
                })
            },
            "dump_bootstrap"
        )?;
        Self::v6_align_to_4k(bootstrap_ctx)?;

        // `Node` offset might be updated during above inodes dumping. So `get_prefetch_table` after it.
        if prefetch_table_size > 0 {
            let prefetch_table = ctx.prefetch.get_v6_prefetch_table(meta_addr);
            if let Some(mut pt) = prefetch_table {
                assert!(pt.len() * size_of::<u32>() <= prefetch_table_size as usize);
                // Device slots are very close to extended super block.
                ext_sb.set_prefetch_table_offset(prefetch_table_offset);
                ext_sb.set_prefetch_table_size(prefetch_table_size);
                bootstrap_ctx
                    .writer
                    .seek_offset(prefetch_table_offset as u64)
                    .context("failed seek prefetch table offset")?;
                pt.store(bootstrap_ctx.writer.as_mut()).unwrap();
            }
        }

        // TODO: get rid of the chunk info array.
        // Dump chunk info array.
        let chunk_table_offset = bootstrap_ctx
            .writer
            .seek_to_end()
            .context("failed to seek to bootstrap's end for chunk table")?;
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
        Self::v6_align_to_4k(bootstrap_ctx)?;

        // Prepare device slots.
        let mut pos = bootstrap_ctx
            .writer
            .seek_to_end()
            .context("failed to seek to bootstrap's end for chunk table")?;
        assert_eq!(pos % block_size, 0);
        let mut devtable: Vec<RafsV6Device> = Vec::new();
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
            } else if entry.uncompressed_size() / block_size > u32::MAX as u64 {
                bail!(format!(
                    "uncompressed blob size (0x:{:x}) is too big",
                    entry.uncompressed_size()
                ));
            }
            if !entry.has_feature(BlobFeatures::INLINED_CHUNK_DIGEST) {
                inlined_chunk_digest = false;
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

        // Dump super block
        let mut sb = RafsV6SuperBlock::new();
        if ctx.conversion_type == ConversionType::TarToTarfs {
            sb.set_block_bits(EROFS_BLOCK_BITS_9);
        }
        sb.set_inos(bootstrap_ctx.get_next_ino() - 1);
        sb.set_blocks(block_count);
        sb.set_root_nid(root_nid as u16);
        sb.set_meta_addr(meta_addr);
        sb.set_extra_devices(blob_table_entries as u16);
        bootstrap_ctx.writer.seek(SeekFrom::Start(0))?;
        sb.store(bootstrap_ctx.writer.as_mut())
            .context("failed to store SB")?;

        // Dump extended super block.
        if ctx.explicit_uidgid {
            ext_sb.set_explicit_uidgid();
        }
        if ctx.has_xattr {
            ext_sb.set_has_xattr();
        }
        if inlined_chunk_digest {
            ext_sb.set_inlined_chunk_digest();
        }
        if ctx.conversion_type == ConversionType::TarToTarfs {
            ext_sb.set_tarfs_mode();
        }
        bootstrap_ctx
            .writer
            .seek_offset((EROFS_SUPER_OFFSET + EROFS_SUPER_BLOCK_SIZE) as u64)
            .context("failed to seek for extended super block")?;
        ext_sb
            .store(bootstrap_ctx.writer.as_mut())
            .context("failed to store extended super block")?;

        // Dump device slots.
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

        Ok(())
    }

    fn v6_align_to_4k(bootstrap_ctx: &mut BootstrapContext) -> Result<()> {
        bootstrap_ctx
            .writer
            .flush()
            .context("failed to flush bootstrap")?;
        let pos = bootstrap_ctx
            .writer
            .seek_to_end()
            .context("failed to seek to bootstrap's end for chunk table")?;
        let padding = align_offset(pos, EROFS_BLOCK_SIZE_4096) - pos;
        bootstrap_ctx
            .writer
            .write_all(&WRITE_PADDING_DATA[0..padding as usize])
            .context("failed to write 0 to padding of bootstrap's end for chunk table")?;
        bootstrap_ctx
            .writer
            .flush()
            .context("failed to flush bootstrap")?;
        Ok(())
    }

    pub fn v6_align_mapped_blkaddr(block_size: u64, addr: u64) -> Result<u32> {
        match addr.checked_add(V6_BLOCK_SEG_ALIGNMENT - 1) {
            None => bail!("address 0x{:x} is too big", addr),
            Some(v) => {
                let v = (v & !(V6_BLOCK_SEG_ALIGNMENT - 1)) / block_size;
                if v > u32::MAX as u64 {
                    bail!("address 0x{:x} is too big", addr);
                } else {
                    Ok(v as u32)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArtifactStorage, BootstrapContext, Overlay};
    use nydus_rafs::metadata::layout::v6::{EROFS_INODE_CHUNK_BASED, EROFS_INODE_SLOT_SIZE};
    use nydus_rafs::metadata::{RafsVersion, RAFS_DEFAULT_CHUNK_SIZE};
    use std::fs::File;
    use vmm_sys_util::{tempdir::TempDir, tempfile::TempFile};

    #[test]
    fn test_set_v6_offset() {
        let pa = TempDir::new().unwrap();
        let pa_aa = TempFile::new_in(pa.as_path()).unwrap();
        let mut node = Node::from_fs_object(
            RafsVersion::V6,
            pa.as_path().to_path_buf(),
            pa_aa.as_path().to_path_buf(),
            Overlay::UpperAddition,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            false,
            false,
        )
        .unwrap();

        let bootstrap_path = TempFile::new().unwrap();
        let storage = ArtifactStorage::SingleFile(bootstrap_path.as_path().to_path_buf());
        let mut bootstrap_ctx = BootstrapContext::new(Some(storage), false).unwrap();
        bootstrap_ctx.offset = 0;

        // reg file.
        // "1" is used only for testing purpose, in practice
        // it's always aligned to 32 bytes.
        node.v6_set_offset(&mut bootstrap_ctx, None, EROFS_BLOCK_SIZE_4096)
            .unwrap();
        assert_eq!(node.v6_offset, 0);
        assert_eq!(node.v6_datalayout, EROFS_INODE_CHUNK_BASED);
        assert!(node.v6_compact_inode);
        assert_eq!(bootstrap_ctx.offset, 32);

        // symlink and dir are handled in the same way.
        let mut dir_node = Node::from_fs_object(
            RafsVersion::V6,
            pa.as_path().to_path_buf(),
            pa.as_path().to_path_buf(),
            Overlay::UpperAddition,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            false,
            false,
        )
        .unwrap();

        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 4064, EROFS_BLOCK_SIZE_4096)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_INLINE);
        assert_eq!(dir_node.v6_offset, 4096);
        assert_eq!(bootstrap_ctx.offset, 8192);

        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 4096, EROFS_BLOCK_SIZE_4096)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_PLAIN);
        assert_eq!(dir_node.v6_offset, 32);
        assert_eq!(dir_node.v6_dirents_offset, 8192);
        assert_eq!(bootstrap_ctx.offset, 8192 + 4096);

        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 8160, EROFS_BLOCK_SIZE_4096)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_INLINE);
        assert_eq!(dir_node.v6_offset, 8192 + 4096);
        assert_eq!(dir_node.v6_dirents_offset, 8192 + 4096 + 4096);
        assert_eq!(bootstrap_ctx.offset, 8192 + 4096 + 8192);

        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 8161, EROFS_BLOCK_SIZE_4096)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_PLAIN);
        assert_eq!(dir_node.v6_offset, 64);
        assert_eq!(dir_node.v6_dirents_offset, 8192 + 4096 + 8192);
        assert_eq!(bootstrap_ctx.offset, 8192 + 4096 + 8192 + 8192);

        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 4096 + 3968, EROFS_BLOCK_SIZE_4096)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_INLINE);
        assert_eq!(dir_node.v6_offset, 96);
        assert_eq!(dir_node.v6_dirents_offset, 8192 + 4096 + 8192 + 8192);
        assert_eq!(bootstrap_ctx.offset, 8192 + 4096 + 8192 + 8192 + 4096);

        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 4096 + 2048, EROFS_BLOCK_SIZE_4096)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_INLINE);
        assert_eq!(dir_node.v6_offset, 8192 + 4096 + 8192 + 8192 + 4096);
        assert_eq!(
            dir_node.v6_dirents_offset,
            8192 + 4096 + 8192 + 8192 + 4096 + 4096
        );
        assert_eq!(
            bootstrap_ctx.offset,
            8192 + 4096 + 8192 + 8192 + 4096 + 8192
        );

        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 1985, EROFS_BLOCK_SIZE_4096)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_INLINE);
        assert_eq!(dir_node.v6_offset, 8192 + 4096 + 8192 + 8192 + 4096 + 8192);
        assert_eq!(
            bootstrap_ctx.offset,
            8192 + 4096 + 8192 + 8192 + 4096 + 8192 + 32 + 1985 + 31
        );

        bootstrap_ctx.align_offset(EROFS_INODE_SLOT_SIZE as u64);
        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 1984, EROFS_BLOCK_SIZE_4096)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_INLINE);
        assert_eq!(
            dir_node.v6_offset,
            8192 + 4096 + 8192 + 8192 + 4096 + 2048 + 32
        );
        assert_eq!(
            bootstrap_ctx.offset,
            8192 + 4096 + 8192 + 8192 + 4096 + 8192 + round_up(32 + 1985, 32)
        );
    }

    #[test]
    fn test_set_v6_inode_compact() {
        let pa = TempDir::new().unwrap();
        let pa_reg = TempFile::new_in(pa.as_path()).unwrap();
        let pa_pyc = pa.as_path().join("foo.pyc");
        let _ = File::create(&pa_pyc).unwrap();

        let reg_node = Node::from_fs_object(
            RafsVersion::V6,
            pa.as_path().to_path_buf(),
            pa_reg.as_path().to_path_buf(),
            Overlay::UpperAddition,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            false,
            false,
        )
        .unwrap();

        assert!(reg_node.v6_compact_inode);

        let pyc_node = Node::from_fs_object(
            RafsVersion::V6,
            pa.as_path().to_path_buf(),
            pa_pyc.as_path().to_path_buf(),
            Overlay::UpperAddition,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            false,
            false,
        )
        .unwrap();

        assert!(!pyc_node.v6_compact_inode);

        std::fs::remove_file(&pa_pyc).unwrap();
    }
}
