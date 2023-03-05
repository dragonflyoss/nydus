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
use nydus_utils::{div_round_up, round_down_4k, round_up};

use super::chunk_dict::DigestWithBlobIndex;
use super::node::Node;
use crate::builder::{BootstrapContext, BuildContext, Tree};
use crate::metadata::chunk::ChunkWrapper;
use crate::metadata::inode::new_v6_inode;
use crate::metadata::layout::v6::{
    align_offset, calculate_nid, RafsV6Dirent, RafsV6InodeChunkAddr, RafsV6InodeChunkHeader,
    RafsV6OndiskInode, EROFS_BLOCK_SIZE, EROFS_INODE_CHUNK_BASED, EROFS_INODE_FLAT_INLINE,
    EROFS_INODE_FLAT_PLAIN,
};
use crate::RafsIoWrite;

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
                self.v6_offset = bootstrap_ctx.allocate_available_block(total_size);
                if self.v6_offset == 0 {
                    self.v6_offset = bootstrap_ctx.offset;
                    bootstrap_ctx.offset += total_size;
                }
            }
            self.v6_datalayout = EROFS_INODE_CHUNK_BASED;
        } else if self.is_symlink() {
            self.v6_set_offset_with_tail(bootstrap_ctx, self.inode.size());
        } else {
            self.v6_offset = bootstrap_ctx.offset;
            bootstrap_ctx.offset += self.v6_size_with_xattr();
        }

        Ok(())
    }

    /// Layout the directory inode and its dirents into meta blob.
    pub fn v6_set_dir_offset(
        &mut self,
        bootstrap_ctx: &mut BootstrapContext,
        d_size: u64,
    ) -> Result<()> {
        ensure!(
            self.is_dir(),
            "{} is not a directory",
            self.path().display()
        );

        // Dir isize is the total bytes of 'dirents + names'.
        self.inode.set_size(d_size);
        self.v6_set_offset_with_tail(bootstrap_ctx, d_size);

        Ok(())
    }

    /// Calculate space needed to store dirents of the directory inode.
    pub fn v6_dirent_size(&self, tree: &Tree) -> Result<u64> {
        ensure!(self.is_dir(), "{} is not a directory", self);
        // Use length in byte, instead of length in character.
        let mut d_size: u64 = (".".as_bytes().len()
            + size_of::<RafsV6Dirent>()
            + "..".as_bytes().len()
            + size_of::<RafsV6Dirent>()) as u64;

        for child in tree.children.iter() {
            let len = child.node.name().as_bytes().len() + size_of::<RafsV6Dirent>();
            // erofs disk format requires dirent to be aligned with 4096.
            if (d_size % EROFS_BLOCK_SIZE) + len as u64 > EROFS_BLOCK_SIZE {
                d_size = div_round_up(d_size as u64, EROFS_BLOCK_SIZE) * EROFS_BLOCK_SIZE;
            }
            d_size += len as u64;
        }

        Ok(d_size)
    }

    fn v6_size_with_xattr(&self) -> u64 {
        self.inode
            .get_inode_size_with_xattr(&self.info.xattrs, self.v6_compact_inode) as u64
    }

    // Layout symlink or directory inodes into the meta blob.
    //
    // For DIR inode, size is the total bytes of 'dirents + names'.
    // For symlink, size is the length of symlink name.
    fn v6_set_offset_with_tail(&mut self, bootstrap_ctx: &mut BootstrapContext, d_size: u64) {
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
        let tail: u64 = d_size % EROFS_BLOCK_SIZE;

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
        let should_inline = tail != 0 && (inode_size + tail) <= EROFS_BLOCK_SIZE;

        // If should inline, we first try to allocate space for the inode together with tail data
        // using used blocks.
        // If no available used block exists, we try to allocate space from current block.
        // If current block doesn't have enough space, we append it to `available_blocks`,
        // and we allocate space from the next block.
        // For the remaining data, we allocate space for it sequentially.
        self.v6_datalayout = if should_inline {
            self.v6_offset = bootstrap_ctx.allocate_available_block(inode_size + tail);
            if self.v6_offset == 0 {
                let available = EROFS_BLOCK_SIZE - bootstrap_ctx.offset % EROFS_BLOCK_SIZE;
                if available < inode_size + tail {
                    bootstrap_ctx.append_available_block(bootstrap_ctx.offset);
                    bootstrap_ctx.align_offset(EROFS_BLOCK_SIZE);
                }

                self.v6_offset = bootstrap_ctx.offset;
                bootstrap_ctx.offset += inode_size + tail;
            }

            if d_size != tail {
                bootstrap_ctx.append_available_block(bootstrap_ctx.offset);
                bootstrap_ctx.align_offset(EROFS_BLOCK_SIZE);
            }
            self.v6_dirents_offset = bootstrap_ctx.offset;
            bootstrap_ctx.offset += round_down_4k(d_size);

            EROFS_INODE_FLAT_INLINE
        } else {
            // Otherwise, we first try to allocate space for the inode from used blocks.
            // If no available used block exists, we allocate space sequentially.
            // Then we allocate space for all data.
            self.v6_offset = bootstrap_ctx.allocate_available_block(inode_size);
            if self.v6_offset == 0 {
                self.v6_offset = bootstrap_ctx.offset;
                bootstrap_ctx.offset += inode_size;
            }

            bootstrap_ctx.append_available_block(bootstrap_ctx.offset);
            bootstrap_ctx.align_offset(EROFS_BLOCK_SIZE);
            self.v6_dirents_offset = bootstrap_ctx.offset;
            bootstrap_ctx.offset += d_size;
            bootstrap_ctx.align_offset(EROFS_BLOCK_SIZE);

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

        trace!(
            "{:?} self.dirents.len {}",
            self.target(),
            self.v6_dirents.len()
        );
        // fill dir blocks one by one
        for (offset, name, file_type) in self.v6_dirents.iter() {
            let len = name.len() + size_of::<RafsV6Dirent>();
            // write to bootstrap when it will exceed EROFS_BLOCK_SIZE
            if used + len as u64 > EROFS_BLOCK_SIZE {
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

                dir_data.clear();
                entry_names.clear();
                dirents.clear();
                nameoff = 0;
                used = 0;
                // track where we're going to write.
                dirent_off += EROFS_BLOCK_SIZE;
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
                nameoff += name.len() as u64;
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
        let info = RafsV6InodeChunkHeader::new(chunk_size);
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
        EROFS_BLOCK_SIZE
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{ArtifactStorage, BootstrapContext, Overlay};
    use crate::metadata::layout::v6::{EROFS_INODE_CHUNK_BASED, EROFS_INODE_SLOT_SIZE};
    use crate::metadata::{RafsVersion, RAFS_DEFAULT_CHUNK_SIZE};
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
        node.v6_set_offset(&mut bootstrap_ctx, None).unwrap();
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
            .v6_set_dir_offset(&mut bootstrap_ctx, 4064)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_INLINE);
        assert_eq!(dir_node.v6_offset, 4096);
        assert_eq!(bootstrap_ctx.offset, 8192);

        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 4096)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_PLAIN);
        assert_eq!(dir_node.v6_offset, 32);
        assert_eq!(dir_node.v6_dirents_offset, 8192);
        assert_eq!(bootstrap_ctx.offset, 8192 + 4096);

        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 8160)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_INLINE);
        assert_eq!(dir_node.v6_offset, 8192 + 4096);
        assert_eq!(dir_node.v6_dirents_offset, 8192 + 4096 + 4096);
        assert_eq!(bootstrap_ctx.offset, 8192 + 4096 + 8192);

        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 8161)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_PLAIN);
        assert_eq!(dir_node.v6_offset, 64);
        assert_eq!(dir_node.v6_dirents_offset, 8192 + 4096 + 8192);
        assert_eq!(bootstrap_ctx.offset, 8192 + 4096 + 8192 + 8192);

        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 4096 + 3968)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_INLINE);
        assert_eq!(dir_node.v6_offset, 96);
        assert_eq!(dir_node.v6_dirents_offset, 8192 + 4096 + 8192 + 8192);
        assert_eq!(bootstrap_ctx.offset, 8192 + 4096 + 8192 + 8192 + 4096);

        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 4096 + 2048)
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
            .v6_set_dir_offset(&mut bootstrap_ctx, 1985)
            .unwrap();
        assert_eq!(dir_node.v6_datalayout, EROFS_INODE_FLAT_INLINE);
        assert_eq!(dir_node.v6_offset, 8192 + 4096 + 8192 + 8192 + 4096 + 8192);
        assert_eq!(
            bootstrap_ctx.offset,
            8192 + 4096 + 8192 + 8192 + 4096 + 8192 + 32 + 1985
        );

        bootstrap_ctx.align_offset(EROFS_INODE_SLOT_SIZE as u64);
        dir_node
            .v6_set_dir_offset(&mut bootstrap_ctx, 1984)
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
