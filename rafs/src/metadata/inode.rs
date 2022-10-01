// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021-2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use nydus_utils::digest::RafsDigest;

use crate::metadata::cached_v5::CachedInodeV5;
use crate::metadata::chunk::ChunkWrapper;
use crate::metadata::direct_v5::OndiskInodeWrapper as OndiskInodeWrapperV5;
use crate::metadata::direct_v6::OndiskInodeWrapper as OndiskInodeWrapperV6;
use crate::metadata::layout::v5::{RafsV5ChunkInfo, RafsV5Inode, RafsV5InodeFlags};
use crate::metadata::{Inode, RafsVersion};
use crate::RafsInodeExt;

#[derive(Clone, Debug)]
pub enum InodeWrapper {
    V5(RafsV5Inode),
    // Reuse `RafsV5Inode` for v6 with a different wrapper to reduce duplicated code.
    V6(RafsV5Inode),
}

impl InodeWrapper {
    pub fn new(version: RafsVersion) -> Self {
        match version {
            RafsVersion::V5 => InodeWrapper::V5(RafsV5Inode::new()),
            RafsVersion::V6 => InodeWrapper::V6(RafsV5Inode::new()),
        }
    }

    pub fn from_inode_info(inode: &dyn RafsInodeExt) -> Self {
        if let Some(inode) = inode.as_any().downcast_ref::<CachedInodeV5>() {
            InodeWrapper::V5(to_rafsv5_inode(inode))
        } else if let Some(inode) = inode.as_any().downcast_ref::<OndiskInodeWrapperV5>() {
            InodeWrapper::V5(to_rafsv5_inode(inode))
        } else if let Some(inode) = inode.as_any().downcast_ref::<OndiskInodeWrapperV6>() {
            InodeWrapper::V6(to_rafsv5_inode(inode))
        } else {
            panic!("unknown inode information struct");
        }
    }

    pub fn inode_size(&self) -> usize {
        match self {
            InodeWrapper::V5(i) => i.size(),
            InodeWrapper::V6(i) => i.size(),
        }
    }

    pub fn mode(&self) -> u32 {
        match self {
            InodeWrapper::V5(i) => i.mode(),
            InodeWrapper::V6(i) => i.mode(),
        }
    }

    pub fn set_mode(&mut self, mode: u32) {
        match self {
            InodeWrapper::V5(i) => i.i_mode = mode,
            InodeWrapper::V6(i) => i.i_mode = mode,
        }
    }

    pub fn is_dir(&self) -> bool {
        match self {
            InodeWrapper::V5(i) => i.is_dir(),
            InodeWrapper::V6(i) => i.is_dir(),
        }
    }

    pub fn is_reg(&self) -> bool {
        match self {
            InodeWrapper::V5(i) => i.is_reg(),
            InodeWrapper::V6(i) => i.is_reg(),
        }
    }

    pub fn is_hardlink(&self) -> bool {
        match self {
            InodeWrapper::V5(i) => i.is_hardlink(),
            InodeWrapper::V6(i) => i.is_hardlink(),
        }
    }

    pub fn is_symlink(&self) -> bool {
        match self {
            InodeWrapper::V5(i) => i.is_symlink(),
            InodeWrapper::V6(i) => i.is_symlink(),
        }
    }

    pub fn is_chrdev(&self) -> bool {
        match self {
            InodeWrapper::V5(i) => i.i_mode & libc::S_IFMT as u32 == libc::S_IFCHR as u32,
            InodeWrapper::V6(i) => i.i_mode & libc::S_IFMT as u32 == libc::S_IFCHR as u32,
        }
    }

    pub fn is_blkdev(&self) -> bool {
        match self {
            InodeWrapper::V5(i) => i.i_mode & libc::S_IFMT as u32 == libc::S_IFBLK as u32,
            InodeWrapper::V6(i) => i.i_mode & libc::S_IFMT as u32 == libc::S_IFBLK as u32,
        }
    }

    pub fn is_fifo(&self) -> bool {
        match self {
            InodeWrapper::V5(i) => i.i_mode & libc::S_IFMT as u32 == libc::S_IFIFO as u32,
            InodeWrapper::V6(i) => i.i_mode & libc::S_IFMT as u32 == libc::S_IFIFO as u32,
        }
    }

    pub fn is_sock(&self) -> bool {
        match self {
            InodeWrapper::V5(i) => i.i_mode & libc::S_IFMT as u32 == libc::S_IFSOCK as u32,
            InodeWrapper::V6(i) => i.i_mode & libc::S_IFMT as u32 == libc::S_IFSOCK as u32,
        }
    }

    pub fn is_special(&self) -> bool {
        self.is_chrdev() || self.is_blkdev() || self.is_fifo() || self.is_sock()
    }

    pub fn has_xattr(&self) -> bool {
        match self {
            InodeWrapper::V5(i) => i.has_xattr(),
            InodeWrapper::V6(i) => i.has_xattr(),
        }
    }

    pub fn set_has_xattr(&mut self, enable: bool) {
        match self {
            InodeWrapper::V5(i) => {
                if enable {
                    i.i_flags |= RafsV5InodeFlags::XATTR;
                } else {
                    i.i_flags &= !RafsV5InodeFlags::XATTR;
                }
            }
            InodeWrapper::V6(i) => {
                if enable {
                    i.i_flags |= RafsV5InodeFlags::XATTR;
                } else {
                    i.i_flags &= !RafsV5InodeFlags::XATTR;
                }
            }
        }
    }

    pub fn ino(&self) -> Inode {
        match self {
            InodeWrapper::V5(i) => i.i_ino,
            InodeWrapper::V6(i) => i.i_ino,
        }
    }

    pub fn set_ino(&mut self, ino: Inode) {
        match self {
            InodeWrapper::V5(i) => i.i_ino = ino,
            InodeWrapper::V6(i) => i.i_ino = ino,
        }
    }

    pub fn parent(&self) -> Inode {
        match self {
            InodeWrapper::V5(i) => i.i_parent,
            InodeWrapper::V6(i) => i.i_parent,
        }
    }

    pub fn set_parent(&mut self, parent: Inode) {
        match self {
            InodeWrapper::V5(i) => i.i_parent = parent,
            InodeWrapper::V6(i) => i.i_parent = parent,
        }
    }

    pub fn size(&self) -> u64 {
        match self {
            InodeWrapper::V5(i) => i.i_size,
            InodeWrapper::V6(i) => i.i_size,
        }
    }

    pub fn set_size(&mut self, size: u64) {
        match self {
            InodeWrapper::V5(i) => i.i_size = size,
            InodeWrapper::V6(i) => i.i_size = size,
        }
    }

    pub fn uid(&self) -> u32 {
        match self {
            InodeWrapper::V5(i) => i.i_uid,
            InodeWrapper::V6(i) => i.i_uid,
        }
    }

    pub fn set_uid(&mut self, uid: u32) {
        match self {
            InodeWrapper::V5(i) => i.i_uid = uid,
            InodeWrapper::V6(i) => i.i_uid = uid,
        }
    }

    pub fn gid(&self) -> u32 {
        match self {
            InodeWrapper::V5(i) => i.i_gid,
            InodeWrapper::V6(i) => i.i_gid,
        }
    }

    pub fn set_gid(&mut self, gid: u32) {
        match self {
            InodeWrapper::V5(i) => i.i_gid = gid,
            InodeWrapper::V6(i) => i.i_gid = gid,
        }
    }

    pub fn mtime(&self) -> u64 {
        match self {
            InodeWrapper::V5(i) => i.i_mtime,
            InodeWrapper::V6(i) => i.i_mtime,
        }
    }

    pub fn set_mtime(&mut self, mtime: u64) {
        match self {
            InodeWrapper::V5(i) => i.i_mtime = mtime,
            InodeWrapper::V6(i) => i.i_mtime = mtime,
        }
    }

    pub fn mtime_nsec(&self) -> u32 {
        match self {
            InodeWrapper::V5(i) => i.i_mtime_nsec,
            InodeWrapper::V6(i) => i.i_mtime_nsec,
        }
    }

    pub fn set_mtime_nsec(&mut self, mtime_nsec: u32) {
        match self {
            InodeWrapper::V5(i) => i.i_mtime_nsec = mtime_nsec,
            InodeWrapper::V6(i) => i.i_mtime_nsec = mtime_nsec,
        }
    }

    pub fn blocks(&self) -> u64 {
        match self {
            InodeWrapper::V5(i) => i.i_blocks,
            InodeWrapper::V6(i) => i.i_blocks,
        }
    }

    pub fn set_blocks(&mut self, blocks: u64) {
        match self {
            InodeWrapper::V5(i) => i.i_blocks = blocks,
            InodeWrapper::V6(i) => i.i_blocks = blocks,
        }
    }

    pub fn set_rdev(&mut self, rdev: u32) {
        match self {
            InodeWrapper::V5(i) => i.i_rdev = rdev,
            InodeWrapper::V6(i) => i.i_rdev = rdev,
        }
    }

    pub fn set_projid(&mut self, projid: u32) {
        match self {
            InodeWrapper::V5(i) => i.i_projid = projid,
            InodeWrapper::V6(i) => i.i_projid = projid,
        }
    }

    pub fn nlink(&self) -> u32 {
        match self {
            InodeWrapper::V5(i) => i.i_nlink,
            InodeWrapper::V6(i) => i.i_nlink,
        }
    }

    pub fn set_nlink(&mut self, nlink: u32) {
        match self {
            InodeWrapper::V5(i) => i.i_nlink = nlink,
            InodeWrapper::V6(i) => i.i_nlink = nlink,
        }
    }

    pub fn digest(&self) -> &RafsDigest {
        match self {
            InodeWrapper::V5(i) => &i.i_digest,
            InodeWrapper::V6(i) => &i.i_digest,
        }
    }

    pub fn set_digest(&mut self, digest: RafsDigest) {
        match self {
            InodeWrapper::V5(i) => i.i_digest = digest,
            InodeWrapper::V6(i) => i.i_digest = digest,
        }
    }

    pub fn name_size(&self) -> u16 {
        match self {
            InodeWrapper::V5(i) => i.i_name_size,
            InodeWrapper::V6(i) => i.i_name_size,
        }
    }

    pub fn set_name_size(&mut self, size: usize) {
        debug_assert!(size < u16::MAX as usize);
        match self {
            InodeWrapper::V5(i) => i.i_name_size = size as u16,
            InodeWrapper::V6(i) => i.i_name_size = size as u16,
        }
    }

    pub fn symlink_size(&self) -> u16 {
        match self {
            InodeWrapper::V5(i) => i.i_symlink_size,
            InodeWrapper::V6(i) => i.i_symlink_size,
        }
    }

    pub fn set_symlink_size(&mut self, size: usize) {
        debug_assert!(size <= u16::MAX as usize);
        match self {
            InodeWrapper::V5(i) => {
                i.i_flags |= RafsV5InodeFlags::SYMLINK;
                i.i_symlink_size = size as u16;
            }
            InodeWrapper::V6(i) => {
                i.i_flags |= RafsV5InodeFlags::SYMLINK;
                i.i_symlink_size = size as u16;
            }
        }
    }

    pub fn child_index(&self) -> u32 {
        match self {
            InodeWrapper::V5(i) => i.i_child_index,
            InodeWrapper::V6(i) => i.i_child_index,
        }
    }

    pub fn set_child_index(&mut self, index: u32) {
        match self {
            InodeWrapper::V5(i) => i.i_child_index = index,
            InodeWrapper::V6(i) => i.i_child_index = index,
        }
    }

    pub fn child_count(&self) -> u32 {
        match self {
            InodeWrapper::V5(i) => i.i_child_count,
            InodeWrapper::V6(i) => i.i_child_count,
        }
    }

    pub fn set_child_count(&mut self, count: u32) {
        match self {
            InodeWrapper::V5(i) => i.i_child_count = count,
            InodeWrapper::V6(i) => i.i_child_count = count,
        }
    }

    pub fn create_chunk(&self) -> ChunkWrapper {
        match self {
            InodeWrapper::V5(_) => ChunkWrapper::V5(RafsV5ChunkInfo::new()),
            InodeWrapper::V6(_) => ChunkWrapper::V6(RafsV5ChunkInfo::new()),
        }
    }
}

/// Construct a `RafsV5Inode` object from a `Arc<dyn RafsInode>` object.
fn to_rafsv5_inode(inode: &dyn RafsInodeExt) -> RafsV5Inode {
    let attr = inode.get_attr();

    RafsV5Inode {
        i_digest: inode.get_digest(),
        i_parent: inode.parent(),
        i_ino: attr.ino,
        i_uid: attr.uid,
        i_gid: attr.gid,
        i_projid: inode.projid(),
        i_mode: attr.mode,
        i_size: attr.size,
        i_blocks: attr.blocks,
        i_flags: RafsV5InodeFlags::from_bits_truncate(inode.flags()),
        i_nlink: attr.nlink,
        i_child_index: inode.get_child_index().unwrap_or(0),
        i_child_count: inode.get_child_count(),
        i_name_size: inode.get_name_size(),
        i_symlink_size: inode.get_symlink_size(),
        i_rdev: attr.rdev,
        i_mtime_nsec: attr.mtimensec,
        i_mtime: attr.mtime,
        i_reserved: [0u8; 8],
    }
}
