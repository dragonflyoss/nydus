// Copyright 2020-2021 Ant Group. All rights reserved.
// Copyright (C) 2020-2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use std::fmt::Debug;
use std::io::Result;
use std::io::SeekFrom;
use std::mem::size_of;

use crate::metadata::RafsStore;
use crate::{impl_bootstrap_converter, RafsIoReader, RafsIoWriter};
use nydus_utils::div_round_up;

/// indicate chunk blkbits, thus 'chunksize = blocksize << chunk blkbits'
pub const EROFS_CHUNK_FORMAT_BLKBITS_MASK: u16 = 0x001F;
/// with chunk indexes or just a 4-byte blkaddr array
pub const EROFS_CHUNK_FORMAT_INDEXES: u16 = 0x0020;

pub const EROFS_SUPER_MAGIC_V1: u32 = 0xE0F5_E1E2;
pub const EROFS_ISLOTBITS: u8 = 5;
pub const EROFS_LOG_BLOCK_SIZE: u8 = 12;
pub const EROFS_BLKSIZE: usize = 1 << EROFS_LOG_BLOCK_SIZE;
pub const EROFS_SLOTSIZE: usize = 1 << EROFS_ISLOTBITS;

pub const EROFS_FEATURE_COMPAT_SB_CHKSUM: u32 = 0x0000_0001;
pub const EROFS_FEATURE_INCOMPAT_CHUNKED_FILE: u32 = 0x0000_0004;
pub const EROFS_FEATURE_INCOMPAT_DEVICE_TABLE: u32 = 0x0000_0008;

pub const EROFS_SUPER_OFFSET: u16 = 1024;
pub const EROFS_SUPER_BLOCK_SIZE: u16 = 128;

/// RAFS v6 superblock on-disk format, 128 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RafsV6SuperBlock {
    /// file system magic number
    pub s_magic: u32,
    /// crc32c(super_block), ignored
    pub s_checksum: u32,
    /// EROFS_FEATURE_COMPAT_SB_CHKSUM
    pub s_feature_compat: u32,
    /// support block_size == PAGE_SIZE only
    /// blkszbits = 12, block_size = 4096
    pub s_blkszbits: u8,
    /// superblock size = 128 + sb_extslots * 16, ignored
    pub s_extslots: u8,
    /// nid of root directory
    /// indicate the root inode offset = meta_blkaddr * 4096 + root_nid * 32
    pub s_root_nid: u16,
    /// total valid ino # (== f_files - f_favail)
    pub s_inos: u64,
    /// image created time
    pub s_build_time: u64,
    pub s_build_time_nsec: u32,
    /// total size of file system in blocks, used for statfs
    pub s_blocks: u32,
    /// start block address of metadata area
    pub s_meta_blkaddr: u32,
    /// start block address of shared xattr area
    pub s_xattr_blkaddr: u32,
    /// 128-bit uuid for volume
    pub s_uuid: [u8; 16],
    /// volume name
    pub s_volume_name: [u8; 16],
    /// RAFS_V6_ALL_FEATURE_INCOMPAT
    pub s_feature_incompat: u32,
    pub s_u: u16,
    /// # of devices besides the primary device
    pub s_extra_devices: u16,
    /// startoff = devt_slotoff * devt_slotsize
    pub s_devt_slotoff: u16,
    pub s_reserved: [u8; 38],
}

impl_bootstrap_converter!(RafsV6SuperBlock);

impl RafsV6SuperBlock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }
}

impl RafsStore for RafsV6SuperBlock {
    fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        // println!(
        //     "SUPER_OFFSET {}",
        //     EROFS_SUPER_OFFSET + EROFS_SUPER_BLOCK_SIZE
        // );
        w.write_all(&[0u8; EROFS_SUPER_OFFSET as usize])?;
        w.write_all(self.as_ref())?;
        w.write_all(
            &[0u8; (EROFS_BLKSIZE - (EROFS_SUPER_OFFSET + EROFS_SUPER_BLOCK_SIZE) as usize)],
        )?;
        Ok(self.as_ref().len())
    }
}

impl Default for RafsV6SuperBlock {
    fn default() -> Self {
        Self {
            s_magic: u32::to_le(EROFS_SUPER_MAGIC_V1),
            s_checksum: u32::to_le(0),
            s_feature_compat: u32::to_le(0),
            s_blkszbits: EROFS_LOG_BLOCK_SIZE,
            s_extslots: 0u8,
            s_root_nid: u16::to_le(0),
            s_inos: u64::to_le(0),
            s_build_time: u64::to_le(0),
            s_build_time_nsec: u32::to_le(0),
            s_blocks: u32::to_le(1),
            s_meta_blkaddr: u32::to_le(0),
            s_xattr_blkaddr: u32::to_le(0),
            s_uuid: [0u8; 16],
            s_volume_name: [0u8; 16],
            s_feature_incompat: u32::to_le(
                EROFS_FEATURE_INCOMPAT_CHUNKED_FILE | EROFS_FEATURE_INCOMPAT_DEVICE_TABLE,
            ),
            s_u: u16::to_le(0),
            s_extra_devices: u16::to_le(0),
            s_devt_slotoff: u16::to_le(0),
            s_reserved: [0u8; 38],
        }
    }
}

/// Rafs v6 on-disk inode format

/// 32-byte on-disk inode
pub const EROFS_INODE_LAYOUT_COMPACT: u16 = 0;
/// 64-byte on-disk inode
pub const EROFS_INODE_LAYOUT_EXTENDED: u16 = 1;

/// inode layout definition
pub const EROFS_INODE_FLAT_PLAIN: u16 = 0;
pub const EROFS_INODE_FLAT_DONTCARE0: u16 = 1;
pub const EROFS_INODE_FLAT_INLINE: u16 = 2;
pub const EROFS_INODE_FLAT_DONTCARE1: u16 = 3;
pub const EROFS_INODE_FLAT_CHUNK_BASED: u16 = 4;

#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum EROFS_FILE_TYPE {
    EROFS_FT_UNKNOWN,
    EROFS_FT_REG_FILE,
    EROFS_FT_DIR,
    EROFS_FT_CHRDEV,
    EROFS_FT_BLKDEV,
    EROFS_FT_FIFO,
    EROFS_FT_SOCK,
    EROFS_FT_SYMLINK,
    EROFS_FT_MAX,
}

bitflags! {
    pub struct RafsV6InodeFormat: u16 {
        const EROFS_I_VERSION = 0x0001;
        const EROFS_I_DATALAYOUT = 0x0016;
        const EROFS_I_ALL = Self::EROFS_I_VERSION.bits | Self::EROFS_I_DATALAYOUT.bits;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct RafsV6InodeExtended {
    /// inode format hints
    pub i_format: u16,
    pub i_xattr_icount: u16,
    pub i_mode: u16,
    pub i_reserved: u16,
    pub i_size: u64,
    /// raw_blkaddr or rdev or rafs_v6_inode_chunk_info
    pub i_u: u32,
    pub i_ino: u32,
    pub i_uid: u32,
    pub i_gid: u32,
    pub i_mtime: u64,
    pub i_mtime_nsec: u32,
    pub i_nlink: u32,
    pub i_reserved2: [u8; 16],
}

impl RafsV6InodeExtended {
    pub fn new() -> Self {
        Self {
            i_format: u16::to_le(1 | (EROFS_INODE_FLAT_PLAIN << 1)),
            i_xattr_icount: u16::to_le(0),
            i_mode: u16::to_le(0),
            i_reserved: u16::to_le(0),
            i_size: u64::to_le(0),
            i_u: u32::to_le(0),
            i_ino: u32::to_le(0),
            i_uid: u32::to_le(0),
            i_gid: u32::to_le(0),
            i_mtime: u64::to_le(0),
            i_mtime_nsec: u32::to_le(0),
            i_nlink: u32::to_le(0),
            i_reserved2: [0u8; 16],
        }
    }

    pub fn set_uidgid(&mut self, uidgid: (u32, u32)) {
        self.i_uid = u32::to_le(uidgid.0);
        self.i_gid = u32::to_le(uidgid.1);
    }

    pub fn set_mtime(&mut self, mtime: (u64, u32)) {
        self.i_mtime = u64::to_le(mtime.0);
        self.i_mtime_nsec = u32::to_le(mtime.1);
    }

    pub fn set_data_layout(&mut self, data_layout: u16) {
        self.i_format = u16::to_le(1 | (data_layout << 1));
    }

    #[inline]
    pub fn set_inline_plain_layout(&mut self) {
        self.i_format = u16::to_le(1 | (EROFS_INODE_FLAT_PLAIN << 1));
    }

    #[inline]
    pub fn set_inline_inline_layout(&mut self) {
        self.i_format = u16::to_le(1 | (EROFS_INODE_FLAT_INLINE << 1));
    }

    #[inline]
    pub fn set_chunk_based_layout(&mut self) {
        self.i_format = u16::to_le(1 | (EROFS_INODE_FLAT_CHUNK_BASED << 1));
    }
}

impl_bootstrap_converter!(RafsV6InodeExtended);

impl RafsStore for RafsV6InodeExtended {
    fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        // println!(
        //     "INODE {} {}",
        //     w.seek(SeekFrom::Current(0))?,
        //     self.as_ref().len()
        // );
        // TODO: need to write xattr as well.
        w.write_all(self.as_ref())?;
        Ok(self.as_ref().len())
    }
}

/// dirent sorts in alphabet order, thus we can do binary search
#[repr(packed(2))]
#[derive(Default, Clone, Copy, Debug)]
pub struct RafsV6Dirent {
    /// node number, inode offset = meta_blkaddr * 4096 + nid * 32
    pub e_nid: u64,
    /// start offset of file name in the block
    pub e_nameoff: u16,
    /// file type
    pub e_file_type: u8,
    /// reserved
    pub e_reserved: u8,
}

impl_bootstrap_converter!(RafsV6Dirent);

impl RafsV6Dirent {
    pub fn new(nid: u64, nameoff: u16, file_type: u8) -> Self {
        Self {
            e_nid: u64::to_le(nid),
            e_nameoff: u16::to_le(nameoff),
            e_file_type: u8::to_le(file_type),
            e_reserved: u8::to_le(0),
        }
    }

    pub fn file_type(mode: u32) -> EROFS_FILE_TYPE {
        match mode {
            mode if mode & libc::S_IFMT == libc::S_IFREG => EROFS_FILE_TYPE::EROFS_FT_REG_FILE,
            mode if mode & libc::S_IFMT == libc::S_IFDIR => EROFS_FILE_TYPE::EROFS_FT_DIR,
            mode if mode & libc::S_IFMT == libc::S_IFCHR => EROFS_FILE_TYPE::EROFS_FT_CHRDEV,
            mode if mode & libc::S_IFMT == libc::S_IFBLK => EROFS_FILE_TYPE::EROFS_FT_BLKDEV,
            mode if mode & libc::S_IFMT == libc::S_IFIFO => EROFS_FILE_TYPE::EROFS_FT_FIFO,
            mode if mode & libc::S_IFMT == libc::S_IFSOCK => EROFS_FILE_TYPE::EROFS_FT_SOCK,
            mode if mode & libc::S_IFMT == libc::S_IFLNK => EROFS_FILE_TYPE::EROFS_FT_SYMLINK,
            _ => EROFS_FILE_TYPE::EROFS_FT_UNKNOWN,
        }
    }

    pub fn update_nameoff(&mut self, nameoff: u16) {
        assert_eq!(nameoff < EROFS_BLKSIZE as u16, true);
        self.e_nameoff = u16::to_le(nameoff);
    }
}

impl RafsStore for RafsV6Dirent {
    fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        w.write_all(self.as_ref())?;
        Ok(self.as_ref().len())
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
pub struct RafsV6InodeChunkInfo {
    // chunk blkbits, etc.
    pub format: u16,
    pub reserved: u16,
}

impl RafsV6InodeChunkInfo {
    pub fn new(chunk_size: u32) -> Self {
        let chunk_bits = (chunk_size as f32).log2() as u32;
        let format = EROFS_CHUNK_FORMAT_INDEXES | (chunk_bits - EROFS_LOG_BLOCK_SIZE as u32) as u16;
        // TODO: liubo: sanity check format.
        Self {
            format: u16::to_le(format as u16),
            reserved: u16::to_le(0),
        }
    }
}

impl_bootstrap_converter!(RafsV6InodeChunkInfo);

/// 8-byte on-disk rafs v6 chunk indexes for kernel + nydus
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
pub struct RafsV6InodeChunkIndex {
    /// don't care for now?
    pub c_advise: u16,
    /// back-end storage id
    pub c_device_id: u16,
    /// start block address of this inode chunk
    pub c_blkaddr: u32,
}

impl RafsV6InodeChunkIndex {
    pub fn new() -> Self {
        Self {
            c_advise: u16::to_le(0),
            c_device_id: u16::to_le(0),
            c_blkaddr: u32::to_le(0),
        }
    }
}

impl_bootstrap_converter!(RafsV6InodeChunkIndex);

impl RafsStore for RafsV6InodeChunkIndex {
    fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        w.write_all(self.as_ref())?;
        Ok(self.as_ref().len())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RafsV6DeviceSlot {
    // blob digest (sha256)
    pub digest: u64,
    pub blocks: u32,
    pub mapped_blkaddr: u32,
    pub reserved: [u8; 56],
}

impl Default for RafsV6DeviceSlot {
    fn default() -> Self {
        Self {
            digest: u64::to_le(0),
            blocks: u32::to_le(0),
            mapped_blkaddr: u32::to_le(0),
            reserved: [0u8; 56],
        }
    }
}

impl RafsV6DeviceSlot {
    pub fn new() -> Self {
        Self::default()
    }
}

impl_bootstrap_converter!(RafsV6DeviceSlot);

impl RafsStore for RafsV6DeviceSlot {
    fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        w.write_all(self.as_ref())?;
        Ok(self.as_ref().len())
    }
}

pub fn align_offset(offset: u64, aligned_size: u64) -> u64 {
    div_round_up(offset, aligned_size) * aligned_size
}

pub fn lookup_nid(offset: u64, meta_addr: u64) -> u64 {
    (offset - meta_addr) >> EROFS_ISLOTBITS
}
