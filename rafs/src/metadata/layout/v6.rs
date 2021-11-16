// Copyright 2020-2021 Ant Group. All rights reserved.
// Copyright (C) 2020-2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use std::fmt::Debug;
use std::io::{Read, Result};
use std::mem::size_of;
use std::sync::Arc;

use nydus_utils::{digest, round_up};

use crate::metadata::layout::v5::{rafsv5_align, RAFSV5_ALIGNMENT};
use crate::metadata::{RafsStore, RafsSuperFlags};
use crate::{impl_bootstrap_converter, impl_pub_getter_setter, RafsIoReader, RafsIoWriter};
use storage::compress;
use storage::device::{BlobFeatures, BlobInfo};
use storage::meta::BlobMetaHeaderOndisk;

/// EROFS metadata slot size.
pub const EROFS_INODE_SLOT_SIZE: usize = 1 << EROFS_INODE_SLOT_BITS;
/// EROFS logical block size.
pub const EROFS_BLOCK_SIZE: u64 = 1u64 << EROFS_BLOCK_BITS;
/// EROFS plain inode.
pub const EROFS_INODE_FLAT_PLAIN: u16 = 0;
/// EROFS inline inode.
pub const EROFS_INODE_FLAT_INLINE: u16 = 2;
/// EROFS chunked inode.
pub const EROFS_INODE_FLAT_CHUNK_BASED: u16 = 4;
/// EROFS device table offset.
pub const EROFS_DEVTABLE_OFFSET: u16 =
    EROFS_SUPER_OFFSET + EROFS_SUPER_BLOCK_SIZE + EROFS_EXT_SUPER_BLOCK_SIZE;

// Offset of EROFS super block.
const EROFS_SUPER_OFFSET: u16 = 1024;
// Size of EROFS super block.
const EROFS_SUPER_BLOCK_SIZE: u16 = 128;
// Size of extended super block, used for rafs v6 specific fields
const EROFS_EXT_SUPER_BLOCK_SIZE: u16 = 256;
// Magic number for EROFS super block.
const EROFS_SUPER_MAGIC_V1: u32 = 0xE0F5_E1E2;
// Bits of EROFS logical block size.
const EROFS_BLOCK_BITS: u8 = 12;
// Bits of EROFS metadata slot size.
const EROFS_INODE_SLOT_BITS: u8 = 5;
// 32-byte on-disk inode
#[allow(dead_code)]
const EROFS_INODE_LAYOUT_COMPACT: u16 = 0;
// 64-byte on-disk inode
const EROFS_INODE_LAYOUT_EXTENDED: u16 = 1;
// Bit flag indicating whether the inode is chunked or not.
const EROFS_CHUNK_FORMAT_INDEXES_FLAG: u16 = 0x0020;
// Encoded chunk size (log2(chunk_size) - EROFS_BLOCK_BITS).
const EROFS_CHUNK_FORMAT_SIZE_MASK: u16 = 0x001F;
/// Checksum of superblock, compatible with EROFS versions prior to Linux kernel 5.5.
#[allow(dead_code)]
const EROFS_FEATURE_COMPAT_SB_CHKSUM: u32 = 0x0000_0001;
/// Chunked inode, incompatible with EROFS versions prior to Linux kernel 5.15.
const EROFS_FEATURE_INCOMPAT_CHUNKED_FILE: u32 = 0x0000_0004;
/// Multi-devices, incompatible with EROFS versions prior to Linux kernel 5.16.
const EROFS_FEATURE_INCOMPAT_DEVICE_TABLE: u32 = 0x0000_0008;

const BLOB_SHA256_LEN: usize = 64;

/// RAFS v6 superblock on-disk format, 128 bytes.
///
/// The structure is designed to be compatible with EROFS superblock, so the in kernel EROFS file
/// system driver could be used to mount a RAFS v6 image.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RafsV6SuperBlock {
    /// File system magic number
    s_magic: u32,
    /// Crc32 checksum of the superblock, ignored by Rafs v6.
    s_checksum: u32,
    /// Compatible filesystem features.
    s_feature_compat: u32,
    /// Bits of block size. Only 12 is supported, thus block_size == PAGE_SIZE(4096).
    s_blkszbits: u8,
    /// Number of extended superblock slots, ignored by Rafs v6.
    /// `superblock size = 128(size of RafsV6SuperBlock) + s_extslots * 16`.
    s_extslots: u8,
    /// Nid of the root directory.
    /// `root inode offset = s_meta_blkaddr * 4096 + s_root_nid * 32`.
    s_root_nid: u16,
    /// Total valid ino #
    s_inos: u64,
    /// Timestamp of filesystem creation.
    s_build_time: u64,
    /// Timestamp of filesystem creation.
    s_build_time_nsec: u32,
    /// Total size of file system in blocks, used for statfs
    s_blocks: u32,
    /// Start block address of the metadata area.
    s_meta_blkaddr: u32,
    /// Start block address of the shared xattr area.
    s_xattr_blkaddr: u32,
    /// 128-bit uuid for volume
    s_uuid: [u8; 16],
    /// Volume name.
    s_volume_name: [u8; 16],
    /// Incompatible filesystem feature flags.
    s_feature_incompat: u32,
    /// A union of `u16` for miscellaneous usage.
    s_u: u16,
    /// # of devices besides the primary device.
    s_extra_devices: u16,
    /// Offset of the device table, `startoff = s_devt_slotoff * devt_slotsize`.
    s_devt_slotoff: u16,
    /// Padding.
    s_reserved: [u8; 38],
}

impl_bootstrap_converter!(RafsV6SuperBlock);

impl RafsV6SuperBlock {
    /// Create a new instance of `RafsV6SuperBlock`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a `RafsV6SuperBlock` from a reader.
    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        let mut buf1 = [0u8; EROFS_SUPER_OFFSET as usize];

        r.read_exact(&mut buf1)?;
        r.read_exact(self.as_mut())
        // we need to leave this to 2nd sb read.
        // let mut buf2 = [0u8; (EROFS_BLOCK_SIZE as usize
        //     - (EROFS_SUPER_OFFSET + EROFS_SUPER_BLOCK_SIZE) as usize)];
        // r.read_exact(&mut buf2)
    }

    /// Get maximum ino.
    pub fn set_inos(&mut self, inos: u64) {
        self.s_inos = inos.to_le();
    }

    /// Set number of logical blocks.
    pub fn set_blocks(&mut self, blocks: u32) {
        self.s_blocks = blocks.to_le();
    }

    /// Set EROFS root nid.
    pub fn set_root_nid(&mut self, nid: u16) {
        self.s_root_nid = nid.to_le();
    }

    /// Set EROFS meta block address.
    pub fn set_meta_addr(&mut self, meta_addr: u64) {
        self.s_meta_blkaddr = u32::to_le((meta_addr / EROFS_BLOCK_SIZE) as u32);
    }

    /// Set number of extra devices.
    pub fn set_extra_devices(&mut self, count: u16) {
        self.s_extra_devices = count.to_le();
    }

    /// Check whether it's super block for Rafs v6.
    pub fn is_rafs_v6(&self) -> bool {
        self.magic() == EROFS_SUPER_MAGIC_V1
    }

    /// Validate the Rafs v6 super block.
    pub fn validate(&self, _meta_size: u64) -> Result<()> {
        // TODO:
        Ok(())
    }

    impl_pub_getter_setter!(magic, set_magic, s_magic, u32);
}

impl RafsStore for RafsV6SuperBlock {
    fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        debug_assert!(((EROFS_SUPER_OFFSET + EROFS_SUPER_BLOCK_SIZE) as u64) < EROFS_BLOCK_SIZE);
        w.write_all(&[0u8; EROFS_SUPER_OFFSET as usize])?;
        w.write_all(self.as_ref())?;
        w.write_all(
            &[0u8; (EROFS_BLOCK_SIZE as usize
                - (EROFS_SUPER_OFFSET + EROFS_SUPER_BLOCK_SIZE) as usize)],
        )?;

        Ok(EROFS_BLOCK_SIZE as usize)
    }
}

impl Default for RafsV6SuperBlock {
    fn default() -> Self {
        Self {
            s_magic: u32::to_le(EROFS_SUPER_MAGIC_V1),
            s_checksum: u32::to_le(0),
            s_feature_compat: u32::to_le(0),
            s_blkszbits: EROFS_BLOCK_BITS,
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
            s_devt_slotoff: u16::to_le(EROFS_DEVTABLE_OFFSET / size_of::<RafsV6Device>() as u16),
            s_reserved: [0u8; 38],
        }
    }
}

/// Extended superblock, 256 bytes
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RafsV6SuperBlockExt {
    /// superblock flags
    pub s_flags: u64,
    /// where on disk blob table starts
    pub s_blob_table_offset: u64,
    /// blob table size
    pub s_blob_table_size: u32,
    /// chunk size
    pub s_chunk_size: u32,
    /// Reserved
    pub s_reserved: [u8; 232],
}

impl_bootstrap_converter!(RafsV6SuperBlockExt);

impl RafsV6SuperBlockExt {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.seek_to_offset((EROFS_SUPER_OFFSET + EROFS_SUPER_BLOCK_SIZE) as u64)?;
        r.read_exact(self.as_mut())
    }

    /// Validate the Rafs v6 super block.
    pub fn validate(&self, _meta_size: u64) -> Result<()> {
        // TODO:
        Ok(())
    }

    /// Set compression algorithm to handle chunk of the Rafs filesystem.
    pub fn set_compressor(&mut self, compressor: compress::Algorithm) {
        let c: RafsSuperFlags = compressor.into();

        self.s_flags &= !RafsSuperFlags::COMPRESS_NONE.bits();
        self.s_flags &= !RafsSuperFlags::COMPRESS_LZ4_BLOCK.bits();
        self.s_flags &= !RafsSuperFlags::COMPRESS_GZIP.bits();
        self.s_flags |= c.bits();
    }

    /// Set message digest algorithm to handle chunk of the Rafs filesystem.
    pub fn set_digester(&mut self, digester: digest::Algorithm) {
        let c: RafsSuperFlags = digester.into();

        self.s_flags &= !RafsSuperFlags::DIGESTER_BLAKE3.bits();
        self.s_flags &= !RafsSuperFlags::DIGESTER_SHA256.bits();
        self.s_flags |= c.bits();
    }

    impl_pub_getter_setter!(chunk_size, set_chunk_size, s_chunk_size, u32);
    impl_pub_getter_setter!(flags, set_flags, s_flags, u64);
    impl_pub_getter_setter!(
        blob_table_offset,
        set_blob_table_offset,
        s_blob_table_offset,
        u64
    );
    impl_pub_getter_setter!(blob_table_size, set_blob_table_size, s_blob_table_size, u32);
}

impl RafsStore for RafsV6SuperBlockExt {
    fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        w.seek_to_offset((EROFS_SUPER_OFFSET + EROFS_SUPER_BLOCK_SIZE) as u64)?;
        w.write_all(self.as_ref())?;
        w.write_all(
            &[0u8; (EROFS_BLOCK_SIZE as usize
                - (EROFS_SUPER_OFFSET + EROFS_SUPER_BLOCK_SIZE + EROFS_EXT_SUPER_BLOCK_SIZE)
                    as usize)],
        )?;
        Ok(self.as_ref().len())
    }
}

impl Default for RafsV6SuperBlockExt {
    fn default() -> Self {
        Self {
            s_flags: u64::to_le(0),
            s_blob_table_offset: u64::to_le(0),
            s_blob_table_size: u32::to_le(0),
            s_chunk_size: u32::to_le(0),
            s_reserved: [0u8; 232],
        }
    }
}

/// Type of EROFS inodes.
#[repr(u8)]
#[allow(non_camel_case_types, dead_code)]
enum EROFS_FILE_TYPE {
    /// Unknown file type.
    EROFS_FT_UNKNOWN,
    /// Regular file.
    EROFS_FT_REG_FILE,
    /// Directory.
    EROFS_FT_DIR,
    /// Character device.
    EROFS_FT_CHRDEV,
    /// Block device.
    EROFS_FT_BLKDEV,
    /// FIFO pipe.
    EROFS_FT_FIFO,
    /// Socket.
    EROFS_FT_SOCK,
    /// Symlink.
    EROFS_FT_SYMLINK,
    /// Maximum value of file type.
    EROFS_FT_MAX,
}

/// RAFS v6 inode on-disk format, 64 bytes.
///
/// This structure is designed to be compatible with EROFS extended inode format.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct RafsV6InodeExtended {
    /// Layout format for of the inode.
    i_format: u16,
    /// TODO: doc
    i_xattr_icount: u16,
    /// Protection mode.
    i_mode: u16,
    i_reserved: u16,
    /// Size of the file content.
    i_size: u64,
    /// A `u32` union: raw_blkaddr or rdev or rafs_v6_inode_chunk_info
    i_u: u32,
    /// Inode number.
    i_ino: u32,
    /// User ID of owner.
    i_uid: u32,
    /// Group ID of owner
    i_gid: u32,
    /// Time of last modification.
    i_mtime: u64,
    /// Time of last modification.
    i_mtime_nsec: u32,
    /// Number of hard links.
    i_nlink: u32,
    i_reserved2: [u8; 16],
}

impl RafsV6InodeExtended {
    /// Create a new instance of `RafsV6InodeExtended`.
    pub fn new() -> Self {
        Self {
            i_format: u16::to_le(EROFS_INODE_LAYOUT_EXTENDED | (EROFS_INODE_FLAT_PLAIN << 1)),
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

    /// Set file size for inode.
    pub fn set_size(&mut self, size: u64) {
        self.i_size = size.to_le();
    }

    /// Set ino for inode.
    pub fn set_ino(&mut self, ino: u32) {
        self.i_ino = ino.to_le();
    }

    /// Set number of hardlink.
    pub fn set_nlink(&mut self, nlinks: u32) {
        self.i_nlink = nlinks.to_le();
    }

    /// Set file protection mode.
    pub fn set_mode(&mut self, mode: u16) {
        self.i_mode = mode.to_le();
    }

    /// Set the union field.
    pub fn set_u(&mut self, u: u32) {
        self.i_u = u.to_le();
    }

    /// Set uid and gid for the inode.
    pub fn set_uidgid(&mut self, uid: u32, gid: u32) {
        self.i_uid = u32::to_le(uid);
        self.i_gid = u32::to_le(gid);
    }

    /// Set last modification time for the inode.
    pub fn set_mtime(&mut self, sec: u64, nsec: u32) {
        self.i_mtime = u64::to_le(sec);
        self.i_mtime_nsec = u32::to_le(nsec);
    }

    /// Set inode data layout format.
    pub fn set_data_layout(&mut self, data_layout: u16) {
        self.i_format = u16::to_le(EROFS_INODE_LAYOUT_EXTENDED | (data_layout << 1));
    }

    /// Set inode data layout format to be PLAIN.
    #[inline]
    pub fn set_inline_plain_layout(&mut self) {
        self.i_format = u16::to_le(EROFS_INODE_LAYOUT_EXTENDED | (EROFS_INODE_FLAT_PLAIN << 1));
    }

    /// Set inode data layout format to be INLINE.
    #[inline]
    pub fn set_inline_inline_layout(&mut self) {
        self.i_format = u16::to_le(EROFS_INODE_LAYOUT_EXTENDED | (EROFS_INODE_FLAT_INLINE << 1));
    }

    /// Set inode data layout format to be CHUNKED.
    #[inline]
    pub fn set_chunk_based_layout(&mut self) {
        self.i_format =
            u16::to_le(EROFS_INODE_LAYOUT_EXTENDED | (EROFS_INODE_FLAT_CHUNK_BASED << 1));
    }

    /// Load a `RafsV6InodeExtended` from a reader.
    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }
}

impl_bootstrap_converter!(RafsV6InodeExtended);

impl RafsStore for RafsV6InodeExtended {
    fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        // TODO: need to write xattr as well.
        w.write_all(self.as_ref())?;
        Ok(self.as_ref().len())
    }
}

/// Dirent sorted in alphabet order to improve performance by binary search.
#[repr(C, packed(2))]
#[derive(Default, Clone, Copy, Debug)]
pub struct RafsV6Dirent {
    /// Node number, inode offset = s_meta_blkaddr * 4096 + nid * 32
    e_nid: u64,
    /// start offset of file name in the block
    e_nameoff: u16,
    /// file type
    e_file_type: u8,
    /// reserved
    e_reserved: u8,
}

impl_bootstrap_converter!(RafsV6Dirent);

impl RafsV6Dirent {
    /// Create a new instance of `RafsV6Dirent`.
    pub fn new(nid: u64, nameoff: u16, file_type: u8) -> Self {
        Self {
            e_nid: u64::to_le(nid),
            e_nameoff: u16::to_le(nameoff),
            e_file_type: u8::to_le(file_type),
            e_reserved: u8::to_le(0),
        }
    }

    /// Get file type from file mode.
    pub fn file_type(mode: u32) -> u8 {
        let val = match mode {
            mode if mode & libc::S_IFMT == libc::S_IFREG => EROFS_FILE_TYPE::EROFS_FT_REG_FILE,
            mode if mode & libc::S_IFMT == libc::S_IFDIR => EROFS_FILE_TYPE::EROFS_FT_DIR,
            mode if mode & libc::S_IFMT == libc::S_IFCHR => EROFS_FILE_TYPE::EROFS_FT_CHRDEV,
            mode if mode & libc::S_IFMT == libc::S_IFBLK => EROFS_FILE_TYPE::EROFS_FT_BLKDEV,
            mode if mode & libc::S_IFMT == libc::S_IFIFO => EROFS_FILE_TYPE::EROFS_FT_FIFO,
            mode if mode & libc::S_IFMT == libc::S_IFSOCK => EROFS_FILE_TYPE::EROFS_FT_SOCK,
            mode if mode & libc::S_IFMT == libc::S_IFLNK => EROFS_FILE_TYPE::EROFS_FT_SYMLINK,
            _ => EROFS_FILE_TYPE::EROFS_FT_UNKNOWN,
        };

        val as u8
    }

    /// Set name offset of the dirent.
    pub fn set_name_offset(&mut self, offset: u16) {
        debug_assert!(offset < EROFS_BLOCK_SIZE as u16);
        self.e_nameoff = u16::to_le(offset);
    }

    /// Load a `RafsV6Dirent` from a reader.
    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }
}

impl RafsStore for RafsV6Dirent {
    fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        w.write_all(self.as_ref())?;

        Ok(self.as_ref().len())
    }
}

/// Rafs v6 ChunkHeader on-disk format.
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
pub struct RafsV6InodeChunkHeader {
    /// Chunk layout format.
    format: u16,
    reserved: u16,
}

impl RafsV6InodeChunkHeader {
    /// Create a new instance of `RafsV6InodeChunkHeader`.
    pub fn new(chunk_size: u32) -> Self {
        debug_assert!(chunk_size.is_power_of_two());
        let chunk_bits = 32 - chunk_size.leading_zeros() as u16;
        debug_assert!(chunk_bits >= EROFS_BLOCK_BITS as u16);
        let chunk_bits = chunk_bits - EROFS_BLOCK_BITS as u16;
        debug_assert!(chunk_bits <= EROFS_CHUNK_FORMAT_SIZE_MASK);
        let format = EROFS_CHUNK_FORMAT_INDEXES_FLAG | chunk_bits;

        Self {
            format: u16::to_le(format),
            reserved: u16::to_le(0),
        }
    }

    /// Convert to a u32 value.
    pub fn to_u32(&self) -> u32 {
        (self.format as u32) | ((self.reserved as u32) << 16)
    }

    /// Convert a u32 value to `RafsV6InodeChunkHeader`.
    pub fn from_u32(val: u32) -> Self {
        Self {
            format: val as u16,
            reserved: (val >> 16) as u16,
        }
    }
}

impl_bootstrap_converter!(RafsV6InodeChunkHeader);

/// Rafs v6 chunk address on-disk format, 8 bytes.
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
pub struct RafsV6InodeChunkAddr {
    /// Lower part of encoded blob address.
    c_blob_addr_lo: u16,
    /// Higher part of encoded blob address.
    c_blob_addr_hi: u16,
    /// start block address of this inode chunk
    c_blk_addr: u32,
}

impl RafsV6InodeChunkAddr {
    /// Create a new instance of `RafsV6InodeChunkIndex`.
    pub fn new() -> Self {
        Self {
            c_blob_addr_lo: u16::to_le(0),
            c_blob_addr_hi: u16::to_le(0),
            c_blk_addr: u32::to_le(0),
        }
    }

    /// Get the blob index of the chunk.
    pub fn blob_index(&self) -> u8 {
        (u16::from_le(self.c_blob_addr_hi)) as u8
    }

    /// Set the blob index of the chunk.
    pub fn set_blob_index(&mut self, blob_idx: u8) {
        let mut val = u16::from_le(self.c_blob_addr_hi);
        val &= 0xff00;
        val |= blob_idx as u16;
        self.c_blob_addr_hi = val.to_le();
    }

    /// Get the index into the blob compression information array.
    pub fn blob_comp_index(&self) -> u32 {
        let val = (u16::from_le(self.c_blob_addr_hi) as u32) >> 8;

        (val << 16) | (u16::from_le(self.c_blob_addr_lo) as u32)
    }

    /// Set the index into the blob compression information array.
    pub fn set_blob_comp_index(&mut self, comp_index: u32) {
        debug_assert!(comp_index <= 0x00ff_ffff);
        let val = (comp_index >> 8) as u16 & 0xff00 | (u16::from_le(self.c_blob_addr_hi) & 0x00ff);
        self.c_blob_addr_hi = val.to_le();
        self.c_blob_addr_lo = u16::to_le(comp_index as u16);
    }

    /// Get block address.
    pub fn block_addr(&self) -> u32 {
        u32::from_le(self.c_blk_addr)
    }

    /// Set block address.
    pub fn set_block_addr(&mut self, addr: u32) {
        self.c_blk_addr = addr.to_le();
    }

    /// Load a `RafsV6InodeChunkAddr` from a reader.
    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }
}

impl_bootstrap_converter!(RafsV6InodeChunkAddr);

impl RafsStore for RafsV6InodeChunkAddr {
    fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        w.write_all(self.as_ref())?;

        Ok(self.as_ref().len())
    }
}

/// Rafs v6 device information on-disk format, 128 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RafsV6Device {
    /// UUID for blob device.
    uuid: [u8; 16],
    /// Blob id of sha256.
    blob_id: [u8; 32],
    reserved1: [u8; 16],
    /// Number of blocks on the device.
    blocks: u32,
    /// Mapping start address.
    mapped_blkaddr: u32,
    reserved2: [u8; 56],
    // =======
    // pub struct RafsV6DeviceSlot {
    //     // blob digest (sha256)
    //     pub digest: [u8; 64],
    //     pub blocks: u32,
    //     pub mapped_blkaddr: u32,
    //     pub reserved: [u8; 56],
    // >>>>>>> patched
}

impl Default for RafsV6Device {
    fn default() -> Self {
        Self {
            uuid: [0u8; 16],
            blob_id: [0u8; 32],
            reserved1: [0u8; 16],
            // =======
            //             digest: [0u8; 64],
            // >>>>>>> patched
            blocks: u32::to_le(0),
            mapped_blkaddr: u32::to_le(0),
            reserved2: [0u8; 56],
        }
    }
}

impl RafsV6Device {
    /// Create a new instance of `RafsV6DeviceSlot`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get blob id.
    pub fn blob_id(&self) -> &[u8] {
        &self.blob_id
    }

    /// Set blob id.
    pub fn set_blob_id(&mut self, id: &[u8; 32]) {
        self.blob_id.copy_from_slice(id);
    }

    /// Get number of blocks.
    pub fn blocks(&self) -> u32 {
        u32::from_le(self.blocks)
    }

    /// Set number of blocks.
    pub fn set_blocks(&mut self, blocks: u32) {
        self.blocks = blocks.to_le();
    }

    /// Load a `RafsV6Device` from a reader.
    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }

    impl_pub_getter_setter!(mapped_blkaddr, set_mapped_blkaddr, mapped_blkaddr, u32);
}

impl_bootstrap_converter!(RafsV6Device);

impl RafsStore for RafsV6Device {
    fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        w.write_all(self.as_ref())?;

        Ok(self.as_ref().len())
    }
}

#[inline]
pub fn align_offset(offset: u64, aligned_size: u64) -> u64 {
    round_up(offset, aligned_size)
}

/// Generate EROFS `nid` from `offset`.
pub fn calculate_nid(offset: u64, meta_size: u64) -> u64 {
    (offset - meta_size) >> EROFS_INODE_SLOT_BITS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RafsIoRead, RafsIoWrite};
    use std::fs::OpenOptions;
    use vmm_sys_util::tempfile::TempFile;

    #[test]
    fn test_super_block_load_store() {
        let mut sb = RafsV6SuperBlock::new();
        let temp = TempFile::new().unwrap();
        let w = OpenOptions::new()
            .read(true)
            .write(true)
            .open(temp.as_path())
            .unwrap();
        let r = OpenOptions::new()
            .read(true)
            .write(false)
            .open(temp.as_path())
            .unwrap();
        let mut writer: Box<dyn RafsIoWrite> = Box::new(w);
        let mut reader: Box<dyn RafsIoRead> = Box::new(r);

        sb.s_blocks = 0x1000;
        sb.s_extra_devices = 5;
        sb.s_inos = 0x200;
        sb.store(&mut writer).unwrap();

        let mut sb2 = RafsV6SuperBlock::new();
        sb2.load(&mut reader).unwrap();
        assert_eq!(sb2.s_magic, EROFS_SUPER_MAGIC_V1.to_le());
        assert_eq!(sb2.s_blocks, 0x1000u32.to_le());
        assert_eq!(sb2.s_extra_devices, 5u16.to_le());
        assert_eq!(sb2.s_inos, 0x200u64.to_le());
        assert_eq!(
            sb2.s_feature_incompat,
            (EROFS_FEATURE_INCOMPAT_CHUNKED_FILE | EROFS_FEATURE_INCOMPAT_DEVICE_TABLE).to_le()
        );
    }

    #[test]
    fn test_rafs_v6_inode_extended() {
        let temp = TempFile::new().unwrap();
        let w = OpenOptions::new()
            .read(true)
            .write(true)
            .open(temp.as_path())
            .unwrap();
        let r = OpenOptions::new()
            .read(true)
            .write(false)
            .open(temp.as_path())
            .unwrap();
        let mut writer: Box<dyn RafsIoWrite> = Box::new(w);
        let mut reader: Box<dyn RafsIoRead> = Box::new(r);

        let mut inode = RafsV6InodeExtended::new();
        assert_eq!(
            inode.i_format,
            u16::to_le(EROFS_INODE_LAYOUT_EXTENDED | (EROFS_INODE_FLAT_PLAIN << 1))
        );
        inode.set_data_layout(EROFS_INODE_FLAT_INLINE);
        assert_eq!(
            inode.i_format,
            u16::to_le(EROFS_INODE_LAYOUT_EXTENDED | (EROFS_INODE_FLAT_INLINE << 1))
        );
        inode.set_inline_plain_layout();
        assert_eq!(
            inode.i_format,
            u16::to_le(EROFS_INODE_LAYOUT_EXTENDED | (EROFS_INODE_FLAT_PLAIN << 1))
        );
        inode.set_inline_inline_layout();
        assert_eq!(
            inode.i_format,
            u16::to_le(EROFS_INODE_LAYOUT_EXTENDED | (EROFS_INODE_FLAT_INLINE << 1))
        );
        inode.set_chunk_based_layout();
        assert_eq!(
            inode.i_format,
            u16::to_le(EROFS_INODE_LAYOUT_EXTENDED | (EROFS_INODE_FLAT_CHUNK_BASED << 1))
        );
        inode.set_uidgid(1, 2);
        inode.set_mtime(3, 4);
        inode.store(&mut writer).unwrap();

        let mut inode2 = RafsV6InodeExtended::new();
        inode2.load(&mut reader).unwrap();
        assert_eq!(inode2.i_uid, 1u32.to_le());
        assert_eq!(inode2.i_gid, 2u32.to_le());
        assert_eq!(inode2.i_mtime, 3u64.to_le());
        assert_eq!(inode2.i_mtime_nsec, 4u32.to_le());
        assert_eq!(
            inode2.i_format,
            u16::to_le(EROFS_INODE_LAYOUT_EXTENDED | (EROFS_INODE_FLAT_CHUNK_BASED << 1))
        );
    }

    #[test]
    fn test_rafs_v6_chunk_header() {
        let chunk_size: u32 = 1024 * 1024;
        let header = RafsV6InodeChunkHeader::new(chunk_size);
        let target = EROFS_CHUNK_FORMAT_INDEXES_FLAG | (20 - 12) as u16;
        assert_eq!(u16::from_le(header.format), target);
    }

    #[test]
    fn test_rafs_v6_chunk_addr() {
        let temp = TempFile::new().unwrap();
        let w = OpenOptions::new()
            .read(true)
            .write(true)
            .open(temp.as_path())
            .unwrap();
        let r = OpenOptions::new()
            .read(true)
            .write(false)
            .open(temp.as_path())
            .unwrap();
        let mut writer: Box<dyn RafsIoWrite> = Box::new(w);
        let mut reader: Box<dyn RafsIoRead> = Box::new(r);

        let mut chunk = RafsV6InodeChunkAddr::new();
        chunk.set_blob_index(3);
        chunk.set_blob_comp_index(0x123456);
        chunk.set_block_addr(0xa5a53412);
        chunk.store(&mut writer).unwrap();

        let mut chunk2 = RafsV6InodeChunkAddr::new();
        chunk2.load(&mut reader).unwrap();
        assert_eq!(chunk2.blob_index(), 3);
        assert_eq!(chunk2.blob_comp_index(), 0x123456);
        assert_eq!(chunk2.block_addr(), 0xa5a53412);
    }

    #[test]
    fn test_rafs_v6_device() {
        let temp = TempFile::new().unwrap();
        let w = OpenOptions::new()
            .read(true)
            .write(true)
            .open(temp.as_path())
            .unwrap();
        let r = OpenOptions::new()
            .read(true)
            .write(false)
            .open(temp.as_path())
            .unwrap();
        let mut writer: Box<dyn RafsIoWrite> = Box::new(w);
        let mut reader: Box<dyn RafsIoRead> = Box::new(r);

        let id = [0xa5u8; 32];
        let mut device = RafsV6Device::new();
        device.set_blocks(0x1234);
        device.set_blob_id(&id);
        device.store(&mut writer).unwrap();

        let mut device2 = RafsV6Device::new();
        device2.load(&mut reader).unwrap();
        assert_eq!(device2.blocks(), 0x1234);
        assert_eq!(device.blob_id(), &id);
    }
}

/// Rafs v6 blob description table.
#[derive(Clone, Debug, Default)]
pub struct RafsV6BlobTable {
    /// Base blob information array.
    pub entries: Vec<Arc<BlobInfo>>,
}

impl RafsV6BlobTable {
    /// Create a new instance of `RafsV6BlobTable`.
    pub fn new() -> Self {
        RafsV6BlobTable {
            entries: Vec::new(),
        }
    }

    fn field_size(&self) -> usize {
        2 * size_of::<u32>() + 3 * size_of::<u64>() + size_of::<u32>() + 2 * size_of::<u64>()
    }

    /// Get blob table size, aligned with RAFS_ALIGNMENT bytes
    pub fn size(&self) -> usize {
        if self.entries.is_empty() {
            return 0;
        }
        // Blob entry split with '\0'
        rafsv5_align(
            self.entries.iter().fold(0usize, |size, entry| {
                // meta_ci info + blob id.
                let entry_size = self.field_size() + entry.blob_id().len();
                size + entry_size + 1
            }) - 1,
        )
    }

    /// Add information for new blob into the blob information table.
    #[allow(clippy::too_many_arguments)]
    pub fn add(
        &mut self,
        blob_id: String,
        readahead_offset: u32,
        readahead_size: u32,
        chunk_size: u32,
        chunk_count: u32,
        uncompressed_size: u64,
        compressed_size: u64,
        blob_features: BlobFeatures,
        flags: RafsSuperFlags,
        header: BlobMetaHeaderOndisk,
    ) -> u32 {
        let blob_index = self.entries.len() as u32;
        let mut blob_info = BlobInfo::new(
            blob_index,
            blob_id,
            uncompressed_size,
            compressed_size,
            chunk_size,
            chunk_count,
            blob_features,
        );

        blob_info.set_compressor(flags.into());
        blob_info.set_digester(flags.into());
        // TODO: readahead may not be needed anymore.
        blob_info.set_readahead(readahead_offset as u64, readahead_size as u64);

        blob_info.set_blob_meta_info(
            header.meta_flags(),
            header.ci_compressed_offset(),
            header.ci_compressed_size(),
            header.ci_uncompressed_size(),
            header.ci_compressor() as u32,
        );

        self.entries.push(Arc::new(blob_info));

        blob_index
    }

    /// Get base information for a blob.
    #[inline]
    pub fn get(&self, blob_index: u32) -> Result<Arc<BlobInfo>> {
        if blob_index >= self.entries.len() as u32 {
            return Err(enoent!("blob not found"));
        }
        Ok(self.entries[blob_index as usize].clone())
    }

    /// Load blob information table from a reader.
    pub fn load(
        &mut self,
        r: &mut RafsIoReader,
        blob_table_size: u32,
        chunk_size: u32,
        flags: RafsSuperFlags,
    ) -> Result<()> {
        if blob_table_size == 0 {
            return Ok(());
        }

        debug!("blob table size {}", blob_table_size);
        let mut data = vec![0u8; blob_table_size as usize];
        r.read_exact(&mut data)?;

        // Each entry frame looks like:
        // u32 * 2 | u64 * 3 | u32 | u64 * 2 | string | trailing '\0' , except that the last entry has no trailing '\0'
        let mut buf = data.as_mut_slice();
        while buf.len() > self.field_size() {
            let ci_compressor =
                unsafe { std::ptr::read_unaligned::<u32>(buf[0..4].as_ptr() as *const u32) };
            let ci_features =
                unsafe { std::ptr::read_unaligned::<u32>(buf[4..8].as_ptr() as *const u32) };
            let ci_offset =
                unsafe { std::ptr::read_unaligned::<u64>(buf[8..16].as_ptr() as *const u64) };
            let ci_compressed_size =
                unsafe { std::ptr::read_unaligned::<u64>(buf[16..24].as_ptr() as *const u64) };
            let ci_uncompressed_size =
                unsafe { std::ptr::read_unaligned::<u64>(buf[24..32].as_ptr() as *const u64) };
            let chunk_count =
                unsafe { std::ptr::read_unaligned::<u32>(buf[32..36].as_ptr() as *const u32) };
            let uncompressed_size =
                unsafe { std::ptr::read_unaligned::<u64>(buf[36..44].as_ptr() as *const u64) };
            let compressed_size =
                unsafe { std::ptr::read_unaligned::<u64>(buf[44..52].as_ptr() as *const u64) };

            let orig_pos = 52;
            let mut pos = orig_pos;
            while pos < buf.len() && buf[pos] != 0 {
                pos += 1;
            }
            let blob_id = std::str::from_utf8(&buf[orig_pos..pos])
                .map(|v| v.to_owned())
                .map_err(|e| einval!(e))?;
            if pos == buf.len() {
                buf = &mut buf[pos..];
            } else {
                buf = &mut buf[pos + 1..];
            }
            debug!("blob {:?} lies on", blob_id);
            if blob_id.len() != BLOB_SHA256_LEN {
                return Err(einval!(format!("invalid blob id len {}", blob_id.len())));
            }

            let index = self.entries.len();
            let mut blob_info = BlobInfo::new(
                index as u32,
                blob_id,
                uncompressed_size,
                compressed_size,
                chunk_size,
                chunk_count,
                BlobFeatures::empty(),
            );

            blob_info.set_compressor(flags.into());
            blob_info.set_digester(flags.into());
            // blob_info.set_readahead(readahead_offset as u64, readahead_size as u64);
            blob_info.set_blob_meta_info(
                ci_features as u32,
                ci_offset as u64,
                ci_compressed_size as u64,
                ci_uncompressed_size as u64,
                ci_compressor as u32,
            );
            trace!("load blob_info {:?}", blob_info);

            self.entries.push(Arc::new(blob_info));
        }

        Ok(())
    }

    /// Get the base blob information array.
    pub fn get_all(&self) -> Vec<Arc<BlobInfo>> {
        self.entries.clone()
    }
}

impl RafsStore for RafsV6BlobTable {
    fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        let mut size = 0;
        self.entries
            .iter()
            .enumerate()
            .try_for_each::<_, Result<()>>(|(idx, entry)| {
                w.write_all(&u32::to_le_bytes(entry.meta_ci_compressor() as u32))?;
                w.write_all(&u32::to_le_bytes(entry.meta_flags() as u32))?;
                w.write_all(&u64::to_le_bytes(entry.meta_ci_offset() as u64))?;
                w.write_all(&u64::to_le_bytes(entry.meta_ci_compressed_size() as u64))?;
                w.write_all(&u64::to_le_bytes(entry.meta_ci_uncompressed_size() as u64))?;
                w.write_all(&u32::to_le_bytes(entry.chunk_count() as u32))?;
                w.write_all(&u64::to_le_bytes(entry.uncompressed_size() as u64))?;
                w.write_all(&u64::to_le_bytes(entry.compressed_size() as u64))?;
                trace!("store blob_info {:?}", entry);
                w.write_all(entry.blob_id().as_bytes())?;

                if idx != self.entries.len() - 1 {
                    size += self.field_size() + entry.blob_id().len() + 1;
                    w.write_all(&[b'\0'])?;
                } else {
                    size += self.field_size() + entry.blob_id().len();
                }
                Ok(())
            })?;

        let padding = rafsv5_align(size) - size;
        w.write_padding(padding)?;
        size += padding;

        w.validate_alignment(size, RAFSV5_ALIGNMENT)
    }
}
