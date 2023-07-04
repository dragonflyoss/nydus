// Copyright 2020-2021 Ant Group. All rights reserved.
// Copyright (C) 2020-2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::ffi::{OsStr, OsString};
use std::fmt::Debug;
use std::io::{Read, Result};
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;
use std::str::FromStr;
use std::sync::Arc;

use lazy_static::lazy_static;
use nydus_storage::device::{BlobFeatures, BlobInfo};
use nydus_storage::meta::{
    BlobChunkInfoV1Ondisk, BlobChunkInfoV2Ondisk, BlobCompressionContextHeader,
};
use nydus_storage::{RAFS_MAX_CHUNKS_PER_BLOB, RAFS_MAX_CHUNK_SIZE};
use nydus_utils::crypt::{self, Cipher, CipherContext};
use nydus_utils::{compress, digest, round_up, ByteSize};

use crate::metadata::inode::InodeWrapper;
use crate::metadata::layout::v5::RafsV5ChunkInfo;
use crate::metadata::layout::{MetaRange, RafsXAttrs};
use crate::metadata::{Inode, RafsBlobExtraInfo, RafsStore, RafsSuperFlags, RafsSuperMeta};
use crate::{impl_bootstrap_converter, impl_pub_getter_setter, RafsIoReader, RafsIoWrite};

/// EROFS metadata slot size.
pub const EROFS_INODE_SLOT_SIZE: usize = 1 << EROFS_INODE_SLOT_BITS;
/// Bits of EROFS logical block size.
pub const EROFS_BLOCK_BITS_12: u8 = 12;
/// EROFS logical block size.
pub const EROFS_BLOCK_SIZE_4096: u64 = 1u64 << EROFS_BLOCK_BITS_12;
pub const EROFS_BLOCK_BITS_9: u8 = 9;
/// EROFS logical block size.
pub const EROFS_BLOCK_SIZE_512: u64 = 1u64 << EROFS_BLOCK_BITS_9;

/// Offset of EROFS super block.
pub const EROFS_SUPER_OFFSET: u16 = 1024;
/// Size of EROFS super block.
pub const EROFS_SUPER_BLOCK_SIZE: u16 = 128;
/// Size of extended super block, used for rafs v6 specific fields
pub const EROFS_EXT_SUPER_BLOCK_SIZE: u16 = 256;
/// EROFS device table offset.
pub const EROFS_DEVTABLE_OFFSET: u16 =
    EROFS_SUPER_OFFSET + EROFS_SUPER_BLOCK_SIZE + EROFS_EXT_SUPER_BLOCK_SIZE;

/// Offseet for inode format flags: compact or extended.
pub const EROFS_I_VERSION_BIT: u16 = 0;
/// Number of bits for inode format flags.
pub const EROFS_I_VERSION_BITS: u16 = 1;
/// 32-byte on-disk inode
pub const EROFS_INODE_LAYOUT_COMPACT: u16 = 0;
/// 64-byte on-disk inode
pub const EROFS_INODE_LAYOUT_EXTENDED: u16 = 1;
/// Number of bits for inode data layout.
pub const EROFS_I_DATALAYOUT_BITS: u16 = 3;
/// EROFS plain inode.
pub const EROFS_INODE_FLAT_PLAIN: u16 = 0;
/// EROFS inline inode.
pub const EROFS_INODE_FLAT_INLINE: u16 = 2;
/// EROFS chunked inode.
pub const EROFS_INODE_CHUNK_BASED: u16 = 4;

// Magic number for EROFS super block.
const EROFS_SUPER_MAGIC_V1: u32 = 0xE0F5_E1E2;
// Bits of EROFS metadata slot size.
const EROFS_INODE_SLOT_BITS: u8 = 5;
// Bit flag indicating whether the inode is chunked or not.
const EROFS_CHUNK_FORMAT_INDEXES_FLAG: u16 = 0x0020;
// Encoded chunk size (log2(chunk_size) - EROFS_BLOCK_BITS).
const EROFS_CHUNK_FORMAT_SIZE_MASK: u16 = 0x001F;

/// Checksum of superblock, compatible with EROFS versions prior to Linux kernel 5.5.
#[allow(dead_code)]
const EROFS_FEATURE_COMPAT_SB_CHKSUM: u32 = 0x0000_0001;
/// Rafs v6 specific metadata, compatible with EROFS versions since Linux kernel 5.16.
const EROFS_FEATURE_COMPAT_RAFS_V6: u32 = 0x4000_0000;
/// Chunked inode, incompatible with EROFS versions prior to Linux kernel 5.15.
const EROFS_FEATURE_INCOMPAT_CHUNKED_FILE: u32 = 0x0000_0004;
/// Multi-devices, incompatible with EROFS versions prior to Linux kernel 5.16.
const EROFS_FEATURE_INCOMPAT_DEVICE_TABLE: u32 = 0x0000_0008;

/// Size of SHA256 digest string.
const BLOB_SHA256_LEN: usize = 64;
const BLOB_MAX_SIZE_UNCOMPRESSED: u64 = 1u64 << 44;
const BLOB_MAX_SIZE_COMPRESSED: u64 = 1u64 << 40;

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
    /// Bits of block size, 4K or 512 bytes.
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
    /// Offset of the device table, `startoff = s_devt_slotoff * 128`.
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
    }

    /// Validate the Rafs v6 super block.
    pub fn validate(&self, meta_size: u64) -> Result<()> {
        if meta_size < EROFS_BLOCK_SIZE_4096 {
            return Err(einval!(format!(
                "invalid Rafs v6 metadata size: {}",
                meta_size
            )));
        }
        let block_size = if self.s_blkszbits == EROFS_BLOCK_BITS_9 {
            EROFS_BLOCK_SIZE_512
        } else {
            EROFS_BLOCK_SIZE_4096
        };
        if meta_size & (block_size - 1) != 0 {
            return Err(einval!(format!(
                "invalid Rafs v6 metadata size: bootstrap size {} is not aligned",
                meta_size
            )));
        }
        let meta_addr = u32::from_le(self.s_meta_blkaddr) as u64 * block_size;
        if meta_addr > meta_size {
            return Err(einval!(format!(
                "invalid Rafs v6 meta block address 0x{:x}, meta file size 0x{:x}",
                meta_addr, meta_size
            )));
        }

        if u32::from_le(self.s_magic) != EROFS_SUPER_MAGIC_V1 {
            return Err(einval!(format!(
                "invalid EROFS magic number 0x{:x} in Rafsv6 superblock",
                u32::from_le(self.s_magic)
            )));
        }

        if self.s_checksum != 0 {
            return Err(einval!(format!(
                "invalid checksum {} in Rafsv6 superblock",
                u32::from_le(self.s_checksum)
            )));
        }

        if self.s_blkszbits != EROFS_BLOCK_BITS_12 && self.s_blkszbits != EROFS_BLOCK_BITS_9 {
            return Err(einval!(format!(
                "invalid block size bits {} in Rafsv6 superblock",
                self.s_blkszbits
            )));
        }

        if self.s_extslots != 0 {
            return Err(einval!("invalid extended slots in Rafsv6 superblock"));
        }

        if self.s_inos == 0 {
            return Err(einval!("invalid inode number in Rafsv6 superblock"));
        }

        if self.s_u != 0 {
            return Err(einval!("invalid union field in Rafsv6 superblock"));
        }

        if self.s_xattr_blkaddr != 0 {
            return Err(einval!(
                "unsupported shared extended attribute namespace in Rafsv6 superblock"
            ));
        }

        // There's a bug in old RAFS v6 images, which has set s_blocks to a fixed value 4096.
        if self.s_extra_devices == 0 && self.s_blocks != 0 && u32::from_le(self.s_blocks) != 4096 {
            warn!(
                "rafs v6 extra devices {}, blocks {}",
                self.s_extra_devices, self.s_blocks
            );
            return Err(einval!("invalid extra device count in Rafsv6 superblock"));
        }

        let devtable_off =
            u16::from_le(self.s_devt_slotoff) as u64 * size_of::<RafsV6Device>() as u64;
        if devtable_off != EROFS_DEVTABLE_OFFSET as u64 {
            return Err(einval!(format!(
                "invalid device table slot offset {} in Rafsv6 superblock",
                u16::from_le(self.s_devt_slotoff)
            )));
        }
        let devtable_end = devtable_off + u16::from_le(self.s_extra_devices) as u64;
        if devtable_end > meta_size {
            return Err(einval!(format!(
                "invalid device table slot count {} in Rafsv6 superblock",
                u16::from_le(self.s_extra_devices)
            )));
        }

        // s_build_time may be used as compact_inode's timestamp in the future.
        // if u64::from_le(self.s_build_time) != 0 || u32::from_le(self.s_build_time_nsec) != 0 {
        //     return Err(einval!("invalid build time in Rafsv6 superblock"));
        // }

        if u32::from_le(self.s_feature_incompat)
            != EROFS_FEATURE_INCOMPAT_CHUNKED_FILE | EROFS_FEATURE_INCOMPAT_DEVICE_TABLE
        {
            return Err(einval!(
                "invalid incompatible feature bits in Rafsv6 superblock"
            ));
        }

        if u32::from_le(self.s_feature_compat) & EROFS_FEATURE_COMPAT_RAFS_V6
            != EROFS_FEATURE_COMPAT_RAFS_V6
        {
            return Err(einval!(
                "invalid compatible feature bits in Rafsv6 superblock"
            ));
        }

        Ok(())
    }

    /// Check whether it's super block for Rafs v6.
    pub fn is_rafs_v6(&self) -> bool {
        self.magic() == EROFS_SUPER_MAGIC_V1
    }

    /// Set number of inodes.
    pub fn set_inos(&mut self, inos: u64) {
        self.s_inos = inos.to_le();
    }

    /// Get total inodes count of this Rafs
    pub fn inodes_count(&self) -> u64 {
        u64::from_le(self.s_inos)
    }

    /// Set number of logical blocks.
    pub fn set_blocks(&mut self, blocks: u32) {
        self.s_blocks = blocks.to_le();
    }

    /// Get root nid.
    pub fn root_nid(&self) -> u16 {
        u16::from_le(self.s_root_nid)
    }

    /// Set EROFS root nid.
    pub fn set_root_nid(&mut self, nid: u16) {
        self.s_root_nid = nid.to_le();
    }

    /// Get meta block address.
    pub fn meta_addr(&self) -> u32 {
        u32::from_le(self.s_meta_blkaddr)
    }

    /// Set EROFS meta block address.
    pub fn set_meta_addr(&mut self, meta_addr: u64) {
        if self.s_blkszbits == EROFS_BLOCK_BITS_12 {
            assert!((meta_addr / EROFS_BLOCK_SIZE_4096) <= u32::MAX as u64);
            self.s_meta_blkaddr = u32::to_le((meta_addr / EROFS_BLOCK_SIZE_4096) as u32);
        } else if self.s_blkszbits == EROFS_BLOCK_BITS_9 {
            assert!((meta_addr / EROFS_BLOCK_SIZE_512) <= u32::MAX as u64);
            self.s_meta_blkaddr = u32::to_le((meta_addr / EROFS_BLOCK_SIZE_512) as u32);
        } else {
            error!("v6: unsupported block bits {}", self.s_blkszbits);
        }
    }

    /// Get device table offset.
    pub fn device_table_offset(&self) -> u64 {
        u16::from_le(self.s_devt_slotoff) as u64 * size_of::<RafsV6Device>() as u64
    }

    /// Set bits of block size.
    pub fn set_block_bits(&mut self, block_bits: u8) {
        assert!(block_bits == EROFS_BLOCK_BITS_12 || block_bits == EROFS_BLOCK_BITS_9);
        self.s_blkszbits = block_bits;
    }

    impl_pub_getter_setter!(magic, set_magic, s_magic, u32);
    impl_pub_getter_setter!(extra_devices, set_extra_devices, s_extra_devices, u16);
}

impl RafsStore for RafsV6SuperBlock {
    // This method must be called before RafsV6SuperBlockExt::store(), otherwise data written by
    // RafsV6SuperBlockExt::store() will be overwritten.
    fn store(&self, w: &mut dyn RafsIoWrite) -> Result<usize> {
        debug_assert!(
            ((EROFS_SUPER_OFFSET + EROFS_SUPER_BLOCK_SIZE) as u64) < EROFS_BLOCK_SIZE_4096
        );
        w.write_all(&[0u8; EROFS_SUPER_OFFSET as usize])?;
        w.write_all(self.as_ref())?;
        w.write_all(
            &[0u8; (EROFS_BLOCK_SIZE_4096 as usize
                - (EROFS_SUPER_OFFSET + EROFS_SUPER_BLOCK_SIZE) as usize)],
        )?;

        Ok(EROFS_BLOCK_SIZE_4096 as usize)
    }
}

impl Default for RafsV6SuperBlock {
    fn default() -> Self {
        debug_assert!(size_of::<RafsV6Device>() == 128);
        Self {
            s_magic: u32::to_le(EROFS_SUPER_MAGIC_V1),
            s_checksum: 0,
            s_feature_compat: u32::to_le(EROFS_FEATURE_COMPAT_RAFS_V6),
            s_blkszbits: EROFS_BLOCK_BITS_12,
            s_extslots: 0u8,
            s_root_nid: 0,
            s_inos: 0,
            s_build_time: 0,
            s_build_time_nsec: 0,
            s_blocks: u32::to_le(1),
            s_meta_blkaddr: 0,
            s_xattr_blkaddr: 0,
            s_uuid: [0u8; 16],
            s_volume_name: [0u8; 16],
            s_feature_incompat: u32::to_le(
                EROFS_FEATURE_INCOMPAT_CHUNKED_FILE | EROFS_FEATURE_INCOMPAT_DEVICE_TABLE,
            ),
            s_u: 0,
            s_extra_devices: 0,
            s_devt_slotoff: u16::to_le(EROFS_DEVTABLE_OFFSET / size_of::<RafsV6Device>() as u16),
            s_reserved: [0u8; 38],
        }
    }
}

/// Extended superblock for RAFS v6, 256 bytes
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RafsV6SuperBlockExt {
    /// superblock flags
    s_flags: u64,
    /// offset of blob table
    s_blob_table_offset: u64,
    /// size of blob table
    s_blob_table_size: u32,
    /// chunk size
    s_chunk_size: u32,
    /// offset of chunk table
    s_chunk_table_offset: u64,
    /// size of chunk table
    s_chunk_table_size: u64,
    s_prefetch_table_offset: u64,
    s_prefetch_table_size: u32,
    s_padding: u32,
    /// Reserved
    s_reserved: [u8; 200],
}

impl_bootstrap_converter!(RafsV6SuperBlockExt);

impl RafsV6SuperBlockExt {
    /// Create a new instance `RafsV6SuperBlockExt`.
    pub fn new() -> Self {
        debug_assert!(size_of::<Self>() == 256);
        Self::default()
    }

    /// Load an `RafsV6SuperBlockExt` from a reader.
    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.seek_to_offset((EROFS_SUPER_OFFSET + EROFS_SUPER_BLOCK_SIZE) as u64)?;
        r.read_exact(self.as_mut())?;
        r.seek_to_offset(EROFS_BLOCK_SIZE_4096 as u64)?;

        Ok(())
    }

    /// Validate the Rafs v6 super block.
    pub fn validate(&self, meta_size: u64, meta: &RafsSuperMeta) -> Result<()> {
        let mut flags = self.flags();
        flags &= RafsSuperFlags::COMPRESSION_NONE.bits()
            | RafsSuperFlags::COMPRESSION_LZ4.bits()
            | RafsSuperFlags::COMPRESSION_GZIP.bits()
            | RafsSuperFlags::COMPRESSION_ZSTD.bits();
        if flags.count_ones() != 1 {
            return Err(einval!(format!(
                "invalid flags {:#x} related to compression algorithm in Rafs v6 extended superblock",
                flags
            )));
        }

        let mut flags = self.flags();
        flags &= RafsSuperFlags::HASH_BLAKE3.bits() | RafsSuperFlags::HASH_SHA256.bits();
        if flags.count_ones() != 1 {
            return Err(einval!(format!(
                "invalid flags {:#x} related to digest algorithm in Rafs v6 extended superblock",
                flags
            )));
        }

        let chunk_size = u32::from_le(self.s_chunk_size) as u64;
        if !chunk_size.is_power_of_two()
            || !(EROFS_BLOCK_SIZE_4096..=RAFS_MAX_CHUNK_SIZE).contains(&chunk_size)
        {
            return Err(einval!("invalid chunk size in Rafs v6 extended superblock"));
        }

        let devslot_end = meta.blob_device_table_offset + meta.blob_table_size as u64;

        let blob_offset = self.blob_table_offset();
        let blob_size = self.blob_table_size() as u64;
        if blob_offset & (EROFS_BLOCK_SIZE_4096 - 1) != 0
            || blob_offset < EROFS_BLOCK_SIZE_4096
            || blob_offset < devslot_end
            || blob_size % size_of::<RafsV6Blob>() as u64 != 0
            || blob_offset.checked_add(blob_size).is_none()
            || blob_offset + blob_size > meta_size
        {
            return Err(einval!(format!(
                "invalid blob table offset 0x{:x}/size 0x{:x} in Rafs v6 extended superblock",
                blob_offset, blob_size
            )));
        }
        let blob_range = MetaRange::new(blob_offset, blob_size, true)?;

        let mut chunk_info_tbl_range = None;
        if self.chunk_table_size() > 0 {
            let chunk_tbl_offset = self.chunk_table_offset();
            let chunk_tbl_size = self.chunk_table_size();
            if chunk_tbl_offset < EROFS_BLOCK_SIZE_4096
                || chunk_tbl_offset % EROFS_BLOCK_SIZE_4096 != 0
                || chunk_tbl_offset < devslot_end
                || chunk_tbl_size % size_of::<RafsV5ChunkInfo>() as u64 != 0
                || chunk_tbl_offset.checked_add(chunk_tbl_size).is_none()
                || chunk_tbl_offset + chunk_tbl_size > meta_size
            {
                return Err(einval!(format!(
                    "invalid chunk table offset 0x{:x}/size 0x{:x} in Rafs v6 extended superblock",
                    chunk_tbl_offset, chunk_tbl_size
                )));
            }
            let chunk_range = MetaRange::new(chunk_tbl_offset, chunk_tbl_size, true)?;
            if blob_range.intersect_with(&chunk_range) {
                return Err(einval!(format!(
                    "blob table intersects with chunk table in Rafs v6 extended superblock",
                )));
            }
            chunk_info_tbl_range = Some(chunk_range);
        }

        // Legacy RAFS may have zero prefetch table offset but non-zero prefetch table size for
        // empty filesystems.
        if self.prefetch_table_size() > 0 && self.prefetch_table_offset() != 0 {
            let tbl_offset = self.prefetch_table_offset();
            let tbl_size = self.prefetch_table_size() as u64;
            if tbl_offset < EROFS_BLOCK_SIZE_4096
                || tbl_size % size_of::<u32>() as u64 != 0
                || tbl_offset < devslot_end
                || tbl_offset.checked_add(tbl_size).is_none()
                || tbl_offset + tbl_size > meta_size
            {
                return Err(einval!(format!(
                    "invalid prefetch table offset 0x{:x}/size 0x{:x} in Rafs v6 extended superblock",
                    tbl_offset, tbl_size
                )));
            }
            let prefetch_range = MetaRange::new(tbl_offset, tbl_size, false)?;
            if blob_range.intersect_with(&prefetch_range) {
                return Err(einval!(format!(
                    "blob table intersects with prefetch table in Rafs v6 extended superblock",
                )));
            }
            if let Some(chunk_range) = chunk_info_tbl_range.as_ref() {
                if chunk_range.intersect_with(&prefetch_range) {
                    return Err(einval!(format!(
                    "chunk information table intersects with prefetch table in Rafs v6 extended superblock",
                )));
                }
            }
        }

        Ok(())
    }

    /// Set compression algorithm to handle chunk of the Rafs filesystem.
    pub fn set_compressor(&mut self, compressor: compress::Algorithm) {
        let c: RafsSuperFlags = compressor.into();

        self.s_flags &= !RafsSuperFlags::COMPRESSION_NONE.bits();
        self.s_flags &= !RafsSuperFlags::COMPRESSION_LZ4.bits();
        self.s_flags &= !RafsSuperFlags::COMPRESSION_GZIP.bits();
        self.s_flags &= !RafsSuperFlags::COMPRESSION_ZSTD.bits();
        self.s_flags |= c.bits();
    }

    /// Set the `has_xattr` flag for the RAFS filesystem.
    pub fn set_has_xattr(&mut self) {
        self.s_flags |= RafsSuperFlags::HAS_XATTR.bits();
    }

    /// Enable explicit Uid/Gid feature.
    pub fn set_explicit_uidgid(&mut self) {
        self.s_flags |= RafsSuperFlags::EXPLICIT_UID_GID.bits();
    }

    /// Set flag indicating that chunk digest is inlined in the data blob.
    pub fn set_inlined_chunk_digest(&mut self) {
        self.s_flags |= RafsSuperFlags::INLINED_CHUNK_DIGEST.bits();
    }

    /// Enable `tarfs` mode, which directly use a tar stream/file as RAFS data blob and do not
    /// generate any blob meta data.
    pub fn set_tarfs_mode(&mut self) {
        self.s_flags |= RafsSuperFlags::TARTFS_MODE.bits();
    }

    /// Set message digest algorithm to handle chunk of the Rafs filesystem.
    pub fn set_digester(&mut self, digester: digest::Algorithm) {
        let c: RafsSuperFlags = digester.into();

        self.s_flags &= !RafsSuperFlags::HASH_BLAKE3.bits();
        self.s_flags &= !RafsSuperFlags::HASH_SHA256.bits();
        self.s_flags |= c.bits();
    }

    /// Set offset and size of chunk information table.
    pub fn set_chunk_table(&mut self, offset: u64, size: u64) {
        self.set_chunk_table_offset(offset);
        self.set_chunk_table_size(size);
    }

    /// Set encryption algorithm to encrypt chunks of the Rafs filesystem.
    pub fn set_cipher(&mut self, cipher: crypt::Algorithm) {
        let c: RafsSuperFlags = cipher.into();

        self.s_flags &= !RafsSuperFlags::ENCRYPTION_NONE.bits();
        self.s_flags &= !RafsSuperFlags::ENCRYPTION_ASE_128_XTS.bits();
        self.s_flags |= c.bits();
    }

    impl_pub_getter_setter!(
        chunk_table_offset,
        set_chunk_table_offset,
        s_chunk_table_offset,
        u64
    );
    impl_pub_getter_setter!(
        chunk_table_size,
        set_chunk_table_size,
        s_chunk_table_size,
        u64
    );
    impl_pub_getter_setter!(chunk_size, set_chunk_size, s_chunk_size, u32);
    impl_pub_getter_setter!(flags, set_flags, s_flags, u64);
    impl_pub_getter_setter!(
        blob_table_offset,
        set_blob_table_offset,
        s_blob_table_offset,
        u64
    );
    impl_pub_getter_setter!(blob_table_size, set_blob_table_size, s_blob_table_size, u32);
    impl_pub_getter_setter!(
        prefetch_table_size,
        set_prefetch_table_size,
        s_prefetch_table_size,
        u32
    );
    impl_pub_getter_setter!(
        prefetch_table_offset,
        set_prefetch_table_offset,
        s_prefetch_table_offset,
        u64
    );
}

impl RafsStore for RafsV6SuperBlockExt {
    fn store(&self, w: &mut dyn RafsIoWrite) -> Result<usize> {
        w.write_all(self.as_ref())?;
        w.seek_offset(EROFS_BLOCK_SIZE_4096 as u64)?;

        Ok(EROFS_BLOCK_SIZE_4096 as usize - (EROFS_SUPER_OFFSET + EROFS_SUPER_BLOCK_SIZE) as usize)
    }
}

impl Default for RafsV6SuperBlockExt {
    fn default() -> Self {
        Self {
            s_flags: 0,
            s_blob_table_offset: 0,
            s_blob_table_size: 0,
            s_chunk_size: 0,
            s_chunk_table_offset: 0,
            s_chunk_table_size: 0,
            s_prefetch_table_offset: 0,
            s_prefetch_table_size: 0,
            s_padding: u32::to_le(0),
            s_reserved: [0u8; 200],
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

/// Trait to manipulate data fields of on-disk RAFS v6 inodes.
///
/// There are two types of on disk inode formats defined by EROFS:
/// - compact inode with 32-byte data
/// - extended inode with 64-byte data
pub trait RafsV6OndiskInode: RafsStore {
    fn set_size(&mut self, size: u64);
    fn set_ino(&mut self, ino: u32);
    fn set_nlink(&mut self, nlinks: u32);
    fn set_mode(&mut self, mode: u16);
    fn set_u(&mut self, u: u32);
    fn set_uidgid(&mut self, uid: u32, gid: u32);
    fn set_mtime(&mut self, _sec: u64, _nsec: u32);
    fn set_rdev(&mut self, rdev: u32);
    fn set_xattr_inline_count(&mut self, count: u16);
    fn set_data_layout(&mut self, data_layout: u16);

    /// Set inode data layout format to be PLAIN.
    #[inline]
    fn set_inline_plain_layout(&mut self) {
        self.set_data_layout(EROFS_INODE_FLAT_PLAIN);
    }

    /// Set inode data layout format to be INLINE.
    #[inline]
    fn set_inline_inline_layout(&mut self) {
        self.set_data_layout(EROFS_INODE_FLAT_INLINE);
    }

    /// Set inode data layout format to be CHUNKED.
    #[inline]
    fn set_chunk_based_layout(&mut self) {
        self.set_data_layout(EROFS_INODE_CHUNK_BASED);
    }

    fn format(&self) -> u16;
    fn mode(&self) -> u16;
    fn size(&self) -> u64;
    fn union(&self) -> u32;
    fn ino(&self) -> u32;
    fn ugid(&self) -> (u32, u32);
    fn mtime_s_ns(&self) -> (u64, u32);
    fn nlink(&self) -> u32;
    fn rdev(&self) -> u32;
    fn xattr_inline_count(&self) -> u16;

    fn load(&mut self, r: &mut RafsIoReader) -> Result<()>;
}

impl Debug for &dyn RafsV6OndiskInode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("RafsV6OndiskInode")
            .field("format", &self.format())
            .field("ino", &self.ino())
            .field("mode", &self.mode())
            .field("size", &self.size())
            .field("union", &self.union())
            .field("nlink", &self.nlink())
            .field("xattr count", &self.xattr_inline_count())
            .finish()
    }
}

/// RAFS v6 inode on-disk format, 32 bytes.
///
/// This structure is designed to be compatible with EROFS compact inode format.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct RafsV6InodeCompact {
    /// inode format hints
    pub i_format: u16,
    pub i_xattr_icount: u16,
    pub i_mode: u16,
    pub i_nlink: u16,
    pub i_size: u32,
    pub i_reserved: u32,
    /// raw_blkaddr or rdev or rafs_v6_inode_chunk_info
    pub i_u: u32,
    pub i_ino: u32,
    pub i_uid: u16,
    pub i_gid: u16,
    pub i_reserved2: [u8; 4],
}

impl RafsV6InodeCompact {
    pub fn new() -> Self {
        Self {
            i_format: u16::to_le(EROFS_INODE_LAYOUT_COMPACT | (EROFS_INODE_FLAT_PLAIN << 1)),
            i_xattr_icount: 0,
            i_mode: 0,
            i_nlink: 0,
            i_size: 0,
            i_reserved: 0,
            i_u: 0,
            i_ino: 0,
            i_uid: 0,
            i_gid: 0,
            i_reserved2: [0u8; 4],
        }
    }
}

impl RafsV6OndiskInode for RafsV6InodeCompact {
    /// Set file size for inode.
    fn set_size(&mut self, size: u64) {
        self.i_size = u32::to_le(size as u32);
    }

    /// Set ino for inode.
    fn set_ino(&mut self, ino: u32) {
        self.i_ino = ino.to_le();
    }

    /// Set number of hardlink.
    fn set_nlink(&mut self, nlinks: u32) {
        self.i_nlink = u16::to_le(nlinks as u16);
    }

    /// Set file protection mode.
    fn set_mode(&mut self, mode: u16) {
        self.i_mode = mode.to_le();
    }

    /// Set the union field.
    fn set_u(&mut self, u: u32) {
        self.i_u = u.to_le();
    }

    /// Set uid and gid for the inode.
    fn set_uidgid(&mut self, uid: u32, gid: u32) {
        self.i_uid = u16::to_le(uid as u16);
        self.i_gid = u16::to_le(gid as u16);
    }

    /// Set last modification time for the inode.
    fn set_mtime(&mut self, _sec: u64, _nsec: u32) {}

    /// Set real device id.
    fn set_rdev(&mut self, _rdev: u32) {}

    /// Set xattr inline count.
    fn set_xattr_inline_count(&mut self, count: u16) {
        self.i_xattr_icount = count.to_le();
    }

    /// Set inode data layout format.
    fn set_data_layout(&mut self, data_layout: u16) {
        self.i_format = u16::to_le(EROFS_INODE_LAYOUT_COMPACT | (data_layout << 1));
    }

    fn format(&self) -> u16 {
        u16::from_le(self.i_format)
    }

    fn mode(&self) -> u16 {
        u16::from_le(self.i_mode)
    }

    fn size(&self) -> u64 {
        u32::from_le(self.i_size) as u64
    }

    fn union(&self) -> u32 {
        u32::from_le(self.i_u)
    }

    fn ino(&self) -> u32 {
        u32::from_le(self.i_ino)
    }

    fn ugid(&self) -> (u32, u32) {
        (
            u16::from_le(self.i_uid) as u32,
            u16::from_le(self.i_gid) as u32,
        )
    }

    fn mtime_s_ns(&self) -> (u64, u32) {
        (0, 0)
    }

    fn nlink(&self) -> u32 {
        u16::from_le(self.i_nlink) as u32
    }

    fn rdev(&self) -> u32 {
        0
    }

    fn xattr_inline_count(&self) -> u16 {
        u16::from_le(self.i_xattr_icount)
    }

    /// Load a `RafsV6InodeCompact` from a reader.
    fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }
}

impl_bootstrap_converter!(RafsV6InodeCompact);

impl RafsStore for RafsV6InodeCompact {
    fn store(&self, w: &mut dyn RafsIoWrite) -> Result<usize> {
        // TODO: need to write xattr as well.
        w.write_all(self.as_ref())?;
        Ok(self.as_ref().len())
    }
}

/// RAFS v6 inode on-disk format, 64 bytes.
///
/// This structure is designed to be compatible with EROFS extended inode format.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct RafsV6InodeExtended {
    /// Layout format for of the inode.
    pub i_format: u16,
    /// Size of extended attributes, in unit of 4Byte
    pub i_xattr_icount: u16,
    /// Protection mode.
    pub i_mode: u16,
    i_reserved: u16,
    /// Size of the file content.
    pub i_size: u64,
    /// A `u32` union: raw_blkaddr or `rdev` or `rafs_v6_inode_chunk_info`
    pub i_u: u32,
    /// Inode number.
    pub i_ino: u32,
    /// User ID of owner.
    pub i_uid: u32,
    /// Group ID of owner
    pub i_gid: u32,
    /// Time of last modification - second part.
    pub i_mtime: u64,
    /// Time of last modification - nanoseconds part.
    pub i_mtime_nsec: u32,
    /// Number of links.
    pub i_nlink: u32,
    i_reserved2: [u8; 16],
}

impl RafsV6InodeExtended {
    /// Create a new instance of `RafsV6InodeExtended`.
    pub fn new() -> Self {
        Self {
            i_format: u16::to_le(EROFS_INODE_LAYOUT_EXTENDED | (EROFS_INODE_FLAT_PLAIN << 1)),
            i_xattr_icount: 0,
            i_mode: 0,
            i_reserved: 0,
            i_size: 0,
            i_u: 0,
            i_ino: 0,
            i_uid: 0,
            i_gid: 0,
            i_mtime: 0,
            i_mtime_nsec: 0,
            i_nlink: 0,
            i_reserved2: [0u8; 16],
        }
    }
}

impl RafsV6OndiskInode for RafsV6InodeExtended {
    /// Set file size for inode.
    fn set_size(&mut self, size: u64) {
        self.i_size = size.to_le();
    }

    /// Set ino for inode.
    fn set_ino(&mut self, ino: u32) {
        self.i_ino = ino.to_le();
    }

    /// Set number of hardlink.
    fn set_nlink(&mut self, nlinks: u32) {
        self.i_nlink = nlinks.to_le();
    }

    /// Set file protection mode.
    fn set_mode(&mut self, mode: u16) {
        self.i_mode = mode.to_le();
    }

    /// Set the union field.
    fn set_u(&mut self, u: u32) {
        self.i_u = u.to_le();
    }

    /// Set uid and gid for the inode.
    fn set_uidgid(&mut self, uid: u32, gid: u32) {
        self.i_uid = u32::to_le(uid);
        self.i_gid = u32::to_le(gid);
    }

    /// Set last modification time for the inode.
    fn set_mtime(&mut self, sec: u64, nsec: u32) {
        self.i_mtime = u64::to_le(sec);
        self.i_mtime_nsec = u32::to_le(nsec);
    }

    fn set_rdev(&mut self, rdev: u32) {
        self.i_u = rdev.to_le()
    }

    /// Set xattr inline count.
    fn set_xattr_inline_count(&mut self, count: u16) {
        self.i_xattr_icount = count.to_le();
    }

    /// Set inode data layout format.
    fn set_data_layout(&mut self, data_layout: u16) {
        self.i_format = u16::to_le(EROFS_INODE_LAYOUT_EXTENDED | (data_layout << 1));
    }

    fn format(&self) -> u16 {
        u16::from_le(self.i_format)
    }

    fn mode(&self) -> u16 {
        u16::from_le(self.i_mode)
    }

    fn size(&self) -> u64 {
        u64::from_le(self.i_size)
    }

    fn union(&self) -> u32 {
        u32::from_le(self.i_u)
    }

    fn ino(&self) -> u32 {
        u32::from_le(self.i_ino)
    }

    fn ugid(&self) -> (u32, u32) {
        (u32::from_le(self.i_uid), u32::from_le(self.i_gid))
    }

    fn mtime_s_ns(&self) -> (u64, u32) {
        (u64::from_le(self.i_mtime), u32::from_le(self.i_mtime_nsec))
    }

    fn nlink(&self) -> u32 {
        u32::from_le(self.i_nlink)
    }

    fn rdev(&self) -> u32 {
        u32::from_le(self.i_u)
    }

    fn xattr_inline_count(&self) -> u16 {
        u16::from_le(self.i_xattr_icount)
    }

    /// Load a `RafsV6InodeExtended` from a reader.
    fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }
}

impl_bootstrap_converter!(RafsV6InodeExtended);

impl RafsStore for RafsV6InodeExtended {
    fn store(&self, w: &mut dyn RafsIoWrite) -> Result<usize> {
        // TODO: need to write xattr as well.
        w.write_all(self.as_ref())?;
        Ok(self.as_ref().len())
    }
}

/// Create RAFS v6 on-disk inode object.
pub fn new_v6_inode(
    inode: &InodeWrapper,
    datalayout: u16,
    xattr_inline_count: u16,
    compact: bool,
) -> Box<dyn RafsV6OndiskInode> {
    let mut i: Box<dyn RafsV6OndiskInode> = match compact {
        true => Box::new(RafsV6InodeCompact::new()),
        false => Box::new(RafsV6InodeExtended::new()),
    };

    assert!(inode.ino() <= i32::MAX as Inode);
    i.set_ino(inode.ino() as u32);
    i.set_size(inode.size());
    i.set_uidgid(inode.uid(), inode.gid());
    i.set_mtime(inode.mtime(), inode.mtime_nsec());
    i.set_nlink(inode.nlink());
    i.set_mode(inode.mode() as u16);
    i.set_data_layout(datalayout);
    i.set_xattr_inline_count(xattr_inline_count);
    if inode.is_special() {
        i.set_rdev(inode.rdev() as u32);
    }

    i
}

/// Dirent sorted in alphabet order to improve performance by binary search.
#[repr(C, packed(2))]
#[derive(Default, Clone, Copy, Debug)]
pub struct RafsV6Dirent {
    /// Node number, inode offset = s_meta_blkaddr * 4096 + nid * 32
    pub e_nid: u64,
    /// start offset of file name in the block
    pub e_nameoff: u16,
    /// file type
    pub e_file_type: u8,
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
            e_reserved: 0,
        }
    }

    /// Get file type from file mode.
    pub fn file_type(mode: u32) -> u8 {
        let val = match mode as libc::mode_t & libc::S_IFMT {
            libc::S_IFREG => EROFS_FILE_TYPE::EROFS_FT_REG_FILE,
            libc::S_IFDIR => EROFS_FILE_TYPE::EROFS_FT_DIR,
            libc::S_IFCHR => EROFS_FILE_TYPE::EROFS_FT_CHRDEV,
            libc::S_IFBLK => EROFS_FILE_TYPE::EROFS_FT_BLKDEV,
            libc::S_IFIFO => EROFS_FILE_TYPE::EROFS_FT_FIFO,
            libc::S_IFSOCK => EROFS_FILE_TYPE::EROFS_FT_SOCK,
            libc::S_IFLNK => EROFS_FILE_TYPE::EROFS_FT_SYMLINK,
            _ => EROFS_FILE_TYPE::EROFS_FT_UNKNOWN,
        };

        val as u8
    }

    /// Set name offset of the dirent.
    pub fn set_name_offset(&mut self, offset: u16) {
        assert!(offset < EROFS_BLOCK_SIZE_4096 as u16);
        self.e_nameoff = u16::to_le(offset);
    }

    /// Load a `RafsV6Dirent` from a reader.
    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }
}

impl RafsStore for RafsV6Dirent {
    fn store(&self, w: &mut dyn RafsIoWrite) -> Result<usize> {
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
    ///
    /// If all chunks are continous in uncompressed cache file, the `chunk_size` will set to
    /// `inode.size().next_power_of_two()`, so EROFS can optimize page cache in this case.
    /// Otherwise `chunk_size` is set to RAFS filesystem's chunk size.
    pub fn new(chunk_size: u64, block_size: u64) -> Self {
        assert!(chunk_size.is_power_of_two());
        assert!(block_size == EROFS_BLOCK_SIZE_4096 || block_size == EROFS_BLOCK_SIZE_512);
        let chunk_bits = chunk_size.trailing_zeros() as u16;
        assert!(chunk_bits >= EROFS_BLOCK_BITS_12 as u16);
        let chunk_bits = if block_size == EROFS_BLOCK_SIZE_4096 {
            chunk_bits - EROFS_BLOCK_BITS_12 as u16
        } else {
            chunk_bits - EROFS_BLOCK_BITS_9 as u16
        };
        assert!(chunk_bits <= EROFS_CHUNK_FORMAT_SIZE_MASK);
        let format = EROFS_CHUNK_FORMAT_INDEXES_FLAG | chunk_bits;

        Self {
            format: u16::to_le(format),
            reserved: 0,
        }
    }

    /// Convert to a u32 value.
    pub fn to_u32(&self) -> u32 {
        (u16::from_le(self.format) as u32) | ((u16::from_le(self.reserved) as u32) << 16)
    }

    /// Convert a u32 value to `RafsV6InodeChunkHeader`.
    pub fn from_u32(val: u32) -> Self {
        Self {
            format: (val as u16).to_le(),
            reserved: ((val >> 16) as u16).to_le(),
        }
    }
}

impl_bootstrap_converter!(RafsV6InodeChunkHeader);

/// Rafs v6 chunk address on-disk format, 8 bytes.
#[repr(C)]
#[derive(Default, Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct RafsV6InodeChunkAddr {
    /// Lower part of encoded blob address.
    c_blob_addr_lo: u16,
    /// Higher part of encoded blob address.
    c_blob_addr_hi: u16,
    /// start block address of this inode chunk
    /// decompressed offset must be aligned, in unit of block
    c_blk_addr: u32,
}

impl RafsV6InodeChunkAddr {
    /// Create a new instance of `RafsV6InodeChunkIndex`.
    pub fn new() -> Self {
        Self {
            c_blob_addr_lo: 0,
            c_blob_addr_hi: 0,
            c_blk_addr: 0,
        }
    }

    /// Get the blob index associated with the chunk.
    ///
    /// Note: for erofs, bump id by 1 since device id 0 is bootstrap.
    /// The index in BlobInfo grows from 0, so when using this method to index the corresponding blob,
    /// the index always needs to be minus 1
    /// Get the blob index of the chunk.
    pub fn blob_index(&self) -> Result<u32> {
        let idx = (u16::from_le(self.c_blob_addr_hi) & 0x00ff) as u32;
        if idx == 0 {
            Err(einval!("invalid zero blob index from RafsV6InodeChunkAddr"))
        } else {
            Ok(idx - 1)
        }
    }

    /// Set the blob index of the chunk.
    pub fn set_blob_index(&mut self, blob_idx: u32) {
        assert!(blob_idx < u8::MAX as u32);
        let mut val = u16::from_le(self.c_blob_addr_hi);
        val &= 0xff00;
        val |= (blob_idx + 1) as u16;
        self.c_blob_addr_hi = val.to_le();
    }

    /// Get the 24-bits index into the blob compression information array.
    pub fn blob_ci_index(&self) -> u32 {
        let val = (u16::from_le(self.c_blob_addr_hi) as u32) >> 8;
        (val << 16) | (u16::from_le(self.c_blob_addr_lo) as u32)
    }

    /// Set the index into the blob compression information array.
    pub fn set_blob_ci_index(&mut self, ci_index: u32) {
        assert!(ci_index <= 0x00ff_ffff);
        let val = (ci_index >> 8) as u16 & 0xff00 | (u16::from_le(self.c_blob_addr_hi) & 0x00ff);
        self.c_blob_addr_hi = val.to_le();
        self.c_blob_addr_lo = u16::to_le(ci_index as u16);
    }

    /// Get block address.
    pub fn block_addr(&self) -> u32 {
        u32::from_le(self.c_blk_addr)
    }

    /// Set block address.
    pub fn set_block_addr(&mut self, addr: u32) {
        self.c_blk_addr = addr.to_le();
    }

    /// Validate the 'RafsV6InodeChunkAddr' object.
    pub fn validate(&self, max_blob_index: u32) -> bool {
        let blob_idx = (u16::from_le(self.c_blob_addr_hi) & 0x00ff) as u32;
        blob_idx > 0 && blob_idx - 1 <= max_blob_index
    }

    /// Load a `RafsV6InodeChunkAddr` from a reader.
    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }
}

impl_bootstrap_converter!(RafsV6InodeChunkAddr);

impl RafsStore for RafsV6InodeChunkAddr {
    fn store(&self, w: &mut dyn RafsIoWrite) -> Result<usize> {
        w.write_all(self.as_ref())?;
        Ok(self.as_ref().len())
    }
}

/// Rafs v6 device information on-disk format, 128 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RafsV6Device {
    /// Blob id of sha256.
    blob_id: [u8; BLOB_SHA256_LEN],
    /// Number of blocks on the device.
    blocks: u32,
    /// Mapping start address.
    mapped_blkaddr: u32,
    reserved2: [u8; 56],
}

impl Default for RafsV6Device {
    fn default() -> Self {
        Self {
            blob_id: [0u8; 64],
            blocks: 0,
            mapped_blkaddr: 0,
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
    pub fn set_blob_id(&mut self, id: &[u8; 64]) {
        self.blob_id.copy_from_slice(id);
    }

    /// Load a `RafsV6Device` from a reader.
    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }

    /// Validate the Rafs v6 Device slot.
    pub fn validate(&self) -> Result<()> {
        match String::from_utf8(self.blob_id.to_vec()) {
            Ok(v) => {
                if v.len() != BLOB_SHA256_LEN {
                    return Err(einval!(format!(
                        "Length of blob_id {} in RAFS v6 device entry is invalid",
                        v.len()
                    )));
                }
            }
            Err(_) => return Err(einval!("blob_id in RAFS v6 device entry is invalid")),
        }

        if self.blocks() == 0 {
            let msg = format!("invalid blocks {} in Rafs v6 device entry", self.blocks());
            return Err(einval!(msg));
        }

        Ok(())
    }

    impl_pub_getter_setter!(blocks, set_blocks, blocks, u32);
    impl_pub_getter_setter!(mapped_blkaddr, set_mapped_blkaddr, mapped_blkaddr, u32);
}

impl_bootstrap_converter!(RafsV6Device);

impl RafsStore for RafsV6Device {
    fn store(&self, w: &mut dyn RafsIoWrite) -> Result<usize> {
        w.write_all(self.as_ref())?;

        Ok(self.as_ref().len())
    }
}

/// Load blob information table from a reader.
pub fn rafsv6_load_blob_extra_info(
    meta: &RafsSuperMeta,
    r: &mut RafsIoReader,
) -> Result<HashMap<String, RafsBlobExtraInfo>> {
    let mut infos = HashMap::new();
    if meta.blob_device_table_count == 0 {
        return Ok(infos);
    }
    r.seek_to_offset(meta.blob_device_table_offset)?;
    for _idx in 0..meta.blob_device_table_count {
        let mut devslot = RafsV6Device::new();
        r.read_exact(devslot.as_mut())?;
        devslot.validate()?;
        let id = String::from_utf8(devslot.blob_id.to_vec())
            .map_err(|e| einval!(format!("invalid blob id, {}", e)))?;
        let info = RafsBlobExtraInfo {
            mapped_blkaddr: devslot.mapped_blkaddr(),
        };
        if infos.contains_key(&id) {
            return Err(einval!("duplicated blob id in RAFS v6 device table"));
        }
        infos.insert(id, info);
    }

    Ok(infos)
}

#[inline]
pub fn align_offset(offset: u64, aligned_size: u64) -> u64 {
    round_up(offset, aligned_size)
}

/// Generate EROFS `nid` from `offset`.
pub fn calculate_nid(offset: u64, meta_size: u64) -> u64 {
    (offset - meta_size) >> EROFS_INODE_SLOT_BITS
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct RafsV6Blob {
    // SHA256 digest of the blob containing chunk data.
    blob_id: [u8; BLOB_SHA256_LEN],
    // Index in the blob table.
    blob_index: u32,
    // Chunk size of the blob.
    chunk_size: u32,
    // Number of chunks in the blob.
    chunk_count: u32,
    // Compression algorithm for chunks in the blob.
    compression_algo: u32,
    // Digest algorithm for chunks in the blob.
    digest_algo: u32,
    // Feature flags.
    features: u32,
    // Size of the compressed blob, not including CI array and header.
    compressed_size: u64,
    // Size of the uncompressed blob, not including CI array and header.
    uncompressed_size: u64,

    // Size of blob ToC content, it's zero for blobs with inlined-meta.
    blob_toc_size: u32,
    // Compression algorithm for the compression information array.
    ci_compressor: u32,
    // Offset into the compressed blob for the compression information array.
    ci_offset: u64,
    // Size of the compressed compression information array.
    ci_compressed_size: u64,
    // Size of the uncompressed compression information array.
    ci_uncompressed_size: u64,

    // SHA256 digest of blob ToC content, including the toc tar header.
    // It's all zero for blobs with inlined-meta.
    blob_toc_digest: [u8; 32],
    // SHA256 digest of RAFS blob for ZRAN, containing `blob.meta`, `blob.digest` `blob.toc` and
    // optionally 'image.boot`. It's all zero for ZRAN blobs with inlined-meta, so need special
    // handling.
    // When using encryption mod, it's reused for saving encryption key.
    blob_meta_digest: [u8; 32],
    // Size of RAFS blob for ZRAN. It's zero ZRAN blobs with inlined-meta.
    // When using encryption mod, it's reused for saving encryption iv first 8 bytes.
    blob_meta_size: u64,
    // When using encryption mod, used for cipher_iv last 8 bytes.
    // 0                  7                 15
    // +------------------+------------------+
    // |  blob_meta_size  | cipher_iv[8..16] |
    // |     8bytes       |      8bytes      |
    // +------------------+------------------+
    //  \_         cipher_iv[0..16]        _/
    cipher_iv: [u8; 8],
    // Crypt algorithm for chunks in the blob.
    cipher_algo: u32,

    reserved2: [u8; 36],
}

impl Default for RafsV6Blob {
    fn default() -> Self {
        RafsV6Blob {
            blob_id: [0u8; BLOB_SHA256_LEN],
            blob_index: 0u32,
            chunk_size: 0u32,
            chunk_count: 0u32,
            compression_algo: (compress::Algorithm::None as u32).to_le(),
            digest_algo: (digest::Algorithm::Blake3 as u32).to_le(),
            features: 0u32,
            compressed_size: 0u64,
            uncompressed_size: 0u64,
            ci_compressor: (compress::Algorithm::None as u32).to_le(),
            ci_offset: 0u64,
            ci_compressed_size: 0u64,
            ci_uncompressed_size: 0u64,

            blob_toc_digest: [0u8; 32],
            blob_meta_digest: [0u8; 32],
            blob_meta_size: 0,
            blob_toc_size: 0u32,
            cipher_iv: [0u8; 8],
            cipher_algo: (crypt::Algorithm::None as u32).to_le(),

            reserved2: [0u8; 36],
        }
    }
}

impl_bootstrap_converter!(RafsV6Blob);

impl RafsV6Blob {
    #[allow(clippy::wrong_self_convention)]
    fn to_blob_info(&self) -> Result<BlobInfo> {
        // debug_assert!(RAFS_DIGEST_LENGTH == 32);
        debug_assert!(size_of::<RafsV6Blob>() == 256);

        let blob_id = String::from_utf8(self.blob_id.to_vec())
            .map_err(|e| einval!(format!("invalid blob id, {}", e)))?;
        let blob_features = BlobFeatures::try_from(u32::from_le(self.features))?;
        let mut blob_info = BlobInfo::new(
            u32::from_le(self.blob_index),
            blob_id,
            u64::from_le(self.uncompressed_size),
            u64::from_le(self.compressed_size),
            u32::from_le(self.chunk_size),
            u32::from_le(self.chunk_count),
            blob_features,
        );

        let comp = compress::Algorithm::try_from(u32::from_le(self.compression_algo))
            .map_err(|_| einval!("invalid compression algorithm in Rafs v6 blob entry"))?;
        blob_info.set_compressor(comp);
        let digest = digest::Algorithm::try_from(u32::from_le(self.digest_algo))
            .map_err(|_| einval!("invalid digest algorithm in Rafs v6 blob entry"))?;
        blob_info.set_digester(digest);
        let cipher = crypt::Algorithm::try_from(u32::from_le(self.cipher_algo))
            .map_err(|_| einval!("invalid cipher algorithm in Rafs v6 blob entry"))?;
        let cipher_object = cipher
            .new_cipher()
            .map_err(|e| einval!(format!("failed to create new cipher object {}", e)))?;
        let cipher_context = match cipher {
            crypt::Algorithm::None => None,
            crypt::Algorithm::Aes128Xts => {
                let mut cipher_iv = [0u8; 16];
                cipher_iv[..8].copy_from_slice(&self.blob_meta_size.to_le_bytes());
                cipher_iv[8..].copy_from_slice(&self.cipher_iv);
                Some(CipherContext::new(
                    self.blob_meta_digest.to_vec(),
                    cipher_iv.to_vec(),
                    false,
                    cipher,
                )?)
            }
            _ => {
                return Err(einval!(format!(
                    "invalid cipher algorithm {:?} when creating cipher context",
                    cipher
                )))
            }
        };
        blob_info.set_cipher_info(cipher, Arc::new(cipher_object), cipher_context);
        blob_info.set_blob_meta_info(
            u64::from_le(self.ci_offset),
            u64::from_le(self.ci_compressed_size),
            u64::from_le(self.ci_uncompressed_size),
            u32::from_le(self.ci_compressor),
        );
        blob_info.set_blob_toc_digest(self.blob_toc_digest);
        blob_info.set_blob_meta_digest(self.blob_meta_digest);
        blob_info.set_blob_meta_size(self.blob_meta_size);
        blob_info.set_blob_toc_size(self.blob_toc_size);

        Ok(blob_info)
    }

    fn from_blob_info(blob_info: &BlobInfo) -> Result<Self> {
        if blob_info.blob_id().len() > BLOB_SHA256_LEN || blob_info.blob_id().is_empty() {
            let msg = format!("invalid blob id in blob info, {}", blob_info.blob_id());
            return Err(einval!(msg));
        }

        let blob_id = blob_info.blob_id();
        let id = blob_id.as_bytes();
        let mut blob_id = [0u8; BLOB_SHA256_LEN];
        blob_id[..id.len()].copy_from_slice(id);

        let (blob_meta_digest, blob_meta_size, cipher_iv) = match blob_info.cipher() {
            crypt::Algorithm::None => (
                *blob_info.blob_meta_digest(),
                blob_info.blob_meta_size(),
                [0u8; 8],
            ),
            crypt::Algorithm::Aes128Xts => {
                let cipher_ctx = match blob_info.cipher_context() {
                    Some(ctx) => ctx,
                    None => {
                        return Err(einval!(
                            "cipher context is unset while using Aes128Xts encryption algorithm"
                        ))
                    }
                };
                let cipher_key: [u8; 32] = cipher_ctx.get_cipher_meta().0.try_into().unwrap();
                let (cipher_iv_top_half, cipher_iv_bottom_half) =
                    cipher_ctx.get_cipher_meta().1.split_at(8);
                (
                    cipher_key,
                    u64::from_le_bytes(cipher_iv_top_half.try_into().unwrap()),
                    cipher_iv_bottom_half.try_into().unwrap(),
                )
            }
            _ => {
                return Err(einval!(format!(
                    "invalid cipher algorithm type {:?} in blob info",
                    blob_info.cipher()
                )))
            }
        };

        Ok(RafsV6Blob {
            blob_id,
            blob_index: blob_info.blob_index().to_le(),
            chunk_size: blob_info.chunk_size().to_le(),
            chunk_count: blob_info.chunk_count().to_le(),
            compression_algo: (blob_info.compressor() as u32).to_le(),
            digest_algo: (blob_info.digester() as u32).to_le(),
            compressed_size: blob_info.compressed_size().to_le(),
            uncompressed_size: blob_info.uncompressed_size().to_le(),
            features: blob_info.features().bits().to_le(),
            ci_compressor: (blob_info.meta_ci_compressor() as u32).to_le(),
            ci_offset: blob_info.meta_ci_offset().to_le(),
            ci_compressed_size: blob_info.meta_ci_compressed_size().to_le(),
            ci_uncompressed_size: blob_info.meta_ci_uncompressed_size().to_le(),

            blob_toc_digest: *blob_info.blob_toc_digest(),
            blob_meta_digest,
            blob_meta_size,
            blob_toc_size: blob_info.blob_toc_size(),
            cipher_iv,
            cipher_algo: (blob_info.cipher() as u32).to_le(),

            reserved2: [0u8; 36],
        })
    }

    fn validate(&self, blob_index: u32, chunk_size: u32, flags: RafsSuperFlags) -> bool {
        match String::from_utf8(self.blob_id.to_vec()) {
            Ok(v) => {
                if v.len() != BLOB_SHA256_LEN {
                    error!(
                        "RafsV6Blob: idx {} blob id length {:x} is invalid",
                        blob_index,
                        v.len()
                    );
                    return false;
                }
            }
            Err(_) => {
                error!(
                    "RafsV6Blob: idx {} blob_id from_utf8 is invalid",
                    blob_index
                );
                return false;
            }
        }

        if u32::from_le(self.blob_index) != blob_index {
            error!(
                "RafsV6Blob: blob_index doesn't match {} {}",
                u32::from_le(self.blob_index),
                blob_index
            );
            return false;
        }

        let c_size = u32::from_le(self.chunk_size) as u64;
        if c_size.count_ones() != 1
            || !(EROFS_BLOCK_SIZE_4096..=RAFS_MAX_CHUNK_SIZE).contains(&c_size)
            || c_size != chunk_size as u64
        {
            error!(
                "RafsV6Blob: idx {} invalid chunk_size 0x{:x}, expect 0x{:x}",
                blob_index, c_size, chunk_size
            );
            return false;
        }

        let chunk_count = u32::from_le(self.chunk_count);
        if chunk_count > RAFS_MAX_CHUNKS_PER_BLOB {
            error!(
                "RafsV6Blob: idx {} invalid chunk_count {:x}",
                blob_index, chunk_count
            );
            return false;
        }

        if compress::Algorithm::try_from(u32::from_le(self.compression_algo)).is_err()
            || compress::Algorithm::try_from(u32::from_le(self.ci_compressor)).is_err()
            || digest::Algorithm::try_from(u32::from_le(self.digest_algo)).is_err()
            || crypt::Algorithm::try_from(self.cipher_algo).is_err()
        {
            error!(
                "RafsV6Blob: idx {} invalid compression_algo {} ci_compressor {} digest_algo {} cipher_algo {}",
                blob_index, self.compression_algo, self.ci_compressor, self.digest_algo, self.cipher_algo,
            );
            return false;
        }

        let uncompressed_blob_size = u64::from_le(self.uncompressed_size);
        let compressed_blob_size = u64::from_le(self.compressed_size);
        if uncompressed_blob_size > BLOB_MAX_SIZE_UNCOMPRESSED {
            error!(
                "RafsV6Blob: idx {} invalid uncompressed_size {:x}",
                blob_index, uncompressed_blob_size
            );
            return false;
        }
        if compressed_blob_size > BLOB_MAX_SIZE_COMPRESSED {
            error!(
                "RafsV6Blob: idx {} invalid compressed_size {:x}",
                blob_index, compressed_blob_size
            );
            return false;
        }

        let blob_features = match BlobFeatures::try_from(self.features) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let tarfs_mode = flags.contains(RafsSuperFlags::TARTFS_MODE);
        match (blob_features.contains(BlobFeatures::ALIGNED), tarfs_mode) {
            (false, false) => {
                error!(
                    "RafsV6Blob: idx {} should have `ALIGNED` feature bit set",
                    blob_index
                );
                return false;
            }
            (true, true) => {
                error!("RafsV6Blob: `ALIGNED` flag should not be set for `TARFS` mode");
                return false;
            }
            _ => {}
        }

        let ci_offset = u64::from_le(self.ci_offset);
        let ci_compr_size = u64::from_le(self.ci_compressed_size);
        let ci_uncompr_size = u64::from_le(self.ci_uncompressed_size);
        if ci_offset.checked_add(ci_compr_size).is_none() {
            error!("RafsV6Blob: idx {} invalid fields, ci_compressed_size {:x} + ci_offset {:x} wraps around", blob_index, ci_compr_size, ci_offset);
            return false;
        } else if ci_compr_size > ci_uncompr_size {
            error!("RafsV6Blob: idx {} invalid fields, ci_compressed_size {:x} is greater than ci_uncompressed_size {:x}", blob_index, ci_compr_size, ci_uncompr_size);
            return false;
        }

        let count = chunk_count as u64;
        if blob_features.contains(BlobFeatures::CHUNK_INFO_V2)
            && (blob_features.contains(BlobFeatures::BATCH)
                || blob_features.contains(BlobFeatures::ZRAN)
                || blob_features.contains(BlobFeatures::ENCRYPTED))
        {
            if ci_uncompr_size < count * size_of::<BlobChunkInfoV2Ondisk>() as u64 {
                error!(
                    "RafsV6Blob: idx {} invalid ci_d_size {}",
                    blob_index, ci_uncompr_size
                );
                return false;
            }
        } else if blob_features.contains(BlobFeatures::CHUNK_INFO_V2) {
            if ci_uncompr_size != count * size_of::<BlobChunkInfoV2Ondisk>() as u64 {
                error!(
                    "RafsV6Blob: idx {} invalid ci_d_size {}",
                    blob_index, ci_uncompr_size
                );
                return false;
            }
        } else if blob_features.contains(BlobFeatures::BATCH)
            || blob_features.contains(BlobFeatures::ZRAN)
            || blob_features.contains(BlobFeatures::ENCRYPTED)
        {
            error!(
                "RafsV6Blob: idx {} invalid feature bits {}",
                blob_index,
                blob_features.bits()
            );
            return false;
        } else if !tarfs_mode
            && ci_uncompr_size != count * size_of::<BlobChunkInfoV1Ondisk>() as u64
        {
            error!(
                "RafsV6Blob: idx {} invalid fields, ci_d_size {:x}, chunk_count {:x}",
                blob_index, ci_uncompr_size, chunk_count
            );
            return false;
        }

        true
    }
}

/// Rafs v6 blob description table.
#[derive(Clone, Debug, Default)]
pub struct RafsV6BlobTable {
    /// Base blob information array.
    entries: Vec<Arc<BlobInfo>>,
}

impl RafsV6BlobTable {
    /// Create a new instance of `RafsV6BlobTable`.
    pub fn new() -> Self {
        RafsV6BlobTable {
            entries: Vec::new(),
        }
    }

    /// Get blob table size.
    pub fn size(&self) -> usize {
        self.entries.len() * size_of::<RafsV6Blob>()
    }

    /// Get base information for a blob.
    #[inline]
    pub fn get(&self, blob_index: u32) -> Result<Arc<BlobInfo>> {
        if blob_index >= self.entries.len() as u32 {
            Err(enoent!("blob not found"))
        } else {
            Ok(self.entries[blob_index as usize].clone())
        }
    }

    /// Get the base blob information array.
    pub fn get_all(&self) -> Vec<Arc<BlobInfo>> {
        self.entries.clone()
    }

    /// Add information for new blob into the blob information table.
    #[allow(clippy::too_many_arguments)]
    pub fn add(
        &mut self,
        blob_id: String,
        prefetch_offset: u32,
        prefetch_size: u32,
        chunk_size: u32,
        chunk_count: u32,
        uncompressed_size: u64,
        compressed_size: u64,
        flags: RafsSuperFlags,
        blob_meta_digest: [u8; 32],
        blob_toc_digest: [u8; 32],
        blob_meta_size: u64,
        blob_toc_size: u32,
        header: BlobCompressionContextHeader,
        cipher_object: Arc<Cipher>,
        cipher_context: Option<CipherContext>,
    ) -> u32 {
        let blob_index = self.entries.len() as u32;
        let blob_features = BlobFeatures::try_from(header.features()).unwrap();
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
        blob_info.set_cipher(flags.into());
        blob_info.set_prefetch_info(prefetch_offset as u64, prefetch_size as u64);
        blob_info.set_blob_meta_info(
            header.ci_compressed_offset(),
            header.ci_compressed_size(),
            header.ci_uncompressed_size(),
            header.ci_compressor() as u32,
        );
        blob_info.set_blob_meta_digest(blob_meta_digest);
        blob_info.set_blob_toc_digest(blob_toc_digest);
        blob_info.set_blob_meta_size(blob_meta_size);
        blob_info.set_blob_toc_size(blob_toc_size);
        blob_info.set_cipher_info(flags.into(), cipher_object, cipher_context);

        self.entries.push(Arc::new(blob_info));

        blob_index
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
        if blob_table_size as usize % size_of::<RafsV6Blob>() != 0 {
            let msg = format!("invalid Rafs v6 blob table size {}", blob_table_size);
            return Err(einval!(msg));
        }

        for idx in 0..(blob_table_size as usize / size_of::<RafsV6Blob>()) {
            let mut blob = RafsV6Blob::default();
            r.read_exact(blob.as_mut())?;
            if !blob.validate(idx as u32, chunk_size, flags) {
                return Err(einval!("invalid Rafs v6 blob entry"));
            }
            let blob_info = blob.to_blob_info()?;
            self.entries.push(Arc::new(blob_info));
        }

        Ok(())
    }
}

impl RafsStore for RafsV6BlobTable {
    fn store(&self, w: &mut dyn RafsIoWrite) -> Result<usize> {
        for blob_info in self.entries.iter() {
            let blob: RafsV6Blob = RafsV6Blob::from_blob_info(blob_info)?;
            trace!(
                "blob_info index {}, chunk_count {} blob_id {:?}",
                blob_info.blob_index(),
                blob_info.chunk_count(),
                blob_info.blob_id(),
            );
            w.write_all(blob.as_ref())?;
        }

        Ok(self.entries.len() * size_of::<RafsV6Blob>())
    }
}

// RafsV6 xattr
const EROFS_XATTR_INDEX_USER: u8 = 1;
const EROFS_XATTR_INDEX_POSIX_ACL_ACCESS: u8 = 2;
const EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT: u8 = 3;
const EROFS_XATTR_INDEX_TRUSTED: u8 = 4;
// const EROFS_XATTR_INDEX_LUSTRE: u8 = 5;
const EROFS_XATTR_INDEX_SECURITY: u8 = 6;

const XATTR_USER_PREFIX: &str = "user.";
const XATTR_SECURITY_PREFIX: &str = "security.";
const XATTR_TRUSTED_PREFIX: &str = "trusted.";
const XATTR_NAME_POSIX_ACL_ACCESS: &str = "system.posix_acl_access";
const XATTR_NAME_POSIX_ACL_DEFAULT: &str = "system.posix_acl_default";

struct RafsV6XattrPrefix {
    index: u8,
    prefix: &'static str,
    prefix_len: usize,
}

impl RafsV6XattrPrefix {
    fn new(prefix: &'static str, index: u8, prefix_len: usize) -> Self {
        RafsV6XattrPrefix {
            index,
            prefix,
            prefix_len,
        }
    }
}

lazy_static! {
    static ref RAFSV6_XATTR_TYPES: Vec<RafsV6XattrPrefix> = vec![
        RafsV6XattrPrefix::new(
            XATTR_USER_PREFIX,
            EROFS_XATTR_INDEX_USER,
            XATTR_USER_PREFIX.as_bytes().len()
        ),
        RafsV6XattrPrefix::new(
            XATTR_NAME_POSIX_ACL_ACCESS,
            EROFS_XATTR_INDEX_POSIX_ACL_ACCESS,
            XATTR_NAME_POSIX_ACL_ACCESS.as_bytes().len()
        ),
        RafsV6XattrPrefix::new(
            XATTR_NAME_POSIX_ACL_DEFAULT,
            EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT,
            XATTR_NAME_POSIX_ACL_DEFAULT.as_bytes().len()
        ),
        RafsV6XattrPrefix::new(
            XATTR_TRUSTED_PREFIX,
            EROFS_XATTR_INDEX_TRUSTED,
            XATTR_TRUSTED_PREFIX.as_bytes().len()
        ),
        RafsV6XattrPrefix::new(
            XATTR_SECURITY_PREFIX,
            EROFS_XATTR_INDEX_SECURITY,
            XATTR_SECURITY_PREFIX.as_bytes().len()
        ),
    ];
}

// inline xattrs (n == i_xattr_icount):
// erofs_xattr_ibody_header(1) + (n - 1) * 4 bytes
//          12 bytes           /                   \
//                            /                     \
//                           /-----------------------\
//                           |  erofs_xattr_entries+ |
//                           +-----------------------+
// inline xattrs must starts with erofs_xattr_ibody_header.
#[repr(C)]
#[derive(Default)]
pub struct RafsV6XattrIbodyHeader {
    h_reserved: u32,
    h_shared_count: u8,
    h_reserved2: [u8; 7],
    // may be followed by shared xattr id array
}

impl_bootstrap_converter!(RafsV6XattrIbodyHeader);

impl RafsV6XattrIbodyHeader {
    pub fn new() -> Self {
        RafsV6XattrIbodyHeader::default()
    }

    /// Load a `RafsV6XattrIbodyHeader` from a reader.
    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }
}

// RafsV6 xattr entry (for both inline & shared xattrs)
#[repr(C)]
#[derive(Default, PartialEq)]
pub struct RafsV6XattrEntry {
    // length of name
    e_name_len: u8,
    // attribute name index
    e_name_index: u8,
    // size of attribute value
    e_value_size: u16,
    // followed by e_name and e_value
}

impl_bootstrap_converter!(RafsV6XattrEntry);

impl RafsV6XattrEntry {
    fn new() -> Self {
        RafsV6XattrEntry::default()
    }

    pub fn name_len(&self) -> u32 {
        self.e_name_len as u32
    }

    pub fn name_index(&self) -> u8 {
        self.e_name_index
    }

    pub fn value_size(&self) -> u32 {
        u16::from_le(self.e_value_size) as u32
    }

    fn set_name_len(&mut self, v: u8) {
        self.e_name_len = v;
    }

    fn set_name_index(&mut self, v: u8) {
        self.e_name_index = v;
    }

    fn set_value_size(&mut self, v: u16) {
        self.e_value_size = v.to_le();
    }
}

pub(crate) fn recover_namespace(index: u8) -> Result<OsString> {
    let pos = RAFSV6_XATTR_TYPES
        .iter()
        .position(|x| x.index == index)
        .ok_or_else(|| einval!(format!("invalid xattr name index {}", index)))?;
    OsString::from_str(RAFSV6_XATTR_TYPES[pos].prefix)
        .map_err(|_e| einval!("invalid xattr name prefix"))
}

impl RafsXAttrs {
    /// Get the number of xattr pairs.
    pub fn count_v6(&self) -> usize {
        if self.is_empty() {
            0
        } else {
            let size = self.aligned_size_v6();
            (size - size_of::<RafsV6XattrIbodyHeader>()) / size_of::<RafsV6XattrEntry>() + 1
        }
    }

    /// Get aligned size of all xattr pairs.
    pub fn aligned_size_v6(&self) -> usize {
        if self.is_empty() {
            0
        } else {
            let mut size: usize = size_of::<RafsV6XattrIbodyHeader>();
            for (key, value) in self.pairs.iter() {
                // Safe to unwrap() because RafsXAttrs.add()/adds() has validated the prefix.
                let (_, prefix_len) = Self::match_prefix(key).expect("xattr is not valid");

                size += size_of::<RafsV6XattrEntry>();
                size += key.byte_size() - prefix_len + value.len();
                size = round_up(size as u64, size_of::<RafsV6XattrEntry>() as u64) as usize;
            }
            size
        }
    }

    /// Write Xattr to rafsv6 ondisk inode.
    pub fn store_v6(&self, w: &mut dyn RafsIoWrite) -> Result<usize> {
        let header = RafsV6XattrIbodyHeader::new();
        w.write_all(header.as_ref())?;

        if !self.pairs.is_empty() {
            for (key, value) in self.pairs.iter() {
                let (index, prefix_len) = Self::match_prefix(key)
                    .map_err(|_| einval!(format!("invalid xattr key {:?}", key)))?;
                if key.len() <= prefix_len {
                    return Err(einval!(format!("invalid xattr key {:?}", key)));
                }
                if value.len() > u16::MAX as usize {
                    return Err(einval!("xattr value size is too big"));
                }

                let mut entry = RafsV6XattrEntry::new();
                entry.set_name_len((key.byte_size() - prefix_len) as u8);
                entry.set_name_index(index);
                entry.set_value_size(value.len() as u16);

                w.write_all(entry.as_ref())?;
                w.write_all(&key.as_bytes()[prefix_len..])?;
                w.write_all(value.as_ref())?;

                let size =
                    size_of::<RafsV6XattrEntry>() + key.byte_size() - prefix_len + value.len();
                let padding =
                    round_up(size as u64, size_of::<RafsV6XattrEntry>() as u64) as usize - size;
                w.write_padding(padding)?;
            }
        }

        Ok(0)
    }

    fn match_prefix(key: &OsStr) -> Result<(u8, usize)> {
        let key_str = key.to_string_lossy();
        let pos = RAFSV6_XATTR_TYPES
            .iter()
            .position(|x| key_str.starts_with(x.prefix))
            .ok_or_else(|| einval!(format!("xattr prefix {:?} is not valid", key)))?;
        Ok((
            RAFSV6_XATTR_TYPES[pos].index,
            RAFSV6_XATTR_TYPES[pos].prefix_len,
        ))
    }
}

#[derive(Clone, Default, Debug)]
pub struct RafsV6PrefetchTable {
    /// List of inode numbers for prefetch.
    /// Note: It's not inode index of inodes table being stored here.
    pub inodes: Vec<u32>,
}

impl RafsV6PrefetchTable {
    /// Create a new instance of `RafsV6PrefetchTable`.
    pub fn new() -> RafsV6PrefetchTable {
        RafsV6PrefetchTable { inodes: vec![] }
    }

    /// Get content size of the inode prefetch table.
    pub fn size(&self) -> usize {
        self.len() * size_of::<u32>()
    }

    /// Get number of entries in the prefetch table.
    pub fn len(&self) -> usize {
        self.inodes.len()
    }

    /// Check whether the inode prefetch table is empty.
    pub fn is_empty(&self) -> bool {
        self.inodes.is_empty()
    }

    /// Add an inode into the inode prefetch table.
    pub fn add_entry(&mut self, ino: u32) {
        self.inodes.push(ino);
    }

    /// Store the inode prefetch table to a writer.
    pub fn store(&mut self, w: &mut dyn RafsIoWrite) -> Result<usize> {
        let (_, data, _) = unsafe { self.inodes.align_to::<u8>() };
        w.write_all(data.as_ref())?;

        // OK. Let's see if we have to align... :-(
        // let cur_len = self.inodes.len() * size_of::<u32>();

        Ok(data.len())
    }

    /// Load a inode prefetch table from a reader.
    ///
    /// Note: Generally, prefetch happens after loading bootstrap, so with methods operating
    /// files with changing their offset won't bring errors. But we still use `pread` now so as
    /// to make this method more stable and robust. Even dup(2) can't give us a separated file struct.
    pub fn load_prefetch_table_from(
        &mut self,
        r: &mut RafsIoReader,
        offset: u64,
        entries: usize,
    ) -> Result<usize> {
        self.inodes = vec![0u32; entries];

        let (_, data, _) = unsafe { self.inodes.align_to_mut::<u8>() };
        r.seek_to_offset(offset)?;
        r.read_exact(data)?;

        Ok(data.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BufWriter, RafsIoRead};
    use std::fs::OpenOptions;
    use std::io::Write;
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
        let mut writer = BufWriter::new(w);
        let mut reader: Box<dyn RafsIoRead> = Box::new(r);

        sb.s_blocks = 0x1000;
        sb.s_extra_devices = 5;
        sb.s_inos = 0x200;
        sb.store(&mut writer).unwrap();
        writer.flush().unwrap();

        let mut sb2 = RafsV6SuperBlock::new();
        sb2.load(&mut reader).unwrap();
        assert_eq!(sb2.s_magic, EROFS_SUPER_MAGIC_V1.to_le());
        assert_eq!(sb2.s_blocks, 0x1000u32.to_le());
        assert_eq!(sb2.s_extra_devices, 5u16.to_le());
        assert_eq!(sb2.s_inos, 0x200u64.to_le());
        assert_eq!(sb2.s_feature_compat, EROFS_FEATURE_COMPAT_RAFS_V6.to_le());
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
        let mut writer = BufWriter::new(w);
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
            u16::to_le(EROFS_INODE_LAYOUT_EXTENDED | (EROFS_INODE_CHUNK_BASED << 1))
        );
        inode.set_uidgid(1, 2);
        inode.set_mtime(3, 4);
        inode.store(&mut writer).unwrap();
        writer.flush().unwrap();

        let mut inode2 = RafsV6InodeExtended::new();
        inode2.load(&mut reader).unwrap();
        assert_eq!(inode2.i_uid, 1u32.to_le());
        assert_eq!(inode2.i_gid, 2u32.to_le());
        assert_eq!(inode2.i_mtime, 3u64.to_le());
        assert_eq!(inode2.i_mtime_nsec, 4u32.to_le());
        assert_eq!(
            inode2.i_format,
            u16::to_le(EROFS_INODE_LAYOUT_EXTENDED | (EROFS_INODE_CHUNK_BASED << 1))
        );
    }

    #[test]
    fn test_rafs_v6_chunk_header() {
        let chunk_size: u32 = 1024 * 1024;
        let header = RafsV6InodeChunkHeader::new(chunk_size as u64, EROFS_BLOCK_SIZE_4096);
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
        let mut writer = BufWriter::new(w);
        let mut reader: Box<dyn RafsIoRead> = Box::new(r);

        let mut chunk = RafsV6InodeChunkAddr::new();
        chunk.set_blob_index(3);
        chunk.set_blob_ci_index(0x123456);
        chunk.set_block_addr(0xa5a53412);
        chunk.store(&mut writer).unwrap();
        writer.flush().unwrap();
        let mut chunk2 = RafsV6InodeChunkAddr::new();
        chunk2.load(&mut reader).unwrap();
        assert_eq!(chunk2.blob_index().unwrap(), 3);
        assert_eq!(chunk2.blob_ci_index(), 0x123456);
        assert_eq!(chunk2.block_addr(), 0xa5a53412);
        assert!(chunk2.validate(4));
        assert!(chunk2.validate(3));
        assert!(!chunk2.validate(2));
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
        let mut writer = BufWriter::new(w);
        let mut reader: Box<dyn RafsIoRead> = Box::new(r);

        let id = [0xa5u8; 64];
        let mut device = RafsV6Device::new();
        device.set_blocks(0x1234);
        device.set_blob_id(&id);
        device.store(&mut writer).unwrap();
        writer.flush().unwrap();
        let mut device2 = RafsV6Device::new();
        device2.load(&mut reader).unwrap();
        assert_eq!(device2.blocks(), 0x1234);
        assert_eq!(device.blob_id(), &id);
    }

    #[test]
    fn test_rafs_xattr_count_v6() {
        let mut xattrs = RafsXAttrs::new();
        xattrs.add(OsString::from("user.a"), vec![1u8]).unwrap();
        xattrs.add(OsString::from("trusted.b"), vec![2u8]).unwrap();

        assert_eq!(xattrs.count_v6(), 5);

        let xattrs2 = RafsXAttrs::new();
        assert_eq!(xattrs2.count_v6(), 0);
    }

    #[test]
    fn test_rafs_xattr_size_v6() {
        let mut xattrs = RafsXAttrs::new();
        xattrs.add(OsString::from("user.a"), vec![1u8]).unwrap();
        xattrs.add(OsString::from("trusted.b"), vec![2u8]).unwrap();

        let size = 12 + 8 + 8;
        assert_eq!(xattrs.aligned_size_v6(), size);

        let xattrs2 = RafsXAttrs::new();
        assert_eq!(xattrs2.aligned_size_v6(), 0);

        let mut xattrs2 = RafsXAttrs::new();
        xattrs2.add(OsString::from("user.a"), vec![1u8]).unwrap();
        xattrs2
            .add(OsString::from("unknown.b"), vec![2u8])
            .unwrap_err();
    }

    #[test]
    fn test_rafs_xattr_store_v6() {
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
        let mut writer = BufWriter::new(w);
        let mut reader: Box<dyn RafsIoRead> = Box::new(r);

        let mut xattrs = RafsXAttrs::new();
        xattrs.add(OsString::from("user.nydus"), vec![1u8]).unwrap();
        xattrs
            .add(OsString::from("security.rafs"), vec![2u8, 3u8])
            .unwrap();
        xattrs.store_v6(&mut writer).unwrap();
        writer.flush().unwrap();

        let mut header = RafsV6XattrIbodyHeader::new();
        header.load(&mut reader).unwrap();
        let mut size = size_of::<RafsV6XattrIbodyHeader>();

        assert_eq!(header.h_shared_count, 0u8);

        let target1 = RafsV6XattrEntry {
            e_name_len: 4u8,
            e_name_index: 6u8,
            e_value_size: u16::to_le(2u16),
        };

        let target2 = RafsV6XattrEntry {
            e_name_len: 5u8,
            e_name_index: 1u8,
            e_value_size: u16::to_le(1u16),
        };

        let mut entry1 = RafsV6XattrEntry::new();
        reader.read_exact(entry1.as_mut()).unwrap();
        assert!((entry1 == target1 || entry1 == target2));

        size += size_of::<RafsV6XattrEntry>()
            + entry1.name_len() as usize
            + entry1.value_size() as usize;

        reader
            .seek_to_offset(round_up(size as u64, size_of::<RafsV6XattrEntry>() as u64))
            .unwrap();

        let mut entry2 = RafsV6XattrEntry::new();
        reader.read_exact(entry2.as_mut()).unwrap();
        if entry1 == target1 {
            assert!(entry2 == target2);
        } else {
            assert!(entry2 == target1);
        }
    }

    #[test]
    fn test_invalid_blob_idx_from_chunk_addr() {
        let mut addr = RafsV6InodeChunkAddr::new();
        assert!(addr.blob_index().is_err());
        addr.set_blob_index(8);
        assert_eq!(addr.blob_index().unwrap(), 8);

        assert_eq!(addr.blob_ci_index(), 0);
        addr.set_blob_ci_index(131);
        assert_eq!(addr.blob_ci_index(), 131);

        assert_eq!(addr.block_addr(), 0);
        addr.set_block_addr(179);
        assert_eq!(addr.block_addr(), 179);
    }
}
