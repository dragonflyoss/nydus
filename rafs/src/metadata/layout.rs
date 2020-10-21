// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! RAFS on disk layout structures.
//!
//! # RAFS File System Meta Data Format Version 5
//! Previously RAFS has different formats for on disk meta data and runtime meta data. So when
//! initializing an RAFS instance, it will sequentially read and parse the on disk meta data,
//! build a copy of in memory runtime meta data. This may cause slow startup and cost too much
//! memory to build in memory meta data.
//!
//! The RAFS File System Meta Data Format Version 5 (aka V5) is defined to support directly mapping
//! RAFS meta data into process as runtime meta data, so we could parse RAFS on disk meta data on
//! demand. The V5 meta data format has following changes:
//! 1) file system version number been bumped to 0x500.
//! 2) Directory inodes will sequentially assign globally unique `child index` to it's child inodes.
//!    Two fields, "child_index" and "child_count", have been added to the OndiskInode struct.
//! 3) For inodes with hard link count as 1, the `child index` equals to its assigned inode number.
//! 4) For inodes with hard link count bigger than 1, the `child index` may be different from the
//!    assigned inode number. Among those child entries linking to the same inode, there's will be
//!    one and only one child entry having the inode number as its assigned `child index'.
//! 5) A child index mapping table is introduced, which is used to map `child index` into offset
//!    from the base of the super block. The formula to calculate the inode offset is:
//!      inode_offset_from_sb = inode_table[child_index] << 3
//! 6) The child index mapping table follows the super block by default.
//!
//! Giving above definition, we could get the inode object for an inode number or child index as:
//!    inode_ptr = sb_base_ptr + inode_offset_from_sb(inode_number)
//!    inode_ptr = sb_base_ptr + inode_offset_from_sb(child_index)

use std::convert::TryFrom;
use std::convert::TryInto;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{Error, Result};
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;

use nydus_utils::{einval, enoent};

use super::*;

pub const RAFS_SUPERBLOCK_SIZE: usize = 8192;
pub const RAFS_SUPERBLOCK_RESERVED_SIZE: usize = RAFS_SUPERBLOCK_SIZE - 72;
pub const RAFS_SUPER_MAGIC: u32 = 0x5241_4653;
pub const RAFS_SUPER_VERSION_V4: u32 = 0x400;
pub const RAFS_SUPER_VERSION_V5: u32 = 0x500;
pub const RAFS_SUPER_MIN_VERSION: u32 = RAFS_SUPER_VERSION_V4;
pub const RAFS_ALIGNMENT: usize = 8;
pub const RAFS_ROOT_INODE: u64 = 1;

macro_rules! impl_bootstrap_converter {
    ($T: ty) => {
        impl TryFrom<&[u8]> for &$T {
            type Error = Error;

            fn try_from(buf: &[u8]) -> std::result::Result<Self, Self::Error> {
                let ptr = buf as *const [u8] as *const u8;
                if buf.len() != size_of::<$T>()
                    || ptr as usize & (std::mem::align_of::<$T>() - 1) != 0
                {
                    return Err(einval!("convert failed"));
                }

                Ok(unsafe { &*(ptr as *const $T) })
            }
        }

        impl TryFrom<&mut [u8]> for &mut $T {
            type Error = Error;

            fn try_from(buf: &mut [u8]) -> std::result::Result<Self, Self::Error> {
                let ptr = buf as *const [u8] as *const u8;
                if buf.len() != size_of::<$T>()
                    || ptr as usize & (std::mem::align_of::<$T>() - 1) != 0
                {
                    return Err(einval!("convert failed"));
                }

                Ok(unsafe { &mut *(ptr as *const $T as *mut $T) })
            }
        }

        impl AsRef<[u8]> for $T {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                let ptr = self as *const $T as *const u8;
                unsafe { &*std::slice::from_raw_parts(ptr, size_of::<$T>()) }
            }
        }

        impl AsMut<[u8]> for $T {
            #[inline]
            fn as_mut(&mut self) -> &mut [u8] {
                let ptr = self as *mut $T as *mut u8;
                unsafe { &mut *std::slice::from_raw_parts_mut(ptr, size_of::<$T>()) }
            }
        }
    };
}

macro_rules! impl_pub_getter_setter {
    ($G: ident, $S: ident, $F: ident, $U: ty) => {
        #[inline]
        pub fn $G(&self) -> $U {
            <$U>::from_le(self.$F)
        }

        #[inline]
        pub fn $S(&mut self, $F: $U) {
            self.$F = <$U>::to_le($F);
        }
    };
}

/// RAFS SuperBlock on disk data format, 8192 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OndiskSuperBlock {
    /// RAFS super magic
    s_magic: u32,
    /// RAFS version
    s_fs_version: u32,
    /// superblock on disk size
    s_sb_size: u32,
    /// block size
    s_block_size: u32,
    /// superblock flags
    s_flags: u64,
    /// V5: Number of unique inodes(hard link counts as 1).
    s_inodes_count: u64,
    /// V5: Offset of inode table
    s_inode_table_offset: u64,
    /// Those inodes which need to prefetch will have there indexes put into this table.
    /// Then Rafs has a hint to prefetch inodes and doesn't have to load all inodes to page cache
    /// under *direct* metadata mode. It helps save memory usage.
    /// [idx1:u32, idx2:u32, idx3:u32 ...]
    s_prefetch_table_offset: u64,
    /// V5: Offset of blob table
    s_blob_table_offset: u64,
    /// V5: Size of inode table
    s_inode_table_entries: u32,
    s_prefetch_table_entries: u32,
    /// V5: Entries of blob table
    s_blob_table_size: u32,
    s_reserved: u32,
    /// Unused area
    s_reserved2: [u8; RAFS_SUPERBLOCK_RESERVED_SIZE],
}

bitflags! {
    pub struct RafsSuperFlags: u64 {
        /// Data chunks are not compressed.
        const COMPRESS_NONE = 0x0000_0001;
        /// Data chunks are compressed with lz4_block.
        const COMPRESS_LZ4_BLOCK = 0x0000_0002;
        /// Use blake3 hash algorithm to calculate digest.
        const DIGESTER_BLAKE3 = 0x0000_0004;
        /// Use sha256 hash algorithm to calculate digest.
        const DIGESTER_SHA256 = 0x0000_0008;
        /// Inode has explicit uid gid fields.
        /// If unset, use nydusd process euid/egid for all
        /// inodes at runtime.
        const EXPLICIT_UID_GID = 0x0000_0010;
        /// Some inode has xattr.
        /// If unset, nydusd may return ENOSYS for getxattr/listxattr
        /// calls.
        const HAS_XATTR = 0x0000_0020;
    }
}

impl Default for RafsSuperFlags {
    fn default() -> Self {
        RafsSuperFlags::empty()
    }
}

impl fmt::Display for RafsSuperFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.contains(RafsSuperFlags::COMPRESS_NONE) {
            write!(f, "COMPRESS_NONE ")?;
        }
        if self.contains(RafsSuperFlags::COMPRESS_LZ4_BLOCK) {
            write!(f, "COMPRESS_LZ4_BLOCK ")?;
        }
        if self.contains(RafsSuperFlags::DIGESTER_BLAKE3) {
            write!(f, "DIGESTER_BLAKE3 ")?;
        }
        if self.contains(RafsSuperFlags::DIGESTER_SHA256) {
            write!(f, "DIGESTER_SHA256 ")?;
        }
        if self.contains(RafsSuperFlags::EXPLICIT_UID_GID) {
            write!(f, "EXPLICIT_UID_GID ")?;
        }
        if self.contains(RafsSuperFlags::HAS_XATTR) {
            write!(f, "HAS_XATTR ")?;
        }
        Ok(())
    }
}

impl Into<digest::Algorithm> for RafsSuperFlags {
    fn into(self) -> digest::Algorithm {
        match self {
            x if x.contains(RafsSuperFlags::DIGESTER_BLAKE3) => digest::Algorithm::Blake3,
            x if x.contains(RafsSuperFlags::DIGESTER_SHA256) => digest::Algorithm::Sha256,
            _ => digest::Algorithm::Blake3,
        }
    }
}

impl From<digest::Algorithm> for RafsSuperFlags {
    fn from(d: digest::Algorithm) -> RafsSuperFlags {
        match d {
            digest::Algorithm::Blake3 => RafsSuperFlags::DIGESTER_BLAKE3,
            digest::Algorithm::Sha256 => RafsSuperFlags::DIGESTER_SHA256,
        }
    }
}

impl Into<compress::Algorithm> for RafsSuperFlags {
    fn into(self) -> compress::Algorithm {
        match self {
            x if x.contains(RafsSuperFlags::COMPRESS_NONE) => compress::Algorithm::None,
            x if x.contains(RafsSuperFlags::COMPRESS_LZ4_BLOCK) => compress::Algorithm::LZ4Block,
            _ => compress::Algorithm::LZ4Block,
        }
    }
}

impl From<compress::Algorithm> for RafsSuperFlags {
    fn from(c: compress::Algorithm) -> RafsSuperFlags {
        match c {
            compress::Algorithm::None => RafsSuperFlags::COMPRESS_NONE,
            compress::Algorithm::LZ4Block => RafsSuperFlags::COMPRESS_LZ4_BLOCK,
        }
    }
}

impl Default for OndiskSuperBlock {
    fn default() -> Self {
        Self {
            s_magic: u32::to_le(RAFS_SUPER_MAGIC as u32),
            s_fs_version: u32::to_le(RAFS_SUPER_VERSION_V5),
            s_sb_size: u32::to_le(RAFS_SUPERBLOCK_SIZE as u32),
            s_block_size: u32::to_le(RAFS_DEFAULT_BLOCK_SIZE as u32),
            s_flags: u64::to_le(0),
            s_inodes_count: u64::to_le(0),
            s_inode_table_entries: u32::to_le(0),
            s_inode_table_offset: u64::to_le(0),
            s_prefetch_table_offset: u64::to_le(0),
            s_prefetch_table_entries: u32::to_le(0),
            s_blob_table_size: u32::to_le(0),
            s_blob_table_offset: u64::to_le(0),
            s_reserved: u32::to_le(0),
            s_reserved2: [0u8; RAFS_SUPERBLOCK_RESERVED_SIZE],
        }
    }
}

impl OndiskSuperBlock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        if self.magic() != RAFS_SUPER_MAGIC
            || self.version() < RAFS_SUPER_MIN_VERSION as u32
            || self.version() > RAFS_SUPER_VERSION_V5 as u32
            || self.sb_size() != RAFS_SUPERBLOCK_SIZE as u32
        {
            return Err(err_invalid_superblock!());
        }

        match self.version() {
            RAFS_SUPER_VERSION_V4 => {
                if self.inodes_count() != 0
                    || self.inode_table_offset() != 0
                    || self.inode_table_entries() != 0
                {
                    return Err(err_invalid_superblock!());
                }
            }
            RAFS_SUPER_VERSION_V5 => {
                if self.inodes_count() == 0
                    || self.inode_table_offset() < RAFS_SUPERBLOCK_SIZE as u64
                    || self.inode_table_offset() & 0x7 != 0
                {
                    return Err(err_invalid_superblock!());
                }
            }
            _ => {
                return Err(einval!("invalid superblock version number"));
            }
        }

        // TODO: validate block_size, flags and reserved.

        Ok(())
    }

    pub fn set_compressor(&mut self, compressor: compress::Algorithm) {
        let c: RafsSuperFlags = compressor.into();
        self.s_flags |= c.bits();
    }

    pub fn set_digester(&mut self, digester: digest::Algorithm) {
        let c: RafsSuperFlags = digester.into();
        self.s_flags |= c.bits();
    }

    pub fn set_explicit_uidgid(&mut self) {
        self.s_flags |= RafsSuperFlags::EXPLICIT_UID_GID.bits();
    }

    pub fn set_has_xattr(&mut self) {
        self.s_flags |= RafsSuperFlags::HAS_XATTR.bits();
    }

    impl_pub_getter_setter!(magic, set_magic, s_magic, u32);
    impl_pub_getter_setter!(version, set_version, s_fs_version, u32);
    impl_pub_getter_setter!(sb_size, set_sb_size, s_sb_size, u32);
    impl_pub_getter_setter!(block_size, set_block_size, s_block_size, u32);
    impl_pub_getter_setter!(flags, set_flags, s_flags, u64);
    impl_pub_getter_setter!(inodes_count, set_inodes_count, s_inodes_count, u64);
    impl_pub_getter_setter!(
        inode_table_entries,
        set_inode_table_entries,
        s_inode_table_entries,
        u32
    );
    impl_pub_getter_setter!(
        inode_table_offset,
        set_inode_table_offset,
        s_inode_table_offset,
        u64
    );
    impl_pub_getter_setter!(blob_table_size, set_blob_table_size, s_blob_table_size, u32);
    impl_pub_getter_setter!(
        blob_table_offset,
        set_blob_table_offset,
        s_blob_table_offset,
        u64
    );
    impl_pub_getter_setter!(
        prefetch_table_offset,
        set_prefetch_table_offset,
        s_prefetch_table_offset,
        u64
    );
    impl_pub_getter_setter!(
        prefetch_table_entries,
        set_prefetch_table_entries,
        s_prefetch_table_entries,
        u32
    );

    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }
}

impl RafsStore for OndiskSuperBlock {
    fn store_inner(&self, w: &mut RafsIoWriter) -> Result<usize> {
        info!(
            "rafs superblock features: {}",
            RafsSuperFlags::from_bits(self.s_flags).unwrap_or_default()
        );
        w.write_all(self.as_ref())?;
        Ok(self.as_ref().len())
    }
}

impl_bootstrap_converter!(OndiskSuperBlock);

impl fmt::Display for OndiskSuperBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "superblock: magic {:x}, version {:x}, sb_size {:x}, block_size {:x}, flags {:x}, inode_count {}",
               self.magic(), self.version(), self.sb_size(), self.block_size(),
               self.flags(), self.s_inodes_count)
    }
}

#[derive(Clone, Default)]
pub struct OndiskInodeTable {
    pub(crate) data: Vec<u32>,
}

impl OndiskInodeTable {
    pub fn new(entries: usize) -> Self {
        let table_size = align_to_rafs(entries * size_of::<u32>()) / size_of::<u32>();
        OndiskInodeTable {
            data: vec![0; table_size],
        }
    }

    #[inline]
    pub fn size(&self) -> usize {
        align_to_rafs(self.data.len() * size_of::<u32>())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.len() == 0
    }

    pub fn set(&mut self, ino: Inode, inode_offset: u32) -> Result<()> {
        if ino > self.data.len() as u64 {
            return Err(einval!("invalid inode number"));
        }

        let offset = inode_offset >> 3;
        self.data[(ino - 1) as usize] = offset as u32;

        Ok(())
    }

    pub fn get(&self, ino: Inode) -> Result<u32> {
        if ino > self.data.len() as u64 {
            return Err(enoent!("inode not found"));
        }

        let offset = u32::from_le(self.data[(ino - 1) as usize]) as usize;
        if offset <= (RAFS_SUPERBLOCK_SIZE >> 3) || offset >= (1usize << 29) {
            return Err(einval!("invalid inode offset"));
        }

        Ok((offset << 3) as u32)
    }

    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        let (_, data, _) = unsafe { self.data.align_to_mut::<u8>() };
        r.read_exact(data)?;
        Ok(())
    }
}

impl RafsStore for OndiskInodeTable {
    fn store_inner(&self, w: &mut RafsIoWriter) -> Result<usize> {
        let (_, data, _) = unsafe { self.data.align_to::<u8>() };
        w.write_all(data)?;

        Ok(data.len())
    }
}

#[derive(Clone, Default)]
pub struct PrefetchTable {
    pub inode_indexes: Vec<u32>,
}

/// Introduce a prefetch table to rafs v5 disk layout.
/// From super block disk structure, its start offset can be told.
/// In order not to load every meta/inode to page cache under rafs Direct
/// mode, which aims at saving physical memory. This prefetch table is
/// introduce. Regular files or directories which are specified during image
/// building will have their inode index persist in this disk table.
/// For a single directory, only its inode index will be put into the table.
/// But all of its descendants fils(recursively) will be prefetch(by hint)
/// when rafs is mounted at the very beginning.
impl PrefetchTable {
    pub fn new() -> PrefetchTable {
        PrefetchTable {
            inode_indexes: vec![],
        }
    }

    pub fn add_entry(&mut self, inode_idx: u32) {
        self.inode_indexes.push(inode_idx);
    }

    pub fn table_aligned_size(&self) -> usize {
        self.inode_indexes.len() * size_of::<u32>()
    }

    pub fn store(&mut self, w: &mut RafsIoWriter) -> Result<usize> {
        // Sort prefetch table by inode index, hopefully, it can save time when mounting rafs
        // Because file data is dumped in the order of inode index.
        self.inode_indexes.sort_unstable();

        let (_, data, _) = unsafe { self.inode_indexes.align_to::<u8>() };

        w.write_all(data.as_ref())?;

        // OK. Let's see if we have to align... :-(
        let cur_len = self.inode_indexes.len() * size_of::<u32>();
        let padding_bytes = align_to_rafs(cur_len) - cur_len;
        w.write_padding(padding_bytes)?;

        Ok(data.len() + padding_bytes)
    }

    /// Note: This method changes file offset.
    /// `len` as u32 hint entries reside in this prefetch table.
    pub fn load_from(
        &mut self,
        r: &mut RafsIoReader,
        offset: u64,
        table_size: usize,
    ) -> Result<()> {
        // Map prefetch table in.
        // TODO: Need to consider about backend switch?
        r.seek(SeekFrom::Start(offset))?;

        self.inode_indexes = vec![0u32; table_size];

        let (_, data, _) = unsafe { self.inode_indexes.align_to_mut::<u8>() };
        r.read_exact(data)?;

        Ok(())
    }

    pub fn entry_size() -> usize {
        size_of::<u32>() as usize
    }
}

#[derive(Clone, Debug, Default)]
pub struct OndiskBlobTableEntry {
    pub readahead_offset: u32,
    pub readahead_size: u32,
    pub blob_id: String,
}

impl OndiskBlobTableEntry {
    pub fn size(&self) -> usize {
        size_of::<u32>() * 2 + self.blob_id.len()
    }
}

#[derive(Clone, Debug, Default)]
pub struct OndiskBlobTable {
    pub entries: Vec<OndiskBlobTableEntry>,
}

impl OndiskBlobTable {
    pub fn new() -> Self {
        OndiskBlobTable {
            entries: Vec::new(),
        }
    }

    /// Get blob table size, aligned with RAFS_ALIGNMENT bytes
    pub fn size(&self) -> usize {
        // Blob entry split with '\0'
        align_to_rafs(
            self.entries
                .iter()
                .fold(0usize, |size, entry| size + entry.size() + 1)
                - 1,
        )
    }

    pub fn add(&mut self, blob_id: String, readahead_offset: u32, readahead_size: u32) -> u32 {
        self.entries.push(OndiskBlobTableEntry {
            blob_id,
            readahead_offset,
            readahead_size,
        });
        (self.entries.len() - 1) as u32
    }

    #[inline]
    pub fn get(&self, blob_index: u32) -> Result<OndiskBlobTableEntry> {
        if blob_index > (self.entries.len() - 1) as u32 {
            return Err(enoent!("blob not found"));
        }
        Ok(self.entries[blob_index as usize].clone())
    }

    pub fn load(&mut self, r: &mut RafsIoReader, size: usize) -> Result<()> {
        let mut input = vec![0u8; size];

        r.read_exact(&mut input)?;
        self.load_from_slice(&input)
    }
    pub fn load_from_slice(&mut self, input: &[u8]) -> Result<()> {
        let mut input_rest = input;

        loop {
            let split_at_64 = std::mem::size_of::<u64>();
            let split_at_32 = std::mem::size_of::<u32>();

            if input_rest.len() < split_at_64 + 1 {
                break;
            }
            let (readahead, rest) = input_rest.split_at(split_at_64);

            if readahead.len() < split_at_32 + 1 {
                break;
            }
            let (readahead_offset, readahead_size) = readahead.split_at(split_at_32);

            let readahead_offset =
                u32::from_le_bytes(readahead_offset.try_into().map_err(|e| einval!(e))?);
            let readahead_size =
                u32::from_le_bytes(readahead_size.try_into().map_err(|e| einval!(e))?);

            let (blob_id, rest) = parse_string(rest)?;

            self.entries.push(OndiskBlobTableEntry {
                blob_id: blob_id.to_string(),
                readahead_offset,
                readahead_size,
            });

            // Break blob id search loop, when rest bytes length is zero,
            // or not split with '\0', or not have enough data to read (ending with padding data).
            if rest.is_empty()
                || rest.as_bytes()[0] != b'\0'
                || rest.as_bytes().len() <= (size_of::<u32>() * 2 + 1)
            {
                break;
            }

            // Skip '\0' splitter for next search
            input_rest = &rest.as_bytes()[1..];
        }

        Ok(())
    }

    pub fn get_all(&self) -> Vec<OndiskBlobTableEntry> {
        self.entries.clone()
    }
}

impl RafsStore for OndiskBlobTable {
    fn store_inner(&self, w: &mut RafsIoWriter) -> Result<usize> {
        let mut size = 0;

        self.entries
            .iter()
            .enumerate()
            .map(|(idx, entry)| {
                w.write_all(&u32::to_le_bytes(entry.readahead_offset))?;
                w.write_all(&u32::to_le_bytes(entry.readahead_size))?;
                w.write_all(entry.blob_id.as_bytes())?;
                if idx != self.entries.len() - 1 {
                    size += size_of::<u32>() * 2 + entry.blob_id.len() + 1;
                    w.write_all(&[b'\0'])?;
                } else {
                    size += size_of::<u32>() * 2 + entry.blob_id.len();
                }
                Ok(())
            })
            .collect::<Result<()>>()?;
        let padding = align_to_rafs(size) - size;
        w.write_padding(padding)?;

        size += padding;

        Ok(size)
    }
}

/// Ondisk rafs inode
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct OndiskInode {
    /// sha256(sha256(chunk) + ...), [char; RAFS_SHA256_LENGTH]
    pub i_digest: RafsDigest, // 32
    /// parent inode number
    pub i_parent: u64,
    /// from fs stat()
    pub i_ino: u64,
    pub i_uid: u32,
    pub i_gid: u32,
    pub i_projid: u32,
    pub i_mode: u32, // 64
    pub i_size: u64,
    pub i_blocks: u64,
    /// HARDLINK | SYMLINK | PREFETCH_HINT
    pub i_flags: RafsInodeFlags,
    pub i_nlink: u32,
    /// for dir, child start index
    pub i_child_index: u32, // 96
    /// for dir, means child count.
    /// for regular file, means chunk info count.
    pub i_child_count: u32,
    /// file name size, [char; i_name_size]
    pub i_name_size: u16,
    /// symlink path size, [char; i_symlink_size]
    pub i_symlink_size: u16, // 104
    pub i_reserved: [u8; 24], // 128
}

bitflags! {
    pub struct RafsInodeFlags: u64 {
        /// Inode is a symlink.
        const SYMLINK = 0x0000_0001;
        /// Inode has hardlinks.
        const HARDLINK = 0x0000_0002;
        /// Inode has extended attributes.
        const XATTR = 0x0000_0004;
        /// Inode chunks has holes.
        const HAS_HOLE = 0x0000_0008;
   }
}

impl Default for RafsInodeFlags {
    fn default() -> Self {
        RafsInodeFlags::empty()
    }
}

impl OndiskInode {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn set_name_size(&mut self, name_len: usize) {
        self.i_name_size = name_len as u16;
    }

    #[inline]
    pub fn set_symlink_size(&mut self, symlink_len: usize) {
        self.i_symlink_size = symlink_len as u16;
    }

    #[inline]
    pub fn size(&self) -> usize {
        size_of::<Self>()
            + (align_to_rafs(self.i_name_size as usize)
                + align_to_rafs(self.i_symlink_size as usize)) as usize
    }

    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }

    #[inline]
    pub fn is_dir(&self) -> bool {
        self.i_mode & libc::S_IFMT == libc::S_IFDIR
    }

    #[inline]
    pub fn is_symlink(&self) -> bool {
        self.i_mode & libc::S_IFMT == libc::S_IFLNK
    }

    #[inline]
    pub fn is_reg(&self) -> bool {
        self.i_mode & libc::S_IFMT == libc::S_IFREG
    }

    #[inline]
    pub fn is_hardlink(&self) -> bool {
        self.i_nlink > 1
    }

    #[inline]
    pub fn has_xattr(&self) -> bool {
        self.i_flags.contains(RafsInodeFlags::XATTR)
    }

    #[inline]
    pub fn has_hole(&self) -> bool {
        self.i_flags.contains(RafsInodeFlags::HAS_HOLE)
    }
}

pub struct OndiskInodeWrapper<'a> {
    pub name: &'a OsStr,
    pub symlink: Option<&'a OsStr>,
    pub inode: &'a OndiskInode,
}

impl<'a> RafsStore for OndiskInodeWrapper<'a> {
    fn store_inner(&self, w: &mut RafsIoWriter) -> Result<usize> {
        let mut size: usize = 0;

        let inode_data = self.inode.as_ref();
        w.write_all(inode_data)?;
        size += inode_data.len();

        let name = self.name.as_bytes();
        w.write_all(name)?;
        size += name.len();

        let padding = align_to_rafs(self.inode.i_name_size as usize) - name.len();
        w.write_padding(padding)?;
        size += padding;

        if let Some(symlink) = self.symlink {
            let symlink_path = symlink.as_bytes();
            w.write_all(symlink_path)?;
            size += symlink_path.len();
            let padding = align_to_rafs(self.inode.i_symlink_size as usize) - symlink_path.len();
            w.write_padding(padding)?;
            size += padding;
        }

        Ok(size)
    }
}

impl_bootstrap_converter!(OndiskInode);

/// On disk Rafs data chunk information.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct OndiskChunkInfo {
    /// sha256(chunk), [char; RAFS_SHA256_LENGTH]
    pub block_id: RafsDigest,
    /// blob index (blob_id = blob_table[blob_index])
    pub blob_index: u32,
    /// chunk flags
    pub flags: RafsChunkFlags,

    /// compressed size in blob
    pub compress_size: u32,
    /// decompressed size in blob
    pub decompress_size: u32,
    /// compressed offset in blob
    pub compress_offset: u64,
    /// decompressed offset in blob
    pub decompress_offset: u64,

    /// offset in file
    pub file_offset: u64,
    /// reserved
    pub reserved: u64,
}

bitflags! {
    pub struct RafsChunkFlags: u32 {
        /// chunk is compressed
        const COMPRESSED = 0x0000_0001;
    }
}

impl Default for RafsChunkFlags {
    fn default() -> Self {
        RafsChunkFlags::empty()
    }
}

impl OndiskChunkInfo {
    pub fn new() -> Self {
        OndiskChunkInfo::default()
    }

    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }
}

impl RafsStore for OndiskChunkInfo {
    fn store_inner(&self, w: &mut RafsIoWriter) -> Result<usize> {
        w.write_all(self.as_ref())?;
        Ok(self.as_ref().len())
    }
}

impl RafsChunkInfo for OndiskChunkInfo {
    fn validate(&self, _sb: &RafsSuperMeta) -> Result<()> {
        Ok(())
    }

    #[inline]
    fn block_id(&self) -> Arc<RafsDigest> {
        Arc::new(self.block_id)
    }

    #[inline]
    fn is_compressed(&self) -> bool {
        self.flags.contains(RafsChunkFlags::COMPRESSED)
    }

    fn cast_ondisk(&self) -> Result<OndiskChunkInfo> {
        Ok(*self)
    }

    impl_getter!(blob_index, blob_index, u32);
    impl_getter!(compress_offset, compress_offset, u64);
    impl_getter!(compress_size, compress_size, u32);
    impl_getter!(decompress_offset, decompress_offset, u64);
    impl_getter!(decompress_size, decompress_size, u32);
    impl_getter!(file_offset, file_offset, u64);
}

impl_bootstrap_converter!(OndiskChunkInfo);

impl fmt::Display for OndiskChunkInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "file_offset {}, compress_offset {}, compress_size {}, decompress_offset {}, decompress_size {}, blob_index {}, block_id {:?}, is_compressed {}",
            self.file_offset,
            self.compress_offset,
            self.compress_size,
            self.decompress_offset,
            self.decompress_size,
            self.blob_index,
            self.block_id,
            self.is_compressed(),
        )
    }
}

/// On disk xattr data.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct OndiskXAttrs {
    pub size: u64,
}

impl_bootstrap_converter!(OndiskXAttrs);

impl OndiskXAttrs {
    pub fn new() -> Self {
        OndiskXAttrs {
            ..Default::default()
        }
    }

    #[inline]
    pub fn size(self) -> usize {
        self.size as usize
    }

    #[inline]
    pub fn aligned_size(self) -> usize {
        align_to_rafs(self.size())
    }
}

pub type XattrName = Vec<u8>;
pub type XattrValue = Vec<u8>;

#[derive(Clone, Default)]
pub struct XAttrs {
    pub pairs: HashMap<OsString, XattrValue>,
}

impl XAttrs {
    pub fn size(&self) -> usize {
        let mut size: usize = 0;

        for (key, value) in self.pairs.iter() {
            size += size_of::<u32>();
            size += key.as_bytes().len() + 1 + value.len();
        }

        size
    }

    #[inline]
    pub fn aligned_size(&self) -> usize {
        align_to_rafs(self.size())
    }
}

impl RafsStore for XAttrs {
    fn store_inner(&self, w: &mut RafsIoWriter) -> Result<usize> {
        let mut size = 0;

        if !self.pairs.is_empty() {
            let size_data = (self.size() as u64).to_le_bytes();
            w.write_all(&size_data)?;
            size += size_data.len();

            for (key, value) in self.pairs.iter() {
                let pair_size = key.as_bytes().len() + 1 + value.len();
                let pair_size_data = (pair_size as u32).to_le_bytes();
                w.write_all(&pair_size_data)?;
                size += pair_size_data.len();

                let key_data = key.as_bytes();
                w.write_all(key_data)?;
                w.write_all(&[0u8])?;
                size += key_data.len() + 1;

                w.write_all(value)?;
                size += value.len();
            }
        }

        let padding = align_to_rafs(size) - size;
        w.write_padding(padding)?;
        size += padding;

        Ok(size)
    }
}

#[inline]
pub fn align_to_rafs(size: usize) -> usize {
    if size & (RAFS_ALIGNMENT - 1) == 0 {
        return size;
    }
    size + (RAFS_ALIGNMENT - (size & (RAFS_ALIGNMENT - 1)))
}

/// Parse a `buf` to utf-8 string.
pub fn parse_string(buf: &[u8]) -> Result<(&str, &str)> {
    std::str::from_utf8(buf)
        .map(|origin| {
            if let Some(pos) = origin.find('\0') {
                origin.split_at(pos)
            } else {
                (origin, "")
            }
        })
        .map_err(|e| einval!(format!("failed in parsing string, {:?}", e)))
}

pub fn bytes_to_os_str(buf: &[u8]) -> &OsStr {
    OsStr::from_bytes(buf)
}

/// Parse a 'buf' to xattr pair then callback.
pub fn parse_xattr<F>(data: &[u8], size: usize, mut cb: F) -> Result<()>
where
    F: FnMut(&OsStr, XattrValue) -> bool,
{
    let mut i: usize = 0;
    let mut rest_data = &data[0..size];

    while i < size {
        let (pair_size, rest) = rest_data.split_at(size_of::<u32>());
        let pair_size = u32::from_le_bytes(
            pair_size
                .try_into()
                .map_err(|_| einval!("failed to parse xattr pair size"))?,
        ) as usize;
        i += size_of::<u32>();

        let (pair, rest) = rest.split_at(pair_size);
        if let Some(pos) = pair.iter().position(|&c| c == 0) {
            let (name, value) = pair.split_at(pos);
            let name = OsStr::from_bytes(name);
            let value = value[1..].to_vec();
            if !cb(name, value) {
                break;
            }
        }
        i += pair_size;

        rest_data = rest;
    }

    Ok(())
}

/// Parse a 'buf' to xattr name list.
pub fn parse_xattr_names(data: &[u8], size: usize) -> Result<Vec<XattrName>> {
    let mut result = Vec::new();

    parse_xattr(data, size, |name, _| {
        result.push(name.as_bytes().to_vec());
        true
    })?;

    Ok(result)
}

/// Parse a 'buf' to xattr value by xattr name.
pub fn parse_xattr_value(data: &[u8], size: usize, name: &OsStr) -> Result<Option<XattrValue>> {
    let mut value = None;

    parse_xattr(data, size, |_name, _value| {
        if _name == name {
            value = Some(_value);
            // stop the iteration if we found the xattr name.
            return false;
        }
        true
    })?;

    Ok(value)
}
