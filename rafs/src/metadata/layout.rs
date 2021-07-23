// Copyright 2020 Ant Group. All rights reserved.
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

use serde::Serialize;

use crate::metadata::extended::blob_table::ExtendedBlobTable;
use nydus_utils::{
    digest::{self, RafsDigest},
    ByteSize,
};
use storage::device::RafsBlobEntry;

use super::*;

pub const RAFS_SUPERBLOCK_SIZE: usize = 8192;
pub const RAFS_SUPERBLOCK_RESERVED_SIZE: usize = RAFS_SUPERBLOCK_SIZE - 80;
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
    s_prefetch_table_entries: u32, // 64 bytes
    /// V5: Entries of blob table
    s_blob_table_size: u32,
    s_extended_blob_table_entries: u32, // 72 bytes
    /// Extended Blob Table
    s_extended_blob_table_offset: u64, // 80 bytes --- reduce me from `RAFS_SUPERBLOCK_RESERVED_SIZE`
    /// Unused area
    s_reserved: [u8; RAFS_SUPERBLOCK_RESERVED_SIZE],
}

bitflags! {
    #[derive(Serialize)]
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
        // Data chunks are compressed with gzip
        const COMPRESS_GZIP = 0x0000_0040;
    }
}

impl Default for RafsSuperFlags {
    fn default() -> Self {
        RafsSuperFlags::empty()
    }
}

impl fmt::Display for RafsSuperFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", format!("{:?}", self))?;
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
            x if x.contains(RafsSuperFlags::COMPRESS_GZIP) => compress::Algorithm::GZip,
            _ => compress::Algorithm::LZ4Block,
        }
    }
}

impl From<compress::Algorithm> for RafsSuperFlags {
    fn from(c: compress::Algorithm) -> RafsSuperFlags {
        match c {
            compress::Algorithm::None => RafsSuperFlags::COMPRESS_NONE,
            compress::Algorithm::LZ4Block => RafsSuperFlags::COMPRESS_LZ4_BLOCK,
            compress::Algorithm::GZip => RafsSuperFlags::COMPRESS_GZIP,
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
            s_extended_blob_table_offset: u64::to_le(0),
            s_extended_blob_table_entries: u32::to_le(0),
            s_reserved: [0u8; RAFS_SUPERBLOCK_RESERVED_SIZE],
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
            return Err(einval!("invalid superblock"));
        }

        match self.version() {
            RAFS_SUPER_VERSION_V4 => {
                if self.inodes_count() != 0
                    || self.inode_table_offset() != 0
                    || self.inode_table_entries() != 0
                {
                    return Err(einval!("invalid superblock"));
                }
            }
            RAFS_SUPER_VERSION_V5 => {
                if self.inodes_count() == 0
                    || self.inode_table_offset() < RAFS_SUPERBLOCK_SIZE as u64
                    || self.inode_table_offset() & 0x7 != 0
                {
                    return Err(einval!("invalid superblock"));
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
    impl_pub_getter_setter!(
        extended_blob_table_offset,
        set_extended_blob_table_offset,
        s_extended_blob_table_offset,
        u64
    );
    impl_pub_getter_setter!(
        extended_blob_table_entries,
        set_extended_blob_table_entries,
        s_extended_blob_table_entries,
        u32
    );

    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }
}

impl RafsStore for OndiskSuperBlock {
    fn store_inner(&self, w: &mut RafsIoWriter) -> Result<usize> {
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
    pub data: Vec<u32>,
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
        self.data.is_empty()
    }

    pub fn set(&mut self, ino: Inode, inode_offset: u32) -> Result<()> {
        if ino > self.data.len() as u64 {
            return Err(einval!("invalid inode number"));
        }

        // The offset is aligned with 8 bytes to make it easier to
        // validate OndiskInode.
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
    /// Store inode numbers of files that have to prefetch.
    /// Note: It's not inode index of inodes table being stored here.
    pub inodes: Vec<u32>,
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
        PrefetchTable { inodes: vec![] }
    }

    pub fn len(&self) -> usize {
        self.inodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inodes.is_empty()
    }

    pub fn add_entry(&mut self, ino: u32) {
        self.inodes.push(ino);
    }

    pub fn size(&self) -> usize {
        align_to_rafs(self.len() * size_of::<u32>())
    }

    pub fn store(&mut self, w: &mut RafsIoWriter) -> Result<usize> {
        // Sort prefetch table by inode index, hopefully, it can save time when mounting rafs
        // Because file data is dumped in the order of inode index.
        self.inodes.sort_unstable();

        let (_, data, _) = unsafe { self.inodes.align_to::<u8>() };

        w.write_all(data.as_ref())?;

        // OK. Let's see if we have to align... :-(
        let cur_len = self.inodes.len() * size_of::<u32>();
        let padding_bytes = align_to_rafs(cur_len) - cur_len;
        w.write_padding(padding_bytes)?;

        Ok(data.len() + padding_bytes)
    }

    /// Note: Generally, prefetch happens after loading bootstrap, so with methods operating
    /// files with changing their offset won't bring errors. But we still use `pread` now so as
    /// to make this method more stable and robust. Even dup(2) can't give us a separated file struct.
    pub fn load_prefetch_table_from(
        &mut self,
        r: &mut RafsIoReader,
        offset: u64,
        table_size: usize,
    ) -> nix::Result<usize> {
        self.inodes = vec![0u32; table_size];
        let (_, data, _) = unsafe { self.inodes.align_to_mut::<u8>() };
        nix::sys::uio::pread(r.as_raw_fd(), data, offset as i64)
    }
}

fn pointer_offset(former_ptr: *const u8, later_ptr: *const u8) -> usize {
    // Rust provides unsafe method `offset_from` from 1.47.0
    // Hopefully, we can adopt it someday. For now, for compatibility, use blow trick.
    later_ptr as usize - former_ptr as usize
}

// TODO: FIXME: This is not a well defined disk structure
#[derive(Clone, Debug, Default)]
pub struct OndiskBlobTable {
    pub entries: Vec<Arc<RafsBlobEntry>>,
    pub extended: ExtendedBlobTable,
}

// A helper to extract blob table entries from disk.
struct BlobEntryFrontPart(u32, u32);

impl OndiskBlobTable {
    pub fn new() -> Self {
        OndiskBlobTable {
            entries: Vec::new(),
            extended: ExtendedBlobTable::new(),
        }
    }

    /// Get blob table size, aligned with RAFS_ALIGNMENT bytes
    pub fn size(&self) -> usize {
        if self.entries.is_empty() {
            return 0;
        }
        // Blob entry split with '\0'
        align_to_rafs(
            self.entries.iter().fold(0usize, |size, entry| {
                let entry_size = size_of::<u32>() * 2 + entry.blob_id.len();
                size + entry_size + 1
            }) - 1,
        )
    }

    pub fn add(
        &mut self,
        blob_id: String,
        readahead_offset: u32,
        readahead_size: u32,
        chunk_count: u32,
        blob_cache_size: u64,
        compressed_blob_size: u64,
    ) -> u32 {
        let blob_index = self.entries.len() as u32;
        self.entries.push(Arc::new(RafsBlobEntry {
            blob_id,
            blob_index,
            readahead_offset,
            readahead_size,
            chunk_count,
            blob_cache_size,
        }));
        self.extended
            .add(chunk_count, blob_cache_size, compressed_blob_size);
        blob_index
    }

    #[inline]
    pub fn get(&self, blob_index: u32) -> Result<Arc<RafsBlobEntry>> {
        if blob_index > (self.entries.len() - 1) as u32 {
            return Err(enoent!("blob not found"));
        }
        Ok(self.entries[blob_index as usize].clone())
    }

    // The goal is to fill `entries` according to blob table. If it is zero-sized,
    // just return Ok.
    pub fn load(&mut self, r: &mut RafsIoReader, blob_table_size: u32) -> Result<()> {
        if blob_table_size == 0 {
            return Ok(());
        }

        let mut data = vec![0u8; blob_table_size as usize];
        r.read_exact(&mut data)?;

        let begin_ptr = data.as_slice().as_ptr() as *const u8;
        let mut frame = begin_ptr;
        debug!("blob table size {}", blob_table_size);
        loop {
            // Each entry frame looks like:
            // u32 | u32 | string | trailing '\0' , except that the last entry has no trailing '\0'
            // Make clippy of 1.45 happy. Higher version of clippy won't complain about this
            #[allow(clippy::cast_ptr_alignment)]
            let front = unsafe { &*(frame as *const BlobEntryFrontPart) };
            // `blob_table_size` has to be greater than zero, otherwise it access a invalid page.
            let readahead_offset = front.0;
            let readahead_size = front.1;

            // Safe because we never tried to take ownership.
            // Make clippy of 1.45 happy. Higher version of clippy won't complain about this
            #[allow(clippy::cast_ptr_alignment)]
            let id_offset = unsafe { (frame as *const BlobEntryFrontPart).add(1) as *const u8 };
            // id_end points to the byte before splitter 'b\0'
            let id_end = Self::blob_id_tail_ptr(id_offset, begin_ptr, blob_table_size as usize);

            // Excluding trailing '\0'.
            // Note: we can't use string.len() to move pointer.
            let bytes_len = pointer_offset(id_offset, id_end) + 1;

            let id_bytes = unsafe { std::slice::from_raw_parts(id_offset, bytes_len) };

            let blob_id = std::str::from_utf8(id_bytes).map_err(|e| einval!(e))?;
            debug!("blob {:?} lies on", blob_id);
            // Move to next entry frame, including splitter 0
            frame = unsafe { frame.add(size_of::<BlobEntryFrontPart>() + bytes_len + 1) };

            let index = self.entries.len();

            // For compatibility concern, blob table might not associate with extended blob table.
            let (chunk_count, blob_cache_size) = if !self.extended.entries.is_empty() {
                // chge: Though below can hardly happen and we can do nothing meeting
                // this possibly due to bootstrap corruption, someone like this kind of check, make them happy.
                if index > self.extended.entries.len() - 1 {
                    error!(
                        "Extended blob table({}) is shorter than blob table",
                        self.extended.entries.len()
                    );
                    return Err(einval!());
                }
                (
                    self.extended.entries[index].chunk_count,
                    self.extended.entries[index].blob_cache_size,
                )
            } else {
                (0, 0)
            };

            self.entries.push(Arc::new(RafsBlobEntry {
                blob_id: blob_id.to_owned(),
                blob_index: index as u32,
                chunk_count,
                readahead_offset,
                readahead_size,
                blob_cache_size,
            }));

            if align_to_rafs(pointer_offset(begin_ptr, frame)) as u32 >= blob_table_size {
                break;
            }
        }

        Ok(())
    }

    pub fn get_all(&self) -> Vec<Arc<RafsBlobEntry>> {
        self.entries.clone()
    }

    pub fn store_extended(&self, w: &mut RafsIoWriter) -> Result<usize> {
        self.extended.store(w)
    }

    fn blob_id_tail_ptr(cur: *const u8, begin_ptr: *const u8, total_size: usize) -> *const u8 {
        let mut id_end = cur as *mut u8;
        loop {
            let next_byte = unsafe { id_end.add(1) };
            // b'\0' is the splitter
            if unsafe { *next_byte } == 0 || pointer_offset(begin_ptr, next_byte) >= total_size {
                return id_end;
            }

            id_end = unsafe { id_end.add(1) };
        }
    }
}

impl RafsStore for OndiskBlobTable {
    fn store_inner(&self, w: &mut RafsIoWriter) -> Result<usize> {
        let mut size = 0;
        self.entries
            .iter()
            .enumerate()
            .try_for_each::<_, Result<()>>(|(idx, entry)| {
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
            })?;

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
    //// inode device block number, ignored for non-special files
    pub i_rdev: u32,          // 108
    pub i_reserved: [u8; 20], // 128
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

    pub fn file_name(&self, r: &mut RafsIoReader) -> Result<OsString> {
        let mut name_buf = vec![0u8; self.i_name_size as usize];
        r.read_exact(name_buf.as_mut_slice())?;
        Ok(bytes_to_os_str(&name_buf).to_os_string())
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
#[derive(Default, Clone, Copy, Debug)]
pub struct OndiskChunkInfo {
    /// sha256(chunk), [char; RAFS_SHA256_LENGTH]
    pub block_id: RafsDigest, // 32
    /// blob index (blob_id = blob_table[blob_index])
    pub blob_index: u32,
    /// chunk flags
    pub flags: RafsChunkFlags, // 40
    /// compressed size in blob
    pub compress_size: u32,
    /// decompressed size in blob
    pub decompress_size: u32, // 48
    /// compressed offset in blob
    pub compress_offset: u64, // 56
    /// decompressed offset in blob
    pub decompress_offset: u64, // 64
    /// offset in file
    pub file_offset: u64, // 72
    /// chunk index, it's allocated sequentially
    /// starting from 0 for one blob.
    pub index: u32,
    /// reserved
    pub reserved: u32, //80
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

impl_bootstrap_converter!(OndiskChunkInfo);

impl fmt::Display for OndiskChunkInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "file_offset {}, compress_offset {}, compress_size {}, decompress_offset {}, decompress_size {}, blob_index {}, block_id {}, index {}, is_compressed {}",
            self.file_offset,
            self.compress_offset,
            self.compress_size,
            self.decompress_offset,
            self.decompress_size,
            self.blob_index,
            self.block_id,
            self.index,
            self.flags.contains(RafsChunkFlags::COMPRESSED),
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
    pairs: HashMap<OsString, XattrValue>,
}

impl XAttrs {
    pub fn new() -> Self {
        Self {
            pairs: HashMap::new(),
        }
    }

    pub fn size(&self) -> usize {
        let mut size: usize = 0;

        for (key, value) in self.pairs.iter() {
            size += size_of::<u32>();
            size += key.byte_size() + 1 + value.len();
        }

        size
    }

    #[inline]
    pub fn aligned_size(&self) -> usize {
        align_to_rafs(self.size())
    }

    pub fn get(&self, name: &OsStr) -> Option<&XattrValue> {
        self.pairs.get(name)
    }

    pub fn add(&mut self, name: OsString, value: XattrValue) {
        self.pairs.insert(name, value);
    }

    pub fn remove(&mut self, name: &OsStr) {
        self.pairs.remove(name);
    }

    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
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
                let pair_size = key.byte_size() + 1 + value.len();
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

#[cfg(test)]
pub mod tests {
    use super::OndiskBlobTable;
    use crate::RafsIoReader;
    use nydus_utils::setup_logging;
    use std::fs::OpenOptions;
    use std::io::{SeekFrom, Write};
    use vmm_sys_util::tempfile::TempFile;

    #[allow(dead_code)]
    struct Entry {
        foo: u32,
        bar: u32,
    }

    unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
        ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
    }

    #[test]
    fn test_load_blob_table() {
        setup_logging(None, log::LevelFilter::Info).unwrap();

        let mut buffer = Vec::new();
        let first = Entry { foo: 1, bar: 2 };
        let second = Entry { foo: 3, bar: 4 };
        let third = Entry { foo: 5, bar: 6 };

        let first_id = "355d403e35d7120cbd6a145874a2705e6842ce9974985013ebdc1fa5199a0184";
        let second_id = "19ebb6e9bdcbbce3f24d694fe20e0e552ae705ce079e26023ad0ecd61d4b130019ebb6e9bdcbbce3f24d694fe20e0e552ae705ce079e26023ad0ecd61d4";
        let third_id = "19ebb6e9bdcbbce3f24d694fe20e0e552ae705ce079e";

        let first_slice = unsafe { any_as_u8_slice(&first) };
        let second_slice = unsafe { any_as_u8_slice(&second) };
        let third_slice = unsafe { any_as_u8_slice(&third) };

        buffer.extend_from_slice(first_slice);
        buffer.extend_from_slice(first_id.as_bytes());
        buffer.push(b'\0');
        buffer.extend_from_slice(second_slice);
        buffer.extend_from_slice(second_id.as_bytes());
        buffer.push(b'\0');
        buffer.extend_from_slice(third_slice);
        buffer.extend_from_slice(third_id.as_bytes());
        // buffer.push(b'\0');

        let tmp_file = TempFile::new().unwrap();

        // Store extended blob table
        let mut tmp_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(tmp_file.as_path())
            .unwrap();

        tmp_file.write_all(&buffer).unwrap();
        tmp_file.flush().unwrap();

        let mut file: RafsIoReader = Box::new(tmp_file);
        let mut blob_table = OndiskBlobTable::new();

        file.seek(SeekFrom::Start(0)).unwrap();
        blob_table.load(&mut file, buffer.len() as u32).unwrap();

        for b in &blob_table.entries {
            let _c = b.clone();
            trace!("{:?}", _c);
        }

        assert_eq!(blob_table.entries[0].blob_id, first_id);
        assert_eq!(blob_table.entries[1].blob_id, second_id);
        assert_eq!(blob_table.entries[2].blob_id, third_id);

        blob_table.entries.truncate(0);

        file.seek(SeekFrom::Start(0)).unwrap();
        blob_table.load(&mut file, 0).unwrap();

        blob_table.entries.truncate(0);

        file.seek(SeekFrom::Start(0)).unwrap();
        blob_table
            .load(&mut file, (buffer.len() - 100) as u32)
            .unwrap();

        assert_eq!(blob_table.entries[0].blob_id, first_id);
    }
}
