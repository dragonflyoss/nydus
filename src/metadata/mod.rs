//! EROFS metadata format definitions.
//!
//! On-disk format structs, constants, and helpers shared between build and
//! runtime. All on-disk structs are `#[repr(C, packed)]` and can be cast
//! directly from mmap'd memory (zero-copy) or constructed in-place for writing.

pub mod blob_footer;
pub mod blob_meta;
pub mod chunk;
pub mod dir;
pub mod inode;
pub mod layout;
pub mod superblock;

pub use blob_footer::*;
pub use blob_meta::*;
pub use chunk::*;
pub use dir::*;
pub use inode::*;
pub use superblock::*;

use std::mem;

// Superblock.
pub const EROFS_SUPER_MAGIC_V1: u32 = 0xE0F5_E1E2;
pub const EROFS_SUPER_OFFSET: u64 = 1024;
pub const EROFS_SB_BASE_SIZE: usize = 128;

// Block / slot sizes.
pub const EROFS_BLOCK_SIZE: u32 = 4096;
pub const EROFS_BLKSZBITS: u8 = 12;
pub const EROFS_ISLOTBITS: u32 = 5;
pub const EROFS_SLOTSIZE: u32 = 1 << EROFS_ISLOTBITS;

// Feature flags.
pub const EROFS_FEATURE_COMPAT_SB_CHKSUM: u32 = 0x0000_0001;
pub const EROFS_FEATURE_COMPAT_MTIME: u32 = 0x0000_0002;
pub const EROFS_FEATURE_INCOMPAT_CHUNKED_FILE: u32 = 0x0000_0004;
pub const EROFS_FEATURE_INCOMPAT_DEVICE_TABLE: u32 = 0x0000_0008;

// Inode layout.
pub const EROFS_INODE_LAYOUT_COMPACT: u16 = 0;
pub const EROFS_INODE_LAYOUT_EXTENDED: u16 = 1;
pub const EROFS_INODE_COMPACT_SIZE: usize = 32;
pub const EROFS_INODE_EXTENDED_SIZE: usize = 64;

// Inode data layout.
pub const EROFS_INODE_FLAT_PLAIN: u16 = 0;
pub const EROFS_INODE_FLAT_INLINE: u16 = 2;
pub const EROFS_INODE_CHUNK_BASED: u16 = 4;

// Inode flag bits.
pub const EROFS_I_VERSION_BIT: u16 = 0;
pub const EROFS_I_DATALAYOUT_BIT: u16 = 1;
pub const EROFS_I_NLINK_1_BIT: u16 = 4;

// Chunk.
pub const EROFS_CHUNK_FORMAT_INDEXES: u16 = 0x0020;
pub const EROFS_CHUNK_INDEX_SIZE: usize = 8;

// File types.
pub const EROFS_FT_REG_FILE: u8 = 1;
pub const EROFS_FT_DIR: u8 = 2;
pub const EROFS_FT_CHRDEV: u8 = 3;
pub const EROFS_FT_BLKDEV: u8 = 4;
pub const EROFS_FT_FIFO: u8 = 5;
pub const EROFS_FT_SOCK: u8 = 6;
pub const EROFS_FT_SYMLINK: u8 = 7;

// Xattr name indexes.
pub const EROFS_XATTR_INDEX_USER: u8 = 1;
pub const EROFS_XATTR_INDEX_POSIX_ACL_ACCESS: u8 = 2;
pub const EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT: u8 = 3;
pub const EROFS_XATTR_INDEX_TRUSTED: u8 = 4;
pub const EROFS_XATTR_INDEX_LUSTRE: u8 = 5;
pub const EROFS_XATTR_INDEX_SECURITY: u8 = 6;
pub const EROFS_XATTR_IBODY_HEADER_SIZE: usize = 12;
pub const EROFS_XATTR_ENTRY_HEADER_SIZE: usize = 4;

// Misc on-disk sizes.
pub const EROFS_DIRENT_SIZE: usize = 12;
pub const EROFS_DEVICESLOT_SIZE: usize = 128;

// Sentinel.
pub const EROFS_NULL_ADDR: u64 = u64::MAX;

/// Map xattr name index to its byte prefix.
pub fn erofs_xattr_prefix(index: u8) -> Option<&'static [u8]> {
    match index {
        EROFS_XATTR_INDEX_USER => Some(b"user."),
        EROFS_XATTR_INDEX_POSIX_ACL_ACCESS => Some(b"system.posix_acl_access"),
        EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT => Some(b"system.posix_acl_default"),
        EROFS_XATTR_INDEX_TRUSTED => Some(b"trusted."),
        EROFS_XATTR_INDEX_LUSTRE => Some(b"lustre."),
        EROFS_XATTR_INDEX_SECURITY => Some(b"security."),
        _ => None,
    }
}

/// Split a full xattr name (as bytes) into (prefix_index, suffix).
/// Returns None if the name doesn't match any known EROFS xattr prefix.
pub fn erofs_xattr_name_split(name: &[u8]) -> Option<(u8, &[u8])> {
    // Order matters: check longer prefixes first to avoid partial matches
    if let Some(suffix) = name.strip_prefix(b"security." as &[u8]) {
        Some((EROFS_XATTR_INDEX_SECURITY, suffix))
    } else if let Some(suffix) = name.strip_prefix(b"trusted." as &[u8]) {
        Some((EROFS_XATTR_INDEX_TRUSTED, suffix))
    } else if let Some(suffix) = name.strip_prefix(b"user." as &[u8]) {
        Some((EROFS_XATTR_INDEX_USER, suffix))
    } else if let Some(suffix) = name.strip_prefix(b"system.posix_acl_access" as &[u8]) {
        Some((EROFS_XATTR_INDEX_POSIX_ACL_ACCESS, suffix))
    } else if let Some(suffix) = name.strip_prefix(b"system.posix_acl_default" as &[u8]) {
        Some((EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT, suffix))
    } else {
        name.strip_prefix(b"lustre." as &[u8])
            .map(|suffix| (EROFS_XATTR_INDEX_LUSTRE, suffix))
    }
}

/// Compute the xattr ibody size for a list of xattr entries.
/// Each entry: 4-byte header + name_suffix_len + value_len, 4-byte aligned.
/// Plus the 12-byte ibody header.
pub fn xattr_ibody_size(xattrs: &[(u8, Vec<u8>, Vec<u8>)]) -> usize {
    if xattrs.is_empty() {
        return 0;
    }

    let mut size = EROFS_XATTR_IBODY_HEADER_SIZE; // 12 bytes header
    for (_, suffix, value) in xattrs {
        let entry_size = EROFS_XATTR_ENTRY_HEADER_SIZE + suffix.len() + value.len();
        size += round_up(entry_size, 4);
    }

    size
}

/// Compute i_xattr_icount from the xattr ibody size.
/// xattr_ibody_size = 12 + 4 * (icount - 1), so icount = (size - 12) / 4 + 1 = (size - 8) / 4
pub fn xattr_icount(xattr_ibody_size: usize) -> u16 {
    if xattr_ibody_size == 0 {
        0
    } else {
        let aligned = round_up(xattr_ibody_size, 4);
        ((aligned - 8) / 4) as u16
    }
}

/// Read a little-endian integer from a byte array.
#[inline(always)]
pub(crate) fn get_u16(b: &[u8; 2]) -> u16 {
    u16::from_le_bytes(*b)
}

#[inline(always)]
pub(crate) fn set_u16(b: &mut [u8; 2], v: u16) {
    *b = v.to_le_bytes();
}

#[inline(always)]
pub(crate) fn get_u32(b: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*b)
}

#[inline(always)]
pub(crate) fn set_u32(b: &mut [u8; 4], v: u32) {
    *b = v.to_le_bytes();
}

#[inline(always)]
pub(crate) fn get_u64(b: &[u8; 8]) -> u64 {
    u64::from_le_bytes(*b)
}

#[inline(always)]
pub(crate) fn set_u64(b: &mut [u8; 8], v: u64) {
    *b = v.to_le_bytes();
}

/// Cast a byte slice to a reference of `T` (`#[repr(C, packed)]`).
#[inline]
pub fn cast_ref<T>(data: &[u8]) -> &T {
    assert!(data.len() >= mem::size_of::<T>());
    unsafe { &*(data.as_ptr() as *const T) }
}

/// Cast a mutable byte slice to a mutable reference of `T`.
#[inline]
pub fn cast_mut<T>(data: &mut [u8]) -> &mut T {
    assert!(data.len() >= mem::size_of::<T>());
    unsafe { &mut *(data.as_mut_ptr() as *mut T) }
}

/// Round `val` up to the next multiple of `align` (power of two).
#[inline]
pub fn round_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

/// Round `val` up to the next multiple of `align` (power of two) for u64.
#[inline]
pub fn round_up_u64(val: u64, align: u64) -> u64 {
    (val + align - 1) & !(align - 1)
}
