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

// Xattr ibody and entry header sizes.
pub const EROFS_XATTR_IBODY_HEADER_SIZE: usize = 12;
pub const EROFS_XATTR_ENTRY_HEADER_SIZE: usize = 4;

// Misc on-disk sizes.
pub const EROFS_DIRENT_SIZE: usize = 12;
pub const EROFS_DEVICESLOT_SIZE: usize = 128;

// Sentinel.
pub const EROFS_NULL_ADDR: u64 = u64::MAX;

/// Lepton internal xattr suffix for prefetch blobs ("trusted.lepton.prefetch.blobs").
pub const LEPTON_XATTR_SUFFIX_PREFETCH_BLOBS: &[u8] = b"lepton.prefetch.blobs";

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lepton_internal_xattr_matches_trusted_lepton_prefix_only() {
        assert!(is_lepton_xattr(b"trusted.lepton.prefetch.blobs"));
        assert!(is_lepton_xattr(b"trusted.lepton.other"));
        assert!(!is_lepton_xattr(b"trusted.other"));
        assert!(!is_lepton_xattr(b"user.lepton.prefetch.blobs"));
    }
}
