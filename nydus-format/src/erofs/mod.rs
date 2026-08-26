//! EROFS metadata format definitions.
//!
//! On-disk format structs, constants, and helpers shared between build and
//! runtime. All on-disk structs are `#[repr(C, packed)]` and can be cast
//! directly from mmap'd memory (zero-copy) or constructed in-place for writing.

pub mod block;
pub mod chunk;
pub mod dir;
pub mod inode;
pub mod superblock;

pub use block::{blocks_to_bytes, bytes_to_blocks};
pub use chunk::ErofsChunkIndex;
pub use chunk::{ErofsChunkAddr, ErofsDeviceSlot};
pub use dir::ErofsDirent;
pub use inode::{
    erofs_chunk_format, erofs_compact_i_format, erofs_extended_i_format, erofs_xattr_icount,
    erofs_xattr_name_split, erofs_xattr_prefix, is_nydus_prefetch_blobs_xattr,
    needs_erofs_extended_inode, ErofsInodeCompact, ErofsInodeExtended, XattrEntry,
};
pub use inode::{erofs_xattr_ibody_size, is_nydus_xattr, mode_to_erofs_file_type, ErofsInode};
pub use superblock::validate_superblock;
pub use superblock::ErofsSuperblock;

use std::mem;

// Superblock.
pub const EROFS_SUPER_MAGIC_V1: u32 = 0xE0F5_E1E2;
pub const EROFS_SUPER_OFFSET: u64 = 1024;
pub const EROFS_SB_BASE_SIZE: usize = 128;

// Blob identity.
/// On-disk blob ID field size: blob IDs are SHA-256 digests.
pub const EROFS_BLOB_ID_SIZE: usize = crate::utils::digest::SHA256_DIGEST_SIZE;

// Block / slot sizes.
pub const EROFS_BLOCK_SIZE: u32 = 4096;
pub const EROFS_BLKSZBITS: u8 = 12;
pub const EROFS_ISLOTBITS: u32 = 5;
pub const EROFS_SLOTSIZE: u32 = 1 << EROFS_ISLOTBITS;

// Feature flags.
pub const EROFS_FEATURE_COMPAT_SB_CHKSUM: u32 = 0x0000_0001;
pub const EROFS_FEATURE_COMPAT_MTIME: u32 = 0x0000_0002;
/// Nydus-private compat bit: no inode in this image carries any xattr, so a
/// userspace server can answer xattr requests with ENOSYS (which makes the
/// kernel stop sending them). Compat bits are ignored by kernel EROFS.
pub const EROFS_FEATURE_COMPAT_NYDUS_NO_XATTR: u32 = 0x2000_0000;
/// RAFS v6 marker: RAFS v6 bootstraps embed a private extension superblock
/// and always set this compat bit; pure-EROFS nydus (rafs v7) bootstraps
/// never do. This crate does not read RAFS v6 images — the bit exists only
/// so the two formats can be told apart (see [`is_rafs_v7_bootstrap`](superblock::is_rafs_v7_bootstrap)).
pub const EROFS_FEATURE_COMPAT_RAFS_V6: u32 = 0x4000_0000;
pub const EROFS_FEATURE_INCOMPAT_CHUNKED_FILE: u32 = 0x0000_0004;
pub const EROFS_FEATURE_INCOMPAT_DEVICE_TABLE: u32 = 0x0000_0008;
/// 48-bit block addressing: the kernel interprets the `*_hi` halves of chunk
/// index and device slot addresses only when this bit is set.
pub const EROFS_FEATURE_INCOMPAT_48BIT: u32 = 0x0000_0080;

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

/// Nydus internal xattr suffix for prefetch blobs ("trusted.nydus.prefetch.blobs").
pub const NYDUS_XATTR_SUFFIX_PREFETCH_BLOBS: &[u8] = b"nydus.prefetch.blobs";

/// Cast a byte slice to a reference of `T` (`#[repr(C, packed)]`).
///
/// `T` must be a packed on-disk struct (alignment 1): the data comes from
/// arbitrary offsets of mmap'd files, so a type with a stricter alignment
/// would make this cast undefined behaviour. Asserted below so a misuse
/// fails loudly instead.
#[inline]
pub fn cast_ref<T>(data: &[u8]) -> &T {
    assert!(data.len() >= mem::size_of::<T>());
    assert_eq!(mem::align_of::<T>(), 1);
    unsafe { &*(data.as_ptr() as *const T) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nydus_internal_xattr_matches_trusted_nydus_prefix_only() {
        assert!(is_nydus_xattr(b"trusted.nydus.prefetch.blobs"));
        assert!(is_nydus_xattr(b"trusted.nydus.other"));
        assert!(!is_nydus_xattr(b"trusted.other"));
        assert!(!is_nydus_xattr(b"user.nydus.prefetch.blobs"));
    }
}
