//! EROFS metadata format definitions.
//!
//! On-disk format structs, constants, and helpers shared between build and
//! runtime. All on-disk structs are `#[repr(C, packed)]` byte arrays viewed
//! in place through `zerocopy`, from mmap'd memory for a reader and into the
//! output buffer for a writer. Field names and constants follow
//! `erofs_fs.h` in the kernel.

use crate::utils::SHA256_DIGEST_SIZE;

pub mod chunk;
pub mod compressor;
pub mod dirent;
pub mod inode;
pub mod superblock;
pub use chunk::{ErofsChunkAddr, ErofsChunkIndex, ErofsDeviceSlot};
pub use compressor::{ZErofsComprCfgs, ZErofsCompressor};
pub use dirent::ErofsDirent;
pub use inode::{
    ErofsInode, ErofsInodeChunkFormat, ErofsInodeCompact, ErofsInodeExtended, XattrEntry,
};
pub use superblock::ErofsSuperblock;

/// The superblock magic.
pub const EROFS_SUPER_MAGIC_V1: u32 = 0xe0f5_e1e2;

/// Byte offset of the superblock in the image.
pub const EROFS_SUPER_OFFSET: u64 = 1024;

/// Size of the superblock without extension slots.
pub const EROFS_SB_BASE_SIZE: usize = 128;

/// Bytes per `sb_extslots` slot extending the superblock past its base size.
pub const EROFS_SB_EXTSLOT_SIZE: usize = 16;

/// On-disk blob id field size: blob ids are SHA-256 digests.
pub const EROFS_BLOB_ID_SIZE: usize = SHA256_DIGEST_SIZE;

/// The only block size this crate reads and writes.
pub const EROFS_BLOCK_SIZE: u32 = 4096;

/// log2 of [`EROFS_BLOCK_SIZE`], the superblock's `blkszbits`.
pub const EROFS_BLKSZBITS: u8 = 12;

/// log2 of the inode slot size, a nid counts slots from `meta_blkaddr`.
pub const EROFS_ISLOTBITS: u32 = 5;

/// The inode slot size, 32 bytes.
pub const EROFS_SLOTSIZE: u32 = 1 << EROFS_ISLOTBITS;

/// The superblock carries a crc32c checksum.
pub const EROFS_FEATURE_COMPAT_SB_CHKSUM: u32 = 0x0000_0001;

/// Inodes carry real mtimes instead of the superblock build time.
pub const EROFS_FEATURE_COMPAT_MTIME: u32 = 0x0000_0002;

/// RAFS v6 marker: RAFS v6 bootstraps embed a private extension superblock
/// and always set this compat bit; pure-EROFS nydus (rafs v7) bootstraps
/// never do. This crate does not read RAFS v6 images, the bit exists only
/// so the two formats can be told apart.
pub const EROFS_FEATURE_COMPAT_RAFS_V6: u32 = 0x4000_0000;

/// Regular files may be laid out as chunk indexes.
pub const EROFS_FEATURE_INCOMPAT_CHUNKED_FILE: u32 = 0x0000_0004;

/// A device table of [`ErofsDeviceSlot`] entries follows the superblock.
pub const EROFS_FEATURE_INCOMPAT_DEVICE_TABLE: u32 = 0x0000_0008;

/// Small files (and file tails) live in the packed inode referenced by the
/// superblock's `packed_nid` (kernel 6.1+).
pub const EROFS_FEATURE_INCOMPAT_FRAGMENTS: u32 = 0x0000_0020;

/// 48-bit block addressing: the kernel interprets the `*_hi` halves of chunk
/// index and device slot addresses only when this bit is set.
pub const EROFS_FEATURE_INCOMPAT_48BIT: u32 = 0x0000_0080;

/// z_erofs: compressed data is tail-aligned inside its pcluster (leading
/// zeros), which lets the kernel decompress in place.
pub const EROFS_FEATURE_INCOMPAT_ZERO_PADDING: u32 = 0x0000_0001;

/// z_erofs: pclusters may span more than one block (CBLKCNT lclusters).
pub const EROFS_FEATURE_INCOMPAT_BIG_PCLUSTER: u32 = 0x0000_0002;

/// z_erofs: per-algorithm compression configs follow the superblock and
/// `available_compr_algs` replaces the legacy `lz4_max_distance` field.
/// Shares its bit with BIG_PCLUSTER (both landed in the same kernel release).
pub const EROFS_FEATURE_INCOMPAT_COMPR_CFGS: u32 = 0x0000_0002;

/// `i_format` version bit value of a 32-byte compact inode.
pub const EROFS_INODE_LAYOUT_COMPACT: u16 = 0;

/// `i_format` version bit value of a 64-byte extended inode.
pub const EROFS_INODE_LAYOUT_EXTENDED: u16 = 1;

/// On-disk size of [`ErofsInodeCompact`].
pub const EROFS_INODE_COMPACT_SIZE: usize = 32;

/// On-disk size of [`ErofsInodeExtended`].
pub const EROFS_INODE_EXTENDED_SIZE: usize = 64;

/// Data layout: whole blocks from `startblk`.
pub const EROFS_INODE_FLAT_PLAIN: u16 = 0;

/// Data layout: z_erofs compressed with full lcluster indexes.
pub const EROFS_INODE_COMPRESSED_FULL: u16 = 1;

/// Data layout: whole blocks from `startblk`, the tail inline after the
/// inode.
pub const EROFS_INODE_FLAT_INLINE: u16 = 2;

/// Data layout: one [`ErofsChunkIndex`] per chunk after the inode.
pub const EROFS_INODE_CHUNK_BASED: u16 = 4;

/// Size of the `z_erofs_map_header` ahead of the lcluster indexes.
pub const Z_EROFS_MAP_HEADER_SIZE: usize = 8;

/// Size of one full lcluster index.
pub const Z_EROFS_LCLUSTER_INDEX_SIZE: usize = 8;

/// `h_advise`: HEAD1 pclusters may span more than one block.
pub const Z_EROFS_ADVISE_BIG_PCLUSTER_1: u16 = 0x0002;

/// The inode's last extent lives in the packed inode: `h_fragmentoff` (the
/// first 4 header bytes) holds the low 32 bits of its offset there and the
/// HEAD lcluster index of that extent the high 32 bits in its blkaddr field.
pub const Z_EROFS_ADVISE_FRAGMENT_PCLUSTER: u16 = 0x0020;

/// lcluster type: uncompressed, one block.
pub const Z_EROFS_LCLUSTER_TYPE_PLAIN: u16 = 0;

/// lcluster type: the head of a pcluster of the first algorithm.
pub const Z_EROFS_LCLUSTER_TYPE_HEAD1: u16 = 1;

/// lcluster type: continues the pcluster of a preceding head.
pub const Z_EROFS_LCLUSTER_TYPE_NONHEAD: u16 = 2;

/// lcluster type: the head of a pcluster of the second algorithm.
pub const Z_EROFS_LCLUSTER_TYPE_HEAD2: u16 = 3;

/// Mask of the lcluster type bits in a full lcluster index `di_advise`.
pub const Z_EROFS_LI_LCLUSTER_TYPE_MASK: u16 = 0x3;

/// Bit 63 of an 8-byte z_erofs map header marks a whole-file fragment: the
/// remaining bits hold the file's offset in the packed inode.
pub const Z_EROFS_FRAGMENT_INODE_FLAG: u64 = 1 << 63;

/// Set in `delta[0]` of the first NONHEAD lcluster to carry the pcluster's
/// physical block count instead of a head distance.
pub const Z_EROFS_LI_D0_CBLKCNT: u16 = 1 << 11;

/// LZ4 sliding-window upper bound recorded in the superblock.
pub const Z_EROFS_LZ4_MAX_DISTANCE: u16 = 65535;

/// `z_erofs_zstd_cfgs.windowlog` is stored relative to this
/// (`ZSTD_WINDOWLOG_ABSOLUTEMIN`).
pub const Z_EROFS_ZSTD_WINDOWLOG_BASE: u8 = 10;

/// Largest zstd window the kernel accepts for z_erofs (1MiB, log2 20).
pub const Z_EROFS_ZSTD_MAX_WINDOWLOG: u8 = 20;

/// `i_format` bit holding the inode layout version.
pub const EROFS_I_VERSION_BIT: u16 = 0;

/// `i_format` first bit of the three-bit data layout.
pub const EROFS_I_DATALAYOUT_BIT: u16 = 1;

/// Chunk format: chunks are [`ErofsChunkIndex`] entries, not bare block
/// addresses.
pub const EROFS_CHUNK_FORMAT_INDEXES: u16 = 0x0020;

/// On-disk size of [`ErofsChunkIndex`].
pub const EROFS_CHUNK_INDEX_SIZE: usize = 8;

/// Directory entry file type: regular file.
pub const EROFS_FT_REG_FILE: u8 = 1;

/// Directory entry file type: directory.
pub const EROFS_FT_DIR: u8 = 2;

/// Directory entry file type: character device.
pub const EROFS_FT_CHRDEV: u8 = 3;

/// Directory entry file type: block device.
pub const EROFS_FT_BLKDEV: u8 = 4;

/// Directory entry file type: FIFO.
pub const EROFS_FT_FIFO: u8 = 5;

/// Directory entry file type: socket.
pub const EROFS_FT_SOCK: u8 = 6;

/// Directory entry file type: symbolic link.
pub const EROFS_FT_SYMLINK: u8 = 7;

/// Xattr name index of the `user.` prefix.
pub const EROFS_XATTR_INDEX_USER: u8 = 1;

/// Xattr name index of `system.posix_acl_access`.
pub const EROFS_XATTR_INDEX_POSIX_ACL_ACCESS: u8 = 2;

/// Xattr name index of `system.posix_acl_default`.
pub const EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT: u8 = 3;

/// Xattr name index of the `trusted.` prefix.
pub const EROFS_XATTR_INDEX_TRUSTED: u8 = 4;

/// Xattr name index of the `lustre.` prefix.
pub const EROFS_XATTR_INDEX_LUSTRE: u8 = 5;

/// Xattr name index of the `security.` prefix.
pub const EROFS_XATTR_INDEX_SECURITY: u8 = 6;

/// Size of the `erofs_xattr_ibody_header` ahead of an inode's xattr
/// entries.
pub const EROFS_XATTR_IBODY_HEADER_SIZE: usize = 12;

/// Size of the `erofs_xattr_entry` header ahead of its name and value.
pub const EROFS_XATTR_ENTRY_HEADER_SIZE: usize = 4;

/// On-disk size of [`ErofsDirent`].
pub const EROFS_DIRENT_SIZE: usize = 12;

/// On-disk size of [`ErofsDeviceSlot`].
pub const EROFS_DEVICESLOT_SIZE: usize = 128;

/// The block address of a hole in a chunk-based file.
pub const EROFS_NULL_ADDR: u64 = u64::MAX;

/// Nydus internal xattr suffix for prefetch blobs
/// (`trusted.nydus.prefetch.blobs`).
pub const NYDUS_XATTR_SUFFIX_PREFETCH_BLOBS: &[u8] = b"nydus.prefetch.blobs";

/// Nydus internal xattr suffix marking an image built without xattrs
/// (`trusted.nydus.no_xattr`).
pub const NYDUS_XATTR_SUFFIX_NO_XATTR: &[u8] = b"nydus.no_xattr";
