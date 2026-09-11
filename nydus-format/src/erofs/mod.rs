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
/// RAFS v6 marker: RAFS v6 bootstraps embed a private extension superblock
/// and always set this compat bit; pure-EROFS nydus (rafs v7) bootstraps
/// never do. This crate does not read RAFS v6 images — the bit exists only
/// so the two formats can be told apart (see [`is_rafs_v7_bootstrap`](superblock::is_rafs_v7_bootstrap)).
pub const EROFS_FEATURE_COMPAT_RAFS_V6: u32 = 0x4000_0000;
pub const EROFS_FEATURE_INCOMPAT_CHUNKED_FILE: u32 = 0x0000_0004;
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

// Inode layout.
pub const EROFS_INODE_LAYOUT_COMPACT: u16 = 0;
pub const EROFS_INODE_LAYOUT_EXTENDED: u16 = 1;
pub const EROFS_INODE_COMPACT_SIZE: usize = 32;
pub const EROFS_INODE_EXTENDED_SIZE: usize = 64;

// Inode data layout.
pub const EROFS_INODE_FLAT_PLAIN: u16 = 0;
pub const EROFS_INODE_COMPRESSED_FULL: u16 = 1;
pub const EROFS_INODE_FLAT_INLINE: u16 = 2;
pub const EROFS_INODE_CHUNK_BASED: u16 = 4;

// z_erofs compressed layout (full lcluster indexes).
pub const Z_EROFS_MAP_HEADER_SIZE: usize = 8;
pub const Z_EROFS_LCLUSTER_INDEX_SIZE: usize = 8;
pub const Z_EROFS_ADVISE_BIG_PCLUSTER_1: u16 = 0x0002;
/// The inode's last extent lives in the packed inode: `h_fragmentoff` (the
/// first 4 header bytes) holds the low 32 bits of its offset there and the
/// HEAD lcluster index of that extent the high 32 bits in its blkaddr field.
pub const Z_EROFS_ADVISE_FRAGMENT_PCLUSTER: u16 = 0x0020;
pub const Z_EROFS_LCLUSTER_TYPE_PLAIN: u16 = 0;
pub const Z_EROFS_LCLUSTER_TYPE_HEAD1: u16 = 1;
pub const Z_EROFS_LCLUSTER_TYPE_NONHEAD: u16 = 2;
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

/// A z_erofs pcluster compression algorithm (`z_erofs_map_header
/// .h_algorithmtype` low nibble, and its bit in `available_compr_algs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ZAlgorithm {
    /// LZ4 blocks (kernel 5.x+).
    Lz4 = 0,
    /// zstd frames (kernel 6.10+).
    Zstd = 3,
}

impl ZAlgorithm {
    /// The `h_algorithmtype` value / `available_compr_algs` bit index.
    pub fn as_type(self) -> u8 {
        self as u8
    }

    /// Parses an `h_algorithmtype` nibble.
    pub fn from_type(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Lz4),
            3 => Some(Self::Zstd),
            _ => None,
        }
    }
}

impl std::fmt::Display for ZAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Lz4 => "lz4",
            Self::Zstd => "zstd",
        })
    }
}

/// The z_erofs algorithms an image declares and their COMPR_CFGS records:
/// `available_compr_algs` in the superblock, and right after it one
/// `le16 size` + config record per set bit in algorithm order. Only the
/// algorithms this crate produces are representable; parsing rejects any
/// other bit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ZComprCfgs {
    /// LZ4 `max_pclusterblks` (the record's `max_distance` is always
    /// [`Z_EROFS_LZ4_MAX_DISTANCE`]), `Some` when LZ4 pclusters may occur.
    pub lz4_max_pclusterblks: Option<u16>,
    /// zstd window log2 (absolute, e.g. 19 for 512KiB), `Some` when zstd
    /// pclusters may occur.
    pub zstd_windowlog: Option<u8>,
}

impl ZComprCfgs {
    /// Upper bound of the serialized records: 16 bytes LZ4 + 8 bytes zstd.
    pub const MAX_SIZE: usize = 16 + 8;

    /// No algorithm declared: not a z_erofs image.
    pub fn is_empty(&self) -> bool {
        self.lz4_max_pclusterblks.is_none() && self.zstd_windowlog.is_none()
    }

    /// The `available_compr_algs` bit mask.
    pub fn available_compr_algs(&self) -> u16 {
        let mut algs = 0u16;
        if self.lz4_max_pclusterblks.is_some() {
            algs |= 1 << ZAlgorithm::Lz4.as_type();
        }
        if self.zstd_windowlog.is_some() {
            algs |= 1 << ZAlgorithm::Zstd.as_type();
        }
        algs
    }

    /// Whether pclusters of `algorithm` are declared.
    pub fn has(&self, algorithm: ZAlgorithm) -> bool {
        match algorithm {
            ZAlgorithm::Lz4 => self.lz4_max_pclusterblks.is_some(),
            ZAlgorithm::Zstd => self.zstd_windowlog.is_some(),
        }
    }

    /// The union of two images' configs (a merged image must decode every
    /// layer): per algorithm the larger limit wins.
    pub fn union(self, other: Self) -> Self {
        Self {
            lz4_max_pclusterblks: self.lz4_max_pclusterblks.max(other.lz4_max_pclusterblks),
            zstd_windowlog: self.zstd_windowlog.max(other.zstd_windowlog),
        }
    }

    /// The records as laid out after the superblock.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::MAX_SIZE);
        if let Some(max_pclusterblks) = self.lz4_max_pclusterblks {
            // le16 size, then z_erofs_lz4_cfgs { max_distance, max_pclusterblks, reserved[10] }.
            out.extend_from_slice(&14u16.to_le_bytes());
            out.extend_from_slice(&Z_EROFS_LZ4_MAX_DISTANCE.to_le_bytes());
            out.extend_from_slice(&max_pclusterblks.to_le_bytes());
            out.extend_from_slice(&[0u8; 10]);
        }
        if let Some(windowlog) = self.zstd_windowlog {
            // le16 size, then z_erofs_zstd_cfgs { format, windowlog, reserved[4] }.
            out.extend_from_slice(&6u16.to_le_bytes());
            out.push(0);
            out.push(windowlog - Z_EROFS_ZSTD_WINDOWLOG_BASE);
            out.extend_from_slice(&[0u8; 4]);
        }
        out
    }

    /// Parses the records for the algorithms in `algs` from the bytes after
    /// the superblock. Returns the config and the number of bytes consumed.
    pub fn parse(algs: u16, bytes: &[u8]) -> Result<(Self, usize), String> {
        let mut cfgs = Self::default();
        let mut pos = 0usize;
        for alg in 0..16u8 {
            if algs & (1 << alg) == 0 {
                continue;
            }
            let algorithm = ZAlgorithm::from_type(alg)
                .ok_or_else(|| format!("unsupported z_erofs algorithm {alg}"))?;
            let size = bytes
                .get(pos..pos + 2)
                .map(|s| u16::from_le_bytes([s[0], s[1]]) as usize)
                .ok_or("truncated z_erofs compression config")?;
            let record = bytes
                .get(pos + 2..pos + 2 + size)
                .ok_or("truncated z_erofs compression config")?;
            match algorithm {
                ZAlgorithm::Lz4 => {
                    if size < 4 {
                        return Err("short z_erofs LZ4 config".to_string());
                    }
                    cfgs.lz4_max_pclusterblks = Some(u16::from_le_bytes([record[2], record[3]]));
                }
                ZAlgorithm::Zstd => {
                    if size < 2 {
                        return Err("short z_erofs zstd config".to_string());
                    }
                    if record[0] != 0 {
                        return Err(format!("unsupported z_erofs zstd format {}", record[0]));
                    }
                    cfgs.zstd_windowlog = Some(record[1] + Z_EROFS_ZSTD_WINDOWLOG_BASE);
                }
            }
            pos += 2 + size;
        }
        Ok((cfgs, pos))
    }
}

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
pub const NYDUS_XATTR_SUFFIX_NO_XATTR: &[u8] = b"nydus.no_xattr";

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

    #[test]
    fn z_compr_cfgs_round_trip_in_algorithm_order() {
        let both = ZComprCfgs {
            lz4_max_pclusterblks: Some(16),
            zstd_windowlog: Some(19),
        };
        assert_eq!(both.available_compr_algs(), 0b1001);
        let bytes = both.to_bytes();
        assert_eq!(bytes.len(), 24);
        assert_eq!(&bytes[..6], &[14, 0, 0xff, 0xff, 16, 0]);
        assert_eq!(&bytes[16..20], &[6, 0, 0, 9]);
        assert_eq!(ZComprCfgs::parse(0b1001, &bytes).unwrap(), (both, 24));

        let zstd_only = ZComprCfgs {
            lz4_max_pclusterblks: None,
            zstd_windowlog: Some(20),
        };
        let bytes = zstd_only.to_bytes();
        assert_eq!(bytes.len(), 8);
        assert_eq!(ZComprCfgs::parse(0b1000, &bytes).unwrap(), (zstd_only, 8));
        assert!(
            ZComprCfgs::parse(0b0010, &bytes).is_err(),
            "lzma is rejected"
        );
        assert!(ZComprCfgs::default().is_empty());
        assert_eq!(zstd_only.union(both), both.union(zstd_only));
        assert_eq!(zstd_only.union(both).zstd_windowlog, Some(20));
    }
}
