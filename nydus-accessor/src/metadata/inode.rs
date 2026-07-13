use std::fs;
use std::mem;
use std::os::unix::fs::MetadataExt;

use super::*;

/// EROFS on-disk inode in compact format (32 bytes).
#[repr(C, packed)]
pub struct ErofsInodeCompact {
    pub i_format: [u8; 2],
    pub i_xattr_icount: [u8; 2],
    pub i_mode: [u8; 2],
    pub i_nb: [u8; 2],
    pub i_size: [u8; 4],
    pub i_mtime: [u8; 4],
    pub i_u: [u8; 4],
    pub i_ino: [u8; 4],
    pub i_uid: [u8; 2],
    pub i_gid: [u8; 2],
    pub i_reserved: [u8; 4],
}

const _: () = assert!(mem::size_of::<ErofsInodeCompact>() == EROFS_INODE_COMPACT_SIZE);

impl ErofsInodeCompact {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        i_format: u16,
        i_mode: u16,
        i_nb: u16,
        i_size: u32,
        i_mtime: u32,
        i_u: u32,
        i_ino: u32,
        i_uid: u16,
        i_gid: u16,
    ) -> Self {
        let mut v: Self = unsafe { mem::zeroed() };
        set_u16(&mut v.i_format, i_format);
        set_u16(&mut v.i_mode, i_mode);
        set_u16(&mut v.i_nb, i_nb);
        set_u32(&mut v.i_size, i_size);
        set_u32(&mut v.i_mtime, i_mtime);
        set_u32(&mut v.i_u, i_u);
        set_u32(&mut v.i_ino, i_ino);
        set_u16(&mut v.i_uid, i_uid);
        set_u16(&mut v.i_gid, i_gid);
        v
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, EROFS_INODE_COMPACT_SIZE)
        }
    }

    pub fn format(&self) -> u16 {
        get_u16(&self.i_format)
    }

    pub fn xattr_icount(&self) -> u16 {
        get_u16(&self.i_xattr_icount)
    }

    pub fn mode(&self) -> u16 {
        get_u16(&self.i_mode)
    }

    pub fn nb(&self) -> u16 {
        get_u16(&self.i_nb)
    }

    pub fn size(&self) -> u64 {
        get_u32(&self.i_size) as u64
    }

    pub fn mtime_delta(&self) -> u32 {
        get_u32(&self.i_mtime)
    }

    pub fn i_u(&self) -> u32 {
        get_u32(&self.i_u)
    }

    pub fn ino(&self) -> u32 {
        get_u32(&self.i_ino)
    }

    pub fn uid(&self) -> u32 {
        get_u16(&self.i_uid) as u32
    }

    pub fn gid(&self) -> u32 {
        get_u16(&self.i_gid) as u32
    }
}

/// EROFS on-disk inode in extended format (64 bytes).
#[repr(C, packed)]
pub struct ErofsInodeExtended {
    pub i_format: [u8; 2],
    pub i_xattr_icount: [u8; 2],
    pub i_mode: [u8; 2],
    pub i_nb: [u8; 2],
    pub i_size: [u8; 8],
    pub i_u: [u8; 4],
    pub i_ino: [u8; 4],
    pub i_uid: [u8; 4],
    pub i_gid: [u8; 4],
    pub i_mtime: [u8; 8],
    pub i_mtime_nsec: [u8; 4],
    pub i_nlink: [u8; 4],
    pub i_reserved2: [u8; 16],
}

const _: () = assert!(mem::size_of::<ErofsInodeExtended>() == EROFS_INODE_EXTENDED_SIZE);

impl ErofsInodeExtended {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        i_format: u16,
        i_mode: u16,
        i_nb: u16,
        i_size: u64,
        i_u: u32,
        i_ino: u32,
        i_uid: u32,
        i_gid: u32,
        i_mtime: u64,
        i_mtime_nsec: u32,
        i_nlink: u32,
    ) -> Self {
        let mut v: Self = unsafe { mem::zeroed() };
        set_u16(&mut v.i_format, i_format);
        set_u16(&mut v.i_mode, i_mode);
        set_u16(&mut v.i_nb, i_nb);
        set_u64(&mut v.i_size, i_size);
        set_u32(&mut v.i_u, i_u);
        set_u32(&mut v.i_ino, i_ino);
        set_u32(&mut v.i_uid, i_uid);
        set_u32(&mut v.i_gid, i_gid);
        set_u64(&mut v.i_mtime, i_mtime);
        set_u32(&mut v.i_mtime_nsec, i_mtime_nsec);
        set_u32(&mut v.i_nlink, i_nlink);
        v
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, EROFS_INODE_EXTENDED_SIZE)
        }
    }

    pub fn format(&self) -> u16 {
        get_u16(&self.i_format)
    }

    pub fn xattr_icount(&self) -> u16 {
        get_u16(&self.i_xattr_icount)
    }

    pub fn mode(&self) -> u16 {
        get_u16(&self.i_mode)
    }

    pub fn nb(&self) -> u16 {
        get_u16(&self.i_nb)
    }

    pub fn size(&self) -> u64 {
        get_u64(&self.i_size)
    }

    pub fn i_u(&self) -> u32 {
        get_u32(&self.i_u)
    }

    pub fn ino(&self) -> u32 {
        get_u32(&self.i_ino)
    }

    pub fn uid(&self) -> u32 {
        get_u32(&self.i_uid)
    }

    pub fn gid(&self) -> u32 {
        get_u32(&self.i_gid)
    }

    pub fn mtime(&self) -> u64 {
        get_u64(&self.i_mtime)
    }

    pub fn mtime_nsec(&self) -> u32 {
        get_u32(&self.i_mtime_nsec)
    }

    pub fn nlink(&self) -> u32 {
        get_u32(&self.i_nlink)
    }
}

/// Erofs inode provides a unified interface to both compact and extended formats. Zero-copy, but
/// requires the caller to provide the raw byte slice (e.g. from mmap) and handle the lifetime.
pub enum ErofsInode<'a> {
    Compact(&'a ErofsInodeCompact),
    Extended(&'a ErofsInodeExtended),
}

impl<'a> ErofsInode<'a> {
    /// Cast from a byte slice (first 2 bytes determine format).
    pub fn cast(data: &'a [u8]) -> std::io::Result<Self> {
        if data.len() < 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "too small for inode header",
            ));
        }

        let i_format = u16::from_le_bytes([data[0], data[1]]);
        let is_compact = (i_format >> EROFS_I_VERSION_BIT) & 1 == EROFS_INODE_LAYOUT_COMPACT;
        if is_compact {
            if data.len() < EROFS_INODE_COMPACT_SIZE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "too small for compact inode",
                ));
            }

            Ok(ErofsInode::Compact(cast_ref::<ErofsInodeCompact>(data)))
        } else {
            if data.len() < EROFS_INODE_EXTENDED_SIZE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "too small for extended inode",
                ));
            }

            Ok(ErofsInode::Extended(cast_ref::<ErofsInodeExtended>(data)))
        }
    }

    pub fn format(&self) -> u16 {
        match self {
            Self::Compact(c) => c.format(),
            Self::Extended(e) => e.format(),
        }
    }

    pub fn data_layout(&self) -> u16 {
        (self.format() >> EROFS_I_DATALAYOUT_BIT) & 0x07
    }

    pub fn is_compact(&self) -> bool {
        matches!(self, Self::Compact(_))
    }

    pub fn header_size(&self) -> usize {
        match self {
            Self::Compact(_) => EROFS_INODE_COMPACT_SIZE,
            Self::Extended(_) => EROFS_INODE_EXTENDED_SIZE,
        }
    }

    pub fn xattr_icount(&self) -> u16 {
        match self {
            Self::Compact(c) => c.xattr_icount(),
            Self::Extended(e) => e.xattr_icount(),
        }
    }

    pub fn xattr_size(&self) -> usize {
        let cnt = self.xattr_icount();
        if cnt == 0 {
            0
        } else {
            // xattr_ibody_size = sizeof(erofs_xattr_ibody_header) + sizeof(u32) * (cnt - 1)
            //                  = 12 + 4 * (cnt - 1) = 4 * cnt + 8
            cnt as usize * 4 + 8
        }
    }

    pub fn mode(&self) -> u16 {
        match self {
            Self::Compact(c) => c.mode(),
            Self::Extended(e) => e.mode(),
        }
    }

    pub fn size(&self) -> u64 {
        match self {
            Self::Compact(c) => c.size(),
            Self::Extended(e) => e.size(),
        }
    }

    /// Absolute mtime in seconds. For compact inodes `epoch` must be provided.
    pub fn mtime(&self, epoch: u64) -> u64 {
        match self {
            Self::Compact(c) => epoch + c.mtime_delta() as u64,
            Self::Extended(e) => e.mtime(),
        }
    }

    pub fn mtime_nsec(&self) -> u32 {
        match self {
            Self::Compact(_) => 0,
            Self::Extended(e) => e.mtime_nsec(),
        }
    }

    pub fn effective_mtime_nsec(&self, fixed_nsec: u32) -> u32 {
        match self {
            Self::Compact(_) => fixed_nsec,
            Self::Extended(e) => e.mtime_nsec(),
        }
    }

    pub fn nlink(&self) -> u32 {
        match self {
            Self::Compact(_) => 1,
            Self::Extended(e) => e.nlink(),
        }
    }

    pub fn uid(&self) -> u32 {
        match self {
            Self::Compact(c) => c.uid(),
            Self::Extended(e) => e.uid(),
        }
    }

    pub fn gid(&self) -> u32 {
        match self {
            Self::Compact(c) => c.gid(),
            Self::Extended(e) => e.gid(),
        }
    }

    pub fn ino(&self) -> u32 {
        match self {
            Self::Compact(c) => c.ino(),
            Self::Extended(e) => e.ino(),
        }
    }

    pub fn i_u(&self) -> u32 {
        match self {
            Self::Compact(c) => c.i_u(),
            Self::Extended(e) => e.i_u(),
        }
    }

    pub fn nb(&self) -> u16 {
        match self {
            Self::Compact(c) => c.nb(),
            Self::Extended(e) => e.nb(),
        }
    }

    pub fn rdev(&self) -> u32 {
        self.i_u()
    }

    pub fn chunk_format(&self) -> u16 {
        self.i_u() as u16
    }

    pub fn startblk(&self) -> u64 {
        ((self.nb() as u64) << 32) | self.i_u() as u64
    }
}

/// Compute the chunk format value for chunk-based inodes.
pub fn erofs_chunk_format(chunk_bits: u32, blksz_bits: u32) -> u16 {
    EROFS_CHUNK_FORMAT_INDEXES | ((chunk_bits - blksz_bits) as u16)
}

/// Helper function to construct i_format value for compact inodes.
///
/// Produces a standard EROFS compact i_format (only the version and datalayout
/// fields). The `EROFS_I_NLINK_1` optimization (i_format bit 4) is intentionally
/// not used: older kernels (e.g. 5.10) reject any inode whose i_format has bits
/// outside `EROFS_I_ALL` (0xF). Since `needs_extended` forces every inode with
/// nlink > 1 to the extended layout, all compact inodes have nlink == 1, which
/// is written directly into the standard compact i_nlink field by the callers.
pub fn erofs_compact_i_format(datalayout: u16) -> u16 {
    (EROFS_INODE_LAYOUT_COMPACT << EROFS_I_VERSION_BIT) | (datalayout << EROFS_I_DATALAYOUT_BIT)
}

/// Helper function to construct i_format value for extended inodes.
pub fn erofs_extended_i_format(datalayout: u16) -> u16 {
    (EROFS_INODE_LAYOUT_EXTENDED << EROFS_I_VERSION_BIT) | (datalayout << EROFS_I_DATALAYOUT_BIT)
}

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
pub fn erofs_xattr_ibody_size(xattrs: &[(u8, Vec<u8>, Vec<u8>)]) -> usize {
    if xattrs.is_empty() {
        return 0;
    }

    let mut size = EROFS_XATTR_IBODY_HEADER_SIZE;
    for (_, suffix, value) in xattrs {
        let entry_size = EROFS_XATTR_ENTRY_HEADER_SIZE + suffix.len() + value.len();
        size += round_up(entry_size, 4);
    }

    size
}

/// Compute i_xattr_icount from the xattr ibody size.
/// xattr_ibody_size = 12 + 4 * (icount - 1), so icount = (size - 12) / 4 + 1 = (size - 8) / 4
pub fn erofs_xattr_icount(xattr_ibody_size: usize) -> u16 {
    if xattr_ibody_size == 0 {
        0
    } else {
        let aligned = round_up(xattr_ibody_size, 4);
        ((aligned - 8) / 4) as u16
    }
}

/// Decide whether an inode must use the 64-byte extended on-disk format.
///
/// Compact (32-byte) inodes only support:
/// - file size  <= u32::MAX
/// - uid / gid  <= u16::MAX
/// - nlink == 1 (hardlinks need a real link count)
/// - no per-inode mtime (falls back to the global build time)
pub fn needs_erofs_extended_inode(meta: &fs::Metadata) -> bool {
    meta.size() > u32::MAX as u64
        || meta.uid() > u16::MAX as u32
        || meta.gid() > u16::MAX as u32
        || meta.nlink() > 1
}

/// Check if an xattr name (as bytes) is a Nydus internal xattr (starts with "trusted.nydus.").
pub fn is_nydus_xattr(name: &[u8]) -> bool {
    name.starts_with(b"trusted.nydus.")
}

/// Check if an xattr name is the Nydus prefetch blobs xattr ("trusted.nydus.prefetch.blobs").
pub fn is_nydus_prefetch_blobs_xattr(name: &[u8]) -> bool {
    is_nydus_xattr(name) && name.ends_with(NYDUS_XATTR_SUFFIX_PREFETCH_BLOBS)
}
