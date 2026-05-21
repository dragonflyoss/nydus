use std::mem;

use super::*;

// =====================================================================
// ErofsInodeCompact — 32 bytes
// =====================================================================

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
}

// =====================================================================
// ErofsInodeExtended — 64 bytes
// =====================================================================

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
}

// =====================================================================
// ErofsInode — unified view over compact / extended on-disk inode
// =====================================================================

/// Zero-copy view of an on-disk inode. Borrows directly from mmap.
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

// ---------- format helpers ----------

pub fn compact_i_format(datalayout: u16, nlink_1: bool) -> u16 {
    let mut fmt = (EROFS_INODE_LAYOUT_COMPACT << EROFS_I_VERSION_BIT)
        | (datalayout << EROFS_I_DATALAYOUT_BIT);
    if nlink_1 {
        fmt |= 1 << EROFS_I_NLINK_1_BIT;
    }
    fmt
}

pub fn extended_i_format(datalayout: u16) -> u16 {
    (EROFS_INODE_LAYOUT_EXTENDED << EROFS_I_VERSION_BIT) | (datalayout << EROFS_I_DATALAYOUT_BIT)
}
