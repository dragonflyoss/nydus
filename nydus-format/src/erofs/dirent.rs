//! The EROFS directory entry.

use crate::erofs::{
    EROFS_DIRENT_SIZE, EROFS_FT_BLKDEV, EROFS_FT_CHRDEV, EROFS_FT_DIR, EROFS_FT_FIFO,
    EROFS_FT_REG_FILE, EROFS_FT_SOCK, EROFS_FT_SYMLINK,
};
use crate::error::{Error, Result};
use crate::utils::bytes::{read_u16, read_u64, write_u16, write_u64};
use std::mem;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned};

/// An EROFS directory entry, `erofs_dirent`, 12 bytes.
///
/// A directory block starts with its entries back to back, and the names
/// follow them: `nameoff` is the name's offset within the block, and the
/// name ends where the next entry's name starts (or at the block end, or a
/// NUL).
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned,
)]
#[repr(C, packed)]
pub struct ErofsDirent {
    /// The entry's inode number.
    pub nid: [u8; 8],

    /// Byte offset of the name within the directory block.
    pub nameoff: [u8; 2],

    /// One of the `EROFS_FT_*` file types.
    pub file_type: u8,

    /// Unused.
    pub reserved: u8,
}

// Fails the build when the struct no longer matches the on-disk size the
// readers slice by.
const _: () = assert!(mem::size_of::<ErofsDirent>() == EROFS_DIRENT_SIZE);

/// Builds a directory entry and reads its fields.
impl ErofsDirent {
    /// Creates an entry pointing at `nid` whose name starts at `nameoff`.
    pub fn new(nid: u64, nameoff: u16, file_type: u8) -> Self {
        let mut dirent = Self::new_zeroed();
        write_u64(&mut dirent.nid, nid);
        write_u16(&mut dirent.nameoff, nameoff);
        dirent.file_type = file_type;
        dirent
    }

    /// Views the directory entry at the start of `bytes`, which must cover it.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self> {
        Self::ref_from_prefix(bytes)
            .map(|(value, _)| value)
            .map_err(|_| {
                Error::InvalidImage(format!(
                    "EROFS directory entry shorter than {EROFS_DIRENT_SIZE} bytes"
                ))
            })
    }

    /// The entry's on-disk bytes.
    pub fn as_bytes(&self) -> &[u8] {
        IntoBytes::as_bytes(self)
    }

    /// The entry's inode number.
    pub fn nid(&self) -> u64 {
        read_u64(&self.nid)
    }

    /// Byte offset of the name within the directory block.
    pub fn nameoff(&self) -> u16 {
        read_u16(&self.nameoff)
    }

    /// One of the `EROFS_FT_*` file types.
    pub fn file_type(&self) -> u8 {
        self.file_type
    }

    /// The `EROFS_FT_*` file type of a Unix file mode, zero for a mode of
    /// unknown type.
    pub fn file_type_from_mode(mode: u16) -> u8 {
        match u32::from(mode) & libc::S_IFMT {
            libc::S_IFREG => EROFS_FT_REG_FILE,
            libc::S_IFDIR => EROFS_FT_DIR,
            libc::S_IFCHR => EROFS_FT_CHRDEV,
            libc::S_IFBLK => EROFS_FT_BLKDEV,
            libc::S_IFIFO => EROFS_FT_FIFO,
            libc::S_IFSOCK => EROFS_FT_SOCK,
            libc::S_IFLNK => EROFS_FT_SYMLINK,
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_encodes_the_fields_little_endian() {
        let test_cases = vec![
            (0, 0, 0, [0u8; 12]),
            (
                0x0102_0304_0506_0708,
                0x0a0b,
                EROFS_FT_REG_FILE,
                [8, 7, 6, 5, 4, 3, 2, 1, 0x0b, 0x0a, EROFS_FT_REG_FILE, 0],
            ),
            (
                u64::MAX,
                u16::MAX,
                EROFS_FT_DIR,
                [
                    0xff,
                    0xff,
                    0xff,
                    0xff,
                    0xff,
                    0xff,
                    0xff,
                    0xff,
                    0xff,
                    0xff,
                    EROFS_FT_DIR,
                    0,
                ],
            ),
        ];

        for (nid, nameoff, file_type, expected) in test_cases {
            let dirent = ErofsDirent::new(nid, nameoff, file_type);
            assert_eq!(dirent.as_bytes(), &expected);

            let parsed = ErofsDirent::from_bytes(&expected).unwrap();
            assert_eq!(parsed.nid(), nid);
            assert_eq!(parsed.nameoff(), nameoff);
            assert_eq!(parsed.file_type(), file_type);
        }
    }

    #[test]
    fn file_type_from_mode_maps_every_mode() {
        let test_cases = vec![
            (0o100644, EROFS_FT_REG_FILE),
            (0o040755, EROFS_FT_DIR),
            (0o020600, EROFS_FT_CHRDEV),
            (0o060600, EROFS_FT_BLKDEV),
            (0o010600, EROFS_FT_FIFO),
            (0o140600, EROFS_FT_SOCK),
            (0o120777, EROFS_FT_SYMLINK),
            (0o000644, 0),
        ];

        for (mode, expected) in test_cases {
            assert_eq!(ErofsDirent::file_type_from_mode(mode), expected);
        }
    }
}
