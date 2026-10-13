//! The two EROFS inode layouts, the zero-copy view over either, and the
//! helpers that compute inode fields when building an image.

use crate::erofs::{
    ErofsDirent, EROFS_CHUNK_FORMAT_INDEXES, EROFS_INODE_CHUNK_BASED, EROFS_INODE_COMPACT_SIZE,
    EROFS_INODE_EXTENDED_SIZE, EROFS_INODE_LAYOUT_COMPACT, EROFS_INODE_LAYOUT_EXTENDED,
    EROFS_I_DATALAYOUT_BIT, EROFS_I_VERSION_BIT, EROFS_XATTR_ENTRY_HEADER_SIZE,
    EROFS_XATTR_IBODY_HEADER_SIZE, EROFS_XATTR_INDEX_LUSTRE, EROFS_XATTR_INDEX_POSIX_ACL_ACCESS,
    EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT, EROFS_XATTR_INDEX_SECURITY, EROFS_XATTR_INDEX_TRUSTED,
    EROFS_XATTR_INDEX_USER, NYDUS_XATTR_SUFFIX_NO_XATTR, NYDUS_XATTR_SUFFIX_PREFETCH_BLOBS,
};
use crate::error::{Error, Result};
use crate::utils::bytes::{
    read_u16, read_u16_at, read_u32, read_u64, write_u16, write_u32, write_u64,
};
use std::mem;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Every `i_format` bit this crate understands, the version bit and the
/// three data layout bits. Older kernels (5.10) reject an inode setting
/// any other bit.
const EROFS_I_ALL: u16 = 0x0f;

/// Mask of the data layout bits in `i_format`.
const EROFS_I_DATALAYOUT_MASK: u16 = 0x07;

/// Xattr name prefixes by index, the prefix a name's index stands for.
const EROFS_XATTR_PREFIXES: [(u8, &[u8]); 6] = [
    (EROFS_XATTR_INDEX_USER, b"user."),
    (
        EROFS_XATTR_INDEX_POSIX_ACL_ACCESS,
        b"system.posix_acl_access",
    ),
    (
        EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT,
        b"system.posix_acl_default",
    ),
    (EROFS_XATTR_INDEX_TRUSTED, b"trusted."),
    (EROFS_XATTR_INDEX_LUSTRE, b"lustre."),
    (EROFS_XATTR_INDEX_SECURITY, b"security."),
];

/// The suffix prefix of every nydus internal xattr, behind `trusted.`.
const NYDUS_XATTR_SUFFIX_PREFIX: &[u8] = b"nydus.";

/// The compact EROFS inode, `erofs_inode_compact`, 32 bytes.
///
/// A compact inode has no mtime of its own (the superblock's `epoch` and
/// `fixed_nsec` apply), 16-bit uid and gid, a 32-bit size and a 16-bit link
/// count, see [`ErofsInodeExtended::is_needed`].
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned,
)]
#[repr(C, packed)]
pub struct ErofsInodeCompact {
    /// The version bit and the data layout, see [`Self::new`].
    pub i_format: [u8; 2],

    /// The xattr ibody size in 4-byte units plus two, zero without xattrs,
    /// see [`XattrEntry::icount`].
    pub i_xattr_icount: [u8; 2],

    /// The Unix file mode.
    pub i_mode: [u8; 2],

    /// The link count.
    pub i_nb: [u8; 2],

    /// The file size.
    pub i_size: [u8; 4],

    /// Seconds since the superblock's `epoch`. The builder writes it, the
    /// reader here reports the epoch itself for every compact inode, see
    /// [`ErofsInode::mtime`].
    pub i_mtime: [u8; 4],

    /// Layout dependent: the start block of a flat file, the device number
    /// of a device node, or the chunk format of a chunk-based file.
    pub i_u: [u8; 4],

    /// The inode number.
    pub i_ino: [u8; 4],

    /// The owner.
    pub i_uid: [u8; 2],

    /// The group.
    pub i_gid: [u8; 2],

    /// Unused.
    pub i_reserved: [u8; 4],
}

// Fails the build when the struct no longer matches the on-disk size the
// readers slice by.
const _: () = assert!(mem::size_of::<ErofsInodeCompact>() == EROFS_INODE_COMPACT_SIZE);

/// Builds a compact inode and reads its fields.
impl ErofsInodeCompact {
    /// Creates a compact inode with `datalayout`, one of the `EROFS_INODE_*`
    /// layouts, from its raw field values.
    ///
    /// `i_format` carries only the version bit and the layout. The
    /// `EROFS_I_NLINK_1` optimization (bit 4) is deliberately not used:
    /// older kernels (5.10) reject any inode with bits outside `EROFS_I_ALL`,
    /// and since [`ErofsInodeExtended::is_needed`] sends every inode with more
    /// than one link to the extended layout, a compact inode always has its
    /// link count of one in `i_nb`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        datalayout: u16,
        i_mode: u16,
        i_nb: u16,
        i_size: u32,
        i_mtime: u32,
        i_u: u32,
        i_ino: u32,
        i_uid: u16,
        i_gid: u16,
    ) -> Self {
        let mut inode = Self::new_zeroed();
        write_u16(
            &mut inode.i_format,
            (EROFS_INODE_LAYOUT_COMPACT << EROFS_I_VERSION_BIT)
                | (datalayout << EROFS_I_DATALAYOUT_BIT),
        );
        write_u16(&mut inode.i_mode, i_mode);
        write_u16(&mut inode.i_nb, i_nb);
        write_u32(&mut inode.i_size, i_size);
        write_u32(&mut inode.i_mtime, i_mtime);
        write_u32(&mut inode.i_u, i_u);
        write_u32(&mut inode.i_ino, i_ino);
        write_u16(&mut inode.i_uid, i_uid);
        write_u16(&mut inode.i_gid, i_gid);
        inode
    }

    /// Views the compact inode at the start of `bytes`, which must cover it.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self> {
        Self::ref_from_prefix(bytes)
            .map(|(value, _)| value)
            .map_err(|_| {
                Error::InvalidImage(format!(
                    "EROFS compact inode shorter than {EROFS_INODE_COMPACT_SIZE} bytes"
                ))
            })
    }

    /// The inode's on-disk bytes.
    pub fn as_bytes(&self) -> &[u8] {
        IntoBytes::as_bytes(self)
    }

    /// The version bit and the data layout.
    pub fn format(&self) -> u16 {
        read_u16(&self.i_format)
    }

    /// The xattr ibody size in 4-byte units plus two, zero without xattrs.
    pub fn xattr_icount(&self) -> u16 {
        read_u16(&self.i_xattr_icount)
    }

    /// The Unix file mode.
    pub fn mode(&self) -> u16 {
        read_u16(&self.i_mode)
    }

    /// The link count.
    pub fn nb(&self) -> u16 {
        read_u16(&self.i_nb)
    }

    /// The file size.
    pub fn size(&self) -> u64 {
        read_u32(&self.i_size) as u64
    }

    /// The layout dependent `i_u` word.
    pub fn i_u(&self) -> u32 {
        read_u32(&self.i_u)
    }

    /// The inode number.
    pub fn ino(&self) -> u32 {
        read_u32(&self.i_ino)
    }

    /// The owner.
    pub fn uid(&self) -> u32 {
        read_u16(&self.i_uid) as u32
    }

    /// The group.
    pub fn gid(&self) -> u32 {
        read_u16(&self.i_gid) as u32
    }
}

/// The extended EROFS inode, `erofs_inode_extended`, 64 bytes.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned,
)]
#[repr(C, packed)]
pub struct ErofsInodeExtended {
    /// The version bit and the data layout, see [`Self::new`].
    pub i_format: [u8; 2],

    /// The xattr ibody size in 4-byte units plus two, zero without xattrs,
    /// see [`XattrEntry::icount`].
    pub i_xattr_icount: [u8; 2],

    /// The Unix file mode.
    pub i_mode: [u8; 2],

    /// Reserved, the block count with 48BIT. Written as zero.
    pub i_nb: [u8; 2],

    /// The file size.
    pub i_size: [u8; 8],

    /// Layout dependent: the start block of a flat file, the device number
    /// of a device node, or the chunk format of a chunk-based file.
    pub i_u: [u8; 4],

    /// The inode number.
    pub i_ino: [u8; 4],

    /// The owner.
    pub i_uid: [u8; 4],

    /// The group.
    pub i_gid: [u8; 4],

    /// The mtime in seconds.
    pub i_mtime: [u8; 8],

    /// The mtime nanoseconds.
    pub i_mtime_nsec: [u8; 4],

    /// The link count.
    pub i_nlink: [u8; 4],

    /// Unused.
    pub i_reserved2: [u8; 16],
}

// Fails the build when the struct no longer matches the on-disk size the
// readers slice by.
const _: () = assert!(mem::size_of::<ErofsInodeExtended>() == EROFS_INODE_EXTENDED_SIZE);

/// Builds an extended inode and reads its fields.
impl ErofsInodeExtended {
    /// Whether an inode of these values must use this layout instead of the
    /// compact one, which holds a size up to `u32::MAX`, a uid and gid up to
    /// `u16::MAX`, exactly one link, and no mtime of its own.
    pub fn is_needed(size: u64, uid: u32, gid: u32, nlink: u64) -> bool {
        size > u32::MAX as u64 || uid > u16::MAX as u32 || gid > u16::MAX as u32 || nlink > 1
    }

    /// Creates an extended inode with `datalayout`, one of the
    /// `EROFS_INODE_*` layouts, from its raw field values.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        datalayout: u16,
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
        let mut inode = Self::new_zeroed();
        write_u16(
            &mut inode.i_format,
            (EROFS_INODE_LAYOUT_EXTENDED << EROFS_I_VERSION_BIT)
                | (datalayout << EROFS_I_DATALAYOUT_BIT),
        );
        write_u16(&mut inode.i_mode, i_mode);
        write_u16(&mut inode.i_nb, i_nb);
        write_u64(&mut inode.i_size, i_size);
        write_u32(&mut inode.i_u, i_u);
        write_u32(&mut inode.i_ino, i_ino);
        write_u32(&mut inode.i_uid, i_uid);
        write_u32(&mut inode.i_gid, i_gid);
        write_u64(&mut inode.i_mtime, i_mtime);
        write_u32(&mut inode.i_mtime_nsec, i_mtime_nsec);
        write_u32(&mut inode.i_nlink, i_nlink);
        inode
    }

    /// Views the extended inode at the start of `bytes`, which must cover it.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self> {
        Self::ref_from_prefix(bytes)
            .map(|(value, _)| value)
            .map_err(|_| {
                Error::InvalidImage(format!(
                    "EROFS extended inode shorter than {EROFS_INODE_EXTENDED_SIZE} bytes"
                ))
            })
    }

    /// The inode's on-disk bytes.
    pub fn as_bytes(&self) -> &[u8] {
        IntoBytes::as_bytes(self)
    }

    /// The version bit and the data layout.
    pub fn format(&self) -> u16 {
        read_u16(&self.i_format)
    }

    /// The xattr ibody size in 4-byte units plus two, zero without xattrs.
    pub fn xattr_icount(&self) -> u16 {
        read_u16(&self.i_xattr_icount)
    }

    /// The Unix file mode.
    pub fn mode(&self) -> u16 {
        read_u16(&self.i_mode)
    }

    /// The `i_nb` word.
    pub fn nb(&self) -> u16 {
        read_u16(&self.i_nb)
    }

    /// The file size.
    pub fn size(&self) -> u64 {
        read_u64(&self.i_size)
    }

    /// The layout dependent `i_u` word.
    pub fn i_u(&self) -> u32 {
        read_u32(&self.i_u)
    }

    /// The inode number.
    pub fn ino(&self) -> u32 {
        read_u32(&self.i_ino)
    }

    /// The owner.
    pub fn uid(&self) -> u32 {
        read_u32(&self.i_uid)
    }

    /// The group.
    pub fn gid(&self) -> u32 {
        read_u32(&self.i_gid)
    }

    /// The mtime in seconds.
    pub fn mtime(&self) -> u64 {
        read_u64(&self.i_mtime)
    }

    /// The mtime nanoseconds.
    pub fn mtime_nsec(&self) -> u32 {
        read_u32(&self.i_mtime_nsec)
    }

    /// The link count.
    pub fn nlink(&self) -> u32 {
        read_u32(&self.i_nlink)
    }
}

/// A zero-copy view of an on-disk inode in either layout, borrowed from
/// the caller's bytes (an mmap, usually).
#[derive(Clone, Copy, Debug)]
pub enum ErofsInode<'a> {
    /// A 32-byte compact inode.
    Compact(&'a ErofsInodeCompact),

    /// A 64-byte extended inode.
    Extended(&'a ErofsInodeExtended),
}

/// Parses an inode and answers the questions both layouts share.
impl<'a> ErofsInode<'a> {
    /// Parses the inode at the start of `data`, whose first two bytes name
    /// its layout. The format word is checked first (`validate_bytes`),
    /// then the layout views its bytes, then the decoded fields are checked
    /// (`validate`).
    pub fn from_bytes(data: &'a [u8]) -> Result<Self> {
        let i_format = Self::validate_bytes(data)?;
        let inode = if Self::is_compact(i_format) {
            Self::Compact(ErofsInodeCompact::from_bytes(data)?)
        } else {
            Self::Extended(ErofsInodeExtended::from_bytes(data)?)
        };

        inode.validate()?;
        Ok(inode)
    }

    /// Validates the format word ahead of the layout it names: present, and
    /// carrying only known bits. Returns the word.
    fn validate_bytes(data: &[u8]) -> Result<u16> {
        let i_format = data
            .get(..2)
            .map(|head| read_u16_at(head, 0))
            .ok_or_else(|| {
                Error::InvalidImage("EROFS inode shorter than its format word".to_string())
            })?;
        if i_format & !EROFS_I_ALL != 0 {
            return Err(Error::Unsupported(format!(
                "unsupported EROFS inode format {i_format:#x}"
            )));
        }

        Ok(i_format)
    }

    /// Validates the decoded fields: a chunk-based inode stores plain chunk
    /// indexes, the only chunk format this crate reads.
    fn validate(&self) -> Result<()> {
        if self.data_layout() != EROFS_INODE_CHUNK_BASED {
            return Ok(());
        }

        self.chunk_format().validate()
    }

    /// Whether an `i_format` word names the compact layout.
    fn is_compact(i_format: u16) -> bool {
        (i_format >> EROFS_I_VERSION_BIT) & 1 == EROFS_INODE_LAYOUT_COMPACT
    }

    /// The version bit and the data layout.
    pub fn format(&self) -> u16 {
        match self {
            Self::Compact(inode) => inode.format(),
            Self::Extended(inode) => inode.format(),
        }
    }

    /// One of the `EROFS_INODE_*` data layouts.
    pub fn data_layout(&self) -> u16 {
        (self.format() >> EROFS_I_DATALAYOUT_BIT) & EROFS_I_DATALAYOUT_MASK
    }

    /// The on-disk size of the inode itself, ahead of its xattrs.
    pub fn header_size(&self) -> usize {
        match self {
            Self::Compact(_) => EROFS_INODE_COMPACT_SIZE,
            Self::Extended(_) => EROFS_INODE_EXTENDED_SIZE,
        }
    }

    /// The xattr ibody size in 4-byte units plus two, zero without xattrs.
    pub fn xattr_icount(&self) -> u16 {
        match self {
            Self::Compact(inode) => inode.xattr_icount(),
            Self::Extended(inode) => inode.xattr_icount(),
        }
    }

    /// The on-disk size of the xattr ibody after the inode, the inverse of
    /// [`XattrEntry::icount`]: `12 + 4 * (icount - 1)`, zero without xattrs.
    pub fn xattr_size(&self) -> usize {
        match self.xattr_icount() as usize {
            0 => 0,
            icount => EROFS_XATTR_IBODY_HEADER_SIZE + 4 * (icount - 1),
        }
    }

    /// The Unix file mode.
    pub fn mode(&self) -> u16 {
        match self {
            Self::Compact(inode) => inode.mode(),
            Self::Extended(inode) => inode.mode(),
        }
    }

    /// The `EROFS_FT_*` file type a directory entry pointing here carries,
    /// zero for a mode of unknown type.
    pub fn file_type(&self) -> u8 {
        ErofsDirent::file_type_from_mode(self.mode())
    }

    /// The file size.
    pub fn size(&self) -> u64 {
        match self {
            Self::Compact(inode) => inode.size(),
            Self::Extended(inode) => inode.size(),
        }
    }

    /// The mtime in seconds, the superblock's `epoch` for a compact inode.
    pub fn mtime(&self, epoch: u64) -> u64 {
        match self {
            Self::Compact(_) => epoch,
            Self::Extended(inode) => inode.mtime(),
        }
    }

    /// The mtime nanoseconds, the superblock's `fixed_nsec` for a compact
    /// inode.
    pub fn mtime_nsec(&self, fixed_nsec: u32) -> u32 {
        match self {
            Self::Compact(_) => fixed_nsec,
            Self::Extended(inode) => inode.mtime_nsec(),
        }
    }

    /// The link count.
    pub fn nlink(&self) -> u32 {
        match self {
            Self::Compact(inode) => inode.nb() as u32,
            Self::Extended(inode) => inode.nlink(),
        }
    }

    /// The owner.
    pub fn uid(&self) -> u32 {
        match self {
            Self::Compact(inode) => inode.uid(),
            Self::Extended(inode) => inode.uid(),
        }
    }

    /// The group.
    pub fn gid(&self) -> u32 {
        match self {
            Self::Compact(inode) => inode.gid(),
            Self::Extended(inode) => inode.gid(),
        }
    }

    /// The inode number.
    pub fn ino(&self) -> u32 {
        match self {
            Self::Compact(inode) => inode.ino(),
            Self::Extended(inode) => inode.ino(),
        }
    }

    /// The layout dependent `i_u` word.
    pub fn i_u(&self) -> u32 {
        match self {
            Self::Compact(inode) => inode.i_u(),
            Self::Extended(inode) => inode.i_u(),
        }
    }

    /// The `i_nb` word.
    pub fn nb(&self) -> u16 {
        match self {
            Self::Compact(inode) => inode.nb(),
            Self::Extended(inode) => inode.nb(),
        }
    }

    /// The device number of a device node.
    pub fn rdev(&self) -> u32 {
        self.i_u()
    }

    /// The chunk format of a chunk-based file.
    pub fn chunk_format(&self) -> ErofsInodeChunkFormat {
        ErofsInodeChunkFormat(self.i_u() as u16)
    }

    /// The start block of a flat file.
    pub fn startblk(&self) -> u64 {
        self.i_u() as u64
    }
}

/// The chunk format word of a chunk-based inode, its `i_u`: the INDEXES
/// flag and the chunk size as its log2 above the block size.
///
/// ```text
/// bit   meaning
/// 0-4   chunk_bits - blksz_bits
/// 5     EROFS_CHUNK_FORMAT_INDEXES, chunks are ErofsChunkIndex entries
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErofsInodeChunkFormat(u16);

/// Builds the word for a writer and decodes it for a reader.
impl ErofsInodeChunkFormat {
    /// Mask of the bits holding `chunk_bits - blksz_bits`.
    const BLKBITS_MASK: u16 = 0x001f;

    /// The format of plain indexes of `1 << chunk_bits` byte chunks in an
    /// image of `1 << blksz_bits` byte blocks.
    pub fn new(chunk_bits: u32, blksz_bits: u32) -> Self {
        Self(EROFS_CHUNK_FORMAT_INDEXES | ((chunk_bits - blksz_bits) as u16))
    }

    /// The raw on-disk word.
    pub fn bits(self) -> u16 {
        self.0
    }

    /// The log2 of the chunk size in an image of `1 << blksz_bits` byte
    /// blocks.
    pub fn chunk_bits(self, blksz_bits: u32) -> u32 {
        blksz_bits + u32::from(self.0 & Self::BLKBITS_MASK)
    }

    /// Validates that the word declares plain indexes and nothing else,
    /// the only chunk format this crate reads.
    fn validate(self) -> Result<()> {
        if self.0 & EROFS_CHUNK_FORMAT_INDEXES == 0
            || self.0 & !(EROFS_CHUNK_FORMAT_INDEXES | Self::BLKBITS_MASK) != 0
        {
            return Err(Error::Unsupported(format!(
                "unsupported EROFS chunk format {:#x}",
                self.0
            )));
        }

        Ok(())
    }
}

/// One extended attribute of an inode: the EROFS name-prefix index, the
/// name suffix after that prefix, and the value bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XattrEntry {
    /// One of the `EROFS_XATTR_INDEX_*` prefixes.
    pub name_index: u8,

    /// The name after the prefix.
    pub suffix: Vec<u8>,

    /// The value.
    pub value: Vec<u8>,
}

/// Splits and rebuilds names, and sizes the xattr ibody entries make.
impl XattrEntry {
    /// Splits the full xattr `name` on the EROFS prefix table, `None` when
    /// no prefix matches, since EROFS cannot store such a name.
    pub fn new(name: &[u8], value: Vec<u8>) -> Option<Self> {
        let (name_index, suffix) = EROFS_XATTR_PREFIXES
            .iter()
            .find_map(|(name_index, prefix)| Some((*name_index, name.strip_prefix(*prefix)?)))?;
        Some(Self {
            name_index,
            suffix: suffix.to_vec(),
            value,
        })
    }

    /// The full xattr name, the prefix the index stands for and then the
    /// suffix. An unknown index contributes no prefix.
    pub fn name(&self) -> Vec<u8> {
        let prefix = EROFS_XATTR_PREFIXES
            .iter()
            .find(|(name_index, _)| *name_index == self.name_index)
            .map_or(&[][..], |(_, prefix)| prefix);
        [prefix, &self.suffix].concat()
    }

    /// The entry's on-disk size: the 4-byte entry header, the suffix and the
    /// value, rounded up to 4 bytes.
    pub fn size(&self) -> usize {
        (EROFS_XATTR_ENTRY_HEADER_SIZE + self.suffix.len() + self.value.len()).next_multiple_of(4)
    }

    /// The xattr ibody size of `xattrs`: the 12-byte ibody header and then
    /// every entry, zero without xattrs.
    pub fn ibody_size(xattrs: &[Self]) -> usize {
        if xattrs.is_empty() {
            return 0;
        }

        EROFS_XATTR_IBODY_HEADER_SIZE + xattrs.iter().map(Self::size).sum::<usize>()
    }

    /// The `i_xattr_icount` of an inode holding `xattrs`:
    /// `(ibody_size - 12) / 4 + 1`, zero without xattrs. The inverse of
    /// [`ErofsInode::xattr_size`].
    pub fn icount(xattrs: &[Self]) -> u16 {
        match Self::ibody_size(xattrs) {
            0 => 0,
            size => ((size - EROFS_XATTR_IBODY_HEADER_SIZE) / 4 + 1) as u16,
        }
    }

    /// Whether the entry is a nydus internal xattr (`trusted.nydus.*`),
    /// which the image's own tooling writes and hides from users.
    pub fn is_nydus(&self) -> bool {
        self.name_index == EROFS_XATTR_INDEX_TRUSTED
            && self.suffix.starts_with(NYDUS_XATTR_SUFFIX_PREFIX)
    }

    /// Whether the entry is the root's prefetch blobs xattr
    /// (`trusted.nydus.prefetch.blobs`).
    pub fn is_nydus_prefetch_blobs(&self) -> bool {
        self.name_index == EROFS_XATTR_INDEX_TRUSTED
            && self.suffix == NYDUS_XATTR_SUFFIX_PREFETCH_BLOBS
    }

    /// Whether the entry is the root's no-xattr marker
    /// (`trusted.nydus.no_xattr`).
    pub fn is_nydus_no_xattr(&self) -> bool {
        self.name_index == EROFS_XATTR_INDEX_TRUSTED && self.suffix == NYDUS_XATTR_SUFFIX_NO_XATTR
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::erofs::{
        EROFS_FT_DIR, EROFS_FT_REG_FILE, EROFS_INODE_FLAT_INLINE, EROFS_INODE_FLAT_PLAIN,
    };

    #[test]
    fn from_bytes_reads_a_compact_inode() {
        let compact = ErofsInodeCompact::new(
            EROFS_INODE_FLAT_PLAIN,
            0o100644,
            1,
            4096,
            u32::MAX,
            7,
            9,
            1000,
            1001,
        );
        let inode = ErofsInode::from_bytes(compact.as_bytes()).unwrap();

        assert!(matches!(inode, ErofsInode::Compact(_)));
        assert_eq!(inode.format(), 0);
        assert_eq!(inode.data_layout(), EROFS_INODE_FLAT_PLAIN);
        assert_eq!(inode.header_size(), EROFS_INODE_COMPACT_SIZE);
        assert_eq!(inode.xattr_icount(), 0);
        assert_eq!(inode.xattr_size(), 0);
        assert_eq!(inode.mode(), 0o100644);
        assert_eq!(inode.file_type(), EROFS_FT_REG_FILE);
        assert_eq!(inode.size(), 4096);
        assert_eq!(inode.mtime(1_700_000_000), 1_700_000_000);
        assert_eq!(inode.mtime_nsec(123_456_789), 123_456_789);
        assert_eq!(inode.nlink(), 1);
        assert_eq!(inode.uid(), 1000);
        assert_eq!(inode.gid(), 1001);
        assert_eq!(inode.ino(), 9);
        assert_eq!(inode.i_u(), 7);
        assert_eq!(inode.nb(), 1);
        assert_eq!(inode.rdev(), 7);
        assert_eq!(inode.chunk_format().bits(), 7);
        assert_eq!(inode.startblk(), 7);
    }

    #[test]
    fn from_bytes_reads_an_extended_inode() {
        let extended = ErofsInodeExtended::new(
            EROFS_INODE_FLAT_INLINE,
            0o040755,
            0xffff,
            1 << 40,
            7,
            9,
            70_000,
            70_001,
            1_600_000_000,
            500,
            3,
        );
        let inode = ErofsInode::from_bytes(extended.as_bytes()).unwrap();

        assert!(matches!(inode, ErofsInode::Extended(_)));
        assert_eq!(inode.format(), 5);
        assert_eq!(inode.data_layout(), EROFS_INODE_FLAT_INLINE);
        assert_eq!(inode.header_size(), EROFS_INODE_EXTENDED_SIZE);
        assert_eq!(inode.mode(), 0o040755);
        assert_eq!(inode.file_type(), EROFS_FT_DIR);
        assert_eq!(inode.size(), 1 << 40);
        assert_eq!(inode.mtime(1_700_000_000), 1_600_000_000);
        assert_eq!(inode.mtime_nsec(123_456_789), 500);
        assert_eq!(inode.nlink(), 3);
        assert_eq!(inode.uid(), 70_000);
        assert_eq!(inode.gid(), 70_001);
        assert_eq!(inode.ino(), 9);
        assert_eq!(inode.nb(), 0xffff);
        assert_eq!(inode.startblk(), 7);
    }

    #[test]
    fn new_places_the_version_and_layout_bits() {
        let test_cases = vec![
            (EROFS_INODE_FLAT_PLAIN, 0, 1),
            (EROFS_INODE_FLAT_INLINE, 4, 5),
            (EROFS_INODE_CHUNK_BASED, 8, 9),
        ];

        for (datalayout, compact, extended) in test_cases {
            assert_eq!(
                ErofsInodeCompact::new(datalayout, 0, 1, 0, 0, 0, 0, 0, 0).format(),
                compact
            );
            assert_eq!(
                ErofsInodeExtended::new(datalayout, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1).format(),
                extended
            );
        }
    }

    #[test]
    fn from_bytes_rejects_short_or_unsupported_inodes() {
        let compact = ErofsInodeCompact::new(EROFS_INODE_FLAT_PLAIN, 0o100644, 1, 0, 0, 0, 1, 0, 0);
        let extended =
            ErofsInodeExtended::new(EROFS_INODE_FLAT_PLAIN, 0o100644, 0, 0, 0, 1, 0, 0, 0, 0, 1);

        let test_cases = vec![
            (Vec::new(), "EROFS inode shorter than its format word"),
            (vec![0], "EROFS inode shorter than its format word"),
            (
                compact.as_bytes()[..31].to_vec(),
                "EROFS compact inode shorter than 32 bytes",
            ),
            (
                extended.as_bytes()[..63].to_vec(),
                "EROFS extended inode shorter than 64 bytes",
            ),
            (vec![0x10, 0x00], "unsupported EROFS inode format 0x10"),
            (vec![0x01, 0x80], "unsupported EROFS inode format 0x8001"),
        ];

        for (bytes, expected) in test_cases {
            assert_eq!(
                ErofsInode::from_bytes(&bytes).unwrap_err().to_string(),
                expected
            );
        }
    }

    #[test]
    fn from_bytes_rejects_unsupported_chunk_formats_even_for_empty_files() {
        let test_cases = vec![
            (0x0000, Err("unsupported EROFS chunk format 0x0")),
            (0x0040, Err("unsupported EROFS chunk format 0x40")),
            (0x0060, Err("unsupported EROFS chunk format 0x60")),
            (0x8020, Err("unsupported EROFS chunk format 0x8020")),
            (EROFS_CHUNK_FORMAT_INDEXES as u32, Ok(())),
            (EROFS_CHUNK_FORMAT_INDEXES as u32 | 0x1f, Ok(())),
        ];

        for size in [0, 4096] {
            for &(chunk_format, expected) in &test_cases {
                let inode = ErofsInodeCompact::new(
                    EROFS_INODE_CHUNK_BASED,
                    0o100644,
                    1,
                    size,
                    0,
                    chunk_format,
                    1,
                    0,
                    0,
                );
                assert_eq!(
                    ErofsInode::from_bytes(inode.as_bytes())
                        .map(drop)
                        .map_err(|err| err.to_string()),
                    expected.map_err(String::from)
                );
            }
        }
    }

    #[test]
    fn xattr_size_follows_the_icount() {
        let test_cases = vec![(0, 0), (1, 12), (2, 16), (5, 28)];

        for (icount, expected) in test_cases {
            let mut compact =
                ErofsInodeCompact::new(EROFS_INODE_FLAT_PLAIN, 0o100644, 1, 0, 0, 0, 1, 0, 0);
            write_u16(&mut compact.i_xattr_icount, icount);
            let inode = ErofsInode::from_bytes(compact.as_bytes()).unwrap();
            assert_eq!(inode.xattr_size(), expected);
        }
    }

    #[test]
    fn chunk_format_new_stores_the_chunk_bits_above_the_block_bits() {
        let test_cases = vec![
            (21, 12, EROFS_CHUNK_FORMAT_INDEXES | 9),
            (12, 12, EROFS_CHUNK_FORMAT_INDEXES),
            (20, 9, EROFS_CHUNK_FORMAT_INDEXES | 11),
        ];

        for (chunk_bits, blksz_bits, expected) in test_cases {
            let chunk_format = ErofsInodeChunkFormat::new(chunk_bits, blksz_bits);
            assert_eq!(chunk_format.bits(), expected);
            assert_eq!(chunk_format.chunk_bits(blksz_bits), chunk_bits);
            chunk_format.validate().unwrap();
        }
    }

    #[test]
    fn xattr_entry_new_splits_the_name_on_the_prefix_table() {
        let test_cases = vec![
            (
                &b"user.mime"[..],
                Some((EROFS_XATTR_INDEX_USER, &b"mime"[..])),
            ),
            (
                b"system.posix_acl_access",
                Some((EROFS_XATTR_INDEX_POSIX_ACL_ACCESS, &b""[..])),
            ),
            (
                b"system.posix_acl_default",
                Some((EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT, &b""[..])),
            ),
            (
                b"trusted.nydus.no_xattr",
                Some((EROFS_XATTR_INDEX_TRUSTED, &b"nydus.no_xattr"[..])),
            ),
            (b"lustre.lov", Some((EROFS_XATTR_INDEX_LUSTRE, &b"lov"[..]))),
            (
                b"security.selinux",
                Some((EROFS_XATTR_INDEX_SECURITY, &b"selinux"[..])),
            ),
            (b"system.other", None),
            (b"user", None),
            (b"", None),
        ];

        for (name, expected) in test_cases {
            let entry = XattrEntry::new(name, b"value".to_vec());
            assert_eq!(
                entry
                    .as_ref()
                    .map(|entry| (entry.name_index, entry.suffix.as_slice())),
                expected
            );
            if let Some(entry) = entry {
                assert_eq!(entry.name(), name);
                assert_eq!(entry.value, b"value");
            }
        }
    }

    #[test]
    fn xattr_entry_name_drops_an_unknown_prefix_index() {
        let test_cases = vec![0, 7, u8::MAX];

        for name_index in test_cases {
            let entry = XattrEntry {
                name_index,
                suffix: b"suffix".to_vec(),
                value: Vec::new(),
            };
            assert_eq!(entry.name(), b"suffix");
        }
    }

    #[test]
    fn xattr_entry_ibody_size_rounds_each_entry_to_four_bytes() {
        let entry = |suffix: &[u8], value: &[u8]| XattrEntry {
            name_index: EROFS_XATTR_INDEX_USER,
            suffix: suffix.to_vec(),
            value: value.to_vec(),
        };

        let test_cases = vec![
            (vec![], 0, 0),
            (vec![entry(b"", b"")], 16, 2),
            (vec![entry(b"a", b"")], 20, 3),
            (vec![entry(b"abcd", b"")], 20, 3),
            (vec![entry(b"abcd", b"v")], 24, 4),
            (vec![entry(b"a", b"v"), entry(b"bcd", b"value")], 32, 6),
        ];

        for (xattrs, expected_size, expected_icount) in test_cases {
            assert_eq!(XattrEntry::ibody_size(&xattrs), expected_size);
            assert_eq!(XattrEntry::icount(&xattrs), expected_icount);
            assert_eq!(
                xattrs.iter().map(XattrEntry::size).sum::<usize>(),
                expected_size.saturating_sub(EROFS_XATTR_IBODY_HEADER_SIZE)
            );
        }
    }

    #[test]
    fn extended_is_needed_checks_every_compact_limit() {
        let test_cases = vec![
            (0, 0, 0, 1, false),
            (u32::MAX as u64, u16::MAX as u32, u16::MAX as u32, 1, false),
            (u32::MAX as u64 + 1, 0, 0, 1, true),
            (0, u16::MAX as u32 + 1, 0, 1, true),
            (0, 0, u16::MAX as u32 + 1, 1, true),
            (0, 0, 0, 2, true),
        ];

        for (size, uid, gid, nlink, expected) in test_cases {
            assert_eq!(
                ErofsInodeExtended::is_needed(size, uid, gid, nlink),
                expected
            );
        }
    }

    #[test]
    fn xattr_entry_is_nydus_matches_the_trusted_nydus_prefix_only() {
        let test_cases = vec![
            (&b"trusted.nydus.prefetch.blobs"[..], true, true, false),
            (b"trusted.nydus.no_xattr", true, false, true),
            (b"trusted.nydus.other", true, false, false),
            (b"trusted.nydus.", true, false, false),
            (b"trusted.nydus.xnydus.prefetch.blobs", true, false, false),
            (b"trusted.other", false, false, false),
            (b"user.nydus.prefetch.blobs", false, false, false),
            (b"security.nydus.no_xattr", false, false, false),
        ];

        for (name, nydus, prefetch_blobs, no_xattr) in test_cases {
            let entry = XattrEntry::new(name, Vec::new()).unwrap();
            assert_eq!(entry.is_nydus(), nydus, "{name:?}");
            assert_eq!(entry.is_nydus_prefetch_blobs(), prefetch_blobs, "{name:?}");
            assert_eq!(entry.is_nydus_no_xattr(), no_xattr, "{name:?}");
        }
    }
}
