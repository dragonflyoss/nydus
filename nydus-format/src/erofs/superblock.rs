//! The EROFS superblock.

use crate::erofs::{
    EROFS_BLKSZBITS, EROFS_FEATURE_INCOMPAT_BIG_PCLUSTER, EROFS_FEATURE_INCOMPAT_CHUNKED_FILE,
    EROFS_FEATURE_INCOMPAT_DEVICE_TABLE, EROFS_FEATURE_INCOMPAT_FRAGMENTS,
    EROFS_FEATURE_INCOMPAT_ZERO_PADDING, EROFS_SB_BASE_SIZE, EROFS_SB_EXTSLOT_SIZE,
    EROFS_SUPER_MAGIC_V1,
};
use crate::error::{Error, Result};
use crate::utils::bytes::{read_u16, read_u32, read_u64, write_u16, write_u32, write_u64};
use crate::utils::FeatureFlags;
use std::mem;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned};

/// The EROFS superblock, `erofs_super_block`, 128 bytes at
/// [`EROFS_SUPER_OFFSET`](crate::erofs::EROFS_SUPER_OFFSET), integers
/// little-endian.
///
/// ```text
/// offset  size  field
///      0     4  magic                EROFS_SUPER_MAGIC_V1
///      4     4  checksum             crc32c, with SB_CHKSUM
///      8     4  feature_compat
///     12     1  blkszbits            always EROFS_BLKSZBITS here
///     13     1  sb_extslots          16-byte slots past the base size
///     14     2  rootnid_2b           root inode nid
///     16     8  inos                 inode count
///     24     8  epoch                build time, compact inode mtime
///     32     4  fixed_nsec           build time nanoseconds
///     36     4  blocks_lo            image size in blocks
///     40     4  meta_blkaddr         block the inode slots count from
///     44     4  xattr_blkaddr        block of the shared xattrs
///     48    16  uuid
///     64    16  volume_name
///     80     4  feature_incompat
///     84     2  compr_or_distance    available_compr_algs with
///                                    COMPR_CFGS, else lz4_max_distance
///     86     2  extra_devices        device slots after the superblock
///     88     2  devt_slotoff         first device slot, in 128-byte units
///     90     1  dirblkbits           0 here, directory block size log2
///     91     1  xattr_prefix_count
///     92     4  xattr_prefix_start
///     96     8  packed_nid           fragment inode, with FRAGMENTS
///    104     1  xattr_filter_reserved
///    105     3  reserved2
///    108     4  build_time           seconds, with 48BIT
///    112     8  rootnid_8b           64-bit root nid, with 48BIT
///    120     8  reserved3
/// ```
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned,
)]
#[repr(C, packed)]
pub struct ErofsSuperblock {
    /// The superblock magic, [`EROFS_SUPER_MAGIC_V1`].
    pub magic: [u8; 4],

    /// crc32c of the superblock, valid with SB_CHKSUM.
    pub checksum: [u8; 4],

    /// The `EROFS_FEATURE_COMPAT_*` bits.
    pub feature_compat: [u8; 4],

    /// log2 of the block size.
    pub blkszbits: u8,

    /// Count of 16-byte slots extending the superblock past its base size.
    pub sb_extslots: u8,

    /// The root inode nid.
    pub rootnid_2b: [u8; 2],

    /// The inode count.
    pub inos: [u8; 8],

    /// Build time in seconds, the mtime of every compact inode.
    pub epoch: [u8; 8],

    /// Build time nanoseconds, the mtime nanoseconds of every compact inode.
    pub fixed_nsec: [u8; 4],

    /// The image size in blocks.
    pub blocks_lo: [u8; 4],

    /// The block inode slots are counted from.
    pub meta_blkaddr: [u8; 4],

    /// The block of the shared xattrs.
    pub xattr_blkaddr: [u8; 4],

    /// The image uuid.
    pub uuid: [u8; 16],

    /// The volume name, NUL padded.
    pub volume_name: [u8; 16],

    /// The `EROFS_FEATURE_INCOMPAT_*` bits.
    pub feature_incompat: [u8; 4],

    /// `available_compr_algs` with COMPR_CFGS, else the legacy
    /// `lz4_max_distance`.
    pub compr_or_distance: [u8; 2],

    /// Count of device slots after the superblock.
    pub extra_devices: [u8; 2],

    /// Offset of the first device slot, in 128-byte units.
    pub devt_slotoff: [u8; 2],

    /// log2 of the directory block size, 0 for the block size.
    pub dirblkbits: u8,

    /// Count of long xattr name prefixes.
    pub xattr_prefix_count: u8,

    /// Start of the long xattr name prefixes, in 4-byte units.
    pub xattr_prefix_start: [u8; 4],

    /// The packed inode holding fragments, valid with FRAGMENTS.
    pub packed_nid: [u8; 8],

    /// Reserved for the xattr name filter.
    pub xattr_filter_reserved: u8,

    /// Unused.
    pub reserved2: [u8; 3],

    /// Build time in seconds, valid with 48BIT.
    pub build_time: [u8; 4],

    /// The 64-bit root inode nid, valid with 48BIT.
    pub rootnid_8b: [u8; 8],

    /// Unused.
    pub reserved3: [u8; 8],
}

// Fails the build when the struct no longer matches the on-disk size the
// readers slice by.
const _: () = assert!(mem::size_of::<ErofsSuperblock>() == EROFS_SB_BASE_SIZE);

/// Builds and validates a superblock, and reads its fields.
impl ErofsSuperblock {
    /// Every incompat bit this reader understands. A superblock setting a
    /// bit outside this mask was written by a newer erofs-utils or nydus and
    /// is rejected by [`FeatureFlags::validate_incompat`]. The z_erofs bits
    /// (ZERO_PADDING, BIG_PCLUSTER/COMPR_CFGS, FRAGMENTS) are accepted for
    /// metadata access (`merge` reads z layer bootstraps); data reads reject
    /// the COMPRESSED_FULL layout themselves.
    const SUPPORTED_INCOMPAT: u32 = EROFS_FEATURE_INCOMPAT_CHUNKED_FILE
        | EROFS_FEATURE_INCOMPAT_DEVICE_TABLE
        | EROFS_FEATURE_INCOMPAT_ZERO_PADDING
        | EROFS_FEATURE_INCOMPAT_BIG_PCLUSTER
        | EROFS_FEATURE_INCOMPAT_FRAGMENTS;

    /// Creates a validated superblock for a 4 KiB block image of `blocks`
    /// blocks. `blocks` must fit the 32-bit `blocks_lo` field, and
    /// `feature_incompat` must stay within the features this crate
    /// implements.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        feature_compat: u32,
        feature_incompat: u32,
        root_nid: u16,
        inos: u64,
        epoch: u64,
        blocks: u64,
        meta_blkaddr: u32,
        extra_devices: u16,
        devt_slotoff: u16,
        uuid: &[u8; 16],
    ) -> Result<Self> {
        let blocks = u32::try_from(blocks).map_err(|_| {
            Error::Overflow(format!("EROFS bootstrap block count {blocks} exceeds u32"))
        })?;

        let mut superblock = Self::new_zeroed();
        write_u32(&mut superblock.magic, EROFS_SUPER_MAGIC_V1);
        write_u32(&mut superblock.feature_compat, feature_compat);
        superblock.blkszbits = EROFS_BLKSZBITS;
        write_u16(&mut superblock.rootnid_2b, root_nid);
        write_u64(&mut superblock.inos, inos);
        write_u64(&mut superblock.epoch, epoch);
        write_u32(&mut superblock.blocks_lo, blocks);
        write_u32(&mut superblock.meta_blkaddr, meta_blkaddr);
        superblock.uuid = *uuid;
        write_u32(&mut superblock.feature_incompat, feature_incompat);
        write_u16(&mut superblock.extra_devices, extra_devices);
        write_u16(&mut superblock.devt_slotoff, devt_slotoff);

        superblock.validate()?;
        Ok(superblock)
    }

    /// Validates the magic, the block size and the incompat features.
    /// Unknown incompat bits reject the image, the standard EROFS contract,
    /// since it cannot be read correctly. The single source of truth for
    /// the supported feature set, extended when a new feature bit is
    /// implemented.
    pub fn validate(&self) -> Result<()> {
        if self.magic() != EROFS_SUPER_MAGIC_V1 {
            return Err(Error::InvalidImage(format!(
                "invalid EROFS magic {:#010x}",
                self.magic()
            )));
        }

        // This reader hardcodes 4 KiB blocks (`EROFS_BLOCK_SIZE`); an
        // untrusted `blkszbits` would otherwise feed unchecked
        // `1 << blkszbits` shifts in the block-geometry math.
        if self.blkszbits != EROFS_BLKSZBITS {
            return Err(Error::Unsupported(format!(
                "unsupported EROFS block size bits {}",
                self.blkszbits
            )));
        }

        self.incompat().validate_incompat(Self::SUPPORTED_INCOMPAT)
    }

    /// Views the superblock at the start of `bytes`, which must cover it.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self> {
        Self::ref_from_prefix(bytes)
            .map(|(value, _)| value)
            .map_err(|_| {
                Error::InvalidImage(format!(
                    "EROFS superblock shorter than {EROFS_SB_BASE_SIZE} bytes"
                ))
            })
    }

    /// The superblock's on-disk bytes, the base size without extension
    /// slots.
    pub fn as_bytes(&self) -> &[u8] {
        IntoBytes::as_bytes(self)
    }

    /// Records the available compression algorithm bitmap (bit 0 = LZ4),
    /// valid when the COMPR_CFGS incompat feature is set.
    pub fn set_available_compr_algs(&mut self, algs: u16) {
        write_u16(&mut self.compr_or_distance, algs);
    }

    /// Records the packed inode holding fragment data, valid when the
    /// FRAGMENTS incompat feature is set.
    pub fn set_packed_nid(&mut self, nid: u64) {
        write_u64(&mut self.packed_nid, nid);
    }

    /// The superblock magic.
    pub fn magic(&self) -> u32 {
        read_u32(&self.magic)
    }

    /// The `EROFS_FEATURE_COMPAT_*` bits.
    pub fn feature_compat(&self) -> u32 {
        read_u32(&self.feature_compat)
    }

    /// The `EROFS_FEATURE_INCOMPAT_*` bits.
    pub fn feature_incompat(&self) -> u32 {
        read_u32(&self.feature_incompat)
    }

    /// The `feature_incompat` word as flags to check and query.
    fn incompat(&self) -> FeatureFlags {
        FeatureFlags::from_bits(self.feature_incompat())
    }

    /// The root inode nid.
    pub fn root_nid(&self) -> u64 {
        read_u16(&self.rootnid_2b) as u64
    }

    /// The inode count.
    pub fn inos(&self) -> u64 {
        read_u64(&self.inos)
    }

    /// Build time in seconds, the mtime of every compact inode.
    pub fn epoch(&self) -> u64 {
        read_u64(&self.epoch)
    }

    /// Build time nanoseconds, the mtime nanoseconds of every compact inode.
    pub fn fixed_nsec(&self) -> u32 {
        read_u32(&self.fixed_nsec)
    }

    /// The image size in blocks.
    pub fn blocks(&self) -> u64 {
        read_u32(&self.blocks_lo) as u64
    }

    /// On-disk superblock size, extension slots included; what follows it
    /// (the COMPR_CFGS records) starts this far past `EROFS_SUPER_OFFSET`.
    pub fn size(&self) -> usize {
        EROFS_SB_BASE_SIZE + self.sb_extslots as usize * EROFS_SB_EXTSLOT_SIZE
    }

    /// The block inode slots are counted from.
    pub fn meta_blkaddr(&self) -> u32 {
        read_u32(&self.meta_blkaddr)
    }

    /// Count of device slots after the superblock.
    pub fn extra_devices(&self) -> u16 {
        read_u16(&self.extra_devices)
    }

    /// Offset of the first device slot, in 128-byte units.
    pub fn devt_slotoff(&self) -> u16 {
        read_u16(&self.devt_slotoff)
    }

    /// Available compression algorithm bitmap (bit 0 = LZ4); non-zero only
    /// for z_erofs images declaring COMPR_CFGS.
    pub fn available_compr_algs(&self) -> u16 {
        read_u16(&self.compr_or_distance)
    }

    /// The packed inode holding fragment data, or `None` without FRAGMENTS.
    pub fn packed_nid(&self) -> Option<u64> {
        self.incompat()
            .contains(EROFS_FEATURE_INCOMPAT_FRAGMENTS)
            .then(|| read_u64(&self.packed_nid))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::*;
    use crate::erofs::{
        EROFS_FEATURE_COMPAT_SB_CHKSUM, EROFS_FEATURE_INCOMPAT_48BIT,
        EROFS_FEATURE_INCOMPAT_COMPR_CFGS,
    };

    fn superblock() -> ErofsSuperblock {
        ErofsSuperblock::new(
            EROFS_FEATURE_COMPAT_SB_CHKSUM,
            EROFS_FEATURE_INCOMPAT_CHUNKED_FILE | EROFS_FEATURE_INCOMPAT_DEVICE_TABLE,
            36,
            7,
            1_700_000_000,
            1234,
            1,
            2,
            9,
            &[0xa5; 16],
        )
        .unwrap()
    }

    #[test]
    fn new_encodes_every_field_at_its_offset() {
        let bytes = superblock().as_bytes().to_vec();
        assert_eq!(bytes.len(), EROFS_SB_BASE_SIZE);
        assert_eq!(&bytes[48..64], &[0xa5; 16]);
        assert_eq!(bytes[12], EROFS_BLKSZBITS);

        let test_cases = vec![
            (0, 4, EROFS_SUPER_MAGIC_V1 as u64),
            (4, 4, 0),
            (8, 4, EROFS_FEATURE_COMPAT_SB_CHKSUM as u64),
            (13, 1, 0),
            (14, 2, 36),
            (16, 8, 7),
            (24, 8, 1_700_000_000),
            (32, 4, 0),
            (36, 4, 1234),
            (40, 4, 1),
            (44, 4, 0),
            (
                80,
                4,
                (EROFS_FEATURE_INCOMPAT_CHUNKED_FILE | EROFS_FEATURE_INCOMPAT_DEVICE_TABLE) as u64,
            ),
            (84, 2, 0),
            (86, 2, 2),
            (88, 2, 9),
            (96, 8, 0),
        ];

        for (offset, size, expected) in test_cases {
            let mut field = [0u8; 8];
            field[..size].copy_from_slice(&bytes[offset..offset + size]);
            assert_eq!(u64::from_le_bytes(field), expected, "{offset}");
        }
    }

    #[test]
    fn getters_return_the_fields() {
        let mut superblock = superblock();
        assert_eq!(superblock.magic(), EROFS_SUPER_MAGIC_V1);
        assert_eq!(superblock.feature_compat(), EROFS_FEATURE_COMPAT_SB_CHKSUM);
        assert_eq!(
            superblock.feature_incompat(),
            EROFS_FEATURE_INCOMPAT_CHUNKED_FILE | EROFS_FEATURE_INCOMPAT_DEVICE_TABLE
        );
        assert_eq!(superblock.root_nid(), 36);
        assert_eq!(superblock.inos(), 7);
        assert_eq!(superblock.epoch(), 1_700_000_000);
        assert_eq!(superblock.fixed_nsec(), 0);
        assert_eq!(superblock.blocks(), 1234);
        assert_eq!(superblock.size(), EROFS_SB_BASE_SIZE);
        assert_eq!(superblock.meta_blkaddr(), 1);
        assert_eq!(superblock.extra_devices(), 2);
        assert_eq!(superblock.devt_slotoff(), 9);
        assert_eq!(superblock.available_compr_algs(), 0);
        assert_eq!(superblock.packed_nid(), None);

        superblock.sb_extslots = 2;
        superblock.set_available_compr_algs(0b1001);
        superblock.set_packed_nid(77);
        write_u32(
            &mut superblock.feature_incompat,
            EROFS_FEATURE_INCOMPAT_COMPR_CFGS | EROFS_FEATURE_INCOMPAT_FRAGMENTS,
        );
        assert_eq!(
            superblock.size(),
            EROFS_SB_BASE_SIZE + 2 * EROFS_SB_EXTSLOT_SIZE
        );
        assert_eq!(superblock.available_compr_algs(), 0b1001);
        assert_eq!(superblock.packed_nid(), Some(77));
    }

    #[test]
    fn tail_fields_sit_at_the_standard_offsets() {
        let mut superblock = superblock();
        assert_eq!(&superblock.as_bytes()[0x68..0x80], &[0; 24]);

        superblock.build_time = 0x1234_5678u32.to_le_bytes();
        superblock.rootnid_8b = 0x90ab_cdef_1234_5678u64.to_le_bytes();
        superblock.reserved3 = [0xa5; 8];

        assert_eq!(
            &superblock.as_bytes()[0x6c..0x70],
            &0x1234_5678u32.to_le_bytes()
        );
        assert_eq!(
            &superblock.as_bytes()[0x70..0x78],
            &0x90ab_cdef_1234_5678u64.to_le_bytes()
        );
        assert_eq!(&superblock.as_bytes()[0x78..0x80], &[0xa5; 8]);
    }

    #[test]
    fn new_accepts_block_counts_up_to_u32_max() {
        let test_cases = vec![
            (0, Ok(0)),
            (u32::MAX as u64 - 1, Ok(u32::MAX as u64 - 1)),
            (u32::MAX as u64, Ok(u32::MAX as u64)),
            (
                1u64 << 32,
                Err("EROFS bootstrap block count 4294967296 exceeds u32"),
            ),
            (
                u64::MAX,
                Err("EROFS bootstrap block count 18446744073709551615 exceeds u32"),
            ),
        ];

        for (blocks, expected) in test_cases {
            assert_eq!(
                ErofsSuperblock::new(0, 0, 0, 0, 0, blocks, 1, 0, 0, &[0; 16])
                    .map(|superblock| superblock.blocks())
                    .map_err(|err| err.to_string()),
                expected.map_err(String::from)
            );
        }
    }

    #[test]
    fn validate_rejects_a_bad_magic_block_size_or_unknown_incompat_feature() {
        let test_cases: Vec<(fn(&mut ErofsSuperblock), std::result::Result<(), &str>)> = vec![
            (|_| {}, Ok(())),
            (
                |superblock| {
                    write_u32(
                        &mut superblock.feature_incompat,
                        ErofsSuperblock::SUPPORTED_INCOMPAT,
                    )
                },
                Ok(()),
            ),
            (
                |superblock| write_u32(&mut superblock.feature_compat, 0xffff_ffff),
                Ok(()),
            ),
            (
                |superblock| write_u32(&mut superblock.magic, 0xdead_beef),
                Err("invalid EROFS magic 0xdeadbeef"),
            ),
            (
                |superblock| superblock.blkszbits = 9,
                Err("unsupported EROFS block size bits 9"),
            ),
            (
                |superblock| {
                    write_u32(
                        &mut superblock.feature_incompat,
                        EROFS_FEATURE_INCOMPAT_48BIT,
                    )
                },
                Err("unsupported incompat flags 0x80 (image is newer than this reader)"),
            ),
            (
                |superblock| {
                    write_u32(
                        &mut superblock.feature_incompat,
                        EROFS_FEATURE_INCOMPAT_CHUNKED_FILE | 0x8000_0000,
                    )
                },
                Err("unsupported incompat flags 0x80000000 (image is newer than this reader)"),
            ),
        ];

        for (corrupt, expected) in test_cases {
            let mut superblock = superblock();
            corrupt(&mut superblock);
            assert_eq!(
                superblock.validate().map_err(|err| err.to_string()),
                expected.map_err(String::from)
            );
        }
    }

    #[test]
    fn new_rejects_unknown_incompat_features() {
        assert_eq!(
            ErofsSuperblock::new(
                0,
                EROFS_FEATURE_INCOMPAT_48BIT,
                0,
                0,
                0,
                1,
                1,
                0,
                0,
                &[0; 16]
            )
            .unwrap_err()
            .to_string(),
            "unsupported incompat flags 0x80 (image is newer than this reader)"
        );
    }
}
