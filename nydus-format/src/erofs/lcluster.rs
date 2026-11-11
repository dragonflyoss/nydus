//! The full lcluster index of a z_erofs compressed inode.

use crate::erofs::{
    EROFS_BLOCK_SIZE, Z_EROFS_LCLUSTER_INDEX_SIZE, Z_EROFS_LCLUSTER_TYPE_NONHEAD,
    Z_EROFS_LI_LCLUSTER_TYPE_MASK,
};
use crate::error::{Error, Result};
use crate::utils::bytes::{read_u16, read_u16_at, read_u32, write_u16, write_u16_at, write_u32};
use std::mem;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned};

/// One full lcluster index of a compressed inode, `z_erofs_lcluster_index`,
/// 8 bytes: one per lcluster of the file, behind the map header.
///
/// A HEAD or PLAIN index starts an extent `di_clusterofs` bytes into its
/// lcluster and holds the block address of the extent's pcluster. A NONHEAD
/// index continues the extent of a preceding head and holds the distances
/// to that head and to the next one instead.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned,
)]
#[repr(C, packed)]
pub struct ZErofsLclusterIndex {
    /// The lcluster type in the low two bits, one of the
    /// `Z_EROFS_LCLUSTER_TYPE_*`.
    pub di_advise: [u8; 2],

    /// Byte offset into the lcluster where the extent of a HEAD or PLAIN
    /// index starts.
    pub di_clusterofs: [u8; 2],

    /// Type dependent: the block address of a HEAD or PLAIN index, or the
    /// `delta[0]` and `delta[1]` distances of a NONHEAD one.
    pub di_u: [u8; 4],
}

// Fails the build when the struct no longer matches the on-disk size the
// readers slice by.
const _: () = assert!(mem::size_of::<ZErofsLclusterIndex>() == Z_EROFS_LCLUSTER_INDEX_SIZE);

/// Builds an lcluster index, reads its fields and tells which indexes
/// address data.
impl ZErofsLclusterIndex {
    /// Creates a HEAD or PLAIN index of `lcluster_type`, one of the
    /// `Z_EROFS_LCLUSTER_TYPE_*`, whose extent starts `clusterofs` bytes
    /// into the lcluster and lives in the pcluster at `blkaddr`.
    pub fn new(lcluster_type: u16, clusterofs: u16, blkaddr: u32) -> Self {
        let mut index = Self::new_zeroed();
        write_u16(&mut index.di_advise, lcluster_type);
        write_u16(&mut index.di_clusterofs, clusterofs);
        write_u32(&mut index.di_u, blkaddr);
        index
    }

    /// Creates a NONHEAD index `delta[0]` lclusters behind its head and
    /// `delta[1]` lclusters ahead of the next HEAD or PLAIN index.
    pub fn new_nonhead(delta: [u16; 2]) -> Self {
        let mut index = Self::new_zeroed();
        write_u16(&mut index.di_advise, Z_EROFS_LCLUSTER_TYPE_NONHEAD);
        write_u16_at(&mut index.di_u, 0, delta[0]);
        write_u16_at(&mut index.di_u, 2, delta[1]);
        index
    }

    /// Views the lcluster index at the start of `bytes`, which must cover it.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self> {
        Self::ref_from_prefix(bytes)
            .map(|(value, _)| value)
            .map_err(|_| {
                Error::InvalidImage(format!(
                    "EROFS lcluster index shorter than {Z_EROFS_LCLUSTER_INDEX_SIZE} bytes"
                ))
            })
    }

    /// The index's on-disk bytes.
    pub fn as_bytes(&self) -> &[u8] {
        IntoBytes::as_bytes(self)
    }

    /// The lcluster type, one of the `Z_EROFS_LCLUSTER_TYPE_*`.
    pub fn lcluster_type(&self) -> u16 {
        read_u16(&self.di_advise) & Z_EROFS_LI_LCLUSTER_TYPE_MASK
    }

    /// Byte offset into the lcluster where the extent of a HEAD or PLAIN
    /// index starts.
    pub fn clusterofs(&self) -> u16 {
        read_u16(&self.di_clusterofs)
    }

    /// The block address of a HEAD or PLAIN index.
    pub fn blkaddr(&self) -> u32 {
        read_u32(&self.di_u)
    }

    /// The `delta[0]` and `delta[1]` of a NONHEAD index: the distance to
    /// its head and to the next HEAD or PLAIN index, in lclusters. With
    /// `Z_EROFS_LI_D0_CBLKCNT` set, `delta[0]` holds the pcluster's block
    /// count instead.
    pub fn delta(&self) -> [u16; 2] {
        [read_u16_at(&self.di_u, 0), read_u16_at(&self.di_u, 2)]
    }

    /// File offset where the extent starts, for the HEAD or PLAIN index of
    /// lcluster `lcn`.
    pub fn extent_start(&self, lcn: usize) -> u64 {
        lcn as u64 * u64::from(EROFS_BLOCK_SIZE) + u64::from(self.clusterofs())
    }

    /// Whether the index of lcluster `lcn` addresses data in a file of
    /// `file_size` bytes.
    ///
    /// A NONHEAD index does not, and neither does the EOF index: the PLAIN
    /// index at the EOF offset, with block address 0, that closes a
    /// compressed last pcluster ending inside an lcluster, what erofs-utils'
    /// `z_erofs_write_indexes_final` writes.
    pub fn addresses_data(&self, lcn: usize, file_size: u64) -> bool {
        self.lcluster_type() != Z_EROFS_LCLUSTER_TYPE_NONHEAD && self.extent_start(lcn) < file_size
    }

    /// The last lcluster of the back to back `indexes` whose index
    /// addresses data in a file of `file_size` bytes, see
    /// [`Self::addresses_data`]. In a tail-fragment inode that index holds
    /// the high half of the fragment offset.
    pub fn last_data(indexes: &[u8], file_size: u64) -> Option<usize> {
        indexes
            .chunks_exact(Z_EROFS_LCLUSTER_INDEX_SIZE)
            .enumerate()
            .rev()
            .find(|(lcn, index)| {
                Self::from_bytes(index).is_ok_and(|index| index.addresses_data(*lcn, file_size))
            })
            .map(|(lcn, _)| lcn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::erofs::{
        Z_EROFS_LCLUSTER_TYPE_HEAD1, Z_EROFS_LCLUSTER_TYPE_PLAIN, Z_EROFS_LI_D0_CBLKCNT,
    };

    const FILE_SIZE: u64 = 2 * EROFS_BLOCK_SIZE as u64 + 5;

    const HEAD: ZErofsLclusterIndex = ZErofsLclusterIndex {
        di_advise: [1, 0],
        di_clusterofs: [0, 0],
        di_u: [100, 0, 0, 0],
    };

    const NONHEAD: ZErofsLclusterIndex = ZErofsLclusterIndex {
        di_advise: [2, 0],
        di_clusterofs: [0, 0],
        di_u: [1, 8, 1, 0],
    };

    const PLAIN: ZErofsLclusterIndex = ZErofsLclusterIndex {
        di_advise: [0, 0],
        di_clusterofs: [0, 0],
        di_u: [102, 0, 0, 0],
    };

    const EOF: ZErofsLclusterIndex = ZErofsLclusterIndex {
        di_advise: [0, 0],
        di_clusterofs: [5, 0],
        di_u: [0, 0, 0, 0],
    };

    #[test]
    fn new_encodes_the_fields_little_endian() {
        let test_cases = vec![
            (Z_EROFS_LCLUSTER_TYPE_PLAIN, 0, 0, [0u8; 8]),
            (
                Z_EROFS_LCLUSTER_TYPE_HEAD1,
                0x0102,
                0x0304_0506,
                [1, 0, 2, 1, 6, 5, 4, 3],
            ),
            (
                Z_EROFS_LCLUSTER_TYPE_PLAIN,
                u16::MAX,
                u32::MAX,
                [0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];

        for (lcluster_type, clusterofs, blkaddr, expected) in test_cases {
            let index = ZErofsLclusterIndex::new(lcluster_type, clusterofs, blkaddr);
            assert_eq!(index.as_bytes(), &expected);

            let parsed = ZErofsLclusterIndex::from_bytes(&expected).unwrap();
            assert_eq!(parsed.lcluster_type(), lcluster_type);
            assert_eq!(parsed.clusterofs(), clusterofs);
            assert_eq!(parsed.blkaddr(), blkaddr);
        }
    }

    #[test]
    fn new_nonhead_encodes_the_deltas_little_endian() {
        let test_cases = vec![
            ([1, 1], [2, 0, 0, 0, 1, 0, 1, 0]),
            (
                [Z_EROFS_LI_D0_CBLKCNT | 2, 0x0304],
                [2, 0, 0, 0, 2, 8, 4, 3],
            ),
            ([u16::MAX, 0], [2, 0, 0, 0, 0xff, 0xff, 0, 0]),
        ];

        for (delta, expected) in test_cases {
            let index = ZErofsLclusterIndex::new_nonhead(delta);
            assert_eq!(index.as_bytes(), &expected);

            let parsed = ZErofsLclusterIndex::from_bytes(&expected).unwrap();
            assert_eq!(parsed.lcluster_type(), Z_EROFS_LCLUSTER_TYPE_NONHEAD);
            assert_eq!(parsed.clusterofs(), 0);
            assert_eq!(parsed.delta(), delta);
        }
    }

    #[test]
    fn from_bytes_rejects_a_short_index() {
        let test_cases = vec![Vec::new(), vec![0; Z_EROFS_LCLUSTER_INDEX_SIZE - 1]];

        for bytes in test_cases {
            assert_eq!(
                ZErofsLclusterIndex::from_bytes(&bytes)
                    .unwrap_err()
                    .to_string(),
                "EROFS lcluster index shorter than 8 bytes"
            );
        }
    }

    #[test]
    fn lcluster_type_ignores_the_other_advise_bits() {
        let mut index = HEAD;
        index.di_advise = [0xfd, 0xff];
        assert_eq!(index.lcluster_type(), Z_EROFS_LCLUSTER_TYPE_HEAD1);
    }

    #[test]
    fn addresses_data_excludes_nonhead_and_eof_indexes() {
        let block = u64::from(EROFS_BLOCK_SIZE);
        let test_cases = vec![
            (HEAD, 0, 0, true),
            (NONHEAD, 1, block, false),
            (PLAIN, 2, 2 * block, true),
            (EOF, 2, FILE_SIZE, false),
            (EOF, 1, block + 5, true),
        ];

        for (index, lcn, extent_start, expected) in test_cases {
            assert_eq!(index.extent_start(lcn), extent_start);
            assert_eq!(index.addresses_data(lcn, FILE_SIZE), expected);
        }
    }

    #[test]
    fn last_data_skips_nonhead_and_eof_indexes() {
        let test_cases = vec![
            (vec![], None),
            (vec![NONHEAD], None),
            (vec![HEAD, NONHEAD, EOF], Some(0)),
            (vec![HEAD, NONHEAD, PLAIN], Some(2)),
            (vec![HEAD, PLAIN, NONHEAD], Some(1)),
        ];

        for (indexes, expected) in test_cases {
            let bytes: Vec<u8> = indexes
                .iter()
                .flat_map(|index| index.as_bytes())
                .copied()
                .collect();
            assert_eq!(ZErofsLclusterIndex::last_data(&bytes, FILE_SIZE), expected);
        }
    }
}
