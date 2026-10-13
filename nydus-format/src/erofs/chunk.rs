//! The chunk index of a chunk-based inode and the device slot it points
//! into.

use crate::erofs::{
    EROFS_BLOB_ID_SIZE, EROFS_CHUNK_INDEX_SIZE, EROFS_DEVICESLOT_SIZE, EROFS_NULL_ADDR,
};
use crate::error::{Error, Result};
use crate::utils::bytes::{read_u16, read_u32, write_u16, write_u32};
use hex::FromHex;
use std::mem;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned};

/// One chunk of a chunk-based inode, `erofs_inode_chunk_index`, 8 bytes:
/// the block address of the chunk on a device.
///
/// Only the 32-bit low halves are written and read, the `*_hi` halves
/// belong to the 48BIT feature this crate does not declare.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned,
)]
#[repr(C, packed)]
pub struct ErofsChunkIndex {
    /// High 16 bits of the block address, valid with 48BIT.
    pub startblk_hi: [u8; 2],

    /// The device the chunk lives on, 0 for the image itself.
    pub device_id: [u8; 2],

    /// Low 32 bits of the block address, all ones for a hole.
    pub startblk_lo: [u8; 4],
}

// Fails the build when the struct no longer matches the on-disk size the
// readers slice by.
const _: () = assert!(mem::size_of::<ErofsChunkIndex>() == EROFS_CHUNK_INDEX_SIZE);

/// Builds a chunk index and reads its fields.
impl ErofsChunkIndex {
    /// [`EROFS_NULL_ADDR`] as the 32-bit `startblk_lo` stores it, all ones.
    const NULL_ADDR: u32 = u32::MAX;

    /// Encodes `addr`, what erofs-utils' `erofs_write_chunk_indexes` does
    /// for one chunk. The address is checked first, see [`ErofsChunkAddr`].
    pub fn new(addr: ErofsChunkAddr) -> Result<Self> {
        addr.validate()?;

        let mut index = Self::new_zeroed();
        if addr.is_hole() {
            write_u32(&mut index.startblk_lo, Self::NULL_ADDR);
        } else {
            write_u16(&mut index.device_id, addr.device_id);
            write_u32(&mut index.startblk_lo, addr.blkaddr as u32);
        }

        Ok(index)
    }

    /// Views the chunk index at the start of `bytes`, which must cover it.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self> {
        Self::ref_from_prefix(bytes)
            .map(|(value, _)| value)
            .map_err(|_| {
                Error::InvalidImage(format!(
                    "EROFS chunk index shorter than {EROFS_CHUNK_INDEX_SIZE} bytes"
                ))
            })
    }

    /// The index's on-disk bytes.
    pub fn as_bytes(&self) -> &[u8] {
        IntoBytes::as_bytes(self)
    }

    /// Decodes the index, what the kernel's `erofs_map_chunks` does for one
    /// entry.
    pub fn addr(&self) -> ErofsChunkAddr {
        ErofsChunkAddr {
            blkaddr: self.blkaddr(),
            device_id: self.device_id(),
        }
    }

    /// The chunk's block address, [`EROFS_NULL_ADDR`] for a hole.
    pub fn blkaddr(&self) -> u64 {
        match read_u32(&self.startblk_lo) {
            Self::NULL_ADDR => EROFS_NULL_ADDR,
            blkaddr => u64::from(blkaddr),
        }
    }

    /// The device the chunk lives on.
    pub fn device_id(&self) -> u16 {
        read_u16(&self.device_id)
    }
}

/// The decoded form of an [`ErofsChunkIndex`], the address of one chunk:
/// erofs-utils' `erofs_chunkitem` as far as the on-disk index is concerned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErofsChunkAddr {
    /// The chunk's block address, [`EROFS_NULL_ADDR`] for a hole.
    pub blkaddr: u64,

    /// The device the chunk lives on, 0 for the image itself.
    pub device_id: u16,
}

/// Checks an address before it is encoded.
impl ErofsChunkAddr {
    /// Whether the address is a hole.
    pub fn is_hole(&self) -> bool {
        self.blkaddr == EROFS_NULL_ADDR
    }

    /// Validates that a real address fits the 32-bit `startblk_lo` below
    /// the hole marker, which [`ErofsChunkIndex::blkaddr`] would read back
    /// as a hole.
    fn validate(&self) -> Result<()> {
        if !self.is_hole() && self.blkaddr >= u64::from(ErofsChunkIndex::NULL_ADDR) {
            return Err(Error::Overflow(format!(
                "EROFS chunk address {} exceeds maximum data address {}",
                self.blkaddr,
                ErofsChunkIndex::NULL_ADDR - 1
            )));
        }

        Ok(())
    }
}

/// One entry of the device table, `erofs_deviceslot`, 128 bytes: a blob the
/// chunk indexes address by `device_id`.
///
/// Only the 32-bit low halves are written and read, the `*_hi` halves
/// belong to the 48BIT feature this crate does not declare.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned,
)]
#[repr(C, packed)]
pub struct ErofsDeviceSlot {
    /// The blob id as a 64-character lowercase SHA-256 hex string, which
    /// fills the field exactly, matching nydus RAFS v6.
    pub tag: [u8; 64],

    /// Low 32 bits of the device size in blocks.
    pub blocks_lo: [u8; 4],

    /// Low 32 bits of the device's first block in the unified address
    /// space.
    pub uniaddr_lo: [u8; 4],

    /// High 16 bits of the device size, valid with 48BIT.
    pub blocks_hi: [u8; 2],

    /// High 16 bits of the unified address, valid with 48BIT.
    pub uniaddr_hi: [u8; 2],

    /// Unused.
    pub reserved: [u8; 52],
}

// Fails the build when the struct no longer matches the on-disk size the
// readers slice by.
const _: () = assert!(mem::size_of::<ErofsDeviceSlot>() == EROFS_DEVICESLOT_SIZE);

/// Builds a device slot and reads its fields.
impl ErofsDeviceSlot {
    /// Creates a slot for a device of `blocks` blocks without a blob id or
    /// mapped address. `blocks` must fit the 32-bit `blocks_lo` field.
    pub fn new(blocks: u64) -> Result<Self> {
        let blocks = u32::try_from(blocks).map_err(|_| {
            Error::Overflow(format!("EROFS device block count {blocks} exceeds u32"))
        })?;

        let mut slot = Self::new_zeroed();
        write_u32(&mut slot.blocks_lo, blocks);
        Ok(slot)
    }

    /// Creates a slot for a device of `blocks` blocks tagged with `blob_id`.
    pub fn with_blob_id(blocks: u64, blob_id: &[u8; EROFS_BLOB_ID_SIZE]) -> Result<Self> {
        let mut slot = Self::new(blocks)?;
        slot.set_blob_id(blob_id);
        Ok(slot)
    }

    /// Creates a slot for a device of `blocks` blocks tagged with `blob_id`
    /// and starting at `mapped_blkaddr` of the unified address space.
    pub fn with_blob_id_and_mapped_blkaddr(
        blocks: u64,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
        mapped_blkaddr: u64,
    ) -> Result<Self> {
        let mut slot = Self::with_blob_id(blocks, blob_id)?;
        slot.set_mapped_blkaddr(mapped_blkaddr)?;
        Ok(slot)
    }

    /// Views the device slot at the start of `bytes`, which must cover it.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self> {
        Self::ref_from_prefix(bytes)
            .map(|(value, _)| value)
            .map_err(|_| {
                Error::InvalidImage(format!(
                    "EROFS device slot shorter than {EROFS_DEVICESLOT_SIZE} bytes"
                ))
            })
    }

    /// The slot's on-disk bytes.
    pub fn as_bytes(&self) -> &[u8] {
        IntoBytes::as_bytes(self)
    }

    /// The device size in blocks.
    pub fn blocks(&self) -> u64 {
        read_u32(&self.blocks_lo) as u64
    }

    /// The device's first block in the unified address space.
    pub fn mapped_blkaddr(&self) -> u64 {
        read_u32(&self.uniaddr_lo) as u64
    }

    /// Records the device's first block in the unified address space, which
    /// must fit the 32-bit `uniaddr_lo` field.
    pub fn set_mapped_blkaddr(&mut self, mapped_blkaddr: u64) -> Result<()> {
        let mapped_blkaddr = u32::try_from(mapped_blkaddr).map_err(|_| {
            Error::Overflow(format!(
                "EROFS mapped block address {mapped_blkaddr} exceeds u32"
            ))
        })?;

        write_u32(&mut self.uniaddr_lo, mapped_blkaddr);
        self.uniaddr_hi = [0; 2];
        Ok(())
    }

    /// Records `blob_id` as the tag, a lowercase SHA-256 hex string.
    pub fn set_blob_id(&mut self, blob_id: &[u8; EROFS_BLOB_ID_SIZE]) {
        self.tag.copy_from_slice(hex::encode(blob_id).as_bytes());
    }

    /// Decodes the tag into a blob id. Anything but a SHA-256 hex string is
    /// a corrupt or foreign device slot and is rejected rather than
    /// reinterpreted as raw digest bytes.
    pub fn blob_id(&self) -> Result<[u8; EROFS_BLOB_ID_SIZE]> {
        <[u8; EROFS_BLOB_ID_SIZE]>::from_hex(self.tag).map_err(|_| {
            Error::InvalidImage("device slot tag is not a sha256 hex blob id".to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOB_ID: [u8; EROFS_BLOB_ID_SIZE] = [0xab; EROFS_BLOB_ID_SIZE];

    #[test]
    fn chunk_index_new_encodes_addresses_and_holes() {
        let test_cases = vec![
            (0, 3, Ok([0, 0, 3, 0, 0, 0, 0, 0])),
            (
                u32::MAX as u64 - 1,
                0x0102,
                Ok([0, 0, 2, 1, 0xfe, 0xff, 0xff, 0xff]),
            ),
            (EROFS_NULL_ADDR, 3, Ok([0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff])),
            (
                u32::MAX as u64,
                1,
                Err("EROFS chunk address 4294967295 exceeds maximum data address 4294967294"),
            ),
            (
                1u64 << 32,
                1,
                Err("EROFS chunk address 4294967296 exceeds maximum data address 4294967294"),
            ),
        ];

        for (blkaddr, device_id, expected) in test_cases {
            let addr = ErofsChunkAddr { blkaddr, device_id };
            let index = ErofsChunkIndex::new(addr);
            assert_eq!(
                index
                    .as_ref()
                    .map(|index| index.as_bytes().to_vec())
                    .map_err(|err| err.to_string()),
                expected.map(|bytes| bytes.to_vec()).map_err(String::from)
            );
            if let Ok(index) = index {
                let device_id = if addr.is_hole() { 0 } else { device_id };
                assert_eq!(index.addr(), ErofsChunkAddr { blkaddr, device_id });
            }
        }
    }

    #[test]
    fn chunk_index_blkaddr_ignores_the_high_half() {
        let mut index = ErofsChunkIndex::new(ErofsChunkAddr {
            blkaddr: 7,
            device_id: 3,
        })
        .unwrap();
        index.startblk_hi = [0xff; 2];
        assert_eq!(index.blkaddr(), 7);
    }

    #[test]
    fn device_slot_new_encodes_the_blocks_blob_id_and_mapped_address() {
        let test_cases = vec![
            (0, 0, Ok(())),
            (u32::MAX as u64 - 1, 1, Ok(())),
            (u32::MAX as u64, u32::MAX as u64, Ok(())),
            (
                1u64 << 32,
                0,
                Err("EROFS device block count 4294967296 exceeds u32"),
            ),
            (
                u64::MAX,
                0,
                Err("EROFS device block count 18446744073709551615 exceeds u32"),
            ),
            (
                1,
                1u64 << 32,
                Err("EROFS mapped block address 4294967296 exceeds u32"),
            ),
        ];

        for (blocks, mapped_blkaddr, expected) in test_cases {
            let slot =
                ErofsDeviceSlot::with_blob_id_and_mapped_blkaddr(blocks, &BLOB_ID, mapped_blkaddr);
            assert_eq!(
                slot.as_ref().map(drop).map_err(|err| err.to_string()),
                expected.map_err(String::from)
            );
            if let Ok(slot) = slot {
                assert_eq!(&slot.as_bytes()[..64], hex::encode(BLOB_ID).as_bytes());
                assert_eq!(slot.blocks(), blocks);
                assert_eq!(slot.mapped_blkaddr(), mapped_blkaddr);
                assert_eq!(slot.blob_id().unwrap(), BLOB_ID);
                assert_eq!(&slot.as_bytes()[72..], &[0; 56]);
            }
        }
    }

    #[test]
    fn device_slot_set_mapped_blkaddr_leaves_the_slot_unchanged_on_error() {
        let mut slot = ErofsDeviceSlot::with_blob_id_and_mapped_blkaddr(5, &BLOB_ID, 9).unwrap();
        let before = slot.as_bytes().to_vec();

        assert!(slot.set_mapped_blkaddr(1u64 << 32).is_err());
        assert_eq!(slot.as_bytes(), before);
    }

    #[test]
    fn device_slot_getters_ignore_the_high_halves() {
        let mut slot = ErofsDeviceSlot::with_blob_id_and_mapped_blkaddr(5, &BLOB_ID, 9).unwrap();
        slot.blocks_hi = [0xff; 2];
        slot.uniaddr_hi = [0xff; 2];

        assert_eq!(slot.blocks(), 5);
        assert_eq!(slot.mapped_blkaddr(), 9);
    }

    #[test]
    fn device_slot_blob_id_rejects_a_tag_that_is_not_a_sha256_hex_string() {
        let mut uppercase = ErofsDeviceSlot::with_blob_id(1, &BLOB_ID).unwrap();
        uppercase.tag.make_ascii_uppercase();
        let mut truncated = ErofsDeviceSlot::with_blob_id(1, &BLOB_ID).unwrap();
        truncated.tag[63] = 0;
        let mut raw = ErofsDeviceSlot::new(1).unwrap();
        raw.tag[..EROFS_BLOB_ID_SIZE].copy_from_slice(&BLOB_ID);

        let test_cases = vec![
            (uppercase, Ok(BLOB_ID)),
            (
                truncated,
                Err("device slot tag is not a sha256 hex blob id"),
            ),
            (raw, Err("device slot tag is not a sha256 hex blob id")),
            (
                ErofsDeviceSlot::new(1).unwrap(),
                Err("device slot tag is not a sha256 hex blob id"),
            ),
        ];

        for (slot, expected) in test_cases {
            assert_eq!(
                slot.blob_id().map_err(|err| err.to_string()),
                expected.map_err(String::from)
            );
        }
    }
}
