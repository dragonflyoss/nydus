use std::mem;

use super::*;
use crate::error::{Context, Error, Result};
use crate::utils::digest::{hex_string, parse_sha256_hex};
use crate::utils::le::{read_u16, read_u32, write_u16, write_u32};

/// EROFS chunk index entry — 8 bytes, `#[repr(C, packed)]`.
#[repr(C, packed)]
pub struct ErofsChunkIndex {
    pub startblk_hi: [u8; 2],
    pub device_id: [u8; 2],
    pub startblk_lo: [u8; 4],
}

const EROFS_CHUNK_NULL_ADDR: u32 = u32::MAX;

const _: () = assert!(mem::size_of::<ErofsChunkIndex>() == EROFS_CHUNK_INDEX_SIZE);

impl ErofsChunkIndex {
    pub fn new(blkaddr: u64, device_id: u16) -> Result<Self> {
        let mut entry: Self = unsafe { mem::zeroed() };
        if blkaddr == EROFS_NULL_ADDR {
            write_u32(&mut entry.startblk_lo, EROFS_CHUNK_NULL_ADDR);
        } else {
            if blkaddr >= EROFS_CHUNK_NULL_ADDR as u64 {
                return Err(Error::InvalidImage(format!(
                    "EROFS chunk address {blkaddr} exceeds maximum data address {}",
                    EROFS_CHUNK_NULL_ADDR - 1
                )));
            }
            write_u16(&mut entry.device_id, device_id);
            write_u32(&mut entry.startblk_lo, blkaddr as u32);
        }
        Ok(entry)
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, EROFS_CHUNK_INDEX_SIZE) }
    }

    pub fn blkaddr(&self) -> u64 {
        let addr = read_u32(&self.startblk_lo);
        if addr == EROFS_CHUNK_NULL_ADDR {
            EROFS_NULL_ADDR
        } else {
            addr as u64
        }
    }

    pub fn device_id(&self) -> u16 {
        read_u16(&self.device_id)
    }
}

/// Information about a single chunk index stored in an inode.
#[derive(Clone)]
pub struct ErofsChunkAddr {
    pub blkaddr: u64,
    pub device_id: u16,
}

/// EROFS device slot entry — 128 bytes, `#[repr(C, packed)]`.
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct ErofsDeviceSlot {
    pub tag: [u8; 64],
    pub blocks_lo: [u8; 4],
    pub uniaddr_lo: [u8; 4],
    pub blocks_hi: [u8; 2],
    pub uniaddr_hi: [u8; 2],
    pub _reserved: [u8; 52],
}

const _: () = assert!(mem::size_of::<ErofsDeviceSlot>() == EROFS_DEVICESLOT_SIZE);

impl ErofsDeviceSlot {
    pub fn new(blocks: u64) -> Result<Self> {
        let blocks = u32::try_from(blocks).map_err(|_| {
            Error::InvalidImage(format!(
                "EROFS device block count {blocks} exceeds 32-bit limit"
            ))
        })?;
        let mut slot: Self = unsafe { mem::zeroed() };
        write_u32(&mut slot.blocks_lo, blocks);
        Ok(slot)
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, EROFS_DEVICESLOT_SIZE) }
    }

    pub fn with_blob_id(blocks: u64, blob_id: &[u8; EROFS_BLOB_ID_SIZE]) -> Result<Self> {
        let mut slot = Self::new(blocks)?;
        slot.set_blob_id(blob_id);
        Ok(slot)
    }

    pub fn with_blob_id_and_mapped_blkaddr(
        blocks: u64,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
        mapped_blkaddr: u64,
    ) -> Result<Self> {
        let mut slot = Self::with_blob_id(blocks, blob_id)?;
        slot.set_mapped_blkaddr(mapped_blkaddr)?;
        Ok(slot)
    }

    pub fn blocks(&self) -> u64 {
        read_u32(&self.blocks_lo) as u64
    }

    pub fn mapped_blkaddr(&self) -> u64 {
        read_u32(&self.uniaddr_lo) as u64
    }

    pub fn set_mapped_blkaddr(&mut self, mapped_blkaddr: u64) -> Result<()> {
        let mapped_blkaddr = u32::try_from(mapped_blkaddr).map_err(|_| {
            Error::InvalidImage(format!(
                "EROFS mapped block address {mapped_blkaddr} exceeds 32-bit limit"
            ))
        })?;
        write_u32(&mut self.uniaddr_lo, mapped_blkaddr);
        self.uniaddr_hi = [0; 2];
        Ok(())
    }

    pub fn set_blob_id(&mut self, blob_id: &[u8; EROFS_BLOB_ID_SIZE]) {
        // Store the blob id as a lowercase sha256 hex string, matching nydus
        // RAFS v6 (`RafsV6Device`). A 32-byte digest encodes to 64 hex
        // characters, which fills the entire 64-byte tag field.
        let hex = hex_string(blob_id);
        let bytes = hex.as_bytes();
        self.tag[..bytes.len()].copy_from_slice(bytes);
        self.tag[bytes.len()..].fill(0);
    }

    pub fn blob_id(&self) -> Result<[u8; EROFS_BLOB_ID_SIZE]> {
        // The tag stores the blob id as a 64-character lowercase sha256 hex
        // string (nydus RAFS v6 compatible). Anything else is a corrupt or
        // foreign device slot and must be rejected rather than silently
        // reinterpreted as raw digest bytes.
        let text = std::str::from_utf8(&self.tag).map_err(|_| {
            Error::InvalidImage("device slot tag is not a sha256 hex blob id".to_string())
        })?;
        parse_sha256_hex(text).context("device slot tag is not a sha256 hex blob id")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_slot_checks_32bit_block_fields() {
        let blob_id = [0xAB; EROFS_BLOB_ID_SIZE];
        for blocks in [0, u32::MAX as u64 - 1, u32::MAX as u64] {
            let mut slot =
                ErofsDeviceSlot::with_blob_id_and_mapped_blkaddr(blocks, &blob_id, u32::MAX as u64)
                    .unwrap();
            assert_eq!(slot.blob_id().unwrap(), blob_id);
            assert_eq!(slot.blocks(), blocks);
            assert_eq!(slot.mapped_blkaddr(), u32::MAX as u64);
            assert_eq!(&slot.as_bytes()[72..], &[0; 56]);
            let before = slot.as_bytes().to_vec();
            assert!(slot.set_mapped_blkaddr(1u64 << 32).is_err());
            assert_eq!(slot.as_bytes(), before);
            slot.blocks_hi = [0xff; 2];
            slot.uniaddr_hi = [0xff; 2];
            assert_eq!(slot.blocks(), blocks);
            assert_eq!(slot.mapped_blkaddr(), u32::MAX as u64);
        }
        for blocks in [1u64 << 32, u64::MAX] {
            assert!(ErofsDeviceSlot::new(blocks).is_err());
        }
    }

    #[test]
    fn chunk_addresses_check_limits_and_use_low_word_holes() {
        for address in [0, u32::MAX as u64 - 1] {
            let mut entry = ErofsChunkIndex::new(address, 3).unwrap();
            assert_eq!(entry.blkaddr(), address);
            assert_eq!(entry.device_id(), 3);
            assert_eq!(&entry.as_bytes()[..2], &[0; 2]);
            entry.startblk_hi = [0xff; 2];
            assert_eq!(entry.blkaddr(), address);
        }
        for address in [u32::MAX as u64, 1u64 << 32] {
            assert!(ErofsChunkIndex::new(address, 1).is_err());
        }
        let hole = ErofsChunkIndex::new(EROFS_NULL_ADDR, 3).unwrap();
        assert_eq!(hole.as_bytes(), &[0, 0, 0, 0, 255, 255, 255, 255]);
        assert_eq!(hole.blkaddr(), EROFS_NULL_ADDR);
    }
}
