use std::mem;

use super::*;

/// EROFS chunk index entry — 8 bytes, `#[repr(C, packed)]`.
#[repr(C, packed)]
pub struct ErofsChunkIndex {
    pub startblk_hi: [u8; 2],
    pub device_id: [u8; 2],
    pub startblk_lo: [u8; 4],
}

const _: () = assert!(mem::size_of::<ErofsChunkIndex>() == EROFS_CHUNK_INDEX_SIZE);

impl ErofsChunkIndex {
    pub fn new(blkaddr: u64, device_id: u16) -> Self {
        let mut v: Self = unsafe { mem::zeroed() };
        if blkaddr == EROFS_NULL_ADDR {
            v.startblk_hi = [0xFF; 2];
            v.device_id = [0xFF; 2];
            v.startblk_lo = [0xFF; 4];
        } else {
            set_u16(&mut v.startblk_hi, (blkaddr >> 32) as u16);
            set_u16(&mut v.device_id, device_id);
            set_u32(&mut v.startblk_lo, blkaddr as u32);
        }
        v
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, EROFS_CHUNK_INDEX_SIZE) }
    }

    pub fn blkaddr(&self) -> u64 {
        let hi = get_u16(&self.startblk_hi) as u64;
        let lo = get_u32(&self.startblk_lo) as u64;
        (hi << 32) | lo
    }

    pub fn device_id(&self) -> u16 {
        get_u16(&self.device_id)
    }
}

pub const EROFS_BLOB_ID_SIZE: usize = 32;

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
    pub fn new(blocks: u64) -> Self {
        let mut v: Self = unsafe { mem::zeroed() };
        debug_assert!(blocks < (1u64 << 48));
        set_u32(&mut v.blocks_lo, blocks as u32);
        set_u16(&mut v.blocks_hi, (blocks >> 32) as u16);
        v
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, EROFS_DEVICESLOT_SIZE) }
    }

    pub fn with_blob_id(blocks: u64, blob_id: &[u8; EROFS_BLOB_ID_SIZE]) -> Self {
        let mut v = Self::new(blocks);
        v.set_blob_id(blob_id);
        v
    }

    pub fn with_blob_id_and_mapped_blkaddr(
        blocks: u64,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
        mapped_blkaddr: u64,
    ) -> Self {
        let mut v = Self::with_blob_id(blocks, blob_id);
        v.set_mapped_blkaddr(mapped_blkaddr);
        v
    }

    pub fn blocks(&self) -> u64 {
        ((get_u16(&self.blocks_hi) as u64) << 32) | get_u32(&self.blocks_lo) as u64
    }

    pub fn mapped_blkaddr(&self) -> u64 {
        ((get_u16(&self.uniaddr_hi) as u64) << 32) | get_u32(&self.uniaddr_lo) as u64
    }

    pub fn set_mapped_blkaddr(&mut self, mapped_blkaddr: u64) {
        debug_assert!(mapped_blkaddr < (1u64 << 48));
        set_u32(&mut self.uniaddr_lo, mapped_blkaddr as u32);
        set_u16(&mut self.uniaddr_hi, (mapped_blkaddr >> 32) as u16);
    }

    pub fn set_blob_id(&mut self, blob_id: &[u8; EROFS_BLOB_ID_SIZE]) {
        self.tag[..EROFS_BLOB_ID_SIZE].copy_from_slice(blob_id);
        self.tag[EROFS_BLOB_ID_SIZE..].fill(0);
    }

    pub fn blob_id(&self) -> [u8; EROFS_BLOB_ID_SIZE] {
        let mut blob_id = [0u8; EROFS_BLOB_ID_SIZE];
        blob_id.copy_from_slice(&self.tag[..EROFS_BLOB_ID_SIZE]);
        blob_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_slot_uses_erofs_48bit_block_fields() {
        let blob_id = [0xAB; EROFS_BLOB_ID_SIZE];
        let blocks = 0x1234_5678_9ABCu64;
        let mapped_blkaddr = 0x2345_6789_ABCDu64;
        let slot =
            ErofsDeviceSlot::with_blob_id_and_mapped_blkaddr(blocks, &blob_id, mapped_blkaddr);

        assert_eq!(slot.blob_id(), blob_id);
        assert_eq!(slot.blocks(), blocks);
        assert_eq!(slot.mapped_blkaddr(), mapped_blkaddr);

        let raw = slot.as_bytes();
        assert_eq!(
            u32::from_le_bytes(raw[64..68].try_into().unwrap()),
            blocks as u32
        );
        assert_eq!(
            u32::from_le_bytes(raw[68..72].try_into().unwrap()),
            mapped_blkaddr as u32
        );
        assert_eq!(
            u16::from_le_bytes(raw[72..74].try_into().unwrap()),
            (blocks >> 32) as u16
        );
        assert_eq!(
            u16::from_le_bytes(raw[74..76].try_into().unwrap()),
            (mapped_blkaddr >> 32) as u16
        );
    }
}
