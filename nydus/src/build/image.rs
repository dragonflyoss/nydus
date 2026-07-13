use std::io::Write;

use anyhow::{bail, Result};
use crc32c::crc32c_append;

use crate::metadata::*;

/// Write the complete EROFS image file.
///
/// Image layout:
///   Block 0:        [1024 zeros] [superblock 128B] [device table start ...]
///   Block 1..N:     [device table continued, if it overflows block 0]
///   Block N (meta_blkaddr)+: metadata area (inodes + directory data)
///
/// The device table is placed right after the superblock and may span several
/// blocks when an image references many external blobs (for example a deep
/// multi-layer merge). `meta_blkaddr` is pushed past the device table so the two
/// regions never overlap. For images with up to 23 device slots the table fits
/// in block 0 and `meta_blkaddr` stays 1, matching the previous layout.
#[allow(clippy::too_many_arguments)]
pub fn write_image(
    image: &mut impl Write,
    metadata_buf: &[u8],
    root_nid: u16,
    total_inodes: u64,
    epoch: u64,
    device_slots: &[ErofsDeviceSlot],
    uuid: &[u8; 16],
) -> Result<()> {
    let block_size = EROFS_BLOCK_SIZE as usize;
    let meta_blkaddr = device_table_meta_blkaddr(device_slots.len())?;
    let head_size = meta_blkaddr as usize * block_size;
    let meta_blocks = metadata_buf.len().div_ceil(block_size);
    let total_blocks = meta_blkaddr as u64 + meta_blocks as u64;

    let feature_compat = EROFS_FEATURE_COMPAT_MTIME | EROFS_FEATURE_COMPAT_SB_CHKSUM;
    let feature_incompat =
        EROFS_FEATURE_INCOMPAT_CHUNKED_FILE | EROFS_FEATURE_INCOMPAT_DEVICE_TABLE;

    let devt_slotoff: u16 = if device_slots.is_empty() {
        0
    } else {
        (EROFS_SUPER_OFFSET as usize + EROFS_SB_BASE_SIZE) as u16 / EROFS_DEVICESLOT_SIZE as u16
    };

    // --- Head region (block 0 .. meta_blkaddr) ---
    let mut head = vec![0u8; head_size];

    let sb = ErofsSuperblock::new(
        feature_compat,
        feature_incompat,
        root_nid,
        total_inodes,
        epoch,
        total_blocks,
        meta_blkaddr,
        device_slots.len() as u16,
        devt_slotoff,
        uuid,
    );
    let sb_offset = EROFS_SUPER_OFFSET as usize;
    head[sb_offset..sb_offset + EROFS_SB_BASE_SIZE].copy_from_slice(sb.as_bytes());

    let devslot_offset = sb_offset + EROFS_SB_BASE_SIZE;
    let device_table_end = devslot_offset + device_slots.len() * EROFS_DEVICESLOT_SIZE;
    if device_table_end > head.len() {
        bail!("device table does not fit in the reserved metadata head region")
    }

    for (index, devslot) in device_slots.iter().enumerate() {
        let start = devslot_offset + index * EROFS_DEVICESLOT_SIZE;
        let end = start + EROFS_DEVICESLOT_SIZE;
        head[start..end].copy_from_slice(devslot.as_bytes());
    }

    write_erofs_superblock_checksum(&mut head)?;

    image.write_all(&head)?;

    // --- Metadata blocks ---
    image.write_all(metadata_buf)?;

    let remainder = metadata_buf.len() % block_size;
    if remainder != 0 {
        let pad = vec![0u8; block_size - remainder];
        image.write_all(&pad)?;
    }

    Ok(())
}

/// Compute the block address at which the inode metadata region starts.
///
/// The device table is laid out immediately after the superblock, at byte
/// `EROFS_SUPER_OFFSET + EROFS_SB_BASE_SIZE` (1152). The metadata must start on
/// the first block boundary at or after the end of the device table so the two
/// regions never overlap. With up to 23 device slots the table fits in block 0
/// and this returns 1, preserving the original layout.
pub fn device_table_meta_blkaddr(device_count: usize) -> Result<u32> {
    let block_size = EROFS_BLOCK_SIZE as usize;
    let table_end = EROFS_SUPER_OFFSET as usize
        + EROFS_SB_BASE_SIZE
        + device_count
            .checked_mul(EROFS_DEVICESLOT_SIZE)
            .ok_or_else(|| anyhow::anyhow!("device table size overflow"))?;
    let blocks = table_end.div_ceil(block_size).max(1);
    u32::try_from(blocks).map_err(|_| anyhow::anyhow!("metadata block address exceeds u32"))
}

pub(crate) fn write_erofs_superblock_checksum(head: &mut [u8]) -> Result<()> {
    let sb_offset = EROFS_SUPER_OFFSET as usize;
    let block_size = EROFS_BLOCK_SIZE as usize;
    if head.len() < block_size {
        bail!("image block is too small for EROFS superblock checksum")
    }

    // The EROFS superblock checksum covers only block 0 from the superblock
    // offset to the end of that block, regardless of how far the device table
    // (and therefore the metadata region) extends afterwards.
    //
    // The Linux kernel verifies it with `crc32c(~0, dsb, EROFS_BLKSIZ -
    // EROFS_SUPER_OFFSET)`, where kernel `crc32c()` is the bare `__crc32c_le`
    // running CRC WITHOUT the trailing one's-complement. The `crc32c` crate's
    // `crc32c(data)` (== `crc32c_append(0, data)`) applies the standard final
    // XOR, so the kernel value is its bitwise complement. Store `!crc32c(..)`
    // so the guest kernel accepts the image (otherwise erofs mount fails with
    // EBADMSG / "Bad message").
    let checksum_offset = sb_offset + 4;
    head[checksum_offset..checksum_offset + 4].fill(0);
    let crc32 = !crc32c_append(0u32, &head[sb_offset..block_size]);
    head[checksum_offset..checksum_offset + 4].copy_from_slice(&crc32.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_image_sets_erofs_superblock_checksum() {
        let mut image = Vec::new();
        write_image(&mut image, &[], 0, 1, 0, &[], &[0u8; 16]).unwrap();

        let sb_offset = EROFS_SUPER_OFFSET as usize;
        let feature_compat =
            u32::from_le_bytes(image[sb_offset + 8..sb_offset + 12].try_into().unwrap());
        let checksum = u32::from_le_bytes(image[sb_offset + 4..sb_offset + 8].try_into().unwrap());
        let mut checksum_bytes = image[sb_offset..EROFS_BLOCK_SIZE as usize].to_vec();
        checksum_bytes[4..8].fill(0);

        assert_ne!(checksum, 0);
        assert_ne!(feature_compat & EROFS_FEATURE_COMPAT_SB_CHKSUM, 0);
        assert_eq!(checksum, !crc32c_append(0u32, &checksum_bytes));
    }

    #[test]
    fn device_table_meta_blkaddr_grows_with_device_count() {
        // 1152 bytes of head precede the device table. (4096 - 1152) / 128 = 23
        // slots fit in block 0; the 24th pushes metadata to block 2.
        assert_eq!(device_table_meta_blkaddr(0).unwrap(), 1);
        assert_eq!(device_table_meta_blkaddr(1).unwrap(), 1);
        assert_eq!(device_table_meta_blkaddr(23).unwrap(), 1);
        assert_eq!(device_table_meta_blkaddr(24).unwrap(), 2);
        // (4096*2 - 1152) / 128 = 55 slots fit in two blocks; 56 needs a third.
        assert_eq!(device_table_meta_blkaddr(55).unwrap(), 2);
        assert_eq!(device_table_meta_blkaddr(56).unwrap(), 3);
    }

    #[test]
    fn write_image_places_large_device_table_across_blocks() {
        let block_size = EROFS_BLOCK_SIZE as usize;
        // 30 slots overflow block 0, so metadata starts at block 2.
        let device_slots: Vec<ErofsDeviceSlot> = (0..30)
            .map(|i| ErofsDeviceSlot::with_blob_id(i as u64 + 1, &[i as u8; EROFS_BLOB_ID_SIZE]))
            .collect();

        let mut image = Vec::new();
        write_image(&mut image, &[0u8; 64], 0, 1, 0, &device_slots, &[0u8; 16]).unwrap();

        let sb_offset = EROFS_SUPER_OFFSET as usize;
        let meta_blkaddr =
            u32::from_le_bytes(image[sb_offset + 40..sb_offset + 44].try_into().unwrap());
        assert_eq!(meta_blkaddr, 2);

        // The superblock checksum still covers only block 0.
        let checksum = u32::from_le_bytes(image[sb_offset + 4..sb_offset + 8].try_into().unwrap());
        let mut block0 = image[sb_offset..block_size].to_vec();
        block0[4..8].fill(0);
        assert_eq!(checksum, !crc32c_append(0u32, &block0));

        // The last device slot lands in block 1, beyond block 0.
        let devslot_offset = sb_offset + EROFS_SB_BASE_SIZE;
        let last_slot_start = devslot_offset + 29 * EROFS_DEVICESLOT_SIZE;
        assert!(last_slot_start >= block_size);
        assert_eq!(
            &image[last_slot_start..last_slot_start + EROFS_DEVICESLOT_SIZE],
            device_slots[29].as_bytes()
        );

        // Metadata begins exactly at meta_blkaddr.
        assert_eq!(image[meta_blkaddr as usize * block_size], 0u8);
        assert_eq!(image.len() % block_size, 0);
    }
}
