use std::io::Write;

use anyhow::Result;

use crate::metadata::*;

/// Write the complete EROFS image file.
///
/// Image layout:
///   Block 0:  [1024 zeros] [superblock 128B] [device slot 128B] [zeros]
///   Block 1+: metadata area (inodes + directory data)
#[allow(clippy::too_many_arguments)]
pub fn write_image(
    image: &mut impl Write,
    metadata_buf: &[u8],
    root_nid: u16,
    total_inodes: u64,
    epoch: u64,
    blob_blocks: u64,
    uuid: &[u8; 16],
) -> Result<()> {
    let block_size = EROFS_BLOCK_SIZE as usize;
    let meta_blkaddr: u32 = 1;
    let meta_blocks = metadata_buf.len().div_ceil(block_size);
    let total_blocks = 1 + meta_blocks as u64;

    let feature_compat = EROFS_FEATURE_COMPAT_MTIME;
    let feature_incompat =
        EROFS_FEATURE_INCOMPAT_CHUNKED_FILE | EROFS_FEATURE_INCOMPAT_DEVICE_TABLE;

    let devt_slotoff: u16 =
        (EROFS_SUPER_OFFSET as usize + EROFS_SB_BASE_SIZE) as u16 / EROFS_DEVICESLOT_SIZE as u16;

    // --- Block 0 ---
    let mut block0 = vec![0u8; block_size];

    let sb = ErofsSuperblock::new(
        feature_compat,
        feature_incompat,
        root_nid,
        total_inodes,
        epoch,
        total_blocks,
        meta_blkaddr,
        1, // extra_devices = 1 (blobdev)
        devt_slotoff,
        uuid,
    );
    let sb_offset = EROFS_SUPER_OFFSET as usize;
    block0[sb_offset..sb_offset + EROFS_SB_BASE_SIZE].copy_from_slice(sb.as_bytes());

    let devslot = ErofsDeviceSlot::new(blob_blocks);
    let devslot_offset = sb_offset + EROFS_SB_BASE_SIZE;
    block0[devslot_offset..devslot_offset + EROFS_DEVICESLOT_SIZE]
        .copy_from_slice(devslot.as_bytes());

    image.write_all(&block0)?;

    // --- Metadata blocks ---
    image.write_all(metadata_buf)?;

    let remainder = metadata_buf.len() % block_size;
    if remainder != 0 {
        let pad = vec![0u8; block_size - remainder];
        image.write_all(&pad)?;
    }

    Ok(())
}
