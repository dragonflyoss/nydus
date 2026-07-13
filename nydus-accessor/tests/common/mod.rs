//! Helpers shared by the integration tests for assembling footer-based
//! full blobs.

use std::io::Write;

use nydus_accessor::metadata::EROFS_BLOCK_SIZE;

pub fn align_u64(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

pub fn bytes_to_blocks(size: u64) -> u32 {
    assert_eq!(size % EROFS_BLOCK_SIZE as u64, 0);
    (size / EROFS_BLOCK_SIZE as u64) as u32
}

pub fn write_zero_padding(
    writer: &mut dyn Write,
    current: u64,
    aligned: u64,
) -> std::io::Result<()> {
    let padding = aligned - current;
    if padding > 0 {
        writer.write_all(&vec![0u8; padding as usize])?;
    }
    Ok(())
}
