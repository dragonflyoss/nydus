//! EROFS block-size conversions.

use crate::error::{Error, Result};

use super::EROFS_BLOCK_SIZE;

/// Convert a byte size to a 4 KiB block count. `name` labels the region in
/// error messages.
pub fn bytes_to_blocks(size: u64, name: &str) -> Result<u32> {
    if size % EROFS_BLOCK_SIZE as u64 != 0 {
        return Err(Error::InvalidImage(format!(
            "{name} size is not block aligned: {size}"
        )));
    }

    u32::try_from(size / EROFS_BLOCK_SIZE as u64)
        .map_err(|err| Error::Overflow(format!("{name} exceeds u32 block count: {err}")))
}

/// Convert a 4 KiB block count to a byte size.
pub fn blocks_to_bytes(blocks: u32) -> u64 {
    blocks as u64 * EROFS_BLOCK_SIZE as u64
}
