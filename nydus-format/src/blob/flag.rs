//! Conventions shared by the nydus on-disk record formats (blob meta, blob
//! footer): a `magic + version + flags` header prefix where `flags` is split
//! EROFS-style — the low 16 bits are incompatible features (unknown bits
//! reject the file), the high 16 bits are compatible features (unknown bits
//! are ignored) — and a crc32c computed over the record with the crc field
//! zeroed.

use crate::error::{Error, Result};

/// The incompatible (reject-when-unknown) half of a format `flags` word.
pub const INCOMPAT_MASK: u32 = 0x0000_FFFF;

/// Reject `flags` whose incompat half carries bits outside `supported`.
pub fn validate_incompat_flags(flags: u32, supported: u32) -> Result<()> {
    let unknown_incompat = flags & INCOMPAT_MASK & !supported;
    if unknown_incompat != 0 {
        return Err(Error::Unsupported(format!(
            "unsupported incompat flags {unknown_incompat:#x} (image is newer than this reader)"
        )));
    }

    Ok(())
}
