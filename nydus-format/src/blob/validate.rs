//! Conventions shared by the nydus on-disk record formats (blob meta, blob
//! footer): a `magic + version + flags` header prefix where `flags` is split
//! EROFS-style — the low 16 bits are incompatible features (unknown bits
//! reject the file), the high 16 bits are compatible features (unknown bits
//! are ignored) — and a crc32c computed over the record with the crc field
//! zeroed.

use std::ops::Range;

use crc32c::crc32c_append;

use crate::error::{FormatError, Result};

/// The incompatible (reject-when-unknown) half of a format `flags` word.
pub const INCOMPAT_MASK: u32 = 0x0000_FFFF;

/// Reject `flags` whose incompat half carries bits outside `supported`.
/// `what` names the format in the error message.
pub fn validate_incompat_flags(flags: u32, supported: u32, what: &str) -> Result<()> {
    let unknown_incompat = flags & INCOMPAT_MASK & !supported;
    if unknown_incompat != 0 {
        return Err(FormatError::Unsupported(format!(
            "unsupported {what} incompat flags: {unknown_incompat:#x}"
        )));
    }
    Ok(())
}

/// crc32c over `bytes` with the `field` range treated as zeroed, without
/// mutating or copying `bytes`. The result may seed further `crc32c_append`
/// calls for records that continue past `bytes`.
pub fn crc32_with_zeroed_field(bytes: &[u8], field: Range<usize>) -> u32 {
    let crc32 = crc32c_append(0, &bytes[..field.start]);
    let crc32 = crc32c_append(crc32, &vec![0u8; field.len()]);
    crc32c_append(crc32, &bytes[field.end..])
}
