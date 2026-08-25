/// Round `value` up to the next multiple of `align`.
///
/// `align` must be a power of two. Returns `None` when the rounded value
/// would overflow `u64`.
#[inline]
pub fn align_up_u64(value: u64, align: u64) -> Option<u64> {
    debug_assert!(align.is_power_of_two());
    value.checked_add(align - 1).map(|v| v & !(align - 1))
}

/// The `usize` twin of [`align_up_u64`] for in-memory offsets and sizes.
#[inline]
pub fn align_up_usize(value: usize, align: usize) -> Option<usize> {
    debug_assert!(align.is_power_of_two());
    value.checked_add(align - 1).map(|v| v & !(align - 1))
}

#[cfg(test)]
mod tests {
    use super::{align_up_u64, align_up_usize};

    #[test]
    fn align_up_u64_rounds_up_to_alignment() {
        assert_eq!(align_up_u64(0, 8), Some(0));
        assert_eq!(align_up_u64(1, 8), Some(8));
        assert_eq!(align_up_u64(16, 8), Some(16));
        assert_eq!(align_up_u64(4097, 4096), Some(8192));
    }

    #[test]
    fn align_up_u64_detects_overflow() {
        assert_eq!(align_up_u64(u64::MAX, 4096), None);
    }

    #[test]
    fn align_up_usize_rounds_and_detects_overflow() {
        assert_eq!(align_up_usize(4097, 4096), Some(8192));
        assert_eq!(align_up_usize(usize::MAX, 4096), None);
    }
}
