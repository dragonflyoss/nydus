/// Round `value` up to the next multiple of `align`.
///
/// `align` must be a power of two. Returns `None` when the rounded value
/// would overflow `u64`.
#[inline]
pub fn align_up(value: u64, align: u64) -> Option<u64> {
    debug_assert!(align.is_power_of_two());
    value.checked_add(align - 1).map(|v| v & !(align - 1))
}

/// Round `val` up to the next multiple of `align` (power of two).
/// Unchecked builder-path twin of [`align_up`]; panics on overflow.
#[inline]
pub(crate) fn round_up(val: usize, align: usize) -> usize {
    align_up(val as u64, align as u64).expect("size rounding overflowed") as usize
}

#[cfg(test)]
mod tests {
    use super::align_up;

    #[test]
    fn align_up_rounds_up_to_alignment() {
        assert_eq!(align_up(0, 8), Some(0));
        assert_eq!(align_up(1, 8), Some(8));
        assert_eq!(align_up(16, 8), Some(16));
        assert_eq!(align_up(4097, 4096), Some(8192));
    }

    #[test]
    fn align_up_detects_overflow() {
        assert_eq!(align_up(u64::MAX, 4096), None);
    }
}
