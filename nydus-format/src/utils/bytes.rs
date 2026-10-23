//! Byte-level helpers for the on-disk formats: little-endian integer
//! fields, the alignment of byte offsets and sizes, and zero padding.
//!
//! The integer helpers come in two shapes for two call patterns:
//! fixed-size byte-array struct fields (`read_u32`) and offset-addressed
//! buffers (`read_u32_at`). The `_at` helpers panic when `data` is too
//! short, callers validate region sizes up front.

use std::io::{self, Read, Write};

/// Writes `count` zero bytes to `writer`, the padding between the regions
/// of a blob and the blocks of a bootstrap.
pub fn write_zeros(writer: &mut dyn Write, count: u64) -> io::Result<()> {
    io::copy(&mut io::repeat(0).take(count), writer)?;
    Ok(())
}

/// Reads a little-endian `u16` from a byte array.
#[inline]
pub fn read_u16(bytes: &[u8; 2]) -> u16 {
    u16::from_le_bytes(*bytes)
}

/// Writes `value` little-endian into a byte array.
#[inline]
pub fn write_u16(bytes: &mut [u8; 2], value: u16) {
    *bytes = value.to_le_bytes();
}

/// Reads a little-endian `u32` from a byte array.
#[inline]
pub fn read_u32(bytes: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*bytes)
}

/// Writes `value` little-endian into a byte array.
#[inline]
pub fn write_u32(bytes: &mut [u8; 4], value: u32) {
    *bytes = value.to_le_bytes();
}

/// Reads a little-endian `u64` from a byte array.
#[inline]
pub fn read_u64(bytes: &[u8; 8]) -> u64 {
    u64::from_le_bytes(*bytes)
}

/// Writes `value` little-endian into a byte array.
#[inline]
pub fn write_u64(bytes: &mut [u8; 8], value: u64) {
    *bytes = value.to_le_bytes();
}

/// Reads the byte of `data` at `offset`.
#[inline]
pub fn read_u8_at(data: &[u8], offset: usize) -> u8 {
    data[offset]
}

/// Reads a little-endian `u16` from `data` at `offset`.
#[inline]
pub fn read_u16_at(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(read_bytes_at(data, offset))
}

/// Reads a little-endian `u32` from `data` at `offset`.
#[inline]
pub fn read_u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(read_bytes_at(data, offset))
}

/// Reads a little-endian `u64` from `data` at `offset`.
#[inline]
pub fn read_u64_at(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(read_bytes_at(data, offset))
}

/// Copies `N` bytes out of `data` at `offset`, for reserved areas and
/// digests.
#[inline]
pub fn read_bytes_at<const N: usize>(data: &[u8], offset: usize) -> [u8; N] {
    data[offset..offset + N].try_into().unwrap()
}

/// Writes `value` into `data` at `offset`.
#[inline]
pub fn write_u8_at(data: &mut [u8], offset: usize, value: u8) {
    data[offset] = value;
}

/// Writes `value` little-endian into `data` at `offset`.
#[inline]
pub fn write_u16_at(data: &mut [u8], offset: usize, value: u16) {
    write_bytes_at(data, offset, &value.to_le_bytes());
}

/// Writes `value` little-endian into `data` at `offset`.
#[inline]
pub fn write_u32_at(data: &mut [u8], offset: usize, value: u32) {
    write_bytes_at(data, offset, &value.to_le_bytes());
}

/// Writes `value` little-endian into `data` at `offset`.
#[inline]
pub fn write_u64_at(data: &mut [u8], offset: usize, value: u64) {
    write_bytes_at(data, offset, &value.to_le_bytes());
}

/// Copies `value` into `data` at `offset`.
#[inline]
pub fn write_bytes_at<const N: usize>(data: &mut [u8], offset: usize, value: &[u8; N]) {
    data[offset..offset + N].copy_from_slice(value);
}

/// Rounds `value` up to the next multiple of `align`, or `None` when the
/// rounded value would overflow a `u64`.
#[inline]
pub fn align_up_u64(value: u64, align: u64) -> Option<u64> {
    value.checked_next_multiple_of(align)
}

/// The `usize` twin of [`align_up_u64`] for in-memory offsets and sizes.
#[inline]
pub fn align_up_usize(value: usize, align: usize) -> Option<usize> {
    value.checked_next_multiple_of(align)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_zeros_writes_count_zero_bytes() {
        let test_cases = vec![0, 1, 4096, 10_000];

        for count in test_cases {
            let mut written = Vec::new();
            write_zeros(&mut written, count).unwrap();
            assert_eq!(written, vec![0u8; count as usize]);
        }
    }

    #[test]
    fn write_then_read_round_trips_little_endian_arrays() {
        let mut u16_bytes = [0u8; 2];
        let mut u32_bytes = [0u8; 4];
        let mut u64_bytes = [0u8; 8];
        write_u16(&mut u16_bytes, 0x2233);
        write_u32(&mut u32_bytes, 0x4455_6677);
        write_u64(&mut u64_bytes, 0x8899_aabb_ccdd_eeff);

        assert_eq!(u16_bytes, [0x33, 0x22]);
        assert_eq!(u32_bytes, [0x77, 0x66, 0x55, 0x44]);
        assert_eq!(u64_bytes, [0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88]);
        assert_eq!(read_u16(&u16_bytes), 0x2233);
        assert_eq!(read_u32(&u32_bytes), 0x4455_6677);
        assert_eq!(read_u64(&u64_bytes), 0x8899_aabb_ccdd_eeff);
    }

    #[test]
    fn write_at_then_read_at_round_trips_little_endian_fields() {
        let mut data = [0u8; 24];
        write_u8_at(&mut data, 0, 0x11);
        write_u16_at(&mut data, 1, 0x2233);
        write_u32_at(&mut data, 3, 0x4455_6677);
        write_u64_at(&mut data, 7, 0x8899_aabb_ccdd_eeff);
        write_bytes_at(&mut data, 15, b"nydus");

        assert_eq!(
            &data[..20],
            &[
                0x11, 0x33, 0x22, 0x77, 0x66, 0x55, 0x44, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
                0x88, b'n', b'y', b'd', b'u', b's'
            ]
        );
        assert_eq!(&data[20..], &[0; 4]);
        assert_eq!(read_u8_at(&data, 0), 0x11);
        assert_eq!(read_u16_at(&data, 1), 0x2233);
        assert_eq!(read_u32_at(&data, 3), 0x4455_6677);
        assert_eq!(read_u64_at(&data, 7), 0x8899_aabb_ccdd_eeff);
        assert_eq!(&read_bytes_at::<5>(&data, 15), b"nydus");
    }

    #[test]
    fn align_up_u64_rounds_up_or_detects_overflow() {
        let test_cases = vec![
            (0, 8, Some(0)),
            (1, 8, Some(8)),
            (16, 8, Some(16)),
            (4097, 4096, Some(8192)),
            (u64::MAX - 4095, 4096, Some(u64::MAX - 4095)),
            (u64::MAX, 4096, None),
        ];

        for (value, align, expected) in test_cases {
            assert_eq!(align_up_u64(value, align), expected);
        }
    }

    #[test]
    fn align_up_usize_rounds_up_or_detects_overflow() {
        let test_cases = vec![
            (0, 4, Some(0)),
            (3, 4, Some(4)),
            (4097, 4096, Some(8192)),
            (usize::MAX, 4096, None),
        ];

        for (value, align, expected) in test_cases {
            assert_eq!(align_up_usize(value, align), expected);
        }
    }
}
