//! Little-endian integer helpers for the on-disk formats.
//!
//! Three shapes for three call patterns: fixed-size byte-array struct fields
//! (`read_u32`), offset-addressed buffers (`read_u32_at`), and sequential
//! readers (`read_u32_from`).

use std::io::{self, Read};

/// Read a little-endian integer from a byte array.
#[inline(always)]
pub(crate) fn read_u16(b: &[u8; 2]) -> u16 {
    u16::from_le_bytes(*b)
}

#[inline(always)]
pub(crate) fn write_u16(b: &mut [u8; 2], v: u16) {
    *b = v.to_le_bytes();
}

#[inline(always)]
pub(crate) fn read_u32(b: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*b)
}

#[inline(always)]
pub(crate) fn write_u32(b: &mut [u8; 4], v: u32) {
    *b = v.to_le_bytes();
}

#[inline(always)]
pub(crate) fn read_u64(b: &[u8; 8]) -> u64 {
    u64::from_le_bytes(*b)
}

#[inline(always)]
pub(crate) fn write_u64(b: &mut [u8; 8], v: u64) {
    *b = v.to_le_bytes();
}

/// Read a little-endian integer from `data` at `offset`.
///
/// Panics when `data` is too short — callers validate region sizes up front.
#[inline]
pub(crate) fn read_u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().expect("slice checked"))
}

#[inline]
pub(crate) fn read_u64_at(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().expect("slice checked"))
}

#[inline]
pub(crate) fn write_u32_at(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[inline]
pub(crate) fn write_u64_at(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Read a little-endian integer from a sequential reader.
pub(crate) fn read_u16_from(reader: &mut dyn Read) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    reader.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

pub(crate) fn read_u32_from(reader: &mut dyn Read) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

pub(crate) fn read_u64_from(reader: &mut dyn Read) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}
