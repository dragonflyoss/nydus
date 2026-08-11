//! Helpers shared by the integration tests for assembling footer-based
//! full blobs. Thin infallible wrappers over the production helpers in
//! `nydus_core::utils` — fixtures use static sizes, so failures are bugs.

use std::io::Write;

pub fn align_up(value: u64, align: u64) -> u64 {
    nydus_core::utils::align_up(value, align).expect("test alignment overflow")
}

pub fn bytes_to_blocks(size: u64) -> u32 {
    nydus_core::utils::bytes_to_blocks(size, "test region").expect("test region not block aligned")
}

pub fn write_zero_padding(
    writer: &mut dyn Write,
    current: u64,
    aligned: u64,
) -> std::io::Result<()> {
    nydus_core::utils::write_zero_padding(writer, current, aligned)
}
