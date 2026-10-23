//! Byte-level helpers shared by the blob and EROFS formats: little-endian
//! field access, alignment, zero padding, feature words and SHA-256
//! digests.

pub mod bytes;
pub mod digest;
pub mod flag;

pub use bytes::{align_up_u64, align_up_usize, write_zeros};
pub use digest::{sha256_reader, SHA256_DIGEST_SIZE};
pub use flag::FeatureFlags;
