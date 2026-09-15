//! The compression and digest algorithms a blob meta file declares in its
//! `flags` word: typed views over the algorithm flag bits, decoded per read
//! from `BlobMetadataFlags` and encoded back via `flag`.

use crate::blob::metadata::BlobMetadataFlags;
use std::fmt;

/// The chunk group payload compressor a blob meta declares. `None` is the
/// absent-flag state: payloads are stored raw.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BlobMetadataCompressor {
    #[default]
    None,
    Zstd,
    Lz4Block,
}

impl BlobMetadataCompressor {
    /// The flag bit encoding this compressor, empty for `None`.
    pub fn flag(self) -> BlobMetadataFlags {
        match self {
            Self::None => BlobMetadataFlags::empty(),
            Self::Zstd => BlobMetadataFlags::COMPRESSOR_ZSTD,
            Self::Lz4Block => BlobMetadataFlags::COMPRESSOR_LZ4,
        }
    }
}

/// The lowercase algorithm name, as surfaced in the `build` and `check`
/// summaries.
impl fmt::Display for BlobMetadataCompressor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::Zstd => "zstd",
            Self::Lz4Block => "lz4",
        })
    }
}

/// Infallible: an absent compressor flag is the valid uncompressed state,
/// and `BlobMetadataFlags` can only hold defined bits.
impl From<BlobMetadataFlags> for BlobMetadataCompressor {
    fn from(value: BlobMetadataFlags) -> Self {
        if value.contains(BlobMetadataFlags::COMPRESSOR_LZ4) {
            Self::Lz4Block
        } else if value.contains(BlobMetadataFlags::COMPRESSOR_ZSTD) {
            Self::Zstd
        } else {
            Self::None
        }
    }
}

/// The chunk digest algorithm a blob meta declares. `None` is the
/// absent-flag state and records zero digests: the chunk table is still
/// addressable but carries no integrity information, for blobs built from
/// content that was already verified upstream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BlobMetadataDigester {
    #[default]
    Blake3,
    None,
}

impl BlobMetadataDigester {
    /// The flag bit encoding this digester, empty for `None`.
    pub fn flag(self) -> BlobMetadataFlags {
        match self {
            Self::Blake3 => BlobMetadataFlags::DIGESTER_BLAKE3,
            Self::None => BlobMetadataFlags::empty(),
        }
    }
}

/// The lowercase algorithm name, as surfaced in the `build` and `check`
/// summaries.
impl fmt::Display for BlobMetadataDigester {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Blake3 => "blake3",
            Self::None => "none",
        })
    }
}

/// Infallible, like the compressor: an absent digester flag is the valid
/// undigested state.
impl From<BlobMetadataFlags> for BlobMetadataDigester {
    fn from(value: BlobMetadataFlags) -> Self {
        if value.contains(BlobMetadataFlags::DIGESTER_BLAKE3) {
            Self::Blake3
        } else {
            Self::None
        }
    }
}
