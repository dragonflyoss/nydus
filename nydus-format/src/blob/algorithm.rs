//! The compression and digest algorithms a blob meta file declares in its
//! `flags` word: typed views over the algorithm flag bits, decoded per read
//! from `BlobMetadataFlags` and encoded back via `flag`.

use crate::blob::metadata::BlobMetadataFlags;
use crate::error::{Error, Result};
use std::fmt;

/// The block group payload compressor a blob meta declares. `None` is the
/// absent-flag state: payloads are stored raw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobMetadataCompressor {
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
            Self::Lz4Block => "lz4-block",
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

/// The chunk digest algorithm a blob meta declares, always explicit (see
/// the `TryFrom` below). `None` records zero digests: the chunk table is
/// still addressable but carries no integrity information, for blobs built
/// from content that was already verified upstream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobMetadataDigester {
    Blake3,
    None,
}

impl BlobMetadataDigester {
    /// The flag bit encoding this digester.
    pub fn flag(self) -> BlobMetadataFlags {
        match self {
            Self::Blake3 => BlobMetadataFlags::DIGESTER_BLAKE3,
            Self::None => BlobMetadataFlags::DIGESTER_NONE,
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

/// Fallible: every blob meta must declare its digester, so an absent flag
/// is a corrupt file rather than a default.
impl TryFrom<BlobMetadataFlags> for BlobMetadataDigester {
    type Error = Error;

    fn try_from(value: BlobMetadataFlags) -> Result<Self> {
        let blake3 = value.contains(BlobMetadataFlags::DIGESTER_BLAKE3);
        let none = value.contains(BlobMetadataFlags::DIGESTER_NONE);
        match (blake3, none) {
            (true, false) => Ok(Self::Blake3),
            (false, true) => Ok(Self::None),
            (true, true) => Err(Error::InvalidImage(
                "blob meta declares more than one digester".to_string(),
            )),
            (false, false) => Err(Error::InvalidImage(
                "blob meta digester flag is missing".to_string(),
            )),
        }
    }
}
