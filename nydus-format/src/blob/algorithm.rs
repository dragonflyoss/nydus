//! The compression and digest algorithms a blob meta file declares as enum
//! codes in its GroupTable and DigestTable headers.

use crate::error::{Error, Result};
use std::fmt;

/// The chunk group payload compressor a blob meta declares. `None` stores
/// payloads raw.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BlobMetadataCompressor {
    #[default]
    None,
    Zstd,
    Lz4Block,
}

impl BlobMetadataCompressor {
    /// The GroupTable header code of this compressor.
    pub fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Zstd => 1,
            Self::Lz4Block => 2,
        }
    }

    /// Decode a GroupTable header code; an unknown compressor rejects the
    /// file, since its payloads cannot be decoded.
    pub fn from_code(code: u8) -> Result<Self> {
        match code {
            0 => Ok(Self::None),
            1 => Ok(Self::Zstd),
            2 => Ok(Self::Lz4Block),
            _ => Err(Error::Unsupported(format!(
                "unsupported blob meta compressor {code} (image is newer than this reader)"
            ))),
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

/// The chunk digest algorithm a blob meta declares. `None` means the blob
/// has no DigestTable: the chunk table is still addressable but carries no
/// integrity information, for blobs built from content that was already
/// verified upstream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BlobMetadataDigester {
    #[default]
    Blake3,
    None,
}

impl BlobMetadataDigester {
    /// The DigestTable header code of this digester, `None` for no table.
    pub fn code(self) -> Option<u8> {
        match self {
            Self::Blake3 => Some(1),
            Self::None => None,
        }
    }

    /// Decode a DigestTable header code, `None` for an unknown algorithm.
    pub fn from_code(code: u8) -> Option<Self> {
        (code == 1).then_some(Self::Blake3)
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
