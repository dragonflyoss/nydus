//! The compression and digest algorithms a blob meta file declares as enum
//! codes in its ChunkGroupTable and ChunkGroupDigestTable headers.

use crate::error::{Error, Result};
use std::fmt;

/// The chunk group payload compressor a blob meta declares. `None` stores
/// payloads raw.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BlobMetadataCompressor {
    /// Payloads are stored as they are.
    #[default]
    None,

    /// One zstd frame per chunk group.
    Zstd,

    /// One LZ4 block per chunk group, without a frame header.
    Lz4Block,
}

/// Maps the compressor to and from the code the ChunkGroupTable header stores.
impl BlobMetadataCompressor {
    /// The ChunkGroupTable header code of this compressor.
    pub fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Zstd => 1,
            Self::Lz4Block => 2,
        }
    }

    /// Decode a ChunkGroupTable header code. An unknown compressor rejects
    /// the file, since its payloads cannot be decoded.
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

/// Names the compressor in the `build` and `check` summaries.
impl fmt::Display for BlobMetadataCompressor {
    /// The lowercase algorithm name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::Zstd => "zstd",
            Self::Lz4Block => "lz4",
        })
    }
}

/// The chunk digest algorithm a blob meta declares. `None` means the blob
/// has no ChunkGroupDigestTable, so its chunks carry no integrity
/// information, for content already verified upstream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BlobMetadataDigester {
    /// BLAKE3, 32-byte digests.
    #[default]
    Blake3,

    /// No ChunkGroupDigestTable.
    None,
}

/// Maps the digester to and from the code the ChunkGroupDigestTable header
/// stores.
impl BlobMetadataDigester {
    /// The ChunkGroupDigestTable header code of BLAKE3.
    pub const BLAKE3_CODE: u8 = 1;

    /// The ChunkGroupDigestTable header code of this digester, `None` for no table.
    pub fn code(self) -> Option<u8> {
        match self {
            Self::Blake3 => Some(Self::BLAKE3_CODE),
            Self::None => None,
        }
    }

    /// Decode a ChunkGroupDigestTable header code, `None` for an unknown algorithm.
    pub fn from_code(code: u8) -> Option<Self> {
        (code == Self::BLAKE3_CODE).then_some(Self::Blake3)
    }
}

/// Names the digester in the `build` and `check` summaries.
impl fmt::Display for BlobMetadataDigester {
    /// The lowercase algorithm name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Blake3 => "blake3",
            Self::None => "none",
        })
    }
}
