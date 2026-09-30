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
}

/// Maps the digester to and from the code the ChunkGroupDigestTable header
/// stores.
impl BlobMetadataDigester {
    /// The ChunkGroupDigestTable header code of this digester.
    pub fn code(self) -> u8 {
        match self {
            Self::Blake3 => 1,
        }
    }

    /// Decode a ChunkGroupDigestTable header code. An unknown code is an
    /// error, the blob then reads as undigested.
    pub fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Blake3),
            _ => Err(Error::Unsupported(format!(
                "unsupported blob meta digester {code} (image is newer than this reader)"
            ))),
        }
    }
}

/// Names the digester in the `build` and `check` summaries.
impl fmt::Display for BlobMetadataDigester {
    /// The lowercase algorithm name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Blake3 => "blake3",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressor_formats_as_its_name() {
        let test_cases = vec![
            (BlobMetadataCompressor::None, "none"),
            (BlobMetadataCompressor::Zstd, "zstd"),
            (BlobMetadataCompressor::Lz4Block, "lz4"),
        ];

        for (compressor, expected) in test_cases {
            assert_eq!(compressor.to_string(), expected);
        }
    }

    #[test]
    fn compressor_from_code_accepts_known_codes() {
        assert_eq!(
            BlobMetadataCompressor::default(),
            BlobMetadataCompressor::None
        );

        let test_cases = vec![
            (0, Ok(BlobMetadataCompressor::None)),
            (1, Ok(BlobMetadataCompressor::Zstd)),
            (2, Ok(BlobMetadataCompressor::Lz4Block)),
            (
                3,
                Err("unsupported blob meta compressor 3 (image is newer than this reader)"),
            ),
        ];

        for (code, expected) in test_cases {
            let compressor = BlobMetadataCompressor::from_code(code).map_err(|err| err.to_string());
            assert_eq!(compressor, expected.map_err(String::from));
            if let Ok(compressor) = compressor {
                assert_eq!(compressor.code(), code);
            }
        }
    }

    #[test]
    fn digester_formats_as_its_name() {
        assert_eq!(BlobMetadataDigester::Blake3.to_string(), "blake3");
    }

    #[test]
    fn digester_from_code_accepts_only_blake3() {
        assert_eq!(
            BlobMetadataDigester::default(),
            BlobMetadataDigester::Blake3
        );
        assert_eq!(BlobMetadataDigester::Blake3.code(), 1);

        let test_cases = vec![
            (
                0,
                Err("unsupported blob meta digester 0 (image is newer than this reader)"),
            ),
            (1, Ok(BlobMetadataDigester::Blake3)),
            (
                2,
                Err("unsupported blob meta digester 2 (image is newer than this reader)"),
            ),
        ];

        for (code, expected) in test_cases {
            assert_eq!(
                BlobMetadataDigester::from_code(code).map_err(|err| err.to_string()),
                expected.map_err(String::from)
            );
        }
    }
}
