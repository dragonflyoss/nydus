//! The chunk group payload compressor a blob meta file declares as an enum
//! code in its ChunkGroupTable header.

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

    /// Decodes a ChunkGroupTable header code. An unknown compressor rejects
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
}
