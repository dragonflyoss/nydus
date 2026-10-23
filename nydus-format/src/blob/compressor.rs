//! The chunk group payload compressor a blob meta file declares as an enum
//! code in its ChunkGroupTable header, and the codec of the payloads.

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

/// Implements the chunk group payload codec.
impl BlobMetadataCompressor {
    /// Compresses `payload`, one chunk group's uncompressed bytes, into its
    /// stored form; `None` for the plain compressor, whose stored form is the
    /// payload itself.
    pub fn compress(self, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        match self {
            Self::None => Ok(None),
            Self::Zstd => Ok(Some(zstd::bulk::compress(
                payload,
                zstd::DEFAULT_COMPRESSION_LEVEL,
            )?)),
            Self::Lz4Block => Ok(Some(lz4_flex::block::compress(payload))),
        }
    }

    /// Decompresses `encoded`, one chunk group's stored bytes, into
    /// `decoded`, exactly the chunk group's uncompressed size, failing when
    /// the bytes do not decode or decode to another size.
    pub fn decompress_into(self, encoded: &[u8], decoded: &mut [u8]) -> Result<()> {
        let written = match self {
            Self::None => {
                return Err(Error::InvalidImage(
                    "blob meta declares no compressor but the chunk group is stored compressed"
                        .to_string(),
                ))
            }
            Self::Zstd => zstd::bulk::Decompressor::new()
                .and_then(|mut decompressor| decompressor.decompress_to_buffer(encoded, decoded))
                .map_err(|err| Error::InvalidImage(format!("invalid zstd chunk group: {err}")))?,
            Self::Lz4Block => lz4_flex::block::decompress_into(encoded, decoded)
                .map_err(|err| Error::InvalidImage(format!("invalid lz4 chunk group: {err}")))?,
        };
        if written != decoded.len() {
            return Err(Error::InvalidImage(format!(
                "{self} chunk group decompressed to {written} bytes, expected {}",
                decoded.len()
            )));
        }

        Ok(())
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
    fn compress_round_trips_through_decompress_into() {
        let payload = vec![0x5au8; 64 * 1024];
        let test_cases = vec![
            BlobMetadataCompressor::Zstd,
            BlobMetadataCompressor::Lz4Block,
        ];

        for compressor in test_cases {
            let encoded = compressor.compress(&payload).unwrap().unwrap();
            assert!(encoded.len() < payload.len(), "{compressor}");
            let mut decoded = vec![0u8; payload.len()];
            compressor.decompress_into(&encoded, &mut decoded).unwrap();
            assert_eq!(decoded, payload, "{compressor}");
            assert!(compressor
                .decompress_into(&encoded, &mut decoded[..payload.len() - 1])
                .is_err());
            assert!(compressor
                .decompress_into(&encoded[..encoded.len() / 2], &mut decoded)
                .is_err());
        }
    }

    #[test]
    fn the_plain_compressor_stores_payloads_as_they_are() {
        let payload = vec![0x5au8; 4096];
        assert!(BlobMetadataCompressor::None
            .compress(&payload)
            .unwrap()
            .is_none());
        assert!(BlobMetadataCompressor::None
            .decompress_into(&payload, &mut vec![0u8; 4096])
            .is_err());
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
