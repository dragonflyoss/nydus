//! The chunk digest algorithm a blob meta file declares as an enum code in
//! its ChunkGroupDigestTable header.

use crate::error::{Error, Result};
use std::fmt;

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

    /// Decodes a ChunkGroupDigestTable header code. An unknown code is an
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
