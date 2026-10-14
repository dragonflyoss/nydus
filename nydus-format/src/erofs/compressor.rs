//! The z_erofs pcluster compressor an image declares as an algorithm code
//! in its map headers, and the COMPR_CFGS records behind its superblock.

use crate::erofs::{
    Z_EROFS_LZ4_MAX_DISTANCE, Z_EROFS_ZSTD_MAX_WINDOWLOG, Z_EROFS_ZSTD_WINDOWLOG_BASE,
};
use crate::error::{Error, Result};
use crate::utils::bytes::{read_u16_at, write_u16_at};
use std::fmt;

/// The z_erofs pcluster compressor, `Z_EROFS_COMPRESSION_*` in the kernel:
/// the low nibble of `z_erofs_map_header.h_algorithmtype` and its bit in
/// the superblock's `available_compr_algs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZErofsCompressor {
    /// LZ4 blocks (kernel 5.x+).
    Lz4,

    /// zstd frames (kernel 6.10+).
    Zstd,
}

/// Maps the compressor to and from the code the map header and the
/// superblock store.
impl ZErofsCompressor {
    /// The `h_algorithmtype` value, also the bit index in
    /// `available_compr_algs`.
    pub fn code(self) -> u8 {
        match self {
            Self::Lz4 => 0,
            Self::Zstd => 3,
        }
    }

    /// Decodes an `h_algorithmtype` nibble. An unknown compressor rejects
    /// the image, since its pclusters cannot be decoded.
    pub fn from_code(code: u8) -> Result<Self> {
        match code {
            0 => Ok(Self::Lz4),
            3 => Ok(Self::Zstd),
            _ => Err(Error::Unsupported(format!(
                "unsupported z_erofs algorithm {code} (image is newer than this reader)"
            ))),
        }
    }
}

/// Names the compressor in the `build` and `check` summaries.
impl fmt::Display for ZErofsCompressor {
    /// The lowercase algorithm name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Lz4 => "lz4",
            Self::Zstd => "zstd",
        })
    }
}

/// The compressors an image declares and their COMPR_CFGS records, the
/// kernel's `z_erofs_lz4_cfgs` and `z_erofs_zstd_cfgs`: `available_compr_algs`
/// in the superblock, and right after the superblock one record per set
/// bit in code order. Only the compressors this crate produces are
/// representable; parsing rejects any other bit.
///
/// ```text
/// offset  size  LZ4 record (z_erofs_lz4_cfgs)
///      0     2  size                    14
///      2     2  max_distance            Z_EROFS_LZ4_MAX_DISTANCE
///      4     2  max_pclusterblks
///      6    10  reserved
///
/// offset  size  zstd record (z_erofs_zstd_cfgs)
///      0     2  size                    6
///      2     1  format                  0
///      3     1  windowlog               absolute log2 minus
///                                       Z_EROFS_ZSTD_WINDOWLOG_BASE
///      4     4  reserved
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ZErofsComprCfgs {
    /// LZ4 `max_pclusterblks` (the record's `max_distance` is always
    /// [`Z_EROFS_LZ4_MAX_DISTANCE`]), `Some` when LZ4 pclusters may occur.
    pub lz4_max_pclusterblks: Option<u16>,

    /// zstd window log2 (absolute, e.g. 19 for 512KiB), `Some` when zstd
    /// pclusters may occur.
    pub zstd_windowlog: Option<u8>,
}

/// Writes and reads the records, and answers which compressors an image
/// declares.
impl ZErofsComprCfgs {
    /// Upper bound of the serialized records: 16 bytes LZ4 + 8 bytes zstd.
    pub const MAX_SIZE: usize = Self::LZ4_RECORD_SIZE + Self::ZSTD_RECORD_SIZE;

    /// Size of the LZ4 record, its `le16 size` included.
    const LZ4_RECORD_SIZE: usize = 16;

    /// Size of the zstd record, its `le16 size` included.
    const ZSTD_RECORD_SIZE: usize = 8;

    /// Whether no compressor is declared, so the image is not a z_erofs
    /// image.
    pub fn is_empty(&self) -> bool {
        self.lz4_max_pclusterblks.is_none() && self.zstd_windowlog.is_none()
    }

    /// The `available_compr_algs` bit mask.
    pub fn available_compr_algs(&self) -> u16 {
        let mut available_compr_algs = 0u16;
        if self.lz4_max_pclusterblks.is_some() {
            available_compr_algs |= 1 << ZErofsCompressor::Lz4.code();
        }

        if self.zstd_windowlog.is_some() {
            available_compr_algs |= 1 << ZErofsCompressor::Zstd.code();
        }

        available_compr_algs
    }

    /// Whether pclusters of `compressor` are declared.
    pub fn contains(&self, compressor: ZErofsCompressor) -> bool {
        match compressor {
            ZErofsCompressor::Lz4 => self.lz4_max_pclusterblks.is_some(),
            ZErofsCompressor::Zstd => self.zstd_windowlog.is_some(),
        }
    }

    /// The union of two images' configs (a merged image must decode every
    /// layer): per compressor the larger limit wins.
    pub fn union(self, other: Self) -> Self {
        Self {
            lz4_max_pclusterblks: self.lz4_max_pclusterblks.max(other.lz4_max_pclusterblks),
            zstd_windowlog: self.zstd_windowlog.max(other.zstd_windowlog),
        }
    }

    /// Serializes the records as laid out after the superblock.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::MAX_SIZE);
        if let Some(max_pclusterblks) = self.lz4_max_pclusterblks {
            let mut record = [0u8; Self::LZ4_RECORD_SIZE];
            write_u16_at(&mut record, 0, (Self::LZ4_RECORD_SIZE - 2) as u16);
            write_u16_at(&mut record, 2, Z_EROFS_LZ4_MAX_DISTANCE);
            write_u16_at(&mut record, 4, max_pclusterblks);
            bytes.extend_from_slice(&record);
        }

        if let Some(windowlog) = self.zstd_windowlog {
            let mut record = [0u8; Self::ZSTD_RECORD_SIZE];
            write_u16_at(&mut record, 0, (Self::ZSTD_RECORD_SIZE - 2) as u16);
            record[3] = windowlog - Z_EROFS_ZSTD_WINDOWLOG_BASE;
            bytes.extend_from_slice(&record);
        }

        bytes
    }

    /// Parses the records from the bytes after the superblock for the
    /// compressors in `available_compr_algs`, the kernel's
    /// `z_erofs_parse_cfgs`. Returns the configs and the number of bytes
    /// consumed.
    pub fn from_bytes(bytes: &[u8], available_compr_algs: u16) -> Result<(Self, usize)> {
        let mut compr_cfgs = Self::default();
        let mut offset = 0usize;
        for code in (0..u16::BITS as u8).filter(|code| available_compr_algs & (1 << code) != 0) {
            let compressor = ZErofsCompressor::from_code(code)?;
            let record = Self::record_at(bytes, offset)?;
            Self::validate_record(compressor, record)?;

            match compressor {
                ZErofsCompressor::Lz4 => {
                    compr_cfgs.lz4_max_pclusterblks = Some(read_u16_at(record, 2))
                }
                ZErofsCompressor::Zstd => {
                    compr_cfgs.zstd_windowlog = Some(record[1] + Z_EROFS_ZSTD_WINDOWLOG_BASE)
                }
            }

            offset += 2 + record.len();
        }

        Ok((compr_cfgs, offset))
    }

    /// The record at `offset`, the bytes behind its `le16 size`.
    fn record_at(bytes: &[u8], offset: usize) -> Result<&[u8]> {
        bytes
            .get(offset..offset + 2)
            .map(|size| read_u16_at(size, 0) as usize)
            .and_then(|size| bytes.get(offset + 2..offset + 2 + size))
            .ok_or_else(|| Error::InvalidImage("truncated z_erofs compression config".to_string()))
    }

    /// Validates one record's bytes before decoding them: long enough for
    /// the fields read, and for zstd a format and window this crate
    /// decodes.
    fn validate_record(compressor: ZErofsCompressor, record: &[u8]) -> Result<()> {
        match compressor {
            ZErofsCompressor::Lz4 => {
                if record.len() < 4 {
                    return Err(Error::InvalidImage("short z_erofs LZ4 config".to_string()));
                }
            }
            ZErofsCompressor::Zstd => {
                if record.len() < 2 {
                    return Err(Error::InvalidImage("short z_erofs zstd config".to_string()));
                }
                if record[0] != 0 {
                    return Err(Error::Unsupported(format!(
                        "unsupported z_erofs zstd format {}",
                        record[0]
                    )));
                }
                if record[1] > Z_EROFS_ZSTD_MAX_WINDOWLOG - Z_EROFS_ZSTD_WINDOWLOG_BASE {
                    return Err(Error::Unsupported(format!(
                        "unsupported z_erofs zstd windowlog encoding {}",
                        record[1]
                    )));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOTH: ZErofsComprCfgs = ZErofsComprCfgs {
        lz4_max_pclusterblks: Some(16),
        zstd_windowlog: Some(19),
    };

    const ZSTD_ONLY: ZErofsComprCfgs = ZErofsComprCfgs {
        lz4_max_pclusterblks: None,
        zstd_windowlog: Some(20),
    };

    #[test]
    fn compressor_formats_as_its_name() {
        let test_cases = vec![
            (ZErofsCompressor::Lz4, "lz4"),
            (ZErofsCompressor::Zstd, "zstd"),
        ];

        for (compressor, expected) in test_cases {
            assert_eq!(compressor.to_string(), expected);
        }
    }

    #[test]
    fn compressor_from_code_accepts_lz4_and_zstd() {
        let test_cases = vec![
            (0, Ok(ZErofsCompressor::Lz4)),
            (
                1,
                Err("unsupported z_erofs algorithm 1 (image is newer than this reader)"),
            ),
            (
                2,
                Err("unsupported z_erofs algorithm 2 (image is newer than this reader)"),
            ),
            (3, Ok(ZErofsCompressor::Zstd)),
            (
                15,
                Err("unsupported z_erofs algorithm 15 (image is newer than this reader)"),
            ),
        ];

        for (code, expected) in test_cases {
            let compressor = ZErofsCompressor::from_code(code).map_err(|err| err.to_string());
            assert_eq!(compressor, expected.map_err(String::from));
            if let Ok(compressor) = compressor {
                assert_eq!(compressor.code(), code);
            }
        }
    }

    #[test]
    fn to_bytes_writes_the_records_in_code_order() {
        let test_cases = vec![
            (ZErofsComprCfgs::default(), 0, Vec::new()),
            (
                BOTH,
                0b1001,
                vec![
                    14, 0, 0xff, 0xff, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 9, 0, 0, 0, 0,
                ],
            ),
            (ZSTD_ONLY, 0b1000, vec![6, 0, 0, 10, 0, 0, 0, 0]),
        ];

        for (compr_cfgs, available_compr_algs, expected) in test_cases {
            assert_eq!(compr_cfgs.available_compr_algs(), available_compr_algs);
            assert_eq!(compr_cfgs.to_bytes(), expected);
            assert_eq!(
                ZErofsComprCfgs::from_bytes(&expected, available_compr_algs).unwrap(),
                (compr_cfgs, expected.len())
            );
        }
    }

    #[test]
    fn from_bytes_rejects_unknown_compressors_and_malformed_records() {
        let both = BOTH.to_bytes();
        let mut bad_format = ZSTD_ONLY.to_bytes();
        bad_format[2] = 1;
        let mut bad_windowlog = ZSTD_ONLY.to_bytes();
        bad_windowlog[3] = Z_EROFS_ZSTD_MAX_WINDOWLOG - Z_EROFS_ZSTD_WINDOWLOG_BASE + 1;

        let test_cases = vec![
            (
                0b0010,
                both.clone(),
                "unsupported z_erofs algorithm 1 (image is newer than this reader)",
            ),
            (
                0b1001,
                both[..1].to_vec(),
                "truncated z_erofs compression config",
            ),
            (
                0b1001,
                both[..20].to_vec(),
                "truncated z_erofs compression config",
            ),
            (0b0001, vec![2, 0, 0xff, 0xff], "short z_erofs LZ4 config"),
            (0b1000, vec![1, 0, 0], "short z_erofs zstd config"),
            (0b1000, bad_format, "unsupported z_erofs zstd format 1"),
            (
                0b1000,
                bad_windowlog,
                "unsupported z_erofs zstd windowlog encoding 11",
            ),
        ];

        for (available_compr_algs, bytes, expected) in test_cases {
            assert_eq!(
                ZErofsComprCfgs::from_bytes(&bytes, available_compr_algs)
                    .unwrap_err()
                    .to_string(),
                expected
            );
        }
    }

    #[test]
    fn contains_and_is_empty_follow_the_declared_compressors() {
        let test_cases = vec![
            (ZErofsComprCfgs::default(), true, false, false),
            (BOTH, false, true, true),
            (ZSTD_ONLY, false, false, true),
        ];

        for (compr_cfgs, empty, lz4, zstd) in test_cases {
            assert_eq!(compr_cfgs.is_empty(), empty);
            assert_eq!(compr_cfgs.contains(ZErofsCompressor::Lz4), lz4);
            assert_eq!(compr_cfgs.contains(ZErofsCompressor::Zstd), zstd);
        }
    }

    #[test]
    fn union_keeps_the_larger_limit_per_compressor() {
        let expected = ZErofsComprCfgs {
            lz4_max_pclusterblks: Some(16),
            zstd_windowlog: Some(20),
        };

        assert_eq!(BOTH.union(ZSTD_ONLY), expected);
        assert_eq!(ZSTD_ONLY.union(BOTH), expected);
        assert_eq!(BOTH.union(ZErofsComprCfgs::default()), BOTH);
    }
}
