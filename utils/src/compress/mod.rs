// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::convert::TryFrom;
use std::fmt;
use std::io::{BufReader, Error, Read, Result, Write};
use std::str::FromStr;

mod lz4_standard;
use self::lz4_standard::*;

#[cfg(feature = "zran")]
pub mod zlib_random;

const COMPRESSION_MINIMUM_RATIO: usize = 100;

/// Supported compression algorithms.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum Algorithm {
    #[default]
    None = 0,
    Lz4Block = 1,
    GZip = 2,
    Zstd = 3,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "none" => Ok(Self::None),
            "lz4_block" => Ok(Self::Lz4Block),
            "gzip" => Ok(Self::GZip),
            "zstd" => Ok(Self::Zstd),
            _ => Err(einval!("compression algorithm should be none or lz4_block")),
        }
    }
}

impl TryFrom<u32> for Algorithm {
    type Error = ();

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        if value == Algorithm::None as u32 {
            Ok(Algorithm::None)
        } else if value == Algorithm::Lz4Block as u32 {
            Ok(Algorithm::Lz4Block)
        } else if value == Algorithm::GZip as u32 {
            Ok(Algorithm::GZip)
        } else if value == Algorithm::Zstd as u32 {
            Ok(Algorithm::Zstd)
        } else {
            Err(())
        }
    }
}

impl TryFrom<u64> for Algorithm {
    type Error = ();

    fn try_from(value: u64) -> std::result::Result<Self, Self::Error> {
        if value == Algorithm::None as u64 {
            Ok(Algorithm::None)
        } else if value == Algorithm::Lz4Block as u64 {
            Ok(Algorithm::Lz4Block)
        } else if value == Algorithm::GZip as u64 {
            Ok(Algorithm::GZip)
        } else if value == Algorithm::Zstd as u64 {
            Ok(Algorithm::Zstd)
        } else {
            Err(())
        }
    }
}

impl Algorithm {
    /// Check whether the compression algorithm is none.
    pub fn is_none(self) -> bool {
        self == Self::None
    }
}

/// Compress data with the specified compression algorithm.
pub fn compress(src: &[u8], algorithm: Algorithm) -> Result<(Cow<[u8]>, bool)> {
    let src_size = src.len();
    if src_size == 0 {
        return Ok((Cow::Borrowed(src), false));
    }

    let compressed = match algorithm {
        Algorithm::None => return Ok((Cow::Borrowed(src), false)),
        Algorithm::Lz4Block => lz4_compress(src)?,
        Algorithm::GZip => {
            let dst: Vec<u8> = Vec::new();
            let mut gz = flate2::write::GzEncoder::new(dst, flate2::Compression::default());
            gz.write_all(src)?;
            gz.finish()?
        }
        Algorithm::Zstd => zstd_compress(src)?,
    };

    // Abandon compressed data when compression ratio greater than COMPRESSION_MINIMUM_RATIO
    if (COMPRESSION_MINIMUM_RATIO == 100 && compressed.len() >= src_size)
        || ((100 * compressed.len() / src_size) >= COMPRESSION_MINIMUM_RATIO)
    {
        Ok((Cow::Borrowed(src), false))
    } else {
        Ok((Cow::Owned(compressed), true))
    }
}

/// Decompress a source slice or file stream into destination slice, with provided compression algorithm.
/// Use the file as decompress source if provided.
pub fn decompress(src: &[u8], dst: &mut [u8], algorithm: Algorithm) -> Result<usize> {
    match algorithm {
        Algorithm::None => {
            assert_eq!(src.len(), dst.len());
            dst.copy_from_slice(src);
            Ok(dst.len())
        }
        Algorithm::Lz4Block => lz4_decompress(src, dst),
        Algorithm::GZip => {
            let mut gz = flate2::bufread::GzDecoder::new(src);
            gz.read_exact(dst)?;
            Ok(dst.len())
        }
        Algorithm::Zstd => zstd::bulk::decompress_to_buffer(src, dst),
    }
}

#[allow(clippy::large_enum_variant)]
/// Stream decoder for gzip/lz4/zstd.
pub enum Decoder<'a, R: Read> {
    None(R),
    Gzip(flate2::bufread::GzDecoder<BufReader<R>>),
    Zstd(zstd::stream::Decoder<'a, BufReader<R>>),
}

impl<'a, R: Read> Decoder<'a, R> {
    /// Create a new instance of `Decoder`.
    pub fn new(reader: R, algorithm: Algorithm) -> Result<Self> {
        let decoder = match algorithm {
            Algorithm::None => Decoder::None(reader),
            Algorithm::GZip => {
                Decoder::Gzip(flate2::bufread::GzDecoder::new(BufReader::new(reader)))
            }
            Algorithm::Lz4Block => panic!("Decoder doesn't support lz4_block"),
            Algorithm::Zstd => Decoder::Zstd(zstd::stream::Decoder::new(reader)?),
        };
        Ok(decoder)
    }
}

impl<'a, R: Read> Read for Decoder<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            Decoder::None(r) => r.read(buf),
            Decoder::Gzip(r) => r.read(buf),
            Decoder::Zstd(r) => r.read(buf),
        }
    }
}

/// Stream decoder for zlib/gzip.
pub struct ZlibDecoder<R> {
    stream: flate2::bufread::GzDecoder<BufReader<R>>,
}

impl<R: Read> ZlibDecoder<R> {
    /// Create a new instance of `ZlibDecoder`.
    pub fn new(reader: R) -> Self {
        ZlibDecoder {
            stream: flate2::bufread::GzDecoder::new(BufReader::new(reader)),
        }
    }
}

impl<R: Read> Read for ZlibDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.stream.read(buf)
    }
}

/// Estimate the maximum compressed data size from uncompressed data size.
///
/// Gzip is special that it doesn't carry compress_size. We need to read the maximum possible size
/// of compressed data for `chunk_decompress_size`, and try to decompress `chunk_decompress_size`
/// bytes of data out of it.
//
// Per man(1) gzip
// The worst case expansion is a few bytes for the gzip file header, plus 5 bytes every 32K block,
// or an expansion ratio of 0.015% for large files.
//
// Per http://www.zlib.org/rfc-gzip.html#header-trailer, each member has the following structure:
// +---+---+---+---+---+---+---+---+---+---+
// |ID1|ID2|CM |FLG|     MTIME     |XFL|OS | (more-->)
// +---+---+---+---+---+---+---+---+---+---+
// (if FLG.FEXTRA set)
// +---+---+=================================+
// | XLEN  |...XLEN bytes of "extra field"...| (more-->)
// +---+---+=================================+
// (if FLG.FNAME set)
// +=========================================+
// |...original file name, zero-terminated...| (more-->)
// +=========================================+
// (if FLG.FCOMMENT set)
// +===================================+
// |...file comment, zero-terminated...| (more-->)
// +===================================+
// (if FLG.FHCRC set)
// +---+---+
// | CRC16 |
// +---+---+
// +=======================+
// |...compressed blocks...| (more-->)
// +=======================+
//   0   1   2   3   4   5   6   7
// +---+---+---+---+---+---+---+---+
// |     CRC32     |     ISIZE     |
// +---+---+---+---+---+---+---+---+
// gzip head+footer is at least 10+8 bytes, stargz header doesn't include any flags
// so it's 18 bytes. Let's read at least 128 bytes more, to allow the decompressor to
// find out end of the gzip stream.
//
// Ideally we should introduce a streaming cache for stargz that maintains internal
// chunks and expose stream APIs.
pub fn compute_compressed_gzip_size(size: usize, max_size: usize) -> usize {
    let size = size + 10 + 8 + 5 + (size / (16 << 10)) * 5 + 128;

    std::cmp::min(size, max_size)
}

fn zstd_compress(src: &[u8]) -> Result<Vec<u8>> {
    zstd::bulk::compress(src, zstd::DEFAULT_COMPRESSION_LEVEL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom};
    use std::path::Path;
    use vmm_sys_util::tempfile::TempFile;

    #[test]
    fn test_compress_algorithm_gzip() {
        let buf = vec![0x2u8; 4095];
        let compressed = compress(&buf, Algorithm::GZip).unwrap();
        assert!(compressed.1);
        let (compressed, _) = compressed;
        assert_ne!(compressed.len(), 0);

        let mut decompressed = vec![0; buf.len()];
        let sz = decompress(&compressed, decompressed.as_mut_slice(), Algorithm::GZip).unwrap();
        assert_eq!(sz, 4095);
        assert_eq!(buf, decompressed);

        let mut tmp_file = TempFile::new().unwrap().into_file();
        tmp_file.write_all(&compressed).unwrap();
        tmp_file.seek(SeekFrom::Start(0)).unwrap();

        let mut decompressed = vec![0; buf.len()];
        let mut decoder = Decoder::new(tmp_file, Algorithm::GZip).unwrap();
        decoder.read_exact(decompressed.as_mut_slice()).unwrap();
        assert_eq!(sz, 4095);
        assert_eq!(buf, decompressed);
    }

    #[test]
    fn test_compress_algorithm_none() {
        let buf = [
            0x1u8, 0x2u8, 0x3u8, 0x4u8, 0x1u8, 0x2u8, 0x3u8, 0x4u8, 0x1u8, 0x2u8, 0x3u8, 0x4u8,
            0x1u8, 0x2u8, 0x3u8, 0x4u8,
        ];
        let (compressed, _) = compress(&buf, Algorithm::None).unwrap();

        assert_eq!(buf.to_vec(), compressed.to_vec());
    }

    #[test]
    fn test_lz4_compress_decompress_1_byte() {
        let buf = vec![0x1u8];
        let compressed = lz4_compress(&buf).unwrap();
        let mut decompressed = vec![0; buf.len()];
        let sz = decompress(
            &compressed,
            decompressed.as_mut_slice(),
            Algorithm::Lz4Block,
        )
        .unwrap();

        assert_eq!(sz, 1);
        assert_eq!(buf, decompressed);
    }

    #[test]
    fn test_lz4_compress_decompress_2_bytes() {
        let buf = vec![0x2u8, 0x3u8];
        let compressed = lz4_compress(&buf).unwrap();
        let mut decompressed = vec![0; buf.len()];
        let sz = decompress(
            &compressed,
            decompressed.as_mut_slice(),
            Algorithm::Lz4Block,
        )
        .unwrap();

        assert_eq!(sz, 2);
        assert_eq!(buf, decompressed);
    }

    #[test]
    fn test_lz4_compress_decompress_16_bytes() {
        let buf = [
            0x1u8, 0x2u8, 0x3u8, 0x4u8, 0x1u8, 0x2u8, 0x3u8, 0x4u8, 0x1u8, 0x2u8, 0x3u8, 0x4u8,
            0x1u8, 0x2u8, 0x3u8, 0x4u8,
        ];
        let compressed = lz4_compress(&buf).unwrap();
        let mut decompressed = vec![0; buf.len()];
        let sz = decompress(
            &compressed,
            decompressed.as_mut_slice(),
            Algorithm::Lz4Block,
        )
        .unwrap();

        assert_eq!(sz, 16);
        assert_eq!(&buf, decompressed.as_slice());
    }

    #[test]
    fn test_lz4_compress_decompress_4095_bytes() {
        let buf = vec![0x2u8; 4095];
        let compressed = lz4_compress(&buf).unwrap();
        let mut decompressed = vec![0; buf.len()];
        let sz = decompress(
            &compressed,
            decompressed.as_mut_slice(),
            Algorithm::Lz4Block,
        )
        .unwrap();

        assert_eq!(sz, 4095);
        assert_eq!(buf, decompressed);
    }

    #[test]
    fn test_lz4_compress_decompress_4096_bytes() {
        let buf = vec![0x2u8; 4096];
        let compressed = lz4_compress(&buf).unwrap();
        let mut decompressed = vec![0; buf.len()];
        let sz = decompress(
            &compressed,
            decompressed.as_mut_slice(),
            Algorithm::Lz4Block,
        )
        .unwrap();

        assert_eq!(sz, 4096);
        assert_eq!(buf, decompressed);
    }

    #[test]
    fn test_lz4_compress_decompress_4097_bytes() {
        let buf = vec![0x2u8; 4097];
        let compressed = lz4_compress(&buf).unwrap();
        let mut decompressed = vec![0; buf.len()];
        let sz = decompress(
            &compressed,
            decompressed.as_mut_slice(),
            Algorithm::Lz4Block,
        )
        .unwrap();

        assert_eq!(sz, 4097);
        assert_eq!(buf, decompressed);
    }

    #[test]
    fn test_zstd_compress_decompress_1_byte() {
        let buf = vec![0x1u8];
        let compressed = zstd_compress(&buf).unwrap();
        let mut decompressed = vec![0; buf.len()];
        let sz = decompress(&compressed, decompressed.as_mut_slice(), Algorithm::Zstd).unwrap();

        assert_eq!(sz, 1);
        assert_eq!(buf, decompressed);
    }

    #[test]
    fn test_zstd_compress_decompress_2_bytes() {
        let buf = vec![0x2u8, 0x3u8];
        let compressed = zstd_compress(&buf).unwrap();
        let mut decompressed = vec![0; buf.len()];
        let sz = decompress(&compressed, decompressed.as_mut_slice(), Algorithm::Zstd).unwrap();

        assert_eq!(sz, 2);
        assert_eq!(buf, decompressed);
    }

    #[test]
    fn test_zstd_compress_decompress_16_bytes() {
        let buf = [
            0x1u8, 0x2u8, 0x3u8, 0x4u8, 0x1u8, 0x2u8, 0x3u8, 0x4u8, 0x1u8, 0x2u8, 0x3u8, 0x4u8,
            0x1u8, 0x2u8, 0x3u8, 0x4u8,
        ];
        let compressed = zstd_compress(&buf).unwrap();
        let mut decompressed = vec![0; buf.len()];
        let sz = decompress(&compressed, decompressed.as_mut_slice(), Algorithm::Zstd).unwrap();

        assert_eq!(sz, 16);
        assert_eq!(&buf, decompressed.as_slice());
    }

    #[test]
    fn test_zstd_compress_decompress_4095_bytes() {
        let buf = vec![0x2u8; 4095];
        let compressed = zstd_compress(&buf).unwrap();
        let mut decompressed = vec![0; buf.len()];
        let sz = decompress(&compressed, decompressed.as_mut_slice(), Algorithm::Zstd).unwrap();

        assert_eq!(sz, 4095);
        assert_eq!(buf, decompressed);
    }

    #[test]
    fn test_zstd_compress_decompress_4096_bytes() {
        let buf = vec![0x2u8; 4096];
        let compressed = zstd_compress(&buf).unwrap();
        let mut decompressed = vec![0; buf.len()];
        let sz = decompress(&compressed, decompressed.as_mut_slice(), Algorithm::Zstd).unwrap();

        assert_eq!(sz, 4096);
        assert_eq!(buf, decompressed);
    }

    #[test]
    fn test_zstd_compress_decompress_4097_bytes() {
        let buf = vec![0x2u8; 4097];
        let compressed = zstd_compress(&buf).unwrap();
        let mut decompressed = vec![0; buf.len()];
        let sz = decompress(&compressed, decompressed.as_mut_slice(), Algorithm::Zstd).unwrap();

        assert_eq!(sz, 4097);
        assert_eq!(buf, decompressed);
    }

    #[test]
    fn test_new_decoder_none() {
        let buf = b"This is a test";
        let mut decoder = Decoder::new(buf.as_slice(), Algorithm::None).unwrap();
        let mut buf2 = vec![0u8; 1024];
        let res = decoder.read(&mut buf2).unwrap();
        assert_eq!(res, 14);
        assert_eq!(&buf2[0..14], buf.as_slice());
    }

    #[test]
    fn test_gzip_decoder() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = Path::new(root_dir).join("../tests/texture/zran/zlib_sample.txt.gz");
        let file = OpenOptions::new().read(true).open(&path).unwrap();
        let mut decoder = Decoder::new(file, Algorithm::GZip).unwrap();
        let mut buf = [0u8; 8];

        decoder.read_exact(&mut buf).unwrap();
        assert_eq!(&String::from_utf8_lossy(&buf), "This is ");
        decoder.read_exact(&mut buf).unwrap();
        assert_eq!(&String::from_utf8_lossy(&buf), "a test f");
        decoder.read_exact(&mut buf).unwrap();
        assert_eq!(&String::from_utf8_lossy(&buf), "ile for ");
        let ret = decoder.read(&mut buf).unwrap();
        assert_eq!(ret, 6);
        assert_eq!(&String::from_utf8_lossy(&buf[0..6]), "zlib.\n");
        let ret = decoder.read(&mut buf).unwrap();
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_zlib_decoder() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = Path::new(root_dir).join("../tests/texture/zran/zlib_sample.txt.gz");
        let file = OpenOptions::new().read(true).open(&path).unwrap();
        let mut decoder = ZlibDecoder::new(file);
        let mut buf = [0u8; 8];

        decoder.read_exact(&mut buf).unwrap();
        assert_eq!(&String::from_utf8_lossy(&buf), "This is ");
        decoder.read_exact(&mut buf).unwrap();
        assert_eq!(&String::from_utf8_lossy(&buf), "a test f");
        decoder.read_exact(&mut buf).unwrap();
        assert_eq!(&String::from_utf8_lossy(&buf), "ile for ");
        let ret = decoder.read(&mut buf).unwrap();
        assert_eq!(ret, 6);
        assert_eq!(&String::from_utf8_lossy(&buf[0..6]), "zlib.\n");
        let ret = decoder.read(&mut buf).unwrap();
        assert_eq!(ret, 0);
    }
}
