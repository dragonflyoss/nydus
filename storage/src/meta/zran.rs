// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::{BufReader, Read, Result};
use std::mem::size_of;
use std::slice;

use nydus_utils::compress::zlib_random::{ZranContext, ZranGenerator, ZranReader};

use crate::meta::chunk_info_v2::BlobChunkInfoV2Ondisk;
use crate::meta::{round_up_4k, BlobMetaChunkInfo};
use crate::RAFS_DEFAULT_CHUNK_SIZE;

/// Context information to support random access to zlib/gzip stream .
#[repr(C, packed)]
pub struct ZranInflateContext {
    /// Offset in the original compression data stream.
    in_offset: u64,
    /// Offset in the uncompressed data stream.
    out_offset: u64,
    /// Offset into the dictionary table to get the inflate dictionary.
    dict_offset: u64,
    /// Size of original compressed data.
    in_len: u32,
    /// Size of uncompressed data.
    out_len: u32,
    /// Size of inflate dictionary.
    dict_size: u32,
    /// Optional previous byte in the original compressed data stream, used when `ctx_bits` is non-zero.
    ctx_byte: u8,
    /// Bits from previous byte to feeds into the inflate context for random access.
    ctx_bits: u8,
    __reserved1: u8,
    __reserved2: u8,
}

impl ZranInflateContext {
    /// Get offset into the compressed stream.
    pub fn in_offset(&self) -> u64 {
        u64::from_le(self.in_offset)
    }

    /// Get size of compressed data.
    pub fn in_size(&self) -> u32 {
        u32::from_le(self.in_len)
    }

    /// Get offset into the decompressed stream.
    pub fn out_offset(&self) -> u64 {
        u64::from_le(self.out_offset)
    }

    /// Get size of the decompressed data.
    pub fn out_size(&self) -> u32 {
        u32::from_le(self.out_len)
    }

    /// Get offset into the dictionary table to fetch associated inflate dictionary.
    pub fn dict_offset(&self) -> u64 {
        u64::from_le(self.dict_offset)
    }

    /// Get size of the associated inflate dictionary.
    pub fn dict_size(&self) -> u32 {
        u32::from_le(self.dict_size)
    }

    /// Get the byte for zlib random decompression.
    pub fn ctx_byte(&self) -> u8 {
        self.ctx_byte
    }

    /// Get the byte for zlib random decompression.
    pub fn ctx_bits(&self) -> u8 {
        self.ctx_bits
    }

    /// Convert to an immutable u8 slice.
    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const ZranInflateContext as *const u8,
                size_of::<ZranInflateContext>(),
            )
        }
    }
}

impl From<&ZranInflateContext> for ZranContext {
    fn from(ctx: &ZranInflateContext) -> Self {
        ZranContext {
            in_offset: ctx.in_offset(),
            out_offset: ctx.out_offset(),
            in_len: ctx.in_size(),
            out_len: ctx.out_size(),
            ctx_byte: ctx.ctx_byte(),
            ctx_bits: ctx.ctx_bits(),
            dict: vec![],
        }
    }
}

/// Struct to generate [ZranInflateContext] objects for zlib/gzip stream.
pub struct ZranContextGenerator<R> {
    generator: ZranGenerator<R>,
    reader: ZranReader<R>,
    uncomp_pos: u64,
}

impl<R: Read> ZranContextGenerator<R> {
    /// Create a new instance of [ZranContextGenerator].
    pub fn new(file: R) -> Result<Self> {
        let reader = ZranReader::new(file)?;
        let mut generator = ZranGenerator::new(reader.clone());

        generator.set_min_compressed_size(RAFS_DEFAULT_CHUNK_SIZE / 2);
        generator.set_max_compressed_size(RAFS_DEFAULT_CHUNK_SIZE);
        generator.set_max_uncompressed_size(RAFS_DEFAULT_CHUNK_SIZE * 2);

        Ok(Self {
            generator,
            reader,
            uncomp_pos: 0,
        })
    }

    /// Create a new instance of [ZranContextGenerator] from a `BufReader`.
    pub fn from_buf_reader(buf_reader: BufReader<R>) -> Result<Self> {
        let buf = buf_reader.buffer().to_vec();
        let file = buf_reader.into_inner();

        let reader = ZranReader::new(file)?;
        reader.set_initial_data(&buf);

        let mut generator = ZranGenerator::new(reader.clone());
        generator.set_min_compressed_size(RAFS_DEFAULT_CHUNK_SIZE / 2);
        generator.set_max_compressed_size(RAFS_DEFAULT_CHUNK_SIZE);
        generator.set_max_uncompressed_size(RAFS_DEFAULT_CHUNK_SIZE * 2);

        Ok(Self {
            generator,
            reader,
            uncomp_pos: 0,
        })
    }

    /// Get reader to read decompressed data.
    pub fn reader(&self) -> ZranReader<R> {
        self.reader.clone()
    }

    /// Get number of zlib/gzip inflate context entries.
    pub fn len(&self) -> usize {
        self.generator.get_compression_ctx_array().len()
    }

    /// Check whether there's any zlib/gzip inflate context entries.
    pub fn is_empty(&self) -> bool {
        self.generator.get_compression_ctx_array().is_empty()
    }

    /// Begin transaction to generate a data chunk for a file.
    pub fn start_chunk(&mut self, chunk_size: u64) -> Result<u32> {
        self.generator.begin_read(chunk_size)
    }

    /// Finish the transaction to generate a data chunk and return the chunk info struct.
    pub fn finish_chunk(&mut self) -> Result<BlobChunkInfoV2Ondisk> {
        let info = self.generator.end_read()?;
        let mut chunk = BlobChunkInfoV2Ondisk::default();
        chunk.set_compressed_offset(info.in_pos);
        chunk.set_compressed_size(info.in_len);
        chunk.set_uncompressed_offset(self.uncomp_pos);
        chunk.set_uncompressed_size(info.ci_len);
        chunk.set_zran(true);
        chunk.set_zran_index(info.ci_index);
        chunk.set_zran_offset(info.ci_offset);
        chunk.set_compressed(true);
        chunk.set_encrypted(false);

        self.uncomp_pos += round_up_4k(info.ci_len as u64);

        Ok(chunk)
    }

    /// Convert all the zlib/gzip random access information to a u8 vector.
    pub fn to_vec(&self) -> Result<(Vec<u8>, u32)> {
        let mut data = Vec::new();
        let records = self.generator.get_compression_ctx_array();
        let mut dict_off = 0;

        for info in records {
            let ctx = ZranInflateContext {
                in_offset: u64::to_le(info.in_offset),
                out_offset: u64::to_le(info.out_offset),
                dict_offset: u64::to_le(dict_off),
                in_len: u32::to_le(info.in_len),
                out_len: u32::to_le(info.out_len),
                dict_size: u32::to_le(info.dict.len() as u32),
                ctx_byte: info.ctx_byte,
                ctx_bits: info.ctx_bits,
                __reserved1: 0,
                __reserved2: 0,
            };
            data.extend_from_slice(ctx.as_slice());
            dict_off += info.dict.len() as u64;
        }
        for info in records {
            if !info.dict.is_empty() {
                data.extend_from_slice(&info.dict);
            }
        }

        Ok((data, records.len() as u32))
    }
}

impl<R: Read> Read for ZranContextGenerator<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.generator.read(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::path::PathBuf;
    use tar::{Archive, EntryType};

    #[test]
    fn test_generate_chunk_info() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = PathBuf::from(root_dir).join("../tests/texture/zran/zran-two-streams.tar.gz");
        let file = OpenOptions::new().read(true).open(&path).unwrap();

        let mut generator = ZranContextGenerator::new(file).unwrap();
        let mut tar = Archive::new(generator.reader());
        tar.set_ignore_zeros(true);

        generator.generator.set_min_compressed_size(1024);
        generator.generator.set_max_compressed_size(2048);
        generator.generator.set_max_uncompressed_size(4096);

        assert_eq!(generator.len(), 0);

        let entries = tar.entries().unwrap();
        for entry in entries {
            let mut entry = entry.unwrap();
            if entry.header().entry_type() == EntryType::Regular {
                loop {
                    let _start = generator.start_chunk(4096).unwrap();
                    let mut buf = vec![0u8; 4096];
                    let sz = entry.read(&mut buf).unwrap();
                    if sz == 0 {
                        break;
                    }
                    let _chunk = generator.finish_chunk().unwrap();
                }
            }
        }

        assert_eq!(generator.len(), 3);
    }
}
