// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use std::io::{BufReader, Read, Result};
use std::mem::size_of;
use std::slice;

use nydus_utils::compress::zlib_random::{ZranContext, ZranGenerator, ZranReader};

use crate::meta::chunk_info_v2::BlobChunkInfoV2Ondisk;
use crate::meta::{round_up_4k, BlobMetaChunkArray, BlobMetaChunkInfo};
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

/// Serialized ZRan metadata for the chunks retained in one blob.
pub struct ZranBlobMeta {
    /// A copy of the chunk table with indexes into the compacted context table.
    pub chunks: BlobMetaChunkArray,
    /// The compacted context table followed by its dictionaries.
    pub inflate_data: Vec<u8>,
    /// Number of entries in the compacted context table.
    pub inflate_count: u32,
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
        let records = self
            .generator
            .get_compression_ctx_array()
            .iter()
            .collect::<Vec<_>>();
        Self::serialize_contexts(&records)
    }

    /// Serialize only contexts referenced by a blob's final V2 ZRan chunk table.
    ///
    /// Contexts retain their original order, and the returned chunk table is a copy with
    /// remapped indexes. Neither the generator nor the input table is changed, so the same
    /// generator can be used to serialize different blobs or the same blob again.
    pub fn to_blob_meta(&self, chunks: &BlobMetaChunkArray) -> Result<ZranBlobMeta> {
        let mut chunks = match chunks {
            BlobMetaChunkArray::V2(chunks) => chunks.to_vec(),
            BlobMetaChunkArray::V1(_) => return Err(einval!("ZRan requires a V2 chunk table")),
        };
        let records = self.generator.get_compression_ctx_array();
        let mut referenced = vec![false; records.len()];
        for chunk in &chunks {
            // get_zran_index also rejects non-ZRan entries, before any indexes are remapped.
            let index = chunk.get_zran_index()? as usize;
            if index >= records.len() {
                return Err(einval!(format!(
                    "ZRan index {} is too big, max {}",
                    index,
                    records.len()
                )));
            }
            referenced[index] = true;
        }

        let mut indexes = vec![0u32; records.len()];
        let mut retained = Vec::new();
        for (index, record) in records.iter().enumerate() {
            if referenced[index] {
                indexes[index] = u32::try_from(retained.len())
                    .map_err(|_| einval!("too many ZRan context entries"))?;
                retained.push(record);
            }
        }
        for chunk in &mut chunks {
            let index = chunk.get_zran_index()? as usize;
            chunk.set_zran_index(indexes[index]);
        }
        let (inflate_data, inflate_count) = Self::serialize_contexts(&retained)?;

        Ok(ZranBlobMeta {
            chunks: BlobMetaChunkArray::V2(chunks.into()),
            inflate_data,
            inflate_count,
        })
    }

    fn serialize_contexts(records: &[&ZranContext]) -> Result<(Vec<u8>, u32)> {
        let count =
            u32::try_from(records.len()).map_err(|_| einval!("too many ZRan context entries"))?;
        let mut data = Vec::new();
        let mut dict_off = 0u64;

        for info in records {
            let dict_size = u32::try_from(info.dict.len())
                .map_err(|_| einval!("ZRan dictionary is too large"))?;
            let ctx = ZranInflateContext {
                in_offset: u64::to_le(info.in_offset),
                out_offset: u64::to_le(info.out_offset),
                dict_offset: u64::to_le(dict_off),
                in_len: u32::to_le(info.in_len),
                out_len: u32::to_le(info.out_len),
                dict_size: u32::to_le(dict_size),
                ctx_byte: info.ctx_byte,
                ctx_bits: info.ctx_bits,
                __reserved1: 0,
                __reserved2: 0,
            };
            data.extend_from_slice(ctx.as_slice());
            dict_off = dict_off
                .checked_add(dict_size as u64)
                .ok_or_else(|| einval!("ZRan dictionary offset overflow"))?;
        }
        for info in records {
            if !info.dict.is_empty() {
                data.extend_from_slice(&info.dict);
            }
        }

        Ok((data, count))
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
    use nydus_utils::compress::{self, zlib_random::ZranDecoder};
    use std::fs::OpenOptions;
    use std::io::Cursor;
    use std::path::PathBuf;
    use tar::{Archive, EntryType};

    const COMPACT_CHUNK_SIZE: usize = 64 * 1024;

    struct CompactFixture {
        generator: ZranContextGenerator<Cursor<Vec<u8>>>,
        chunks: Vec<BlobChunkInfoV2Ondisk>,
        compressed: Vec<u8>,
        contents: Vec<Vec<u8>>,
    }

    impl CompactFixture {
        fn select_chunks(&self, indexes: &[usize]) -> BlobMetaChunkArray {
            let chunks: Vec<_> = indexes.iter().map(|index| self.chunks[*index]).collect();
            BlobMetaChunkArray::V2(chunks.into())
        }

        fn assert_decodes(
            &self,
            source: &BlobMetaChunkArray,
            meta: &ZranBlobMeta,
            expected_indexes: &[u32],
        ) {
            let source = match source {
                BlobMetaChunkArray::V2(chunks) => chunks,
                _ => unreachable!(),
            };
            let chunks = match &meta.chunks {
                BlobMetaChunkArray::V2(chunks) => chunks,
                _ => unreachable!(),
            };
            assert_eq!(source.len(), chunks.len());
            assert_eq!(source.len(), expected_indexes.len());

            // The index is the only part of a chunk record that compaction may change.
            let mut expected = source.to_vec();
            for (chunk, index) in expected.iter_mut().zip(expected_indexes) {
                chunk.set_zran_index(*index);
            }
            assert_eq!(
                BlobMetaChunkArray::V2(expected.into()).as_byte_slice(),
                meta.chunks.as_byte_slice()
            );

            let table_size = meta.inflate_count as usize * size_of::<ZranInflateContext>();
            for (original_chunk, chunk) in source.iter().zip(chunks.iter()) {
                let original_index = original_chunk.get_zran_index().unwrap() as usize;
                let original =
                    &self.generator.generator.get_compression_ctx_array()[original_index];
                let index = chunk.get_zran_index().unwrap() as usize;
                assert!(index < meta.inflate_count as usize);
                let offset = index * size_of::<ZranInflateContext>();
                // The serialized context consists only of integer fields, and the complete
                // record lies in the context table. It need not have the Vec's alignment.
                let entry = unsafe {
                    std::ptr::read_unaligned::<ZranInflateContext>(
                        meta.inflate_data[offset..].as_ptr().cast(),
                    )
                };
                assert_eq!(entry.in_offset(), original.in_offset);
                assert_eq!(entry.out_offset(), original.out_offset);
                assert_eq!(entry.in_size(), original.in_len);
                assert_eq!(entry.out_size(), original.out_len);
                assert_eq!(entry.ctx_byte(), original.ctx_byte);
                assert_eq!(entry.ctx_bits(), original.ctx_bits);
                let dict_start = table_size + entry.dict_offset() as usize;
                let dict = &meta.inflate_data[dict_start..dict_start + entry.dict_size() as usize];
                assert_eq!(dict, original.dict);

                let context = ZranContext::from(&entry);
                let start = context.in_offset as usize;
                let end = start + context.in_len as usize;
                let mut decoded = vec![0; context.out_len as usize];
                ZranDecoder::new()
                    .unwrap()
                    .uncompress(
                        &context,
                        Some(dict),
                        &self.compressed[start..end],
                        &mut decoded,
                    )
                    .unwrap();
                let offset = chunk.get_zran_offset().unwrap() as usize;
                let source_index =
                    original_chunk.uncompressed_offset() as usize / COMPACT_CHUNK_SIZE;
                assert_eq!(
                    &decoded[offset..offset + chunk.uncompressed_size() as usize],
                    self.contents[source_index]
                );
            }
        }
    }

    fn compact_fixture() -> CompactFixture {
        // Two chunks share each context. Random seven-bit data compresses enough to stay
        // gzip, but crosses enough DEFLATE blocks to exercise real saved dictionaries.
        let mut random = 0x1234_5678u32;
        let contents: Vec<Vec<u8>> = (0..8)
            .map(|_| {
                (0..COMPACT_CHUNK_SIZE)
                    .map(|_| {
                        random ^= random << 13;
                        random ^= random >> 17;
                        random ^= random << 5;
                        (random & 0x7f) as u8
                    })
                    .collect()
            })
            .collect();
        let mut source = vec![0; 4096];
        for chunk in &contents {
            source.extend_from_slice(chunk);
        }
        source.extend_from_slice(&[0; 8192]);
        let (compressed, is_compressed) =
            compress::compress(&source, compress::Algorithm::GZip).unwrap();
        assert!(is_compressed);
        let compressed = compressed.into_owned();
        let mut generator = ZranContextGenerator::new(Cursor::new(compressed.clone())).unwrap();
        generator.generator.set_min_compressed_size(32 * 1024);
        generator.generator.set_max_compressed_size(192 * 1024);
        generator
            .generator
            .set_max_uncompressed_size(4 * COMPACT_CHUNK_SIZE as u64);
        let mut reader = generator.reader();
        // Consume the gzip header and a prefix before capturing the first raw inflate context.
        reader.read_exact(&mut [0; 4096]).unwrap();
        let mut chunks = Vec::new();
        for expected in &contents {
            generator.start_chunk(COMPACT_CHUNK_SIZE as u64).unwrap();
            let mut actual = vec![0; COMPACT_CHUNK_SIZE];
            reader.read_exact(&mut actual).unwrap();
            assert_eq!(&actual, expected);
            chunks.push(generator.finish_chunk().unwrap());
        }
        assert_eq!(generator.len(), 4);
        let indexes: Vec<_> = chunks
            .iter()
            .map(|chunk| chunk.get_zran_index().unwrap())
            .collect();
        assert_eq!(indexes, [0, 0, 1, 1, 2, 2, 3, 3]);
        assert!(!generator.generator.get_compression_ctx_array()[3]
            .dict
            .is_empty());
        CompactFixture {
            generator,
            chunks,
            compressed,
            contents,
        }
    }

    #[test]
    fn test_zran_to_blob_meta_sparse_and_shared_contexts() {
        let fixture = compact_fixture();
        // Reference context 3 before context 0 to ensure serialization follows the
        // original context order rather than the order in which chunks reference it.
        let source = fixture.select_chunks(&[6, 0, 7]);
        let source_before = source.as_byte_slice().to_vec();
        let meta = fixture.generator.to_blob_meta(&source).unwrap();
        assert_eq!(meta.inflate_count, 2);
        let records = fixture.generator.generator.get_compression_ctx_array();
        assert_eq!(
            meta.inflate_data.len(),
            2 * size_of::<ZranInflateContext>() + records[0].dict.len() + records[3].dict.len()
        );
        fixture.assert_decodes(&source, &meta, &[1, 0, 1]);
        assert_eq!(source.as_byte_slice(), source_before);
        assert_eq!(fixture.generator.len(), 4);
    }

    #[test]
    fn test_zran_to_blob_meta_without_unused_contexts() {
        let fixture = compact_fixture();
        let source = fixture.select_chunks(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let (legacy, count) = fixture.generator.to_vec().unwrap();
        let meta = fixture.generator.to_blob_meta(&source).unwrap();
        assert_eq!(meta.inflate_count, count);
        assert_eq!(meta.inflate_data, legacy);
        assert_eq!(meta.chunks.as_byte_slice(), source.as_byte_slice());
        fixture.assert_decodes(&source, &meta, &[0, 0, 1, 1, 2, 2, 3, 3]);
    }

    #[test]
    fn test_zran_to_blob_meta_independent_subsets() {
        let fixture = compact_fixture();
        let original = fixture.generator.to_vec().unwrap();
        let first = fixture.select_chunks(&[6]);
        let second = fixture.select_chunks(&[2, 4]);
        let first_meta = fixture.generator.to_blob_meta(&first).unwrap();
        let second_meta = fixture.generator.to_blob_meta(&second).unwrap();
        let repeated = fixture.generator.to_blob_meta(&first).unwrap();
        assert_eq!(first_meta.inflate_count, 1);
        assert_eq!(second_meta.inflate_count, 2);
        assert_eq!(first_meta.inflate_data, repeated.inflate_data);
        assert_eq!(
            first_meta.chunks.as_byte_slice(),
            repeated.chunks.as_byte_slice()
        );
        assert_eq!(fixture.generator.to_vec().unwrap(), original);
        fixture.assert_decodes(&first, &first_meta, &[0]);
        fixture.assert_decodes(&second, &second_meta, &[0, 1]);
    }

    #[test]
    fn test_zran_to_blob_meta_invalid_and_empty_chunks() {
        let fixture = compact_fixture();
        assert!(fixture
            .generator
            .to_blob_meta(&BlobMetaChunkArray::new_v1())
            .is_err());
        let mut non_zran = fixture.chunks[0];
        non_zran.set_zran(false);
        let non_zran = BlobMetaChunkArray::V2(vec![non_zran].into());
        assert!(fixture.generator.to_blob_meta(&non_zran).is_err());
        for index in [fixture.generator.len() as u32, u32::MAX] {
            let mut chunk = fixture.chunks[0];
            chunk.set_zran_index(index);
            let chunks = BlobMetaChunkArray::V2(vec![chunk].into());
            assert!(fixture.generator.to_blob_meta(&chunks).is_err());
        }
        let meta = fixture
            .generator
            .to_blob_meta(&BlobMetaChunkArray::new_v2())
            .unwrap();
        assert!(meta.chunks.is_empty());
        assert_eq!(meta.inflate_count, 0);
        assert!(meta.inflate_data.is_empty());
        assert_eq!(fixture.generator.len(), 4);
    }

    #[test]
    fn test_zran_inflate_context_getters() {
        let ctx = ZranInflateContext {
            in_offset: u64::to_le(1024),
            out_offset: u64::to_le(2048),
            dict_offset: u64::to_le(4096),
            in_len: u32::to_le(100),
            out_len: u32::to_le(200),
            dict_size: u32::to_le(32),
            ctx_byte: 0x42,
            ctx_bits: 0x03,
            __reserved1: 0,
            __reserved2: 0,
        };

        assert_eq!(ctx.in_offset(), 1024);
        assert_eq!(ctx.out_offset(), 2048);
        assert_eq!(ctx.dict_offset(), 4096);
        assert_eq!(ctx.in_size(), 100);
        assert_eq!(ctx.out_size(), 200);
        assert_eq!(ctx.dict_size(), 32);
        assert_eq!(ctx.ctx_byte(), 0x42);
        assert_eq!(ctx.ctx_bits(), 0x03);
    }

    #[test]
    fn test_zran_inflate_context_as_slice() {
        let ctx = ZranInflateContext {
            in_offset: u64::to_le(1024),
            out_offset: u64::to_le(2048),
            dict_offset: u64::to_le(4096),
            in_len: u32::to_le(100),
            out_len: u32::to_le(200),
            dict_size: u32::to_le(32),
            ctx_byte: 0x42,
            ctx_bits: 0x03,
            __reserved1: 0,
            __reserved2: 0,
        };

        let slice = ctx.as_slice();
        assert_eq!(slice.len(), size_of::<ZranInflateContext>());
    }

    #[test]
    fn test_zran_inflate_context_to_zran_context() {
        let ctx = ZranInflateContext {
            in_offset: u64::to_le(1024),
            out_offset: u64::to_le(2048),
            dict_offset: u64::to_le(4096),
            in_len: u32::to_le(100),
            out_len: u32::to_le(200),
            dict_size: u32::to_le(32),
            ctx_byte: 0x42,
            ctx_bits: 0x03,
            __reserved1: 0,
            __reserved2: 0,
        };

        let zran_ctx: ZranContext = (&ctx).into();
        assert_eq!(zran_ctx.in_offset, 1024);
        assert_eq!(zran_ctx.out_offset, 2048);
        assert_eq!(zran_ctx.in_len, 100);
        assert_eq!(zran_ctx.out_len, 200);
        assert_eq!(zran_ctx.ctx_byte, 0x42);
        assert_eq!(zran_ctx.ctx_bits, 0x03);
        assert!(zran_ctx.dict.is_empty());
    }

    #[test]
    fn test_zran_inflate_context_zero_values() {
        let ctx = ZranInflateContext {
            in_offset: 0,
            out_offset: 0,
            dict_offset: 0,
            in_len: 0,
            out_len: 0,
            dict_size: 0,
            ctx_byte: 0,
            ctx_bits: 0,
            __reserved1: 0,
            __reserved2: 0,
        };

        assert_eq!(ctx.in_offset(), 0);
        assert_eq!(ctx.out_offset(), 0);
        assert_eq!(ctx.dict_offset(), 0);
        assert_eq!(ctx.in_size(), 0);
        assert_eq!(ctx.out_size(), 0);
        assert_eq!(ctx.dict_size(), 0);
        assert_eq!(ctx.ctx_byte(), 0);
        assert_eq!(ctx.ctx_bits(), 0);
    }

    #[test]
    fn test_generate_chunk_info() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = PathBuf::from(root_dir).join("../tests/texture/zran/zran-two-streams.tar.gz");
        let file = OpenOptions::new().read(true).open(path).unwrap();

        let mut generator = ZranContextGenerator::new(file).unwrap();
        let mut tar = Archive::new(generator.reader());
        tar.set_ignore_zeros(true);

        generator.generator.set_min_compressed_size(1024);
        generator.generator.set_max_compressed_size(2048);
        generator.generator.set_max_uncompressed_size(4096);

        assert_eq!(generator.len(), 0);
        assert!(generator.is_empty());

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
        assert!(!generator.is_empty());
    }

    #[test]
    fn test_zran_context_generator_to_vec() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = PathBuf::from(root_dir).join("../tests/texture/zran/zran-two-streams.tar.gz");
        let file = OpenOptions::new().read(true).open(path).unwrap();

        let mut generator = ZranContextGenerator::new(file).unwrap();
        let mut tar = Archive::new(generator.reader());
        tar.set_ignore_zeros(true);

        generator.generator.set_min_compressed_size(1024);
        generator.generator.set_max_compressed_size(2048);
        generator.generator.set_max_uncompressed_size(4096);

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

        let (data, count) = generator.to_vec().unwrap();
        assert_eq!(count, 3);
        assert!(!data.is_empty());
        // Data should contain context entries + dictionaries
        assert!(data.len() >= count as usize * size_of::<ZranInflateContext>());
    }
}
