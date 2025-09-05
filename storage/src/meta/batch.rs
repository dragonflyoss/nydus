// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::mem::size_of;
use std::slice;

use crate::meta::chunk_info_v2::BlobChunkInfoV2Ondisk;
use crate::meta::BlobMetaChunkInfo;

/// Context information to support batch chunk.
/// Each one corresponds to a whole batch chunk containing multiple small chunks.
#[repr(C, packed)]
#[derive(Default)]
pub struct BatchInflateContext {
    /// Compressed size of the whole batch chunk data.
    compressed_size: u32,
    /// Uncompressed size of the whole batch chunk data without 4K aligned.
    uncompressed_batch_size: u32,
    __reserved1: u64,
    __reserved2: u64,
    __reserved3: u64,
    __reserved4: u64,
}

impl BatchInflateContext {
    /// Get compressed size of the whole batch chunk data.
    pub fn compressed_size(&self) -> u32 {
        u32::from_le(self.compressed_size)
    }

    /// Set compressed size of the whole batch chunk data.
    pub fn set_compressed_size(&mut self, compressed_size: u32) {
        self.compressed_size = u32::to_le(compressed_size);
    }

    /// Set uncompressed size of the whole batch chunk data.
    pub fn set_uncompressed_batch_size(&mut self, uncompressed_batch_size: u32) {
        self.uncompressed_batch_size = u32::to_le(uncompressed_batch_size);
    }

    /// Get uncompressed size of the whole batch chunk data.
    pub fn uncompressed_batch_size(&self) -> u32 {
        u32::from_le(self.uncompressed_batch_size)
    }

    /// Convert to an immutable u8 slice.
    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const BatchInflateContext as *const u8,
                size_of::<BatchInflateContext>(),
            )
        }
    }
}

/// Struct to generate [BatchInflateContext] objects for batch chunks.
pub struct BatchContextGenerator {
    /// Buffering the to be dumped chunk data for Chunk Merging.
    chunk_data_buf: Vec<u8>,
    /// Storing all `BatchInflateContext` of current blob.
    contexts: Vec<BatchInflateContext>,
}

impl BatchContextGenerator {
    /// Get the buffer of to be dumped chunk data for batch chunk.
    pub fn chunk_data_buf(&self) -> &Vec<u8> {
        &self.chunk_data_buf
    }

    /// Check whether the chunk data buffer is empty.
    pub fn chunk_data_buf_is_empty(&self) -> bool {
        self.chunk_data_buf.is_empty()
    }

    /// Get the length of chunk data buffer.
    pub fn chunk_data_buf_len(&self) -> usize {
        self.chunk_data_buf.len()
    }

    /// Append new chunk data to the chunk data buffer.
    pub fn append_chunk_data_buf(&mut self, chunk_data: &[u8]) {
        self.chunk_data_buf.extend_from_slice(chunk_data);
    }

    /// Clear the chunk data buffer.
    pub fn clear_chunk_data_buf(&mut self) {
        self.chunk_data_buf.clear();
    }

    /// Add a batch context for a dumped batch chunk.
    pub fn add_context(&mut self, compressed_size: u32) {
        let ctx = BatchInflateContext {
            compressed_size: u32::to_le(compressed_size),
            uncompressed_batch_size: u32::to_le(self.chunk_data_buf_len() as u32),
            __reserved1: u64::to_le(0),
            __reserved2: u64::to_le(0),
            __reserved3: u64::to_le(0),
            __reserved4: u64::to_le(0),
        };
        self.contexts.push(ctx);
    }

    /// Create a new instance of [BatchInflateContext].
    pub fn new(batch_size: u32) -> Result<Self> {
        Ok(Self {
            chunk_data_buf: Vec::with_capacity(batch_size as usize),
            contexts: Vec::with_capacity(10240),
        })
    }

    /// Generate and return a v2 chunk info struct.
    pub fn generate_chunk_info(
        &mut self,
        compressed_offset: u64,
        uncompressed_offset: u64,
        uncompressed_size: u32,
        encrypted: bool,
    ) -> Result<BlobChunkInfoV2Ondisk> {
        let mut chunk = BlobChunkInfoV2Ondisk::default();
        chunk.set_compressed_offset(compressed_offset);
        chunk.set_compressed_size(0);
        chunk.set_uncompressed_offset(uncompressed_offset);
        chunk.set_uncompressed_size(uncompressed_size);
        chunk.set_batch(true);
        chunk.set_batch_index(self.contexts.len() as u32);
        chunk.set_uncompressed_offset_in_batch_buf(self.chunk_data_buf_len() as u32);
        chunk.set_compressed(true);
        chunk.set_encrypted(encrypted);
        chunk.set_has_crc32(false); // Batch chunk cannot store CRC32 due to data field conflict

        Ok(chunk)
    }

    /// Convert all the batch chunk information to a u8 vector.
    pub fn to_vec(&self) -> Result<(Vec<u8>, u32)> {
        let mut data = Vec::new();

        for ctx in &self.contexts {
            data.extend_from_slice(ctx.as_slice());
        }

        Ok((data, self.contexts.len() as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::ManuallyDrop;

    #[test]
    fn test_batch_inflate_context() {
        let mut ctx = BatchInflateContext {
            compressed_size: 0,
            uncompressed_batch_size: 0,
            __reserved1: 0,
            __reserved2: 0,
            __reserved3: 0,
            __reserved4: 0,
        };
        ctx.set_compressed_size(0x20);
        assert_eq!(ctx.compressed_size(), 0x20);
        ctx.set_uncompressed_batch_size(0x30);
        assert_eq!(ctx.uncompressed_batch_size(), 0x30);
        let mut v = [0u8; 40];
        v[0] = 0x20;
        v[4] = 0x30;
        assert_eq!(ctx.as_slice(), v);
    }

    #[test]
    fn test_batch_context_generator() {
        let mut generator = BatchContextGenerator::new(0x100000).unwrap();
        assert!(generator.chunk_data_buf_is_empty());
        assert_eq!(generator.chunk_data_buf_len(), 0);

        generator.append_chunk_data_buf(&[1, 2, 3, 4]);
        assert!(!generator.chunk_data_buf_is_empty());
        assert_eq!(generator.chunk_data_buf_len(), 4);

        generator.add_context(4);

        let (ctx_data, _) = generator.to_vec().unwrap();
        let ctx_vec = unsafe {
            ManuallyDrop::new(Vec::from_raw_parts(
                ctx_data.as_slice().as_ptr() as *mut BatchInflateContext,
                1,
                1,
            ))
        };
        assert_eq!(ctx_vec[0].compressed_size(), 4);
        assert_eq!(ctx_vec[0].uncompressed_batch_size(), 4);

        generator.clear_chunk_data_buf();
        assert!(generator.chunk_data_buf_is_empty());
        assert_eq!(generator.chunk_data_buf_len(), 0);

        let chunk_info = generator.generate_chunk_info(0, 0, 4, false).unwrap();
        assert!(chunk_info.is_batch());
    }
}
