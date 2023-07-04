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
pub struct BatchInflateContext {
    /// Offset of the batch chunk data into the compressed data blob.
    compressed_offset: u64,
    /// Compressed size of the whole batch chunk data.
    compressed_size: u32,
    /// Uncompressed size of the whole batch chunk data without 4K aligned.
    uncompressed_batch_size: u32,
    __reserved1: u64,
    __reserved2: u64,
    __reserved3: u64,
}

impl BatchInflateContext {
    /// Get offset of the batch chunk data into the compressed data blob.
    pub fn compressed_offset(&self) -> u64 {
        u64::from_le(self.compressed_offset)
    }

    /// Set offset of the batch chunk data into the compressed data blob.
    pub fn set_compressed_offset(&mut self, compressed_offset: u64) {
        self.compressed_offset = u64::to_le(compressed_offset);
    }

    /// Get compressed size of the whole batch chunk data.
    pub fn compressed_size(&self) -> u32 {
        u32::from_le(self.compressed_size)
    }

    /// Set compressed size of the whole batch chunk data.
    pub fn set_compressed_size(&mut self, compressed_size: u32) {
        self.compressed_size = u32::to_le(compressed_size);
    }

    /// Get compressed offset of the end of the whole batch chunk data.
    pub fn compressed_end(&self) -> u64 {
        self.compressed_offset() + self.compressed_size() as u64
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

    /// Get the lenth of chunk data buffer.
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
    pub fn add_context(&mut self, compressed_offset: u64, compressed_size: u32) {
        let ctx = BatchInflateContext {
            compressed_offset: u64::to_le(compressed_offset),
            compressed_size: u32::to_le(compressed_size),
            uncompressed_batch_size: self.chunk_data_buf_len() as u32,
            __reserved1: u64::to_le(0),
            __reserved2: u64::to_le(0),
            __reserved3: u64::to_le(0),
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
        uncompressed_offset: u64,
        uncompressed_size: u32,
        encrypted: bool,
    ) -> Result<BlobChunkInfoV2Ondisk> {
        let mut chunk = BlobChunkInfoV2Ondisk::default();
        chunk.set_compressed_offset(0);
        chunk.set_compressed_size(0);
        chunk.set_uncompressed_offset(uncompressed_offset);
        chunk.set_uncompressed_size(uncompressed_size);
        chunk.set_batch(true);
        chunk.set_batch_index(self.contexts.len() as u32);
        chunk.set_uncompressed_offset_in_batch_buf(self.chunk_data_buf_len() as u32);
        chunk.set_compressed(true);
        chunk.set_encrypted(encrypted);

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
