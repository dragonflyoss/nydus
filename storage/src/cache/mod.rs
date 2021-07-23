// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::cmp;
use std::fs::File;
use std::io::Result;
use std::slice;
use std::sync::Arc;

use vm_memory::VolatileSlice;

use crate::backend::BlobBackend;
use crate::device::{BlobPrefetchControl, RafsBio, RafsBlobEntry, RafsChunkInfo};
use crate::utils::{alloc_buf, digest_check};
use crate::{compress, StorageResult};

use nydus_utils::digest;

pub mod blobcache;
pub mod chunkmap;
pub mod dummycache;

#[derive(Default, Clone)]
struct MergedBackendRequest {
    seq: u64,
    // Chunks that are continuous to each other.
    pub chunks: Vec<Arc<dyn RafsChunkInfo>>,
    pub blob_offset: u64,
    pub blob_size: u32,
    pub blob_entry: Arc<RafsBlobEntry>,
}

impl MergedBackendRequest {
    fn new(seq: u64, first_cki: Arc<dyn RafsChunkInfo>, blob: Arc<RafsBlobEntry>) -> Self {
        let mut chunks = Vec::<Arc<dyn RafsChunkInfo>>::new();
        let blob_size = first_cki.compress_size();
        let blob_offset = first_cki.compress_offset();
        chunks.push(first_cki);

        MergedBackendRequest {
            seq,
            blob_offset,
            blob_size,
            chunks,
            blob_entry: blob,
        }
    }

    fn merge_one_chunk(&mut self, cki: Arc<dyn RafsChunkInfo>) {
        self.blob_size += cki.compress_size();
        self.chunks.push(cki);
    }
}

#[derive(Clone, Default)]
pub struct PrefetchWorker {
    pub enable: bool,
    pub threads_count: usize,
    pub merging_size: usize,
    // In unit of Bytes and Zero means no rate limit is set.
    pub bandwidth_rate: u32,
}

pub trait RafsCache {
    /// Do init after super block loaded
    fn init(&self, prefetch_vec: &[BlobPrefetchControl]) -> Result<()>;

    /// Read a chunk data through cache
    /// offset is relative to chunk start
    // TODO: Cache is indexed by each chunk's block id. When this read request can't
    // hit local cache and it spans two chunks, group more than one requests to backend
    // storage could benefit the performance.
    fn read(&self, bio: &RafsBio, bufs: &[VolatileSlice], offset: u64) -> Result<usize>;

    /// Write a chunk data through cache
    fn write(&self, blob_id: &str, blk: &dyn RafsChunkInfo, buf: &[u8]) -> Result<usize>;

    /// Get the size of a blob
    fn blob_size(&self, blob: &RafsBlobEntry) -> Result<u64>;

    fn prefetch(&self, bio: &mut [RafsBio]) -> StorageResult<usize>;
    fn stop_prefetch(&self) -> StorageResult<()>;

    /// Release cache
    fn release(&self);

    fn backend(&self) -> &(dyn BlobBackend + Sync + Send);

    fn digester(&self) -> digest::Algorithm;
    fn compressor(&self) -> compress::Algorithm;
    fn need_validate(&self) -> bool;

    /// Read a whole chunk directly from *backend*.
    /// The fetched chunk could be compressed or not by different compressors.
    /// It depends on `cki` how to describe the chunk data.
    /// Moreover, chunk data from backend can be validated as per nydus configuration.
    /// Above is not redundant with blob cache's validation given IO path backend -> blobcache
    fn read_backend_chunk<F>(
        &self,
        blob: &RafsBlobEntry,
        cki: &dyn RafsChunkInfo,
        chunk: &mut [u8],
        cacher: F,
    ) -> Result<usize>
    where
        F: FnOnce(&[u8]) -> Result<()>,
        Self: Sized,
    {
        let offset = cki.compress_offset();
        let mut d;

        let raw_chunk = if cki.is_compressed() {
            // Need to put compressed data into a temporary buffer so as to perform decompression.
            //
            // gzip is special that it doesn't carry compress_size, instead, we can read as much
            // as chunk_decompress_size compressed data per chunk, decompress as much as necessary to fill in chunk
            // that has the original uncompressed data size.
            let c_size = if self.compressor() != compress::Algorithm::GZip {
                cki.compress_size() as usize
            } else {
                // Per man(1) gzip
                // The worst case expansion is a few bytes for the gzip file header,
                // plus 5 bytes every 32K block, or an expansion ratio of 0.015% for
                // large files.
                //
                // Per http://www.zlib.org/rfc-gzip.html#header-trailer
                // Each member has the following structure:
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
                let size = chunk.len() + 10 + 8 + 5 + (chunk.len() / (16 << 10)) * 5 + 128;
                cmp::min(size as u64, self.blob_size(blob)? - cki.compress_offset()) as usize
            };
            d = alloc_buf(c_size);
            d.as_mut_slice()
        } else {
            // We have this unsafe assignment as it can directly store data into call's buffer.
            unsafe { slice::from_raw_parts_mut(chunk.as_mut_ptr(), chunk.len()) }
        };

        self.backend()
            .read(&blob.blob_id, raw_chunk, offset)
            .map_err(|e| eio!(e))?;
        // Try to validate data just fetched from backend inside.
        self.process_raw_chunk(
            cki,
            raw_chunk,
            None,
            chunk,
            cki.is_compressed(),
            self.need_validate(),
        )
        .map_err(|e| eio!(format!("fail to read from backend: {}", e)))?;
        cacher(chunk)?;
        Ok(chunk.len())
    }

    /// Before storing chunk data into blob cache file. We have cook the raw chunk from
    /// backend a bit as per the chunk description as blob cache always saves plain data
    /// into cache file rather than compressed.
    /// An inside trick is that it tries to directly save data into caller's buffer.
    fn process_raw_chunk(
        &self,
        cki: &dyn RafsChunkInfo,
        raw_chunk: &[u8],
        raw_stream: Option<File>,
        chunk: &mut [u8],
        need_decompress: bool,
        need_validate: bool,
    ) -> Result<usize> {
        if need_decompress {
            compress::decompress(raw_chunk, raw_stream, chunk, self.compressor()).map_err(|e| {
                error!("failed to decompress chunk: {}", e);
                e
            })?;
        } else if raw_chunk.as_ptr() != chunk.as_ptr() {
            // Sometimes, caller directly put data into consumer provided buffer.
            // Then we don't have to copy data between slices.
            chunk.copy_from_slice(raw_chunk);
        }

        let d_size = cki.decompress_size() as usize;
        if chunk.len() != d_size {
            return Err(eio!());
        }
        if need_validate && !digest_check(chunk, cki.block_id(), self.digester()) {
            return Err(eio!());
        }

        Ok(chunk.len())
    }

    /// Read multiple complete chunks from backend in batch. Caller must ensure that
    /// range [`blob_offset`..`blob_offset` + `blob_size`] exactly covers more than one
    /// chunks and `cki_set` can correctly describe how to extract chunk from batched buffer.
    /// Afterwards, several chunks are returned, caller does not have to decompress them.
    fn read_chunks(
        &self,
        blob_id: &str,
        blob_offset: u64,
        blob_size: usize,
        cki_set: &[Arc<dyn RafsChunkInfo>],
    ) -> Result<Vec<Vec<u8>>> {
        let mut c_buf = alloc_buf(blob_size);
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        // TODO: Currently, request length to backend may span a whole chunk,
        // Do we need to split it into smaller pieces like 128K or 256K?
        let nr_read = self
            .backend()
            .read(blob_id, c_buf.as_mut_slice(), blob_offset)
            .map_err(|e| eio!(e))?;

        if nr_read != blob_size {
            return Err(eio!(format!(
                "request for {} bytes but got {} bytes",
                blob_size, nr_read
            )));
        }

        for cki in cki_set {
            // TODO: Also check if adjacent here?
            let offset_merged = (cki.compress_offset() - blob_offset) as usize;
            let size_merged = cki.compress_size() as usize;
            let mut chunk = alloc_buf(cki.decompress_size() as usize);
            self.process_raw_chunk(
                cki.as_ref(),
                &c_buf[offset_merged..(offset_merged + size_merged)],
                None,
                &mut chunk,
                cki.is_compressed(),
                self.need_validate(),
            )?;
            chunks.push(chunk);
        }

        Ok(chunks)
    }
}
