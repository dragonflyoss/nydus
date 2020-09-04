// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::cmp;
use std::io::Result;
use std::slice;
use std::sync::Arc;

use vm_memory::VolatileSlice;

use crate::metadata::digest;
use crate::metadata::layout::OndiskBlobTableEntry;
use crate::metadata::{RafsChunkInfo, RafsSuperMeta};
use crate::storage::backend::BlobBackend;
use crate::storage::compress;
use crate::storage::device::RafsBio;
use crate::storage::utils::{alloc_buf, digest_check};

use nydus_utils::eio;

pub mod blobcache;
pub mod dummycache;

#[derive(Default, Clone)]
struct MergedBackendRequest {
    // Chunks that are continuous to each other.
    pub chunks: Vec<Arc<dyn RafsChunkInfo>>,
    pub blob_offset: u64,
    pub blob_size: u32,
    pub blob_id: String,
}

impl<'a> MergedBackendRequest {
    fn reset(&mut self) {
        self.blob_offset = 0;
        self.blob_size = 0;
        self.blob_id.truncate(0);
        self.chunks.clear();
    }

    fn merge_begin(&mut self, first_cki: Arc<dyn RafsChunkInfo>, blob_id: &str) {
        self.blob_offset = first_cki.compress_offset();
        self.blob_size = first_cki.compress_size();
        self.chunks.push(first_cki);
        self.blob_id = String::from(blob_id);
    }

    fn merge_one_chunk(&mut self, cki: Arc<dyn RafsChunkInfo>) {
        self.blob_size += cki.compress_size();
        self.chunks.push(cki);
    }
}

fn is_chunk_continuous(prior: &RafsBio, cur: &RafsBio) -> bool {
    let prior_cki = &prior.chunkinfo;
    let cur_cki = &cur.chunkinfo;

    let prior_end = prior_cki.compress_offset() + prior_cki.compress_size() as u64;
    let cur_offset = cur_cki.compress_offset();

    if prior_end == cur_offset && prior.blob_id == cur.blob_id {
        return true;
    }

    false
}

fn generate_merged_requests(
    bios: &mut [RafsBio],
    tx: &mut spmc::Sender<MergedBackendRequest>,
    merging_size: usize,
) {
    bios.sort_by_key(|entry| entry.chunkinfo.compress_offset());
    let mut index: usize = 1;
    if bios.is_empty() {
        return;
    }
    let first_cki = &bios[0].chunkinfo;
    let mut mr = MergedBackendRequest::default();
    mr.merge_begin(Arc::clone(first_cki), &bios[0].blob_id);

    if bios.len() == 1 {
        tx.send(mr).unwrap();
        return;
    }

    loop {
        let cki = &bios[index].chunkinfo;
        let prior_bio = &bios[index - 1];
        let cur_bio = &bios[index];

        // Even more chunks are continuous, still split them per as certain size.
        // So that to achieve an appropriate request size to backend.
        if is_chunk_continuous(prior_bio, cur_bio) && mr.blob_size <= merging_size as u32 {
            mr.merge_one_chunk(Arc::clone(&cki));
        } else {
            // New a MR if a non-continuous chunk is met.
            tx.send(mr.clone()).unwrap();
            mr.reset();
            mr.merge_begin(Arc::clone(&cki), &cur_bio.blob_id);
        }

        index += 1;

        if index >= bios.len() {
            tx.send(mr).unwrap();
            break;
        }
    }
}

#[derive(Clone, Default, Deserialize)]
pub struct PrefetchWorker {
    pub threads_count: usize,
    pub merging_size: usize,
}

pub trait RafsCache {
    /// Whether has block data
    fn has(&self, blk: Arc<dyn RafsChunkInfo>) -> bool;

    /// Do init after super block loaded
    fn init(&self, sb_info: &RafsSuperMeta, blobs: &[OndiskBlobTableEntry]) -> Result<()>;

    /// Evict block data
    fn evict(&self, blk: Arc<dyn RafsChunkInfo>) -> Result<()>;

    /// Flush cache
    fn flush(&self) -> Result<()>;

    /// Read a chunk data through cache, always used in decompressed cache
    fn read(&self, bio: &RafsBio, bufs: &[VolatileSlice], offset: u64) -> Result<usize>;

    /// Write a chunk data through cache
    fn write(&self, blob_id: &str, blk: &dyn RafsChunkInfo, buf: &[u8]) -> Result<usize>;

    /// Get the size of a blob
    fn blob_size(&self, blob_id: &str) -> Result<u64>;

    fn prefetch(&self, bio: &mut [RafsBio]) -> Result<usize>;

    /// Release cache
    fn release(&self);

    fn backend(&self) -> &(dyn BlobBackend + Sync + Send);

    fn digester(&self) -> digest::Algorithm;
    fn compressor(&self) -> compress::Algorithm;
    fn need_validate(&self) -> bool;

    /// Read a whole chunk directly from *backend*.
    /// The fetched chunk could be compressed or not by different compressors.
    /// It depends on `cki` how to describe the chunk data.
    /// Moreover, chunk data from backend can be validated per as to nydus configuration.
    /// Above is not redundant with blob cache's validation given IO path backend -> blobcache
    fn read_backend_chunk(
        &self,
        blob_id: &str,
        cki: &dyn RafsChunkInfo,
        chunk: &mut [u8],
    ) -> Result<usize> {
        let offset = cki.compress_offset();
        let d_size = cki.decompress_size() as usize;
        let mut d;

        let raw_chunk = if cki.is_compressed() {
            // Need to put compressed data into a temporary buffer so as to perform decompression.
            // TODO: Use a buffer pool for lower latency?
            //
            // gzip is special that it doesn't carry compress_size, instead, we can read as much
            // as 4MB compressed data per chunk, decompress as much as necessary to fill in chunk
            // that has the original uncompressed data size.
            // FIXME: This is ineffecient! Eventually we should have a streaming blob cache that is managed
            // by fixed chunk size instead of RafsChunkInfo.
            // And it is extremely ineffecient for dummy cache.
            let c_size = if self.compressor() != compress::Algorithm::GZip {
                cki.compress_size() as usize
            } else {
                let size = self.blob_size(blob_id)? - cki.compress_offset();
                cmp::min(size, 4 << 20) as usize
            };
            d = alloc_buf(c_size);
            d.as_mut_slice()
        } else {
            // We have this unsafe assignment as it can directly store data into call's buffer.
            unsafe { slice::from_raw_parts_mut(chunk.as_mut_ptr(), chunk.len()) }
        };

        self.backend().read(blob_id, raw_chunk, offset)?;
        // Try to validate data just fetched from backend inside.
        self.process_raw_chunk(cki, raw_chunk, chunk, cki.is_compressed())
            .map_err(|e| eio!(format!("fail to read from backend: {}", e)))?;
        Ok(d_size)
    }

    /// Before storing chunk data into blob cache file. We have cook the raw chunk from
    /// backend a bit per as to the chunk description as blob cache always saves plain data
    /// into cache file rather than compressed.
    /// An inside trick is that it tries to directly save data into caller's buffer.
    fn process_raw_chunk(
        &self,
        cki: &dyn RafsChunkInfo,
        raw_chunk: &[u8],
        chunk: &mut [u8],
        need_decompress: bool,
    ) -> Result<usize> {
        if need_decompress {
            compress::decompress(raw_chunk, chunk, self.compressor()).map_err(|e| {
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
        if self.need_validate() && !digest_check(chunk, &cki.block_id(), self.digester()) {
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
            .read(blob_id, c_buf.as_mut_slice(), blob_offset)?;

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
                &mut chunk,
                cki.is_compressed(),
            )?;
            chunks.push(chunk);
        }

        Ok(chunks)
    }
}
