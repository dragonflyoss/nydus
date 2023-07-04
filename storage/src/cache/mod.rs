// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! A blob cache layer over storage backend to improve performance.
//!
//! One of Rafs filesystem's goal is to support "on demand data loading". On demand loading may
//! help to speed up application/container startup, but it may also cause serious performance
//! penalty if all data chunks are retrieved from remoted backend storage. So cache layer is
//! introduced between Rafs filesystem and backend storage, which caches remote data onto local
//! storage and merge small data request into bigger request to improve network performance.
//!
//! There are several cache drivers implemented:
//! - [DummyCacheMgr](dummycache/struct.DummyCacheMgr.html): a dummy implementation of
//!   `BlobCacheMgr`, simply reporting each chunk as cached or not cached according to
//!   configuration.

use std::cmp;
use std::io::Result;
use std::sync::Arc;
use std::time::Instant;

use fuse_backend_rs::file_buf::FileVolatileSlice;
use nydus_utils::compress::zlib_random::ZranDecoder;
use nydus_utils::crypt::{self, Cipher, CipherContext};
use nydus_utils::{compress, digest};

use crate::backend::{BlobBackend, BlobReader};
use crate::cache::state::ChunkMap;
use crate::device::{
    BlobChunkInfo, BlobInfo, BlobIoDesc, BlobIoRange, BlobIoVec, BlobObject, BlobPrefetchRequest,
};
use crate::meta::BlobCompressionContextInfo;
use crate::utils::{alloc_buf, check_digest};
use crate::{StorageResult, RAFS_MAX_CHUNK_SIZE};

mod cachedfile;
mod dummycache;
mod filecache;
#[cfg(target_os = "linux")]
mod fscache;
mod worker;

pub mod state;

pub use dummycache::DummyCacheMgr;
pub use filecache::FileCacheMgr;
#[cfg(target_os = "linux")]
pub use fscache::FsCacheMgr;

/// Timeout in milli-seconds to retrieve blob data from backend storage.
pub const SINGLE_INFLIGHT_WAIT_TIMEOUT: u64 = 2000;

struct BlobIoMergeState<'a, F: FnMut(BlobIoRange)> {
    cb: F,
    // size of compressed data
    size: u32,
    bios: Vec<&'a BlobIoDesc>,
}

impl<'a, F: FnMut(BlobIoRange)> BlobIoMergeState<'a, F> {
    /// Create a new instance of 'IoMergeState`.
    pub fn new(bio: &'a BlobIoDesc, cb: F) -> Self {
        let size = bio.chunkinfo.compressed_size();

        BlobIoMergeState {
            cb,
            size,
            bios: vec![bio],
        }
    }

    /// Get size of pending compressed data.
    #[inline]
    fn size(&self) -> usize {
        self.size as usize
    }

    /// Push a new io descriptor into the pending list.
    #[inline]
    fn push(&mut self, bio: &'a BlobIoDesc) {
        let start = bio.chunkinfo.compressed_offset();
        let size = if !self.bios.is_empty() {
            let last = &self.bios[self.bios.len() - 1].chunkinfo;
            let prev = last.compressed_offset() + last.compressed_size() as u64;
            assert!(prev <= start);
            assert!(start - prev < u32::MAX as u64);
            (start - prev) as u32 + bio.chunkinfo.compressed_size()
        } else {
            bio.chunkinfo.compressed_size()
        };
        assert!(self.size.checked_add(size).is_some());
        self.size += size;
        self.bios.push(bio);
    }

    /// Issue all pending io descriptors.
    #[inline]
    pub fn issue(&mut self, max_gap: u64) {
        if !self.bios.is_empty() {
            let mut mr = BlobIoRange::new(self.bios[0], self.bios.len());
            for bio in self.bios[1..].iter() {
                mr.merge(bio, max_gap);
            }
            (self.cb)(mr);

            self.bios.truncate(0);
            self.size = 0;
        }
    }

    /// Merge adjacent chunks into bigger request with compressed size no bigger than `max_size`
    /// and issue all blob IO descriptors.
    pub fn merge_and_issue(bios: &[BlobIoDesc], max_comp_size: u64, max_gap: u64, op: F) {
        if !bios.is_empty() {
            let mut index = 1;
            let mut state = BlobIoMergeState::new(&bios[0], op);

            for cur_bio in &bios[1..] {
                // Issue pending descriptors when next chunk is not continuous with current chunk
                // or the accumulated compressed data size is big enough.
                if !bios[index - 1].is_continuous(cur_bio, max_gap)
                    || state.size() as u64 >= max_comp_size
                {
                    state.issue(max_gap);
                }
                state.push(cur_bio);
                index += 1
            }
            state.issue(max_gap);
        }
    }
}

/// Trait representing a cache object for a blob on backend storage.
///
/// The caller may use the `BlobCache` trait to access blob data on backend storage, with an
/// optional intermediate cache layer to improve performance.
pub trait BlobCache: Send + Sync {
    /// Get id of the blob object.
    fn blob_id(&self) -> &str;

    /// Get size of the decompressed blob object.
    fn blob_uncompressed_size(&self) -> Result<u64>;

    /// Get size of the compressed blob object.
    fn blob_compressed_size(&self) -> Result<u64>;

    /// Get data compression algorithm to handle chunks in the blob.
    fn blob_compressor(&self) -> compress::Algorithm;

    /// Get data encryption algorithm to handle chunks in the blob.
    fn blob_cipher(&self) -> crypt::Algorithm;

    /// Cipher object to encrypt/decrypt chunk data.
    fn blob_cipher_object(&self) -> Arc<Cipher>;

    /// Cipher context to encrypt/decrypt chunk data.
    fn blob_cipher_context(&self) -> Option<CipherContext>;

    /// Get message digest algorithm to handle chunks in the blob.
    fn blob_digester(&self) -> digest::Algorithm;

    /// Check whether the cache object is for an stargz image with legacy chunk format.
    fn is_legacy_stargz(&self) -> bool;

    /// Get maximum size of gzip compressed data.
    fn get_legacy_stargz_size(&self, offset: u64, uncomp_size: usize) -> Result<usize> {
        let blob_size = self.blob_compressed_size()?;
        let max_size = blob_size.checked_sub(offset).ok_or_else(|| {
            einval!(format!(
                "chunk compressed offset {:x} is bigger than blob file size {:x}",
                offset, blob_size
            ))
        })?;
        let max_size = cmp::min(max_size, usize::MAX as u64) as usize;
        Ok(compress::compute_compressed_gzip_size(
            uncomp_size,
            max_size,
        ))
    }

    /// Check whether the blob is ZRan based.
    fn is_zran(&self) -> bool {
        false
    }

    /// Check whether the blob is Batch based.
    fn is_batch(&self) -> bool {
        false
    }

    /// Check whether need to validate the data chunk by digest value.
    fn need_validation(&self) -> bool;

    /// Get the [BlobReader](../backend/trait.BlobReader.html) to read data from storage backend.
    fn reader(&self) -> &dyn BlobReader;

    /// Get the underlying `ChunkMap` object.
    fn get_chunk_map(&self) -> &Arc<dyn ChunkMap>;

    /// Get the `BlobChunkInfo` object corresponding to `chunk_index`.
    fn get_chunk_info(&self, chunk_index: u32) -> Option<Arc<dyn BlobChunkInfo>>;

    /// Get a `BlobObject` instance to directly access uncompressed blob file.
    fn get_blob_object(&self) -> Option<&dyn BlobObject> {
        None
    }

    /// Enable prefetching blob data in background.
    ///
    /// It should be paired with stop_prefetch().
    fn start_prefetch(&self) -> StorageResult<()>;

    /// Stop prefetching blob data in background.
    ///
    /// It should be paired with start_prefetch().
    fn stop_prefetch(&self) -> StorageResult<()>;

    // Check whether data prefetch is still active.
    fn is_prefetch_active(&self) -> bool;

    /// Start to prefetch requested data in background.
    fn prefetch(
        &self,
        cache: Arc<dyn BlobCache>,
        prefetches: &[BlobPrefetchRequest],
        bios: &[BlobIoDesc],
    ) -> StorageResult<usize>;

    /// Execute filesystem data prefetch.
    fn prefetch_range(&self, _range: &BlobIoRange) -> Result<usize> {
        Err(enosys!("doesn't support prefetch_range()"))
    }

    /// Read chunk data described by the blob Io descriptors from the blob cache into the buffer.
    fn read(&self, iovec: &mut BlobIoVec, buffers: &[FileVolatileSlice]) -> Result<usize>;

    /// Read multiple chunks from the blob cache in batch mode.
    ///
    /// This is an interface to optimize chunk data fetch performance by merging multiple continuous
    /// chunks into one backend request. Callers must ensure that chunks in `chunks` covers a
    /// continuous range, and the range exactly matches [`blob_offset`..`blob_offset` + `blob_size`].
    /// Function `read_chunks_from_backend()` returns one buffer containing decompressed chunk data
    /// for each entry in the `chunks` array in corresponding order.
    ///
    /// This method returns success only if all requested data are successfully fetched.
    fn read_chunks_from_backend<'a, 'b>(
        &'a self,
        blob_offset: u64,
        blob_size: usize,
        chunks: &'b [Arc<dyn BlobChunkInfo>],
        prefetch: bool,
    ) -> Result<ChunkDecompressState<'a, 'b>>
    where
        Self: Sized,
    {
        // Read requested data from the backend by altogether.
        let mut c_buf = alloc_buf(blob_size);
        let start = Instant::now();
        let nr_read = self
            .reader()
            .read(c_buf.as_mut_slice(), blob_offset)
            .map_err(|e| eio!(e))?;
        if nr_read != blob_size {
            return Err(eio!(format!(
                "request for {} bytes but got {} bytes",
                blob_size, nr_read
            )));
        }
        let duration = Instant::now().duration_since(start).as_millis();
        debug!(
            "read_chunks_from_backend: {} {} {} bytes at {}, duration {}ms",
            std::thread::current().name().unwrap_or_default(),
            if prefetch { "prefetch" } else { "fetch" },
            blob_size,
            blob_offset,
            duration
        );

        let chunks = chunks.iter().map(|v| v.as_ref()).collect();
        Ok(ChunkDecompressState::new(blob_offset, self, chunks, c_buf))
    }

    /// Read a whole chunk directly from the storage backend.
    ///
    /// The fetched chunk data may be compressed or encrypted or not, which depends on chunk information
    /// from `chunk`. Moreover, chunk data from backend storage may be validated per user's configuration.
    fn read_chunk_from_backend(
        &self,
        chunk: &dyn BlobChunkInfo,
        buffer: &mut [u8],
    ) -> Result<Option<Vec<u8>>> {
        let start = Instant::now();
        let offset = chunk.compressed_offset();
        let mut c_buf = None;

        if self.is_zran() || self.is_batch() {
            return Err(enosys!("read_chunk_from_backend"));
        } else if !chunk.is_compressed() && !chunk.is_encrypted() {
            let size = self.reader().read(buffer, offset).map_err(|e| eio!(e))?;
            if size != buffer.len() {
                return Err(eio!("storage backend returns less data than requested"));
            }
        } else {
            let c_size = if self.is_legacy_stargz() {
                self.get_legacy_stargz_size(offset, buffer.len())?
            } else {
                chunk.compressed_size() as usize
            };
            let mut raw_buffer = alloc_buf(c_size);
            let size = self
                .reader()
                .read(raw_buffer.as_mut_slice(), offset)
                .map_err(|e| eio!(e))?;
            if size != raw_buffer.len() {
                return Err(eio!("storage backend returns less data than requested"));
            }
            let decrypted_buffer = crypt::decrypt_with_context(
                &raw_buffer,
                &self.blob_cipher_object(),
                &self.blob_cipher_context(),
                chunk.is_encrypted(),
            )?;
            self.decompress_chunk_data(&decrypted_buffer, buffer, chunk.is_compressed())?;
            c_buf = Some(raw_buffer);
        }

        let duration = Instant::now().duration_since(start).as_millis();
        debug!(
            "read_chunk_from_backend: {} {} bytes at {}, duration {}ms",
            std::thread::current().name().unwrap_or_default(),
            chunk.compressed_size(),
            chunk.compressed_offset(),
            duration
        );
        self.validate_chunk_data(chunk, buffer, false)
            .map_err(|e| {
                warn!("failed to read data from backend, {}", e);
                e
            })?;

        Ok(c_buf)
    }

    /// Decompress chunk data.
    fn decompress_chunk_data(
        &self,
        raw_buffer: &[u8],
        buffer: &mut [u8],
        is_compressed: bool,
    ) -> Result<()> {
        if is_compressed {
            let compressor = self.blob_compressor();
            let ret = compress::decompress(raw_buffer, buffer, compressor).map_err(|e| {
                error!("failed to decompress chunk: {}", e);
                e
            })?;
            if ret != buffer.len() {
                return Err(einval!(format!(
                    "size of decompressed data doesn't match expected, {} vs {}, raw_buffer: {}",
                    ret,
                    buffer.len(),
                    raw_buffer.len()
                )));
            }
        } else if raw_buffer.as_ptr() != buffer.as_ptr() {
            // raw_chunk and chunk may point to the same buffer, so only copy data when needed.
            buffer.copy_from_slice(raw_buffer);
        }
        Ok(())
    }

    /// Validate chunk data.
    fn validate_chunk_data(
        &self,
        chunk: &dyn BlobChunkInfo,
        buffer: &[u8],
        force_validation: bool,
    ) -> Result<usize> {
        let d_size = chunk.uncompressed_size() as usize;
        if buffer.len() != d_size {
            Err(eio!("uncompressed size and buffer size doesn't match"))
        } else if (self.need_validation() || force_validation)
            && !self.is_legacy_stargz()
            && !check_digest(buffer, chunk.chunk_id(), self.blob_digester())
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "data digest value doesn't match",
            ))
        } else {
            Ok(d_size)
        }
    }

    fn get_blob_meta_info(&self) -> Result<Option<Arc<BlobCompressionContextInfo>>> {
        Ok(None)
    }
}

/// An iterator to enumerate decompressed data for chunks.
pub struct ChunkDecompressState<'a, 'b> {
    blob_offset: u64,
    chunk_idx: usize,
    batch_idx: u32,
    zran_idx: u32,
    cache: &'a dyn BlobCache,
    chunks: Vec<&'b dyn BlobChunkInfo>,
    c_buf: Vec<u8>,
    d_buf: Vec<u8>,
}

impl<'a, 'b> ChunkDecompressState<'a, 'b> {
    fn new(
        blob_offset: u64,
        cache: &'a dyn BlobCache,
        chunks: Vec<&'b dyn BlobChunkInfo>,
        c_buf: Vec<u8>,
    ) -> Self {
        ChunkDecompressState {
            blob_offset,
            chunk_idx: 0,
            batch_idx: u32::MAX,
            zran_idx: u32::MAX,
            cache,
            chunks,
            c_buf,
            d_buf: Vec::new(),
        }
    }

    fn decompress_batch(&mut self, meta: &Arc<BlobCompressionContextInfo>) -> Result<()> {
        let ctx = meta
            .get_batch_context(self.batch_idx)
            .ok_or_else(|| einval!("failed to get Batch context for chunk"))?;
        let c_offset = ctx.compressed_offset();
        let c_size = ctx.compressed_size() as u64;
        let d_size = ctx.uncompressed_batch_size() as u64;
        if c_offset < self.blob_offset
            || c_offset.checked_add(c_size).is_none()
            || c_offset + c_size > self.blob_offset + self.c_buf.len() as u64
            || d_size > RAFS_MAX_CHUNK_SIZE
        {
            let msg = format!(
                "invalid chunk: z_offset 0x{:x}, z_size 0x{:x}, c_offset 0x{:x}, c_size 0x{:x}, d_size 0x{:x}",
                self.blob_offset,
                self.c_buf.len(),
                c_offset,
                c_size,
                d_size
            );
            return Err(einval!(msg));
        }

        let c_offset = (c_offset - self.blob_offset) as usize;
        let input = &self.c_buf[c_offset..c_offset + c_size as usize];
        let decrypted_buffer = crypt::decrypt_with_context(
            input,
            &self.cache.blob_cipher_object(),
            &self.cache.blob_cipher_context(),
            meta.state.is_encrypted(),
        )?;
        let mut output = alloc_buf(d_size as usize);

        self.cache
            .decompress_chunk_data(&decrypted_buffer, &mut output, c_size != d_size)?;

        if output.len() != d_size as usize {
            return Err(einval!(format!(
                "decompressed data size doesn't match: {} vs {}",
                output.len(),
                d_size
            )));
        }

        self.d_buf = output;

        Ok(())
    }

    fn decompress_zran(&mut self, meta: &Arc<BlobCompressionContextInfo>) -> Result<()> {
        let (ctx, dict) = meta
            .get_zran_context(self.zran_idx)
            .ok_or_else(|| einval!("failed to get ZRan context for chunk"))?;
        let c_offset = ctx.in_offset;
        let c_size = ctx.in_len as u64;
        if c_offset < self.blob_offset
            || c_offset.checked_add(c_size).is_none()
            || c_offset + c_size > self.blob_offset + self.c_buf.len() as u64
            || ctx.out_len as u64 > RAFS_MAX_CHUNK_SIZE
        {
            let msg = format!(
                "invalid chunk: z_offset 0x{:x}, z_size 0x{:x}, c_offset 0x{:x}, c_size 0x{:x}, d_size 0x{:x}",
                self.blob_offset,
                self.c_buf.len(),
                c_offset,
                c_size,
                ctx.out_len
            );
            return Err(einval!(msg));
        }

        let c_offset = (c_offset - self.blob_offset) as usize;
        let input = &self.c_buf[c_offset..c_offset + c_size as usize];
        let mut output = alloc_buf(ctx.out_len as usize);
        let mut decoder = ZranDecoder::new()?;
        decoder.uncompress(&ctx, Some(dict), input, &mut output)?;
        self.d_buf = output;

        Ok(())
    }

    fn next_batch(&mut self, chunk: &dyn BlobChunkInfo) -> Result<Vec<u8>> {
        let meta = self
            .cache
            .get_blob_meta_info()?
            .ok_or_else(|| einval!("failed to get blob meta object for Batch"))?;

        // If the chunk is not a batch chunk, decompress it as normal.
        if !meta.is_batch_chunk(chunk.id()) {
            return self.next_buf(chunk);
        }

        let batch_idx = meta.get_batch_index(chunk.id());
        if batch_idx != self.batch_idx {
            self.batch_idx = batch_idx;
            self.decompress_batch(&meta)?;
        }
        let offset = meta.get_uncompressed_offset_in_batch_buf(chunk.id()) as usize;
        let end = offset + chunk.uncompressed_size() as usize;
        if end > self.d_buf.len() {
            return Err(einval!(format!(
                "invalid Batch decompression status, end: {}, len: {}",
                end,
                self.d_buf.len()
            )));
        }

        // Use alloc_buf here to ensure 4k alignment for later use
        // in adjust_buffer_for_dio.
        let mut buffer = alloc_buf(chunk.uncompressed_size() as usize);
        buffer.copy_from_slice(&self.d_buf[offset as usize..end]);
        Ok(buffer)
    }

    fn next_zran(&mut self, chunk: &dyn BlobChunkInfo) -> Result<Vec<u8>> {
        let meta = self
            .cache
            .get_blob_meta_info()?
            .ok_or_else(|| einval!("failed to get blob meta object for ZRan"))?;
        let zran_idx = meta.get_zran_index(chunk.id());
        if zran_idx != self.zran_idx {
            self.zran_idx = zran_idx;
            self.decompress_zran(&meta)?;
        }
        let offset = meta.get_zran_offset(chunk.id()) as usize;
        let end = offset + chunk.uncompressed_size() as usize;
        if end > self.d_buf.len() {
            return Err(einval!("invalid ZRan decompression status"));
        }
        // Use alloc_buf here to ensure 4k alignment for later use
        // in adjust_buffer_for_dio.
        let mut buffer = alloc_buf(chunk.uncompressed_size() as usize);
        buffer.copy_from_slice(&self.d_buf[offset as usize..end]);
        Ok(buffer)
    }

    fn next_buf(&mut self, chunk: &dyn BlobChunkInfo) -> Result<Vec<u8>> {
        let c_offset = chunk.compressed_offset();
        let c_size = chunk.compressed_size();
        let d_size = chunk.uncompressed_size() as usize;
        if c_offset < self.blob_offset
            || c_offset - self.blob_offset > usize::MAX as u64
            || c_offset.checked_add(c_size as u64).is_none()
            || c_offset + c_size as u64 > self.blob_offset + self.c_buf.len() as u64
            || d_size as u64 > RAFS_MAX_CHUNK_SIZE
        {
            let msg = format!(
                "invalid chunk info: c_offset 0x{:x}, c_size 0x{:x}, d_size 0x{:x}, blob_offset 0x{:x}",
                c_offset, c_size, d_size, self.blob_offset
            );
            return Err(eio!(msg));
        }

        let offset_merged = (c_offset - self.blob_offset) as usize;
        let end_merged = offset_merged + c_size as usize;
        let decrypted_buffer = crypt::decrypt_with_context(
            &self.c_buf[offset_merged..end_merged],
            &self.cache.blob_cipher_object(),
            &self.cache.blob_cipher_context(),
            chunk.is_encrypted(),
        )?;
        let mut buffer = alloc_buf(d_size);
        self.cache
            .decompress_chunk_data(&decrypted_buffer, &mut buffer, chunk.is_compressed())?;
        self.cache
            .validate_chunk_data(chunk, &buffer, false)
            .map_err(|e| {
                warn!("failed to read data from backend, {}", e);
                e
            })?;
        Ok(buffer)
    }

    /// Get an immutable reference to the compressed data buffer.
    pub fn compressed_buf(&self) -> &[u8] {
        &self.c_buf
    }
}

impl<'a, 'b> Iterator for ChunkDecompressState<'a, 'b> {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.chunk_idx >= self.chunks.len() {
            return None;
        }

        let cache = self.cache;
        let chunk = self.chunks[self.chunk_idx];
        self.chunk_idx += 1;
        let res = if cache.is_batch() {
            self.next_batch(chunk)
        } else if cache.is_zran() {
            self.next_zran(chunk)
        } else {
            self.next_buf(chunk)
        };
        Some(res)
    }
}

/// Trait representing blob manager to manage a group of [BlobCache](trait.BlobCache.html) objects.
///
/// The main responsibility of the blob cache manager is to create blob cache objects for blobs,
/// all IO requests should be issued to the blob cache object directly.
pub(crate) trait BlobCacheMgr: Send + Sync {
    /// Initialize the blob cache manager.
    fn init(&self) -> Result<()>;

    /// Tear down the blob cache manager.
    fn destroy(&self);

    /// Garbage-collect unused resources.
    ///
    /// Return true if the blob cache manager itself should be garbage-collected.
    fn gc(&self, _id: Option<&str>) -> bool;

    /// Get the underlying `BlobBackend` object of the blob cache object.
    fn backend(&self) -> &(dyn BlobBackend);

    /// Get the blob cache to provide access to the `blob` object.
    fn get_blob_cache(&self, blob_info: &Arc<BlobInfo>) -> Result<Arc<dyn BlobCache>>;

    /// Check the blob cache data status, if data all ready stop prefetch workers.
    fn check_stat(&self);
}

#[cfg(test)]
mod tests {
    use crate::device::{BlobChunkFlags, BlobFeatures};
    use crate::test::MockChunkInfo;

    use super::*;

    #[test]
    fn test_io_merge_state_new() {
        let blob_info = Arc::new(BlobInfo::new(
            1,
            "test1".to_owned(),
            0x200000,
            0x100000,
            0x100000,
            512,
            BlobFeatures::_V5_NO_EXT_BLOB_TABLE,
        ));
        let chunk1 = Arc::new(MockChunkInfo {
            block_id: Default::default(),
            blob_index: 1,
            flags: BlobChunkFlags::empty(),
            compress_size: 0x800,
            uncompress_size: 0x1000,
            compress_offset: 0,
            uncompress_offset: 0,
            file_offset: 0,
            index: 0,
            reserved: 0,
        }) as Arc<dyn BlobChunkInfo>;
        let chunk2 = Arc::new(MockChunkInfo {
            block_id: Default::default(),
            blob_index: 1,
            flags: BlobChunkFlags::empty(),
            compress_size: 0x800,
            uncompress_size: 0x1000,
            compress_offset: 0x800,
            uncompress_offset: 0x1000,
            file_offset: 0x1000,
            index: 1,
            reserved: 0,
        }) as Arc<dyn BlobChunkInfo>;
        let chunk3 = Arc::new(MockChunkInfo {
            block_id: Default::default(),
            blob_index: 1,
            flags: BlobChunkFlags::empty(),
            compress_size: 0x800,
            uncompress_size: 0x1000,
            compress_offset: 0x1000,
            uncompress_offset: 0x1000,
            file_offset: 0x1000,
            index: 1,
            reserved: 0,
        }) as Arc<dyn BlobChunkInfo>;

        let cb = |_merged| {};
        let desc1 = BlobIoDesc {
            blob: blob_info.clone(),
            chunkinfo: chunk1.into(),
            offset: 0,
            size: 0x1000,
            user_io: true,
        };
        let mut state = BlobIoMergeState::new(&desc1, cb);
        assert_eq!(state.size(), 0x800);
        assert_eq!(state.bios.len(), 1);

        let desc2 = BlobIoDesc {
            blob: blob_info.clone(),
            chunkinfo: chunk2.into(),
            offset: 0,
            size: 0x1000,
            user_io: true,
        };
        state.push(&desc2);
        assert_eq!(state.size, 0x1000);
        assert_eq!(state.bios.len(), 2);

        state.issue(0);
        assert_eq!(state.size(), 0x0);
        assert_eq!(state.bios.len(), 0);

        let desc3 = BlobIoDesc {
            blob: blob_info,
            chunkinfo: chunk3.into(),
            offset: 0,
            size: 0x1000,
            user_io: true,
        };
        state.push(&desc3);
        assert_eq!(state.size, 0x800);
        assert_eq!(state.bios.len(), 1);

        state.issue(0);
        assert_eq!(state.size(), 0x0);
        assert_eq!(state.bios.len(), 0);

        let mut count = 0;
        BlobIoMergeState::merge_and_issue(
            &[desc1.clone(), desc2.clone(), desc3.clone()],
            0x4000,
            0x0,
            |_v| count += 1,
        );
        assert_eq!(count, 1);

        let mut count = 0;
        BlobIoMergeState::merge_and_issue(
            &[desc1.clone(), desc2.clone(), desc3.clone()],
            0x1000,
            0x0,
            |_v| count += 1,
        );
        assert_eq!(count, 2);

        let mut count = 0;
        BlobIoMergeState::merge_and_issue(&[desc1.clone(), desc3.clone()], 0x4000, 0x0, |_v| {
            count += 1
        });
        assert_eq!(count, 2);

        assert!(desc1.is_continuous(&desc2, 0));
        assert!(!desc1.is_continuous(&desc3, 0));
    }
}
