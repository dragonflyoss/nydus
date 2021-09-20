// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::sync::Arc;

use nydus_utils::digest;

use crate::backend::BlobBackend;
use crate::device::{BlobChunkInfo, BlobInfo, BlobPrefetchRequest};
use crate::{compress, StorageResult};

pub mod blobcache;
pub mod chunkmap;
pub mod dummycache;

/// Timeout in milli-seconds to retrieve blob data from backend storage.
pub const SINGLE_INFLIGHT_WAIT_TIMEOUT: u64 = 2000;

/// A segment representing a continuous range in a data chunk.
#[derive(Clone, Debug)]
pub struct ChunkSegment {
    // From where within a chunk user data is stored
    pub offset: u32,
    // Tht user data total length in a chunk
    pub len: u32,
}

impl ChunkSegment {
    /// Create a new instance of `ChunkSegment`.
    pub fn new(offset: u32, len: u32) -> Self {
        Self { offset, len }
    }
}

/// `IoInitiator` denotes that a chunk fulfill user io or internal io.
#[derive(Clone, Debug)]
pub enum IoInitiator {
    /// Io requests to fulfill user requests.
    User(ChunkSegment),
    /// Io requests to fulfill internal requirements with (Chunk index, blob/compressed offset).
    Internal(u32, u64),
}

/// Configuration information for blob data prefetching.
#[derive(Clone, Default)]
pub struct BlobPrefetchConfig {
    /// Whether to enable blob data prefetching.
    pub enable: bool,
    /// Number of data prefetching working threads.
    pub threads_count: usize,
    /// The maximum size of a merged IO request.
    pub merging_size: usize,
    /// Network bandwidth rate limit in unit of Bytes and Zero means no limit.
    pub bandwidth_rate: u32,
}

pub trait BlobCache: Send + Sync {
    /// Get message digest algorithm used by the underlying blob.
    fn digester(&self) -> digest::Algorithm;

    /// Get data compression algorithm used by the underlying blob.
    fn compressor(&self) -> compress::Algorithm;

    /// Check whether need to validate the data chunk.
    fn need_validate(&self) -> bool;

    /// Get size of the blob object.
    fn blob_size(&self) -> Result<u64>;

    /// Check whether data of a chunk has been cached and ready for use.
    fn is_chunk_cached(&self, chunk: &dyn BlobChunkInfo) -> bool;
}

pub trait BlobCacheMgr: Send + Sync {
    /// Initialize the blob cache manager.
    fn init(&self, prefetch_vec: &[BlobPrefetchRequest]) -> Result<()>;

    /// Tear down the blob cache manager.
    fn destroy(&self);

    /// Get the underlying `BlobBackend` object of the blob cache object.
    fn backend(&self) -> &(dyn BlobBackend);

    /// Get the blob cache to provide access to the `blob` object.
    fn get_blob_cache(&self, blob: BlobInfo) -> Result<Arc<dyn BlobCache>>;

    /*
    /// Check whether data of a chunk has been cached and ready for use.
    fn prefetch(&self, bio: &mut [BlobV5Bio]) -> StorageResult<usize>;

    /// Stop prefetching blob data.
    fn stop_prefetch(&self) -> StorageResult<()>;
     */
}

/// Blob cache manager to access Rafs V5 images.
pub mod v5 {
    use std::cmp;
    use std::fmt::Debug;
    use std::fs::File;
    use std::slice;

    use vm_memory::VolatileSlice;

    use super::*;
    use crate::device::v5::BlobV5ChunkInfo;
    use crate::device::BlobIoDesc;
    use crate::utils::{alloc_buf, digest_check};

    /// Trait representing a blob cache manager to access Rafs V5 images.
    pub trait BlobV5Cache: BlobCacheMgr {
        /// Get message digest algorithm used by the underlying blob.
        fn digester(&self) -> digest::Algorithm;

        /// Get data compression algorithm used by the underlying blob.
        fn compressor(&self) -> compress::Algorithm;

        /// Check whether need to validate the data chunk.
        fn need_validate(&self) -> bool;

        /// Get size of the blob object.
        fn blob_size(&self, blob: &BlobInfo) -> Result<u64>;

        //<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
        /// Check whether data of a chunk has been cached.
        fn is_chunk_cached(&self, chunk: &dyn BlobV5ChunkInfo, blob: &BlobInfo) -> bool;

        /// Check whether data of a chunk has been cached and ready for use.
        fn prefetch(&self, bio: &mut [BlobIoDesc]) -> StorageResult<usize>;

        /// Stop prefetching blob data.
        fn stop_prefetch(&self) -> StorageResult<()>;

        /// Read chunk data described by `bio` from the blob into the `bufs`.
        ///
        /// This method should only used to serve RAFS v4/v5 data blobs only because it depends on
        /// the RAFS v4/v5 filesystem metadata information to serve the request.
        //
        // TODO: Cache is indexed by each chunk's block id. When this read request can't
        // hit local cache and it spans two chunks, group more than one requests to backend
        // storage could benefit the performance.
        fn read(&self, bio: &mut [BlobIoDesc], bufs: &[VolatileSlice]) -> Result<usize>;

        /// Read multiple full chunks from the backend storage in batch.
        ///
        /// Callers must ensure that chunks in `cki_set` covers a continuous range, and the range
        /// exactly matches [`blob_offset`..`blob_offset` + `blob_size`].
        /// Function `read_chunks()` returns one buffer containing decompressed chunk data for each
        /// entry in the `cki_set` array in corresponding order.
        fn read_chunks(
            &self,
            blob_id: &str,
            blob_offset: u64,
            blob_size: usize,
            cki_set: &[Arc<dyn BlobV5ChunkInfo>],
        ) -> Result<Vec<Vec<u8>>> {
            // TODO: Also check if sorted and continuous here?

            let mut c_buf = alloc_buf(blob_size);
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

            let mut chunks: Vec<Vec<u8>> = Vec::with_capacity(cki_set.len());
            for cki in cki_set {
                let offset_merged = (cki.compress_offset() - blob_offset) as usize;
                let size_merged = cki.compress_size() as usize;
                let buf = &c_buf[offset_merged..(offset_merged + size_merged)];
                let mut chunk = alloc_buf(cki.decompress_size() as usize);

                self.process_raw_chunk(
                    cki.as_ref(),
                    buf,
                    None,
                    &mut chunk,
                    cki.is_compressed(),
                    self.need_validate(),
                )?;
                chunks.push(chunk);
            }

            Ok(chunks)
        }

        /// Read a whole chunk directly from the storage backend.
        ///
        /// The fetched chunk data may be compressed or not, which depends chunk information from `cki`.
        /// Moreover, chunk data from backend storage may be validated per user's configuration.
        /// Above is not redundant with blob cache's validation given IO path backend -> blobcache
        /// `raw_hook` provides caller a chance to read fetched compressed chunk data.
        fn read_backend_chunk(
            &self,
            blob: &BlobInfo,
            cki: &dyn BlobV5ChunkInfo,
            chunk: &mut [u8],
            raw_hook: Option<&dyn Fn(&[u8])>,
        ) -> Result<usize> {
            let mut d;
            let offset = cki.compress_offset();
            let raw_chunk = if cki.is_compressed() {
                // Need a scratch buffer to decompress compressed data.
                let max_size = self.blob_size(blob)?.checked_sub(offset).ok_or_else(|| {
                    einval!("chunk compressed offset is bigger than blob file size")
                })?;
                let max_size = cmp::min(max_size, usize::MAX as u64);
                let c_size = if self.compressor() == compress::Algorithm::GZip {
                    compress::compute_compressed_gzip_size(chunk.len(), max_size as usize)
                } else {
                    cki.compress_size() as usize
                };
                d = alloc_buf(c_size);
                d.as_mut_slice()
            } else {
                // We have this unsafe assignment as it can directly store data into call's buffer.
                unsafe { slice::from_raw_parts_mut(chunk.as_mut_ptr(), chunk.len()) }
            };

            let size = self
                .backend()
                .read(&blob.blob_id, raw_chunk, offset)
                .map_err(|e| eio!(e))?;

            if size != raw_chunk.len() {
                return Err(eio!("storage backend returns less data than requested"));
            }
            self.process_raw_chunk(
                cki,
                raw_chunk,
                None,
                chunk,
                cki.is_compressed(),
                self.need_validate(),
            )
            .map_err(|e| eio!(format!("fail to read from backend: {}", e)))?;
            if let Some(hook) = raw_hook {
                hook(raw_chunk)
            }

            Ok(chunk.len())
        }

        /// Before storing chunk data into blob cache file. We have cook the raw chunk from
        /// backend a bit as per the chunk description as blob cache always saves plain data
        /// into cache file rather than compressed.
        /// An inside trick is that it tries to directly save data into caller's buffer.
        fn process_raw_chunk(
            &self,
            cki: &dyn BlobV5ChunkInfo,
            raw_chunk: &[u8],
            raw_stream: Option<File>,
            chunk: &mut [u8],
            need_decompress: bool,
            need_validate: bool,
        ) -> Result<usize> {
            if need_decompress {
                compress::decompress(raw_chunk, raw_stream, chunk, self.compressor()).map_err(
                    |e| {
                        error!("failed to decompress chunk: {}", e);
                        e
                    },
                )?;
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

            Ok(d_size)
        }
        //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    }

    //<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    #[derive(Default, Clone)]
    pub(crate) struct MergedBackendRequest {
        // Chunks that are continuous to each other.
        pub chunks: Vec<Arc<dyn BlobV5ChunkInfo>>,
        pub chunk_tags: Vec<IoInitiator>,
        pub blob_offset: u64,
        pub blob_size: u32,
        pub blob_entry: Arc<BlobInfo>,
    }

    impl Debug for MergedBackendRequest {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.debug_struct("MergedBackendRequest")
                .field("blob index", &self.blob_entry.blob_index)
                .field("chunk tags", &self.chunk_tags)
                .field("blob offset", &self.blob_offset)
                .field("blob size", &self.blob_size)
                .finish()
        }
    }

    impl MergedBackendRequest {
        pub(crate) fn new(
            first_cki: Arc<dyn BlobV5ChunkInfo>,
            blob: Arc<BlobInfo>,
            bio: &BlobIoDesc,
        ) -> Self {
            let mut chunks = Vec::<Arc<dyn BlobV5ChunkInfo>>::new();
            let mut tags: Vec<IoInitiator> = Vec::new();
            let blob_size = first_cki.compress_size();
            let blob_offset = first_cki.compress_offset();

            let tag = if bio.user_io {
                IoInitiator::User(ChunkSegment::new(bio.offset, bio.size as u32))
            } else {
                IoInitiator::Internal(first_cki.index(), first_cki.compress_offset())
            };

            chunks.push(first_cki);

            tags.push(tag);

            MergedBackendRequest {
                blob_offset,
                blob_size,
                chunks,
                chunk_tags: tags,
                blob_entry: blob,
            }
        }

        pub(crate) fn merge_one_chunk(&mut self, cki: Arc<dyn BlobV5ChunkInfo>, bio: &BlobIoDesc) {
            self.blob_size += cki.compress_size();

            let tag = if bio.user_io {
                IoInitiator::User(ChunkSegment::new(bio.offset, bio.size as u32))
            } else {
                IoInitiator::Internal(cki.index(), cki.compress_offset())
            };

            self.chunks.push(cki);
            self.chunk_tags.push(tag);
        }
    }
    //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
}
