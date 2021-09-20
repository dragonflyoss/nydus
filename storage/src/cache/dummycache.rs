// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! A dummy implementation of the [BlobCacheMgr](trait.BlobCacheMgr.html) trait.
//!
//! The [DummyCacheMgr](struct.DummyCacheMgr.html) is a dummy implementation of the
//! [BlobCacheMgr](../trait.BlobCacheMgr.html) trait, which doesn't really cache any data.
//! Instead it just reads data from the backend, uncompressed it if needed and then pass on
//! the data to the clients.
//!
//! There are two possible usage mode of the [DummyCacheMgr]:
//! - Read compressed/uncompressed data from remote Registry/OSS backend but not cache the
//!   uncompressed data on local storage. The
//!   [is_chunk_cached()](../trait.BlobCache.html#tymethod.is_chunk_cached)
//!   method always return false to disable data prefetching.
//! - Read uncompressed data from local disk and no need to double cache the data.
//!   The [is_chunk_cached()](../trait.BlobCache.html#tymethod.is_chunk_cached) method always
//!   return true to enable data prefetching.
use std::io::Result;
use std::sync::Arc;

use nydus_utils::digest;
use vm_memory::VolatileSlice;

use crate::backend::{BlobBackend, BlobReader};
use crate::cache::{BlobCache, BlobCacheMgr};
use crate::device::{BlobChunkInfo, BlobInfo, BlobPrefetchRequest};
use crate::factory::CacheConfig;
use crate::utils::{alloc_buf, copyv};
use crate::{compress, StorageResult};

struct DummyCache {
    reader: Arc<dyn BlobReader>,
    cached: bool,
    compressor: compress::Algorithm,
    digester: digest::Algorithm,
    validate: bool,
}

impl BlobCache for DummyCache {
    fn digester(&self) -> digest::Algorithm {
        self.digester
    }

    fn compressor(&self) -> compress::Algorithm {
        self.compressor
    }

    fn need_validate(&self) -> bool {
        self.validate
    }

    fn blob_size(&self) -> Result<u64> {
        self.reader.blob_size().map_err(|e| eother!(e))
    }

    fn is_chunk_cached(&self, _chunk: &dyn BlobChunkInfo) -> bool {
        self.cached
    }
}

/// A dummy `BlobCacheMgr` implementation, reporting every chunk as cached or not cached as
/// configured.
///
/// The `DummyCacheMgr` is a dummy implementation of the `BlobCacheMgr`, which doesn't really cache
/// data. Instead it just reads data from the backend, uncompressed it if needed and then pass on
/// the data to the clients.
pub struct DummyCacheMgr {
    backend: Arc<dyn BlobBackend>,
    cached: bool,
    compressor: compress::Algorithm,
    digester: digest::Algorithm,
    enable_prefetch: bool,
    validate: bool,
}

impl DummyCacheMgr {
    /// Create a new instance of `DummmyCacheMgr`.
    pub fn new(
        config: CacheConfig,
        backend: Arc<dyn BlobBackend>,
        compressor: compress::Algorithm,
        digester: digest::Algorithm,
        cached: bool,
        enable_prefetch: bool,
    ) -> Result<DummyCacheMgr> {
        Ok(DummyCacheMgr {
            backend,
            cached,
            compressor,
            digester,
            validate: config.cache_validate,
            enable_prefetch,
        })
    }
}

impl BlobCacheMgr for DummyCacheMgr {
    fn init(&self, prefetch_vec: &[BlobPrefetchRequest]) -> Result<()> {
        if self.enable_prefetch {
            for b in prefetch_vec {
                if let Ok(reader) = self.backend.get_reader(&b.blob_id) {
                    let _ = reader.prefetch_blob_data_range(b.offset, b.len);
                }
            }
        }

        Ok(())
    }

    fn destroy(&self) {
        self.backend().shutdown()
    }

    fn backend(&self) -> &(dyn BlobBackend) {
        self.backend.as_ref()
    }

    fn get_blob_cache(&self, blob: BlobInfo) -> Result<Arc<dyn BlobCache>> {
        let reader = self
            .backend
            .get_reader(&blob.blob_id)
            .map_err(|e| eother!(e))?;

        // TODO: set compressor and digester according to blob configuration
        Ok(Arc::new(DummyCache {
            reader,
            cached: self.cached,
            compressor: self.compressor,
            digester: self.digester,
            validate: self.validate,
        }))
    }
}

mod v5 {
    use super::*;
    use crate::cache::v5::BlobV5Cache;
    use crate::device::v5::BlobV5ChunkInfo;
    use crate::device::BlobIoDesc;

    impl BlobV5Cache for DummyCacheMgr {
        fn digester(&self) -> digest::Algorithm {
            self.digester
        }

        fn compressor(&self) -> compress::Algorithm {
            self.compressor
        }

        fn need_validate(&self) -> bool {
            self.validate
        }

        fn blob_size(&self, blob: &BlobInfo) -> Result<u64> {
            let reader = self
                .backend
                .get_reader(&blob.blob_id)
                .map_err(|e| eother!(e))?;

            reader.blob_size().map_err(|e| eother!(e))
        }

        fn is_chunk_cached(&self, _chunk: &dyn BlobV5ChunkInfo, _blob: &BlobInfo) -> bool {
            self.cached
        }

        fn prefetch(&self, bios: &mut [BlobIoDesc]) -> StorageResult<usize> {
            if self.enable_prefetch {
                for b in bios {
                    if let Ok(reader) = self.backend.get_reader(b.blob.blob_id()) {
                        let _ = reader.prefetch_blob_data_range(b.offset, b.size as u32);
                    }
                }
            }

            Ok(0)
        }

        fn stop_prefetch(&self) -> StorageResult<()> {
            // TODO: find a way to disable prefetch
            Ok(())
        }

        fn read(&self, bios: &mut [BlobIoDesc], bufs: &[VolatileSlice]) -> Result<usize> {
            if bios.is_empty() {
                return Err(einval!("parameter `bios` is empty"));
            }

            let bios_len = bios.len();
            let offset = bios[0].offset;
            let chunk = bios[0].chunkinfo.as_v5()?;
            let d_size = chunk.decompress_size() as usize;
            // Use the destination buffer to received the decompressed data if possible.
            if bufs.len() == 1 && bios_len == 1 && offset == 0 && bufs[0].len() >= d_size {
                if !bios[0].user_io {
                    return Ok(0);
                }
                let buf = unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), d_size) };
                return self.read_backend_chunk(&bios[0].blob, chunk.as_ref(), buf, None);
            }

            let mut user_size = 0;
            let mut buffer_holder: Vec<Vec<u8>> = Vec::with_capacity(bios.len());
            for bio in bios.iter() {
                if !bio.user_io {
                    continue;
                }

                let mut d = alloc_buf(chunk.decompress_size() as usize);
                let chunk = bio.chunkinfo.as_v5()?;
                self.read_backend_chunk(&bio.blob, chunk.as_ref(), d.as_mut_slice(), None)?;
                buffer_holder.push(d);
                user_size += bio.size;
            }

            let chunk_buffers: Vec<&[u8]> = buffer_holder.iter().map(|b| b.as_slice()).collect();

            copyv(
                chunk_buffers.as_slice(),
                bufs,
                offset as usize,
                user_size,
                0,
                0,
            )
            .map(|(n, _)| n)
            .map_err(|e| eother!(e))
        }
    }
}
