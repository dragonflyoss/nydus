// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::sync::Arc;

use nydus_utils::digest;
use vm_memory::VolatileSlice;

use crate::backend::{BlobBackend, BlobReader};
use crate::cache::{BlobCache, BlobCacheMgr};
use crate::device::{BlobChunkInfo, BlobEntry, BlobPrefetchControl};
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
pub struct DummyCacheMgr {
    pub backend: Arc<dyn BlobBackend>,
    cached: bool,
    compressor: compress::Algorithm,
    digester: digest::Algorithm,
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
    ) -> Result<DummyCacheMgr> {
        Ok(DummyCacheMgr {
            backend,
            cached,
            compressor,
            digester,
            validate: config.cache_validate,
        })
    }
}

impl BlobCacheMgr for DummyCacheMgr {
    fn init(&self, prefetch_vec: &[BlobPrefetchControl]) -> Result<()> {
        for b in prefetch_vec {
            if let Ok(reader) = self.backend.get_reader(&b.blob_id) {
                let _ = reader.prefetch_blob_data_range(b.offset, b.len);
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

    fn get_blob_cache(&self, blob: BlobEntry) -> Result<Arc<dyn BlobCache>> {
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
    use crate::device::v5::{BlobV5Bio, BlobV5ChunkInfo};

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

        fn blob_size(&self, blob: &BlobEntry) -> Result<u64> {
            let reader = self
                .backend
                .get_reader(&blob.blob_id)
                .map_err(|e| eother!(e))?;

            reader.blob_size().map_err(|e| eother!(e))
        }

        fn is_chunk_cached(&self, _chunk: &dyn BlobV5ChunkInfo, _blob: &BlobEntry) -> bool {
            self.cached
        }

        //<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
        fn prefetch(&self, _bios: &mut [BlobV5Bio]) -> StorageResult<usize> {
            Ok(0)
        }

        fn stop_prefetch(&self) -> StorageResult<()> {
            Ok(())
        }
        //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

        //<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
        fn read(&self, bios: &mut [BlobV5Bio], bufs: &[VolatileSlice]) -> Result<usize> {
            let mut buffer_holder: Vec<Vec<u8>> = Vec::new();
            let offset = bios[0].offset;
            let mut user_size = 0;

            let bios_len = bios.len();

            for bio in bios {
                if !bio.user_io {
                    continue;
                }

                user_size += bio.size;
                let chunk = &bio.chunkinfo;
                let mut reuse = false;
                let d_size = chunk.decompress_size() as usize;
                let one_chunk_buf =
                    if bufs.len() == 1 && bios_len == 1 && offset == 0 && bufs[0].len() >= d_size {
                        // Use the destination buffer to received the decompressed data.
                        reuse = true;
                        unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), d_size) }
                    } else {
                        let d = alloc_buf(d_size);
                        buffer_holder.push(d);
                        buffer_holder.last_mut().unwrap().as_mut_slice()
                    };
                self.read_backend_chunk(&bio.blob, chunk.as_ref(), one_chunk_buf, None)?;
                if reuse {
                    return Ok(one_chunk_buf.len());
                }
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
    //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
}
