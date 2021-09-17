// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::sync::Arc;

use vm_memory::VolatileSlice;

use crate::backend::BlobBackend;
use crate::cache::*;
use crate::device::{BlobPrefetchControl, RafsBio};
use crate::factory::CacheConfig;
use crate::utils::{alloc_buf, copyv};
use crate::{compress, StorageResult};

use nydus_utils::digest;

pub struct DummyCache {
    pub backend: Arc<dyn BlobBackend + Sync + Send>,
    validate: bool,
    compressor: compress::Algorithm,
    digester: digest::Algorithm,
}

impl RafsCache for DummyCache {
    fn backend(&self) -> &(dyn BlobBackend + Sync + Send) {
        self.backend.as_ref()
    }

    fn init(&self, prefetch_vec: &[BlobPrefetchControl]) -> Result<()> {
        for b in prefetch_vec {
            let _ = self.backend.prefetch_blob(&b.blob_id, b.offset, b.len);
        }
        Ok(())
    }

    fn read(&self, bios: &mut [RafsBio], bufs: &[VolatileSlice]) -> Result<usize> {
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

    fn blob_size(&self, blob: &RafsBlobEntry) -> Result<u64> {
        self.backend()
            .blob_size(&blob.blob_id)
            .map_err(|e| eother!(e))
    }

    fn digester(&self) -> digest::Algorithm {
        self.digester
    }

    fn compressor(&self) -> compress::Algorithm {
        self.compressor
    }

    fn need_validate(&self) -> bool {
        self.validate
    }

    /// Prefetch works when blobcache is enabled
    fn prefetch(&self, _bios: &mut [RafsBio]) -> StorageResult<usize> {
        Ok(0)
    }

    fn stop_prefetch(&self) -> StorageResult<()> {
        Ok(())
    }

    fn release(&self) {
        self.backend().release()
    }

    fn is_chunk_cached(&self, _chunk: &dyn RafsChunkInfo, _blob: &RafsBlobEntry) -> bool {
        false
    }
}

pub fn new(
    config: CacheConfig,
    backend: Arc<dyn BlobBackend + Sync + Send>,
    compressor: compress::Algorithm,
    digester: digest::Algorithm,
) -> Result<DummyCache> {
    Ok(DummyCache {
        backend,
        validate: config.cache_validate,
        compressor,
        digester,
    })
}
