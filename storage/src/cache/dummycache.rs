// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::sync::Arc;

use vm_memory::VolatileSlice;

use crate::backend::BlobBackend;
use crate::cache::*;
use crate::device::{BlobPrefetchControl, RafsBio, RafsChunkInfo};
use crate::factory::CacheConfig;
use crate::utils::{alloc_buf, copyv};
use crate::{compress, StorageResult};

use nydus_utils::{digest, eother};

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

    fn read(&self, bio: &RafsBio, bufs: &[VolatileSlice], offset: u64) -> Result<usize> {
        let chunk = &bio.chunkinfo;
        let mut reuse = false;

        let d_size = chunk.decompress_size() as usize;

        let mut d;
        let one_chunk_buf = if bufs.len() == 1 && offset == 0 && bufs[0].len() >= d_size {
            // Use the destination buffer to received the decompressed data.
            reuse = true;
            unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), d_size) }
        } else {
            d = alloc_buf(d_size);
            d.as_mut_slice()
        };

        self.read_backend_chunk(&bio.blob, chunk.as_ref(), one_chunk_buf, |_| Ok(()))?;

        if reuse {
            Ok(one_chunk_buf.len())
        } else {
            copyv(one_chunk_buf, bufs, offset, bio.size)
        }
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

    fn write(&self, blob_id: &str, blk: &dyn RafsChunkInfo, buf: &[u8]) -> Result<usize> {
        let out;
        let wbuf = if blk.is_compressed() {
            out = compress::compress(buf, self.compressor())?;
            out.0.as_ref()
        } else {
            unsafe { slice::from_raw_parts(buf.as_ptr(), buf.len()) }
        };

        self.backend
            .write(blob_id, wbuf, blk.compress_offset())
            .map_err(|e| eother!(e))
    }

    fn release(&self) {
        self.backend().release()
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
