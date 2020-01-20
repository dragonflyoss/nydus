// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::sync::Arc;
use std::thread;

use vm_memory::VolatileSlice;

use crate::metadata::digest;
use crate::metadata::layout::OndiskBlobTableEntry;
use crate::metadata::{RafsChunkInfo, RafsSuperMeta};
use crate::storage::backend::BlobBackend;
use crate::storage::cache::*;
use crate::storage::compress;
use crate::storage::device::RafsBio;
use crate::storage::factory::CacheConfig;
use crate::storage::utils::{alloc_buf, copyv};

pub struct DummyCache {
    pub backend: Arc<dyn BlobBackend + Sync + Send>,
    validate: bool,
    prefetch_worker: PrefetchWorker,
    compressor: compress::Algorithm,
    digester: digest::Algorithm,
}

impl RafsCache for DummyCache {
    fn backend(&self) -> &(dyn BlobBackend + Sync + Send) {
        self.backend.as_ref()
    }

    fn has(&self, _blk: Arc<dyn RafsChunkInfo>) -> bool {
        true
    }

    fn init(&self, _sb_meta: &RafsSuperMeta, blobs: &[OndiskBlobTableEntry]) -> Result<()> {
        for b in blobs {
            let _ = self.backend.prefetch_blob(
                b.blob_id.as_str(),
                b.readahead_offset,
                b.readahead_size,
            );
        }
        Ok(())
    }

    fn evict(&self, _blk: Arc<dyn RafsChunkInfo>) -> Result<()> {
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        Ok(())
    }

    fn read(&self, bio: &RafsBio, bufs: &[VolatileSlice], offset: u64) -> Result<usize> {
        let blob_id = &bio.blob_id;
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

        self.read_by_chunk(blob_id, chunk.as_ref(), one_chunk_buf)?;

        if reuse {
            Ok(one_chunk_buf.len())
        } else {
            copyv(one_chunk_buf, bufs, offset, bio.size)
        }
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
    fn prefetch(&self, bios: &mut [RafsBio]) -> Result<usize> {
        let (mut tx, rx) = spmc::channel::<MergedBackendRequest>();
        for num in 0..self.prefetch_worker.threads_count {
            let backend = Arc::clone(&self.backend);
            let rx = rx.clone();
            let _thread = thread::Builder::new()
                .name(format!("prefetch_thread_{}", num))
                .spawn(move || {
                    while let Ok(mr) = rx.recv() {
                        let blob_offset = mr.blob_offset;
                        let blob_size = mr.blob_size;
                        let blob_id = &mr.blob_id;
                        trace!(
                            "Merged req id {} req offset {} size {}",
                            blob_id,
                            blob_offset,
                            blob_size
                        );
                        // Blob id must be unique.
                        // TODO: Currently, request length to backend may span a whole chunk,
                        // Do we need to split it into smaller pieces?
                        if backend
                            .prefetch_blob(blob_id, blob_offset as u32, blob_size)
                            .is_err()
                        {
                            error!(
                                "Readahead from {} for {} bytes failed",
                                blob_offset, blob_size
                            )
                        }
                    }
                    info!("Prefetch thread exits.")
                });
        }

        let mut bios = bios.to_vec();
        let merging_size = self.prefetch_worker.merging_size;
        let _thread = thread::Builder::new().spawn({
            move || {
                generate_merged_requests(bios.as_mut_slice(), &mut tx, merging_size);
            }
        });

        Ok(0)
    }

    fn write(&self, blob_id: &str, blk: &dyn RafsChunkInfo, buf: &[u8]) -> Result<usize> {
        let out;
        let wbuf = if blk.is_compressed() {
            out = compress::compress(buf, self.compressor())?;
            out.0.as_ref()
        } else {
            unsafe { slice::from_raw_parts(buf.as_ptr(), buf.len()) }
        };

        self.backend.write(blob_id, wbuf, blk.compress_offset())
    }

    fn release(&self) {}
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
        prefetch_worker: config.prefetch_worker,
        compressor,
        digester,
    })
}
