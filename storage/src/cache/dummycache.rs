// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use fuse_backend_rs::file_buf::FileVolatileSlice;
use nydus_api::CacheConfigV2;
use nydus_utils::crypt::{Algorithm, Cipher, CipherContext};
use nydus_utils::{compress, digest};

use crate::backend::{BlobBackend, BlobReader};
use crate::cache::state::{ChunkMap, NoopChunkMap};
use crate::cache::{BlobCache, BlobCacheMgr};
use crate::device::{
    BlobChunkInfo, BlobFeatures, BlobInfo, BlobIoDesc, BlobIoVec, BlobPrefetchRequest,
};
use crate::utils::{alloc_buf, copyv};
use crate::{StorageError, StorageResult};

struct DummyCache {
    blob_id: String,
    blob_info: Arc<BlobInfo>,
    chunk_map: Arc<dyn ChunkMap>,
    reader: Arc<dyn BlobReader>,
    compressor: compress::Algorithm,
    digester: digest::Algorithm,
    is_legacy_stargz: bool,
    need_validation: bool,
}

impl BlobCache for DummyCache {
    fn blob_id(&self) -> &str {
        &self.blob_id
    }

    fn blob_uncompressed_size(&self) -> Result<u64> {
        Ok(self.blob_info.uncompressed_size())
    }

    fn blob_compressed_size(&self) -> Result<u64> {
        self.reader.blob_size().map_err(|e| eother!(e))
    }

    fn blob_compressor(&self) -> compress::Algorithm {
        self.compressor
    }

    fn blob_cipher(&self) -> Algorithm {
        self.blob_info.cipher()
    }

    fn blob_cipher_object(&self) -> Arc<Cipher> {
        self.blob_info.cipher_object()
    }

    fn blob_cipher_context(&self) -> Option<CipherContext> {
        self.blob_info.cipher_context()
    }

    fn blob_digester(&self) -> digest::Algorithm {
        self.digester
    }

    fn is_legacy_stargz(&self) -> bool {
        self.is_legacy_stargz
    }

    fn need_validation(&self) -> bool {
        self.need_validation
    }

    fn reader(&self) -> &dyn BlobReader {
        &*self.reader
    }

    fn get_chunk_map(&self) -> &Arc<dyn ChunkMap> {
        &self.chunk_map
    }

    fn get_chunk_info(&self, _chunk_index: u32) -> Option<Arc<dyn BlobChunkInfo>> {
        None
    }

    fn start_prefetch(&self) -> StorageResult<()> {
        Ok(())
    }

    fn stop_prefetch(&self) -> StorageResult<()> {
        Ok(())
    }

    fn is_prefetch_active(&self) -> bool {
        false
    }

    fn prefetch(
        &self,
        _blob_cache: Arc<dyn BlobCache>,
        _prefetches: &[BlobPrefetchRequest],
        _bios: &[BlobIoDesc],
    ) -> StorageResult<usize> {
        Err(StorageError::Unsupported)
    }

    fn read(&self, iovec: &mut BlobIoVec, bufs: &[FileVolatileSlice]) -> Result<usize> {
        let bios = &iovec.bi_vec;

        if iovec.size() == 0 || bios.is_empty() {
            return Err(einval!("parameter `bios` is empty"));
        }

        let bios_len = bios.len();
        let offset = bios[0].offset;
        let d_size = bios[0].chunkinfo.uncompressed_size() as usize;
        // Use the destination buffer to receive the uncompressed data if possible.
        if bufs.len() == 1 && bios_len == 1 && offset == 0 && bufs[0].len() >= d_size {
            if !bios[0].user_io {
                return Ok(0);
            }
            if self
                .blob_info
                .get_dedup_by_chunk_idx(bios[0].chunkinfo.id() as usize)
            {
                return Ok(0);
            }
            let buf = unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), d_size) };
            self.read_chunk_from_backend(&bios[0].chunkinfo, buf)?;
            return Ok(buf.len());
        }

        let mut user_size = 0;
        let mut buffer_holder: Vec<Vec<u8>> = Vec::with_capacity(bios.len());
        for bio in bios.iter() {
            if bio.user_io {
                let mut d = alloc_buf(bio.chunkinfo.uncompressed_size() as usize);
                self.read_chunk_from_backend(&bio.chunkinfo, d.as_mut_slice())?;
                buffer_holder.push(d);
                // Even a merged IO can hardly reach u32::MAX. So this is safe
                user_size += bio.size;
            }
        }

        copyv(
            &buffer_holder,
            bufs,
            offset as usize,
            user_size as usize,
            0,
            0,
        )
        .map(|(n, _)| n)
        .map_err(|e| eother!(e))
    }
}

/// A dummy implementation of [BlobCacheMgr](../trait.BlobCacheMgr.html), simply reporting each
/// chunk as cached or not cached according to configuration.
///
/// The `DummyCacheMgr` is a dummy implementation of the `BlobCacheMgr`, which doesn't really cache
/// data. Instead it just reads data from the backend, uncompressed it if needed and then pass on
/// the data to the clients.
pub struct DummyCacheMgr {
    backend: Arc<dyn BlobBackend>,
    cached: bool,
    need_validation: bool,
    closed: AtomicBool,
}

impl DummyCacheMgr {
    /// Create a new instance of `DummmyCacheMgr`.
    pub fn new(
        config: &CacheConfigV2,
        backend: Arc<dyn BlobBackend>,
        cached: bool,
    ) -> Result<DummyCacheMgr> {
        Ok(DummyCacheMgr {
            backend,
            cached,
            need_validation: config.cache_validate,
            closed: AtomicBool::new(false),
        })
    }
}

impl BlobCacheMgr for DummyCacheMgr {
    fn init(&self) -> Result<()> {
        Ok(())
    }

    fn destroy(&self) {
        if !self.closed.load(Ordering::Acquire) {
            self.closed.store(true, Ordering::Release);
            self.backend().shutdown();
        }
    }

    fn gc(&self, _id: Option<&str>) -> bool {
        false
    }

    fn backend(&self) -> &(dyn BlobBackend) {
        self.backend.as_ref()
    }

    fn get_blob_cache(&self, blob_info: &Arc<BlobInfo>) -> Result<Arc<dyn BlobCache>> {
        if blob_info.has_feature(BlobFeatures::ZRAN) {
            return Err(einval!(
                "BlobCacheMgr doesn't support ZRan based RAFS data blobs"
            ));
        }

        let blob_id = blob_info.blob_id();
        let reader = self.backend.get_reader(&blob_id).map_err(|e| eother!(e))?;

        Ok(Arc::new(DummyCache {
            blob_id,
            blob_info: blob_info.clone(),
            chunk_map: Arc::new(NoopChunkMap::new(self.cached)),
            reader,
            compressor: blob_info.compressor(),
            digester: blob_info.digester(),
            is_legacy_stargz: blob_info.is_legacy_stargz(),
            need_validation: self.need_validation && !blob_info.is_legacy_stargz(),
        }))
    }

    fn check_stat(&self) {}
}

impl Drop for DummyCacheMgr {
    fn drop(&mut self) {
        self.destroy();
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;

    use nydus_api::ConfigV2;
    use nydus_utils::metrics::BackendMetrics;
    use vmm_sys_util::tempdir::TempDir;

    use crate::{
        cache::state::IndexedChunkMap,
        device::{BlobIoChunk, BlobIoRange},
        meta::tests::DummyBlobReader,
        test::{MockBackend, MockChunkInfo},
    };

    use super::*;

    #[test]
    fn test_dummy_cache() {
        let info = BlobInfo::new(
            0,
            "blob-0".to_string(),
            800,
            0,
            8,
            100,
            BlobFeatures::empty(),
        );
        let dir = TempDir::new().unwrap();
        let blob_path = dir
            .as_path()
            .join("blob-0")
            .as_os_str()
            .to_str()
            .unwrap()
            .to_string();
        let chunkmap = IndexedChunkMap::new(blob_path.as_str(), 100, true).unwrap();
        let chunkmap_unuse = IndexedChunkMap::new(blob_path.as_str(), 100, true).unwrap();

        let f = OpenOptions::new()
            .truncate(true)
            .create(true)
            .write(true)
            .read(true)
            .open(blob_path.as_str())
            .unwrap();
        assert!(f.set_len(800).is_ok());
        let reader: Arc<dyn BlobReader> = Arc::new(DummyBlobReader {
            metrics: BackendMetrics::new("dummy", "localfs"),
            file: f,
        });
        let cache = DummyCache {
            blob_id: "0".to_string(),
            blob_info: Arc::new(info.clone()),
            chunk_map: Arc::new(chunkmap),
            reader: reader.clone(),
            compressor: compress::Algorithm::None,
            digester: digest::Algorithm::Blake3,
            is_legacy_stargz: false,
            need_validation: false,
        };

        let cache_unuse = DummyCache {
            blob_id: "1".to_string(),
            blob_info: Arc::new(info.clone()),
            chunk_map: Arc::new(chunkmap_unuse),
            reader,
            compressor: compress::Algorithm::None,
            digester: digest::Algorithm::Blake3,
            is_legacy_stargz: false,
            need_validation: false,
        };

        assert!(cache.get_legacy_stargz_size(0, 100).is_ok());
        assert!(!cache.is_zran());
        assert!(!cache.is_batch());
        assert!(cache.get_blob_object().is_none());
        assert!(cache.prefetch_range(&BlobIoRange::default()).is_err());
        assert_eq!(cache.blob_id, "0");
        assert_eq!(cache.blob_uncompressed_size().unwrap(), 800);
        assert_eq!(cache.blob_compressed_size().unwrap(), 0);
        assert_eq!(cache.blob_compressor(), compress::Algorithm::None);
        assert_eq!(cache.blob_cipher(), Algorithm::None);
        match cache.blob_cipher_object().as_ref() {
            Cipher::None => {}
            _ => panic!(),
        }
        assert!(cache.blob_cipher_context().is_none());
        assert_eq!(cache.blob_digester(), digest::Algorithm::Blake3);
        assert!(!cache.is_legacy_stargz());
        assert!(!cache.need_validation());
        let _r = cache.reader();
        let _m = cache.get_chunk_map();
        assert!(cache.get_chunk_info(0).is_none());

        assert!(cache.start_prefetch().is_ok());
        let reqs = BlobPrefetchRequest {
            blob_id: "blob-0".to_string(),
            offset: 0,
            len: 10,
        };
        let iovec_arr: &[BlobIoDesc] = &[];
        let reqs = &[reqs];

        assert!(cache
            .prefetch(Arc::new(cache_unuse), reqs, iovec_arr)
            .is_err());
        assert!(cache.stop_prefetch().is_ok());
        let mut iovec = BlobIoVec::new(Arc::new(info.clone()));
        let chunk: Arc<dyn BlobChunkInfo> = Arc::new(MockChunkInfo {
            block_id: Default::default(),
            blob_index: 0,
            flags: Default::default(),
            compress_size: 0,
            uncompress_size: 800,
            compress_offset: 0,
            uncompress_offset: 0,
            file_offset: 0,
            index: 0,
            reserved: 0,
        });
        iovec.push(BlobIoDesc::new(
            Arc::new(info.clone()),
            BlobIoChunk::from(chunk.clone()),
            0,
            10,
            true,
        ));

        let mut dst_buf1 = vec![0x0u8; 800];
        let volatile_slice_1 =
            unsafe { FileVolatileSlice::from_raw_ptr(dst_buf1.as_mut_ptr(), dst_buf1.len()) };
        let bufs: &[FileVolatileSlice] = &[volatile_slice_1];
        assert_eq!(cache.read(&mut iovec, bufs).unwrap(), 800);

        let chunk2: Arc<dyn BlobChunkInfo> = Arc::new(MockChunkInfo {
            block_id: Default::default(),
            blob_index: 0,
            flags: Default::default(),
            compress_size: 0,
            uncompress_size: 100,
            compress_offset: 0,
            uncompress_offset: 0,
            file_offset: 0,
            index: 0,
            reserved: 0,
        });

        let chunk3: Arc<dyn BlobChunkInfo> = Arc::new(MockChunkInfo {
            block_id: Default::default(),
            blob_index: 0,
            flags: Default::default(),
            compress_size: 0,
            uncompress_size: 100,
            compress_offset: 100,
            uncompress_offset: 0,
            file_offset: 0,
            index: 0,
            reserved: 0,
        });

        let mut iovec = BlobIoVec::new(Arc::new(info.clone()));

        iovec.push(BlobIoDesc::new(
            Arc::new(info.clone()),
            BlobIoChunk::from(chunk2.clone()),
            0,
            100,
            true,
        ));

        iovec.push(BlobIoDesc::new(
            Arc::new(info),
            BlobIoChunk::from(chunk3.clone()),
            100,
            100,
            true,
        ));

        let mut dst_buf2 = vec![0x0u8; 100];
        let mut dst_buf3 = vec![0x0u8; 100];
        let volatile_slice_2 =
            unsafe { FileVolatileSlice::from_raw_ptr(dst_buf2.as_mut_ptr(), dst_buf2.len()) };

        let volatile_slice_3 =
            unsafe { FileVolatileSlice::from_raw_ptr(dst_buf3.as_mut_ptr(), dst_buf3.len()) };
        let bufs: &[FileVolatileSlice] = &[volatile_slice_2, volatile_slice_3];
        assert_eq!(cache.read(&mut iovec, bufs).unwrap(), 200);
    }

    #[test]
    fn test_dummy_cache_mgr() {
        let content = r#"version=2
        id = "my_id"
        metadata_path = "meta_path"
        [backend]
        type = "localfs"
        [backend.localfs]
        blob_file = "/tmp/nydus.blob.data"
        dir = "/tmp"
        alt_dirs = ["/var/nydus/cache"]
        [cache]
        type = "filecache"
        compressed = true
        validate = true
        [cache.filecache]
        work_dir = "/tmp"
        "#;

        let cfg: ConfigV2 = toml::from_str(content).unwrap();
        let backend = MockBackend {
            metrics: BackendMetrics::new("dummy", "localfs"),
        };
        let mgr =
            DummyCacheMgr::new(cfg.get_cache_config().unwrap(), Arc::new(backend), false).unwrap();
        assert!(mgr.init().is_ok());
        assert!(!mgr.gc(Some("blob-0")));
        let _bak = mgr.backend();
        mgr.check_stat();
        mgr.destroy();
        assert!(mgr.closed.load(Ordering::Acquire));
        drop(mgr);
    }
}
