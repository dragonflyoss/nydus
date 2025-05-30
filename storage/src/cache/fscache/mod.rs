// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::File;
use std::io::{Error, Result};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, RwLock};

use nydus_api::CacheConfigV2;
use nydus_utils::metrics::BlobcacheMetrics;
use tokio::runtime::Runtime;

use crate::backend::BlobBackend;
use crate::cache::cachedfile::{FileCacheEntry, FileCacheMeta};
use crate::cache::filecache::BLOB_DATA_FILE_SUFFIX;
use crate::cache::state::{BlobStateMap, IndexedChunkMap, RangeMap};
use crate::cache::worker::{AsyncPrefetchConfig, AsyncWorkerMgr};
use crate::cache::{BlobCache, BlobCacheMgr, CasMgr};
use crate::device::{BlobFeatures, BlobInfo, BlobObject};
use crate::factory::BLOB_FACTORY;
use crate::utils::get_path_from_file;

const FSCACHE_BLOBS_CHECK_NUM: u8 = 1;

/// An implementation of [BlobCacheMgr](../trait.BlobCacheMgr.html) to improve performance by
/// caching uncompressed blob with Linux fscache subsystem.
#[derive(Clone)]
pub struct FsCacheMgr {
    blobs: Arc<RwLock<HashMap<String, Arc<FileCacheEntry>>>>,
    backend: Arc<dyn BlobBackend>,
    metrics: Arc<BlobcacheMetrics>,
    prefetch_config: Arc<AsyncPrefetchConfig>,
    runtime: Arc<Runtime>,
    worker_mgr: Arc<AsyncWorkerMgr>,
    work_dir: String,
    need_validation: bool,
    blobs_check_count: Arc<AtomicU8>,
    closed: Arc<AtomicBool>,
    user_io_batch_size: u32,
}

impl FsCacheMgr {
    /// Create a new instance of `FileCacheMgr`.
    pub fn new(
        config: &CacheConfigV2,
        backend: Arc<dyn BlobBackend>,
        runtime: Arc<Runtime>,
        id: &str,
        user_io_batch_size: u32,
    ) -> Result<FsCacheMgr> {
        if config.cache_compressed {
            return Err(enosys!("fscache doesn't support compressed cache mode"));
        }

        let blob_cfg = config.get_fscache_config()?;
        let work_dir = blob_cfg.get_work_dir()?;
        let metrics = BlobcacheMetrics::new(id, work_dir);
        let prefetch_config: Arc<AsyncPrefetchConfig> = Arc::new((&config.prefetch).into());
        let worker_mgr = AsyncWorkerMgr::new(metrics.clone(), prefetch_config.clone())?;

        BLOB_FACTORY.start_mgr_checker();

        Ok(FsCacheMgr {
            blobs: Arc::new(RwLock::new(HashMap::new())),
            backend,
            metrics,
            prefetch_config,
            runtime,
            worker_mgr: Arc::new(worker_mgr),
            work_dir: work_dir.to_owned(),
            need_validation: config.cache_validate,
            blobs_check_count: Arc::new(AtomicU8::new(0)),
            closed: Arc::new(AtomicBool::new(false)),
            user_io_batch_size,
        })
    }

    // Get the file cache entry for the specified blob object.
    fn get(&self, blob: &Arc<BlobInfo>) -> Option<Arc<FileCacheEntry>> {
        self.blobs.read().unwrap().get(&blob.blob_id()).cloned()
    }

    // Create a file cache entry for the specified blob object if not present, otherwise
    // return the existing one.
    fn get_or_create_cache_entry(&self, blob: &Arc<BlobInfo>) -> Result<Arc<FileCacheEntry>> {
        if let Some(entry) = self.get(blob) {
            return Ok(entry);
        }

        let entry = FileCacheEntry::new_fs_cache(
            self,
            blob.clone(),
            self.prefetch_config.clone(),
            self.runtime.clone(),
            self.worker_mgr.clone(),
        )?;
        let entry = Arc::new(entry);
        let mut guard = self.blobs.write().unwrap();
        if let Some(entry) = guard.get(&blob.blob_id()) {
            Ok(entry.clone())
        } else {
            let blob_id = blob.blob_id();
            guard.insert(blob_id.clone(), entry.clone());
            self.metrics
                .underlying_files
                .lock()
                .unwrap()
                .insert(blob_id + BLOB_DATA_FILE_SUFFIX);
            Ok(entry)
        }
    }
}

impl BlobCacheMgr for FsCacheMgr {
    fn init(&self) -> Result<()> {
        AsyncWorkerMgr::start(self.worker_mgr.clone())
    }

    fn destroy(&self) {
        if !self.closed.load(Ordering::Acquire) {
            self.closed.store(true, Ordering::Release);
            self.worker_mgr.stop();
            self.backend().shutdown();
            self.metrics.release().unwrap_or_else(|e| error!("{:?}", e));
        }
    }

    fn gc(&self, id: Option<&str>) -> bool {
        if let Some(blob_id) = id {
            self.blobs.write().unwrap().remove(blob_id);
        } else {
            let mut reclaim = Vec::new();
            let guard = self.blobs.write().unwrap();
            for (id, entry) in guard.iter() {
                if Arc::strong_count(entry) == 1 {
                    reclaim.push(id.to_owned());
                }
            }
            drop(guard);

            for key in reclaim.iter() {
                let mut guard = self.blobs.write().unwrap();
                if let Some(entry) = guard.get(key) {
                    if Arc::strong_count(entry) == 1 {
                        guard.remove(key);
                    }
                }
            }
        }

        self.blobs.read().unwrap().len() == 0
    }

    fn backend(&self) -> &(dyn BlobBackend) {
        self.backend.as_ref()
    }

    fn get_blob_cache(&self, blob_info: &Arc<BlobInfo>) -> Result<Arc<dyn BlobCache>> {
        self.get_or_create_cache_entry(blob_info)
            .map(|v| v as Arc<dyn BlobCache>)
    }

    fn check_stat(&self) {
        let guard = self.blobs.read().unwrap();

        let mut all_ready = true;
        for (_id, entry) in guard.iter() {
            if !entry.is_all_data_ready() {
                all_ready = false;
                break;
            }
        }

        // we should double check blobs stat, in case some blobs hadn't been created when we checked.
        if all_ready {
            if self.blobs_check_count.load(Ordering::Acquire) == FSCACHE_BLOBS_CHECK_NUM {
                self.worker_mgr.stop();
                self.metrics.data_all_ready.store(true, Ordering::Release);
            } else {
                self.blobs_check_count.fetch_add(1, Ordering::Acquire);
            }
        } else {
            self.blobs_check_count.store(0, Ordering::Release);
        }
    }
}

impl Drop for FsCacheMgr {
    fn drop(&mut self) {
        self.destroy();
    }
}

impl FileCacheEntry {
    pub fn new_fs_cache(
        mgr: &FsCacheMgr,
        blob_info: Arc<BlobInfo>,
        prefetch_config: Arc<AsyncPrefetchConfig>,
        runtime: Arc<Runtime>,
        workers: Arc<AsyncWorkerMgr>,
    ) -> Result<Self> {
        if blob_info.has_feature(BlobFeatures::_V5_NO_EXT_BLOB_TABLE) {
            return Err(einval!("fscache does not support Rafs v5 blobs"));
        }
        let is_tarfs = blob_info.features().is_tarfs();
        if is_tarfs {
            return Err(einval!("fscache does not support RAFS in tarfs mode"));
        }

        let file = blob_info
            .get_fscache_file()
            .ok_or_else(|| einval!("No fscache file associated with the blob_info"))?;
        let is_separate_meta = blob_info.has_feature(BlobFeatures::SEPARATE);
        let is_batch = blob_info.has_feature(BlobFeatures::BATCH);
        let is_zran = blob_info.has_feature(BlobFeatures::ZRAN);
        let cache_cipher = blob_info.cipher();
        let is_cache_encrypted = cache_cipher.is_encryption_enabled();
        let blob_id = blob_info.blob_id();
        let blob_meta_id = if is_separate_meta {
            blob_info.get_blob_meta_id()?
        } else {
            blob_id.clone()
        };
        let reader = mgr
            .backend
            .get_reader(&blob_id)
            .map_err(|_e| eio!("failed to get reader for data blob"))?;
        let blob_meta_reader = if is_separate_meta {
            mgr.backend.get_reader(&blob_meta_id).map_err(|e| {
                eio!(format!(
                    "failed to get reader for blob.meta {}, {}",
                    blob_id, e
                ))
            })?
        } else {
            reader.clone()
        };
        let blob_compressed_size = Self::get_blob_size(&reader, &blob_info)?;

        // Turn off chunk deduplication in case of tarfs.
        let cas_mgr = if is_tarfs {
            warn!("chunk deduplication trun off");
            None
        } else {
            #[cfg(feature = "dedup")]
            {
                CasMgr::get_singleton()
            }
            #[cfg(not(feature = "dedup"))]
            None
        };

        let need_validation = mgr.need_validation
            && !blob_info.is_legacy_stargz()
            && blob_info.has_feature(BlobFeatures::INLINED_CHUNK_DIGEST);
        let load_chunk_digest = need_validation || cas_mgr.is_some();
        let blob_file_path = format!("{}/{}", mgr.work_dir, blob_meta_id);
        let meta = if blob_info.meta_ci_is_valid() {
            FileCacheMeta::new(
                blob_file_path.clone(),
                blob_info.clone(),
                Some(blob_meta_reader),
                None,
                true,
                load_chunk_digest,
            )?
        } else {
            return Err(enosys!(
                "fscache doesn't support blobs without blob meta information"
            ));
        };

        let chunk_map = Arc::new(BlobStateMap::from(IndexedChunkMap::new(
            &format!("{}{}", blob_file_path, BLOB_DATA_FILE_SUFFIX),
            blob_info.chunk_count(),
            false,
        )?));
        Self::restore_chunk_map(blob_info.clone(), file.clone(), &meta, &chunk_map);

        let mut blob_data_file_path = String::new();
        if cas_mgr.is_some() {
            blob_data_file_path = if let Some(path) = get_path_from_file(&file) {
                path
            } else {
                warn!("can't get path from file");
                "".to_string()
            }
        }

        Ok(FileCacheEntry {
            blob_id,
            blob_info: blob_info.clone(),
            cache_cipher_object: Default::default(),
            cache_cipher_context: Default::default(),
            cas_mgr,
            chunk_map,
            file,
            file_path: Arc::new(blob_data_file_path),
            meta: Some(meta),
            metrics: mgr.metrics.clone(),
            prefetch_state: Arc::new(AtomicU32::new(0)),
            reader,
            runtime,
            workers,

            blob_compressed_size,
            blob_uncompressed_size: blob_info.uncompressed_size(),
            is_get_blob_object_supported: true,
            is_raw_data: false,
            is_direct_chunkmap: true,
            is_cache_encrypted,
            is_legacy_stargz: blob_info.is_legacy_stargz(),
            is_tarfs,
            is_batch,
            is_zran,
            dio_enabled: true,
            need_validation,
            user_io_batch_size: mgr.user_io_batch_size,
            prefetch_config,
        })
    }

    fn restore_chunk_map(
        blob_info: Arc<BlobInfo>,
        file: Arc<File>,
        meta: &FileCacheMeta,
        chunk_map: &BlobStateMap<IndexedChunkMap, u32>,
    ) {
        let blob_meta = match meta.get_blob_meta() {
            Some(v) => v,
            None => {
                warn!("failed to get blob meta object for blob, skip chunkmap recover");
                return;
            }
        };

        let mut i = 0;
        while i < blob_info.chunk_count() {
            let hole_offset = unsafe {
                libc::lseek64(
                    file.as_raw_fd(),
                    blob_meta.get_uncompressed_offset(i as usize) as i64,
                    libc::SEEK_HOLE,
                )
            };

            if hole_offset < 0 {
                warn!(
                    "seek hole err {} for blob {}",
                    Error::last_os_error(),
                    blob_info.blob_id()
                );
                break;
            }

            if hole_offset as u64 == blob_info.uncompressed_size() {
                debug!(
                    "seek hole to file end, blob {} rest chunks {} - {} all ready",
                    blob_info.blob_id(),
                    i,
                    blob_info.chunk_count() - 1,
                );
                if let Err(e) =
                    chunk_map.set_range_ready_and_clear_pending(i, blob_info.chunk_count() - i)
                {
                    warn!("set range ready err {}", e);
                }
                break;
            }

            let hole_index = match blob_meta.get_chunk_index(hole_offset as u64) {
                Ok(h) => h as u32,
                Err(e) => {
                    warn!("get offset chunk index err {}", e);
                    break;
                }
            };
            if hole_index > i {
                debug!(
                    "set blob {} rang {}-{} ready",
                    blob_info.blob_id(),
                    i,
                    hole_index - 1,
                );
                if let Err(e) = chunk_map.set_range_ready_and_clear_pending(i, hole_index - i) {
                    warn!("set range ready err {}", e);
                    break;
                }
            }
            i = hole_index + 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::OpenOptions, path::PathBuf};

    use nydus_api::ConfigV2;
    use nydus_utils::{compress, metrics::BackendMetrics};

    use crate::{factory::ASYNC_RUNTIME, test::MockBackend, RAFS_DEFAULT_CHUNK_SIZE};

    use super::*;

    #[test]
    fn test_fs_cache_mgr() {
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
        type = "fscache"
        compressed = false
        validate = true
        [cache.fscache]
        work_dir = "/tmp"
        "#;

        let cfg: ConfigV2 = toml::from_str(content).unwrap();
        let backend = MockBackend {
            metrics: BackendMetrics::new("dummy", "localfs"),
        };

        let mut mgr: FsCacheMgr = FsCacheMgr::new(
            cfg.get_cache_config().unwrap(),
            Arc::new(backend),
            ASYNC_RUNTIME.clone(),
            &cfg.id,
            0,
        )
        .unwrap();
        assert!(mgr.init().is_ok());
        mgr.work_dir = "../tests/texture/zran/".to_string();

        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = PathBuf::from(root_dir).join("../tests/texture/zran/233c72f2b6b698c07021c4da367cfe2dff4f049efbaa885ca0ff760ea297865a");

        let features = BlobFeatures::ALIGNED
            | BlobFeatures::INLINED_FS_META
            | BlobFeatures::CHUNK_INFO_V2
            | BlobFeatures::ZRAN;

        let mut blob_info = BlobInfo::new(
            0,
            "233c72f2b6b698c07021c4da367cfe2dff4f049efbaa885ca0ff760ea297865a".to_string(),
            0x16c6000,
            9839040,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            0xa3,
            features,
        );

        blob_info.set_blob_meta_info(0, 0xa1290, 0xa1290, compress::Algorithm::None as u32);

        let f1: File = OpenOptions::new()
            .truncate(true)
            .create(true)
            .write(true)
            .read(true)
            .open(path.as_os_str())
            .unwrap();
        f1.set_len(800).unwrap();

        blob_info.set_fscache_file(Some(Arc::new(f1.try_clone().unwrap())));

        assert!(mgr.get_blob_cache(&Arc::new(blob_info.clone())).is_ok());
        assert!(mgr.gc(Some(
            "233c72f2b6b698c07021c4da367cfe2dff4f049efbaa885ca0ff760ea297865a"
        )));
        mgr.check_stat();
        let _backend = mgr.backend();
        mgr.destroy();
        drop(mgr);
    }
}
