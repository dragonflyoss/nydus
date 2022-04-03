// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs;
use std::io::Result;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, RwLock};

use nydus_utils::metrics::BlobcacheMetrics;
use tokio::runtime::Runtime;

use crate::backend::BlobBackend;
use crate::cache::cachedfile::FileCacheEntry;
use crate::cache::state::{BlobStateMap, IndexedChunkMap};
use crate::cache::worker::{AsyncPrefetchConfig, AsyncRequestState, AsyncWorkerMgr};
use crate::cache::{BlobCache, BlobCacheMgr};
use crate::device::{BlobFeatures, BlobInfo};
use crate::factory::CacheConfig;
use crate::meta::BlobMetaInfo;

fn default_work_dir() -> String {
    ".".to_string()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct FsCacheConfig {
    #[serde(default = "default_work_dir")]
    work_dir: String,
}

impl FsCacheConfig {
    fn get_work_dir(&self) -> Result<&str> {
        let path = fs::metadata(&self.work_dir)
            .or_else(|_| {
                fs::create_dir_all(&self.work_dir)?;
                fs::metadata(&self.work_dir)
            })
            .map_err(|e| {
                last_error!(format!(
                    "fail to stat fscache work_dir {}: {}",
                    self.work_dir, e
                ))
            })?;

        if path.is_dir() {
            Ok(&self.work_dir)
        } else {
            Err(enoent!(format!(
                "fscache work_dir {} is not a directory",
                self.work_dir
            )))
        }
    }
}

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
    validate: bool,
}

impl FsCacheMgr {
    /// Create a new instance of `FileCacheMgr`.
    pub fn new(
        config: CacheConfig,
        backend: Arc<dyn BlobBackend>,
        runtime: Arc<Runtime>,
        id: &str,
    ) -> Result<FsCacheMgr> {
        let blob_config: FsCacheConfig =
            serde_json::from_value(config.cache_config).map_err(|e| einval!(e))?;
        let work_dir = blob_config.get_work_dir()?;
        let metrics = BlobcacheMetrics::new(id, work_dir);
        let prefetch_config: Arc<AsyncPrefetchConfig> = Arc::new(config.prefetch_config.into());
        let worker_mgr = AsyncWorkerMgr::new(metrics.clone(), prefetch_config.clone())?;

        Ok(FsCacheMgr {
            blobs: Arc::new(RwLock::new(HashMap::new())),
            backend,
            metrics,
            prefetch_config,
            runtime,
            worker_mgr: Arc::new(worker_mgr),
            work_dir: work_dir.to_owned(),
            validate: config.cache_validate,
        })
    }

    // Get the file cache entry for the specified blob object.
    fn get(&self, blob: &Arc<BlobInfo>) -> Option<Arc<FileCacheEntry>> {
        self.blobs.read().unwrap().get(blob.blob_id()).cloned()
    }

    // Create a file cache entry for the specified blob object if not present, otherwise
    // return the existing one.
    fn get_or_create_cache_entry(&self, blob: &Arc<BlobInfo>) -> Result<Arc<FileCacheEntry>> {
        if let Some(entry) = self.get(blob) {
            return Ok(entry);
        }

        let entry = FileCacheEntry::new_fs_cache(
            &self,
            blob.clone(),
            self.prefetch_config.clone(),
            self.runtime.clone(),
            self.worker_mgr.clone(),
        )?;
        let entry = Arc::new(entry);
        let mut guard = self.blobs.write().unwrap();
        if let Some(entry) = guard.get(blob.blob_id()) {
            Ok(entry.clone())
        } else {
            guard.insert(blob.blob_id().to_owned(), entry.clone());
            self.metrics
                .underlying_files
                .lock()
                .unwrap()
                .insert(blob.blob_id().to_string());
            Ok(entry)
        }
    }
}

impl BlobCacheMgr for FsCacheMgr {
    fn init(&self) -> Result<()> {
        AsyncWorkerMgr::start(self.worker_mgr.clone())
    }

    fn destroy(&self) {
        self.worker_mgr.stop();
        self.backend().shutdown();
        self.metrics.release().unwrap_or_else(|e| error!("{:?}", e));
    }

    fn gc(&self, id: Option<&str>) {
        let mut reclaim = Vec::new();

        if let Some(blob_id) = id {
            reclaim.push(blob_id.to_string());
        } else {
            let guard = self.blobs.write().unwrap();
            for (id, entry) in guard.iter() {
                if Arc::strong_count(entry) == 1 {
                    reclaim.push(id.to_owned());
                }
            }
        }

        for key in reclaim.iter() {
            let mut guard = self.blobs.write().unwrap();
            if let Some(entry) = guard.get(key) {
                if Arc::strong_count(entry) > 1 {
                    continue;
                }
            }
            guard.remove(key);
        }
    }

    fn backend(&self) -> &(dyn BlobBackend) {
        self.backend.as_ref()
    }

    fn get_blob_cache(&self, blob_info: &Arc<BlobInfo>) -> Result<Arc<dyn BlobCache>> {
        self.get_or_create_cache_entry(blob_info)
            .map(|v| v as Arc<dyn BlobCache>)
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
        if blob_info.has_feature(BlobFeatures::V5_NO_EXT_BLOB_TABLE) {
            return Err(einval!("fscache does not support Rafs v5 blobs"));
        }
        if blob_info.is_stargz() {
            return Err(einval!("fscache does not support stargz blob file"));
        }
        let file = blob_info
            .get_fscache_file()
            .ok_or_else(|| einval!("No fscache file associated with the blob_info"))?;

        let blob_file_path = format!("{}/{}", mgr.work_dir, blob_info.blob_id());
        let chunk_map = Arc::new(BlobStateMap::from(IndexedChunkMap::new(
            &blob_file_path,
            blob_info.chunk_count(),
        )?));
        let reader = mgr
            .backend
            .get_reader(blob_info.blob_id())
            .map_err(|_e| eio!("failed to get blob reader"))?;
        let blob_size = blob_info.uncompressed_size();
        let meta = if blob_info.meta_ci_is_valid() {
            Some(Arc::new(BlobMetaInfo::new(
                &blob_file_path,
                &blob_info,
                Some(&reader),
            )?))
        } else {
            None
        };

        Ok(FileCacheEntry {
            blob_info: blob_info.clone(),
            chunk_map,
            file,
            meta,
            metrics: mgr.metrics.clone(),
            prefetch_state: Arc::new(AtomicU32::new(AsyncRequestState::Init as u32)),
            reader,
            runtime,
            workers,

            blob_size,
            compressor: blob_info.compressor(),
            digester: blob_info.digester(),
            is_get_blob_object_supported: true,
            is_compressed: false,
            is_direct_chunkmap: true,
            is_stargz: false,
            need_validate: mgr.validate,
            prefetch_config,
        })
    }
}
