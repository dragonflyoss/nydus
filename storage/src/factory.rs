// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Factory to create blob cache objects for blobs.
//!
//! The factory module provides methods to create
//! [blob cache objects](../cache/trait.BlobCache.html) for blobs. Internally it caches a group
//! of [BlobCacheMgr](../cache/trait.BlobCacheMgr.html) objects according to their
//! [ConfigV2](../../api/http/struct.ConfigV2.html). Those cached blob managers may be
//! garbage-collected! by [BlobFactory::gc()](struct.BlobFactory.html#method.gc) if not used anymore.
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::Result as IOResult;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lazy_static::lazy_static;
use nydus_api::{BackendConfigV2, ConfigV2};
use tokio::runtime::{Builder, Runtime};
use tokio::time;

#[cfg(feature = "backend-http-proxy")]
use crate::backend::http_proxy;
#[cfg(feature = "backend-localdisk")]
use crate::backend::localdisk;
#[cfg(feature = "backend-localfs")]
use crate::backend::localfs;
#[cfg(feature = "backend-oss")]
use crate::backend::oss;
#[cfg(feature = "backend-registry")]
use crate::backend::registry;
#[cfg(feature = "backend-s3")]
use crate::backend::s3;
use crate::backend::BlobBackend;
use crate::cache::{BlobCache, BlobCacheMgr, DummyCacheMgr, FileCacheMgr};
use crate::device::BlobInfo;

lazy_static! {
    pub static ref ASYNC_RUNTIME: Arc<Runtime> = {
        let runtime = Builder::new_multi_thread()
                .worker_threads(1) // Limit the number of worker thread to 1 since this runtime is generally used to do blocking IO.
                .thread_keep_alive(Duration::from_secs(10))
                .max_blocking_threads(8)
                .thread_name("cache-flusher")
                .enable_all()
                .build();
        match runtime {
            Ok(v) => Arc::new(v),
            Err(e) => panic!("failed to create tokio async runtime, {}", e),
        }
    };
}

#[derive(Eq, PartialEq)]
struct BlobCacheMgrKey {
    config: Arc<ConfigV2>,
}

#[allow(clippy::derived_hash_with_manual_eq)]
impl Hash for BlobCacheMgrKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.config.id.hash(state);
        if let Some(backend) = self.config.backend.as_ref() {
            backend.backend_type.hash(state);
        }
        if let Some(cache) = self.config.cache.as_ref() {
            cache.cache_type.hash(state);
            cache.prefetch.hash(state);
        }
    }
}

lazy_static::lazy_static! {
    /// Default blob factory.
    pub static ref BLOB_FACTORY: BlobFactory = BlobFactory::new();
}

/// Factory to create blob cache for blob objects.
pub struct BlobFactory {
    mgrs: Mutex<HashMap<BlobCacheMgrKey, Arc<dyn BlobCacheMgr>>>,
    mgr_checker_active: AtomicBool,
}

impl BlobFactory {
    /// Create a new instance of blob factory object.
    pub fn new() -> Self {
        BlobFactory {
            mgrs: Mutex::new(HashMap::new()),
            mgr_checker_active: AtomicBool::new(false),
        }
    }

    pub fn start_mgr_checker(&self) {
        if self
            .mgr_checker_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        ASYNC_RUNTIME.spawn(async {
            let mut interval = time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                BLOB_FACTORY.check_cache_stat();
            }
        });
    }

    /// Create a blob cache object for a blob with specified configuration.
    pub fn new_blob_cache(
        &self,
        config: &Arc<ConfigV2>,
        blob_info: &Arc<BlobInfo>,
    ) -> IOResult<Arc<dyn BlobCache>> {
        let backend_cfg = config.get_backend_config()?;
        let cache_cfg = config.get_cache_config()?;
        let key = BlobCacheMgrKey {
            config: config.clone(),
        };
        let mut guard = self.mgrs.lock().unwrap();
        // Use the existing blob cache manager if there's one with the same configuration.
        if let Some(mgr) = guard.get(&key) {
            return mgr.get_blob_cache(blob_info);
        }
        let backend = Self::new_backend(backend_cfg, &blob_info.blob_id())?;
        let mgr = match cache_cfg.cache_type.as_str() {
            "blobcache" | "filecache" => {
                let mgr = FileCacheMgr::new(cache_cfg, backend, ASYNC_RUNTIME.clone(), &config.id)?;
                mgr.init()?;
                Arc::new(mgr) as Arc<dyn BlobCacheMgr>
            }
            #[cfg(target_os = "linux")]
            "fscache" => {
                let mgr = crate::cache::FsCacheMgr::new(
                    cache_cfg,
                    backend,
                    ASYNC_RUNTIME.clone(),
                    &config.id,
                )?;
                mgr.init()?;
                Arc::new(mgr) as Arc<dyn BlobCacheMgr>
            }
            _ => {
                let mgr = DummyCacheMgr::new(cache_cfg, backend, false)?;
                mgr.init()?;
                Arc::new(mgr) as Arc<dyn BlobCacheMgr>
            }
        };

        let mgr = guard.entry(key).or_insert_with(|| mgr);

        mgr.get_blob_cache(blob_info)
    }

    /// Garbage-collect unused blob cache managers and blob caches.
    pub fn gc(&self, victim: Option<(&Arc<ConfigV2>, &str)>) {
        let mut mgrs = Vec::new();

        if let Some((config, id)) = victim {
            let key = BlobCacheMgrKey {
                config: config.clone(),
            };
            let mgr = self.mgrs.lock().unwrap().get(&key).cloned();
            if let Some(mgr) = mgr {
                if mgr.gc(Some(id)) {
                    mgrs.push((key, mgr.clone()));
                }
            }
        } else {
            for (key, mgr) in self.mgrs.lock().unwrap().iter() {
                if mgr.gc(None) {
                    mgrs.push((
                        BlobCacheMgrKey {
                            config: key.config.clone(),
                        },
                        mgr.clone(),
                    ));
                }
            }
        }

        for (key, mgr) in mgrs {
            let mut guard = self.mgrs.lock().unwrap();
            if mgr.gc(None) {
                guard.remove(&key);
            }
        }
    }

    /// Create a storage backend for the blob with id `blob_id`.
    #[allow(unused_variables)]
    pub fn new_backend(
        config: &BackendConfigV2,
        blob_id: &str,
    ) -> IOResult<Arc<dyn BlobBackend + Send + Sync>> {
        match config.backend_type.as_str() {
            #[cfg(feature = "backend-oss")]
            "oss" => Ok(Arc::new(oss::Oss::new(
                config.get_oss_config()?,
                Some(blob_id),
            )?)),
            #[cfg(feature = "backend-s3")]
            "s3" => Ok(Arc::new(s3::S3::new(
                config.get_s3_config()?,
                Some(blob_id),
            )?)),
            #[cfg(feature = "backend-registry")]
            "registry" => Ok(Arc::new(registry::Registry::new(
                config.get_registry_config()?,
                Some(blob_id),
            )?)),
            #[cfg(feature = "backend-localfs")]
            "localfs" => Ok(Arc::new(localfs::LocalFs::new(
                config.get_localfs_config()?,
                Some(blob_id),
            )?)),
            #[cfg(feature = "backend-localdisk")]
            "localdisk" => Ok(Arc::new(localdisk::LocalDisk::new(
                config.get_localdisk_config()?,
                Some(blob_id),
            )?)),
            #[cfg(feature = "backend-http-proxy")]
            "http-proxy" => Ok(Arc::new(http_proxy::HttpProxy::new(
                config.get_http_proxy_config()?,
                Some(blob_id),
            )?)),
            _ => Err(einval!(format!(
                "unsupported backend type '{}'",
                config.backend_type
            ))),
        }
    }

    fn check_cache_stat(&self) {
        let mgrs = self.mgrs.lock().unwrap();
        for (_key, mgr) in mgrs.iter() {
            mgr.check_stat();
        }
    }
}

impl Default for BlobFactory {
    fn default() -> Self {
        Self::new()
    }
}
