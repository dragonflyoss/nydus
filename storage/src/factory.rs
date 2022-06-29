// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Factory to create blob cache objects for blobs.
//!
//! The factory module provides methods to create
//! [blob cache objects](../cache/trait.BlobCache.html) for blobs. Internally it caches a group
//! of [BlobCacheMgr](../cache/trait.BlobCacheMgr.html) objects according to their
//! [FactoryConfig](../../api/http/struct.FactoryConfig.html). Those cached blob managers may be garbage-collected
//! by [BlobFactory::gc()](struct.BlobFactory.html#method.gc).
//! if not used anymore.
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::Result as IOResult;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lazy_static::lazy_static;
use tokio::runtime::{Builder, Runtime};

use nydus_api::http::{BackendConfig, FactoryConfig};

#[cfg(feature = "backend-localfs")]
use crate::backend::localfs;
#[cfg(feature = "backend-oss")]
use crate::backend::oss;
#[cfg(feature = "backend-registry")]
use crate::backend::registry;
use crate::backend::BlobBackend;
use crate::cache::{BlobCache, BlobCacheMgr, DummyCacheMgr, FileCacheMgr, FsCacheMgr};
use crate::device::BlobInfo;

lazy_static! {
    static ref ASYNC_RUNTIME: Arc<Runtime> = {
        let runtime = Builder::new_multi_thread()
                .worker_threads(1) // Limit the number of worker thread to 1 since this runtime is generally used to do blocking IO.
                .thread_keep_alive(Duration::from_secs(10))
                .max_blocking_threads(8)
                .thread_name("cache-flusher")
                .build();
        match runtime {
            Ok(v) => Arc::new(v),
            Err(e) => panic!("failed to create tokio async runtime, {}", e),
        }
    };
}

#[derive(Eq, PartialEq)]
struct BlobCacheMgrKey {
    config: Arc<FactoryConfig>,
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for BlobCacheMgrKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.config.id.hash(state);
        self.config.backend.backend_type.hash(state);
        self.config.cache.cache_type.hash(state);
        self.config.cache.prefetch_config.hash(state);
    }
}

lazy_static::lazy_static! {
    /// Default blob factory.
    pub static ref BLOB_FACTORY: BlobFactory = BlobFactory::new();
}

/// Factory to create blob cache for blob objects.
pub struct BlobFactory {
    mgrs: Mutex<HashMap<BlobCacheMgrKey, Arc<dyn BlobCacheMgr>>>,
}

impl BlobFactory {
    /// Create a new instance of blob factory object.
    pub fn new() -> Self {
        BlobFactory {
            mgrs: Mutex::new(HashMap::new()),
        }
    }

    /// Create a blob cache object for a blob with specified configuration.
    pub async fn async_new_blob_cache(
        &self,
        config: &Arc<FactoryConfig>,
        blob_info: &Arc<BlobInfo>,
    ) -> IOResult<Arc<dyn BlobCache>> {
        let key = BlobCacheMgrKey {
            config: config.clone(),
        };
        // Use the existing blob cache manager if there's one with the same configuration.
        let mgr = self.mgrs.lock().unwrap().get(&key).cloned();
        if let Some(mgr) = mgr {
            return mgr.async_get_blob_cache(blob_info).await;
        }

        let backend =
            Self::async_new_backend(key.config.backend.clone(), blob_info.blob_id()).await?;
        let mgr = match key.config.cache.cache_type.as_str() {
            "blobcache" => {
                let mgr = FileCacheMgr::async_new(
                    config.cache.clone(),
                    backend,
                    ASYNC_RUNTIME.clone(),
                    &config.id,
                )
                .await?;
                mgr.init()?;
                Arc::new(mgr) as Arc<dyn BlobCacheMgr>
            }
            "fscache" => {
                let mgr = FsCacheMgr::async_new(
                    config.cache.clone(),
                    backend,
                    ASYNC_RUNTIME.clone(),
                    &config.id,
                )
                .await?;
                mgr.init()?;
                Arc::new(mgr) as Arc<dyn BlobCacheMgr>
            }
            _ => {
                let mgr = DummyCacheMgr::new(config.cache.clone(), backend, false, false)?;
                mgr.init()?;
                Arc::new(mgr) as Arc<dyn BlobCacheMgr>
            }
        };

        let mgr = {
            let mut guard = self.mgrs.lock().unwrap();
            guard.entry(key).or_insert_with(|| mgr).clone()
        };

        mgr.async_get_blob_cache(blob_info).await
    }

    /// Garbage-collect unused blob cache managers and blob caches.
    pub fn gc(&self, victim: Option<(&Arc<FactoryConfig>, &str)>) {
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
    pub async fn async_new_backend(
        config: BackendConfig,
        blob_id: &str,
    ) -> IOResult<Arc<dyn BlobBackend + Send + Sync>> {
        match config.backend_type.as_str() {
            #[cfg(feature = "backend-oss")]
            "oss" => Ok(Arc::new(oss::Oss::new(
                config.backend_config,
                Some(blob_id),
            )?)),
            #[cfg(feature = "backend-registry")]
            "registry" => Ok(Arc::new(registry::Registry::new(
                config.backend_config,
                Some(blob_id),
            )?)),
            #[cfg(feature = "backend-localfs")]
            "localfs" => Ok(Arc::new(localfs::LocalFs::new(
                config.backend_config,
                Some(blob_id),
            )?)),
            _ => Err(einval!(format!(
                "unsupported backend type '{}'",
                config.backend_type
            ))),
        }
    }
}

impl Default for BlobFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_config() {
        let config = BackendConfig {
            backend_type: "localfs".to_string(),
            backend_config: Default::default(),
        };
        let str_val = serde_json::to_string(&config).unwrap();
        let config2 = serde_json::from_str(&str_val).unwrap();

        assert_eq!(config, config2);
    }
}
