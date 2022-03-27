// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Factory to create blob cache objects for blobs.
//!
//! The factory module provides methods to create
//! [blob cache objects](../cache/trait.BlobCache.html) for blobs. Internally it caches a group
//! of [BlobCacheMgr](../cache/trait.BlobCacheMgr.html) objects according to their
//! [FactoryConfig](struct.FactoryConfig.html). Those cached blob managers may be garbage-collected
//! by [BlobFactory::gc()](struct.BlobFactory.html#method.gc).
//! if not used anymore.
use std::collections::HashMap;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::Result as IOResult;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use lazy_static::lazy_static;
use serde::Deserialize;
use serde_json::value::Value;
use tokio::runtime::{Builder, Runtime};

#[cfg(feature = "backend-oss")]
use crate::backend::oss;
#[cfg(feature = "backend-registry")]
use crate::backend::registry;
use crate::backend::{localfs, BlobBackend};
use crate::cache::{BlobCache, BlobCacheMgr, BlobPrefetchConfig, DummyCacheMgr, FileCacheMgr};
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

/// Configuration information for storage backend.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackendConfig {
    /// Type of storage backend.
    #[serde(rename = "type")]
    pub backend_type: String,
    /// Configuration for storage backend.
    #[serde(rename = "config")]
    pub backend_config: Value,
}

impl BackendConfig {
    /// Create a new instance of `BackendConfig`.
    pub fn from_str(backend_type: &str, json_str: &str) -> Result<BackendConfig> {
        let backend_config = serde_json::from_str(json_str)
            .context("failed to parse backend config in JSON string")?;

        Ok(Self {
            backend_type: backend_type.to_string(),
            backend_config,
        })
    }

    /// Load storage backend configuration from a configuration file.
    pub fn from_file(backend_type: &str, file_path: &str) -> Result<BackendConfig> {
        let file = File::open(file_path)
            .with_context(|| format!("failed to open backend config file {}", file_path))?;
        let backend_config = serde_json::from_reader(file)
            .with_context(|| format!("failed to parse backend config file {}", file_path))?;

        Ok(Self {
            backend_type: backend_type.to_string(),
            backend_config,
        })
    }
}

/// Configuration information for blob cache manager.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheConfig {
    /// Type of blob cache.
    #[serde(default, rename = "type")]
    pub cache_type: String,
    /// Whether the data from the cache is compressed, not used anymore.
    #[serde(default, rename = "compressed")]
    pub cache_compressed: bool,
    /// Blob cache manager specific configuration.
    #[serde(default, rename = "config")]
    pub cache_config: Value,
    /// Whether to validate data read from the cache.
    #[serde(skip_serializing, skip_deserializing)]
    pub cache_validate: bool,
    /// Configuration for blob data prefetching.
    #[serde(skip_serializing, skip_deserializing)]
    pub prefetch_config: BlobPrefetchConfig,
}

/// Configuration information to create blob cache manager.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct FactoryConfig {
    /// Id of the factory.
    #[serde(default)]
    pub id: String,
    /// Configuration for storage backend.
    pub backend: BackendConfig,
    /// Configuration for blob cache manager.
    #[serde(default)]
    pub cache: CacheConfig,
}

#[derive(Eq, PartialEq)]
struct BlobCacheMgrKey {
    config: Arc<FactoryConfig>,
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for BlobCacheMgrKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
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
    pub fn new_blob_cache(
        &self,
        config: &Arc<FactoryConfig>,
        blob_info: &Arc<BlobInfo>,
    ) -> IOResult<Arc<dyn BlobCache>> {
        let key = BlobCacheMgrKey {
            config: config.clone(),
        };
        // Use the existing blob cache manager if there's one with the same configuration.
        if let Some(mgr) = self.mgrs.lock().unwrap().get(&key) {
            return mgr.get_blob_cache(blob_info);
        }

        let backend = Self::new_backend(key.config.backend.clone(), blob_info.blob_id())?;
        let mgr = match key.config.cache.cache_type.as_str() {
            "blobcache" => {
                let mgr = FileCacheMgr::new(
                    config.cache.clone(),
                    backend,
                    ASYNC_RUNTIME.clone(),
                    &config.id,
                )?;
                mgr.init()?;
                Arc::new(mgr) as Arc<dyn BlobCacheMgr>
            }
            _ => {
                let mgr = DummyCacheMgr::new(config.cache.clone(), backend, false, false)?;
                mgr.init()?;
                Arc::new(mgr) as Arc<dyn BlobCacheMgr>
            }
        };

        let mut guard = self.mgrs.lock().unwrap();
        let mgr = guard.entry(key).or_insert_with(|| mgr);

        mgr.get_blob_cache(blob_info)
    }

    /// Garbage-collect unused blob cache managers and blob caches.
    pub fn gc(&self) {
        unimplemented!("TODO")
    }

    /// Create a storage backend for the blob with id `blob_id`.
    pub fn new_backend(
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
