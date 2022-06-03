// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

// Blob cache manager to manage all cached blob objects.
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use nydus_api::http::{BlobCacheEntry, BlobCacheList, BlobObjectParam, BLOB_CACHE_TYPE_BOOTSTRAP};
use rafs::metadata::{RafsMode, RafsSuper};
use storage::cache::FsCacheConfig;
use storage::device::BlobInfo;
use storage::factory::{BackendConfig, CacheConfig, FactoryConfig};

const ID_SPLITTER: &str = "-";

/// Configuration information for cached bootstrap blob objects.
#[derive(Clone)]
pub struct BlobCacheConfigBootstrap {
    blob_id: String,
    scoped_blob_id: String,
    path: PathBuf,
    factory_config: Arc<FactoryConfig>,
}

impl BlobCacheConfigBootstrap {
    /// Get file path of the bootstrap blob file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Configuration information for cached data blob objects.
#[derive(Clone)]
pub struct BlobCacheConfigDataBlob {
    blob_info: Arc<BlobInfo>,
    scoped_blob_id: String,
    factory_config: Arc<FactoryConfig>,
}

impl BlobCacheConfigDataBlob {
    /// Get [`BlobInfo`] of the data blob.
    pub fn blob_info(&self) -> &Arc<BlobInfo> {
        &self.blob_info
    }

    /// Get ['FactoryConfig'] of the data blob.
    pub fn factory_config(&self) -> &Arc<FactoryConfig> {
        &self.factory_config
    }
}

/// Configuration information for cached blob objects.
#[derive(Clone)]
pub enum BlobCacheObjectConfig {
    /// Configuration information for cached bootstrap blob objects.
    Bootstrap(Arc<BlobCacheConfigBootstrap>),
    /// Configuration information for cached data blob objects.
    DataBlob(Arc<BlobCacheConfigDataBlob>),
}

impl BlobCacheObjectConfig {
    fn new_data_blob(
        domain_id: String,
        blob_info: Arc<BlobInfo>,
        factory_config: Arc<FactoryConfig>,
    ) -> Self {
        let scoped_blob_id = if domain_id.is_empty() {
            blob_info.blob_id().to_string()
        } else {
            domain_id + ID_SPLITTER + blob_info.blob_id()
        };

        BlobCacheObjectConfig::DataBlob(Arc::new(BlobCacheConfigDataBlob {
            blob_info,
            scoped_blob_id,
            factory_config,
        }))
    }

    fn new_bootstrap_blob(
        domain_id: String,
        blob_id: String,
        path: PathBuf,
        factory_config: Arc<FactoryConfig>,
    ) -> Self {
        let scoped_blob_id = if domain_id.is_empty() {
            blob_id.clone()
        } else {
            domain_id + ID_SPLITTER + &blob_id
        };

        BlobCacheObjectConfig::Bootstrap(Arc::new(BlobCacheConfigBootstrap {
            blob_id,
            scoped_blob_id,
            path,
            factory_config,
        }))
    }

    fn get_key(&self) -> &str {
        match self {
            BlobCacheObjectConfig::Bootstrap(o) => &o.scoped_blob_id,
            BlobCacheObjectConfig::DataBlob(o) => &o.scoped_blob_id,
        }
    }
}

#[derive(Default)]
struct BlobCacheState {
    id_to_config_map: HashMap<String, BlobCacheObjectConfig>,
}

impl BlobCacheState {
    fn new() -> Self {
        Self {
            id_to_config_map: HashMap::new(),
        }
    }

    fn try_add(&mut self, config: BlobCacheObjectConfig) -> Result<()> {
        let key = config.get_key();
        if self.id_to_config_map.contains_key(key) {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "blob configuration information already exists",
            ));
        }
        self.id_to_config_map.insert(key.to_owned(), config);
        Ok(())
    }

    fn remove(&mut self, domain_id: &str) {
        let scoped_blob_prefix = format!("{}{}", domain_id, ID_SPLITTER);
        self.id_to_config_map.retain(|_k, v| match v {
            BlobCacheObjectConfig::Bootstrap(o) => {
                !o.scoped_blob_id.starts_with(&scoped_blob_prefix)
            }
            BlobCacheObjectConfig::DataBlob(o) => {
                !o.scoped_blob_id.starts_with(&scoped_blob_prefix)
            }
        })
    }

    fn get(&self, key: &str) -> Option<BlobCacheObjectConfig> {
        self.id_to_config_map.get(key).cloned()
    }
}

/// Manager for cached file objects.
#[derive(Default)]
pub struct BlobCacheMgr {
    state: Mutex<BlobCacheState>,
}

impl BlobCacheMgr {
    /// Create a new instance of `BlobCacheMgr`.
    pub fn new() -> Self {
        BlobCacheMgr {
            state: Mutex::new(BlobCacheState::new()),
        }
    }

    /// Add a bootstrap/data blob to be managed by the cache manager.
    ///
    /// When adding a rafs bootstrap blob to the cache manager, all data blobs referenced by the
    /// bootstrap blob will also be added to the cache manager too. It may be used to add a rafs
    /// container image to the cache manager.
    ///
    /// Domains are used to control the blob sharing scope. All bootstrap and data blobs associated
    /// with the same domain will be shared/reused, but blobs associated with different domains are
    /// isolated. The `domain_id` is used to identify the associated domain.
    pub fn add_blob_entry(&self, entry: &BlobCacheEntry) -> Result<()> {
        if entry.blob_type == BLOB_CACHE_TYPE_BOOTSTRAP {
            let (path, factory_config) = self.get_bootstrap_info(entry)?;
            self.add_bootstrap_object(&entry.domain_id, &entry.blob_id, path, factory_config)
                .map_err(|e| {
                    warn!(
                        "blob_cache: failed to add cache entry for bootstrap blob: {:?}",
                        entry
                    );
                    e
                })
        } else {
            warn!("blob_cache: invalid blob cache entry: {:?}", entry);
            Err(einval!("blob_cache: invalid blob cache entry"))
        }
    }

    /// Add a list of bootstrap and/or data blobs.
    pub fn add_blob_list(&self, blobs: &BlobCacheList) -> Result<()> {
        for entry in blobs.blobs.iter() {
            self.add_blob_entry(entry)?;
        }

        Ok(())
    }

    /// Remove a blob object from the cache manager.
    pub fn remove_blob_entry(&self, param: &BlobObjectParam) -> Result<()> {
        let mut state = self.get_state();
        state.remove(&param.domain_id);
        Ok(())
    }

    /// Get configuration information for the blob with `key`.
    pub fn get_config(&self, key: &str) -> Option<BlobCacheObjectConfig> {
        self.get_state().get(key)
    }

    #[inline]
    fn get_state(&self) -> MutexGuard<BlobCacheState> {
        self.state.lock().unwrap()
    }

    fn get_bootstrap_info(&self, entry: &BlobCacheEntry) -> Result<(PathBuf, Arc<FactoryConfig>)> {
        // Validate type of backend and cache.
        let config = &entry.blob_config;
        if config.cache_type != "fscache" {
            return Err(einval!(
                "blob_cache: `config.cache_type` for bootstrap blob is invalid"
            ));
        }
        let cache_config = serde_json::from_value::<FsCacheConfig>(config.cache_config.clone())
            .map_err(|_e| {
                einval!("blob_cache: `config.cache_config` for bootstrap blob is invalid")
            })?;

        let path = config.metadata_path.clone().unwrap_or_default();
        if path.is_empty() {
            return Err(einval!(
                "blob_cache: `config.metadata_path` for bootstrap blob is empty"
            ));
        }
        let path = Path::new(&path).canonicalize().map_err(|_e| {
            einval!("blob_cache: `config.metadata_path` for bootstrap blob is invalid")
        })?;
        if !path.is_file() {
            return Err(einval!(
                "blob_cache: `config.metadata_path` for bootstrap blob is not a file"
            ));
        }

        // Validate the working directory for fscache
        let path2 = Path::new(&cache_config.work_dir);
        let path2 = path2
            .canonicalize()
            .map_err(|_e| eio!("blob_cache: `config.cache_config.work_dir` is invalid"))?;
        if !path2.is_dir() {
            return Err(einval!(
                "blob_cache: `config.cache_config.work_dir` is not a directory"
            ));
        }

        let prefetch_config = match serde_json::from_value(entry.fs_prefetch.clone()) {
            Ok(fs_prefetch) => fs_prefetch,
            Err(_e) => Default::default(),
        };
        let factory_config = Arc::new(FactoryConfig {
            id: entry.blob_config.id.clone(),
            backend: BackendConfig {
                backend_type: entry.blob_config.backend_type.clone(),
                backend_config: entry.blob_config.backend_config.clone(),
            },
            cache: CacheConfig {
                cache_type: entry.blob_config.cache_type.clone(),
                cache_compressed: false,
                cache_config: entry.blob_config.cache_config.clone(),
                cache_validate: false,
                prefetch_config,
            },
        });

        Ok((path, factory_config))
    }

    fn add_bootstrap_object(
        &self,
        domain_id: &str,
        id: &str,
        path: PathBuf,
        factory_config: Arc<FactoryConfig>,
    ) -> Result<()> {
        let rs = RafsSuper::load_from_metadata(&path, RafsMode::Direct, true)?;
        let meta_config = BlobCacheObjectConfig::new_bootstrap_blob(
            domain_id.to_string(),
            id.to_string(),
            path,
            factory_config.clone(),
        );

        let mut state = self.get_state();
        state.try_add(meta_config)?;

        // Try to add the referenced data blob object if it doesn't exist yet.
        for bi in rs.superblock.get_blob_infos() {
            debug!(
                "blob_cache: found blob {} in domain {}",
                &bi.blob_id(),
                domain_id
            );
            let blob_config = BlobCacheObjectConfig::new_data_blob(
                domain_id.to_string(),
                bi,
                factory_config.clone(),
            );
            state.try_add(blob_config)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmm_sys_util::tempdir::TempDir;

    fn create_factory_config() -> String {
        let config = r#"
        {
            "type": "bootstrap",
            "id": "bootstrap1",
            "domain_id": "userid1",
            "config": {
                "id": "factory1",
                "backend_type": "localfs",
                "backend_config": {
                    "dir": "/tmp/nydus"
                },
                "cache_type": "fscache",
                "cache_config": {
                    "work_dir": "/tmp/nydus"
                },
                "metadata_path": "/tmp/nydus/bootstrap1"
            }
          }"#;

        config.to_string()
    }

    #[test]
    fn test_blob_cache_entry() {
        let tmpdir = TempDir::new().unwrap();
        let path = tmpdir.as_path().join("bootstrap1");
        std::fs::write(&path, "metadata").unwrap();
        let config = create_factory_config();
        let content = config.replace("/tmp/nydus", tmpdir.as_path().to_str().unwrap());
        let entry: BlobCacheEntry = serde_json::from_str(&content).unwrap();

        assert_eq!(&entry.blob_type, "bootstrap");
        assert_eq!(&entry.blob_id, "bootstrap1");
        assert_eq!(&entry.domain_id, "userid1");
        assert_eq!(&entry.blob_config.id, "factory1");
        assert_eq!(&entry.blob_config.backend_type, "localfs");
        assert_eq!(&entry.blob_config.cache_type, "fscache");
        assert!(entry.blob_config.metadata_path.is_some());
        assert!(entry.blob_config.backend_config.is_object());
        assert!(entry.blob_config.cache_config.is_object());

        let mgr = BlobCacheMgr::new();
        let (path, factory_config) = mgr.get_bootstrap_info(&entry).unwrap();
        assert_eq!(path, tmpdir.as_path().join("bootstrap1"));
        assert_eq!(&factory_config.id, "factory1");
        assert_eq!(&factory_config.backend.backend_type, "localfs");
        assert_eq!(&factory_config.cache.cache_type, "fscache");

        let blob = BlobCacheConfigBootstrap {
            blob_id: "123456789-123".to_string(),
            scoped_blob_id: "domain1".to_string(),
            path: path.clone(),
            factory_config,
        };
        assert_eq!(blob.path(), &path);
    }

    #[test]
    fn test_blob_cache_list() {
        let config = r#"
         {
            "blobs" : [
                {
                    "type": "bootstrap",
                    "id": "bootstrap1",
                    "domain_id": "userid1",
                    "config": {
                        "id": "factory1",
                        "backend_type": "localfs",
                        "backend_config": {
                            "dir": "/tmp/nydus"
                        },
                        "cache_type": "fscache",
                        "cache_config": {
                            "work_dir": "/tmp/nydus"
                        },
                        "metadata_path": "/tmp/nydus/bootstrap1"
                    }
                },
                {
                    "type": "bootstrap",
                    "id": "bootstrap2",
                    "domain_id": "userid2",
                    "config": {
                        "id": "factory1",
                        "backend_type": "localfs",
                        "backend_config": {
                            "dir": "/tmp/nydus"
                        },
                        "cache_type": "fscache",
                        "cache_config": {
                            "work_dir": "/tmp/nydus"
                        },
                        "metadata_path": "/tmp/nydus/bootstrap2"
                    }
                }
            ]
         }"#;
        let list: BlobCacheList = serde_json::from_str(config).unwrap();

        assert_eq!(list.blobs.len(), 2);
        assert_eq!(&list.blobs[0].blob_type, "bootstrap");
        assert_eq!(&list.blobs[0].blob_id, "bootstrap1");
        assert_eq!(&list.blobs[0].blob_config.id, "factory1");
        assert_eq!(&list.blobs[0].blob_config.backend_type, "localfs");
        assert_eq!(&list.blobs[0].blob_config.cache_type, "fscache");
        assert_eq!(&list.blobs[1].blob_type, "bootstrap");
        assert_eq!(&list.blobs[1].blob_id, "bootstrap2");
    }
}
