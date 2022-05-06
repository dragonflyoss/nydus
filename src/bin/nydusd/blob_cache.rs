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

#[derive(Clone)]
pub struct BlobCacheConfigBootstrap {
    blob_id: String,
    scoped_blob_id: String,
    path: PathBuf,
    factory_config: Arc<FactoryConfig>,
}

impl BlobCacheConfigBootstrap {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Clone)]
pub struct BlobCacheConfigDataBlob {
    blob_info: Arc<BlobInfo>,
    scoped_blob_id: String,
    factory_config: Arc<FactoryConfig>,
}

impl BlobCacheConfigDataBlob {
    pub fn blob_info(&self) -> &Arc<BlobInfo> {
        &self.blob_info
    }

    pub fn factory_config(&self) -> &Arc<FactoryConfig> {
        &self.factory_config
    }
}

#[derive(Clone)]
pub enum BlobCacheObjectConfig {
    DataBlob(Arc<BlobCacheConfigDataBlob>),
    Bootstrap(Arc<BlobCacheConfigBootstrap>),
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
            domain_id + "-" + blob_info.blob_id()
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
            domain_id + "-" + &blob_id
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

    fn remove(&mut self, domain_id: &str) {
        let scoped_blob_prefix = format!("{}-", domain_id);
        self.id_to_config_map.retain(|_k, v| match v {
            BlobCacheObjectConfig::Bootstrap(o) => {
                !o.scoped_blob_id.starts_with(&scoped_blob_prefix)
            }
            BlobCacheObjectConfig::DataBlob(o) => {
                !o.scoped_blob_id.starts_with(&scoped_blob_prefix)
            }
        })
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

    fn get(&self, key: &str) -> Option<BlobCacheObjectConfig> {
        self.id_to_config_map.get(key).cloned()
    }
}

/// Struct to maintain cached file objects.
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

    /// Add a metadata blob object to be managed by the `FsCacheHandler`.
    ///
    /// When adding a rafs metadata blob to the manager, all data blobs referenced by it will
    /// also be added to the manager. It's convenient to support rafs image filesystem.
    ///
    /// The `domain_id` and `id` forms a unique identifier to identify cached bootstrap objects.
    /// That means `domain_id` is used to divide cached objects into groups and blobs with the
    /// same `id` may exist in different groups.
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
            debug!("Found blob {} on domain {}", &bi.blob_id(), domain_id);
            let blob_config = BlobCacheObjectConfig::new_data_blob(
                domain_id.to_string(),
                bi,
                factory_config.clone(),
            );
            state.try_add(blob_config)?;
        }

        Ok(())
    }

    /// Add an entry of bootstrap and/or data blobs.
    pub fn add_blob_entry(&self, entry: &BlobCacheEntry) -> Result<()> {
        if entry.blob_type == BLOB_CACHE_TYPE_BOOTSTRAP {
            let (path, factory_config) = self.get_bootstrap_info(entry)?;
            if let Err(e) =
                self.add_bootstrap_object(&entry.domain_id, &entry.blob_id, path, factory_config)
            {
                warn!("Failed to add cache entry for bootstrap blob: {:?}", entry);
                return Err(e);
            }
        } else {
            warn!("Invalid blob cache entry: {:?}", entry);
            return Err(einval!("Invalid blob cache entry"));
        }

        Ok(())
    }

    pub fn remove_blob_entry(&self, param: &BlobObjectParam) -> Result<()> {
        let mut state = self.get_state();
        state.remove(&param.domain_id);
        Ok(())
    }

    /// Add a list of bootstrap and/or data blobs.
    pub fn add_blob_list(&self, blobs: &BlobCacheList) -> Result<()> {
        for entry in blobs.blobs.iter() {
            self.add_blob_entry(entry)?;
        }

        Ok(())
    }

    /// Get blob configuration for blob with `key`.
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
            return Err(einval!("`config.cache_type` for metadata blob is invalid"));
        }
        let cache_config =
            serde_json::from_value::<FsCacheConfig>(entry.blob_config.cache_config.clone())
                .map_err(|_e| {
                    eother!("Invalid configuration of `FsCacheConfig` in blob cache entry")
                })?;

        let path = config.metadata_path.clone().unwrap_or_default();
        if path.is_empty() {
            return Err(einval!("`config.metadata_path` for metadata blob is empty"));
        }
        let path = Path::new(&path)
            .canonicalize()
            .map_err(|_e| einval!("`config.backend_config.blob_file` is invalid"))?;
        if !path.is_file() {
            return Err(einval!("`config.backend_config.blob_file` is not a file"));
        }

        // Validate the working directory for fscache
        let path2 = Path::new(&cache_config.work_dir);
        let path2 = path2
            .canonicalize()
            .map_err(|_e| eio!("`config.cache_config.work_dir` is invalid"))?;
        if !path2.is_dir() {
            return Err(einval!("`config.cache_config.work_dir` is not a directory"));
        }

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
                prefetch_config: match serde_json::from_value(entry.fs_prefetch.clone()) {
                    Ok(fs_prefetch) => fs_prefetch,
                    Err(_e) => Default::default(),
                },
            },
        });

        Ok((path, factory_config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmm_sys_util::tempdir::TempDir;

    #[test]
    fn test_blob_cache_entry() {
        let tmpdir = TempDir::new().unwrap();
        let path = tmpdir.as_path().join("bootstrap1");
        std::fs::write(&path, "metadata").unwrap();

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
        let content = config.replace("/tmp/nydus", tmpdir.as_path().to_str().unwrap());
        let entry: BlobCacheEntry = serde_json::from_str(&content).unwrap();

        assert_eq!(&entry.blob_type, "bootstrap");
        assert_eq!(&entry.blob_id, "bootstrap1");
        assert_eq!(&entry.domain_id, "userid1");
        assert_eq!(&entry.blob_config.id, "factory1");
        assert_eq!(&entry.blob_config.backend_type, "localfs");
        assert_eq!(&entry.blob_config.cache_type, "fscache");
        assert!(entry.blob_config.backend_config.is_object());
        assert!(entry.blob_config.cache_config.is_object());

        let mgr = BlobCacheMgr::new();
        let (path, factory_config) = mgr.get_bootstrap_info(&entry).unwrap();
        assert_eq!(path, tmpdir.as_path().join("bootstrap1"));
        assert_eq!(&factory_config.id, "factory1");
        assert_eq!(&factory_config.backend.backend_type, "localfs");
        assert_eq!(&factory_config.cache.cache_type, "fscache");
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
