// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

// Blob cache manager to manage all cached blob objects.
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use nydus_api::http::BlobCacheList;
use rafs::metadata::{RafsMode, RafsSuper};
use storage::device::BlobInfo;
use storage::factory::FactoryConfig;

#[derive(Clone)]
pub struct BlobCacheConfigBootstrap {
    blob_id: String,
    scoped_blob_id: String,
    path: String,
    factory_config: Arc<FactoryConfig>,
}

impl BlobCacheConfigBootstrap {
    pub fn path(&self) -> &str {
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
        let scoped_blob_id = domain_id + "-" + blob_info.blob_id();
        BlobCacheObjectConfig::DataBlob(Arc::new(BlobCacheConfigDataBlob {
            blob_info,
            scoped_blob_id,
            factory_config,
        }))
    }

    fn new_bootstrap_blob(
        domain_id: String,
        blob_id: String,
        path: String,
        factory_config: Arc<FactoryConfig>,
    ) -> Self {
        let scoped_blob_id = domain_id + "-" + &blob_id;
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

/// Struct to maintain cached file objects.
#[derive(Default)]
pub struct BlobCacheMgr {
    state: Mutex<BlobCacheState>,
}

impl BlobCacheMgr {
    /// Create a new instance of `BlobCacheMgr`.
    pub fn new() -> Self {
        BlobCacheMgr {
            state: Mutex::new(BlobCacheState {
                id_to_config_map: HashMap::new(),
            }),
        }
    }

    /// Add a blob object to be managed by the `FsCacheHandler`.
    ///
    /// The `domain_id` and `blob_id` forms a unique identifier to identify cached objects.
    /// That means `domain_id` is used to divide cached objects into groups and blobs with the same
    /// `blob_id` may exist in different groups.
    pub fn add_blob_object(
        &self,
        domain_id: String,
        blob_info: Arc<BlobInfo>,
        factory_config: Arc<FactoryConfig>,
    ) -> Result<()> {
        let config = BlobCacheObjectConfig::new_data_blob(domain_id, blob_info, factory_config);
        let mut state = self.get_state();
        if state.id_to_config_map.contains_key(config.get_key()) {
            Err(Error::new(
                ErrorKind::AlreadyExists,
                "blob configuration information already exists",
            ))
        } else {
            state
                .id_to_config_map
                .insert(config.get_key().to_string(), config);
            Ok(())
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
    #[allow(unused)]
    pub fn add_bootstrap_object(
        &self,
        domain_id: String,
        id: &str,
        path: &Path,
        factory_config: Arc<FactoryConfig>,
    ) -> Result<()> {
        let rs = RafsSuper::load_from_metadata(path, RafsMode::Direct, true)?;
        let config = BlobCacheObjectConfig::new_bootstrap_blob(
            domain_id.clone(),
            id.to_string(),
            path.to_str().unwrap().to_string(),
            factory_config.clone(),
        );
        let mut state = self.get_state();

        if state.id_to_config_map.contains_key(config.get_key()) {
            Err(Error::new(
                ErrorKind::AlreadyExists,
                "blob configuration information already exists",
            ))
        } else {
            state
                .id_to_config_map
                .insert(config.get_key().to_string(), config);
            // Try to add the referenced data blob object if it doesn't exist yet.
            for bi in rs.superblock.get_blob_infos() {
                let data_blob = BlobCacheObjectConfig::new_data_blob(
                    domain_id.clone(),
                    bi,
                    factory_config.clone(),
                );
                if !state.id_to_config_map.contains_key(data_blob.get_key()) {
                    state
                        .id_to_config_map
                        .insert(data_blob.get_key().to_string(), data_blob);
                }
            }
            Ok(())
        }
    }

    /// Add a list of bootstrap and/or data blobs.
    pub fn add_blob_list(&self, blobs: &BlobCacheList) -> Result<()> {
        for _entry in blobs.blobs.iter() {
            /*
            if let Err(e) = entry.validate() {
                warn!("Invalid blob config entry: {:?}", entry);
                return Err(e);
            }
            if entry.blob_type == BLOB_CACHE_TYPE_BOOTSTRAP
                && entry.blob_config.cache_type == "fscache"
            {
                let path = entry.blob_path.as_ref().unwrap();
                if let Err(e) = self.add_bootstrap_object(
                    entry.domain_id.clone(),
                    &entry.blob_id,
                    path,
                    Arc::new(entry.blob_config.clone()),
                ) {
                    warn!("Failed to add bootstrap entry: {:?}", entry);
                    return Err(e);
                }
            } else {
                warn!("Unsupported blob config entry: {:?}", entry);
                return Err(einval!("unsupported blob configuration entry"));
            }
             */
            todo!();
        }

        Ok(())
    }

    /// Get blob configuration for blob with `key`.
    pub fn get_config(&self, key: &str) -> Option<BlobCacheObjectConfig> {
        self.get_state().id_to_config_map.get(key).cloned()
    }

    #[inline]
    fn get_state(&self) -> MutexGuard<BlobCacheState> {
        self.state.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_cache_entry() {
        let config = r#"
        {
            "domain_id": "domain1",
            "id": "blob1",
            "type": "bootstrap",
            "path": "/tmp/file1",
            "config": {
                "id": "factory1",
                "backend": {
                    "type": "oss",
                    "config": {
                        "endpoint": "test",
                        "access_key_id": "test",
                        "access_key_secret": "test",
                        "bucket_name": "antsys-nydus",
                        "object_prefix":"nydus_v2/",
                        "scheme": "http"
                    }
                },
                "cache": {
                    "type": "fscache",
                    "compressed": false,
                    "config": {}
                }
            }
          }"#;
        let mut entry: BlobCacheEntry = serde_json::from_str(config).unwrap();

        assert_eq!(&entry.domain_id, "domain1");
        assert_eq!(&entry.blob_id, "blob1");
        assert_eq!(&entry.blob_type, "bootstrap");
        assert_eq!(entry.blob_path, Some("/tmp/file1".to_string()));
        assert_eq!(&entry.blob_config.id, "factory1");
        assert_eq!(&entry.blob_config.backend.backend_type, "oss");
        assert_eq!(&entry.blob_config.cache.cache_type, "fscache");
        assert_eq!(entry.blob_config.cache.cache_compressed, false);
        assert!(entry.blob_config.backend.backend_config.is_object());
        entry.validate().unwrap();

        let path = entry.blob_path.take();
        entry.validate().unwrap_err();
        entry.blob_path = path;
        entry.validate().unwrap();
        entry.blob_type = "unknown".to_string();
        entry.validate().unwrap_err();
    }

    #[test]
    fn test_blob_cache_list() {
        let config = r#"
         {
            "blobs" : [
                {
                    "domain_id": "domain1",
                    "id": "blob1",
        		    "type": "bootstrap",
        		    "path": "/tmp/file1",
        		    "config": {
        			    "id": "factory1",
        			    "backend": {
        				    "type": "oss",
        				    "config": {
        					    "endpoint": "test",
        					    "access_key_id": "test",
        					    "access_key_secret": "test",
        					    "bucket_name": "antsys-nydus",
        					    "object_prefix": "nydus_v2/",
        					    "scheme": "http"
        				    }
        			    },
        			    "cache": {
        				    "type": "fscache",
        				    "compressed": false,
        				    "config": {}
        			    }
        		    }
        	    },
        	    {
                    "domain_id": "domain1",
                    "id": "blob2",
        		    "type": "bootstrap",
        		    "path": "/tmp/file2",
        		    "config": {
        			    "id": "factory2",
        			    "backend": {
        				    "type": "oss",
        				    "config": {
        					    "endpoint": "test",
        					    "access_key_id": "test",
        					    "access_key_secret": "test",
        					    "bucket_name": "antsys-nydus",
        					    "object_prefix": "nydus_v2/",
        					    "scheme": "http"
        				    }
        			    },
        			    "cache": {
        				    "type": "fscache",
        				    "compressed": false,
        				    "config": {}
        			    }
        		    }
        	    }
            ]
         }"#;
        let list: BlobCacheList = serde_json::from_str(config).unwrap();

        assert_eq!(list.blobs.len(), 2);
        assert_eq!(&list.blobs[0].blob_type, "bootstrap");
        assert_eq!(list.blobs[0].blob_path, Some("/tmp/file1".to_string()));
        assert_eq!(&list.blobs[0].blob_config.id, "factory1");
        assert_eq!(&list.blobs[0].blob_config.backend.backend_type, "oss");
        assert_eq!(&list.blobs[0].blob_config.cache.cache_type, "fscache");
        assert_eq!(list.blobs[0].blob_config.cache.cache_compressed, false);
        assert!(list.blobs[0].blob_config.backend.backend_config.is_object());
        list.blobs[0].validate().unwrap();
        assert_eq!(list.blobs[1].blob_path, Some("/tmp/file2".to_string()));
        list.blobs[1].validate().unwrap();
    }
}
