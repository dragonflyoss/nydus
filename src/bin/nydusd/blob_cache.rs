// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

// Blob cache manager to manage all cached blob objects.
use rafs::metadata::{RafsMode, RafsSuper};
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::sync::{Arc, Mutex, MutexGuard};
use storage::device::BlobInfo;
use storage::factory::FactoryConfig;

#[derive(Clone)]
pub struct FsCacheBootstrapConfig {
    blob_id: String,
    scoped_blob_id: String,
    path: String,
    factory_config: Arc<FactoryConfig>,
}

impl FsCacheBootstrapConfig {
    pub fn path(&self) -> &str {
        &self.path
    }
}

#[derive(Clone)]
pub struct FsCacheDataBlobConfig {
    blob_info: Arc<BlobInfo>,
    scoped_blob_id: String,
    factory_config: Arc<FactoryConfig>,
}

impl FsCacheDataBlobConfig {
    pub fn blob_info(&self) -> &Arc<BlobInfo> {
        &self.blob_info
    }

    pub fn factory_config(&self) -> &Arc<FactoryConfig> {
        &self.factory_config
    }
}

#[derive(Clone)]
pub enum FsCacheObjectConfig {
    DataBlob(Arc<FsCacheDataBlobConfig>),
    Bootstrap(Arc<FsCacheBootstrapConfig>),
}

impl FsCacheObjectConfig {
    fn new_data_blob(
        domain_id: String,
        blob_info: Arc<BlobInfo>,
        factory_config: Arc<FactoryConfig>,
    ) -> Self {
        let scoped_blob_id = domain_id + "-" + blob_info.blob_id();
        FsCacheObjectConfig::DataBlob(Arc::new(FsCacheDataBlobConfig {
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
        FsCacheObjectConfig::Bootstrap(Arc::new(FsCacheBootstrapConfig {
            blob_id,
            scoped_blob_id,
            path,
            factory_config,
        }))
    }

    fn get_key(&self) -> &str {
        match self {
            FsCacheObjectConfig::Bootstrap(o) => &o.scoped_blob_id,
            FsCacheObjectConfig::DataBlob(o) => &o.scoped_blob_id,
        }
    }
}

#[derive(Default)]
struct BlobCacheState {
    id_to_config_map: HashMap<String, FsCacheObjectConfig>,
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
        let config = FsCacheObjectConfig::new_data_blob(domain_id, blob_info, factory_config);
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
        path: &str,
        factory_config: Arc<FactoryConfig>,
    ) -> Result<()> {
        let rs = RafsSuper::load_from_metadata(path, RafsMode::Direct, true)?;
        let config = FsCacheObjectConfig::new_bootstrap_blob(
            domain_id.clone(),
            id.to_string(),
            path.to_string(),
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
                let data_blob = FsCacheObjectConfig::new_data_blob(
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

    pub fn get_config(&self, key: &str) -> Option<FsCacheObjectConfig> {
        self.get_state().id_to_config_map.get(key).cloned()
    }

    #[inline]
    fn get_state(&self) -> MutexGuard<BlobCacheState> {
        self.state.lock().unwrap()
    }
}
