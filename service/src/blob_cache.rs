// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Blob cache manager to cache RAFS meta/data blob objects.

use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use nydus_api::{
    BlobCacheEntry, BlobCacheList, BlobCacheObjectId, ConfigV2, BLOB_CACHE_TYPE_DATA_BLOB,
    BLOB_CACHE_TYPE_META_BLOB,
};
use nydus_rafs::metadata::RafsSuper;
use nydus_storage::device::BlobInfo;

const ID_SPLITTER: &str = "/";

/// Generate keys for cached blob objects from domain identifiers and blob identifiers.
pub fn generate_blob_key(domain_id: &str, blob_id: &str) -> String {
    if domain_id.is_empty() {
        blob_id.to_string()
    } else {
        format!("{}{}{}", domain_id, ID_SPLITTER, blob_id)
    }
}

/// Configuration information for cached meta blob objects.
pub struct BlobCacheConfigMetaBlob {
    _blob_id: String,
    scoped_blob_id: String,
    path: PathBuf,
    config: Arc<ConfigV2>,
    data_blobs: Mutex<Vec<Arc<BlobCacheConfigDataBlob>>>,
}

impl BlobCacheConfigMetaBlob {
    /// Get file path to access the meta blob.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the ['ConfigV2'] object associated with the cached data blob.
    pub fn config_v2(&self) -> &Arc<ConfigV2> {
        &self.config
    }

    fn add_data_blob(&self, blob: Arc<BlobCacheConfigDataBlob>) {
        self.data_blobs.lock().unwrap().push(blob);
    }
}

/// Configuration information for cached data blob objects.
pub struct BlobCacheConfigDataBlob {
    blob_info: Arc<BlobInfo>,
    scoped_blob_id: String,
    config: Arc<ConfigV2>,
    ref_count: AtomicU32,
}

impl BlobCacheConfigDataBlob {
    /// Get the [`BlobInfo`](https://docs.rs/nydus-storage/latest/nydus_storage/device/struct.BlobInfo.html) object associated with the cached data blob.
    pub fn blob_info(&self) -> &Arc<BlobInfo> {
        &self.blob_info
    }

    /// Get the ['ConfigV2'] object associated with the cached data blob.
    pub fn config_v2(&self) -> &Arc<ConfigV2> {
        &self.config
    }
}

/// Configuration information for cached blob objects.
#[derive(Clone)]
pub enum BlobCacheObjectConfig {
    /// Configuration information for cached meta blob objects.
    MetaBlob(Arc<BlobCacheConfigMetaBlob>),
    /// Configuration information for cached data blob objects.
    DataBlob(Arc<BlobCacheConfigDataBlob>),
}

impl BlobCacheObjectConfig {
    /// Get the ['ConfigV2'] object associated with the cached data blob.
    pub fn config_v2(&self) -> &Arc<ConfigV2> {
        match self {
            BlobCacheObjectConfig::MetaBlob(v) => v.config_v2(),
            BlobCacheObjectConfig::DataBlob(v) => v.config_v2(),
        }
    }

    fn new_data_blob(domain_id: String, blob_info: Arc<BlobInfo>, config: Arc<ConfigV2>) -> Self {
        let scoped_blob_id = generate_blob_key(&domain_id, &blob_info.blob_id());

        BlobCacheObjectConfig::DataBlob(Arc::new(BlobCacheConfigDataBlob {
            blob_info,
            scoped_blob_id,
            config,
            ref_count: AtomicU32::new(1),
        }))
    }

    fn new_meta_blob(
        domain_id: String,
        blob_id: String,
        path: PathBuf,
        config: Arc<ConfigV2>,
    ) -> Self {
        let scoped_blob_id = generate_blob_key(&domain_id, &blob_id);

        BlobCacheObjectConfig::MetaBlob(Arc::new(BlobCacheConfigMetaBlob {
            _blob_id: blob_id,
            scoped_blob_id,
            path,
            config,
            data_blobs: Mutex::new(Vec::new()),
        }))
    }

    fn key(&self) -> &str {
        match self {
            BlobCacheObjectConfig::MetaBlob(o) => &o.scoped_blob_id,
            BlobCacheObjectConfig::DataBlob(o) => &o.scoped_blob_id,
        }
    }

    fn meta_config(&self) -> Option<Arc<BlobCacheConfigMetaBlob>> {
        match self {
            BlobCacheObjectConfig::MetaBlob(o) => Some(o.clone()),
            BlobCacheObjectConfig::DataBlob(_o) => None,
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
        let key = config.key();

        if let Some(entry) = self.id_to_config_map.get(key) {
            match entry {
                BlobCacheObjectConfig::MetaBlob(_o) => {
                    // Meta blob must be unique.
                    return Err(Error::new(
                        ErrorKind::AlreadyExists,
                        "blob_cache: bootstrap blob already exists",
                    ));
                }
                BlobCacheObjectConfig::DataBlob(o) => {
                    // Data blob is reference counted.
                    o.ref_count.fetch_add(1, Ordering::AcqRel);
                }
            }
        } else {
            self.id_to_config_map.insert(key.to_owned(), config);
        }

        Ok(())
    }

    fn remove(&mut self, param: &BlobCacheObjectId) -> Result<()> {
        if param.blob_id.is_empty() && !param.domain_id.is_empty() {
            // Remove all blobs associated with the domain.
            let scoped_blob_prefix = format!("{}{}", param.domain_id, ID_SPLITTER);
            self.id_to_config_map.retain(|_k, v| match v {
                BlobCacheObjectConfig::MetaBlob(o) => {
                    !o.scoped_blob_id.starts_with(&scoped_blob_prefix)
                }
                BlobCacheObjectConfig::DataBlob(o) => {
                    !o.scoped_blob_id.starts_with(&scoped_blob_prefix)
                }
            });
        } else {
            let mut data_blobs = Vec::new();
            let mut is_meta = false;
            let scoped_blob_prefix = generate_blob_key(&param.domain_id, &param.blob_id);

            match self.id_to_config_map.get(&scoped_blob_prefix) {
                None => return Err(enoent!("blob_cache: cache entry not found")),
                Some(BlobCacheObjectConfig::MetaBlob(o)) => {
                    is_meta = true;
                    data_blobs = o.data_blobs.lock().unwrap().clone();
                }
                Some(BlobCacheObjectConfig::DataBlob(o)) => {
                    data_blobs.push(o.clone());
                }
            }

            for entry in data_blobs {
                if entry.ref_count.fetch_sub(1, Ordering::AcqRel) == 1 {
                    self.id_to_config_map.remove(&entry.scoped_blob_id);
                }
            }

            if is_meta {
                self.id_to_config_map.remove(&scoped_blob_prefix);
            }
        }

        Ok(())
    }

    fn get(&self, key: &str) -> Option<BlobCacheObjectConfig> {
        self.id_to_config_map.get(key).cloned()
    }
}

/// Structure to manage and cache RAFS meta/data blob objects.
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

    /// Add a meta/data blob to be managed by the cache manager.
    ///
    /// When adding a RAFS meta blob to the cache manager, all data blobs referenced by the
    /// bootstrap blob will also be added to the cache manager too. It may be used to add a RAFS
    /// container image to the cache manager.
    ///
    /// Domains are used to control the blob sharing scope. All meta and data blobs associated
    /// with the same domain will be shared/reused, but blobs associated with different domains are
    /// isolated. The `domain_id` is used to identify the associated domain.
    pub fn add_blob_entry(&self, entry: &BlobCacheEntry) -> Result<()> {
        match entry.blob_type.as_str() {
            BLOB_CACHE_TYPE_META_BLOB => {
                let (path, config) = self.get_meta_info(entry)?;
                self.add_meta_object(&entry.domain_id, &entry.blob_id, path, config)
                    .map_err(|e| {
                        warn!(
                            "blob_cache: failed to add cache entry for meta blob: {:?}",
                            entry
                        );
                        e
                    })
            }
            BLOB_CACHE_TYPE_DATA_BLOB => {
                warn!("blob_cache: invalid data blob cache entry: {:?}", entry);
                Err(einval!("blob_cache: invalid data blob cache entry"))
            }
            _ => {
                warn!("blob_cache: invalid blob cache entry: {:?}", entry);
                Err(einval!("blob_cache: invalid blob cache entry"))
            }
        }
    }

    /// Add a list of meta/data blobs to be cached by the cache manager.
    pub fn add_blob_list(&self, blobs: &BlobCacheList) -> Result<()> {
        for entry in blobs.blobs.iter() {
            self.add_blob_entry(entry)?;
        }

        Ok(())
    }

    /// Remove a meta/data blob object from the cache manager.
    pub fn remove_blob_entry(&self, param: &BlobCacheObjectId) -> Result<()> {
        self.get_state().remove(param)
    }

    /// Get configuration information of the cached blob with specified `key`.
    pub fn get_config(&self, key: &str) -> Option<BlobCacheObjectConfig> {
        self.get_state().get(key)
    }

    #[inline]
    fn get_state(&self) -> MutexGuard<BlobCacheState> {
        self.state.lock().unwrap()
    }

    fn get_meta_info(&self, entry: &BlobCacheEntry) -> Result<(PathBuf, Arc<ConfigV2>)> {
        // Validate type of backend and cache.
        let config = entry
            .blob_config
            .as_ref()
            .ok_or_else(|| einval!("missing blob cache configuration information"))?;
        if config.cache.cache_type != "fscache" {
            return Err(einval!(
                "blob_cache: `config.cache_type` for meta blob is invalid"
            ));
        }
        let cache_config = config.cache.get_fscache_config()?;

        if entry.blob_id.contains(ID_SPLITTER) {
            return Err(einval!("blob_cache: `blob_id` for meta blob is invalid"));
        } else if entry.domain_id.contains(ID_SPLITTER) {
            return Err(einval!("blob_cache: `domain_id` for meta blob is invalid"));
        }

        let path = config.metadata_path.clone().unwrap_or_default();
        if path.is_empty() {
            return Err(einval!(
                "blob_cache: `config.metadata_path` for meta blob is empty"
            ));
        }
        let path = Path::new(&path)
            .canonicalize()
            .map_err(|_e| einval!("blob_cache: `config.metadata_path` for meta blob is invalid"))?;
        if !path.is_file() {
            return Err(einval!(
                "blob_cache: `config.metadata_path` for meta blob is not a file"
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

        let config: Arc<ConfigV2> = Arc::new(config.into());
        config.internal.set_blob_accessible(true);

        Ok((path, config))
    }

    fn add_meta_object(
        &self,
        domain_id: &str,
        id: &str,
        path: PathBuf,
        config: Arc<ConfigV2>,
    ) -> Result<()> {
        let (rs, _) = RafsSuper::load_from_file(&path, config.clone(), true, false)?;
        let meta = BlobCacheObjectConfig::new_meta_blob(
            domain_id.to_string(),
            id.to_string(),
            path,
            config,
        );
        let meta_obj = meta.meta_config().unwrap();
        let mut state = self.get_state();
        state.try_add(meta)?;

        // Try to add the referenced data blob object if it doesn't exist yet.
        for bi in rs.superblock.get_blob_infos() {
            debug!(
                "blob_cache: add data blob {} to domain {}",
                &bi.blob_id(),
                domain_id
            );
            let data_blob = BlobCacheObjectConfig::new_data_blob(
                domain_id.to_string(),
                bi,
                meta_obj.config.clone(),
            );
            let data_blob_config = match &data_blob {
                BlobCacheObjectConfig::DataBlob(entry) => entry.clone(),
                _ => panic!("blob_cache: internal error"),
            };

            if let Err(e) = state.try_add(data_blob) {
                // Rollback added bootstrap/data blobs.
                let id = BlobCacheObjectId {
                    domain_id: domain_id.to_string(),
                    blob_id: id.to_string(),
                };
                let _ = state.remove(&id);
                return Err(e);
            }

            // Associate the data blob with the bootstrap blob.
            meta_obj.add_data_blob(data_blob_config);
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
    fn test_generate_blob_key() {
        assert_eq!(&generate_blob_key("", "blob1"), "blob1");
        assert_eq!(&generate_blob_key("domain1", "blob1"), "domain1/blob1");
    }

    #[test]
    fn test_blob_cache_entry() {
        let tmpdir = TempDir::new().unwrap();
        let path = tmpdir.as_path().join("bootstrap1");
        std::fs::write(&path, "metadata").unwrap();
        let cfg = create_factory_config();
        let content = cfg.replace("/tmp/nydus", tmpdir.as_path().to_str().unwrap());
        let mut entry: BlobCacheEntry = serde_json::from_str(&content).unwrap();
        assert!(entry.prepare_configuration_info());
        let blob_config = entry.blob_config.as_ref().unwrap();

        assert_eq!(&entry.blob_type, "bootstrap");
        assert_eq!(&entry.blob_id, "bootstrap1");
        assert_eq!(&entry.domain_id, "userid1");
        assert_eq!(&blob_config.id, "factory1");
        assert_eq!(&blob_config.backend.backend_type, "localfs");
        assert_eq!(&blob_config.cache.cache_type, "fscache");
        assert!(blob_config.metadata_path.is_some());
        assert!(blob_config.backend.localfs.is_some());
        assert!(blob_config.cache.fs_cache.is_some());

        let mgr = BlobCacheMgr::new();
        let (path, config) = mgr.get_meta_info(&entry).unwrap();
        let backend_cfg = config.get_backend_config().unwrap();
        let cache_cfg = config.get_cache_config().unwrap();
        assert_eq!(path, tmpdir.as_path().join("bootstrap1"));
        assert_eq!(&config.id, "factory1");
        assert_eq!(&backend_cfg.backend_type, "localfs");
        assert_eq!(&cache_cfg.cache_type, "fscache");

        let blob = BlobCacheConfigMetaBlob {
            _blob_id: "123456789-123".to_string(),
            scoped_blob_id: "domain1".to_string(),
            path: path.clone(),
            config,
            data_blobs: Mutex::new(Vec::new()),
        };
        assert_eq!(blob.path(), &path);
    }

    #[test]
    fn test_invalid_blob_id() {
        let tmpdir = TempDir::new().unwrap();
        let path = tmpdir.as_path().join("bootstrap1");
        std::fs::write(&path, "metadata").unwrap();
        let config = create_factory_config();
        let content = config.replace("/tmp/nydus", tmpdir.as_path().to_str().unwrap());
        let mut entry: BlobCacheEntry = serde_json::from_str(&content).unwrap();
        let mgr = BlobCacheMgr::new();

        entry.blob_id = "domain2/blob1".to_string();
        mgr.get_meta_info(&entry).unwrap_err();
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
        let mut list: BlobCacheList = serde_json::from_str(config).unwrap();
        assert!(list.blobs[0].prepare_configuration_info());

        assert_eq!(list.blobs.len(), 2);
        assert_eq!(&list.blobs[0].blob_type, "bootstrap");
        assert_eq!(&list.blobs[0].blob_id, "bootstrap1");
        let blob_config = &list.blobs[0].blob_config.as_ref().unwrap();
        assert_eq!(&blob_config.id, "factory1");
        assert_eq!(&blob_config.backend.backend_type, "localfs");
        assert_eq!(&blob_config.cache.cache_type, "fscache");
        assert_eq!(&list.blobs[1].blob_type, "bootstrap");
        assert_eq!(&list.blobs[1].blob_id, "bootstrap2");
    }

    #[test]
    fn test_add_bootstrap() {
        let tmpdir = TempDir::new().unwrap();
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/bootstrap/rafs-v5.boot");

        let config = r#"
        {
            "type": "bootstrap",
            "id": "rafs-v5",
            "domain_id": "domain2",
            "config_v2": {
                "version": 2,
                "id": "factory1",
                "backend": {
                    "type": "localfs",
                    "localfs": {
                        "dir": "/tmp/nydus"
                    }
                },
                "cache": {
                    "type": "fscache",
                    "fscache": {
                        "work_dir": "/tmp/nydus"
                    }
                },
                "metadata_path": "RAFS_V5"
            }
          }"#;
        let content = config
            .replace("/tmp/nydus", tmpdir.as_path().to_str().unwrap())
            .replace("RAFS_V5", &source_path.display().to_string());
        let mut entry: BlobCacheEntry = serde_json::from_str(&content).unwrap();
        assert!(entry.prepare_configuration_info());

        let mgr = BlobCacheMgr::new();
        mgr.add_blob_entry(&entry).unwrap();
        let blob_id = generate_blob_key(&entry.domain_id, &entry.blob_id);
        assert!(mgr.get_config(&blob_id).is_some());

        // Check existence of data blob referenced by the bootstrap.
        let key = generate_blob_key(
            &entry.domain_id,
            "7fe907a0c9c7f35538f23f40baae5f2e8d148a3a6186f0f443f62d04b5e2d731",
        );
        assert!(mgr.get_config(&key).is_some());

        assert_eq!(mgr.get_state().id_to_config_map.len(), 19);

        entry.blob_id = "rafs-v5-cloned".to_string();
        let blob_id_cloned = generate_blob_key(&entry.domain_id, &entry.blob_id);
        mgr.add_blob_entry(&entry).unwrap();
        assert_eq!(mgr.get_state().id_to_config_map.len(), 20);
        assert!(mgr.get_config(&blob_id).is_some());
        assert!(mgr.get_config(&blob_id_cloned).is_some());

        mgr.remove_blob_entry(&BlobCacheObjectId {
            domain_id: entry.domain_id.clone(),
            blob_id: "rafs-v5".to_string(),
        })
        .unwrap();
        assert_eq!(mgr.get_state().id_to_config_map.len(), 19);
        assert!(mgr.get_config(&blob_id).is_none());
        assert!(mgr.get_config(&blob_id_cloned).is_some());

        mgr.remove_blob_entry(&BlobCacheObjectId {
            domain_id: entry.domain_id,
            blob_id: "rafs-v5-cloned".to_string(),
        })
        .unwrap();
        assert_eq!(mgr.get_state().id_to_config_map.len(), 0);
        assert!(mgr.get_config(&blob_id).is_none());
        assert!(mgr.get_config(&blob_id_cloned).is_none());
    }
}
