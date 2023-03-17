// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Blob cache manager to cache RAFS meta/data blob objects.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Error, ErrorKind, Result};
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use nydus_api::{
    BlobCacheEntry, BlobCacheList, BlobCacheObjectId, ConfigV2, BLOB_CACHE_TYPE_DATA_BLOB,
    BLOB_CACHE_TYPE_META_BLOB,
};
use nydus_rafs::metadata::layout::v6::{EROFS_BLOCK_BITS_12, EROFS_BLOCK_SIZE_4096};
use nydus_rafs::metadata::{RafsBlobExtraInfo, RafsSuper, RafsSuperFlags};
use nydus_storage::cache::BlobCache;
use nydus_storage::device::BlobInfo;
use nydus_storage::factory::BLOB_FACTORY;
use tokio_uring::buf::IoBufMut;
use tokio_uring::fs::File;

const ID_SPLITTER: &str = "/";

/// Generate keys for cached blob objects from domain identifiers and blob identifiers.
pub fn generate_blob_key(domain_id: &str, blob_id: &str) -> String {
    if domain_id.is_empty() {
        blob_id.to_string()
    } else {
        format!("{}{}{}", domain_id, ID_SPLITTER, blob_id)
    }
}

/// Configuration information for a cached metadata blob.
pub struct MetaBlobConfig {
    blob_id: String,
    scoped_blob_id: String,
    path: PathBuf,
    config: Arc<ConfigV2>,
    blobs: Mutex<Vec<Arc<DataBlobConfig>>>,
    blob_extra_infos: HashMap<String, RafsBlobExtraInfo>,
    is_tarfs_mode: bool,
}

impl MetaBlobConfig {
    /// Get blob id.
    pub fn blob_id(&self) -> &str {
        &self.blob_id
    }

    /// Get file path to access the meta blob.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the ['ConfigV2'] object associated with the cached data blob.
    pub fn config_v2(&self) -> &Arc<ConfigV2> {
        &self.config
    }

    pub fn get_blobs(&self) -> Vec<Arc<DataBlobConfig>> {
        self.blobs.lock().unwrap().clone()
    }

    /// Get optional extra information associated with a blob object.
    pub fn get_blob_extra_info(&self, blob_id: &str) -> Option<&RafsBlobExtraInfo> {
        self.blob_extra_infos.get(blob_id)
    }

    /// Check whether the filesystem is in `TARFS` mode.
    pub fn is_tarfs_mode(&self) -> bool {
        self.is_tarfs_mode
    }

    fn add_data_blob(&self, blob: Arc<DataBlobConfig>) {
        self.blobs.lock().unwrap().push(blob);
    }
}

/// Configuration information for a cached data blob.
pub struct DataBlobConfig {
    scoped_blob_id: String,
    blob_info: Arc<BlobInfo>,
    config: Arc<ConfigV2>,
    ref_count: AtomicU32,
}

impl DataBlobConfig {
    /// Get the [`BlobInfo`](https://docs.rs/nydus-storage/latest/nydus_storage/device/struct.BlobInfo.html) object associated with the cached data blob.
    pub fn blob_info(&self) -> &Arc<BlobInfo> {
        &self.blob_info
    }

    /// Get the ['ConfigV2'] object associated with the cached data blob.
    pub fn config_v2(&self) -> &Arc<ConfigV2> {
        &self.config
    }
}

/// Configuration information for a cached metadata/data blob.
#[derive(Clone)]
pub enum BlobConfig {
    /// Configuration information for cached meta blob objects.
    MetaBlob(Arc<MetaBlobConfig>),
    /// Configuration information for cached data blob objects.
    DataBlob(Arc<DataBlobConfig>),
}

impl BlobConfig {
    /// Get the ['ConfigV2'] object associated with the cached data blob.
    pub fn config_v2(&self) -> &Arc<ConfigV2> {
        match self {
            BlobConfig::MetaBlob(v) => v.config_v2(),
            BlobConfig::DataBlob(v) => v.config_v2(),
        }
    }

    fn new_data_blob(domain_id: String, blob_info: Arc<BlobInfo>, config: Arc<ConfigV2>) -> Self {
        let scoped_blob_id = generate_blob_key(&domain_id, &blob_info.blob_id());

        BlobConfig::DataBlob(Arc::new(DataBlobConfig {
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
        blob_extra_infos: HashMap<String, RafsBlobExtraInfo>,
        is_tarfs_mode: bool,
    ) -> Self {
        let scoped_blob_id = generate_blob_key(&domain_id, &blob_id);

        BlobConfig::MetaBlob(Arc::new(MetaBlobConfig {
            blob_id,
            scoped_blob_id,
            path,
            config,
            blobs: Mutex::new(Vec::new()),
            blob_extra_infos,
            is_tarfs_mode,
        }))
    }

    fn key(&self) -> &str {
        match self {
            BlobConfig::MetaBlob(o) => &o.scoped_blob_id,
            BlobConfig::DataBlob(o) => &o.scoped_blob_id,
        }
    }

    fn meta_config(&self) -> Option<Arc<MetaBlobConfig>> {
        match self {
            BlobConfig::MetaBlob(o) => Some(o.clone()),
            BlobConfig::DataBlob(_o) => None,
        }
    }
}

#[derive(Default)]
struct BlobCacheState {
    id_to_config_map: HashMap<String, BlobConfig>,
}

impl BlobCacheState {
    fn new() -> Self {
        Self {
            id_to_config_map: HashMap::new(),
        }
    }

    fn try_add(&mut self, config: BlobConfig) -> Result<()> {
        let key = config.key();

        if let Some(entry) = self.id_to_config_map.get(key) {
            match entry {
                BlobConfig::MetaBlob(_o) => {
                    // Meta blob must be unique.
                    return Err(Error::new(
                        ErrorKind::AlreadyExists,
                        "blob_cache: bootstrap blob already exists",
                    ));
                }
                BlobConfig::DataBlob(o) => {
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
                BlobConfig::MetaBlob(o) => !o.scoped_blob_id.starts_with(&scoped_blob_prefix),
                BlobConfig::DataBlob(o) => !o.scoped_blob_id.starts_with(&scoped_blob_prefix),
            });
        } else {
            let mut data_blobs = Vec::new();
            let mut is_meta = false;
            let scoped_blob_prefix = generate_blob_key(&param.domain_id, &param.blob_id);

            match self.id_to_config_map.get(&scoped_blob_prefix) {
                None => return Err(enoent!("blob_cache: cache entry not found")),
                Some(BlobConfig::MetaBlob(o)) => {
                    is_meta = true;
                    data_blobs = o.blobs.lock().unwrap().clone();
                }
                Some(BlobConfig::DataBlob(o)) => {
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

    fn get(&self, key: &str) -> Option<BlobConfig> {
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
            BLOB_CACHE_TYPE_DATA_BLOB => Err(einval!(format!(
                "blob_cache: invalid data blob cache entry: {:?}",
                entry
            ))),
            _ => Err(einval!(format!(
                "blob_cache: invalid blob cache entry, {:?}",
                entry
            ))),
        }
    }

    /// Add a list of meta/data blobs to be cached by the cache manager.
    ///
    /// If failed to add some blob, the blobs already added won't be rolled back.
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
    pub fn get_config(&self, key: &str) -> Option<BlobConfig> {
        self.get_state().get(key)
    }

    #[inline]
    fn get_state(&self) -> MutexGuard<BlobCacheState> {
        self.state.lock().unwrap()
    }

    fn get_meta_info(&self, entry: &BlobCacheEntry) -> Result<(PathBuf, Arc<ConfigV2>)> {
        let config = entry
            .blob_config
            .as_ref()
            .ok_or_else(|| einval!("missing blob cache configuration information"))?;

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
        let path = Path::new(&path).canonicalize().map_err(|_e| {
            einval!(format!(
                "blob_cache: `config.metadata_path={}` for meta blob is invalid",
                path
            ))
        })?;
        if !path.is_file() {
            return Err(einval!(
                "blob_cache: `config.metadata_path` for meta blob is not a file"
            ));
        }

        // Validate type of backend and cache.
        if config.cache.is_fscache() {
            // Validate the working directory for fscache
            let cache_config = config.cache.get_fscache_config()?;
            let path2 = Path::new(&cache_config.work_dir);
            let path2 = path2
                .canonicalize()
                .map_err(|_e| eio!("blob_cache: `config.cache_config.work_dir` is invalid"))?;
            if !path2.is_dir() {
                return Err(einval!(
                    "blob_cache: `config.cache_config.work_dir` is not a directory"
                ));
            }
        } else if config.cache.is_filecache() {
            // Validate the working directory for filecache
            let cache_config = config.cache.get_filecache_config()?;
            let path2 = Path::new(&cache_config.work_dir);
            let path2 = path2
                .canonicalize()
                .map_err(|_e| eio!("blob_cache: `config.cache_config.work_dir` is invalid"))?;
            if !path2.is_dir() {
                return Err(einval!(
                    "blob_cache: `config.cache_config.work_dir` is not a directory"
                ));
            }
        } else {
            return Err(einval!("blob_cache: unknown cache type"));
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
        let (rs, _) = RafsSuper::load_from_file(&path, config.clone(), false)?;
        if rs.meta.is_v5() {
            return Err(einval!("blob_cache: RAFSv5 image is not supported"));
        }

        let blob_extra_infos = rs.superblock.get_blob_extra_infos()?;
        let meta = BlobConfig::new_meta_blob(
            domain_id.to_string(),
            id.to_string(),
            path,
            config,
            blob_extra_infos,
            rs.meta.flags.contains(RafsSuperFlags::TARTFS_MODE),
        );
        // Safe to unwrap because it's a meta blob object.
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
            let data_blob =
                BlobConfig::new_data_blob(domain_id.to_string(), bi, meta_obj.config.clone());
            let data_blob_config = match &data_blob {
                BlobConfig::DataBlob(entry) => entry.clone(),
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

/// Structure representing a cached metadata blob.
pub struct MetaBlob {
    file: File,
    size: u64,
}

impl MetaBlob {
    /// Create a new [MetaBlob] object from
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(path.as_ref())
            .map_err(|e| {
                warn!(
                    "blob_cache: failed to open metadata blob {}",
                    path.as_ref().display()
                );
                e
            })?;
        let md = file.metadata().map_err(|e| {
            warn!(
                "blob_cache: failed to get metadata about metadata blob {}",
                path.as_ref().display()
            );
            e
        })?;
        let size = md.len();
        if size % EROFS_BLOCK_SIZE_4096 != 0 || (size >> EROFS_BLOCK_BITS_12) > u32::MAX as u64 {
            return Err(einval!(format!(
                "blob_cache: metadata blob size (0x{:x}) is invalid",
                size
            )));
        }

        Ok(MetaBlob {
            file: File::from_std(file),
            size,
        })
    }

    /// Get number of blocks in unit of EROFS_BLOCK_SIZE.
    pub fn blocks(&self) -> u32 {
        (self.size >> EROFS_BLOCK_BITS_12) as u32
    }

    /// Read data from the cached metadata blob in asynchronous mode.
    pub async fn async_read<T: IoBufMut>(&self, pos: u64, buf: T) -> (Result<usize>, T) {
        self.file.read_at(buf, pos).await
    }
}

/// Structure representing a cached data blob.
pub struct DataBlob {
    blob_id: String,
    blob: Arc<dyn BlobCache>,
    file: File,
}

impl DataBlob {
    /// Create a new instance of [DataBlob].
    pub fn new(config: &Arc<DataBlobConfig>) -> Result<Self> {
        let blob_id = config.blob_info().blob_id();
        let blob = BLOB_FACTORY
            .new_blob_cache(config.config_v2(), &config.blob_info)
            .map_err(|e| {
                warn!(
                    "blob_cache: failed to create cache object for blob {}",
                    blob_id
                );
                e
            })?;

        match blob.get_blob_object() {
            Some(obj) => {
                let fd = nix::unistd::dup(obj.as_raw_fd())?;
                // Safe because the `fd` is valid.
                let file = unsafe { File::from_raw_fd(fd) };
                Ok(DataBlob {
                    blob_id,
                    blob,
                    file,
                })
            }
            None => Err(eio!(format!(
                "blob_cache: failed to get BlobObject for blob {}",
                blob_id
            ))),
        }
    }

    /// Read data from the cached data blob in asynchronous mode.
    pub async fn async_read<T: IoBufMut>(&self, pos: u64, buf: T) -> (Result<usize>, T) {
        match self.blob.get_blob_object() {
            Some(obj) => match obj.fetch_range_uncompressed(pos, buf.bytes_total() as u64) {
                Ok(_) => self.file.read_at(buf, pos).await,
                Err(e) => (Err(e), buf),
            },
            None => (
                Err(eio!(format!(
                    "blob_cache: failed to get BlobObject for blob {}",
                    self.blob_id
                ))),
                buf,
            ),
        }
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

        let blob = MetaBlobConfig {
            blob_id: "123456789-123".to_string(),
            scoped_blob_id: "domain1".to_string(),
            path: path.clone(),
            config,
            blobs: Mutex::new(Vec::new()),
            blob_extra_infos: HashMap::new(),
            is_tarfs_mode: false,
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
        source_path.push("../tests/texture/bootstrap/rafs-v6-2.2.boot");

        let config = r#"
        {
            "type": "bootstrap",
            "id": "rafs-v6",
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
            "be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef",
        );
        assert!(mgr.get_config(&key).is_some());

        assert_eq!(mgr.get_state().id_to_config_map.len(), 2);

        entry.blob_id = "rafs-v6-cloned".to_string();
        let blob_id_cloned = generate_blob_key(&entry.domain_id, &entry.blob_id);
        mgr.add_blob_entry(&entry).unwrap();
        assert_eq!(mgr.get_state().id_to_config_map.len(), 3);
        assert!(mgr.get_config(&blob_id).is_some());
        assert!(mgr.get_config(&blob_id_cloned).is_some());

        mgr.remove_blob_entry(&BlobCacheObjectId {
            domain_id: entry.domain_id.clone(),
            blob_id: "rafs-v6".to_string(),
        })
        .unwrap();
        assert_eq!(mgr.get_state().id_to_config_map.len(), 2);
        assert!(mgr.get_config(&blob_id).is_none());
        assert!(mgr.get_config(&blob_id_cloned).is_some());

        mgr.remove_blob_entry(&BlobCacheObjectId {
            domain_id: entry.domain_id,
            blob_id: "rafs-v6-cloned".to_string(),
        })
        .unwrap();
        assert_eq!(mgr.get_state().id_to_config_map.len(), 0);
        assert!(mgr.get_config(&blob_id).is_none());
        assert!(mgr.get_config(&blob_id_cloned).is_none());
    }

    #[test]
    fn test_meta_blob() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/bootstrap/rafs-v6-2.2.boot");

        tokio_uring::start(async move {
            let meta_blob = MetaBlob::new(&source_path).unwrap();
            assert_eq!(meta_blob.blocks(), 5);
            let buf = vec![0u8; 4096];
            let (res, buf) = meta_blob.async_read(0, buf).await;
            assert_eq!(res.unwrap(), 4096);
            assert_eq!(buf[0], 0);
            assert_eq!(buf[1023], 0);
            assert_eq!(buf[1024], 0xe2);
            assert_eq!(buf[1027], 0xe0);
            let (res, _buf) = meta_blob.async_read(0x6000, buf).await;
            assert_eq!(res.unwrap(), 0);
        });
    }
}
