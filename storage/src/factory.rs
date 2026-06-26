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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lazy_static::lazy_static;
#[cfg(feature = "backend-http-proxy")]
use nydus_api::HttpProxyConfig;
#[cfg(feature = "backend-localdisk")]
use nydus_api::LocalDiskConfig;
#[cfg(feature = "backend-localfs")]
use nydus_api::LocalFsConfig;
#[cfg(feature = "backend-oss")]
use nydus_api::OssConfig;
#[cfg(feature = "backend-registry")]
use nydus_api::RegistryConfig;
#[cfg(feature = "backend-s3")]
use nydus_api::S3Config;
use nydus_api::{default_user_io_batch_size, BackendConfigV2, ConfigV2};
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

struct BlobCacheMgrEntry {
    mgr: Arc<dyn BlobCacheMgr>,
    active_users: AtomicUsize,
}

impl BlobCacheMgrEntry {
    fn new(mgr: Arc<dyn BlobCacheMgr>) -> Self {
        Self {
            mgr,
            active_users: AtomicUsize::new(0),
        }
    }

    fn pin(self: &Arc<Self>) -> BlobCacheMgrGuard {
        self.active_users.fetch_add(1, Ordering::AcqRel);
        BlobCacheMgrGuard {
            entry: Some(self.clone()),
        }
    }

    fn active_users(&self) -> usize {
        self.active_users.load(Ordering::Acquire)
    }
}

struct BlobCacheMgrGuard {
    entry: Option<Arc<BlobCacheMgrEntry>>,
}

impl Drop for BlobCacheMgrGuard {
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take() {
            let previous = entry.active_users.fetch_sub(1, Ordering::AcqRel);
            debug_assert!(previous > 0);
        }
    }
}

/// Factory to create blob cache for blob objects.
pub struct BlobFactory {
    mgrs: Mutex<HashMap<BlobCacheMgrKey, Arc<BlobCacheMgrEntry>>>,
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
        id: &str,
    ) -> IOResult<Arc<dyn BlobCache>> {
        let backend_cfg = config.get_backend_config()?;
        let cache_cfg = config.get_cache_config()?;
        let user_io_batch_size = config
            .get_rafs_config()
            .map_or_else(|_| default_user_io_batch_size(), |v| v.user_io_batch_size)
            as u32;
        let key = BlobCacheMgrKey {
            config: config.clone(),
        };
        let mut guard = self.mgrs.lock().unwrap();
        // Use the existing blob cache manager if there's one with the same configuration.
        if let Some(entry) = guard.get(&key).cloned() {
            let _active_guard = entry.pin();
            drop(guard);
            return entry.mgr.get_blob_cache(blob_info);
        }
        let backend = Self::new_backend(backend_cfg, id)?;
        let mgr = match cache_cfg.cache_type.as_str() {
            "blobcache" | "filecache" => {
                let mgr = FileCacheMgr::new(
                    cache_cfg,
                    backend,
                    ASYNC_RUNTIME.clone(),
                    &config.id,
                    user_io_batch_size,
                )?;
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
                    user_io_batch_size,
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

        let entry = Arc::new(BlobCacheMgrEntry::new(mgr.clone()));
        let _active_guard = entry.pin();
        guard.insert(key, entry);
        drop(guard);

        mgr.get_blob_cache(blob_info)
    }

    /// Garbage-collect unused blob cache managers and blob caches.
    pub fn gc(&self, victim: Option<(&Arc<ConfigV2>, &str)>) {
        let mut guard = self.mgrs.lock().unwrap();
        if let Some((config, id)) = victim {
            let key = BlobCacheMgrKey {
                config: config.clone(),
            };
            if let Some(entry) = guard.get(&key).cloned() {
                if entry.active_users() == 0 && entry.mgr.gc(Some(id)) {
                    guard.remove(&key);
                }
            }
        } else {
            let mut reclaim = Vec::new();
            for (key, entry) in guard.iter() {
                if entry.active_users() == 0 && entry.mgr.gc(None) {
                    reclaim.push(BlobCacheMgrKey {
                        config: key.config.clone(),
                    });
                }
            }
            for key in reclaim {
                guard.remove(&key);
            }
        }
    }

    pub fn supported_backends() -> Vec<String> {
        let backends = vec![
            #[cfg(feature = "backend-oss")]
            "oss".to_string(),
            #[cfg(feature = "backend-s3")]
            "s3".to_string(),
            #[cfg(feature = "backend-registry")]
            "registry".to_string(),
            #[cfg(feature = "backend-localfs")]
            "localfs".to_string(),
            #[cfg(feature = "backend-localdisk")]
            "localdisk".to_string(),
            #[cfg(feature = "backend-http-proxy")]
            "http-proxy".to_string(),
        ];
        backends
    }

    /// Create a storage backend for the blob with id `blob_id`.
    #[allow(unused_variables)]
    pub fn new_backend(
        config: &BackendConfigV2,
        id: &str,
    ) -> IOResult<Arc<dyn BlobBackend + Send + Sync>> {
        match config.backend_type.as_str() {
            #[cfg(feature = "backend-oss")]
            "oss" => Ok(Arc::new(oss::Oss::new(config.get_oss_config()?, Some(id))?)),
            #[cfg(feature = "backend-s3")]
            "s3" => Ok(Arc::new(s3::S3::new(config.get_s3_config()?, Some(id))?)),
            #[cfg(feature = "backend-registry")]
            "registry" => Ok(Arc::new(registry::Registry::new(
                config.get_registry_config()?,
                Some(id),
            )?)),
            #[cfg(feature = "backend-localfs")]
            "localfs" => Ok(Arc::new(localfs::LocalFs::new(
                config.get_localfs_config()?,
                Some(id),
            )?)),
            #[cfg(feature = "backend-localdisk")]
            "localdisk" => Ok(Arc::new(localdisk::LocalDisk::new(
                config.get_localdisk_config()?,
                Some(id),
            )?)),
            #[cfg(feature = "backend-http-proxy")]
            "http-proxy" => Ok(Arc::new(http_proxy::HttpProxy::new(
                config.get_http_proxy_config()?,
                Some(id),
            )?)),
            _ => Err(einval!(format!(
                "unsupported backend type '{}'",
                config.backend_type
            ))),
        }
    }

    pub fn new_backend_from_json(
        backend_type: &str,
        _content: &str,
        _id: &str,
    ) -> IOResult<Arc<dyn BlobBackend + Send + Sync>> {
        match backend_type {
            #[cfg(feature = "backend-oss")]
            "oss" => {
                let cfg = serde_json::from_str::<OssConfig>(_content)?;
                Ok(Arc::new(oss::Oss::new(&cfg, Some(_id))?))
            }
            #[cfg(feature = "backend-s3")]
            "s3" => {
                let cfg = serde_json::from_str::<S3Config>(_content)?;
                Ok(Arc::new(s3::S3::new(&cfg, Some(_id))?))
            }
            #[cfg(feature = "backend-registry")]
            "registry" => {
                let cfg = serde_json::from_str::<RegistryConfig>(_content)?;
                Ok(Arc::new(registry::Registry::new(&cfg, Some(_id))?))
            }
            #[cfg(feature = "backend-localfs")]
            "localfs" => {
                let cfg = serde_json::from_str::<LocalFsConfig>(_content)?;
                Ok(Arc::new(localfs::LocalFs::new(&cfg, Some(_id))?))
            }
            #[cfg(feature = "backend-localdisk")]
            "localdisk" => {
                let cfg = serde_json::from_str::<LocalDiskConfig>(_content)?;
                Ok(Arc::new(localdisk::LocalDisk::new(&cfg, Some(_id))?))
            }
            #[cfg(feature = "backend-http-proxy")]
            "http-proxy" => {
                let cfg = serde_json::from_str::<HttpProxyConfig>(_content)?;
                Ok(Arc::new(http_proxy::HttpProxy::new(&cfg, Some(_id))?))
            }
            _ => Err(einval!(format!(
                "unsupported backend type '{}'",
                backend_type
            ))),
        }
    }

    fn check_cache_stat(&self) {
        let guard = self.mgrs.lock().unwrap();
        for (_key, entry) in guard.iter() {
            entry.mgr.check_stat();
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
    use std::io::ErrorKind;
    use std::sync::{mpsc, Arc, Barrier};
    use std::time::Duration;

    use nydus_api::CacheConfigV2;
    use nydus_utils::metrics::BackendMetrics;

    use crate::device::BlobFeatures;
    use crate::test::MockBackend;

    struct BlockingMgr {
        backend: Arc<dyn BlobBackend>,
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
    }

    impl BlobCacheMgr for BlockingMgr {
        fn init(&self) -> IOResult<()> {
            Ok(())
        }

        fn destroy(&self) {}

        fn gc(&self, _id: Option<&str>) -> bool {
            false
        }

        fn backend(&self) -> &dyn BlobBackend {
            self.backend.as_ref()
        }

        fn get_blob_cache(&self, _blob_info: &Arc<BlobInfo>) -> IOResult<Arc<dyn BlobCache>> {
            self.entered.wait();
            self.release.wait();
            Err(std::io::Error::new(
                ErrorKind::Other,
                "blocking test manager always errors",
            ))
        }

        fn check_stat(&self) {}
    }

    fn invalid_backend_config(backend_type: &str) -> BackendConfigV2 {
        BackendConfigV2 {
            backend_type: backend_type.to_string(),
            localdisk: None,
            localfs: None,
            oss: None,
            s3: None,
            registry: None,
            http_proxy: None,
        }
    }

    fn test_factory_config(id: &str) -> Arc<ConfigV2> {
        Arc::new(ConfigV2 {
            id: id.to_string(),
            backend: Some(BackendConfigV2 {
                backend_type: "unused".to_string(),
                ..Default::default()
            }),
            cache: Some(CacheConfigV2 {
                cache_type: "dummycache".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    #[test]
    fn test_blob_factory_default_state() {
        let factory = BlobFactory::default();

        assert!(factory.mgrs.lock().unwrap().is_empty());
        assert!(!factory.mgr_checker_active.load(Ordering::Acquire));
    }

    #[test]
    fn test_supported_backends_are_known() {
        let backends = BlobFactory::supported_backends();
        let allowed = [
            "oss",
            "s3",
            "registry",
            "localfs",
            "localdisk",
            "http-proxy",
        ];

        for backend in &backends {
            assert!(allowed.contains(&backend.as_str()));
        }

        let mut uniq = backends.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(uniq.len(), backends.len());
    }

    #[test]
    fn test_new_backend_rejects_unknown_backend_type() {
        let err = match BlobFactory::new_backend(&invalid_backend_config("unknown"), "blob-1") {
            Err(err) => err,
            Ok(_) => panic!("unexpected backend creation success"),
        };

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_new_backend_from_json_rejects_unknown_backend_type() {
        let err = match BlobFactory::new_backend_from_json("unknown", "{}", "blob-1") {
            Err(err) => err,
            Ok(_) => panic!("unexpected backend creation success"),
        };

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_new_blob_cache_releases_factory_lock_for_existing_mgr() {
        let factory = Arc::new(BlobFactory::default());
        let config = test_factory_config("factory-lock-test");
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let backend: Arc<dyn BlobBackend> = Arc::new(MockBackend {
            metrics: BackendMetrics::new("factory-lock-test", "mock"),
        });
        let mgr: Arc<dyn BlobCacheMgr> = Arc::new(BlockingMgr {
            backend,
            entered: entered.clone(),
            release: release.clone(),
        });
        factory.mgrs.lock().unwrap().insert(
            BlobCacheMgrKey {
                config: config.clone(),
            },
            Arc::new(BlobCacheMgrEntry::new(mgr)),
        );

        let blob_info = Arc::new(BlobInfo::new(
            0,
            "blob-1".to_string(),
            0,
            0,
            0,
            0,
            BlobFeatures::empty(),
        ));
        let worker_factory = factory.clone();
        let worker_config = config.clone();
        let worker_blob = blob_info.clone();
        let worker = std::thread::spawn(move || {
            worker_factory.new_blob_cache(&worker_config, &worker_blob, "/")
        });

        entered.wait();

        let (lock_tx, lock_rx) = mpsc::channel();
        let lock_factory = factory.clone();
        let locker = std::thread::spawn(move || {
            let _guard = lock_factory.mgrs.lock().unwrap();
            let _ = lock_tx.send(());
        });

        let lock_acquired_while_getting_blob = lock_rx.recv_timeout(Duration::from_secs(1)).is_ok();

        release.wait();

        let result = worker.join().unwrap();
        locker.join().unwrap();

        assert!(result.is_err());
        assert!(
            lock_acquired_while_getting_blob,
            "factory lock should not be held while an existing manager resolves blob cache"
        );
    }
}
