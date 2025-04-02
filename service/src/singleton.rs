// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Nydus daemon to host multiple services, including fscache and fusedev.

use std::any::Any;
use std::fs::metadata;
#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard};

use mio::Waker;
use nydus_api::config::BlobCacheList;
use nydus_api::BuildTimeInfo;

use crate::daemon::{
    DaemonState, DaemonStateMachineContext, DaemonStateMachineInput, DaemonStateMachineSubscriber,
    NydusDaemon,
};
use crate::fs_service::FsService;
#[cfg(target_os = "linux")]
use crate::upgrade;
use crate::upgrade::UpgradeManager;
use crate::{BlobCacheMgr, Error, Result};

#[allow(dead_code)]
pub struct ServiceController {
    bti: BuildTimeInfo,
    id: Option<String>,
    request_sender: Arc<Mutex<Sender<DaemonStateMachineInput>>>,
    result_receiver: Mutex<Receiver<Result<()>>>,
    state: AtomicI32,
    supervisor: Option<String>,
    waker: Arc<Waker>,

    blob_cache_mgr: Arc<BlobCacheMgr>,
    upgrade_mgr: Option<Mutex<UpgradeManager>>,
    fscache_enabled: AtomicBool,
    #[cfg(target_os = "linux")]
    fscache: Mutex<Option<Arc<crate::fs_cache::FsCacheHandler>>>,
}

impl ServiceController {
    /// Start all enabled services.
    fn start_services(&self) -> std::io::Result<()> {
        info!("Starting all Nydus services...");

        #[cfg(target_os = "linux")]
        if self.fscache_enabled.load(Ordering::Acquire) {
            if let Some(fscache) = self.fscache.lock().unwrap().clone() {
                for _ in 0..fscache.working_threads() {
                    let fscache2 = fscache.clone();
                    let waker = self.waker.clone();
                    std::thread::spawn(move || {
                        if let Err(e) = fscache2.run_loop() {
                            error!("Failed to run fscache service loop, {}", e);
                        }
                        // Notify the global service controller that one working thread is exiting.
                        if let Err(err) = waker.wake() {
                            error!("fail to exit daemon, error: {:?}", err);
                        }
                    });
                }
            }
        }

        Ok(())
    }

    /// Stop all enabled services.
    fn stop_services(&self) {
        info!("Stopping all Nydus services...");

        #[cfg(target_os = "linux")]
        if self.fscache_enabled.load(Ordering::Acquire) {
            if let Some(fscache) = self.fscache.lock().unwrap().take() {
                fscache.stop();
            }
        }
    }

    fn initialize_blob_cache(&self, config: &Option<serde_json::Value>) -> std::io::Result<()> {
        // Create blob cache objects configured by the configuration file.
        if let Some(config) = config {
            if let Some(config1) = config.as_object() {
                if config1.contains_key("blobs") {
                    if let Ok(v) = serde_json::from_value::<BlobCacheList>(config.clone()) {
                        if let Err(e) = self.blob_cache_mgr.add_blob_list(&v) {
                            error!("Failed to add blob list: {}", e);
                            return Err(e);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl ServiceController {
    pub fn initialize_fscache_service(
        &self,
        tag: Option<&str>,
        threads: usize,
        path: &str,
        file: Option<&File>,
    ) -> std::io::Result<()> {
        // Validate --fscache option value is an existing directory.
        let p = match std::path::Path::new(&path).canonicalize() {
            Err(e) => {
                error!("--fscache option needs a directory to cache files");
                return Err(e);
            }
            Ok(v) => {
                if !v.is_dir() {
                    error!("--fscache options needs a directory to cache files");
                    return Err(einval!("--fscache options is not a directory"));
                }
                v
            }
        };
        let p = match p.to_str() {
            Some(v) => v,
            None => {
                error!("--fscache option contains invalid characters");
                return Err(einval!("--fscache option contains invalid characters"));
            }
        };

        info!(
            "Create fscache instance at {} with tag {}, {} working threads",
            p,
            tag.unwrap_or("<none>"),
            threads
        );
        let fscache = crate::fs_cache::FsCacheHandler::new(
            "/dev/cachefiles",
            p,
            tag,
            self.blob_cache_mgr.clone(),
            threads,
            file,
        )?;
        *self.fscache.lock().unwrap() = Some(Arc::new(fscache));
        self.fscache_enabled.store(true, Ordering::Release);

        Ok(())
    }

    fn get_fscache_file(&self) -> std::io::Result<File> {
        if let Some(fscache) = self.fscache.lock().unwrap().clone() {
            let f = fscache.get_file().try_clone()?;
            Ok(f)
        } else {
            Err(einval!("fscache file not init"))
        }
    }
}

impl NydusDaemon for ServiceController {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn id(&self) -> Option<String> {
        self.id.clone()
    }

    fn version(&self) -> BuildTimeInfo {
        self.bti.clone()
    }

    fn get_state(&self) -> DaemonState {
        self.state.load(Ordering::Relaxed).into()
    }

    fn set_state(&self, state: DaemonState) {
        self.state.store(state as i32, Ordering::Relaxed);
    }

    fn start(&self) -> Result<()> {
        self.start_services()
            .map_err(|e| Error::StartService(format!("{}", e)))
    }

    fn umount(&self) -> Result<()> {
        self.stop_services();
        Ok(())
    }

    fn wait(&self) -> Result<()> {
        Ok(())
    }

    fn supervisor(&self) -> Option<String> {
        self.supervisor.clone()
    }

    fn save(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        return upgrade::fscache_upgrade::save(self);
        #[cfg(target_os = "macos")]
        return Ok(());
    }

    fn restore(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        return upgrade::fscache_upgrade::restore(self);
        #[cfg(target_os = "macos")]
        return Ok(());
    }

    fn upgrade_mgr(&self) -> Option<MutexGuard<UpgradeManager>> {
        self.upgrade_mgr.as_ref().map(|mgr| mgr.lock().unwrap())
    }

    fn get_default_fs_service(&self) -> Option<Arc<dyn FsService>> {
        None
    }

    fn get_blob_cache_mgr(&self) -> Option<Arc<BlobCacheMgr>> {
        Some(self.blob_cache_mgr.clone())
    }

    fn delete_blob(&self, _blob_id: String) -> Result<()> {
        #[cfg(target_os = "linux")]
        if self.fscache_enabled.load(Ordering::Acquire) {
            if let Some(fscache) = self.fscache.lock().unwrap().clone() {
                return fscache
                    .cull_cache(_blob_id)
                    .map_err(|e| Error::StartService(format!("{}", e)));
            }
        }
        Err(Error::Unsupported)
    }
}

impl DaemonStateMachineSubscriber for ServiceController {
    fn on_event(&self, event: DaemonStateMachineInput) -> Result<()> {
        self.request_sender
            .lock()
            .unwrap()
            .send(event)
            .map_err(Error::ChannelSend)?;

        self.result_receiver
            .lock()
            .expect("Not expect poisoned lock!")
            .recv()
            .map_err(Error::ChannelReceive)?
    }
}

#[allow(unused)]
fn is_sock_residual(sock: impl AsRef<Path>) -> bool {
    if metadata(&sock).is_ok() {
        return UnixStream::connect(&sock).is_err();
    }

    false
}
/// When nydusd starts, it checks that whether a previous nydusd died unexpected by:
///     1. Checking whether /dev/cachefiles can be opened.
///     2. Checking whether the API socket exists and the connection can established or not.
fn is_crashed(_sock: &impl AsRef<Path>) -> Result<bool> {
    #[cfg(target_os = "linux")]
    if let Err(_e) = OpenOptions::new()
        .write(true)
        .read(true)
        .create(false)
        .open("/dev/cachefiles")
    {
        warn!("cachefiles devfd can not open, the devfd may hold by supervisor or another daemon.");
        if is_sock_residual(_sock) {
            warn!("A previous daemon crashed! Try to failover later.");
            return Ok(true);
        }
        warn!("another daemon is running, will exit!");
        return Err(Error::Unsupported);
    }
    Ok(false)
}

/// Create and start a Nydus daemon to host fscache and fusedev services.
#[allow(clippy::too_many_arguments, unused)]
pub fn create_daemon(
    id: Option<String>,
    supervisor: Option<String>,
    fscache: Option<&str>,
    tag: Option<&str>,
    threads: Option<&str>,
    config: Option<serde_json::Value>,
    bti: BuildTimeInfo,
    waker: Arc<Waker>,
    api_sock: Option<impl AsRef<Path>>,
    upgrade: bool,
) -> std::io::Result<Arc<dyn NydusDaemon>> {
    let (to_sm, from_client) = channel::<DaemonStateMachineInput>();
    let (to_client, from_sm) = channel::<Result<()>>();
    let upgrade_mgr = supervisor
        .as_ref()
        .map(|s| Mutex::new(UpgradeManager::new(s.to_string().into())));

    let service_controller = ServiceController {
        bti,
        id,
        request_sender: Arc::new(Mutex::new(to_sm)),
        result_receiver: Mutex::new(from_sm),
        state: AtomicI32::new(DaemonState::INIT as i32),
        supervisor,
        waker,

        blob_cache_mgr: Arc::new(BlobCacheMgr::new()),
        upgrade_mgr,
        fscache_enabled: AtomicBool::new(false),
        #[cfg(target_os = "linux")]
        fscache: Mutex::new(None),
    };

    service_controller.initialize_blob_cache(&config)?;

    let daemon = Arc::new(service_controller);
    let machine = DaemonStateMachineContext::new(daemon.clone(), from_client, to_client);
    machine.kick_state_machine()?;

    // Without api socket, nydusd can't do neither live-upgrade nor failover, so the helper
    // finding a victim is not necessary.
    if (api_sock.as_ref().is_some() && !upgrade && !is_crashed(api_sock.as_ref().unwrap())?)
        || api_sock.is_none()
    {
        #[cfg(target_os = "linux")]
        if let Some(path) = fscache {
            let threads = if let Some(threads_value) = threads {
                crate::validate_threads_configuration(threads_value).map_err(|err| einval!(err))?
            } else {
                1usize
            };
            daemon.initialize_fscache_service(tag, threads, path, None)?;
            let f = daemon.get_fscache_file()?;
            if let Some(mut mgr_guard) = daemon.upgrade_mgr() {
                mgr_guard.hold_file(&f).map_err(|e| {
                    error!("Failed to hold fscache fd, {:?}", e);
                    eother!(e)
                })?;
                mgr_guard.save_fscache_states(threads, path.to_string());
            }
        }

        daemon
            .on_event(DaemonStateMachineInput::Mount)
            .map_err(|e| eother!(e))?;
        daemon
            .on_event(DaemonStateMachineInput::Start)
            .map_err(|e| eother!(e))?;
    }

    Ok(daemon)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use crate::blob_cache::generate_blob_key;

    use super::*;
    use mio::{Poll, Token};
    use vmm_sys_util::tempdir::TempDir;

    fn create_service_controller() -> ServiceController {
        let bti = BuildTimeInfo {
            package_ver: String::from("package_ver"),
            git_commit: String::from("git_commit"),
            build_time: String::from("build_time"),
            profile: String::from("profile"),
            rustc: String::from("rustc"),
        };

        let (to_sm, _) = channel::<DaemonStateMachineInput>();
        let (_, from_sm) = channel::<Result<()>>();

        let poller = Poll::new().expect("Failed to create poller");
        let waker = Waker::new(poller.registry(), Token(1)).expect("Failed to create waker");

        ServiceController {
            bti,
            id: Some(String::from("id")),
            request_sender: Arc::new(Mutex::new(to_sm)),
            result_receiver: Mutex::new(from_sm),
            state: Default::default(),
            supervisor: Some(String::from("supervisor")),
            waker: Arc::new(waker),
            blob_cache_mgr: Arc::new(BlobCacheMgr::new()),
            upgrade_mgr: None,
            fscache_enabled: AtomicBool::new(false),
            fscache: Mutex::new(None),
        }
    }

    #[test]
    fn test_initialize_fscache_service() {
        let service_controller = create_service_controller();

        assert!(service_controller
            .initialize_fscache_service(None, 1, "some path", None)
            .is_err());

        let mut p = std::env::current_dir().unwrap();
        p.push("Cargo.toml");
        assert!(service_controller
            .initialize_fscache_service(None, 1, p.to_str().unwrap(), None)
            .is_err());

        let tmp_dir = TempDir::new().unwrap();
        let dir = tmp_dir.as_path().to_str().unwrap();
        assert!(service_controller
            .initialize_fscache_service(None, 1, dir, None)
            .is_ok());

        assert_eq!(service_controller.id(), Some(String::from("id")));
        assert_eq!(
            service_controller.version().build_time,
            String::from("build_time")
        );
        assert_eq!(
            service_controller.supervisor(),
            Some(String::from("supervisor"))
        );
    }

    fn create_factory_config() -> String {
        let config = r#"{
            "blobs": [{
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
            }]
        }"#;
        config.to_string()
    }

    #[test]
    fn test_initialize_blob_cache() {
        let service_controller = create_service_controller();
        let blob_cache_mgr = service_controller.get_blob_cache_mgr().unwrap();
        let content = create_factory_config();
        let key = generate_blob_key("domain2", "rafs-v6");

        // test first if
        assert!(service_controller.initialize_blob_cache(&None).is_ok());
        assert!(blob_cache_mgr.get_config(&key).is_none());

        //test second if
        let config = serde_json::Value::Null;
        assert!(service_controller
            .initialize_blob_cache(&Some(config))
            .is_ok());
        assert!(blob_cache_mgr.get_config(&key).is_none());

        // test third if
        let cfg = content.replace("blobs", "blob");
        let config: serde_json::Value = serde_json::from_str(&cfg).unwrap();
        assert!(service_controller
            .initialize_blob_cache(&Some(config))
            .is_ok());
        assert!(blob_cache_mgr.get_config(&key).is_none());

        //test fourth if
        let tmp_dir = TempDir::new().unwrap();
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = std::path::PathBuf::from(root_dir);
        source_path.push("../tests/texture/bootstrap/rafs-v6-2.2.boot");
        let cfg = content
            .replace("/tmp/nydus", tmp_dir.as_path().to_str().unwrap())
            .replace("RAFS_V5", &source_path.display().to_string());
        let config: serde_json::Value = serde_json::from_str(&cfg).unwrap();
        assert!(service_controller
            .initialize_blob_cache(&Some(config))
            .is_ok());
        assert!(blob_cache_mgr.get_config(&key).is_some());
    }
}
