// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::any::Any;
use std::io::Result;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

use nydus_app::BuildTimeInfo;

use crate::blob_cache::{BlobCacheConfigList, BlobCacheMgr};
use crate::daemon::{
    DaemonError, DaemonResult, DaemonState, DaemonStateMachineContext, DaemonStateMachineInput,
    DaemonStateMachineSubscriber,
};
use crate::{FsService, NydusDaemon, SubCmdArgs};

pub struct ServiceContoller {
    bti: BuildTimeInfo,
    id: Option<String>,
    request_sender: Arc<Mutex<Sender<DaemonStateMachineInput>>>,
    result_receiver: Mutex<Receiver<DaemonResult<()>>>,
    state: AtomicI32,
    supervisor: Option<String>,

    blob_cache_mgr: Arc<BlobCacheMgr>,

    fscache_enabled: AtomicBool,
    #[cfg(target_os = "linux")]
    fscache: Mutex<Option<Arc<crate::fs_cache::FsCacheHandler>>>,
}

impl ServiceContoller {
    /// Start all enabled services.
    fn start_services(&self) -> Result<()> {
        info!("Starting all Nydus services...");

        #[cfg(target_os = "linux")]
        if self.fscache_enabled.load(Ordering::Acquire) {
            if let Some(fscache) = self.fscache.lock().unwrap().clone() {
                std::thread::spawn(move || {
                    if let Err(e) = fscache.run_loop() {
                        error!("Failed to run fscache service loop, {}", e);
                    }
                    // Notify the global service controller that one working thread is exiting.
                    if let Err(e) = crate::DAEMON_CONTROLLER.waker.wake() {
                        error!("Failed to notify the global service controller, {}", e);
                    }
                });
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

    fn initialize_blob_cache(&self, config: &Option<serde_json::Value>) -> Result<()> {
        // Create blob cache objects configured by the configuration file.
        if let Some(config) = config {
            if let Some(config1) = config.as_object() {
                if config1.contains_key("blobs") {
                    if let Ok(v) = serde_json::from_value::<BlobCacheConfigList>(config.clone()) {
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
impl ServiceContoller {
    fn initialize_fscache_service(&self, subargs: &SubCmdArgs, path: &str) -> Result<()> {
        // Validate --fscache option value is an existing directory.
        let p = match Path::new(&path).canonicalize() {
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
        let tag = subargs.value_of("fscache-tag");

        info!(
            "Create fscache instance at {} with tag {}",
            p,
            tag.clone().unwrap_or("<none>")
        );
        let fscache = crate::fs_cache::FsCacheHandler::new(
            "/dev/cachefiles",
            p,
            tag,
            self.blob_cache_mgr.clone(),
        )?;
        *self.fscache.lock().unwrap() = Some(Arc::new(fscache));
        self.fscache_enabled.store(true, Ordering::Release);

        Ok(())
    }
}

impl NydusDaemon for ServiceContoller {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn id(&self) -> Option<String> {
        self.id.clone()
    }

    fn get_state(&self) -> DaemonState {
        self.state.load(Ordering::Relaxed).into()
    }

    fn set_state(&self, state: DaemonState) {
        self.state.store(state as i32, Ordering::Relaxed);
    }

    fn version(&self) -> BuildTimeInfo {
        self.bti.clone()
    }

    fn start(&self) -> DaemonResult<()> {
        self.start_services()
            .map_err(|e| DaemonError::StartService(format!("{}", e)))
    }

    fn disconnect(&self) -> DaemonResult<()> {
        self.stop_services();
        Ok(())
    }

    fn wait(&self) -> DaemonResult<()> {
        Ok(())
    }

    fn supervisor(&self) -> Option<String> {
        self.supervisor.clone()
    }

    fn save(&self) -> DaemonResult<()> {
        Err(DaemonError::Unsupported)
    }

    fn restore(&self) -> DaemonResult<()> {
        Err(DaemonError::Unsupported)
    }

    fn get_default_fs_service(&self) -> Option<Arc<dyn FsService>> {
        None
    }
}

impl DaemonStateMachineSubscriber for ServiceContoller {
    fn on_event(&self, event: DaemonStateMachineInput) -> DaemonResult<()> {
        self.request_sender
            .lock()
            .unwrap()
            .send(event)
            .map_err(|e| DaemonError::Channel(format!("send {:?}", e)))?;
        self.result_receiver
            .lock()
            .expect("Not expect poisoned lock!")
            .recv()
            .map_err(|e| DaemonError::Channel(format!("recv {:?}", e)))?
    }
}

pub fn create_daemon(subargs: &SubCmdArgs, bti: BuildTimeInfo) -> Result<Arc<dyn NydusDaemon>> {
    let id = subargs.value_of("id").map(|id| id.to_string());
    let supervisor = subargs.value_of("supervisor").map(|s| s.to_string());
    let config = match subargs.value_of("config") {
        None => None,
        Some(path) => {
            let config = std::fs::read_to_string(path)?;
            let config: serde_json::Value = serde_json::from_str(&config)
                .map_err(|_e| einval!("invalid configuration file"))?;
            Some(config)
        }
    };

    let (to_sm, from_client) = channel::<DaemonStateMachineInput>();
    let (to_client, from_sm) = channel::<DaemonResult<()>>();
    let service_controller = ServiceContoller {
        bti,
        id,
        request_sender: Arc::new(Mutex::new(to_sm)),
        result_receiver: Mutex::new(from_sm),
        state: Default::default(),
        supervisor,

        blob_cache_mgr: Arc::new(BlobCacheMgr::new()),

        fscache_enabled: AtomicBool::new(false),
        #[cfg(target_os = "linux")]
        fscache: Mutex::new(None),
    };

    service_controller.initialize_blob_cache(&config)?;
    #[cfg(target_os = "linux")]
    if let Some(path) = subargs.value_of("fscache") {
        service_controller.initialize_fscache_service(subargs, path)?;
    }

    let daemon = Arc::new(service_controller);
    let machine = DaemonStateMachineContext::new(daemon.clone(), from_client, to_client);
    machine.kick_state_machine()?;
    daemon
        .on_event(DaemonStateMachineInput::Start)
        .map_err(|e| eother!(e))?;

    Ok(daemon)
}
