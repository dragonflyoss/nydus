// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::any::Any;
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::convert::From;
use std::fmt::{Display, Formatter};
use std::io::Result;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::process::id;
use std::str::FromStr;
use std::sync::{
    mpsc::{Receiver, Sender},
    Arc, MutexGuard,
};
use std::thread;
use std::{error, fmt, io};

use fuse_backend_rs::api::{vfs::VfsError, BackendFileSystem, Vfs};
#[cfg(target_os = "linux")]
use fuse_backend_rs::passthrough::{Config, PassthroughFs};
use fuse_backend_rs::transport::Error as FuseTransportError;
use fuse_backend_rs::Error as FuseError;
use rust_fsm::*;
use serde::{self, Deserialize, Serialize};
use serde_json::Error as SerdeError;

use nydus::{FsBackendDesc, FsBackendType};
use nydus_app::BuildTimeInfo;
use rafs::{
    fs::{Rafs, RafsConfig},
    trim_backend_config, RafsError, RafsIoRead,
};

use crate::upgrade::{self, UpgradeManager, UpgradeMgrError};

//TODO: Try to public below type from fuse-rs thus no need to redefine it here.
type BackFileSystem = Box<dyn BackendFileSystem<Inode = u64, Handle = u64> + Send + Sync>;

#[allow(dead_code)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Hash, PartialEq, Eq, Serialize)]
pub enum DaemonState {
    INIT = 1,
    RUNNING = 2,
    UPGRADING = 3,
    INTERRUPTED = 4,
    STOPPED = 5,
    UNKNOWN = 6,
}

impl Display for DaemonState {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<i32> for DaemonState {
    fn from(i: i32) -> Self {
        match i {
            1 => DaemonState::INIT,
            2 => DaemonState::RUNNING,
            3 => DaemonState::UPGRADING,
            4 => DaemonState::INTERRUPTED,
            5 => DaemonState::STOPPED,
            _ => DaemonState::UNKNOWN,
        }
    }
}

#[derive(Debug)]
pub enum DaemonError {
    /// Invalid arguments provided.
    InvalidArguments(String),
    /// Invalid config provided
    InvalidConfig(String),
    /// Failed to handle event other than input event.
    HandleEventNotEpollIn,
    /// Failed to handle unknown event.
    HandleEventUnknownEvent,
    /// No memory configured.
    NoMemoryConfigured,
    /// Fail to walk descriptor chain
    IterateQueue,
    /// Invalid Virtio descriptor chain.
    InvalidDescriptorChain(FuseTransportError),
    /// Processing queue failed.
    ProcessQueue(FuseError),
    /// Cannot create epoll context.
    Epoll(io::Error),
    /// Cannot clone event fd.
    EventFdClone(io::Error),
    /// Cannot spawn a new thread
    ThreadSpawn(io::Error),
    /// Failure against Passthrough FS.
    PassthroughFs(io::Error),
    /// Daemon related error
    DaemonFailure(String),

    Common(String),
    NotFound,
    AlreadyExists,
    Serde(SerdeError),
    UpgradeManager(UpgradeMgrError),
    Vfs(VfsError),
    Rafs(RafsError),
    /// Daemon does not reach the stable working state yet,
    /// some capabilities may not be provided.
    NotReady,
    /// Daemon can't fulfill external requests.
    Unsupported,
    /// State-machine related error codes if something bad happens when to communicate with state-machine
    Channel(String),
    /// Input event to stat-machine is not expected.
    UnexpectedEvent(DaemonStateMachineInput),
    /// File system backend service related errors.
    StartService(String),
    ServiceStop,
    /// Wait daemon failure
    WaitDaemon(io::Error),
    SessionShutdown(FuseTransportError),
    Downcast(String),
    FsTypeMismatch(String),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArguments(s) => write!(f, "Invalid argument: {}", s),
            Self::InvalidConfig(s) => write!(f, "Invalid config: {}", s),
            Self::DaemonFailure(s) => write!(f, "Daemon error: {}", s),
            _ => write!(f, "{:?}", self),
        }
    }
}

impl error::Error for DaemonError {}

impl From<DaemonError> for io::Error {
    fn from(e: DaemonError) -> Self {
        einval!(e)
    }
}

impl From<VfsError> for DaemonError {
    fn from(e: VfsError) -> Self {
        DaemonError::Vfs(e)
    }
}

impl From<RafsError> for DaemonError {
    fn from(error: RafsError) -> Self {
        DaemonError::Rafs(error)
    }
}

pub type DaemonResult<T> = std::result::Result<T, DaemonError>;

/// Used to export daemon working state
#[derive(Serialize)]
pub struct DaemonInfo {
    pub version: BuildTimeInfo,
    pub id: Option<String>,
    pub supervisor: Option<String>,
    pub state: DaemonState,
    pub backend_collection: FsBackendCollection,
}

#[derive(Clone)]
pub struct FsBackendMountCmd {
    pub fs_type: FsBackendType,
    pub source: String,
    pub config: String,
    pub mountpoint: String,
    pub prefetch_files: Option<Vec<String>>,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct FsBackendUmountCmd {
    pub mountpoint: String,
}

#[derive(Default, Serialize, Clone)]
pub struct FsBackendCollection(HashMap<String, FsBackendDesc>);

impl FsBackendCollection {
    fn add(&mut self, id: &str, cmd: &FsBackendMountCmd) -> DaemonResult<()> {
        // We only wash Rafs backend now.
        let fs_config = match cmd.fs_type {
            FsBackendType::Rafs => {
                let mut config: serde_json::Value =
                    serde_json::from_str(&cmd.config).map_err(DaemonError::Serde)?;
                trim_backend_config!(
                    config,
                    "access_key_id",
                    "access_key_secret",
                    "auth",
                    "token"
                );
                Some(config)
            }
            FsBackendType::PassthroughFs => {
                // Passthrough Fs has no config ever input.
                None
            }
        };

        let desc = FsBackendDesc {
            backend_type: cmd.fs_type.clone(),
            mountpoint: cmd.mountpoint.clone(),
            mounted_time: chrono::Local::now(),
            config: fs_config,
        };

        self.0.insert(id.to_string(), desc);

        Ok(())
    }

    fn del(&mut self, id: &str) {
        self.0.remove(id);
    }
}

pub trait NydusDaemon: DaemonStateMachineSubscriber {
    fn start(&self) -> DaemonResult<()>;
    fn wait(&self) -> DaemonResult<()>;
    fn stop(&self) -> DaemonResult<()> {
        self.on_event(DaemonStateMachineInput::Stop)
    }
    fn disconnect(&self) -> DaemonResult<()>;
    fn as_any(&self) -> &dyn Any;
    fn interrupt(&self) {}
    fn get_state(&self) -> DaemonState;
    fn set_state(&self, s: DaemonState);
    fn trigger_exit(&self) -> DaemonResult<()> {
        self.on_event(DaemonStateMachineInput::Exit)?;
        // Ensure all fuse threads have be terminated thus this nydusd won't
        // race fuse messages when upgrading.
        self.wait().map_err(|_| DaemonError::ServiceStop)?;
        Ok(())
    }
    fn trigger_takeover(&self) -> DaemonResult<()> {
        self.on_event(DaemonStateMachineInput::Takeover)?;
        self.on_event(DaemonStateMachineInput::Successful)?;
        Ok(())
    }
    fn id(&self) -> Option<String>;
    fn supervisor(&self) -> Option<String>;
    fn save(&self) -> DaemonResult<()>;
    fn restore(&self) -> DaemonResult<()>;
    fn get_vfs(&self) -> &Vfs;
    fn upgrade_mgr(&self) -> Option<MutexGuard<UpgradeManager>>;
    fn backend_collection(&self) -> MutexGuard<FsBackendCollection>;
    fn version(&self) -> BuildTimeInfo;
    fn export_info(&self) -> DaemonResult<String> {
        let response = DaemonInfo {
            version: self.version(),
            id: self.id(),
            supervisor: self.supervisor(),
            state: self.get_state(),
            backend_collection: self.backend_collection().deref().clone(),
        };

        serde_json::to_string(&response).map_err(DaemonError::Serde)
    }
    fn export_backend_info(&self, mountpoint: &str) -> DaemonResult<String> {
        let fs = self
            .backend_from_mountpoint(mountpoint)?
            .ok_or(DaemonError::NotFound)?;
        let any_fs = fs.deref().as_any();
        let rafs = any_fs
            .downcast_ref::<Rafs>()
            .ok_or_else(|| DaemonError::FsTypeMismatch("to rafs".to_string()))?;
        let resp = serde_json::to_string(rafs.metadata()).map_err(DaemonError::Serde)?;
        Ok(resp)
    }

    fn backend_from_mountpoint(&self, mp: &str) -> DaemonResult<Option<Arc<BackFileSystem>>> {
        let r = self.get_vfs().get_rootfs(mp)?;
        Ok(r)
    }
    fn export_inflight_ops(&self) -> DaemonResult<Option<String>>;

    // NOTE: This method is not thread-safe, however, it is acceptable as
    // mount/umount/remount/restore_mount is invoked from single thread in FSM
    fn mount(&self, cmd: FsBackendMountCmd) -> DaemonResult<()> {
        if self.backend_from_mountpoint(&cmd.mountpoint)?.is_some() {
            return Err(DaemonError::AlreadyExists);
        }
        let backend = fs_backend_factory(&cmd)?;
        let index = self.get_vfs().mount(backend, &cmd.mountpoint)?;
        info!("{} mounted at {}", &cmd.fs_type, &cmd.mountpoint);
        self.backend_collection().add(&cmd.mountpoint, &cmd)?;

        // Add mounts opaque to UpgradeManager
        if let Some(mut mgr_guard) = self.upgrade_mgr() {
            upgrade::add_mounts_state(&mut mgr_guard, cmd, index)?;
        }

        Ok(())
    }

    fn remount(&self, cmd: FsBackendMountCmd) -> DaemonResult<()> {
        let rootfs = self
            .backend_from_mountpoint(&cmd.mountpoint)?
            .ok_or(DaemonError::NotFound)?;
        let rafs_config = RafsConfig::from_str(&&cmd.config)?;
        let mut bootstrap = <dyn RafsIoRead>::from_file(&&cmd.source)?;
        let any_fs = rootfs.deref().as_any();
        let rafs = any_fs
            .downcast_ref::<Rafs>()
            .ok_or_else(|| DaemonError::FsTypeMismatch("to rafs".to_string()))?;

        rafs.update(&mut bootstrap, rafs_config)
            .map_err(|e| match e {
                RafsError::Unsupported => DaemonError::Unsupported,
                e => DaemonError::Rafs(e),
            })?;

        // To update mounted time and backend configurations.
        self.backend_collection().add(&cmd.mountpoint, &cmd)?;

        // Update mounts opaque from UpgradeManager
        if let Some(mut mgr_guard) = self.upgrade_mgr() {
            upgrade::update_mounts_state(&mut mgr_guard, cmd)?;
        }

        Ok(())
    }

    fn umount(&self, cmd: FsBackendUmountCmd) -> DaemonResult<()> {
        let _ = self
            .backend_from_mountpoint(&cmd.mountpoint)?
            .ok_or(DaemonError::NotFound)?;
        self.get_vfs().umount(&cmd.mountpoint)?;

        self.backend_collection().del(&cmd.mountpoint);

        // Remove mount opaque from UpgradeManager
        if let Some(mut mgr_guard) = self.upgrade_mgr() {
            upgrade::remove_mounts_state(&mut mgr_guard, cmd)?;
        }

        Ok(())
    }
}

/// Validate prefetch file list command line parameter.
///
/// A string including multiple directories and regular files should be separated by white-spaces, e.g.
///      <path1> <path2> <path3>
/// And each path should be relative to rafs root, e.g.
///      /foo1/bar1 /foo2/bar2
/// Specifying both regular file and directory simultaneously is supported.
fn input_prefetch_files_verify(input: &Option<Vec<String>>) -> DaemonResult<Option<Vec<PathBuf>>> {
    let prefetch_files: Option<Vec<PathBuf>> = input
        .as_ref()
        .map(|files| files.iter().map(PathBuf::from).collect());

    if let Some(files) = &prefetch_files {
        for f in files.iter() {
            if !f.starts_with(Path::new("/")) {
                return Err(DaemonError::Common("Illegal prefetch list".to_string()));
            }
        }
    }

    Ok(prefetch_files)
}

fn fs_backend_factory(cmd: &FsBackendMountCmd) -> DaemonResult<BackFileSystem> {
    let prefetch_files = input_prefetch_files_verify(&cmd.prefetch_files)?;

    match cmd.fs_type {
        FsBackendType::Rafs => {
            let rafs_config = RafsConfig::from_str(cmd.config.as_str())?;
            let mut bootstrap = <dyn RafsIoRead>::from_file(&cmd.source)?;
            let mut rafs = Rafs::new(rafs_config, &cmd.mountpoint, &mut bootstrap)?;
            rafs.import(bootstrap, prefetch_files)?;
            info!("Rafs imported");
            Ok(Box::new(rafs))
        }
        FsBackendType::PassthroughFs => {
            #[cfg(target_os = "macos")]
            return Err(DaemonError::InvalidArguments(String::from(
                "not support passthroughfs",
            )));
            #[cfg(target_os = "linux")]
            {
                // Vfs by default enables no_open and writeback, passthroughfs
                // needs to specify them explicitly.
                // TODO(liubo): enable no_open_dir.
                let fs_cfg = Config {
                    root_dir: cmd.source.to_string(),
                    do_import: false,
                    writeback: true,
                    no_open: true,
                    xattr: true,
                    ..Default::default()
                };
                // TODO: Passthrough Fs needs to enlarge rlimit against host. We can exploit `MountCmd`
                // `config` field to pass such a configuration into here.
                let passthrough_fs =
                    PassthroughFs::new(fs_cfg).map_err(DaemonError::PassthroughFs)?;
                passthrough_fs
                    .import()
                    .map_err(DaemonError::PassthroughFs)?;
                info!("PassthroughFs imported");
                Ok(Box::new(passthrough_fs))
            }
        }
    }
}

// State machine for Nydus daemon workflow.
//
// Valid states:
// - `Init` means nydusd is just started and potentially configured well but not
//    yet negotiate with kernel the capabilities of both sides. It even does not try
//    to set up fuse session by mounting `/fuse/dev`(in case of `fusedev` backend).
// - `Running` means nydusd has successfully prepared all the stuff needed to work as a
//   user-space fuse filesystem, however, the essential capabilities negotiation might not be
//   done yet. It relies on `fuse-rs` to tell if capability negotiation is done.
// - `Upgrading` state means the nydus daemon is being live-upgraded. There's no need
//   to do kernel mount again to set up a session but try to reuse a fuse fd from somewhere else.
//   In this state, we try to push `Successful` event to state machine to trigger state transition.
// - `Interrupt` state means nydusd has shutdown fuse server, which means no more message will
//    be read from kernel and handled and no pending and in-flight fuse message exists. But the
//    nydusd daemon should be alive and wait for coming events.
// - `Die` state means the whole nydusd process is going to die.
state_machine! {
    derive(Debug, Clone)
    pub DaemonStateMachine(Init)

    // FIXME: It's possible that failover does not succeed or resource is not capable to
    // be passed. To handle event `Stop` when being `Init`.
    Init => {
        Mount => Running [StartService],
        Takeover => Upgrading [Restore],
        Stop => Die[Umount],
    },
    Running => {
        Exit => Interrupted [TerminateFuseService],
        Stop => Die[Umount],
    },
    Upgrading(Successful) => Running [StartService],
    // Quit from daemon but not disconnect from fuse front-end.
    Interrupted(Stop) => Die,
}

pub struct DaemonStateMachineContext {
    sm: StateMachine<DaemonStateMachine>,
    daemon: Arc<dyn NydusDaemon + Send + Sync>,
    event_collector: Receiver<DaemonStateMachineInput>,
    result_sender: Sender<DaemonResult<()>>,
    pid: u32,
}

impl DaemonStateMachineContext {
    pub fn new(
        d: Arc<dyn NydusDaemon + Send + Sync>,
        rx: Receiver<DaemonStateMachineInput>,
        result_sender: Sender<DaemonResult<()>>,
    ) -> Self {
        DaemonStateMachineContext {
            sm: StateMachine::new(),
            daemon: d,
            event_collector: rx,
            result_sender,
            pid: id(),
        }
    }

    pub fn kick_state_machine(mut self) -> Result<()> {
        thread::Builder::new()
            .name("state_machine".to_string())
            .spawn(move || loop {
                use DaemonStateMachineOutput::*;
                let event = self
                    .event_collector
                    .recv()
                    .expect("Event channel can't be broken!");
                let last = self.sm.state().clone();
                let sm_rollback = StateMachine::<DaemonStateMachine>::from_state(last.clone());
                let input = &event;

                let action = if let Ok(a) = self.sm.consume(&event) {
                    a
                } else {
                    error!(
                        "Wrong event input. Event={:?}, CurrentState={:?}",
                        input, &last
                    );
                    // Safe to unwrap because channel is never closed
                    self.result_sender
                        .send(Err(DaemonError::UnexpectedEvent(input.clone())))
                        .unwrap();
                    continue;
                };

                let d = self.daemon.as_ref();
                let cur = self.sm.state();
                info!(
                    "State machine(pid={}): from {:?} to {:?}, input [{:?}], output [{:?}]",
                    &self.pid, last, cur, input, &action
                );
                let r = match action {
                    Some(a) => match a {
                        StartService => d.start().map(|r| {
                            d.set_state(DaemonState::RUNNING);
                            r
                        }),
                        TerminateFuseService => {
                            d.interrupt();
                            d.set_state(DaemonState::INTERRUPTED);
                            Ok(())
                        }
                        Umount => d.disconnect().map(|r| {
                            // Always interrupt fuse service loop after shutdown connection to kernel.
                            // In case that kernel does not really shutdown the session due to some reasons
                            // causing service loop keep waiting of `/dev/fuse`.
                            d.interrupt();
                            d.set_state(DaemonState::STOPPED);
                            r
                        }),
                        Restore => {
                            d.set_state(DaemonState::UPGRADING);
                            d.restore()
                        }
                    },
                    _ => Ok(()), // With no output action involved, caller should also have reply back
                }
                .map_err(|e| {
                    error!(
                        "Handle action failed, {:?}. Rollback machine to State {:?}",
                        e,
                        sm_rollback.state()
                    );
                    self.sm = sm_rollback;
                    e
                });

                // Safe to unwrap because channel is never closed
                self.result_sender.send(r).unwrap();
            })
            .map(|_| ())
    }
}

pub trait DaemonStateMachineSubscriber {
    /// Event handler for state transition events.
    ///
    /// It should be invoked in single-thread context.
    fn on_event(&self, event: DaemonStateMachineInput) -> DaemonResult<()>;
}

pub type Trigger = Sender<DaemonStateMachineInput>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_should_convert_int_to_daemonstate() {
        let stat = DaemonState::from(1);
        assert_eq!(stat, DaemonState::INIT);

        let stat = DaemonState::from(6);
        assert_eq!(stat, DaemonState::UNKNOWN);

        let stat = DaemonState::from(7);
        assert_eq!(stat, DaemonState::UNKNOWN);
    }

    #[test]
    fn it_should_convert_str_to_fsbackendtype() {
        let backend_type: FsBackendType = "rafs".parse().unwrap();
        assert!(backend_type == FsBackendType::Rafs);

        let backend_type: FsBackendType = "passthrough_fs".parse().unwrap();
        assert!(backend_type == FsBackendType::PassthroughFs);

        assert!("xxxxxxxxxxxxx".parse::<FsBackendType>().is_err());
    }

    #[test]
    fn it_should_add_new_backend() {
        let mut col: FsBackendCollection = Default::default();
        let r = col.add(
            "test",
            &FsBackendMountCmd {
                fs_type: FsBackendType::Rafs,
                config: "{\"config\": \"test\"}".to_string(),
                mountpoint: "testmonutount".to_string(),
                source: "testsource".to_string(),
                prefetch_files: Some(vec!["testfile".to_string()]),
            },
        );
        assert!(r.is_ok(), "failed to add backend collection");

        assert_eq!(col.0.len(), 1);

        col.del("test");
        assert_eq!(col.0.len(), 0);
    }

    #[test]
    fn it_should_verify_prefetch_files() {
        let files = input_prefetch_files_verify(&Some(vec!["/etc/passwd".to_string()]));
        assert!(files.is_ok(), "failed to verify prefetch files");
        assert_eq!(1, files.unwrap().unwrap().len());

        assert!(
            input_prefetch_files_verify(&Some(vec!["etc/passwd".to_string()])).is_err(),
            "should not pass verify"
        );
    }

    #[test]
    fn it_should_create_rafs_backend() {
        let config = r#"
        {
            "device": {
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
              }
            },
            "mode": "direct",
            "digest_validate": false,
            "enable_xattr": true,
            "fs_prefetch": {
              "enable": true,
              "threads_count": 10,
              "merging_size": 131072,
              "bandwidth_rate": 10485760
            }
          }"#;
        let bootstrap = "./tests/texture/bootstrap/nydusd_daemon_test_bootstrap";
        if fs_backend_factory(&FsBackendMountCmd {
            fs_type: FsBackendType::Rafs,
            config: config.to_string(),
            mountpoint: "testmountpoint".to_string(),
            source: bootstrap.to_string(),
            prefetch_files: Some(vec!["/testfile".to_string()]),
        })
        .unwrap()
        .as_any()
        .downcast_ref::<Rafs>()
        .is_none()
        {
            panic!("failed to create rafs backend")
        }
    }
}
