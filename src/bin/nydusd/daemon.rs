// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::any::Any;
use std::cmp::PartialEq;
use std::convert::From;
use std::fmt::{Display, Formatter};
use std::io::Result;
use std::ops::Deref;
use std::process::id;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::{error, fmt, io};

use fuse_backend_rs::api::vfs::VfsError;
use fuse_backend_rs::transport::Error as FuseTransportError;
use fuse_backend_rs::Error as FuseError;
use rust_fsm::*;
use serde::{self, Serialize};
use serde_json::Error as SerdeError;

use crate::fs_service::{FsBackendCollection, FsService};
use nydus_app::BuildTimeInfo;
use rafs::RafsError;

use crate::upgrade::UpgradeMgrError;

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
    /// Object already exists.
    AlreadyExists,
    /// Generic error message.
    Common(String),
    /// Invalid arguments provided.
    InvalidArguments(String),
    /// Invalid config provided
    InvalidConfig(String),
    /// Object not found.
    NotFound,
    /// Daemon does not reach the stable working state yet,
    /// some capabilities may not be provided.
    NotReady,
    /// Request not supported.
    Unsupported,
    /// Failed to serialize/deserialize message.
    Serde(SerdeError),
    /// Cannot spawn a new thread
    ThreadSpawn(io::Error),
    /// Failed to upgrade the mount
    UpgradeManager(UpgradeMgrError),

    /// State-machine related error codes if something bad happens when to communicate with state-machine
    Channel(String),
    /// Failed to start service.
    StartService(String),
    /// Failed to stop service
    ServiceStop,
    /// Input event to stat-machine is not expected.
    UnexpectedEvent(DaemonStateMachineInput),
    /// Wait daemon failure
    WaitDaemon(io::Error),

    // Filesystem type mismatch.
    FsTypeMismatch(String),
    /// Failure occurred in the Passthrough subsystem.
    PassthroughFs(io::Error),
    /// Failure occurred in the Rafs subsystem.
    Rafs(RafsError),
    /// Failure occurred in the VFS subsystem.
    Vfs(VfsError),

    // virtio-fs
    /// Failed to handle event other than input event.
    HandleEventNotEpollIn,
    /// Failed to handle unknown event.
    HandleEventUnknownEvent,
    /// Fail to walk descriptor chain
    IterateQueue,
    /// Invalid Virtio descriptor chain.
    InvalidDescriptorChain(FuseTransportError),
    /// Processing queue failed.
    ProcessQueue(FuseError),
    /// Cannot create epoll context.
    Epoll(io::Error),
    /// Daemon related error
    DaemonFailure(String),

    // Fuse session has been shutdown.
    SessionShutdown(FuseTransportError),
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

/// Specialized version of `std::result::Result` for `NydusDaemon`.
pub type DaemonResult<T> = std::result::Result<T, DaemonError>;

/// Used to export daemon working state
#[derive(Serialize)]
pub struct DaemonInfo {
    pub version: BuildTimeInfo,
    pub id: Option<String>,
    pub supervisor: Option<String>,
    pub state: DaemonState,
    pub backend_collection: Option<FsBackendCollection>,
}

pub trait NydusDaemon: DaemonStateMachineSubscriber + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn id(&self) -> Option<String>;
    fn get_state(&self) -> DaemonState;
    fn set_state(&self, s: DaemonState);
    fn version(&self) -> BuildTimeInfo;
    fn export_info(&self, include_fs_info: bool) -> DaemonResult<String> {
        let mut response = DaemonInfo {
            version: self.version(),
            id: self.id(),
            supervisor: self.supervisor(),
            state: self.get_state(),
            backend_collection: None,
        };
        if include_fs_info {
            if let Some(fs) = self.get_default_fs_service() {
                response.backend_collection = Some(fs.backend_collection().deref().clone());
            }
        }

        serde_json::to_string(&response).map_err(DaemonError::Serde)
    }

    fn start(&self) -> DaemonResult<()>;
    fn disconnect(&self) -> DaemonResult<()>;
    fn interrupt(&self) {}
    fn stop(&self) -> DaemonResult<()> {
        let s = self.get_state();
        if s != DaemonState::INTERRUPTED && s != DaemonState::STOPPED {
            return self.on_event(DaemonStateMachineInput::Stop);
        }
        Ok(())
    }
    fn wait(&self) -> DaemonResult<()>;
    fn trigger_exit(&self) -> DaemonResult<()> {
        self.on_event(DaemonStateMachineInput::Exit)
    }

    fn supervisor(&self) -> Option<String>;
    fn save(&self) -> DaemonResult<()>;
    fn restore(&self) -> DaemonResult<()>;
    fn trigger_takeover(&self) -> DaemonResult<()> {
        self.on_event(DaemonStateMachineInput::Takeover)?;
        self.on_event(DaemonStateMachineInput::Successful)?;
        Ok(())
    }

    // For backward compatibility.
    fn get_default_fs_service(&self) -> Option<Arc<dyn FsService>>;
}

// State machine for Nydus daemon workflow.
//
// State machine for FUSE:
// - `Init` means nydusd is just started and potentially configured well but not
//    yet negotiate with kernel the capabilities of both sides. It even does not try
//    to set up fuse session by mounting `/fuse/dev`(in case of `fusedev` backend).
// - `Running` means nydusd has successfully prepared all the stuff needed to work as a
//   user-space fuse filesystem, however, the essential capabilities negotiation might not be
//   done yet. It relies on `fuse-rs` to tell if capability negotiation is done.
// - `Upgrading` state means the nydus daemon is being live-upgraded. There's no need
//   to do kernel mount again to set up a session but try to reuse a fuse fd from somewhere else.
//   In this state, we try to push `Successful` event to state machine to trigger state transition.
// - `Interrupted` state means nydusd has shutdown fuse server, which means no more message will
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
        Exit => Die[StopStateMachine],
        Stop => Die[Umount],
    },
    Running => {
        Exit => Interrupted [TerminateService],
        Stop => Die[Umount],
    },
    Upgrading(Successful) => Running [StartService],
    // Quit from daemon but not disconnect from fuse front-end.
    Interrupted(Stop) => Die[StopStateMachine],
}

/// Implementation of the state machine defined by `DaemonStateMachine`.
pub struct DaemonStateMachineContext {
    pid: u32,
    daemon: Arc<dyn NydusDaemon>,
    sm: StateMachine<DaemonStateMachine>,
    request_receiver: Receiver<DaemonStateMachineInput>,
    result_sender: Sender<DaemonResult<()>>,
}

impl DaemonStateMachineContext {
    /// Create a new instance of `DaemonStateMachineContext`.
    pub fn new(
        daemon: Arc<dyn NydusDaemon>,
        request_receiver: Receiver<DaemonStateMachineInput>,
        result_sender: Sender<DaemonResult<()>>,
    ) -> Self {
        DaemonStateMachineContext {
            pid: id(),
            daemon,
            sm: StateMachine::new(),
            request_receiver,
            result_sender,
        }
    }

    pub fn kick_state_machine(mut self) -> Result<JoinHandle<Result<()>>> {
        let thread = thread::Builder::new()
            .name("state_machine".to_string())
            .spawn(move || {
                loop {
                    use DaemonStateMachineOutput::*;
                    let event = self
                        .request_receiver
                        .recv()
                        .expect("Event channel can't be broken!");
                    let last = self.sm.state().clone();
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
                            TerminateService => {
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
                            StopStateMachine => {
                                d.set_state(DaemonState::STOPPED);
                                Ok(())
                            }
                        },
                        _ => Ok(()), // With no output action involved, caller should also have reply back
                    };

                    // Safe to unwrap because channel is never closed
                    self.result_sender.send(r).unwrap();
                    // Quit state machine thread if interrupted or stopped
                    if d.get_state() == DaemonState::INTERRUPTED
                        || d.get_state() == DaemonState::STOPPED
                    {
                        break;
                    }
                }
                info!("state_machine thread exits");
                Ok(())
            })
            .map_err(DaemonError::ThreadSpawn)?;
        Ok(thread)
    }
}

/// Handler to process rquest from the state machine.
pub trait DaemonStateMachineSubscriber {
    /// Event handler for state transition events.
    ///
    /// It should be invoked in single-thread context.
    fn on_event(&self, event: DaemonStateMachineInput) -> DaemonResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus::FsBackendType;

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
}
