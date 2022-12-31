// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::any::Any;
use std::cmp::PartialEq;
use std::convert::From;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::process::id;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use nydus::{Error, Result};
use nydus_app::BuildTimeInfo;
use rust_fsm::*;
use serde::{self, Serialize};

use crate::fs_service::{FsBackendCollection, FsService};

#[allow(dead_code)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Hash, PartialEq, Eq, Serialize)]
pub enum DaemonState {
    INIT = 1,
    RUNNING = 2,
    READY = 3,
    STOPPED = 4,
    UNKNOWN = 5,
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
            3 => DaemonState::READY,
            4 => DaemonState::STOPPED,
            _ => DaemonState::UNKNOWN,
        }
    }
}

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
    fn export_info(&self, include_fs_info: bool) -> Result<String> {
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

        serde_json::to_string(&response).map_err(Error::Serde)
    }

    fn start(&self) -> Result<()>;
    fn disconnect(&self) -> Result<()>;
    fn interrupt(&self) {}
    fn stop(&self) -> Result<()> {
        let s = self.get_state();

        if s == DaemonState::STOPPED {
            return Ok(());
        }

        if s == DaemonState::RUNNING {
            self.on_event(DaemonStateMachineInput::Stop)?;
        }

        self.on_event(DaemonStateMachineInput::Stop)
    }
    fn wait(&self) -> Result<()>;
    fn wait_service(&self) -> Result<()> {
        Ok(())
    }
    fn wait_state_machine(&self) -> Result<()> {
        Ok(())
    }
    fn trigger_exit(&self) -> Result<()> {
        let s = self.get_state();

        if s == DaemonState::STOPPED {
            return Ok(());
        }

        if s == DaemonState::INIT {
            return self.on_event(DaemonStateMachineInput::Stop);
        }

        if s == DaemonState::RUNNING {
            self.on_event(DaemonStateMachineInput::Stop)?;
        }

        self.on_event(DaemonStateMachineInput::Exit)
    }
    fn supervisor(&self) -> Option<String>;
    fn save(&self) -> Result<()>;
    fn restore(&self) -> Result<()>;
    fn trigger_takeover(&self) -> Result<()> {
        self.on_event(DaemonStateMachineInput::Takeover)
    }
    fn trigger_start(&self) -> Result<()> {
        self.on_event(DaemonStateMachineInput::Start)
    }

    // For backward compatibility.
    fn get_default_fs_service(&self) -> Option<Arc<dyn FsService>>;

    fn delete_blob(&self, _blob_id: String) -> Result<()> {
        Ok(())
    }
}

// State machine for Nydus daemon workflow.
//
// State machine for FUSE:
// - `Init` means nydusd is just started and potentially configured well but not
//    yet negotiate with kernel the capabilities of both sides. It even does not try
//    to set up fuse session by mounting `/fuse/dev`(in case of `fusedev` backend).
// - `Ready` means nydusd is ready for start or die. Fuse session is created.
// - `Running` means nydusd has successfully prepared all the stuff needed to work as a
//   user-space fuse filesystem, however, the essential capabilities negotiation might not be
//   done yet. It relies on `fuse-rs` to tell if capability negotiation is done.
// - `Die` state means the whole nydusd process is going to die.
state_machine! {
    derive(Debug, Clone)
    pub DaemonStateMachine(Init)

    Init => {
        Mount => Ready,
        Takeover => Ready[Restore],
        Stop => Die[StopStateMachine],
    },
    Ready => {
        Start => Running[StartService],
        Stop => Die[Umount],
        Exit => Die[StopStateMachine],
    },
    Running => {
        Stop => Ready [TerminateService],
    },
}

/// Implementation of the state machine defined by `DaemonStateMachine`.
pub struct DaemonStateMachineContext {
    pid: u32,
    daemon: Arc<dyn NydusDaemon>,
    sm: StateMachine<DaemonStateMachine>,
    request_receiver: Receiver<DaemonStateMachineInput>,
    result_sender: Sender<Result<()>>,
}

impl DaemonStateMachineContext {
    /// Create a new instance of `DaemonStateMachineContext`.
    pub fn new(
        daemon: Arc<dyn NydusDaemon>,
        request_receiver: Receiver<DaemonStateMachineInput>,
        result_sender: Sender<Result<()>>,
    ) -> Self {
        DaemonStateMachineContext {
            pid: id(),
            daemon,
            sm: StateMachine::new(),
            request_receiver,
            result_sender,
        }
    }

    pub fn kick_state_machine(mut self) -> std::io::Result<JoinHandle<std::io::Result<()>>> {
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
                            .send(Err(Error::UnexpectedEvent(format!("{:?}", input))))
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
                                let res = d.wait_service();
                                if res.is_ok() {
                                    d.set_state(DaemonState::READY);
                                }

                                res
                            }
                            Umount => d.disconnect().map(|r| {
                                // Always interrupt fuse service loop after shutdown connection to kernel.
                                // In case that kernel does not really shutdown the session due to some reasons
                                // causing service loop keep waiting of `/dev/fuse`.
                                d.interrupt();
                                d.wait_service()
                                    .unwrap_or_else(|e| error!("failed to wait service {}", e));
                                // at least all fuse thread stopped, no matter what error each thread got
                                d.set_state(DaemonState::STOPPED);
                                r
                            }),
                            Restore => {
                                let res = d.restore();
                                if res.is_ok() {
                                    d.set_state(DaemonState::READY);
                                }
                                res
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
                    if d.get_state() == DaemonState::STOPPED {
                        break;
                    }
                }
                info!("state_machine thread exits");
                Ok(())
            })
            .map_err(Error::ThreadSpawn)?;
        Ok(thread)
    }
}

/// Handler to process rquest from the state machine.
pub trait DaemonStateMachineSubscriber {
    /// Event handler for state transition events.
    ///
    /// It should be invoked in single-thread context.
    fn on_event(&self, event: DaemonStateMachineInput) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus::FsBackendType;

    #[test]
    fn it_should_convert_int_to_daemonstate() {
        let stat = DaemonState::from(1);
        assert_eq!(stat, DaemonState::INIT);

        let stat = DaemonState::from(2);
        assert_eq!(stat, DaemonState::RUNNING);

        let stat = DaemonState::from(3);
        assert_eq!(stat, DaemonState::READY);

        let stat = DaemonState::from(4);
        assert_eq!(stat, DaemonState::STOPPED);

        let stat = DaemonState::from(5);
        assert_eq!(stat, DaemonState::UNKNOWN);

        let stat = DaemonState::from(8);
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
