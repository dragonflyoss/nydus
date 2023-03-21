// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020-2022 Alibaba Cloud. All rights reserved.
// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Infrastructure to define and manage Nydus service daemons.

use std::any::Any;
use std::cmp::PartialEq;
use std::convert::From;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{Builder, JoinHandle};

use mio::{Events, Poll, Token, Waker};
use nydus_api::BuildTimeInfo;
use rust_fsm::*;
use serde::{self, Serialize};

use crate::fs_service::{FsBackendCollection, FsService};
use crate::{BlobCacheMgr, Error, Result};

/// Nydus daemon working states.
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

/// Build, version and working state information for Nydus daemons.
#[derive(Serialize)]
pub struct DaemonInfo {
    /// Build and version information.
    pub version: BuildTimeInfo,
    /// Optional daemon identifier.
    pub id: Option<String>,
    /// Optional daemon supervisor configuration information.
    pub supervisor: Option<String>,
    /// Daemon working state.
    pub state: DaemonState,
    /// Optional metrics and statistics about filesystem instances.
    pub backend_collection: Option<FsBackendCollection>,
}

/// Abstract interfaces for Nydus daemon objects.
///
/// The [`NydusDaemon`] trait defines interfaces that an Nydus daemon object should implement,
/// so the daemon manager can manage those objects.
pub trait NydusDaemon: DaemonStateMachineSubscriber + Send + Sync {
    /// Cast `self` to trait object of [Any] to support object downcast.
    fn as_any(&self) -> &dyn Any;

    /// Get optional daemon identifier.
    fn id(&self) -> Option<String>;

    /// Get build and version information.
    fn version(&self) -> BuildTimeInfo;

    /// Get status information about the daemon.
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

    /// Get daemon working state.
    fn get_state(&self) -> DaemonState;
    /// Set daemon working state.
    fn set_state(&self, s: DaemonState);
    /// Start the daemon object to serve incoming requests.
    fn start(&self) -> Result<()>;
    /// Umount the FUSE filesystem.
    fn umount(&self) -> Result<()>;
    /// Stop the daemon object.
    fn stop(&self) {}
    /// Trigger `Stop` transition event to stop the daemon.
    fn trigger_stop(&self) -> Result<()> {
        let s = self.get_state();

        if s == DaemonState::STOPPED {
            return Ok(());
        }

        if s == DaemonState::RUNNING {
            self.on_event(DaemonStateMachineInput::Stop)?;
        }

        self.on_event(DaemonStateMachineInput::Stop)
    }
    /// Trigger transition events to move the state machine to `STOPPED` state.
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

    /// Wait for daemon to exit.
    fn wait(&self) -> Result<()>;
    /// Wait for service worker thread to exit.
    fn wait_service(&self) -> Result<()> {
        Ok(())
    }
    /// Wait for state machine worker thread to exit.
    fn wait_state_machine(&self) -> Result<()> {
        Ok(())
    }

    /// Get supervisor configuration information.
    fn supervisor(&self) -> Option<String>;
    /// Save state for online upgrade.
    fn save(&self) -> Result<()>;
    /// Restore state for online upgrade.
    fn restore(&self) -> Result<()>;
    /// Trigger `Takeover` transition event to take over control from old instance.
    fn trigger_takeover(&self) -> Result<()> {
        self.on_event(DaemonStateMachineInput::Takeover)
    }
    /// Trigger `Start` transition event to start the new instance.
    fn trigger_start(&self) -> Result<()> {
        self.on_event(DaemonStateMachineInput::Start)
    }

    // For backward compatibility.
    /// Set default filesystem service object.
    fn get_default_fs_service(&self) -> Option<Arc<dyn FsService>> {
        None
    }

    /// Get the optional `BlobCacheMgr` object.
    fn get_blob_cache_mgr(&self) -> Option<Arc<BlobCacheMgr>> {
        None
    }

    /// Delete a blob object managed by the daemon.
    fn delete_blob(&self, _blob_id: String) -> Result<()> {
        Ok(())
    }
}

// State machine for Nydus daemon workflow.
//
// Valid states for Nydus daemon state machine:
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

/// An implementation of the state machine defined by [`DaemonStateMachine`].
pub struct DaemonStateMachineContext {
    pid: u32,
    daemon: Arc<dyn NydusDaemon>,
    sm: StateMachine<DaemonStateMachine>,
    request_receiver: Receiver<DaemonStateMachineInput>,
    result_sender: Sender<Result<()>>,
}

impl DaemonStateMachineContext {
    /// Create a new instance of [`DaemonStateMachineContext`].
    pub fn new(
        daemon: Arc<dyn NydusDaemon>,
        request_receiver: Receiver<DaemonStateMachineInput>,
        result_sender: Sender<Result<()>>,
    ) -> Self {
        DaemonStateMachineContext {
            pid: process::id(),
            daemon,
            sm: StateMachine::new(),
            request_receiver,
            result_sender,
        }
    }

    /// Create a worker thread to run event loop for the state machine.
    pub fn kick_state_machine(self) -> Result<JoinHandle<std::io::Result<()>>> {
        Builder::new()
            .name("state_machine".to_string())
            .spawn(move || self.run_state_machine_event_loop())
            .map_err(Error::ThreadSpawn)
    }

    fn run_state_machine_event_loop(mut self) -> std::io::Result<()> {
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
                    .send(Err(Error::UnexpectedEvent(event)))
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
                Some(StartService) => d.start().map(|r| {
                    d.set_state(DaemonState::RUNNING);
                    r
                }),
                Some(TerminateService) => {
                    d.stop();
                    let res = d.wait_service();
                    if res.is_ok() {
                        d.set_state(DaemonState::READY);
                    }
                    res
                }
                Some(Umount) => d.umount().map(|r| {
                    // Always interrupt fuse service loop after shutdown connection to kernel.
                    // In case that kernel does not really shutdown the session due to some reasons
                    // causing service loop keep waiting of `/dev/fuse`.
                    d.stop();
                    d.wait_service()
                        .unwrap_or_else(|e| error!("failed to wait service {}", e));
                    // at least all fuse thread stopped, no matter what error each thread got
                    d.set_state(DaemonState::STOPPED);
                    r
                }),
                Some(Restore) => {
                    let res = d.restore();
                    if res.is_ok() {
                        d.set_state(DaemonState::READY);
                    }
                    res
                }
                Some(StopStateMachine) => {
                    d.set_state(DaemonState::STOPPED);
                    Ok(())
                }
                // With no output action involved, caller should also have reply back
                None => Ok(()),
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
    }
}

/// Handler to process state transition events emitted from the state machine.
pub trait DaemonStateMachineSubscriber {
    /// Event handler to process state transition events.
    ///
    /// It will be invoked in single-threaded context.
    fn on_event(&self, event: DaemonStateMachineInput) -> Result<()>;
}

/// Controller to manage registered filesystem/blobcache/fscache services.
pub struct DaemonController {
    active: AtomicBool,
    singleton_mode: AtomicBool,
    daemon: Mutex<Option<Arc<dyn NydusDaemon>>>,
    blob_cache_mgr: Mutex<Option<Arc<BlobCacheMgr>>>,
    // For backward compatibility to support singleton fusedev/virtiofs server.
    fs_service: Mutex<Option<Arc<dyn FsService>>>,
    waker: Arc<Waker>,
    poller: Mutex<Poll>,
}

impl DaemonController {
    /// Create a new instance of [DaemonController].
    pub fn new() -> Self {
        let poller = Poll::new().expect("Failed to create poller for DaemonController");
        let waker = Waker::new(poller.registry(), Token(1))
            .expect("Failed to create waker for DaemonController");

        Self {
            active: AtomicBool::new(true),
            singleton_mode: AtomicBool::new(false),
            daemon: Mutex::new(None),
            blob_cache_mgr: Mutex::new(None),
            fs_service: Mutex::new(None),
            waker: Arc::new(waker),
            poller: Mutex::new(poller),
        }
    }

    /// Check whether the service controller is still in active/working state.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// Allocate a waker to notify stop events.
    pub fn alloc_waker(&self) -> Arc<Waker> {
        self.waker.clone()
    }

    /// Enable/disable singleton mode.
    pub fn set_singleton_mode(&self, enabled: bool) {
        self.singleton_mode.store(enabled, Ordering::Release);
    }

    /// Set the daemon service object.
    pub fn set_daemon(&self, daemon: Arc<dyn NydusDaemon>) -> Option<Arc<dyn NydusDaemon>> {
        self.daemon.lock().unwrap().replace(daemon)
    }

    /// Get the daemon service object.
    ///
    /// Panic if called before `set_daemon()` has been called.
    pub fn get_daemon(&self) -> Arc<dyn NydusDaemon> {
        self.daemon.lock().unwrap().clone().unwrap()
    }

    /// Get the optional blob cache manager.
    pub fn get_blob_cache_mgr(&self) -> Option<Arc<BlobCacheMgr>> {
        self.blob_cache_mgr.lock().unwrap().clone()
    }

    /// Set the optional blob cache manager.
    pub fn set_blob_cache_mgr(&self, mgr: Arc<BlobCacheMgr>) -> Option<Arc<BlobCacheMgr>> {
        self.blob_cache_mgr.lock().unwrap().replace(mgr)
    }

    /// Set the default fs service object.
    pub fn set_fs_service(&self, service: Arc<dyn FsService>) -> Option<Arc<dyn FsService>> {
        self.fs_service.lock().unwrap().replace(service)
    }

    /// Get the default fs service object.
    pub fn get_fs_service(&self) -> Option<Arc<dyn FsService>> {
        self.fs_service.lock().unwrap().clone()
    }

    /// Shutdown all services managed by the controller.
    pub fn shutdown(&self) {
        // Marking exiting state.
        self.active.store(false, Ordering::Release);
        // Signal the `run_loop()` working thread to exit.
        let _ = self.waker.wake();

        let daemon = self.daemon.lock().unwrap().take();
        if let Some(d) = daemon {
            if let Err(e) = d.trigger_stop() {
                error!("failed to stop daemon: {}", e);
            }
            if let Err(e) = d.wait() {
                error!("failed to wait daemon: {}", e)
            }
        }
    }

    /// Run the event loop to handle service management events.
    pub fn run_loop(&self) {
        let mut events = Events::with_capacity(8);

        loop {
            match self.poller.lock().unwrap().poll(&mut events, None) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => error!("failed to receive notification from waker: {}", e),
                Ok(_) => {}
            }

            for event in events.iter() {
                if event.is_error() {
                    error!("Got error on the monitored event.");
                    continue;
                }

                if event.is_readable() && event.token() == Token(1) {
                    if !self.active.load(Ordering::Acquire) {
                        return;
                    } else if !self.singleton_mode.load(Ordering::Acquire) {
                        self.active.store(false, Ordering::Relaxed);
                        return;
                    }
                }
            }
        }
    }
}

impl Default for DaemonController {
    fn default() -> Self {
        DaemonController::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FsBackendType;

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
        assert_eq!(backend_type, FsBackendType::Rafs);

        let backend_type: FsBackendType = "passthrough_fs".parse().unwrap();
        assert_eq!(backend_type, FsBackendType::PassthroughFs);

        assert!("xxxxxxxxxxxxx".parse::<FsBackendType>().is_err());
    }
}
