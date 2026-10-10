//! Tracks live-session ownership and coordinates pause, transfer, release, and
//! teardown.

use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nydus_error::{Context, Result};
use uuid::Uuid;

use crate::continuity::handoff::SessionControl;
use crate::continuity::wire::Transfer;
use crate::continuity::SessionLifecycle;

use super::identity::InstanceInfo;
use super::ownership::SessionOwner;
use super::transfer::{FuseInitState, SessionTransfer};

/// FUSE resources and worker control bound to the shared ownership lifecycle.
#[derive(Clone)]
pub(crate) struct SessionRuntimeHandle {
    pauser: fuser::SessionPauser,
    fuse_fd: Arc<OwnedFd>,
    init_state: FuseInitState,
    disarmer: fuser::MountDisarmer,
    lifecycle: SessionLifecycle,
    owner: Arc<Mutex<Option<SessionOwner>>>,
}

impl SessionRuntimeHandle {
    pub(crate) fn new(
        pauser: fuser::SessionPauser,
        fuse_fd: OwnedFd,
        init_state: FuseInitState,
        disarmer: fuser::MountDisarmer,
        owner: Arc<Mutex<Option<SessionOwner>>>,
    ) -> Self {
        Self {
            pauser,
            fuse_fd: Arc::new(fuse_fd),
            init_state,
            disarmer,
            lifecycle: SessionLifecycle::default(),
            owner,
        }
    }

    pub(crate) fn resume(&self) {
        self.pauser.resume();
    }

    pub(crate) fn exit(&self) {
        self.pauser.exit();
    }

    pub(crate) fn is_paused(&self) -> bool {
        self.pauser.is_paused()
    }

    pub(crate) fn disarm_mount(&self) {
        self.disarmer.disarm();
    }

    pub(crate) fn fuse_fd_owner(&self) -> Arc<OwnedFd> {
        self.fuse_fd.clone()
    }

    pub(crate) fn lifecycle(&self) -> SessionLifecycle {
        self.lifecycle.clone()
    }

    /// Captures the live connection and its negotiated INIT state.
    pub(super) fn session_transfer(&self, info: &InstanceInfo) -> Result<Transfer> {
        SessionTransfer::capture(info, &self.init_state, self.fuse_fd.as_fd())
    }
}

impl SessionControl for SessionRuntimeHandle {
    type Identity = InstanceInfo;

    fn lifecycle(&self) -> SessionLifecycle {
        self.lifecycle.clone()
    }

    fn session_id(&self) -> Option<Uuid> {
        None
    }

    fn prepare(&self, info: &InstanceInfo, timeout: Duration) -> Result<Option<Transfer>> {
        if !self.pauser.is_paused() {
            self.pauser
                .pause(timeout)
                .context("failed to pause fuse workers")?;
        }
        self.session_transfer(info).map(Some)
    }

    fn resume(&self) {
        self.pauser.resume();
    }

    fn release(&self) -> Result<()> {
        self.disarm_mount();
        self.exit();
        // Workers are already parked at request boundaries. Neither they nor
        // teardown can touch this mount again; do not wait for serve() to join
        // them before permitting the successor to activate.
        self.owner.lock().unwrap().take();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuse::upgrade::test_support::parked_runtime_handle;
    use crate::fuse::upgrade::transfer::SessionTransferMetadata;

    #[test]
    fn handoff_releases_the_owner_only_after_irreversible_relinquishment() {
        let dir = tempfile::tempdir().unwrap();
        let control = dir.path().join("control.sock");
        let (handle, background, _kernel) = parked_runtime_handle();
        *handle.owner.lock().unwrap() = Some(SessionOwner::acquire(&control, true).unwrap());
        let info = InstanceInfo::new("/mnt", &[1; 32]);
        background.pauser().resume();
        handle.lifecycle.begin_handoff().unwrap();
        handle.prepare(&info, Duration::from_secs(1)).unwrap();
        assert!(SessionOwner::acquire(&control, false).is_err());
        assert!(handle.lifecycle.abort_handoff());
        handle.resume();
        assert!(SessionOwner::acquire(&control, false).is_err());
        handle.lifecycle.begin_handoff().unwrap();
        handle.prepare(&info, Duration::from_secs(1)).unwrap();
        handle.lifecycle.mark_released().unwrap();
        handle.release().unwrap();
        assert!(handle.lifecycle.is_released());
        assert!(SessionOwner::acquire(&control, false).is_ok());
        assert!(handle.lifecycle.begin_handoff().is_err());
        background.join().unwrap();
    }

    #[test]
    fn common_handoff_transfers_one_connection_and_init_state() {
        use crate::continuity::handoff::{probe, ControlServer};
        use crate::continuity::test_support::metrics;

        let info = InstanceInfo::new("/mnt", &[0x11; 32]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let (handle, background, _kernel) = parked_runtime_handle();
        background.pauser().resume();
        let server = ControlServer::start(&path, info.clone(), handle.clone(), metrics()).unwrap();
        let mut handoff = probe(&path, &info)
            .unwrap()
            .unwrap()
            .begin(&info)
            .unwrap()
            .unwrap();
        let transfer = handoff
            .take_transfer()
            .expect("FUSE handoff must transfer resources");
        let metadata = SessionTransferMetadata::decode(&transfer.metadata).unwrap();
        assert_eq!(metadata.mountpoint, info.mountpoint);
        assert_eq!(metadata.image_digest, info.image_digest);
        assert_eq!(transfer.fds.len(), 1);
        assert!(handoff.commit(|| Ok(())).unwrap());
        assert!(handle.lifecycle.is_released());
        drop(server);
        background.join().unwrap();
    }
}
