//! Tracks live-session ownership and coordinates pause, transfer, release, and
//! teardown.

use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nydus_error::{Context, Result};
use uuid::Uuid;

use crate::continuity::handoff::SessionControl;
use crate::continuity::wire::Transfer;
use crate::continuity::SessionLifecycle;

use super::identity::InstanceInfo;
use super::ownership::SessionOwner;
use super::transfer::{FuseInitState, SessionProtection, SessionTransfer};

/// FUSE resources and worker control bound to the shared ownership lifecycle.
#[derive(Clone)]
pub(crate) struct SessionRuntimeHandle {
    pauser: fuser::SessionPauser,
    /// The main device first, then the cloned worker devices of a protected session.
    devices: Arc<Vec<OwnedFd>>,
    init_state: FuseInitState,
    lifecycle: SessionLifecycle,
    /// The crash-failover protection, preserved across hot upgrade.
    protection: SessionProtection,
    /// Set once the workers first run; before that they are parked by startup.
    activated: Arc<AtomicBool>,
    owner: Arc<Mutex<Option<SessionOwner>>>,
}

impl SessionRuntimeHandle {
    /// Creates the handle of workers that read `devices`, main device first.
    pub(crate) fn new(
        pauser: fuser::SessionPauser,
        devices: Vec<OwnedFd>,
        init_state: FuseInitState,
        protection: SessionProtection,
        owner: Arc<Mutex<Option<SessionOwner>>>,
    ) -> Self {
        Self {
            pauser,
            devices: Arc::new(devices),
            init_state,
            lifecycle: SessionLifecycle::default(),
            protection,
            activated: Arc::default(),
            owner,
        }
    }

    /// Starts the workers that startup left parked.
    pub(crate) fn activate(&self) {
        self.activated.store(true, Ordering::Release);
        self.pauser.resume();
    }

    pub(crate) fn exit(&self) {
        self.pauser.exit();
    }

    /// Returns the FUSE devices, main device first.
    pub(crate) fn devices(&self) -> Arc<Vec<OwnedFd>> {
        self.devices.clone()
    }

    pub(crate) fn lifecycle(&self) -> SessionLifecycle {
        self.lifecycle.clone()
    }

    /// Captures the live session without adding or removing failover protection.
    pub(super) fn session_transfer(&self, info: &InstanceInfo) -> Result<Transfer> {
        SessionTransfer::capture(info, &self.init_state, &self.devices, &self.protection)
    }
}

impl SessionControl for SessionRuntimeHandle {
    type Identity = InstanceInfo;

    fn lifecycle(&self) -> SessionLifecycle {
        self.lifecycle.clone()
    }

    fn session_id(&self) -> Option<Uuid> {
        self.protection.session_id()
    }

    fn prepare(&self, info: &InstanceInfo, timeout: Duration) -> Result<Option<Transfer>> {
        // Holder retention of a fresh protected session precedes activation,
        // while startup keeps the workers parked; a handoff follows it.
        if self.activated.load(Ordering::Acquire) {
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
        // The lifecycle is already released, so teardown retires the mount
        // with `finish_handoff` instead of unmounting it, and the parked
        // workers cannot touch it again; do not wait for serve() to join
        // them before permitting the successor to activate.
        self.exit();
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
        let (handle, background, _kernel) = parked_runtime_handle(None);
        *handle.owner.lock().unwrap() = Some(SessionOwner::acquire(&control, true).unwrap());
        let info = InstanceInfo::new("/mnt", Some(&[1; 32]));
        handle.activate();
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
    fn handoff_transfers_every_device_and_journal_of_a_protected_session() {
        use crate::continuity::handoff::{probe, ControlServer};
        use crate::continuity::test_support::{metrics, ondemand};

        let info = InstanceInfo::new("/mnt", Some(&[0x11; 32]));
        for session_id in [None, Some(Uuid::from_u128(7))] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("api.sock");
            let (handle, background, _kernel) = parked_runtime_handle(session_id);
            handle
                .prepare(&info, Duration::from_secs(1))
                .unwrap()
                .unwrap();
            handle.activate();
            let server =
                ControlServer::start(&path, info.clone(), handle.clone(), metrics(), ondemand())
                    .unwrap();
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
            assert_eq!(Some(metadata.image_digest), info.image_digest);
            assert_eq!(metadata.session_id, session_id);
            let devices = handle.devices().len();
            assert_eq!(
                transfer.fds.len(),
                devices + usize::from(session_id.is_some())
            );
            assert!(handoff.commit(|| Ok(())).unwrap());
            assert!(handle.lifecycle.is_released());
            drop(server);
            background.join().unwrap();
        }
    }
}
