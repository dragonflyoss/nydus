use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nydus_error::{Context, Error, Result};
use tracing::{info, warn};
use uuid::Uuid;

use super::fs::ErofsFs;
use super::mount::{connection_dead, finish_session, mount_dev_of};
use super::upgrade::{
    FuseInitState, SessionOwner, SessionProtection, SessionRuntimeHandle, SessionTransfer,
    HANDOFF_TIMEOUT,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SessionOrigin {
    Fresh,
    Adopted,
}

/// Background FUSE workers with ownership-aware teardown.
pub struct FuseService {
    session: fuser::BackgroundSession,
    mountpoint: PathBuf,
    handle: SessionRuntimeHandle,
    origin: SessionOrigin,
    mount_dev: Option<String>,
    /// The ownership guard, shared with the filesystem so workers keep it alive.
    owner: Arc<Mutex<Option<SessionOwner>>>,
}

impl FuseService {
    /// Mounts `fs` at `mountpoint` and starts serving it in the background.
    ///
    /// `mountpoint` must be absolute; relative paths are rejected before mounting.
    pub fn mount(fs: ErofsFs, mountpoint: &Path, config: &fuser::Config) -> Result<Self> {
        if !mountpoint.is_absolute() {
            return Err(Error::InvalidParameter(
                "FUSE mountpoint must be an absolute path".into(),
            ));
        }
        let owner = Arc::clone(&fs.owner);
        let session = fuser::Session::new(fs, mountpoint, config).context("mount failed")?;
        Self::start(
            session,
            mountpoint,
            SessionOrigin::Fresh,
            None,
            SessionProtection::Standalone,
            owner,
        )
    }

    /// Mounts with workers parked until the holder acknowledges retention.
    pub(super) fn mount_failover(
        fs: ErofsFs,
        mountpoint: &Path,
        config: &fuser::Config,
    ) -> Result<Self> {
        let owner = Arc::clone(&fs.owner);
        let mut session = fuser::Session::new(fs, mountpoint, config).context("mount failed")?;
        let journal = session
            .create_inflight_journal()
            .context("failed to create the FUSE inflight journal")?;
        let protection = SessionProtection::Failover {
            session_id: Uuid::new_v4(),
            journal: journal.map(Arc::new),
        };
        Self::start(
            session,
            mountpoint,
            SessionOrigin::Fresh,
            Some(HANDOFF_TIMEOUT),
            protection,
            owner,
        )
    }

    /// Adopts a transferred session with workers parked.
    pub(super) fn adopt(
        fs: ErofsFs,
        mountpoint: &Path,
        config: &fuser::Config,
        transfer: SessionTransfer,
        timeout: Duration,
    ) -> Result<Self> {
        let (metadata, mut devices, journal) = transfer.into_adoption();
        if Path::new(&metadata.mountpoint) != mountpoint {
            return Err(Error::InvalidParameter(format!(
                "session transfer mountpoint mismatch: transfer uses {}, adoption requested {}",
                metadata.mountpoint,
                mountpoint.display()
            )));
        }
        let state = metadata.fuse_session_state;
        let negotiated = fuser::InitFlags::from_bits_retain(state.negotiated_init_flags);
        fs.restore_init_flags(negotiated);
        let owner = Arc::clone(&fs.owner);
        let init = fuser::InitState {
            proto_version: fuser::Version(state.proto_major, state.proto_minor),
            negotiated,
            kernel_capabilities: fuser::InitFlags::from_bits_retain(state.kernel_init_flags),
        };
        let (session, protection) = match metadata.session_id {
            None => {
                let main = devices
                    .pop()
                    .ok_or_else(|| Error::Protocol("session transfer has no FUSE device".into()))?;
                let session =
                    fuser::Session::from_initialized_fd(fs, main, config.acl, config.clone(), init)
                        .context("failed to build a session on the handed-over fd")?;
                (session, SessionProtection::Standalone)
            }
            Some(session_id) => {
                // Workers keep reading the devices the Holder retains, so the
                // predecessor's worker count is kept.
                let mut config = config.clone();
                if config.clone_fd && config.n_threads != Some(devices.len()) {
                    warn!(
                        "keeping the protected session's {} FUSE workers instead of the configured {}",
                        devices.len(),
                        config.n_threads.unwrap_or(1)
                    );
                    config.n_threads = Some(devices.len());
                }
                let mut session =
                    fuser::Session::from_initialized_fds(fs, devices, config.acl, config, init)
                        .context("failed to build a session on the handed-over devices")?;
                let journal = journal
                    .map(|journal| -> Result<_> {
                        let retained = journal
                            .try_clone()
                            .context("failed to duplicate the inflight journal")?;
                        session
                            .adopt_inflight_journal(journal)
                            .context("failed to adopt the inflight journal")?;
                        Ok(Arc::new(retained))
                    })
                    .transpose()?;
                let protection = SessionProtection::Failover {
                    session_id,
                    journal,
                };
                (session, protection)
            }
        };
        Self::start(
            session,
            mountpoint,
            SessionOrigin::Adopted,
            Some(timeout),
            protection,
            owner,
        )
        .context("failed to adopt fuse session")
    }

    /// Starts the workers, parked when `park_timeout` is set, after capturing
    /// the state a handoff transfers.
    fn start(
        mut session: fuser::Session<ErofsFs>,
        mountpoint: &Path,
        origin: SessionOrigin,
        park_timeout: Option<Duration>,
        protection: SessionProtection,
        owner: Arc<Mutex<Option<SessionOwner>>>,
    ) -> Result<Self> {
        // Capture handoff state before spawn consumes the session. A protected
        // session hands over every device, as a request read on a device can
        // only be answered on that device.
        let devices = match protection {
            SessionProtection::Standalone => vec![session
                .as_fd()
                .try_clone_to_owned()
                .context("failed to dup the fuse fd")?],
            SessionProtection::Failover { .. } => session
                .try_clone_fds()
                .context("failed to dup the fuse devices")?,
        };
        let fuser::InitState {
            proto_version: fuser::Version(proto_major, proto_minor),
            negotiated,
            kernel_capabilities,
        } = session.init_state();
        let init_state = FuseInitState {
            proto_major,
            proto_minor,
            negotiated_init_flags: negotiated.bits(),
            kernel_init_flags: kernel_capabilities.bits(),
        };
        let mount_dev = Some(
            mount_dev_of(mountpoint)
                .with_context(|| {
                    format!(
                        "failed to record the mount device of {}",
                        mountpoint.display()
                    )
                })?
                .ok_or_else(|| {
                    Error::Runtime(format!(
                        "no mount device found for {}",
                        mountpoint.display()
                    ))
                })?,
        );
        let session = match park_timeout {
            Some(timeout) => session
                .spawn_paused(timeout)
                .context("failed to prepare paused fuse workers")?,
            None => session.spawn().context("spawn failed")?,
        };
        let handle = SessionRuntimeHandle::new(
            session.pauser(),
            devices,
            init_state,
            protection,
            Arc::clone(&owner),
        );
        Ok(Self {
            session,
            mountpoint: mountpoint.to_path_buf(),
            handle,
            origin,
            mount_dev,
            owner,
        })
    }

    pub(super) fn runtime_handle(&self) -> SessionRuntimeHandle {
        self.handle.clone()
    }

    pub(super) fn set_owner(&mut self, owner: SessionOwner) -> Result<()> {
        let mut slot = self.owner.lock().unwrap();
        if slot.is_some() {
            return Err(Error::Runtime(
                "session ownership is already assigned".into(),
            ));
        }
        *slot = Some(owner);
        Ok(())
    }

    /// Recovers inflight requests while adopted workers remain parked: resends the
    /// requests a crashed predecessor never answered, or fails the journaled ones
    /// with `EIO` for their callers to retry.
    pub(super) fn recover_inflight(&self) -> Result<()> {
        let outcome = self
            .session
            .notifier()
            .recover_inflight(fuser::Errno::EIO)
            .context("failed to recover inflight FUSE requests")?;
        info!(
            ?outcome,
            "inflight FUSE requests recovered; workers remain parked"
        );
        Ok(())
    }

    pub(super) fn start_serving(&self) {
        self.handle.activate();
    }

    /// Stops a failed startup: unmount fresh resources, preserve adopted mounts for retry.
    pub(super) fn stop_unpublished(self) -> Result<()> {
        let FuseService {
            session,
            mountpoint,
            handle,
            origin,
            mount_dev,
            owner,
        } = self;
        let _owner = owner;
        if origin == SessionOrigin::Adopted {
            // An adopted session owns no mount, so this cannot unmount it.
            handle.exit();
            return session
                .join()
                .context("failed to join the stopped fuse successor");
        }
        let released = handle.lifecycle().is_released();
        finish_session(session, &mountpoint, origin, released, mount_dev.as_deref())
            .context("failed to stop unpublished FUSE session")
    }

    /// Serves until shutdown or connection exit, then tears down only the owned mount.
    /// Returns whether the session ended: not handed off, and its mount removed or
    /// its connection closed.
    pub fn serve(self, shutdown: &AtomicBool) -> std::io::Result<bool> {
        let FuseService {
            session: bg,
            mountpoint,
            handle,
            origin,
            mount_dev,
            owner,
        } = self;

        let _owner = owner;
        let lifecycle = handle.lifecycle();
        let devices = handle.devices();
        while !shutdown.load(Ordering::Relaxed)
            && !lifecycle.is_released()
            && !connection_dead(devices[0].as_fd())
            && !bg.is_finished()
        {
            std::thread::sleep(Duration::from_millis(100));
        }
        // Even a dead connection must exclude a concurrent handoff before teardown.
        lifecycle.begin_teardown();
        finish_session(
            bg,
            &mountpoint,
            origin,
            lifecycle.is_released(),
            mount_dev.as_deref(),
        )?;
        // A mount teardown could not identify may still be in place.
        let unmounted = matches!(mount_dev_of(&mountpoint), Ok(current) if current != mount_dev);
        Ok(!lifecycle.is_released() && (unmounted || connection_dead(devices[0].as_fd())))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;

    use super::*;
    use crate::fuse::upgrade::test_support::{empty_session, fuse_init_state};

    fn stub_service(origin: SessionOrigin) -> (FuseService, UnixStream) {
        let (session, kernel) = empty_session(fuser::InitFlags::empty());
        let devices = vec![session.as_fd().try_clone_to_owned().unwrap()];
        let background = if origin == SessionOrigin::Adopted {
            session.spawn_paused(Duration::from_secs(5)).unwrap()
        } else {
            session.spawn().unwrap()
        };
        let owner = Arc::new(Mutex::new(None));
        let handle = SessionRuntimeHandle::new(
            background.pauser(),
            devices,
            fuse_init_state(),
            SessionProtection::Standalone,
            Arc::clone(&owner),
        );
        let service = FuseService {
            session: background,
            mountpoint: PathBuf::from("/nonexistent-shutdown-unpublished-stub"),
            handle,
            origin,
            mount_dev: None,
            owner,
        };
        (service, kernel)
    }

    #[test]
    fn stop_unpublished_stops_fresh_and_adopted_sessions_without_a_real_mount() {
        for origin in [SessionOrigin::Fresh, SessionOrigin::Adopted] {
            let (service, _kernel) = stub_service(origin);
            service.stop_unpublished().unwrap();
        }
    }

    #[test]
    fn serving_observes_shutdown_without_a_signal_thread() {
        let (service, _kernel) = stub_service(SessionOrigin::Adopted);
        service.serve(&AtomicBool::new(true)).unwrap();
    }
}
