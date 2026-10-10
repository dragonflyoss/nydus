use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::fs::ErofsFs;
use super::mount::{connection_dead, finish_session, mount_dev_of};
use super::upgrade::{
    validate_fuse_connection, FuseInitState, SessionOwner, SessionRuntimeHandle, SessionTransfer,
};
use nydus_error::{Context, Error, Result};

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
        Self::start(session, mountpoint, SessionOrigin::Fresh, None, owner)
    }

    /// Adopts a transferred session with workers parked.
    pub(super) fn adopt(
        fs: ErofsFs,
        mountpoint: &Path,
        config: &fuser::Config,
        transfer: SessionTransfer,
        timeout: Duration,
    ) -> Result<Self> {
        let (metadata, fuse_fd) = transfer.into_adoption();
        if Path::new(&metadata.mountpoint) != mountpoint {
            return Err(Error::InvalidParameter(format!(
                "session transfer mountpoint mismatch: transfer uses {}, adoption requested {}",
                metadata.mountpoint,
                mountpoint.display()
            )));
        }
        validate_fuse_connection(fuse_fd.as_fd()).context("invalid handed-over FUSE connection")?;
        let state = metadata.fuse_session_state;
        let negotiated = fuser::InitFlags::from_bits_retain(state.negotiated_init_flags);
        fs.restore_init_flags(negotiated);
        let owner = Arc::clone(&fs.owner);
        let session = fuser::Session::from_initialized_fd(
            fs,
            fuse_fd,
            config.acl,
            config.clone(),
            fuser::Version(state.proto_major, state.proto_minor),
            negotiated,
            fuser::InitFlags::from_bits_retain(state.kernel_init_flags),
        )
        .context("failed to build a session on the handed-over fd")?;
        Self::start(
            session,
            mountpoint,
            SessionOrigin::Adopted,
            Some(timeout),
            owner,
        )
        .context("failed to adopt fuse session")
    }

    fn start(
        session: fuser::Session<ErofsFs>,
        mountpoint: &Path,
        origin: SessionOrigin,
        park_timeout: Option<Duration>,
        owner: Arc<Mutex<Option<SessionOwner>>>,
    ) -> Result<Self> {
        // Capture handoff state before spawn consumes the session.
        let fuse_fd = session
            .as_fd()
            .try_clone_to_owned()
            .context("failed to dup the fuse fd")?;
        let fuser::Version(proto_major, proto_minor) = session
            .proto_version()
            .ok_or_else(|| Error::Runtime("fuse session has no negotiated version".to_string()))?;
        let init_state = FuseInitState {
            proto_major,
            proto_minor,
            negotiated_init_flags: session.negotiated_init_flags().bits(),
            kernel_init_flags: session.kernel_init_flags().bits(),
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
            fuse_fd,
            init_state,
            session.mount_disarmer(),
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

    pub(super) fn start_serving(&self) {
        self.handle.resume();
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
            handle.disarm_mount();
            handle.exit();
            return session
                .join()
                .context("failed to join the stopped fuse successor");
        }
        if handle.is_paused() {
            handle.exit();
        }
        let released = handle.lifecycle().is_released();
        finish_session(session, &mountpoint, origin, released, mount_dev.as_deref())
            .context("failed to stop unpublished FUSE session")
    }

    /// Serves until shutdown or connection exit, then tears down only the owned mount.
    pub fn serve(self, shutdown: &AtomicBool) -> std::io::Result<()> {
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
        let fuse_fd = handle.fuse_fd_owner();
        while !shutdown.load(Ordering::Relaxed)
            && !lifecycle.is_released()
            && !connection_dead(fuse_fd.as_fd())
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
        )
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;

    use super::*;
    use crate::fuse::upgrade::test_support::{empty_session, fuse_init_state};

    fn stub_service(origin: SessionOrigin) -> (FuseService, UnixStream) {
        let (session, kernel) = empty_session(fuser::InitFlags::empty());
        let fuse_fd = session.as_fd().try_clone_to_owned().unwrap();
        let background = if origin == SessionOrigin::Adopted {
            session.spawn_paused(Duration::from_secs(5)).unwrap()
        } else {
            session.spawn().unwrap()
        };
        let owner = Arc::new(Mutex::new(None));
        let handle = SessionRuntimeHandle::new(
            background.pauser(),
            fuse_fd,
            fuse_init_state(),
            background.mount_disarmer(),
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
