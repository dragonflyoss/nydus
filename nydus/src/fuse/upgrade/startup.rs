use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use fuser::Config;
use nydus_core::{Metrics, OndemandRecorder};
use nydus_error::{Context, Error, Result};
use uuid::Uuid;

use super::identity::InstanceInfo;
use super::lifecycle::SessionRuntimeHandle;
use super::ownership::{OwnerRecord, SessionOwner};
use super::transfer::SessionTransfer;
use crate::continuity::handoff::SessionControl;
use crate::continuity::startup::{self, Frontend, Open};
use crate::fuse::mount::{is_fuse_fstype, mount_entry_of};
use crate::fuse::{ErofsFs, FuseService};

/// The maximum number of final-component symlinks explicitly expanded during resolution.
const MAX_SYMLINK_HOPS: usize = 40;

/// FUSE-specific startup identity and path validation.
pub struct Startup {
    mountpoint: PathBuf,
    coordinator: startup::Startup<InstanceInfo>,
}

impl Startup {
    /// Resolves mountpoint aliases and validates paths for startup coordination.
    ///
    /// An API endpoint or a Recovery Holder requires an image digest to adopt a session.
    pub fn new(
        mountpoint: &Path,
        api_socket: Option<PathBuf>,
        image_digest: Option<&[u8]>,
        supervisor_socket: Option<PathBuf>,
        metrics: Arc<Metrics>,
        ondemand: Arc<OndemandRecorder>,
    ) -> Result<Self> {
        let mountpoint = normalize_mountpoint(mountpoint)?;
        let mountpoint_id = mountpoint.to_str().ok_or_else(|| {
            Error::InvalidParameter(
                "mountpoint must be valid UTF-8 for FUSE session continuity".into(),
            )
        })?;
        let state_base = ownership_state_base(&mountpoint)?;
        startup::validate_socket_paths(
            api_socket.as_deref(),
            supervisor_socket.as_deref(),
            Some(&mountpoint),
        )?;
        let info = InstanceInfo::new(mountpoint_id, image_digest);
        if api_socket.is_some() || supervisor_socket.is_some() {
            info.require_image_digest()?;
        }
        Ok(Self {
            mountpoint,
            coordinator: startup::Startup {
                info,
                state_base,
                holder: supervisor_socket.map(|path| path.components().collect()),
                api_socket: api_socket.map(|path| path.components().collect()),
                metrics,
                ondemand,
            },
        })
    }

    /// Runs common selection and handoff with FUSE-native resource operations.
    pub fn start(
        self,
        fs: ErofsFs,
        config: &Config,
        shutdown: Arc<AtomicBool>,
    ) -> Result<RunningSession> {
        let frontend = FuseFrontend {
            mountpoint: self.mountpoint,
            info: self.coordinator.info.clone(),
            fs: Some(fs),
            config: config.clone(),
            protected: self.coordinator.holder.is_some(),
            shutdown: shutdown.clone(),
        };
        let session = self.coordinator.start(frontend)?;
        Ok(RunningSession { session, shutdown })
    }
}

struct FuseFrontend {
    mountpoint: PathBuf,
    info: InstanceInfo,
    fs: Option<ErofsFs>,
    config: Config,
    /// Whether a fresh mount is retained by the Recovery Holder.
    protected: bool,
    shutdown: Arc<AtomicBool>,
}

impl Frontend for FuseFrontend {
    type Identity = InstanceInfo;
    type Resource = String;
    type Record = OwnerRecord;
    type Session = FuseService;
    type Control = SessionRuntimeHandle;

    fn check_cancelled(&self) -> Result<()> {
        if self.shutdown.load(Ordering::Relaxed) {
            return Err(Error::Runtime("FUSE startup cancelled".into()));
        }
        Ok(())
    }

    fn inspect(&self) -> Result<Option<String>> {
        match mount_entry_of(&self.mountpoint)? {
            Some((device, kind)) if is_fuse_fstype(&kind) => Ok(Some(device)),
            Some(_) => Err(Error::Runtime(
                "another filesystem occupies the FUSE mountpoint; refusing startup".into(),
            )),
            None => Ok(None),
        }
    }

    fn prepare(&mut self, _peer: &InstanceInfo) -> Result<()> {
        // The caller already prepared ErofsFs; adoption waits for the transferred connection.
        Ok(())
    }

    fn validate_record(
        &self,
        info: &InstanceInfo,
        record: &OwnerRecord,
        device: &String,
    ) -> Result<Option<Uuid>> {
        record.validate(info, device)
    }

    fn validate_fresh(&self, previous: Option<&OwnerRecord>) -> Result<()> {
        if let Some(record) = previous {
            record.ensure_standalone_fresh()?;
        }
        let metadata = std::fs::metadata(&self.mountpoint).with_context(|| {
            format!(
                "failed to inspect fresh mountpoint {}",
                self.mountpoint.display()
            )
        })?;
        if !metadata.is_dir() {
            return Err(Error::InvalidParameter(format!(
                "fresh mountpoint {} must be a directory",
                self.mountpoint.display()
            )));
        }
        Ok(())
    }

    fn open(&mut self, how: Open<OwnerRecord>) -> Result<FuseService> {
        let fs = self
            .fs
            .take()
            .ok_or_else(|| Error::Runtime("FUSE resources were already opened".into()))?;
        match how {
            Open::Fresh if self.protected => {
                FuseService::mount_failover(fs, &self.mountpoint, &self.config)
            }
            Open::Fresh => FuseService::mount(fs, &self.mountpoint, &self.config),
            Open::Adopt {
                transfer: Some(transfer),
                session_id,
                timeout,
                ..
            } => {
                let transfer = SessionTransfer::from_opaque(transfer, session_id, &self.info)?;
                FuseService::adopt(fs, &self.mountpoint, &self.config, transfer, timeout)
            }
            Open::Adopt { transfer: None, .. } => Err(Error::InvalidParameter(
                "FUSE adoption requires a Session Transfer".into(),
            )),
        }
    }

    fn record(&self, info: &InstanceInfo, device: &String, session: &FuseService) -> OwnerRecord {
        OwnerRecord::new(info, device, session.runtime_handle().session_id())
    }

    fn control(session: &FuseService) -> SessionRuntimeHandle {
        session.runtime_handle()
    }

    fn set_owner(session: &mut FuseService, owner: SessionOwner) -> Result<()> {
        session.set_owner(owner)
    }

    fn recover(session: &FuseService) -> Result<()> {
        session.recover_inflight()
    }

    fn activate(session: &FuseService) -> Result<()> {
        session.start_serving();
        Ok(())
    }

    fn stop(session: FuseService) -> Result<()> {
        session.stop_unpublished()
    }
}

/// Retains the API endpoint through FUSE serving and teardown.
pub struct RunningSession {
    session: startup::RunningSession<FuseService>,
    shutdown: Arc<AtomicBool>,
}

impl RunningSession {
    pub fn serve(self) -> Result<()> {
        self.session.serve(|session| {
            session
                .serve(&self.shutdown)
                .context("failed to finish FUSE session")
        })
    }
}

/// Resolves mountpoint aliases to an absolute path for session identity and ownership.
fn normalize_mountpoint(path: &Path) -> Result<PathBuf> {
    let mut path = std::path::absolute(path)?;
    if path.components().any(|part| part == Component::ParentDir) {
        return Err(Error::InvalidParameter(format!(
            "mountpoint {} must not contain '..'",
            path.display()
        )));
    }
    for _ in 0..=MAX_SYMLINK_HOPS {
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return resolve_directory_path(&path);
        };
        let parent = resolve_directory_path(parent)?;
        let resolved = parent.join(name);

        // Use readlink to inspect the final component without stat'ing the mountpoint.
        match std::fs::read_link(&resolved) {
            Ok(target) => path = parent.join(target),
            Err(err)
                if err.raw_os_error() == Some(libc::EINVAL)
                    || err.kind() == std::io::ErrorKind::NotFound =>
            {
                // Defer missing-leaf validation until fresh startup.
                return Ok(resolved);
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("failed to resolve mountpoint {}", resolved.display())
                });
            }
        }
    }
    Err(Error::InvalidParameter(format!(
        "mountpoint {} has too many levels of symbolic links",
        path.display()
    )))
}

/// Returns the resolved absolute path of a directory.
fn resolve_directory_path(path: &Path) -> Result<PathBuf> {
    // Use O_PATH to follow aliases without opening the directory for I/O.
    let directory = std::fs::File::options()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
        .open(path)
        .with_context(|| format!("failed to resolve mountpoint directory {}", path.display()))?;
    std::fs::read_link(format!("/proc/self/fd/{}", directory.as_raw_fd())).with_context(|| {
        format!(
            "failed to read resolved mountpoint directory {}",
            path.display()
        )
    })
}

fn ownership_state_base(mountpoint: &Path) -> Result<PathBuf> {
    let resource = mountpoint.to_str().ok_or_else(|| {
        Error::InvalidParameter("mountpoint must be valid UTF-8 for FUSE session continuity".into())
    })?;
    let base = crate::continuity::ownership::state_base("fuse", resource)?;
    if base
        .parent()
        .is_some_and(|directory| directory.starts_with(mountpoint))
    {
        return Err(Error::InvalidParameter(
            "FUSE ownership state directory must be outside the FUSE mountpoint".into(),
        ));
    }
    Ok(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::continuity::ownership::prepare_state_directory;
    use crate::continuity::test_support::{metrics, ondemand};
    use crate::fuse::upgrade::test_support::empty_filesystem;

    #[test]
    fn startup_validates_mountpoint_and_api_paths() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("absent");
        assert_eq!(
            Startup::new(&absent, None, None, None, metrics(), ondemand())
                .unwrap()
                .mountpoint,
            absent
        );
        assert!(normalize_mountpoint(&dir.path().join("../other")).is_err());
        for mountpoint in ["/", "/run", "/run/nydus", "/run/nydus/fuse"] {
            assert!(Startup::new(
                Path::new(mountpoint),
                None,
                None,
                None,
                metrics(),
                ondemand()
            )
            .is_err());
        }
        assert!(Startup::new(
            dir.path(),
            Some(dir.path().join("api.sock")),
            Some(&[0; 32]),
            None,
            metrics(),
            ondemand()
        )
        .is_err());
        for (api, holder) in [
            (Some(dir.path().join("api.sock")), None),
            (None, Some(dir.path().join("holder.sock"))),
        ] {
            assert!(Startup::new(&absent, api, None, holder, metrics(), ondemand()).is_err());
        }
    }

    #[test]
    fn workers_keep_ownership_and_failed_discovery_cannot_bypass_it() {
        let dir = tempfile::tempdir().unwrap();
        let fs = empty_filesystem();
        let state = dir.path().join("state/session");
        prepare_state_directory(state.parent().unwrap()).unwrap();
        *fs.owner.lock().unwrap() = Some(SessionOwner::acquire(&state, true).unwrap());
        assert!(SessionOwner::acquire(&state, false).is_err());
        for api in [None, Some(dir.path().join("missing-api.sock"))] {
            let mut startup = Startup::new(
                &dir.path().join("absent"),
                api,
                Some(&[0; 32]),
                Some(dir.path().join("missing-holder.sock")),
                metrics(),
                ondemand(),
            )
            .unwrap();
            startup.coordinator.state_base = state.clone();
            let err = startup
                .start(empty_filesystem(), &Config::default(), Arc::default())
                .err()
                .unwrap();
            assert!(err.report().to_string().contains("session ownership"));
        }
        drop(fs);
        assert!(SessionOwner::acquire(&state, false).is_ok());
    }
}
