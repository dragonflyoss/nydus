use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use fuser::Config;
use nydus_error::{Context, Error, Result};
use nydus_telemetry::metrics::ImageMetrics;
use uuid::Uuid;

use super::identity::InstanceInfo;
use super::lifecycle::SessionRuntimeHandle;
use super::ownership::{OwnerRecord, SessionOwner};
use super::transfer::SessionTransfer;
use crate::continuity::startup::{self, Frontend, Open};
use crate::fuse::mount::{is_fuse_fstype, mount_entry_of};
use crate::fuse::{ErofsFs, FuseService};

/// FUSE-specific startup identity and path validation.
pub struct Startup {
    mountpoint: PathBuf,
    coordinator: startup::Startup<InstanceInfo>,
}

impl Startup {
    /// Validates the endpoint without accessing a potentially stalled mount.
    pub fn new(
        mountpoint: &Path,
        api_socket: Option<PathBuf>,
        image_digest: &[u8],
        metrics: Arc<ImageMetrics>,
    ) -> Result<Self> {
        let mountpoint = normalize_mountpoint(mountpoint)?;
        let mountpoint_id = mountpoint.to_str().ok_or_else(|| {
            Error::InvalidParameter(
                "mountpoint must be valid UTF-8 for FUSE session continuity".into(),
            )
        })?;
        let state_base = ownership_state_base(&mountpoint)?;
        startup::validate_socket_paths(api_socket.as_deref(), None, Some(&mountpoint))?;
        let info = InstanceInfo::new(mountpoint_id, image_digest);
        Ok(Self {
            mountpoint,
            coordinator: startup::Startup {
                info,
                state_base,
                holder: None,
                api_socket: api_socket.map(|path| path.components().collect()),
                metrics,
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
        record.validate(info, device)?;
        Ok(None)
    }

    fn validate_fresh(&self, _previous: Option<&OwnerRecord>) -> Result<()> {
        validate_fresh_mountpoint(&self.mountpoint)
    }

    fn open(&mut self, how: Open<OwnerRecord>) -> Result<FuseService> {
        let fs = self
            .fs
            .take()
            .ok_or_else(|| Error::Runtime("FUSE resources were already opened".into()))?;
        match how {
            Open::Fresh => FuseService::mount(fs, &self.mountpoint, &self.config),
            Open::Adopt {
                transfer: Some(transfer),
                timeout,
                ..
            } => {
                let transfer = SessionTransfer::from_opaque(transfer, &self.info)?;
                FuseService::adopt(fs, &self.mountpoint, &self.config, transfer, timeout)
            }
            Open::Adopt { transfer: None, .. } => Err(Error::InvalidParameter(
                "FUSE adoption requires a Session Transfer".into(),
            )),
        }
    }

    fn record(&self, info: &InstanceInfo, device: &String, _session: &FuseService) -> OwnerRecord {
        OwnerRecord::new(info, device)
    }

    fn control(session: &FuseService) -> SessionRuntimeHandle {
        session.runtime_handle()
    }

    fn set_owner(session: &mut FuseService, owner: SessionOwner) -> Result<()> {
        session.set_owner(owner)
    }

    fn recover(_session: &FuseService) -> Result<()> {
        Err(Error::Runtime(
            "FUSE adoption requires a live session transfer".into(),
        ))
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

fn normalize_mountpoint(path: &Path) -> Result<PathBuf> {
    let path = std::path::absolute(path)?;
    if path.components().any(|part| part == Component::ParentDir) {
        return Err(Error::InvalidParameter(
            "mountpoint must use its canonical path without '..'".into(),
        ));
    }
    Ok(path.components().collect())
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

fn validate_fresh_mountpoint(path: &Path) -> Result<()> {
    if std::fs::canonicalize(path)? != path || !path.is_dir() {
        return Err(Error::InvalidParameter(
            "fresh mountpoint must be a directory at its canonical path".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::continuity::ownership::prepare_state_directory;
    use crate::continuity::test_support::metrics;
    use crate::fuse::upgrade::test_support::empty_filesystem;

    #[test]
    fn startup_does_not_access_the_mount_and_fresh_paths_must_be_canonical() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("absent");
        assert_eq!(
            Startup::new(&absent, None, &[0; 32], metrics())
                .unwrap()
                .mountpoint,
            absent
        );
        assert!(validate_fresh_mountpoint(&absent).is_err());
        validate_fresh_mountpoint(dir.path()).unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(dir.path(), &alias).unwrap();
        assert!(validate_fresh_mountpoint(&alias).is_err());
        assert!(normalize_mountpoint(&dir.path().join("../other")).is_err());
        for mountpoint in ["/", "/tmp"] {
            assert!(Startup::new(Path::new(mountpoint), None, &[0; 32], metrics()).is_err());
        }
        assert!(Startup::new(
            dir.path(),
            Some(dir.path().join("api.sock")),
            &[0; 32],
            metrics()
        )
        .is_err());
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
            let mut startup =
                Startup::new(&dir.path().join("absent"), api, &[0; 32], metrics()).unwrap();
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
