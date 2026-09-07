use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use fuser::Config;
use nydus_error::{Context, Error, Result};
use tracing::{info, warn};

use super::handoff::{
    begin_handoff, probe_existing_instance, ControlServer, InstanceInfo, ServingInstance,
};
use super::holder::{receive_retained_session_transfer, retain_session_transfer};
use super::STANDALONE_UPGRADE_ERROR;
use crate::fuse::mount::{is_fuse_fstype, mount_fstype_of};
use crate::fuse::{ErofsFs, FuseService};

pub(super) struct StartupLock {
    _file: std::fs::File,
}

fn control_lock_path(control_path: &Path) -> PathBuf {
    let mut lock_path = control_path.as_os_str().to_os_string();
    lock_path.push(".lock");
    PathBuf::from(lock_path)
}

fn normalize_control_socket(control_path: &Path) -> Result<PathBuf> {
    if !control_path.is_absolute() {
        return Err(Error::InvalidParameter(
            "--control-socket must be an absolute path shared by every generation".to_string(),
        ));
    }
    let file_name = control_path.file_name().ok_or_else(|| {
        Error::InvalidParameter("--control-socket must name a socket file".to_string())
    })?;
    let parent = control_path.parent().ok_or_else(|| {
        Error::InvalidParameter("--control-socket must have a parent directory".to_string())
    })?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create control directory {}", parent.display()))?;
    let parent = std::fs::canonicalize(parent).with_context(|| {
        format!(
            "failed to canonicalize control directory {}",
            parent.display()
        )
    })?;
    Ok(parent.join(file_name))
}

impl StartupLock {
    pub(super) fn acquire(control_path: &Path) -> Result<Self> {
        if let Some(parent) = control_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let lock_path = control_lock_path(control_path);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let err = std::io::Error::last_os_error();
            if err
                .raw_os_error()
                .is_some_and(|code| code == libc::EAGAIN || code == libc::EWOULDBLOCK)
            {
                return Err(Error::Runtime(format!(
                    "another process is deciding ownership through control socket {}",
                    control_path.display()
                )));
            }
            return Err(err).with_context(|| format!("failed to lock {}", lock_path.display()));
        }
        Ok(Self { _file: file })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StartupMode {
    Fresh { supervisor_socket: Option<PathBuf> },
    Upgrade,
    Recover { supervisor_socket: PathBuf },
}

impl StartupMode {
    pub fn from_options(
        upgrade: bool,
        recover: bool,
        supervisor_socket: Option<PathBuf>,
    ) -> Result<Self> {
        match (upgrade, recover, supervisor_socket) {
            (false, false, supervisor_socket) => Ok(Self::Fresh { supervisor_socket }),
            // Launchers may carry the Holder path across daemon generations.
            // Upgrade inherits the retained transfer and does not reconnect to it.
            (true, false, _) => Ok(Self::Upgrade),
            (false, true, Some(supervisor_socket)) => Ok(Self::Recover { supervisor_socket }),
            (true, true, _) => Err(Error::InvalidParameter(
                "--upgrade cannot be combined with --recover: hot upgrade and crash recovery are \
                 different FUSE startup modes"
                    .to_string(),
            )),
            (false, true, None) => Err(Error::InvalidParameter(
                "--recover requires --supervisor-socket".to_string(),
            )),
        }
    }

    fn is_recovery(&self) -> bool {
        matches!(self, Self::Recover { .. })
    }
}

pub struct Startup {
    mountpoint: PathBuf,
    socket_path: PathBuf,
    info: InstanceInfo,
    mode: StartupMode,
}

impl Startup {
    pub fn new(
        mountpoint: &Path,
        control_socket: PathBuf,
        image_digest: &[u8],
        mode: StartupMode,
    ) -> Result<Self> {
        let mountpoint = canonicalize_mountpoint(mountpoint, &mode)
            .with_context(|| format!("failed to canonicalize {}", mountpoint.display()))?;
        if !mode.is_recovery() && !mountpoint.is_dir() {
            return Err(Error::InvalidParameter(format!(
                "mountpoint {} is not a directory",
                mountpoint.display()
            )));
        }
        let mountpoint_id = mountpoint.to_str().ok_or_else(|| {
            Error::InvalidParameter(
                "mountpoint must be valid UTF-8 for FUSE session continuity".to_string(),
            )
        })?;
        if control_socket.starts_with(&mountpoint) {
            return Err(Error::InvalidParameter(format!(
                "--control-socket {} must be outside the FUSE mountpoint {}",
                control_socket.display(),
                mountpoint.display()
            )));
        }
        let control_socket = normalize_control_socket(&control_socket)?;
        if control_socket.starts_with(&mountpoint) {
            return Err(Error::InvalidParameter(format!(
                "--control-socket {} must be outside the FUSE mountpoint {}",
                control_socket.display(),
                mountpoint.display()
            )));
        }
        let info = InstanceInfo::new(mountpoint_id, image_digest);
        Ok(Self {
            mountpoint,
            socket_path: control_socket,
            info,
            mode,
        })
    }

    pub fn start(self, fs: ErofsFs, config: &Config) -> Result<RunningSession> {
        let ownership_lock = StartupLock::acquire(&self.socket_path)?;
        let mounted =
            mount_fstype_of(&self.mountpoint).context("failed to inspect the mountpoint")?;
        let existing = probe_existing_instance(&self.socket_path)?;
        let predecessor_serving = validate_existing_instance(&self.mode, existing.as_ref())?;
        if let Some(instance) = existing {
            info!(
                "fuse: taking over from pid {} (version {})",
                instance.info.pid, instance.info.version
            );
        }

        let fuse_mounted = mounted
            .as_ref()
            .is_some_and(|fstype| is_fuse_fstype(fstype));
        validate_mount_state(
            &self.mode,
            predecessor_serving,
            fuse_mounted,
            &self.mountpoint,
            &self.socket_path,
        )?;

        // The control path is the stable coordination key across generations.
        // Keep its sibling lock through probing and binding so two starters
        // using that path cannot both decide they own the session.
        let Self {
            mountpoint,
            socket_path,
            info,
            mode,
        } = self;
        match mode {
            StartupMode::Fresh { supervisor_socket } => Self::start_fresh(
                fs,
                &mountpoint,
                config,
                supervisor_socket,
                socket_path,
                info,
                ownership_lock,
            ),
            StartupMode::Upgrade => {
                Self::start_upgrade(fs, &mountpoint, config, socket_path, info, ownership_lock)
            }
            StartupMode::Recover { supervisor_socket } => Self::start_recover(
                fs,
                &mountpoint,
                config,
                &supervisor_socket,
                socket_path,
                info,
                ownership_lock,
            ),
        }
    }

    /// Creates a new standalone or failover-protected mount. Protected workers
    /// remain parked until the Recovery Holder acknowledges retention.
    fn start_fresh(
        fs: ErofsFs,
        mountpoint: &Path,
        config: &Config,
        supervisor_socket: Option<PathBuf>,
        socket_path: PathBuf,
        info: InstanceInfo,
        ownership_lock: StartupLock,
    ) -> Result<RunningSession> {
        let session = if supervisor_socket.is_some() {
            FuseService::mount_failover(fs, mountpoint, config)?
        } else {
            FuseService::mount(fs, mountpoint, config)?
        };
        let runtime_handle = session.runtime_handle();

        if let Some(supervisor_socket) = supervisor_socket {
            match retain_session_transfer(&supervisor_socket, &info, &runtime_handle) {
                Ok(session_id) => {
                    session.start_serving();
                    info!(
                        session_id = %session_id,
                        supervisor = %supervisor_socket.display(),
                        "fuse: Recovery Holder stored the fresh session transfer"
                    );
                }
                Err(err) => {
                    return stop_unpublished_session(
                        session,
                        err.context("failed to protect the fresh FUSE Session"),
                    );
                }
            }
        }

        let control = match ControlServer::start(&socket_path, info, runtime_handle, ownership_lock)
        {
            Ok(control) => control,
            Err(err) => {
                return stop_unpublished_session(
                    session,
                    err.context(format!(
                        "refusing to serve {} without its control socket",
                        mountpoint.display()
                    )),
                );
            }
        };
        Ok(RunningSession {
            session,
            control: Some(control),
        })
    }

    /// Adopts the predecessor's live connection and publishes a new control
    /// endpoint. Publication failure only prevents another hot upgrade.
    fn start_upgrade(
        fs: ErofsFs,
        mountpoint: &Path,
        config: &Config,
        socket_path: PathBuf,
        info: InstanceInfo,
        ownership_lock: StartupLock,
    ) -> Result<RunningSession> {
        let session = take_over(fs, mountpoint, config, &socket_path, &info)?;
        let control = match ControlServer::start(
            &socket_path,
            info,
            session.runtime_handle(),
            ownership_lock,
        ) {
            Ok(control) => Some(control),
            Err(err) => {
                warn!(
                    "failed to start the control socket at {}; hot upgrade of this \
                     instance will not be possible: {}",
                    socket_path.display(),
                    err.report()
                );
                None
            }
        };
        info!(
            "fuse: took over {} from the previous instance",
            mountpoint.display()
        );
        Ok(RunningSession { session, control })
    }

    /// Restores a Holder-retained session and publishes its control endpoint.
    /// Publication failure preserves the retained mount for another attempt.
    fn start_recover(
        fs: ErofsFs,
        mountpoint: &Path,
        config: &Config,
        supervisor_socket: &Path,
        socket_path: PathBuf,
        info: InstanceInfo,
        ownership_lock: StartupLock,
    ) -> Result<RunningSession> {
        let transfer = receive_retained_session_transfer(supervisor_socket, &info)?;
        let session = FuseService::recover(fs, mountpoint, config, transfer)?;
        let control = match ControlServer::start(
            &socket_path,
            info,
            session.runtime_handle(),
            ownership_lock,
        ) {
            Ok(control) => control,
            Err(err) => {
                return abort_adoption(
                    session,
                    err.context("failed to start the recovery control endpoint"),
                );
            }
        };
        info!("fuse: recovered session is serving through the instance control endpoint");
        Ok(RunningSession {
            session,
            control: Some(control),
        })
    }
}

pub struct RunningSession {
    session: FuseService,
    control: Option<ControlServer>,
}

impl RunningSession {
    pub fn serve(self) -> Result<std::io::Result<()>> {
        let Self { session, control } = self;
        let result = session.serve();
        drop(control);
        result
    }
}

fn canonicalize_mountpoint(path: &Path, mode: &StartupMode) -> std::io::Result<PathBuf> {
    if mode.is_recovery() {
        if path.is_absolute() {
            return Ok(path.to_path_buf());
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "recovery mountpoint must be the absolute canonical path recorded at fresh readiness",
        ));
    }
    std::fs::canonicalize(path)
}

fn validate_existing_instance(
    mode: &StartupMode,
    existing: Option<&ServingInstance>,
) -> Result<bool> {
    match (mode, existing) {
        (StartupMode::Upgrade, Some(instance)) if instance.is_failover_protected() => Ok(true),
        (StartupMode::Upgrade, Some(_)) => {
            Err(Error::Runtime(STANDALONE_UPGRADE_ERROR.to_string()))
        }
        (StartupMode::Upgrade, None) => Err(Error::Runtime(
            "--upgrade requested but no existing instance is listening".to_string(),
        )),
        (StartupMode::Recover { .. }, Some(instance)) => Err(Error::Runtime(format!(
            "--recover requested but instance pid {} is still serving {}",
            instance.info.pid, instance.info.mountpoint
        ))),
        (StartupMode::Fresh { .. }, Some(instance)) => Err(Error::Runtime(format!(
            "an instance (pid {}, version {}) is already serving {}; pass --upgrade to take over",
            instance.info.pid, instance.info.version, instance.info.mountpoint
        ))),
        (_, None) => Ok(false),
    }
}

fn validate_mount_state(
    mode: &StartupMode,
    predecessor_serving: bool,
    fuse_mounted: bool,
    mountpoint: &Path,
    socket_path: &Path,
) -> Result<()> {
    if predecessor_serving && !fuse_mounted {
        return Err(Error::Runtime(format!(
            "--upgrade requested but no fuse filesystem is mounted at {}",
            mountpoint.display()
        )));
    }
    if mode.is_recovery() && !fuse_mounted {
        return Err(Error::Runtime(format!(
            "--recover requested but no fuse filesystem is mounted at {}",
            mountpoint.display()
        )));
    }
    if !predecessor_serving && fuse_mounted && !mode.is_recovery() {
        return Err(Error::Runtime(format!(
            "a fuse mount already exists at {} but nothing answers its control socket {}; \
             unmount it before restarting",
            mountpoint.display(),
            socket_path.display()
        )));
    }
    Ok(())
}

fn take_over(
    fs: ErofsFs,
    mountpoint: &Path,
    config: &Config,
    socket_path: &Path,
    info: &InstanceInfo,
) -> Result<FuseService> {
    let mut handoff = begin_handoff(socket_path, info)?;
    let timeout = handoff.remaining()?;
    let transfer = handoff.take_transfer();
    let session = match FuseService::adopt(fs, mountpoint, config, transfer, timeout) {
        Ok(session) => session,
        Err(err) => {
            drop(handoff);
            return Err(err);
        }
    };

    if let Err(err) = handoff.commit() {
        warn!("fuse: handoff aborted: {}", err.report());
        session.abort_adoption()?;
        return Err(err).context("fuse hot upgrade aborted");
    }
    session.start_serving();
    info!("fuse: took over the live session at {}", info.mountpoint);
    Ok(session)
}

fn abort_adoption(session: FuseService, cause: Error) -> Result<RunningSession> {
    match session.abort_adoption() {
        Ok(()) => Err(cause).context("fuse recovery successor stood down"),
        Err(cleanup) => Err(Error::Runtime(format!(
            "{}; failed to stand down the recovery successor: {}",
            cause.report(),
            cleanup.report()
        ))),
    }
}

fn stop_unpublished_session(session: FuseService, cause: Error) -> Result<RunningSession> {
    match session.shutdown_unpublished() {
        Ok(()) => Err(cause).context("unpublished FUSE session stopped"),
        Err(cleanup) => Err(Error::Runtime(format!(
            "{}; failed to stop unpublished FUSE session: {}",
            cause.report(),
            cleanup.report()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_is_control_path_scoped() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("nested").join("first.sock");
        let second = dir.path().join("second.sock");

        let _held = StartupLock::acquire(&first).unwrap();
        assert!(control_lock_path(&first).is_file());
        assert!(StartupLock::acquire(&first).is_err());
        assert!(StartupLock::acquire(&second).is_ok());
    }

    #[test]
    fn startup_rejects_a_relative_control_path() {
        let mountpoint = tempfile::tempdir().unwrap();
        let mode = StartupMode::Fresh {
            supervisor_socket: None,
        };
        let error = Startup::new(
            mountpoint.path(),
            PathBuf::from("control.sock"),
            &[0; 32],
            mode,
        )
        .err()
        .expect("relative control path must be rejected");
        assert!(error.report().to_string().contains("absolute path"));
    }

    #[test]
    fn startup_normalizes_the_control_socket_parent() {
        let mountpoint = tempfile::tempdir().unwrap();
        let control_dir = tempfile::tempdir().unwrap();
        let nested = control_dir.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let spelled = nested.join("..").join("control.sock");
        let expected = control_dir.path().join("control.sock");
        let mode = StartupMode::Fresh {
            supervisor_socket: None,
        };

        let first =
            Startup::new(mountpoint.path(), expected.clone(), &[0; 32], mode.clone()).unwrap();
        let second = Startup::new(mountpoint.path(), spelled, &[0; 32], mode).unwrap();
        assert_eq!(first.socket_path, expected);
        assert_eq!(second.socket_path, expected);

        let _held = StartupLock::acquire(&first.socket_path).unwrap();
        assert!(StartupLock::acquire(&second.socket_path).is_err());
    }

    #[test]
    fn startup_rejects_a_control_socket_inside_the_mountpoint() {
        let mountpoint = tempfile::tempdir().unwrap();
        let mode = StartupMode::Fresh {
            supervisor_socket: None,
        };
        let error = Startup::new(
            mountpoint.path(),
            mountpoint.path().join("control.sock"),
            &[0; 32],
            mode,
        )
        .err()
        .expect("a control socket hidden by the FUSE mount must be rejected");
        assert!(error.report().to_string().contains("outside"));
    }

    #[test]
    fn startup_mode_rejects_mixed_upgrade_options() {
        let supervisor = PathBuf::from("/run/nydus/supervisor.sock");
        assert_eq!(
            StartupMode::from_options(false, false, None).unwrap(),
            StartupMode::Fresh {
                supervisor_socket: None
            }
        );
        assert_eq!(
            StartupMode::from_options(false, false, Some(supervisor.clone())).unwrap(),
            StartupMode::Fresh {
                supervisor_socket: Some(supervisor.clone())
            }
        );
        assert_eq!(
            StartupMode::from_options(true, false, None).unwrap(),
            StartupMode::Upgrade
        );
        assert_eq!(
            StartupMode::from_options(false, true, Some(supervisor.clone())).unwrap(),
            StartupMode::Recover {
                supervisor_socket: supervisor.clone()
            }
        );
        assert_eq!(
            StartupMode::from_options(true, false, Some(supervisor.clone())).unwrap(),
            StartupMode::Upgrade
        );
        assert!(StartupMode::from_options(true, true, Some(supervisor)).is_err());
        assert!(StartupMode::from_options(false, true, None).is_err());
    }

    #[test]
    fn upgrade_rejects_standalone_and_accepts_protected_sessions() {
        let info = InstanceInfo::new("/mnt/img", &[1; 32]);
        let standalone = ServingInstance {
            info: info.clone(),
            session_id: None,
        };
        let protected = ServingInstance {
            info,
            session_id: Some(uuid::Uuid::from_u128(7)),
        };

        let error = validate_existing_instance(&StartupMode::Upgrade, Some(&standalone))
            .expect_err("Standalone Session upgrade must be rejected");
        assert!(error.report().to_string().contains("Standalone Session"));
        assert!(validate_existing_instance(&StartupMode::Upgrade, Some(&protected)).unwrap());
    }

    #[test]
    fn crash_recovery_uses_the_supervisor_supplied_canonical_mountpoint_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let mountpoint = dir.path().join("unresponsive-fuse-mount");
        let symlink = dir.path().join("mountpoint-link");
        std::os::unix::fs::symlink(&mountpoint, &symlink).unwrap();
        let recovery = StartupMode::Recover {
            supervisor_socket: PathBuf::from("/run/nydus/supervisor.sock"),
        };

        assert_eq!(
            canonicalize_mountpoint(&mountpoint, &recovery).unwrap(),
            mountpoint
        );
        assert_eq!(
            canonicalize_mountpoint(&symlink, &recovery).unwrap(),
            symlink
        );
        assert!(canonicalize_mountpoint(Path::new("relative-mountpoint"), &recovery).is_err());
        assert!(canonicalize_mountpoint(
            &mountpoint,
            &StartupMode::Fresh {
                supervisor_socket: None
            }
        )
        .is_err());
    }
}
