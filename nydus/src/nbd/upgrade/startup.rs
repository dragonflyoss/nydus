use nydus_core::NydusCore;
use nydus_error::{Context, Error, Result};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::info;
use uuid::Uuid;

use super::identity::InstanceInfo;
use super::lifecycle::{NativeSession, NbdControl, Origin};
use super::ownership::{kernel_resource, OwnerRecord, Resource, JSON_FORMAT_VERSION};
use crate::continuity::ownership::{state_base, SessionOwner};
use crate::continuity::startup::{self, Frontend, Open};
use crate::continuity::wire::Transfer;
use crate::mount::table::mount_entry_of;
use crate::nbd::netlink;
use crate::nbd::service::{NbdOptions, NbdSession, POLL_INTERVAL};
use crate::nbd::{mount_nbd, NbdCore};
use crate::pool::FetchPool;

/// The NBD startup that selects fresh attach, live handoff or crash recovery through shared continuity.
pub struct Startup {
    /// The resolved device node.
    node: String,

    /// The `/dev/nbd<N>` index.
    index: u32,

    /// The `major:minor` of the device.
    mount_dev: String,

    /// The settings for a fresh session.
    options: NbdOptions,

    /// The shared continuity startup.
    coordinator: startup::Startup<InstanceInfo>,
}

/// Implements the NBD startup.
impl Startup {
    /// Resolves the device and validates paths for startup coordination, keeping ownership
    /// state under `runtime_dir`.
    pub fn new(
        device: &Path,
        mountpoint: Option<&Path>,
        runtime_dir: &Path,
        api_socket: Option<PathBuf>,
        options: NbdOptions,
        core: &NydusCore,
    ) -> Result<Self> {
        options.validate()?;
        let device = std::fs::canonicalize(device)
            .with_context(|| format!("failed to resolve NBD device {}", device.display()))?;
        let node = device
            .to_str()
            .ok_or_else(|| {
                Error::InvalidParameter(format!(
                    "NBD device path {} must be UTF-8",
                    device.display()
                ))
            })?
            .to_string();
        let metadata = std::fs::metadata(&device)
            .with_context(|| format!("failed to inspect NBD device {node}"))?;
        let index = device
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix("nbd"))
            .filter(|index| !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|index| index.parse::<u32>().ok())
            .ok_or_else(|| {
                Error::InvalidParameter(format!("NBD device {node} must name /dev/nbd<N>"))
            })?;
        if metadata.mode() & libc::S_IFMT != libc::S_IFBLK {
            return Err(Error::InvalidParameter(format!(
                "NBD device {node} is not a block device"
            )));
        }
        let mount_dev = format!(
            "{}:{}",
            libc::major(metadata.rdev()),
            libc::minor(metadata.rdev())
        );
        let kernel_dev = std::fs::read_to_string(format!("/sys/block/nbd{index}/dev"))
            .with_context(|| format!("failed to identify the kernel device nbd{index}"))?;
        if kernel_dev.trim() != mount_dev {
            return Err(Error::InvalidParameter(format!(
                "NBD device node {node} does not match the kernel device nbd{index}"
            )));
        }
        let resource = format!("/dev/nbd{index}");
        let mountpoint = mountpoint.map(normalize_mountpoint).transpose()?;
        let state = state_base(runtime_dir, "nbd", &resource)?;
        if let Some(path) = mountpoint
            .as_ref()
            .filter(|path| state.parent().is_some_and(|dir| dir.starts_with(path)))
        {
            return Err(Error::InvalidParameter(format!(
                "NBD ownership state {} must be outside the mountpoint {}",
                state.display(),
                path.display()
            )));
        }
        startup::validate_socket_paths(api_socket.as_deref(), None, mountpoint.as_deref())?;
        let info = InstanceInfo {
            pid: std::process::id(),
            version: env!("CARGO_PKG_VERSION").into(),
            device: resource,
            image_digest: hex::encode(core.image_digest()),
            mountpoint,
        };
        Ok(Self {
            node,
            index,
            mount_dev,
            options,
            coordinator: startup::Startup {
                info,
                api_socket,
                state_base: state,
                holder: None,
                metrics: core.metrics().clone(),
                ondemand: core.ondemand_recorder().clone(),
            },
        })
    }

    /// Attaches, takes over or recovers the session on the device, serving reads on `pool`.
    ///
    /// Setting `stop` cancels the startup at its next safe boundary. A cancelled startup tears
    /// down only a session it created: until this daemon reports ready the predecessor keeps
    /// or resumes serving, and an adopted session stays retained for the next daemon to
    /// recover.
    pub fn start(
        self,
        core: Arc<NbdCore>,
        pool: Arc<FetchPool>,
        stop: Arc<AtomicBool>,
    ) -> Result<RunningSession> {
        let frontend = NbdFrontend {
            node: self.node,
            index: self.index,
            mount_dev: self.mount_dev,
            core,
            info: self.coordinator.info.clone(),
            options: self.options,
            pool,
            stop,
        };
        self.coordinator.start(frontend).map(RunningSession)
    }
}

/// The NBD adapter of shared continuity.
struct NbdFrontend {
    /// The resolved device node.
    node: String,

    /// The `/dev/nbd<N>` index.
    index: u32,

    /// The `major:minor` of the device.
    mount_dev: String,

    /// The image the workers serve.
    core: Arc<NbdCore>,

    /// The identity of this daemon.
    info: InstanceInfo,

    /// The settings for a fresh session.
    options: NbdOptions,

    /// The threads that serve reads.
    pool: Arc<FetchPool>,

    /// Whether a termination signal arrived.
    stop: Arc<AtomicBool>,
}

/// Implements the NBD session setup.
impl NbdFrontend {
    /// Creates the worker pool of the session a record describes.
    fn session(&self, record: &OwnerRecord) -> Result<NbdSession> {
        NbdSession::new(
            self.core.clone(),
            self.pool.clone(),
            self.index,
            record.options.clone(),
            record.resource().backend,
        )
    }

    /// Creates a fresh kernel session.
    fn connect(&self) -> Result<NativeSession> {
        let record = OwnerRecord {
            version: JSON_FORMAT_VERSION,
            device: self.info.device.clone(),
            image_digest: self.info.image_digest.clone(),
            mountpoint: self.info.mountpoint.clone(),
            session_id: Uuid::new_v4(),
            bytes: self.core.device_size(),
            options: self.options.clone(),
        };
        let mut pool = self.session(&record)?;
        let connected = pool.connect(record.bytes);

        // Let the kernel's view decide: an interrupted ACK can hide a successful CONNECT,
        // and a kernel that cannot report the backend identity leaves a session no
        // successor could adopt.
        let inspected = self.inspect();
        let identified = matches!(&inspected, Ok(Some(resource)) if *resource == record.resource());
        if connected.is_ok() && identified {
            return Ok(NativeSession::new(
                pool,
                record,
                self.node.clone(),
                self.mount_dev.clone(),
                Origin::Fresh,
            ));
        }
        let undone = if connected.is_ok() || identified {
            netlink::disconnect_device(self.index)
        } else {
            Ok(())
        };
        let err = connected.err().or(inspected.err()).unwrap_or_else(|| {
            Error::Runtime(format!(
                "the NBD session on {} lacks the backend identity just registered",
                record.device
            ))
        });
        Err(match undone {
            Ok(()) => err,
            Err(undo) => err.context(format!("NBD cleanup also failed: {}", undo.report())),
        })
    }

    /// Takes over the connections a live predecessor parked for the handoff.
    ///
    /// The connections stay parked until activation: the predecessor may still resume them
    /// until it is told that this daemon is ready.
    fn take_over(&self, transfer: Transfer) -> Result<NativeSession> {
        let record: OwnerRecord =
            serde_json::from_slice(&transfer.metadata).context("invalid NBD session transfer")?;
        let resource = self.inspect()?.ok_or_else(|| {
            Error::Runtime(format!(
                "{} has no kernel session to take over",
                self.info.device
            ))
        })?;
        self.validate_record(&self.info, &record, &resource)?;
        if record.options != self.options {
            info!("nbd: inheriting recorded connection count and timeouts");
        }
        let mut pool = self.session(&record)?;
        pool.adopt(transfer.fds)?;
        info!(
            "nbd: took over the connections of the session on {}",
            record.device
        );
        Ok(NativeSession::new(
            pool,
            record,
            self.node.clone(),
            self.mount_dev.clone(),
            Origin::Adopted,
        ))
    }

    /// Attaches fresh connections to every slot of the kernel session a crashed daemon left.
    fn adopt(&self, record: OwnerRecord, deadline: Instant) -> Result<NativeSession> {
        if record.options != self.options {
            info!("nbd: inheriting recorded connection count and timeouts");
        }
        let mut pool = self.session(&record)?;
        let mut missing = record.options.connections;
        loop {
            missing -= pool.attach(missing).map_err(|err| {
                if err.io_error().and_then(io::Error::raw_os_error) == Some(libc::EINVAL) {
                    err.context(format!(
                        "the kernel no longer accepts connections for {}; if the session was disconnected, unmount its filesystem before starting nydus again",
                        record.device
                    ))
                } else {
                    err
                }
            })?;
            if missing == 0 {
                break;
            }
            if Instant::now() >= deadline {
                return Err(Error::Runtime(format!(
                    "kernel did not accept all NBD replacement connections on {}",
                    record.device
                )));
            }

            // Retry the slots the kernel has not retired yet.
            std::thread::sleep(POLL_INTERVAL);
        }
        info!("nbd: attached to the retained session on {}", record.device);
        Ok(NativeSession::new(
            pool,
            record,
            self.node.clone(),
            self.mount_dev.clone(),
            Origin::Adopted,
        ))
    }
}

/// Implements the NBD continuity frontend.
impl Frontend for NbdFrontend {
    /// The identity of an NBD daemon.
    type Identity = InstanceInfo;

    /// The kernel session.
    type Resource = Resource;

    /// The ownership record.
    type Record = OwnerRecord;

    /// The served session.
    type Session = NativeSession;

    /// The control a live predecessor exposes.
    type Control = NbdControl;

    /// Fails once a termination signal arrived, so a startup stops at its next safe boundary.
    fn check_cancelled(&self) -> Result<()> {
        if self.stop.load(Ordering::Acquire) {
            return Err(Error::Runtime("NBD startup cancelled by a signal".into()));
        }
        Ok(())
    }

    /// Returns the kernel session on the device, if any.
    fn inspect(&self) -> Result<Option<Resource>> {
        kernel_resource(Path::new("/sys/block"), self.index)
    }

    /// Prepares nothing: the connections arrive with the predecessor's transfer.
    fn prepare(&mut self, _peer: &InstanceInfo) -> Result<()> {
        Ok(())
    }

    /// Checks the record against the kernel session, the mount and the opened image.
    fn validate_record(
        &self,
        info: &InstanceInfo,
        record: &OwnerRecord,
        resource: &Resource,
    ) -> Result<Option<Uuid>> {
        let session_id = record.validate(info, resource)?;
        if resource.bytes != self.core.device_size() {
            return Err(Error::Runtime(format!(
                "the kernel capacity of {} differs from the opened image",
                info.device
            )));
        }
        check_mount(
            info.mountpoint.as_deref(),
            &info.device,
            &self.mount_dev,
            true,
        )?;
        Ok(session_id)
    }

    /// Checks that the mountpoint is free and canonical for a fresh session.
    fn validate_fresh(&self, _previous: Option<&OwnerRecord>) -> Result<()> {
        check_mount(
            self.info.mountpoint.as_deref(),
            &self.info.device,
            &self.mount_dev,
            false,
        )?;
        if let Some(path) = &self.info.mountpoint {
            let resolved = std::fs::canonicalize(path)
                .with_context(|| format!("failed to resolve NBD mountpoint {}", path.display()))?;
            if resolved != *path || !path.is_dir() {
                return Err(Error::InvalidParameter(format!(
                    "NBD mountpoint {} must be a directory named without symlinks",
                    path.display()
                )));
            }
        }
        Ok(())
    }

    /// Creates a fresh session, takes over a live predecessor's connections or reattaches
    /// to the session a crashed daemon left.
    ///
    /// Connections taken over stay parked until activation. Reattached ones, unlike the
    /// inactive adoption the shared [`Frontend`] contract asks for, serve as soon as the
    /// kernel accepts them: no daemon serves the session any more, the caller holds
    /// lifetime ownership, and the kernel only attaches sockets that carry the backend
    /// identity of the validated session.
    fn open(&mut self, how: Open<OwnerRecord>) -> Result<NativeSession> {
        match how {
            Open::Fresh => self.connect(),
            Open::Adopt {
                transfer: Some(transfer),
                ..
            } => self.take_over(transfer),
            Open::Adopt {
                transfer: None,
                record: Some(record),
                timeout,
                ..
            } => self.adopt(record, Instant::now() + timeout),
            Open::Adopt { .. } => Err(Error::InvalidParameter(
                "NBD adoption requires a session transfer or the recorded kernel session".into(),
            )),
        }
    }

    /// Returns the record of the opened session.
    fn record(
        &self,
        _info: &InstanceInfo,
        _resource: &Resource,
        session: &NativeSession,
    ) -> OwnerRecord {
        session.control.record.clone()
    }

    /// Returns the control of the opened session.
    fn control(session: &NativeSession) -> NbdControl {
        session.control.clone()
    }

    /// Hands lifetime ownership to the session, which holds it until its workers exit.
    fn set_owner(session: &mut NativeSession, owner: SessionOwner) -> Result<()> {
        *session.control.service.owner.lock().unwrap() = Some(owner);
        Ok(())
    }

    /// Logs a crash recovery; opening already restored the session.
    fn recover(_session: &NativeSession) -> Result<()> {
        info!("nbd: recovered the kernel session a crashed daemon left");
        Ok(())
    }

    /// Mounts a fresh session and lets the connections taken over serve; an adopted session
    /// keeps its mount.
    fn activate(session: &NativeSession) -> Result<()> {
        let record = &session.control.record;
        if let (Origin::Fresh, Some(path)) = (session.origin, &record.mountpoint) {
            check_mount(Some(path), &record.device, &session.mount_dev, false)?;
            mount_nbd(&session.node, path, "erofs")?;
            info!("mounted {} at {}", session.node, path.display());
        }
        session.control.service.resume()?;
        info!(
            "nydus nbd service attached to {} ({} connections)",
            record.device, record.options.connections
        );
        Ok(())
    }

    /// Tears down a fresh session or lets go of the connections of an adopted one.
    ///
    /// The connections taken over from a predecessor that resumes serving must stay open.
    fn stop(mut session: NativeSession) -> Result<()> {
        match session.origin {
            Origin::Fresh => session.shutdown(),
            Origin::Adopted => session.pool.detach(),
        }
    }
}

/// The started NBD session that retains both native resources and the shared control endpoint.
pub struct RunningSession(startup::RunningSession<NativeSession>);

/// Implements the started NBD session.
impl RunningSession {
    /// Serves until `stop` is set, keeping the control endpoint published.
    pub fn serve(self, stop: Arc<AtomicBool>) -> Result<()> {
        self.0.serve(|session| session.serve(stop))
    }
}

/// Returns the absolute mountpoint, rejecting `..` components.
fn normalize_mountpoint(path: &Path) -> Result<PathBuf> {
    let path = std::path::absolute(path)?;
    if path.components().any(|part| part == Component::ParentDir) {
        return Err(Error::InvalidParameter(format!(
            "NBD mountpoint {} must not contain '..'",
            path.display()
        )));
    }
    Ok(path.components().collect())
}

/// Checks that nothing is mounted at the mountpoint, or with `existing` that the EROFS
/// filesystem of `device`, whose `major:minor` is `mount_dev`, is.
fn check_mount(path: Option<&Path>, device: &str, mount_dev: &str, existing: bool) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let path = match (mount_entry_of(path)?, existing) {
        (None, false) => return Ok(()),
        (Some((mounted, kind)), true) if mounted == mount_dev && kind == "erofs" => return Ok(()),
        _ => path.display(),
    };
    Err(Error::Runtime(if existing {
        format!(
            "NBD mountpoint {path} does not hold the filesystem of the NBD session on {device}; to discard the session, unmount its filesystem and run `nbd-client -d {device}`"
        )
    } else {
        format!(
            "NBD mountpoint {path} is already a mountpoint; unmount it or choose another directory"
        )
    }))
}
