use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use nydus_error::{Context, Error, Result};
use nydus_telemetry::metrics::ImageMetrics;
use serde::{de::DeserializeOwned, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use super::handoff::{self, ControlServer, Handoff, SessionControl};
use super::ownership::{lock_startup, prepare_state_directory, SessionOwner};
use super::wire::Transfer;
use super::{holder, Identity, Mode, HANDOFF_TIMEOUT};

pub enum Open<R> {
    Fresh,
    /// `transfer` is present only in [`Mode::Transfer`]; `record` is absent while a live
    /// predecessor still owns it.
    Adopt {
        transfer: Option<Transfer>,
        record: Option<R>,
        session_id: Option<Uuid>,
        timeout: Duration,
    },
}

/// The startup-side native operations. Opened sessions must not activate adopted resources.
/// `prepare` is reversible and runs before asking a live predecessor to release anything.
pub trait Frontend {
    type Identity: Identity;
    type Resource: Eq;
    type Record: Serialize + DeserializeOwned;
    type Session;
    type Control: SessionControl<Identity = Self::Identity>;

    /// Checks cancellation at safe boundaries; it never grants resource ownership.
    fn check_cancelled(&self) -> Result<()> {
        Ok(())
    }
    /// Inspects native identity without requiring a responsive serving process.
    fn inspect(&self) -> Result<Option<Self::Resource>>;
    fn prepare(&mut self, peer: &Self::Identity) -> Result<()>;
    /// Checks that the record describes `resource` and returns its session ID.
    fn validate_record(
        &self,
        info: &Self::Identity,
        record: &Self::Record,
        resource: &Self::Resource,
    ) -> Result<Option<Uuid>>;
    fn validate_fresh(&self, previous: Option<&Self::Record>) -> Result<()>;
    /// Leaves adopted workers inactive and cleans up any partial native setup on error.
    fn open(&mut self, how: Open<Self::Record>) -> Result<Self::Session>;
    fn record(
        &self,
        info: &Self::Identity,
        resource: &Self::Resource,
        session: &Self::Session,
    ) -> Self::Record;
    fn control(session: &Self::Session) -> Self::Control;
    /// Attaches the guard to workers and teardown, not just to the controller.
    fn set_owner(session: &mut Self::Session, owner: SessionOwner) -> Result<()>;
    /// Recovers inflight state while the session owns the resource but remains inactive.
    fn recover(session: &Self::Session) -> Result<()>;
    fn activate(session: &Self::Session) -> Result<()>;
    /// Stops an unpublished session, destroying fresh resources but preserving adopted ones.
    fn stop(session: Self::Session) -> Result<()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Fresh,
    Upgrade,
    Recovery,
}

/// Coordinates one frontend resource without interpreting its native identity or record.
pub struct Startup<I> {
    pub info: I,
    pub api_socket: Option<PathBuf>,
    pub state_base: PathBuf,
    /// The Recovery Holder that protects a [`Mode::Transfer`] session against crashes.
    pub holder: Option<PathBuf>,
    /// Served at `/metrics` on the API socket alongside control.
    pub metrics: Arc<ImageMetrics>,
}

impl<I: Identity> Startup<I> {
    pub fn start<F: Frontend<Identity = I>>(
        self,
        mut frontend: F,
    ) -> Result<RunningSession<F::Session>> {
        frontend.check_cancelled()?;
        if self.holder.is_some() && I::MODE != Mode::Transfer {
            return Err(Error::InvalidParameter(
                "a Recovery Holder requires transfer handoff".into(),
            ));
        }
        validate_socket_paths(self.api_socket.as_deref(), self.holder.as_deref(), None)?;
        let directory = self.state_base.parent().ok_or_else(|| {
            Error::InvalidParameter("ownership state must have a parent directory".into())
        })?;
        prepare_state_directory(directory)?;
        let startup_lock = lock_startup(&self.state_base)?;
        if let Some(parent) = self.api_socket.as_ref().and_then(|path| path.parent()) {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create API directory {}", parent.display()))?;
        }
        let mounted = frontend.inspect()?;
        let peer = self
            .api_socket
            .as_deref()
            .map(|path| handoff::probe(path, &self.info))
            .transpose()?
            .flatten();
        let handoff = match peer {
            Some(peer) => {
                // Read-only checks precede HANDOFF_BEGIN, the kernel mode's point of no return.
                let resource = mounted.ok_or_else(|| {
                    Error::Runtime("live instance has no matching resource".into())
                })?;
                let record = SessionOwner::peek(&self.state_base)?;
                if frontend.validate_record(&self.info, &record, &resource)? != peer.session_id {
                    return Err(Error::Runtime(
                        "live instance does not match the recorded session".into(),
                    ));
                }
                frontend.prepare(&peer.info)?;
                frontend.check_cancelled()?;
                let session_id = peer.session_id;
                peer.begin(&self.info)?
                    .map(|handoff| (handoff, (resource, record, session_id)))
            }
            None => None,
        };
        let (session, kind) = match handoff {
            Some((handoff, recorded)) => {
                self.adopt_from_predecessor(&mut frontend, handoff, recorded)?
            }
            None => self.start_without_predecessor(&mut frontend)?,
        };
        if let Err(err) = frontend
            .check_cancelled()
            .and_then(|()| F::activate(&session))
        {
            return stop_failed_session::<F, _>(session, err);
        }
        let control = match &self.api_socket {
            Some(path) => {
                match ControlServer::start(path, self.info, F::control(&session), self.metrics) {
                    Ok(control) => Some(control),
                    Err(err) if kind == Kind::Upgrade => {
                        warn!("handoff completed but API publication at {} failed; continuing without API: {}", path.display(), err.report());
                        None
                    }
                    Err(err) => {
                        return stop_failed_session::<F, _>(
                            session,
                            err.context("failed to publish the API endpoint"),
                        )
                    }
                }
            }
            None => None,
        };
        drop(startup_lock);
        info!(?kind, "session startup complete");
        Ok(RunningSession { session, control })
    }

    /// The record was validated before HANDOFF_BEGIN; after the point of no return only the owner wait remains.
    fn adopt_from_predecessor<F: Frontend<Identity = I>>(
        &self,
        frontend: &mut F,
        mut handoff: Handoff,
        recorded: (F::Resource, F::Record, Option<Uuid>),
    ) -> Result<(F::Session, Kind)> {
        let (resource, record, session_id) = recorded;
        let Some(transfer) = handoff.take_transfer() else {
            // The kernel resource can be reopened only after its irreversible release.
            handoff.commit(|| frontend.check_cancelled())?;
            let owner = SessionOwner::wait_for_predecessor_release(&self.state_base, || {
                frontend.check_cancelled()
            })?;
            return self.adopt(
                frontend,
                owner,
                &resource,
                None,
                (record, session_id),
                Kind::Upgrade,
            );
        };
        // Everything fallible runs before READY, while the predecessor can still resume.
        frontend.check_cancelled()?;
        let session = frontend.open(Open::Adopt {
            transfer: Some(transfer),
            record: None,
            session_id,
            timeout: handoff.remaining()?,
        })?;
        self.finish::<F>(session, |session| {
            if F::control(session).session_id() != session_id {
                return Err(Error::Runtime(
                    "handoff changed the advertised Session Identity".into(),
                ));
            }
            self.check_resource(frontend, &resource)?;
            let committed = handoff.commit(|| frontend.check_cancelled())?;
            let owner = SessionOwner::wait_for_predecessor_release(&self.state_base, || {
                frontend.check_cancelled()
            })?;
            F::set_owner(session, owner)?;
            if committed || !I::protected(session_id) {
                return Ok(Kind::Upgrade);
            }
            F::recover(session)?;
            Ok(Kind::Recovery)
        })
    }

    fn check_resource<F: Frontend<Identity = I>>(
        &self,
        frontend: &F,
        expected: &F::Resource,
    ) -> Result<()> {
        if frontend.inspect()?.as_ref() != Some(expected) {
            return Err(Error::Runtime("resource changed during handoff".into()));
        }
        Ok(())
    }

    fn finish<F: Frontend<Identity = I>>(
        &self,
        mut session: F::Session,
        setup: impl FnOnce(&mut F::Session) -> Result<Kind>,
    ) -> Result<(F::Session, Kind)> {
        match setup(&mut session) {
            Ok(kind) => Ok((session, kind)),
            Err(err) => stop_failed_session::<F, _>(session, err),
        }
    }

    fn start_without_predecessor<F: Frontend<Identity = I>>(
        &self,
        frontend: &mut F,
    ) -> Result<(F::Session, Kind)> {
        frontend.check_cancelled()?;
        // Discovery can race predecessor exit or unmount; re-read before ownership acquisition.
        let mounted = frontend.inspect()?;
        let mut owner = SessionOwner::wait_for_release(&self.state_base, mounted.is_none())?;
        let recorded = match mounted {
            Some(resource) => {
                let record = owner.read()?;
                let session_id = frontend.validate_record(&self.info, &record, &resource)?;
                if !I::protected(session_id) {
                    return Err(Error::Runtime(
                        "the abandoned session has no crash recovery protection".into(),
                    ));
                }
                Some((resource, record, session_id))
            }
            None => None,
        };
        let transfer = match &self.holder {
            Some(socket) => holder::fetch(socket)?,
            None => None,
        };
        frontend.check_cancelled()?;
        let Some((resource, record, session_id)) = recorded else {
            if transfer.is_some() {
                return Err(Error::Runtime(
                    "Holder retains a session but its resource is absent; refusing replacement"
                        .into(),
                ));
            }
            return self.start_fresh(frontend, owner);
        };
        if I::MODE == Mode::Transfer && transfer.is_none() {
            return Err(Error::Runtime(
                "an existing resource has no recovery available; refusing fresh startup".into(),
            ));
        }
        self.adopt(
            frontend,
            owner,
            &resource,
            transfer,
            (record, session_id),
            Kind::Recovery,
        )
    }

    fn start_fresh<F: Frontend<Identity = I>>(
        &self,
        frontend: &mut F,
        mut owner: SessionOwner,
    ) -> Result<(F::Session, Kind)> {
        let previous = if self.holder.is_some() {
            None
        } else {
            owner.read_optional()?
        };
        frontend.validate_fresh(previous.as_ref())?;
        let session = frontend.open(Open::Fresh)?;
        self.finish::<F>(session, |session| {
            let recorded = (|| {
                let resource = frontend.inspect()?.ok_or_else(|| {
                    Error::Runtime("fresh resource has no device identity".into())
                })?;
                owner.write(&frontend.record(&self.info, &resource, session))
            })();
            F::set_owner(session, owner)?;
            recorded?;
            frontend.check_cancelled()?;
            if let Some(socket) = &self.holder {
                let transfer = F::control(session)
                    .prepare(&self.info, HANDOFF_TIMEOUT)?
                    .ok_or_else(|| {
                        Error::Runtime("Holder retention requires a session transfer".into())
                    })?;
                holder::retain(socket, &transfer)?;
            }
            Ok(Kind::Fresh)
        })
    }

    fn adopt<F: Frontend<Identity = I>>(
        &self,
        frontend: &mut F,
        owner: SessionOwner,
        resource: &F::Resource,
        transfer: Option<Transfer>,
        recorded: (F::Record, Option<Uuid>),
        kind: Kind,
    ) -> Result<(F::Session, Kind)> {
        let (record, session_id) = recorded;
        let session = frontend.open(Open::Adopt {
            transfer,
            record: Some(record),
            session_id,
            timeout: HANDOFF_TIMEOUT,
        })?;
        self.finish::<F>(session, |session| {
            F::set_owner(session, owner)?;
            frontend.check_cancelled()?;
            self.check_resource(frontend, resource)?;
            if F::control(session).session_id() != session_id {
                return Err(Error::Runtime(
                    "recovered session does not match its ownership record".into(),
                ));
            }
            if kind == Kind::Recovery {
                F::recover(session)?;
            }
            Ok(kind)
        })
    }
}

/// Keeps the published endpoint alive until native serving and teardown finish.
pub struct RunningSession<S> {
    session: S,
    control: Option<ControlServer>,
}

impl<S> RunningSession<S> {
    pub fn serve<T>(self, serve: impl FnOnce(S) -> Result<T>) -> Result<T> {
        let result = serve(self.session);
        drop(self.control);
        result
    }
}

fn stop_failed_session<F: Frontend, T>(session: F::Session, cause: Error) -> Result<T> {
    match F::stop(session) {
        Ok(()) => Err(cause).context("startup stood down"),
        Err(cleanup) => Err(Error::Runtime(format!(
            "{}; failed to stop unsuccessful startup: {}",
            cause.report(),
            cleanup.report()
        ))),
    }
}

/// Checks endpoint spelling without following links into an unresponsive resource.
pub fn validate_socket_paths(
    api: Option<&Path>,
    holder: Option<&Path>,
    excluded: Option<&Path>,
) -> Result<()> {
    let mut paths = Vec::new();
    for (name, path) in [("--apiserver", api), ("--supervisor-socket", holder)] {
        let Some(path) = path else { continue };
        if !path.is_absolute() {
            return Err(Error::InvalidParameter(format!(
                "{name} must be an absolute path"
            )));
        }
        if path.components().any(|part| part == Component::ParentDir) {
            return Err(Error::InvalidParameter(format!(
                "{name} must use a path without '..'"
            )));
        }
        path.file_name()
            .ok_or_else(|| Error::InvalidParameter(format!("{name} must name a socket file")))?;
        if excluded.is_some_and(|excluded| path.starts_with(excluded)) {
            return Err(Error::InvalidParameter(format!(
                "{name} must be outside the resource mountpoint"
            )));
        }
        let path: PathBuf = path.components().collect();
        for (other_name, other_path) in &paths {
            if path == *other_path {
                return Err(Error::InvalidParameter(format!(
                    "{name} and {other_name} must use different Unix socket paths: {}",
                    path.display()
                )));
            }
        }
        paths.push((name, path));
    }
    for (name, path) in paths {
        let mut prefix = PathBuf::new();
        for part in path.components() {
            prefix.push(part.as_os_str());
            match std::fs::symlink_metadata(&prefix) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(Error::InvalidParameter(format!(
                        "{name} must not contain symlinks: {}",
                        prefix.display()
                    )))
                }
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("failed to inspect {name} path {}", prefix.display())
                    })
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::continuity::test_support::{metrics, KernelInfo, LiveInfo, TestInfo, TestSession};

    struct TestFrontend<const KERNEL: bool> {
        base: PathBuf,
        info: TestInfo<KERNEL>,
        session_id: Option<Uuid>,
        mounted: Arc<AtomicBool>,
        events: Arc<Mutex<Vec<&'static str>>>,
        fail_recovery: bool,
        fail_activation: bool,
    }

    struct TestRunning<const KERNEL: bool> {
        control: TestSession<KERNEL>,
        fail_recovery: bool,
        fail_activation: bool,
    }

    impl<const KERNEL: bool> Frontend for TestFrontend<KERNEL> {
        type Identity = TestInfo<KERNEL>;
        type Resource = u64;
        type Record = u64;
        type Session = TestRunning<KERNEL>;
        type Control = TestSession<KERNEL>;

        fn inspect(&self) -> Result<Option<u64>> {
            Ok(self.mounted.load(Ordering::SeqCst).then_some(1))
        }
        fn prepare(&mut self, _peer: &TestInfo<KERNEL>) -> Result<()> {
            self.events.lock().unwrap().push("local-prepare");
            Ok(())
        }
        fn validate_record(
            &self,
            _info: &TestInfo<KERNEL>,
            record: &u64,
            resource: &u64,
        ) -> Result<Option<Uuid>> {
            if record != resource {
                return Err(Error::Runtime("record mismatch".into()));
            }
            Ok(self.session_id)
        }
        fn validate_fresh(&self, _previous: Option<&u64>) -> Result<()> {
            Ok(())
        }
        fn open(&mut self, how: Open<u64>) -> Result<TestRunning<KERNEL>> {
            assert!(SessionOwner::acquire(&self.base, false).is_err());
            if let Open::Adopt {
                transfer: None,
                record,
                ..
            } = how
            {
                assert!(KERNEL);
                assert_eq!(record, Some(1));
            }
            self.events.lock().unwrap().push("open");
            self.mounted.store(true, Ordering::SeqCst);
            Ok(TestRunning {
                control: TestSession {
                    events: self.events.clone(),
                    session_id: self.session_id,
                    ..Default::default()
                },
                fail_recovery: self.fail_recovery,
                fail_activation: self.fail_activation,
            })
        }
        fn record(
            &self,
            _info: &TestInfo<KERNEL>,
            resource: &u64,
            _session: &TestRunning<KERNEL>,
        ) -> u64 {
            *resource
        }
        fn control(session: &TestRunning<KERNEL>) -> TestSession<KERNEL> {
            session.control.clone()
        }
        fn set_owner(session: &mut TestRunning<KERNEL>, owner: SessionOwner) -> Result<()> {
            *session.control.owner.lock().unwrap() = Some(owner);
            session.control.events.lock().unwrap().push("owner");
            Ok(())
        }
        fn recover(session: &TestRunning<KERNEL>) -> Result<()> {
            assert!(session.control.owner.lock().unwrap().is_some());
            session.control.events.lock().unwrap().push("recover");
            if session.fail_recovery {
                return Err(Error::Runtime("recovery failed".into()));
            }
            Ok(())
        }
        fn activate(session: &TestRunning<KERNEL>) -> Result<()> {
            assert!(session.control.owner.lock().unwrap().is_some());
            session.control.events.lock().unwrap().push("activate");
            if session.fail_activation {
                return Err(Error::Runtime("activation failed".into()));
            }
            Ok(())
        }
        fn stop(session: TestRunning<KERNEL>) -> Result<()> {
            session.control.events.lock().unwrap().push("stop");
            Ok(())
        }
    }

    fn frontend<const KERNEL: bool>(base: &Path, mounted: bool) -> TestFrontend<KERNEL> {
        TestFrontend {
            base: base.into(),
            info: TestInfo::new(),
            session_id: None,
            mounted: Arc::new(AtomicBool::new(mounted)),
            events: Arc::new(Mutex::new(Vec::new())),
            fail_recovery: false,
            fail_activation: false,
        }
    }

    fn take_over_live_predecessor<const KERNEL: bool>(expected: &[&str]) {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("state/session");
        prepare_state_directory(base.parent().unwrap()).unwrap();
        let path = dir.path().join("api.sock");
        let backend = frontend::<KERNEL>(&base, true);
        let info = backend.info.clone();
        let events = backend.events.clone();
        let mut owner = SessionOwner::acquire(&base, true).unwrap();
        owner.write(&1u64).unwrap();
        let source = TestSession::<KERNEL> {
            events: events.clone(),
            ..Default::default()
        };
        *source.owner.lock().unwrap() = Some(owner);
        let source_server =
            ControlServer::start(&path, info.clone(), source.clone(), metrics()).unwrap();
        let running = Startup {
            info,
            api_socket: Some(path.clone()),
            state_base: base.clone(),
            holder: None,
            metrics: metrics(),
        }
        .start(backend)
        .unwrap();
        assert!(source.lifecycle.is_released());
        assert!(SessionOwner::acquire(&base, false).is_err());
        assert_eq!(*events.lock().unwrap(), expected);
        drop(source_server);
        assert!(handoff::probe(&path, &TestInfo::<KERNEL>::new())
            .unwrap()
            .is_some());
        running.serve(|_| Ok(())).unwrap();
        assert!(SessionOwner::acquire(&base, false).is_ok());
    }

    #[test]
    fn live_and_reopen_takeovers_activate_only_after_ownership() {
        take_over_live_predecessor::<false>(&[
            "local-prepare",
            "prepare",
            "open",
            "release",
            "owner",
            "activate",
        ]);
        take_over_live_predecessor::<true>(&[
            "local-prepare",
            "prepare",
            "release",
            "open",
            "owner",
            "activate",
        ]);
    }

    fn reject_mismatch_before_begin<const KERNEL: bool>() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("state/session");
        prepare_state_directory(base.parent().unwrap()).unwrap();
        let path = dir.path().join("api.sock");
        let backend = frontend::<KERNEL>(&base, true);
        let info = backend.info.clone();
        let events = backend.events.clone();
        let mut owner = SessionOwner::acquire(&base, true).unwrap();
        owner.write(&2u64).unwrap();
        let source = TestSession::<KERNEL> {
            events: events.clone(),
            ..Default::default()
        };
        *source.owner.lock().unwrap() = Some(owner);
        let _source_server =
            ControlServer::start(&path, info.clone(), source.clone(), metrics()).unwrap();
        let result = Startup {
            info,
            api_socket: Some(path),
            state_base: base,
            holder: None,
            metrics: metrics(),
        }
        .start(backend);
        assert!(result.is_err());
        assert!(events.lock().unwrap().is_empty());
        assert!(!source.lifecycle.is_released());
    }

    #[test]
    fn record_mismatch_is_rejected_before_the_predecessor_is_touched() {
        reject_mismatch_before_begin::<false>();
        reject_mismatch_before_begin::<true>();
    }

    #[test]
    fn kernel_recovery_and_failures_preserve_the_resource_without_early_activation() {
        for (fail_recovery, fail_activation) in [(false, false), (true, false), (false, true)] {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().join("state/session");
            prepare_state_directory(base.parent().unwrap()).unwrap();
            let mut owner = SessionOwner::acquire(&base, true).unwrap();
            owner.write(&1u64).unwrap();
            drop(owner);
            let mut backend = frontend::<true>(&base, true);
            backend.fail_recovery = fail_recovery;
            backend.fail_activation = fail_activation;
            let events = backend.events.clone();
            let resource = backend.mounted.clone();
            let result = Startup {
                info: KernelInfo::new(),
                api_socket: None,
                state_base: base.clone(),
                holder: None,
                metrics: metrics(),
            }
            .start(backend);
            if fail_recovery || fail_activation {
                assert!(result.is_err());
            } else {
                result.unwrap().serve(|_| Ok(())).unwrap();
            }
            assert_eq!(
                *events.lock().unwrap(),
                if fail_recovery {
                    vec!["open", "owner", "recover", "stop"]
                } else if fail_activation {
                    vec!["open", "owner", "recover", "activate", "stop"]
                } else {
                    vec!["open", "owner", "recover", "activate"]
                }
            );
            assert!(resource.load(Ordering::SeqCst));
            assert!(SessionOwner::acquire(&base, false).is_ok());
        }
    }

    #[test]
    fn fresh_start_records_ownership_before_publication() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("state/session");
        let backend = frontend::<false>(&base, false);
        let events = backend.events.clone();
        let running = Startup {
            info: LiveInfo::new(),
            api_socket: Some(dir.path().join("api.sock")),
            state_base: base.clone(),
            holder: None,
            metrics: metrics(),
        }
        .start(backend)
        .unwrap();
        assert_eq!(*events.lock().unwrap(), ["open", "owner", "activate"]);
        assert!(dir.path().join("api.sock").exists());
        assert!(SessionOwner::acquire(&base, false).is_err());
        running.serve(|_| Ok(())).unwrap();
        assert_eq!(
            SessionOwner::acquire(&base, false)
                .unwrap()
                .read::<u64>()
                .unwrap(),
            1
        );
    }

    #[test]
    fn holder_requires_transfer_handoff() {
        let dir = tempfile::tempdir().unwrap();
        let result = Startup {
            info: KernelInfo::new(),
            api_socket: None,
            state_base: dir.path().join("state/session"),
            holder: Some(dir.path().join("holder.sock")),
            metrics: metrics(),
        }
        .start(frontend::<true>(&dir.path().join("state/session"), false));
        assert!(result.is_err());
    }

    #[test]
    fn fresh_holder_protection_requires_complete_retention_before_activation() {
        use crate::continuity::test_support::test_deadline;
        use crate::continuity::wire::{read_frame_until, write_frame_until, Transfer};
        use std::os::unix::net::UnixListener;

        for retained in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().join("state/session");
            let socket = dir.path().join("holder.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let recorded_base = base.clone();
            let holder = std::thread::spawn(move || {
                let (mut fetch, _) = listener.accept().unwrap();
                let request: serde_json::Value = read_frame_until(&mut fetch, test_deadline())
                    .unwrap()
                    .unwrap();
                assert_eq!(request, serde_json::json!({"type":"fetch"}));
                write_frame_until(
                    &mut fetch,
                    test_deadline(),
                    &serde_json::json!({"type":"empty"}),
                )
                .unwrap();
                let (mut retain, _) = listener.accept().unwrap();
                let request: serde_json::Value = read_frame_until(&mut retain, test_deadline())
                    .unwrap()
                    .unwrap();
                assert_eq!(request, serde_json::json!({"type":"retain"}));
                assert!(SessionOwner::acquire(&recorded_base, false).is_err());
                let transfer = Transfer::receive(&mut retain, test_deadline()).unwrap();
                assert_eq!(transfer.metadata, b"native state");
                assert_eq!(transfer.fds.len(), 2);
                let reply = if retained {
                    serde_json::json!({"type":"retained"})
                } else {
                    serde_json::json!({"type":"error","message":"rejected"})
                };
                write_frame_until(&mut retain, test_deadline(), &reply).unwrap();
            });
            let mut backend = frontend::<false>(&base, false);
            backend.session_id = Some(Uuid::from_u128(1));
            let events = backend.events.clone();
            let result = Startup {
                info: LiveInfo::new(),
                api_socket: None,
                state_base: base.clone(),
                holder: Some(socket),
                metrics: metrics(),
            }
            .start(backend);
            if retained {
                result.unwrap().serve(|_| Ok(())).unwrap();
            } else {
                assert!(result.is_err());
            }
            holder.join().unwrap();
            assert_eq!(
                *events.lock().unwrap(),
                if retained {
                    vec!["open", "owner", "prepare", "activate"]
                } else {
                    vec!["open", "owner", "prepare", "stop"]
                }
            );
            assert!(SessionOwner::acquire(&base, false).is_ok());
        }
    }

    #[test]
    fn endpoints_are_checked_without_following_aliases_into_resources() {
        let dir = tempfile::tempdir().unwrap();
        let excluded = dir.path().join("mount");
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&alias, &alias).unwrap();
        let socket = dir.path().join("api.sock");
        for (api, holder, expected) in [
            (Some(PathBuf::from("relative")), None, "absolute"),
            (None, Some(PathBuf::from("relative")), "absolute"),
            (Some(excluded.join("api.sock")), None, "outside"),
            (Some(alias.join("api.sock")), None, "symlinks"),
            (Some(excluded.join("../api.sock")), None, "without '..'"),
            (
                Some(socket.clone()),
                Some(dir.path().join("./api.sock")),
                "different Unix socket",
            ),
        ] {
            let error = validate_socket_paths(api.as_deref(), holder.as_deref(), Some(&excluded))
                .unwrap_err();
            assert!(error.report().to_string().contains(expected), "{error:?}");
        }
        validate_socket_paths(Some(&socket), None, Some(&excluded)).unwrap();
        assert!(!socket.exists());
        assert!(!excluded.exists());
    }
}
