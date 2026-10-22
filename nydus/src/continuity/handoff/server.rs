use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nydus_core::{Metrics, OndemandRecorder};
use nydus_error::{Context, Error, Result};
use tracing::{info, warn};

use super::protocol::{Request, Response};
use super::SessionControl;
use crate::api_server::{remove_socket, ApiServer, ControlEndpoint};
use crate::continuity::peer::{authenticate_peer, PeerProcess};
use crate::continuity::wire::{
    connect_until, read_buffered_frame_until, read_frame_until, write_frame_until, ProtocolDeadline,
};
use crate::continuity::{
    Identity, Mode, SessionLifecycle, CONTROL_RESPONSE_TIMEOUT, HANDOFF_TIMEOUT,
};

struct PendingHandoff<'a, S: SessionControl>(&'a S);

impl<S: SessionControl> Drop for PendingHandoff<'_, S> {
    fn drop(&mut self) {
        if self.0.lifecycle().abort_handoff() {
            self.0.resume();
        }
    }
}

pub(crate) struct ControlServer {
    api: Option<ApiServer>,
    path: PathBuf,
    lifecycle: SessionLifecycle,
}

impl ControlServer {
    /// The caller holds startup serialization through binding and publication.
    /// `metrics` and the `ondemand` record back `/metrics` and `/trace` on the same listener.
    pub(crate) fn start<S: SessionControl>(
        path: &Path,
        info: S::Identity,
        session: S,
        metrics: Arc<Metrics>,
        ondemand: Arc<OndemandRecorder>,
    ) -> Result<Self> {
        let listener = match bind_listener(path) {
            Ok(listener) => listener,
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => replace_stale_socket(path)?,
            Err(err) => return Err(err.into()),
        };
        let handler_path = path.to_path_buf();
        let lifecycle = session.lifecycle();
        let control = ControlEndpoint {
            protocol: S::Identity::CONTROL,
            handler: Arc::new(move |stream, buffered| {
                handle_connection(stream, buffered, &info, &session, &handler_path)
            }),
        };
        let api = match ApiServer::from_listener(listener, Some(control), metrics, ondemand) {
            Ok(api) => api,
            Err(err) => {
                remove_socket(path);
                return Err(err).context("failed to start the control apiserver");
            }
        };
        info!("control apiserver listening on unix://{}", path.display());
        Ok(Self {
            api: Some(api),
            path: path.into(),
            lifecycle,
        })
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        if let Some(api) = self.api.take() {
            api.stop();
        }
        if !self.lifecycle.is_released() {
            remove_socket(&self.path);
        }
    }
}

fn bind_listener(path: &Path) -> io::Result<UnixListener> {
    let listener = UnixListener::bind(path)?;
    if let Err(err) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        drop(listener);
        remove_socket(path);
        return Err(err);
    }
    Ok(listener)
}

/// ECONNREFUSED also occurs for regular files; only unlink an unlistened socket.
fn replace_stale_socket(path: &Path) -> Result<UnixListener> {
    let deadline = ProtocolDeadline::after(CONTROL_RESPONSE_TIMEOUT, "control socket probe");
    match connect_until(path, deadline) {
        Ok(_) => {
            return Err(Error::Runtime(format!(
                "another instance is serving {}",
                path.display()
            )))
        }
        Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {}
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to probe control socket {}", path.display()))
        }
    }
    if !path.symlink_metadata()?.file_type().is_socket() {
        return Err(Error::Runtime(format!(
            "{} already exists and is not a socket",
            path.display()
        )));
    }
    std::fs::remove_file(path)?;
    Ok(bind_listener(path)?)
}

fn reply_error(stream: &mut UnixStream, deadline: ProtocolDeadline, message: String) -> Result<()> {
    write_frame_until(stream, deadline, &Response::<()>::Error { message })
}

fn handle_connection<S: SessionControl>(
    mut stream: UnixStream,
    buffered: Vec<u8>,
    info: &S::Identity,
    session: &S,
    path: &Path,
) -> Result<bool> {
    let peer_pid = authenticate_peer(&stream)?;
    let deadline = ProtocolDeadline::after(HANDOFF_TIMEOUT, "control conversation");
    let mut buffered = io::Cursor::new(buffered);
    let mut discovered = false;
    loop {
        let request = match read_buffered_frame_until::<Request<S::Identity>>(
            &mut stream,
            &mut buffered,
            deadline,
        ) {
            Ok(Some(request)) => request,
            Ok(None) => return Ok(false),
            Err(err) => {
                if let Err(reply_err) = reply_error(
                    &mut stream,
                    deadline,
                    format!("invalid control request: {}", err.report()),
                ) {
                    warn!(
                        "failed to send control error response: {}",
                        reply_err.report()
                    );
                }
                return Err(err);
            }
        };
        match request {
            Request::Info {} => {
                write_frame_until(
                    &mut stream,
                    deadline,
                    &Response::Info {
                        info,
                        session_id: session.session_id(),
                    },
                )?;
                discovered = true;
            }
            Request::HandoffBegin { peer } => {
                let deadline = ProtocolDeadline::after(HANDOFF_TIMEOUT, "handoff transaction");
                if !discovered || buffered.position() != buffered.get_ref().len() as u64 {
                    reply_error(
                        &mut stream,
                        deadline,
                        "handoff requires an INFO exchange and no pipelined requests".into(),
                    )?;
                    return Ok(false);
                }
                if let Err(err) = peer.check_pid(peer_pid).and_then(|()| info.check(&peer)) {
                    reply_error(&mut stream, deadline, err.report().to_string())?;
                    return Ok(false);
                }
                info!(
                    "handing the live session to successor pid {} (version {})",
                    peer.pid(),
                    peer.version()
                );
                return hand_off(&mut stream, deadline, peer_pid, info, session, path);
            }
            Request::Ready {} => {
                reply_error(&mut stream, deadline, "no handoff is in progress".into())?;
                return Ok(false);
            }
        }
    }
}

fn hand_off<S: SessionControl>(
    stream: &mut UnixStream,
    deadline: ProtocolDeadline,
    peer_pid: u32,
    info: &S::Identity,
    session: &S,
    path: &Path,
) -> Result<bool> {
    let remaining = deadline.remaining()?;
    if let Err(err) = session.lifecycle().begin_handoff() {
        reply_error(stream, deadline, err.report().to_string())?;
        return Ok(false);
    }
    let _pending = PendingHandoff(session);
    let prepared = match session.prepare(info, remaining) {
        Ok(prepared) => prepared,
        Err(err) => {
            reply_error(stream, deadline, err.report().to_string())?;
            return Ok(false);
        }
    };
    let verdict = match (S::Identity::MODE, prepared) {
        (Mode::Transfer, Some(transfer)) => {
            let successor = PeerProcess::observe(peer_pid);
            let ready = (|| {
                write_frame_until(stream, deadline, &Response::<()>::HandoffTransfer {})?;
                transfer.send(stream, deadline)?;
                match read_frame_until::<Request<S::Identity>>(stream, deadline)? {
                    Some(Request::Ready {}) => Ok(()),
                    other => Err(Error::Protocol(format!(
                        "unexpected readiness request: {other:?}"
                    ))),
                }
            })();
            if let Err(err) = ready {
                let released = resolve_failed_handoff(stream, session, &successor, err)?;
                if released {
                    remove_socket(path);
                }
                return Ok(released);
            }
            Response::<()>::Committed {}
        }
        // From this point even a failed/partial native release is not reversible.
        (Mode::Kernel, None) => Response::<()>::Released {},
        _ => {
            return Err(Error::Protocol(
                "frontend prepared resources that do not match its mode".into(),
            ))
        }
    };
    session.lifecycle().mark_released()?;
    session.release()?;
    remove_socket(path);
    let deadline = ProtocolDeadline::after(CONTROL_RESPONSE_TIMEOUT, "handoff verdict");
    if let Err(err) = write_frame_until(stream, deadline, &verdict) {
        warn!("failed to send handoff verdict: {}", err.report());
    }
    info!("handoff complete; control socket removed");
    Ok(true)
}

fn resolve_failed_handoff<S: SessionControl>(
    stream: &mut UnixStream,
    session: &S,
    successor: &PeerProcess,
    cause: Error,
) -> Result<bool> {
    warn!(
        "handoff failed before successor readiness ({}); sending abort before resuming service",
        cause.report()
    );
    let abort = write_frame_until(
        stream,
        ProtocolDeadline::after(CONTROL_RESPONSE_TIMEOUT, "handoff abort"),
        &Response::<()>::Abort {
            message: format!("handoff aborted before READY: {}", cause.report()),
        },
    );
    match abort {
        Ok(()) => Ok(false),
        Err(err) if successor.confirm_exited(CONTROL_RESPONSE_TIMEOUT) => {
            warn!(
                "successor exited before abort delivery completed: {}",
                err.report()
            );
            Ok(false)
        }

        Err(err) => {
            warn!(
                "abort could not reach a potentially live successor; releasing the session: {}",
                err.report()
            );
            session.lifecycle().mark_released()?;
            session.release()?;
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    use super::super::client::upgrade_control_client;
    use super::*;
    use crate::continuity::test_support::{
        metrics, ondemand, test_deadline, KernelInfo, LiveInfo, TestInfo, TestSession,
    };
    use crate::continuity::wire::{connect_until, Transfer};

    /// A listener whose backlog is already full, so further connects get EAGAIN.
    fn saturated_listener(path: &Path) -> (UnixListener, UnixStream) {
        let listener = UnixListener::bind(path).unwrap();
        // SAFETY: a plain syscall on a descriptor the listener keeps alive.
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
        let queued = connect_until(path, test_deadline()).unwrap();
        (listener, queued)
    }

    fn connect<const KERNEL: bool>(path: &Path, info: &TestInfo<KERNEL>) -> UnixStream {
        let mut stream = upgrade_control_client(
            UnixStream::connect(path).unwrap(),
            LiveInfo::CONTROL,
            test_deadline(),
        )
        .unwrap();
        write_frame_until(&mut stream, test_deadline(), &Request::<()>::Info {}).unwrap();
        assert!(matches!(
            read_frame_until::<Response<TestInfo<KERNEL>>>(&mut stream, test_deadline()).unwrap(),
            Some(Response::Info { .. })
        ));
        write_frame_until(
            &mut stream,
            test_deadline(),
            &Request::HandoffBegin { peer: info },
        )
        .unwrap();
        stream
    }

    #[test]
    fn live_transfer_commits_aborts_or_retires_without_concurrent_owners() {
        for action in ["ready", "abort", "disconnect"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("api.sock");
            let info = LiveInfo::new();
            let session = TestSession::<false>::default();
            let server =
                ControlServer::start(&path, info.clone(), session.clone(), metrics(), ondemand())
                    .unwrap();
            let mut stream = connect(&path, &info);
            assert!(matches!(
                read_frame_until::<Response<LiveInfo>>(&mut stream, test_deadline()).unwrap(),
                Some(Response::HandoffTransfer {})
            ));
            let _transfer = Transfer::receive(&mut stream, test_deadline()).unwrap();
            match action {
                "ready" => {
                    write_frame_until(&mut stream, test_deadline(), &Request::<()>::Ready {})
                        .unwrap();
                    assert!(matches!(
                        read_frame_until::<Response<LiveInfo>>(&mut stream, test_deadline())
                            .unwrap(),
                        Some(Response::Committed {})
                    ));
                }
                "abort" => {
                    write_frame_until(&mut stream, test_deadline(), &Request::<()>::Info {})
                        .unwrap();
                    assert!(matches!(
                        read_frame_until::<Response<LiveInfo>>(&mut stream, test_deadline())
                            .unwrap(),
                        Some(Response::Abort { .. })
                    ));
                }
                _ => {}
            }
            drop(stream);
            drop(server);
            assert_eq!(session.lifecycle.is_released(), action != "abort");
            assert_eq!(
                *session.events.lock().unwrap(),
                if action == "abort" {
                    vec!["prepare", "resume"]
                } else {
                    vec!["prepare", "release"]
                }
            );
        }
    }

    #[test]
    fn native_release_never_rolls_back() {
        for fail_release in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("api.sock");
            let info = KernelInfo::new();
            let session = TestSession::<true> {
                fail_release,
                ..Default::default()
            };
            let server =
                ControlServer::start(&path, info.clone(), session.clone(), metrics(), ondemand())
                    .unwrap();
            let mut stream = connect(&path, &info);
            let response =
                read_frame_until::<Response<KernelInfo>>(&mut stream, test_deadline()).unwrap();
            if fail_release {
                assert!(response.is_none());
            } else {
                assert!(matches!(response, Some(Response::Released {})));
            }
            drop(stream);
            drop(server);
            assert!(session.lifecycle.is_released());
            assert!(!session.lifecycle.abort_handoff());
            assert_eq!(*session.events.lock().unwrap(), ["prepare", "release"]);
        }
    }

    #[test]
    fn control_endpoint_is_configurable_and_does_not_block_observability() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let _server = ControlServer::start(
            &path,
            LiveInfo::new(),
            TestSession::<false>::default(),
            metrics(),
            ondemand(),
        )
        .unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        let mut control = upgrade_control_client(
            UnixStream::connect(&path).unwrap(),
            LiveInfo::CONTROL,
            test_deadline(),
        )
        .unwrap();
        write_frame_until(&mut control, test_deadline(), &Request::<()>::Info {}).unwrap();
        assert!(matches!(
            read_frame_until::<Response<LiveInfo>>(&mut control, test_deadline()).unwrap(),
            Some(Response::Info { .. })
        ));
        for (route, status) in [
            ("/metrics", 200),
            ("/trace", 200),
            ("/resource/control", 426),
            ("/fuse/handoff", 404),
        ] {
            let mut observer = UnixStream::connect(&path).unwrap();
            observer
                .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .unwrap();
            write!(
                observer,
                "GET {route} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            let mut response = String::new();
            observer.read_to_string(&mut response).unwrap();
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status}")),
                "{response}"
            );
        }
    }

    #[test]
    fn invalid_requests_leave_the_endpoint_and_session_alive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let session = TestSession::<false>::default();
        let server = ControlServer::start(
            &path,
            LiveInfo::new(),
            session.clone(),
            metrics(),
            ondemand(),
        )
        .unwrap();
        for frame in [
            0u32.to_le_bytes().to_vec(),
            (4u32 * 1024 * 1024 + 1).to_le_bytes().to_vec(),
            [1u32.to_le_bytes().as_slice(), b"{"].concat(),
            [2u32.to_le_bytes().as_slice(), b"{"].concat(),
        ] {
            let mut stream = upgrade_control_client(
                UnixStream::connect(&path).unwrap(),
                LiveInfo::CONTROL,
                test_deadline(),
            )
            .unwrap();
            stream.write_all(&frame).unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            assert!(matches!(
                read_frame_until::<Response<LiveInfo>>(&mut stream, test_deadline()).unwrap(),
                Some(Response::Error { .. })
            ));
        }
        assert!(super::super::probe(&path, &LiveInfo::new())
            .unwrap()
            .is_some());
        let mut wrong = LiveInfo::new();
        wrong.resource = "wrong-resource".into();
        let mut stream = connect(&path, &wrong);
        assert!(matches!(
            read_frame_until::<Response<LiveInfo>>(&mut stream, test_deadline()).unwrap(),
            Some(Response::Error { .. })
        ));
        drop(stream);
        drop(server);
        assert!(session.events.lock().unwrap().is_empty());
    }

    #[test]
    fn socket_publication_preserves_busy_and_non_socket_paths() {
        let start = |path: &Path| {
            ControlServer::start(
                path,
                LiveInfo::new(),
                TestSession::<false>::default(),
                metrics(),
                ondemand(),
            )
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let (listener, queued) = saturated_listener(&path);
        let inode = std::fs::metadata(&path).unwrap().ino();
        let error = start(&path).err().unwrap();
        assert_eq!(error.io_error().unwrap().kind(), io::ErrorKind::TimedOut);
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
        drop((listener, queued));
        drop(start(&path).unwrap());
        std::fs::write(&path, b"operator data").unwrap();
        assert!(start(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"operator data");
    }
}
