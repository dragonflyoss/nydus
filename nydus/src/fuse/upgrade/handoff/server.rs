use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use nydus_error::{Context, Error, Result};
use tracing::{info, warn};

use super::super::startup::StartupLock;
use super::super::transfer::SessionTransfer;
use super::super::wire::{read_frame_until, write_frame_until, ProtocolDeadline};
use super::super::CONTROL_RESPONSE_TIMEOUT;
use super::identity::{authenticate_peer, InstanceInfo, PeerProcess};
use super::lifecycle::{handoff_deadline, SessionRuntimeHandle};
use super::protocol::{Request, Response};

const CONTROL_STOP: u8 = 2;

struct PendingHandoff {
    transfer: SessionTransfer,
    handle: Option<SessionRuntimeHandle>,
}

impl PendingHandoff {
    fn abort(mut self) {
        let handle = self.handle.take().expect("handoff resolved once");
        handle.handoff_abort();
    }

    fn retire(mut self) {
        let handle = self.handle.take().expect("handoff resolved once");
        handle.handoff_cutover();
    }
}

impl Drop for PendingHandoff {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.handoff_abort();
        }
    }
}

pub(in crate::fuse::upgrade) struct ControlServer {
    command: Option<UnixStream>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ControlServer {
    /// Binds the control socket and starts its accept loop.
    ///
    /// Consumes the startup ownership `lock` and drops it only once the
    /// listener is bound and the accept thread is running, so a concurrent
    /// starter can never observe the gap between the ownership probe and the
    /// bound socket.
    pub(in crate::fuse::upgrade) fn start(
        path: &Path,
        info: InstanceInfo,
        handle: SessionRuntimeHandle,
        lock: StartupLock,
    ) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Held through probe, reclamation, and bind. The startup `lock` is
        // mountpoint-scoped, so two mountpoints configured with the same
        // explicit control path could otherwise both deem the old socket
        // stale, and the second remove+bind would silently unlink the first
        // daemon's freshly bound endpoint.
        let _path_lock = lock_control_path(path)?;
        let listener = match bind_listener(path) {
            Ok(listener) => listener,
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                if UnixStream::connect(path).is_ok() {
                    return Err(Error::Runtime(format!(
                        "another fuse instance is serving {}",
                        path.display()
                    )));
                }
                // A refused connect only proves nobody is listening, not that
                // this name is ours to delete: bind reports AddrInUse for any
                // existing path, and a regular file answers connect with the
                // same ECONNREFUSED a stale socket does. Unlink a socket and
                // nothing else, without following a symlink to one.
                if !path.symlink_metadata()?.file_type().is_socket() {
                    return Err(Error::Runtime(format!(
                        "{} already exists and is not a socket",
                        path.display()
                    )));
                }
                std::fs::remove_file(path)?;
                bind_listener(path)?
            }
            Err(err) => return Err(err.into()),
        };
        // One cleanup point for everything after the bind: on any failure,
        // drop the listener (moved into the closure) and unlink the socket.
        let spawned = (|| {
            listener.set_nonblocking(true)?;
            let (command, thread_command) = UnixStream::pair()?;
            let thread_path = path.to_path_buf();
            let thread = std::thread::Builder::new()
                .name("nydus_fuse_ctl".to_string())
                .spawn(move || accept_loop(listener, thread_command, thread_path, info, handle))?;
            Ok::<_, io::Error>((command, thread))
        })();
        let (command, thread) = match spawned {
            Ok(pair) => pair,
            Err(err) => {
                let _ = std::fs::remove_file(path);
                return Err(err).context("failed to start the fuse control thread");
            }
        };
        drop(lock);
        info!("control socket listening at {}", path.display());
        Ok(Self {
            command: Some(command),
            thread: Some(thread),
        })
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        if let Some(mut command) = self.command.take() {
            let _ = command.write_all(&[CONTROL_STOP]);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Serializes stale-socket reclamation and bind across starters that share
/// one control-socket path: a sibling `<path>.lock` flock, exclusive and
/// non-blocking. The lock file is left behind; flock ownership, not the
/// file's existence, is the mutex.
fn lock_control_path(path: &Path) -> Result<std::fs::File> {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(PathBuf::from(lock_path))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let err = io::Error::last_os_error();
        if err
            .raw_os_error()
            .is_some_and(|code| code == libc::EAGAIN || code == libc::EWOULDBLOCK)
        {
            return Err(Error::Runtime(format!(
                "another process is reclaiming the control socket {}",
                path.display()
            )));
        }
        return Err(err).with_context(|| format!("failed to lock {}.lock", path.display()));
    }
    Ok(file)
}

fn bind_listener(path: &Path) -> io::Result<UnixListener> {
    let listener = UnixListener::bind(path)?;
    if let Err(err) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        drop(listener);
        let _ = std::fs::remove_file(path);
        return Err(err);
    }
    Ok(listener)
}

fn accept_loop(
    listener: UnixListener,
    stop: UnixStream,
    path: PathBuf,
    info: InstanceInfo,
    handle: SessionRuntimeHandle,
) {
    let mut retired = false;
    loop {
        let mut poll = [
            libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stop.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let result = unsafe { libc::poll(poll.as_mut_ptr(), 2, -1) };
        if result < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        if poll[1].revents & libc::POLLIN != 0 {
            break;
        }
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => {
                warn!("fuse control endpoint lost, this instance can no longer be upgraded: {err}");
                break;
            }
        };
        match handle_connection(stream, &info, &handle, &path) {
            Ok(true) => {
                retired = true;
                break;
            }
            Ok(false) => {}
            Err(err) => warn!("fuse control connection failed: {}", err.report()),
        }
    }
    if !retired {
        let _ = std::fs::remove_file(&path);
    }
}

fn handle_connection(
    mut stream: UnixStream,
    info: &InstanceInfo,
    handle: &SessionRuntimeHandle,
    path: &Path,
) -> Result<bool> {
    let peer_pid = authenticate_peer(&stream)?;
    let deadline = handoff_deadline();
    loop {
        let request = match read_frame_until(&mut stream, deadline) {
            Ok(Some(request)) => request,
            Ok(None) => return Ok(false),
            Err(err) => {
                let _ = write_frame_until(
                    &mut stream,
                    deadline,
                    &Response::Error {
                        message: format!("invalid control request: {}", err.report()),
                    },
                );
                return Err(err);
            }
        };
        match request {
            Request::Info {} => {
                write_frame_until(
                    &mut stream,
                    deadline,
                    &Response::Info {
                        info: info.clone(),
                        session_id: handle.session_id(),
                    },
                )?;
            }
            Request::HandoffBegin { peer } => {
                let identity = peer.check_pid(peer_pid).and_then(|_| info.check(&peer));
                if let Err(message) = identity {
                    write_frame_until(&mut stream, deadline, &Response::Error { message })?;
                    return Ok(false);
                }
                info!(
                    "fuse: handing the live session to successor pid {} (version {})",
                    peer.pid, peer.version
                );
                let successor = PeerProcess::observe(peer_pid);
                let transfer = match handle.handoff_begin(deadline.remaining()?, info) {
                    Ok(transfer) => transfer,
                    Err(message) => {
                        write_frame_until(&mut stream, deadline, &Response::Error { message })?;
                        return Ok(false);
                    }
                };
                let pending = PendingHandoff {
                    transfer,
                    handle: Some(handle.clone()),
                };
                let retired =
                    match send_transfer_await_ready(&mut stream, &pending.transfer, deadline) {
                        Ok(()) => {
                            pending.retire();
                            let _ = std::fs::remove_file(path);
                            if let Err(err) = write_frame_until(
                                &mut stream,
                                ProtocolDeadline::after(
                                    CONTROL_RESPONSE_TIMEOUT,
                                    "fuse handoff commit verdict",
                                ),
                                &Response::Committed {},
                            ) {
                                warn!("failed to send fuse handoff COMMITTED: {}", err.report());
                            }
                            info!("fd handoff complete; retiring control socket");
                            return Ok(true);
                        }
                        Err(err) => resolve_failed_handoff(&mut stream, pending, &successor, err),
                    };
                if retired {
                    let _ = std::fs::remove_file(path);
                }
                return Ok(retired);
            }
            Request::Ready {} => {
                write_frame_until(
                    &mut stream,
                    deadline,
                    &Response::Error {
                        message: "no fuse handoff is in progress".to_string(),
                    },
                )?;
                return Ok(false);
            }
        }
    }
}

/// Aborts a failed handoff and resumes serving only when the successor cannot
/// still own the session. Returns whether the predecessor had to retire.
fn resolve_failed_handoff(
    stream: &mut UnixStream,
    pending: PendingHandoff,
    successor: &PeerProcess,
    cause: Error,
) -> bool {
    warn!(
        "fd handoff failed before successor readiness ({}); sending abort \
         before resuming service",
        cause.report()
    );
    let abort = write_frame_until(
        stream,
        ProtocolDeadline::after(CONTROL_RESPONSE_TIMEOUT, "fuse handoff abort"),
        &Response::Abort {
            message: format!("handoff aborted before READY: {}", cause.report()),
        },
    );
    match abort {
        Ok(()) => {
            pending.abort();
            false
        }
        Err(abort_err) if successor.confirm_exited(CONTROL_RESPONSE_TIMEOUT) => {
            warn!(
                "fuse handoff successor exited before abort delivery completed: {}",
                abort_err.report()
            );
            pending.abort();
            false
        }
        Err(abort_err) => {
            warn!(
                "failed to deliver fuse handoff abort to a potentially live \
                 successor ({}); retiring instead of resuming",
                abort_err.report()
            );
            pending.retire();
            true
        }
    }
}

fn send_transfer_await_ready(
    stream: &mut UnixStream,
    transfer: &SessionTransfer,
    deadline: ProtocolDeadline,
) -> Result<()> {
    write_frame_until(stream, deadline, &Response::HandoffTransfer {})?;
    transfer.send(stream, deadline)?;
    match read_frame_until(stream, deadline)? {
        Some(Request::Ready {}) => Ok(()),
        Some(other) => Err(Error::Protocol(format!(
            "unexpected readiness request: {other:?}"
        ))),
        None => Err(Error::Protocol(
            "successor closed before reporting readiness".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    use super::*;
    use crate::fuse::upgrade::test_support::{parked_runtime_handle, test_deadline};
    use crate::fuse::upgrade::transfer::{receive_opaque_transfer, OpaqueSessionTransfer};

    /// Drives a successor through HANDOFF_BEGIN against a live predecessor
    /// and returns right after receiving the Session Transfer, leaving the
    /// verdict to the caller. The returned tempdir and kernel-side socket are
    /// guards that must live for the whole test: a dropped kernel socket
    /// delivers EOF to the resumed worker loop and kills it.
    fn begin_handoff(
        session_id: u128,
    ) -> (
        tempfile::TempDir,
        UnixStream,
        UnixStream,
        OpaqueSessionTransfer,
        std::thread::JoinHandle<Result<bool>>,
        fuser::BackgroundSession,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let info = InstanceInfo::new("/mnt", &[1; 32]);
        let (handle, background, kernel) =
            parked_runtime_handle(Some(uuid::Uuid::from_u128(session_id)));
        background.pauser().resume();
        let (server, mut successor) = UnixStream::pair().unwrap();
        let server_info = info.clone();
        let handoff =
            std::thread::spawn(move || handle_connection(server, &server_info, &handle, &path));

        write_frame_until(
            &mut successor,
            test_deadline(),
            &Request::HandoffBegin { peer: info },
        )
        .unwrap();
        assert!(matches!(
            read_frame_until::<Response>(&mut successor, test_deadline()).unwrap(),
            Some(Response::HandoffTransfer {})
        ));
        let transfer = receive_opaque_transfer(&mut successor, handoff_deadline()).unwrap();
        (dir, kernel, successor, transfer, handoff, background)
    }

    fn started_server(
        session_id: Option<uuid::Uuid>,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        ControlServer,
        fuser::BackgroundSession,
        UnixStream,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let lock = StartupLock::acquire_in(dir.path(), "/mnt").unwrap();
        let (handle, background, kernel) = parked_runtime_handle(session_id);
        let server =
            ControlServer::start(&path, InstanceInfo::new("/mnt", &[1; 32]), handle, lock).unwrap();
        (dir, path, server, background, kernel)
    }

    #[test]
    fn control_socket_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let _listener = bind_listener(&path).unwrap();
        let mode = std::fs::metadata(path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn startup_refuses_to_unlink_a_non_socket_at_the_control_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a.sock");
        std::fs::write(&path, b"operator data").unwrap();
        let lock = StartupLock::acquire_in(dir.path(), "/mnt").unwrap();
        let (handle, background, _kernel) = parked_runtime_handle(None);

        // bind reports AddrInUse and connect reports ECONNREFUSED for a
        // regular file exactly as they do for a stale socket, so startup must
        // refuse rather than delete whatever the path names.
        let Err(err) =
            ControlServer::start(&path, InstanceInfo::new("/mnt", &[1; 32]), handle, lock)
        else {
            panic!("a non-socket at the control path must not be adopted");
        };
        assert!(
            err.report().to_string().contains("is not a socket"),
            "unexpected error: {err:?}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"operator data");

        background.pauser().exit();
        background.join().unwrap();
    }

    #[test]
    fn info_reports_the_protected_session_identity() {
        let session_id = uuid::Uuid::from_u128(7);
        let (_dir, path, server, background, _kernel) = started_server(Some(session_id));

        let mut client = UnixStream::connect(&path).unwrap();
        write_frame_until(&mut client, test_deadline(), &Request::Info {}).unwrap();
        match read_frame_until::<Response>(&mut client, test_deadline()).unwrap() {
            Some(Response::Info {
                session_id: reported,
                ..
            }) => assert_eq!(reported, Some(session_id)),
            response => panic!("unexpected INFO response: {response:?}"),
        }

        drop(server);
        background.pauser().exit();
        background.join().unwrap();
    }

    #[test]
    fn malformed_control_requests_do_not_retire_the_serving_daemon() {
        let (_dir, path, server, background, _kernel) = started_server(None);

        for request in [
            0u32.to_le_bytes().to_vec(),
            (4u32 * 1024 * 1024 + 1).to_le_bytes().to_vec(),
            [1u32.to_le_bytes().as_slice(), b"{"].concat(),
            [2u32.to_le_bytes().as_slice(), b"{"].concat(),
        ] {
            let mut client = UnixStream::connect(&path).unwrap();
            client.write_all(&request).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            assert!(matches!(
                read_frame_until::<Response>(&mut client, test_deadline()).unwrap(),
                Some(Response::Error { .. })
            ));
            drop(client);

            let peer = (0..20).find_map(|_| {
                let peer = super::super::probe_existing_instance(&path).ok().flatten();
                if peer.is_none() {
                    std::thread::sleep(Duration::from_millis(5));
                }
                peer
            });
            assert!(peer.is_some(), "malformed request retired control server");
        }

        drop(server);
        background.pauser().exit();
        background.join().unwrap();
    }

    #[test]
    fn complete_ready_reports_commit_and_retires_predecessor() {
        let (_dir, _kernel, mut successor, transfer, handoff, background) = begin_handoff(9);

        write_frame_until(&mut successor, test_deadline(), &Request::Ready {}).unwrap();
        assert!(matches!(
            read_frame_until::<Response>(&mut successor, test_deadline()).unwrap(),
            Some(Response::Committed {})
        ));
        assert!(
            read_frame_until::<Response>(&mut successor, test_deadline())
                .unwrap()
                .is_none()
        );
        assert!(handoff.join().unwrap().unwrap());

        drop(transfer);
        background.join().unwrap();
    }

    #[test]
    fn explicit_abort_before_ready_resumes_the_predecessor() {
        let (_dir, _kernel, mut successor, transfer, handoff, background) = begin_handoff(10);

        write_frame_until(&mut successor, test_deadline(), &Request::Info {}).unwrap();
        assert!(matches!(
            read_frame_until::<Response>(&mut successor, test_deadline()).unwrap(),
            Some(Response::Abort { .. })
        ));
        assert!(!handoff.join().unwrap().unwrap());
        assert!(!background.pauser().is_paused());

        drop(transfer);
        background.pauser().exit();
        background.join().unwrap();
    }

    #[test]
    fn undeliverable_abort_to_a_live_successor_retires_the_predecessor() {
        let (_dir, _kernel, successor, transfer, handoff, background) = begin_handoff(11);

        drop(successor);
        assert!(handoff.join().unwrap().unwrap());

        drop(transfer);
        background.join().unwrap();
    }
}
