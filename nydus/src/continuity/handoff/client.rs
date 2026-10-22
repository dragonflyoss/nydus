use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use nydus_error::{Context, Error, Result};
use serde::de::IgnoredAny;
use tracing::{info, warn};
use uuid::Uuid;

use super::protocol::{Request, Response};
use crate::api_server::{is_control_upgrade, ControlProtocol};
use crate::continuity::peer::{authenticate_peer, PeerProcess};
use crate::continuity::wire::{
    connect_until, read_frame_until, write_frame_until, DeadlineStream, ProtocolDeadline, Transfer,
};
use crate::continuity::{Identity, Mode, CONTROL_RESPONSE_TIMEOUT, HANDOFF_TIMEOUT};

const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;

struct ControlClient {
    stream: UnixStream,
    peer_pid: u32,
    peer_process: PeerProcess,
}

pub(crate) struct Peer<I> {
    client: ControlClient,
    pub(crate) info: I,
    pub(crate) session_id: Option<Uuid>,
}

/// Interrupted discovery permits an ownership recheck, never bypassing its lifetime lock.
pub(crate) fn probe<I: Identity>(path: &Path, me: &I) -> Result<Option<Peer<I>>> {
    let deadline = ProtocolDeadline::after(CONTROL_RESPONSE_TIMEOUT, "control INFO transaction");
    let result = (|| {
        let mut client = ControlClient::connect(path, I::CONTROL, deadline)?;
        if !client.peer_process.can_terminate() {
            return Err(Error::Runtime(
                "hot upgrade requires pidfd process control to resolve handoff ownership".into(),
            ));
        }
        write_frame_until(&mut client.stream, deadline, &Request::<I>::Info {})?;
        match read_frame_until(&mut client.stream, deadline)? {
            Some(Response::Info { info, session_id }) => {
                let info: I = info;
                info.check_pid(client.peer_pid)?;
                me.check(&info)?;
                Ok(Peer {
                    client,
                    info,
                    session_id,
                })
            }
            Some(Response::Error { message }) => Err(Error::Protocol(message)),
            Some(other) => Err(Error::Protocol(format!(
                "unexpected INFO response: {other:?}"
            ))),
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "control connection closed during INFO",
            )
            .into()),
        }
    })();
    match result {
        Ok(peer) => Ok(Some(peer)),
        Err(err) if interrupted_transport(&err) => {
            warn!(
                "direct handoff unavailable; checking ownership: {}",
                err.report()
            );
            Ok(None)
        }
        Err(err) => Err(err).context("handoff rejected"),
    }
}

fn interrupted_transport(err: &Error) -> bool {
    err.io_error().is_some_and(|err| {
        matches!(
            err.kind(),
            io::ErrorKind::NotFound
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::UnexpectedEof
                | io::ErrorKind::TimedOut
                | io::ErrorKind::WouldBlock
        )
    })
}

pub(crate) fn upgrade_control_client(
    mut stream: UnixStream,
    protocol: ControlProtocol,
    deadline: ProtocolDeadline,
) -> Result<UnixStream> {
    let mut connection = DeadlineStream {
        stream: &mut stream,
        deadline,
    };
    write!(
        connection,
        "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: {}\r\n\r\n",
        protocol.path, protocol.token,
    )?;
    // Stop at the terminator: subsequent descriptor-bearing bytes require recvmsg.
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() == MAX_HTTP_HEADER_BYTES {
            return Err(Error::Protocol("control HTTP header exceeds 16 KiB".into()));
        }
        let mut byte = [0];
        connection.read_exact(&mut byte)?;
        header.push(byte[0]);
    }
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut reply = httparse::Response::new(&mut headers);
    let parsed = reply
        .parse(&header)
        .map_err(|err| Error::Protocol(format!("invalid control HTTP response: {err}")))?;
    if !parsed.is_complete()
        || reply.version != Some(1)
        || reply.code != Some(101)
        || !is_control_upgrade(
            reply.headers.iter().map(|h| (h.name, h.value)),
            protocol.token,
        )
    {
        return Err(Error::Protocol(format!(
            "control HTTP upgrade rejected: status {:?}, expected 101 {}",
            reply.code, protocol.token
        )));
    }
    Ok(stream)
}

impl ControlClient {
    fn connect(path: &Path, protocol: ControlProtocol, deadline: ProtocolDeadline) -> Result<Self> {
        let stream = connect_until(path, deadline)
            .with_context(|| format!("failed to connect control socket {}", path.display()))?;
        let peer_pid = authenticate_peer(&stream)
            .with_context(|| format!("failed to authenticate control socket {}", path.display()))?;
        let peer_process = PeerProcess::observe(peer_pid);
        let stream = upgrade_control_client(stream, protocol, deadline)?;
        Ok(Self {
            stream,
            peer_pid,
            peer_process,
        })
    }
}

impl<I: Identity> Peer<I> {
    /// Returns `None` only when a protected predecessor exited during HANDOFF_BEGIN.
    pub(crate) fn begin(mut self, me: &I) -> Result<Option<Handoff>> {
        let deadline = ProtocolDeadline::after(HANDOFF_TIMEOUT, "handoff transaction");
        let incoming = (|| {
            write_frame_until(
                &mut self.client.stream,
                deadline,
                &Request::HandoffBegin { peer: me },
            )?;
            match (
                I::MODE,
                read_frame_until::<Response<I>>(&mut self.client.stream, deadline)?,
            ) {
                (Mode::Transfer, Some(Response::HandoffTransfer {})) => {
                    Transfer::receive(&mut self.client.stream, deadline).map(Some)
                }
                (Mode::Kernel, Some(Response::Released {})) => Ok(None),
                (_, Some(Response::Error { message })) => Err(Error::Runtime(message)),
                (_, Some(other)) => Err(Error::Protocol(format!(
                    "unexpected HANDOFF_BEGIN response: {other:?}"
                ))),
                (_, None) => Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "control connection closed during HANDOFF_BEGIN",
                )
                .into()),
            }
        })();
        match incoming {
            Ok(transfer) => Ok(Some(Handoff {
                client: self.client,
                deadline,
                awaiting_ready: transfer.is_some(),
                transfer,
            })),
            Err(err)
                if interrupted_transport(&err)
                    && I::protected(self.session_id)
                    && self.client.peer_process.confirm_exited(Duration::ZERO) =>
            {
                warn!(
                    "predecessor exited during handoff; checking ownership: {}",
                    err.report()
                );
                Ok(None)
            }
            Err(err) => {
                Err(err).context("handoff failed after HANDOFF_BEGIN; successor must stand down")
            }
        }
    }
}

/// An accepted HANDOFF_BEGIN. A transfer handoff can still be cancelled until READY;
/// a kernel handoff has already been released by the predecessor.
pub(crate) struct Handoff {
    client: ControlClient,
    deadline: ProtocolDeadline,
    transfer: Option<Transfer>,
    awaiting_ready: bool,
}

impl Handoff {
    pub(crate) fn take_transfer(&mut self) -> Option<Transfer> {
        self.transfer.take()
    }

    pub(crate) fn remaining(&self) -> Result<Duration> {
        Ok(self.deadline.remaining()?)
    }

    /// Returns `true` when the predecessor committed, or `false` when it exited without
    /// a verdict and any inflight state must be recovered.
    pub(crate) fn commit(mut self, check_cancelled: impl Fn() -> Result<()>) -> Result<bool> {
        self.commit_with_timeout(CONTROL_RESPONSE_TIMEOUT, check_cancelled)
    }

    fn commit_with_timeout(
        &mut self,
        timeout: Duration,
        check_cancelled: impl Fn() -> Result<()>,
    ) -> Result<bool> {
        check_cancelled()?;
        if !self.awaiting_ready {
            return Ok(true);
        }
        self.awaiting_ready = false;
        if let Err(err) = write_frame_until(
            &mut self.client.stream,
            self.deadline,
            &Request::<()>::Ready {},
        ) {
            if self.client.peer_process.confirm_exited(timeout) {
                return Ok(false);
            }
            return Err(err).context("failed to send READY; predecessor exit is not confirmed");
        }
        // Once READY is sent, only ABORT permits rollback. Ambiguity requires confirmed exit.
        loop {
            check_cancelled()?;
            let deadline = ProtocolDeadline::after(timeout, "handoff verdict");
            match read_frame_until::<Response<IgnoredAny>>(&mut self.client.stream, deadline) {
                Ok(Some(Response::Committed {})) => return Ok(true),
                Ok(Some(Response::Abort { message })) => return Err(Error::Runtime(message)),
                outcome => {
                    check_cancelled()?;
                    warn!(predecessor_pid = self.client.peer_pid,
                        "ambiguous handoff verdict; successor remains parked until predecessor exit: {outcome:?}");
                    match self
                        .client
                        .peer_process
                        .terminate_and_confirm(CONTROL_RESPONSE_TIMEOUT)
                    {
                        Ok(true) => {
                            info!(
                                predecessor_pid = self.client.peer_pid,
                                "predecessor exit confirmed"
                            );
                            return Ok(false);
                        }
                        Ok(false) => {}
                        Err(err) => {
                            warn!(
                                "failed to terminate predecessor; successor remains parked: {err}"
                            )
                        }
                    }
                }
            }
        }
    }
}

impl Drop for Handoff {
    fn drop(&mut self) {
        if !self.awaiting_ready {
            return;
        }
        // EOF before READY requests the existing ABORT exchange without losing its reply.
        let cancelled = (|| {
            self.client.stream.shutdown(Shutdown::Write)?;
            let deadline =
                ProtocolDeadline::after(CONTROL_RESPONSE_TIMEOUT, "handoff cancellation");
            match read_frame_until::<Response<IgnoredAny>>(&mut self.client.stream, deadline)? {
                Some(Response::Abort { .. }) => Ok(()),
                other => Err(Error::Protocol(format!(
                    "unexpected handoff cancellation response: {other:?}"
                ))),
            }
        })();
        if let Err(err) = cancelled {
            warn!("failed to cancel handoff before READY: {}", err.report());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;
    use crate::continuity::test_support::{
        metrics, ondemand, test_deadline, LiveInfo, TestInfo, TestSession,
    };

    fn handoff(stream: UnixStream, awaiting_ready: bool, peer_process: PeerProcess) -> Handoff {
        Handoff {
            client: ControlClient {
                stream,
                peer_pid: 0,
                peer_process,
            },
            deadline: test_deadline(),
            transfer: None,
            awaiting_ready,
        }
    }

    #[test]
    fn discovery_does_not_treat_http_rejection_as_an_absent_predecessor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let _server = crate::api_server::ApiServer::start(
            &format!("unix://{}", path.display()),
            metrics(),
            ondemand(),
        )
        .unwrap();
        let error = probe(&path, &LiveInfo::new()).err().unwrap();
        assert!(error.report().to_string().contains("404"));
        assert!(!interrupted_transport(&error));
    }

    #[test]
    fn ready_write_failure_only_recovers_after_confirmed_exit() {
        for exited in [false, true] {
            let (stream, _peer) = UnixStream::pair().unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
            let peer = if exited {
                PeerProcess::Exited
            } else {
                PeerProcess::Untracked
            };
            let result = handoff(stream, true, peer).commit_with_timeout(Duration::ZERO, || Ok(()));
            if exited {
                assert!(!result.unwrap());
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn released_handoff_commits_without_ready() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        assert!(handoff(stream, false, PeerProcess::Untracked)
            .commit(|| Ok(()))
            .unwrap());
        assert!(
            read_frame_until::<Request<LiveInfo>>(&mut peer, test_deadline())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn explicit_abort_stands_down_but_ambiguous_verdict_requires_exit() {
        for abort in [true, false] {
            let (stream, mut peer) = UnixStream::pair().unwrap();
            let mut child = Command::new("sleep").arg("10").spawn().unwrap();
            let process = PeerProcess::observe(child.id());
            let server = std::thread::spawn(move || {
                assert!(matches!(
                    read_frame_until::<Request<LiveInfo>>(&mut peer, test_deadline()).unwrap(),
                    Some(Request::Ready {})
                ));
                if abort {
                    write_frame_until(
                        &mut peer,
                        test_deadline(),
                        &Response::<()>::Abort {
                            message: "stop".into(),
                        },
                    )
                    .unwrap();
                }
            });
            let result = handoff(stream, true, process).commit(|| Ok(()));
            server.join().unwrap();
            if abort {
                assert!(result.is_err());
                child.kill().unwrap();
            } else {
                assert!(!result.unwrap());
            }
            child.wait().unwrap();
        }
    }

    #[test]
    fn dropping_a_prepared_handoff_resumes_the_predecessor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let info = LiveInfo::new();
        let session = TestSession::<false>::default();
        let server = super::super::ControlServer::start(
            &path,
            info.clone(),
            session.clone(),
            metrics(),
            ondemand(),
        )
        .unwrap();
        let handoff = probe(&path, &info).unwrap().unwrap().begin(&info).unwrap();
        assert!(handoff.is_some_and(|handoff| handoff.transfer.is_some()));
        drop(server);
        assert!(!session.lifecycle.is_released());
        assert_eq!(*session.events.lock().unwrap(), ["prepare", "resume"]);
    }

    #[test]
    fn cancellation_after_ready_does_not_claim_cutover() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let checks = std::cell::Cell::new(0);
        let result = handoff(stream, true, PeerProcess::Untracked).commit(|| {
            checks.set(checks.get() + 1);
            if checks.get() > 1 {
                Err(Error::Runtime("startup cancelled".into()))
            } else {
                Ok(())
            }
        });
        assert!(result.is_err());
        assert!(matches!(
            read_frame_until::<Request<LiveInfo>>(&mut peer, test_deadline()).unwrap(),
            Some(Request::Ready {})
        ));
    }

    fn interrupted_begin<const KERNEL: bool>(protected: bool, exited: bool) -> Result<bool> {
        let info = TestInfo::<KERNEL>::new();
        let (stream, _other) = UnixStream::pair().unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let peer = Peer {
            client: ControlClient {
                stream,
                peer_pid: 0,
                peer_process: if exited {
                    PeerProcess::Exited
                } else {
                    PeerProcess::Untracked
                },
            },
            info: info.clone(),
            session_id: protected.then(|| Uuid::from_u128(1)),
        };
        peer.begin(&info).map(|handoff| handoff.is_none())
    }

    #[test]
    fn interrupted_begin_requires_recoverable_state_and_confirmed_exit() {
        assert!(interrupted_begin::<false>(false, true).is_err());
        assert!(interrupted_begin::<false>(true, true).unwrap());
        assert!(interrupted_begin::<true>(false, true).unwrap());
        assert!(interrupted_begin::<true>(false, false).is_err());
    }
}
