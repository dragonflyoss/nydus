use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;

use nydus_error::{Context, Error, Result};
use tracing::warn;
use uuid::Uuid;

use super::super::transfer::SessionTransfer;
use super::super::wire::{read_frame_until, write_frame_until, ProtocolDeadline};
use super::super::CONTROL_RESPONSE_TIMEOUT;
use super::identity::{authenticate_peer, InstanceInfo, PeerProcess};
use super::lifecycle::handoff_deadline;
use super::protocol::{Request, Response};

struct ControlClient {
    stream: UnixStream,
    peer_pid: u32,
    peer_process: PeerProcess,
}

pub(in crate::fuse::upgrade) struct ServingInstance {
    pub(in crate::fuse::upgrade) info: InstanceInfo,
    pub(in crate::fuse::upgrade) session_id: Option<Uuid>,
}

impl ServingInstance {
    pub(in crate::fuse::upgrade) fn is_failover_protected(&self) -> bool {
        self.session_id.is_some()
    }
}

pub(in crate::fuse::upgrade) fn probe_existing_instance(
    path: &Path,
) -> Result<Option<ServingInstance>> {
    let mut client = match ControlClient::connect(path) {
        Ok(client) => client,
        Err(err) => {
            return match err.io_error().map(io::Error::kind) {
                Some(io::ErrorKind::NotFound) | Some(io::ErrorKind::ConnectionRefused) => Ok(None),
                _ => Err(err),
            }
        }
    };
    let (info, session_id) = client.info_until(ControlClient::info_deadline())?;
    Ok(Some(ServingInstance { info, session_id }))
}

pub(in crate::fuse::upgrade) fn begin_handoff(path: &Path, me: &InstanceInfo) -> Result<Handoff> {
    let client = ControlClient::connect(path)
        .context("the predecessor stopped answering while this process was preparing")?;
    client.begin_handoff(me).context("fuse handoff failed")
}

impl ControlClient {
    fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path)
            .with_context(|| format!("failed to connect control socket {}", path.display()))?;
        let peer_pid = authenticate_peer(&stream)
            .with_context(|| format!("failed to authenticate control socket {}", path.display()))?;
        let peer_process = PeerProcess::observe(peer_pid);
        Ok(Self {
            stream,
            peer_pid,
            peer_process,
        })
    }

    fn info_deadline() -> ProtocolDeadline {
        ProtocolDeadline::after(CONTROL_RESPONSE_TIMEOUT, "fuse control INFO transaction")
    }

    fn info_until(&mut self, deadline: ProtocolDeadline) -> Result<(InstanceInfo, Option<Uuid>)> {
        write_frame_until(&mut self.stream, deadline, &Request::Info {})?;
        match read_frame_until(&mut self.stream, deadline)? {
            Some(Response::Info { info, session_id }) => {
                info.check_pid(self.peer_pid).map_err(Error::Protocol)?;
                Ok((info, session_id))
            }
            Some(Response::Error { message }) => Err(Error::Protocol(message)),
            Some(other) => Err(Error::Protocol(format!(
                "unexpected INFO response: {other:?}"
            ))),
            None => Err(Error::Protocol(
                "control connection closed during INFO".to_string(),
            )),
        }
    }

    /// Retains the INFO Session Identity so the predecessor's
    /// [`SessionTransfer`] can be validated against it before adoption.
    fn begin_handoff(mut self, me: &InstanceInfo) -> Result<Handoff> {
        if !self.peer_process.can_terminate() {
            return Err(Error::Runtime(
                "hot upgrade requires pidfd process control to resolve cutover ownership"
                    .to_string(),
            ));
        }
        let (peer, session_id) = self.info_until(Self::info_deadline())?;
        me.check(&peer).map_err(Error::InvalidParameter)?;
        let deadline = handoff_deadline();
        write_frame_until(
            &mut self.stream,
            deadline,
            &Request::HandoffBegin { peer: me.clone() },
        )?;
        let transfer = match read_frame_until(&mut self.stream, deadline)? {
            Some(Response::HandoffTransfer {}) => {
                let session_id = session_id.ok_or_else(|| {
                    Error::Protocol(
                        "predecessor sent a protected handoff without an INFO session identity"
                            .to_string(),
                    )
                })?;
                SessionTransfer::receive(&mut self.stream, deadline, session_id, me)?
            }
            Some(Response::Error { message }) => return Err(Error::Runtime(message)),
            Some(other) => {
                return Err(Error::Protocol(format!(
                    "unexpected HANDOFF_BEGIN response: {other:?}"
                )))
            }
            None => {
                return Err(Error::Protocol(
                    "control connection closed during HANDOFF_BEGIN".to_string(),
                ))
            }
        };
        Ok(Handoff {
            transfer: Some(transfer),
            client: self,
            deadline,
        })
    }
}

pub(in crate::fuse::upgrade) struct Handoff {
    transfer: Option<SessionTransfer>,
    client: ControlClient,
    deadline: ProtocolDeadline,
}

impl Handoff {
    pub(in crate::fuse::upgrade) fn take_transfer(&mut self) -> SessionTransfer {
        self.transfer.take().expect("session transfer taken once")
    }

    pub(in crate::fuse::upgrade) fn remaining(&self) -> Result<std::time::Duration> {
        Ok(self.deadline.remaining()?)
    }

    pub(in crate::fuse::upgrade) fn commit(mut self) -> Result<()> {
        self.commit_with_timeout(CONTROL_RESPONSE_TIMEOUT)
    }

    fn commit_with_timeout(&mut self, timeout: std::time::Duration) -> Result<()> {
        if self.transfer.is_some() {
            return Err(Error::InvalidParameter(
                "cannot commit FUSE handoff before taking the session transfer".to_string(),
            ));
        }
        write_frame_until(&mut self.client.stream, self.deadline, &Request::Ready {})
            .context("failed to send READY")?;

        loop {
            let cutover = ProtocolDeadline::after(timeout, "fuse handoff cutover completion");
            match read_frame_until::<Response>(&mut self.client.stream, cutover) {
                Ok(Some(Response::Committed {})) => return Ok(()),
                Ok(Some(Response::Abort { message })) => return Err(Error::Runtime(message)),
                outcome => {
                    warn!("ambiguous fuse handoff cutover: {outcome:?}");
                    match self
                        .client
                        .peer_process
                        .terminate_and_confirm(CONTROL_RESPONSE_TIMEOUT)
                    {
                        Ok(true) => return Ok(()),
                        Ok(false) => {}
                        Err(err) => warn!("failed to retire fuse predecessor: {err}"),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Shutdown;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixListener;

    use super::*;
    use crate::fuse::upgrade::test_support::{fuse_init_state, test_deadline};
    use crate::fuse::upgrade::transfer::{send_opaque_transfer, SessionTransferMetadata};
    use crate::fuse::upgrade::STANDALONE_UPGRADE_ERROR;

    fn incoming_handoff(stream: UnixStream, deadline: ProtocolDeadline) -> Handoff {
        Handoff {
            transfer: None,
            client: ControlClient {
                stream,
                peer_pid: std::process::id(),
                peer_process: PeerProcess::Untracked,
            },
            deadline,
        }
    }

    /// Runs a predecessor control endpoint that answers INFO with the given
    /// Session Identity, expects HANDOFF_BEGIN, and lets `respond` deliver
    /// the predecessor's verdict on it.
    fn predecessor_endpoint(
        session_id: Option<Uuid>,
        respond: impl FnOnce(&mut UnixStream, &InstanceInfo) + Send + 'static,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        InstanceInfo,
        std::thread::JoinHandle<()>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let me = InstanceInfo::new("/mnt/protected", &[0x22; 32]);
        let info = me.clone();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert!(matches!(
                read_frame_until::<Request>(&mut stream, test_deadline()).unwrap(),
                Some(Request::Info {})
            ));
            write_frame_until(
                &mut stream,
                test_deadline(),
                &Response::Info {
                    info: info.clone(),
                    session_id,
                },
            )
            .unwrap();

            assert!(matches!(
                read_frame_until::<Request>(&mut stream, test_deadline()).unwrap(),
                Some(Request::HandoffBegin { .. })
            ));
            respond(&mut stream, &info);
        });
        (dir, path, me, server)
    }

    #[test]
    fn ready_write_failure_does_not_cut_over() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        stream.shutdown(Shutdown::Write).unwrap();

        assert!(incoming_handoff(stream, handoff_deadline())
            .commit()
            .is_err());
    }

    #[test]
    fn ambiguous_cutover_retires_a_tracked_predecessor() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("10")
            .spawn()
            .unwrap();
        let mut handoff = incoming_handoff(stream, handoff_deadline());
        handoff.client.peer_process = PeerProcess::observe(child.id());
        let server = std::thread::spawn(move || {
            assert!(matches!(
                read_frame_until::<Request>(&mut peer, test_deadline()).unwrap(),
                Some(Request::Ready {})
            ));
            std::thread::sleep(std::time::Duration::from_millis(40));
        });

        handoff
            .commit_with_timeout(std::time::Duration::from_millis(10))
            .unwrap();
        child.wait().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn untracked_predecessor_is_rejected_before_handoff() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let client = incoming_handoff(stream, handoff_deadline()).client;
        let error = client
            .begin_handoff(&InstanceInfo::new("/mnt", &[1; 32]))
            .err()
            .expect("untracked predecessor must be rejected");
        assert!(error.report().to_string().contains("pidfd"));
    }

    #[test]
    fn explicit_abort_before_cutover_rejects_the_handoff() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            assert!(matches!(
                read_frame_until::<Request>(&mut peer, test_deadline()).unwrap(),
                Some(Request::Ready {})
            ));
            write_frame_until(
                &mut peer,
                test_deadline(),
                &Response::Abort {
                    message: "pre-cutover failure".to_string(),
                },
            )
            .unwrap();
        });

        let error = incoming_handoff(stream, handoff_deadline())
            .commit()
            .expect_err("successor must not resume after an explicit abort");
        assert!(error.report().to_string().contains("pre-cutover failure"));
        server.join().unwrap();
    }

    #[test]
    fn protected_handoff_rejects_transfer_metadata_that_disagrees_with_info() {
        // INFO advertises the protected Session Identity and canonical
        // instance fields; the received Session Transfer contains a different
        // identity. The successor rejects it before adoption.
        let (_dir, path, me, server) =
            predecessor_endpoint(Some(Uuid::from_u128(11)), |stream, info| {
                write_frame_until(stream, test_deadline(), &Response::HandoffTransfer {}).unwrap();

                let metadata = SessionTransferMetadata {
                    session_id: Uuid::from_u128(12),
                    mountpoint: info.mountpoint.clone(),
                    image_digest: info.image_digest.clone(),
                    fuse_session_state: fuse_init_state(),
                };
                let journal = fuser::InflightJournal::create().unwrap();
                let (fuse_sentinel, _fuse_peer) = UnixStream::pair().unwrap();
                send_opaque_transfer(
                    stream,
                    &metadata.encode().unwrap(),
                    [fuse_sentinel.as_fd(), journal.as_fd()],
                    test_deadline(),
                )
                .unwrap();
            });

        let error = begin_handoff(&path, &me)
            .err()
            .expect("mismatched session transfer must be rejected before adoption");
        assert!(
            error.report().to_string().contains("session"),
            "unexpected error: {error:?}"
        );
        server.join().unwrap();
    }

    #[test]
    fn handoff_begin_rejects_a_standalone_predecessor() {
        let (_dir, path, me, server) = predecessor_endpoint(None, |stream, _| {
            write_frame_until(
                stream,
                test_deadline(),
                &Response::Error {
                    message: STANDALONE_UPGRADE_ERROR.to_string(),
                },
            )
            .unwrap();
        });

        let error = begin_handoff(&path, &me)
            .err()
            .expect("a Standalone Session predecessor must be rejected");
        assert!(
            error.report().to_string().contains("Standalone Session"),
            "unexpected error: {error:?}"
        );
        server.join().unwrap();
    }
}
