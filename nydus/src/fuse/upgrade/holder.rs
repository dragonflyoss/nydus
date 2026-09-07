use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use nydus_error::{Context, Error, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::handoff::{authenticate_peer, InstanceInfo, SessionRuntimeHandle};
use super::transfer::SessionTransfer;
#[cfg(test)]
use super::transfer::{receive_opaque_transfer, send_opaque_transfer, SessionTransferMetadata};
#[cfg(test)]
use super::wire::write_frame_until;
use super::wire::{read_frame_until, ProtocolDeadline};

const HOLDER_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum HolderAcknowledgement {
    Retained {},
    Error { message: String },
}

fn holder_deadline() -> ProtocolDeadline {
    ProtocolDeadline::after(HOLDER_TIMEOUT, "FUSE Recovery Holder transaction")
}

fn connect(path: &Path) -> Result<UnixStream> {
    let stream = UnixStream::connect(path).with_context(|| {
        format!(
            "failed to connect Recovery Holder socket {}",
            path.display()
        )
    })?;
    authenticate_peer(&stream).with_context(|| {
        format!(
            "failed to authenticate Recovery Holder socket {}",
            path.display()
        )
    })?;
    Ok(stream)
}

/// Sends a non-destructive copy of the live FUSE Session Transfer to the
/// Recovery Holder and waits until it acknowledges complete retention.
pub(super) fn retain_session_transfer(
    path: &Path,
    info: &InstanceInfo,
    handle: &SessionRuntimeHandle,
) -> Result<Uuid> {
    let transfer = handle.session_transfer(info).map_err(Error::Runtime)?;
    let session_id = transfer.session_id();
    let deadline = holder_deadline();
    let mut stream = connect(path)?;

    transfer
        .send(&mut stream, deadline)
        .context("failed to send FUSE session transfer")?;

    match read_frame_until(&mut stream, deadline)? {
        Some(HolderAcknowledgement::Retained {}) => Ok(session_id),
        Some(HolderAcknowledgement::Error { message }) => Err(Error::Runtime(format!(
            "Recovery Holder rejected FUSE Session Transfer: {message}"
        ))),
        None => Err(Error::Protocol(
            "Recovery Holder closed before acknowledging Session Transfer retention".to_string(),
        )),
    }
}

/// Receives a retained FUSE Session Transfer from the Recovery Holder.
///
/// The Supervisor configures transfer direction before launching this process,
/// so recovery sends no command. The Holder immediately sends descriptor
/// copies and keeps its originals for later attempts.
pub(super) fn receive_retained_session_transfer(
    path: &Path,
    expected: &InstanceInfo,
) -> Result<SessionTransfer> {
    let deadline = holder_deadline();
    let mut stream = connect(path)?;
    SessionTransfer::receive_retained(&mut stream, deadline, expected)
        .context("failed to receive FUSE session transfer")
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::net::UnixListener;

    use super::*;
    use crate::fuse::upgrade::test_support::{
        assert_cloexec, assert_peer_closed, fuse_init_state, parked_runtime_handle,
    };

    fn bind_supervisor_socket() -> (tempfile::TempDir, std::path::PathBuf, UnixListener) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("supervisor.sock");
        let listener = UnixListener::bind(&path).unwrap();
        (dir, path, listener)
    }

    fn recovery_info() -> InstanceInfo {
        InstanceInfo::new("/mnt/recovery", &[0x5a; 32])
    }

    /// Encodes via plain serde so tests can also stream metadata that
    /// `encode` itself would refuse, such as a nil Session Identity.
    fn valid_metadata(session_id: Uuid) -> Vec<u8> {
        let info = recovery_info();
        serde_json::to_vec(&SessionTransferMetadata {
            session_id,
            mountpoint: info.mountpoint.clone(),
            image_digest: info.image_digest.clone(),
            fuse_session_state: fuse_init_state(),
        })
        .unwrap()
    }

    /// Plays a Holder that immediately streams the given Session Transfer to
    /// a recovering instance, and returns the rejection the recovery reports.
    fn rejected_recovery_error(metadata: Vec<u8>, fds: [OwnedFd; 2]) -> String {
        let (_dir, path, listener) = bind_supervisor_socket();
        let holder = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            send_opaque_transfer(
                &mut stream,
                &metadata,
                [fds[0].as_fd(), fds[1].as_fd()],
                holder_deadline(),
            )
            .unwrap();
        });

        let error = receive_retained_session_transfer(&path, &recovery_info())
            .err()
            .expect("recovery must be rejected");
        holder.join().unwrap();
        // Not a tail expression: `report()` borrows `error`, and a temporary
        // at the end of the block would outlive the local it borrows (E0597).
        let message = error.report().to_string();
        message
    }

    #[test]
    fn fresh_session_sends_opaque_transfer_before_holder_acknowledgement() {
        let (_dir, path, listener) = bind_supervisor_socket();
        let session_id = Uuid::from_u128(9);
        let (handle, background, _kernel) = parked_runtime_handle(Some(session_id));

        let holder = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let opaque = receive_opaque_transfer(&mut stream, holder_deadline()).unwrap();
            let metadata = SessionTransferMetadata::decode(&opaque.metadata).unwrap();
            assert_eq!(metadata.session_id, session_id);
            assert_eq!(
                opaque.fds.len(),
                2,
                "fresh protection must transfer exactly two descriptors"
            );
            assert_cloexec(opaque.fds.iter().map(AsFd::as_fd));
            write_frame_until(
                &mut stream,
                holder_deadline(),
                &HolderAcknowledgement::Retained {},
            )
            .unwrap();
        });

        let stored = retain_session_transfer(&path, &recovery_info(), &handle).unwrap();
        assert_eq!(stored, session_id);
        holder.join().unwrap();

        background.pauser().exit();
        background.join().unwrap();
    }

    #[test]
    fn fresh_session_surfaces_holder_rejection() {
        let (_dir, path, listener) = bind_supervisor_socket();
        let (handle, background, _kernel) = parked_runtime_handle(Some(Uuid::from_u128(9)));

        let holder = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = receive_opaque_transfer(&mut stream, holder_deadline()).unwrap();
            write_frame_until(
                &mut stream,
                holder_deadline(),
                &HolderAcknowledgement::Error {
                    message: "retention unavailable".to_string(),
                },
            )
            .unwrap();
        });

        let error = retain_session_transfer(&path, &recovery_info(), &handle)
            .expect_err("a Holder rejection must fail fresh protection");
        assert!(
            error.report().to_string().contains("retention unavailable"),
            "unexpected error: {error:?}"
        );
        holder.join().unwrap();

        background.pauser().exit();
        background.join().unwrap();
    }

    #[test]
    fn recovery_receives_transfer_immediately_and_rejects_invalid_session_identity() {
        let (fuse_sentinel, fuse_peer) = UnixStream::pair().unwrap();
        let (journal_sentinel, journal_peer) = UnixStream::pair().unwrap();

        let error = rejected_recovery_error(
            valid_metadata(Uuid::nil()),
            [fuse_sentinel.into(), journal_sentinel.into()],
        );
        assert!(
            error.contains("nil session identity"),
            "unexpected error: {error}"
        );
        assert_peer_closed(fuse_peer);
        assert_peer_closed(journal_peer);
    }

    #[test]
    fn recovery_rejects_an_unusable_fuse_descriptor_and_closes_received_descriptors() {
        let journal = fuser::InflightJournal::create().unwrap();
        let (invalid_fuse, fuse_peer) = UnixStream::pair().unwrap();

        let error = rejected_recovery_error(
            valid_metadata(Uuid::from_u128(7)),
            [invalid_fuse.into(), journal.try_clone_fd().unwrap()],
        );
        assert!(
            error.contains("/dev/fuse") || error.contains("FUSE connection"),
            "unexpected error: {error}"
        );
        assert_peer_closed(fuse_peer);
    }

    #[test]
    fn recovery_rejects_an_invalid_journal_and_closes_the_fuse_descriptor() {
        let (fuse_sentinel, fuse_peer) = UnixStream::pair().unwrap();
        let invalid_journal = tempfile::tempfile().unwrap();

        let error = rejected_recovery_error(
            valid_metadata(Uuid::from_u128(7)),
            [fuse_sentinel.into(), invalid_journal.into()],
        );
        assert!(
            error.contains("inflight journal"),
            "unexpected error: {error}"
        );
        assert_peer_closed(fuse_peer);
    }
}
