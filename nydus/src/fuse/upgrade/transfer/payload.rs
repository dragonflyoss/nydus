use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use nydus_error::{Context, Error, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::super::handoff::InstanceInfo;
use super::super::wire::{
    read_raw_frame_until, recv_fds_exact_until, send_fds_until, write_raw_frame_until,
    ProtocolDeadline,
};
use super::state::FuseInitState;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(in crate::fuse) struct SessionTransferMetadata {
    pub(in crate::fuse) session_id: Uuid,
    pub(in crate::fuse) mountpoint: String,
    pub(in crate::fuse) image_digest: String,
    pub(in crate::fuse) fuse_session_state: FuseInitState,
}

impl SessionTransferMetadata {
    pub(in crate::fuse) fn encode(&self) -> Result<Vec<u8>> {
        self.validate().map_err(Error::Protocol)?;
        Ok(serde_json::to_vec(self)?)
    }

    pub(in crate::fuse) fn decode(bytes: &[u8]) -> Result<Self> {
        // Unknown optional metadata is compatible: the required fields and
        // the two-descriptor order are the frozen ABI, and evolution is
        // additive only.
        let metadata: Self = serde_json::from_slice(bytes).map_err(|err| {
            Error::Protocol(format!("malformed session transfer metadata JSON: {err}"))
        })?;
        metadata.validate().map_err(Error::Protocol)?;
        Ok(metadata)
    }

    fn validate(&self) -> std::result::Result<(), String> {
        if self.session_id.is_nil() {
            return Err("session transfer metadata has a nil session identity".to_string());
        }
        if !Path::new(&self.mountpoint).is_absolute() {
            return Err("session transfer metadata mountpoint is not absolute".to_string());
        }
        if self.image_digest.len() != 64
            || !self
                .image_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("session transfer metadata image digest is not SHA-256 hex".to_string());
        }
        self.fuse_session_state.validate()?;
        Ok(())
    }

    fn check_expected(
        &self,
        session_id: Option<Uuid>,
        expected: &InstanceInfo,
    ) -> std::result::Result<(), String> {
        if let Some(session_id) = session_id {
            if self.session_id != session_id {
                return Err(format!(
                    "session transfer returned session {}, expected {session_id}",
                    self.session_id
                ));
            }
        }
        if self.mountpoint != expected.mountpoint {
            return Err(format!(
                "session transfer mountpoint mismatch: transfer uses {}, expected {}",
                self.mountpoint, expected.mountpoint
            ));
        }
        if self.image_digest != expected.image_digest {
            return Err(format!(
                "session transfer image content mismatch: transfer {}, expected {}",
                self.image_digest, expected.image_digest
            ));
        }
        Ok(())
    }
}

pub struct SessionTransfer {
    metadata: SessionTransferMetadata,
    fuse_fd: OwnedFd,
    journal: fuser::InflightJournal,
}

impl SessionTransfer {
    pub(super) fn capture(
        info: &InstanceInfo,
        session_id: Uuid,
        fuse_session_state: &FuseInitState,
        fuse_fd: BorrowedFd<'_>,
        journal: &fuser::InflightJournal,
    ) -> Result<Self> {
        let metadata = SessionTransferMetadata {
            session_id,
            mountpoint: info.mountpoint.clone(),
            image_digest: info.image_digest.clone(),
            fuse_session_state: fuse_session_state.clone(),
        };
        metadata.validate().map_err(Error::Protocol)?;
        let fuse_fd = fuse_fd
            .try_clone_to_owned()
            .context("failed to duplicate session transfer FUSE descriptor")?;
        Ok(Self {
            metadata,
            fuse_fd,
            journal: journal.clone(),
        })
    }

    pub(super) fn session_id(&self) -> Uuid {
        self.metadata.session_id
    }

    pub(super) fn send(&self, stream: &mut UnixStream, deadline: ProtocolDeadline) -> Result<()> {
        let metadata = self.metadata.encode()?;
        send_opaque_transfer(
            stream,
            &metadata,
            [self.fuse_fd.as_fd(), self.journal.as_fd()],
            deadline,
        )
    }

    pub(super) fn receive(
        stream: &mut UnixStream,
        deadline: ProtocolDeadline,
        session_id: Uuid,
        expected: &InstanceInfo,
    ) -> Result<Self> {
        Self::receive_expected(stream, deadline, Some(session_id), expected)
    }

    pub(super) fn receive_retained(
        stream: &mut UnixStream,
        deadline: ProtocolDeadline,
        expected: &InstanceInfo,
    ) -> Result<Self> {
        Self::receive_expected(stream, deadline, None, expected)
    }

    fn receive_expected(
        stream: &mut UnixStream,
        deadline: ProtocolDeadline,
        session_id: Option<Uuid>,
        expected: &InstanceInfo,
    ) -> Result<Self> {
        let opaque = receive_opaque_transfer(stream, deadline)?;
        let metadata = SessionTransferMetadata::decode(&opaque.metadata)
            .context("failed to decode session transfer metadata")?;
        metadata
            .check_expected(session_id, expected)
            .map_err(Error::Protocol)?;
        let [fuse_fd, journal_fd] = opaque.fds;
        let journal = fuser::InflightJournal::from_fd(journal_fd)
            .context("failed to import session transfer inflight journal")?;
        validate_fuse_connection(fuse_fd.as_fd())
            .context("session transfer FUSE connection is unusable")?;
        Ok(Self {
            metadata,
            fuse_fd,
            journal,
        })
    }

    pub(in crate::fuse) fn into_adoption(
        self,
    ) -> (SessionTransferMetadata, OwnedFd, FuseFailoverSession) {
        let failover = FuseFailoverSession {
            session_id: self.metadata.session_id,
            journal: self.journal,
        };
        (self.metadata, self.fuse_fd, failover)
    }
}

#[derive(Clone)]
pub(in crate::fuse) struct FuseFailoverSession {
    pub(in crate::fuse) session_id: Uuid,
    pub(in crate::fuse) journal: fuser::InflightJournal,
}

impl FuseFailoverSession {
    pub(in crate::fuse) fn create() -> std::io::Result<Self> {
        Ok(Self {
            session_id: Uuid::new_v4(),
            journal: fuser::InflightJournal::create()?,
        })
    }
}

pub(super) struct OpaqueSessionTransfer {
    pub metadata: Vec<u8>,
    pub fds: [OwnedFd; 2],
}

pub(super) fn send_opaque_transfer(
    stream: &mut UnixStream,
    metadata: &[u8],
    fds: [BorrowedFd<'_>; 2],
    deadline: ProtocolDeadline,
) -> Result<()> {
    write_raw_frame_until(stream, deadline, metadata)
        .context("failed to send session transfer metadata")?;
    send_fds_until(stream, &fds, deadline)
        .context("failed to send session transfer descriptors")?;
    Ok(())
}

pub(super) fn receive_opaque_transfer(
    stream: &mut UnixStream,
    deadline: ProtocolDeadline,
) -> Result<OpaqueSessionTransfer> {
    let metadata = read_raw_frame_until(stream, deadline)?
        .ok_or_else(|| Error::Protocol("session transfer closed before metadata".to_string()))?;
    let fds = recv_fds_exact_until(stream, 2, deadline)
        .context("failed to receive session transfer descriptors")?;
    let fds: [OwnedFd; 2] = fds
        .try_into()
        .map_err(|_| Error::Protocol("session transfer descriptor count changed".to_string()))?;
    Ok(OpaqueSessionTransfer { metadata, fds })
}

pub(in crate::fuse) fn validate_fuse_connection(fd: BorrowedFd<'_>) -> std::io::Result<()> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFCHR
        || libc::major(stat.st_rdev) != 10
        || libc::minor(stat.st_rdev) != 229
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "descriptor is not the /dev/fuse character device",
        ));
    }

    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if flags & libc::O_ACCMODE != libc::O_RDWR {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "/dev/fuse descriptor is not open for reading and writing",
        ));
    }
    if crate::fuse::mount::connection_dead(fd) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "/dev/fuse descriptor no longer has a live kernel connection",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use uuid::Uuid;

    use super::*;
    use crate::fuse::upgrade::wire::{send_fds_until, ProtocolDeadline};

    fn deadline() -> ProtocolDeadline {
        ProtocolDeadline::after(Duration::from_secs(5), "session transfer test")
    }

    fn metadata() -> SessionTransferMetadata {
        SessionTransferMetadata {
            session_id: Uuid::from_u128(1),
            mountpoint: "/mnt/nydus".to_string(),
            image_digest: "01".repeat(32),
            fuse_session_state: FuseInitState {
                proto_major: 7,
                proto_minor: 31,
                negotiated_init_flags: 0,
                kernel_init_flags: 0,
            },
        }
    }

    fn stat(fd: BorrowedFd<'_>) -> libc::stat {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        assert_eq!(unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) }, 0);
        unsafe { stat.assume_init() }
    }

    fn assert_same_file(actual: BorrowedFd<'_>, expected: BorrowedFd<'_>) {
        let actual = stat(actual);
        let expected = stat(expected);
        assert_eq!(actual.st_dev, expected.st_dev);
        assert_eq!(actual.st_ino, expected.st_ino);
    }

    fn assert_cloexec(fds: &[std::os::fd::OwnedFd]) {
        for fd in fds {
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
            assert_ne!(flags, -1);
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
        }
    }

    #[test]
    fn metadata_round_trip_rejects_missing_required_and_tolerates_additions() {
        let metadata = metadata();
        let encoded = metadata.encode().unwrap();
        let json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(SessionTransferMetadata::decode(&encoded).unwrap(), metadata);

        let mut missing = json.clone();
        missing.as_object_mut().unwrap().remove("session_id");
        assert!(SessionTransferMetadata::decode(&serde_json::to_vec(&missing).unwrap()).is_err());

        let mut extended = json;
        extended["optional_extension"] = serde_json::json!(true);
        assert!(SessionTransferMetadata::decode(&serde_json::to_vec(&extended).unwrap()).is_ok());
    }

    #[test]
    fn opaque_transfer_preserves_metadata_descriptor_order_and_cloexec() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let first = tempfile::tempfile().unwrap();
        let second = tempfile::tempfile().unwrap();
        send_opaque_transfer(
            &mut sender,
            b"{\"opaque\":true}",
            [first.as_fd(), second.as_fd()],
            deadline(),
        )
        .unwrap();
        let received = receive_opaque_transfer(&mut receiver, deadline()).unwrap();
        assert_eq!(received.metadata, b"{\"opaque\":true}");
        assert_same_file(received.fds[0].as_fd(), first.as_fd());
        assert_same_file(received.fds[1].as_fd(), second.as_fd());
        assert_cloexec(&received.fds);
    }

    #[test]
    fn opaque_transfer_rejects_the_wrong_descriptor_count() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        write_raw_frame_until(&mut sender, deadline(), b"{\"opaque\":true}").unwrap();
        let (sentinel, mut peer) = UnixStream::pair().unwrap();
        send_fds_until(&sender, &[sentinel.as_fd()], deadline()).unwrap();
        drop(sentinel);

        let error = receive_opaque_transfer(&mut receiver, deadline())
            .err()
            .expect("wrong descriptor count must be rejected");
        assert_eq!(
            error.io_error().map(std::io::Error::kind),
            Some(std::io::ErrorKind::InvalidData)
        );

        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(peer.read(&mut byte).unwrap(), 0);
    }
}
