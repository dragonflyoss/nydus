use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use nydus_error::{Context, Error, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::super::identity::InstanceInfo;
use super::super::wire::{
    read_raw_frame_until, recv_fds_exact_until, send_fds_until, write_raw_frame_until,
    ProtocolDeadline,
};
use super::state::FuseInitState;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(in crate::fuse) struct SessionTransferMetadata {
    pub(in crate::fuse) session_id: Option<Uuid>,
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
        // Unknown optional metadata is compatible. A missing or null identity
        // denotes a standalone transfer with no recovery descriptor.
        let metadata: Self = serde_json::from_slice(bytes).map_err(|err| {
            Error::Protocol(format!("malformed session transfer metadata JSON: {err}"))
        })?;
        metadata.validate().map_err(Error::Protocol)?;
        Ok(metadata)
    }

    fn validate(&self) -> std::result::Result<(), String> {
        if self.session_id.is_some_and(|id| id.is_nil()) {
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
            if self.session_id != Some(session_id) {
                return Err(format!(
                    "session transfer returned session {:?}, expected {session_id}",
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

pub(in crate::fuse) struct SessionTransfer {
    metadata: SessionTransferMetadata,
    fuse_fd: OwnedFd,
    protection: SessionProtection,
}

impl SessionTransfer {
    pub(in crate::fuse::upgrade) fn capture(
        info: &InstanceInfo,
        fuse_session_state: &FuseInitState,
        fuse_fd: BorrowedFd<'_>,
        protection: &SessionProtection,
    ) -> Result<Self> {
        let metadata = SessionTransferMetadata {
            session_id: protection.session_id(),
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
            protection: protection.clone(),
        })
    }

    pub(in crate::fuse) fn session_id(&self) -> Option<Uuid> {
        self.metadata.session_id
    }

    pub(in crate::fuse::upgrade) fn send(
        &self,
        stream: &mut UnixStream,
        deadline: ProtocolDeadline,
    ) -> Result<()> {
        let metadata = self.metadata.encode()?;
        let mut fds = vec![self.fuse_fd.as_fd()];
        if let Some(journal) = self.protection.journal() {
            fds.push(journal.as_fd());
        }
        send_opaque_transfer(stream, &metadata, &fds, deadline)
    }

    pub(in crate::fuse::upgrade) fn receive(
        stream: &mut UnixStream,
        deadline: ProtocolDeadline,
        session_id: Option<Uuid>,
        expected: &InstanceInfo,
    ) -> Result<Self> {
        let fd_count = 1 + usize::from(session_id.is_some());
        let opaque = receive_opaque_transfer(stream, fd_count, deadline)?;
        Self::from_opaque(opaque, session_id, expected)
    }

    pub(in crate::fuse::upgrade) fn receive_retained(
        stream: &mut UnixStream,
        deadline: ProtocolDeadline,
        expected: &InstanceInfo,
    ) -> Result<Self> {
        let opaque = receive_opaque_transfer(stream, 2, deadline)?;
        Self::from_opaque(opaque, None, expected)
    }

    fn from_opaque(
        mut opaque: OpaqueSessionTransfer,
        session_id: Option<Uuid>,
        expected: &InstanceInfo,
    ) -> Result<Self> {
        let metadata = SessionTransferMetadata::decode(&opaque.metadata)
            .context("failed to decode session transfer metadata")?;
        metadata
            .check_expected(session_id, expected)
            .map_err(Error::Protocol)?;
        // Handoff derives the count from INFO; Holder recovery always expects
        // two. Bind metadata to that count so neither path can change protection.
        if opaque.fds.len() != 1 + usize::from(metadata.session_id.is_some()) {
            return Err(Error::Protocol(
                "session transfer descriptor count does not match its protection".to_string(),
            ));
        }
        let protection = match metadata.session_id {
            Some(session_id) => SessionProtection::Failover {
                session_id,
                journal: fuser::InflightJournal::from_fd(
                    opaque
                        .fds
                        .pop()
                        .expect("protected transfer has two descriptors"),
                )
                .context("failed to import session transfer inflight journal")?,
            },
            None => SessionProtection::Standalone,
        };
        let fuse_fd = opaque.fds.pop().expect("transfer has a FUSE descriptor");
        validate_fuse_connection(fuse_fd.as_fd())
            .context("session transfer FUSE connection is unusable")?;
        Ok(Self {
            metadata,
            fuse_fd,
            protection,
        })
    }

    pub(in crate::fuse) fn into_adoption(
        self,
    ) -> (SessionTransferMetadata, OwnedFd, SessionProtection) {
        (self.metadata, self.fuse_fd, self.protection)
    }
}

/// Optional crash-failover protection, preserved unchanged across hot upgrade.
#[derive(Clone)]
pub(in crate::fuse) enum SessionProtection {
    /// Supports direct hot upgrade, but has no external crash-recovery escrow.
    Standalone,
    /// Protected by a Recovery Holder escrow.
    Failover {
        session_id: Uuid,
        journal: fuser::InflightJournal,
    },
}

impl SessionProtection {
    /// A fresh Failover-Protected identity with its inflight journal.
    pub(in crate::fuse) fn fresh_failover() -> std::io::Result<Self> {
        Ok(Self::Failover {
            session_id: Uuid::new_v4(),
            journal: fuser::InflightJournal::create()?,
        })
    }

    /// The protected Session Identity advertised by `INFO`.
    pub(in crate::fuse) fn session_id(&self) -> Option<Uuid> {
        match self {
            Self::Standalone => None,
            Self::Failover { session_id, .. } => Some(*session_id),
        }
    }

    /// The inflight journal a session must record into, if any.
    pub(in crate::fuse) fn journal(&self) -> Option<&fuser::InflightJournal> {
        match self {
            Self::Standalone => None,
            Self::Failover { journal, .. } => Some(journal),
        }
    }

    /// Captures the live session without adding or removing failover protection.
    pub(in crate::fuse::upgrade) fn capture_transfer(
        &self,
        info: &InstanceInfo,
        fuse_session_state: &FuseInitState,
        fuse_fd: BorrowedFd<'_>,
    ) -> std::result::Result<SessionTransfer, String> {
        SessionTransfer::capture(info, fuse_session_state, fuse_fd, self)
            .map_err(|err| err.report().to_string())
    }
}

pub(in crate::fuse::upgrade) struct OpaqueSessionTransfer {
    pub metadata: Vec<u8>,
    pub fds: Vec<OwnedFd>,
}

pub(in crate::fuse::upgrade) fn send_opaque_transfer(
    stream: &mut UnixStream,
    metadata: &[u8],
    fds: &[BorrowedFd<'_>],
    deadline: ProtocolDeadline,
) -> Result<()> {
    write_raw_frame_until(stream, deadline, metadata)
        .context("failed to send session transfer metadata")?;
    send_fds_until(stream, fds, deadline).context("failed to send session transfer descriptors")?;
    Ok(())
}

pub(in crate::fuse::upgrade) fn receive_opaque_transfer(
    stream: &mut UnixStream,
    fd_count: usize,
    deadline: ProtocolDeadline,
) -> Result<OpaqueSessionTransfer> {
    let metadata = read_raw_frame_until(stream, deadline)?
        .ok_or_else(|| Error::Protocol("session transfer closed before metadata".to_string()))?;
    let fds = recv_fds_exact_until(stream, fd_count, deadline)
        .context("failed to receive session transfer descriptors")?;
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
    use std::mem::MaybeUninit;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
    use std::os::unix::net::UnixStream;

    use uuid::Uuid;

    use super::*;
    use crate::fuse::upgrade::test_support::{
        assert_cloexec, assert_peer_closed, fuse_init_state, test_deadline,
    };
    use crate::fuse::upgrade::wire::send_fds_until;

    fn metadata() -> SessionTransferMetadata {
        SessionTransferMetadata {
            session_id: Some(Uuid::from_u128(1)),
            mountpoint: "/mnt/nydus".to_string(),
            image_digest: "01".repeat(32),
            fuse_session_state: fuse_init_state(),
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

    #[test]
    fn metadata_round_trip_rejects_missing_required_and_tolerates_additions() {
        let metadata = metadata();
        let encoded = metadata.encode().unwrap();
        let json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(SessionTransferMetadata::decode(&encoded).unwrap(), metadata);

        let mut missing = json.clone();
        missing.as_object_mut().unwrap().remove("mountpoint");
        assert!(SessionTransferMetadata::decode(&serde_json::to_vec(&missing).unwrap()).is_err());

        let mut extended = json;
        extended["optional_extension"] = serde_json::json!(true);
        assert!(SessionTransferMetadata::decode(&serde_json::to_vec(&extended).unwrap()).is_ok());
    }

    #[test]
    fn metadata_allows_no_protection_but_rejects_a_nil_protected_identity() {
        let mut metadata = metadata();
        metadata.session_id = None;
        let mut json = serde_json::to_value(&metadata).unwrap();
        assert!(json["session_id"].is_null());
        assert_eq!(
            SessionTransferMetadata::decode(&metadata.encode().unwrap()).unwrap(),
            metadata
        );
        json.as_object_mut().unwrap().remove("session_id");
        assert_eq!(
            SessionTransferMetadata::decode(&serde_json::to_vec(&json).unwrap()).unwrap(),
            metadata,
        );
        metadata.session_id = Some(Uuid::nil());
        assert!(metadata.encode().is_err());
    }

    #[test]
    fn capture_and_send_preserve_standalone_and_protected_resources() {
        let info = InstanceInfo::new("/mnt/nydus", &[1; 32]);
        let fuse_fd = tempfile::tempfile().unwrap();
        for protection in [
            SessionProtection::Standalone,
            SessionProtection::fresh_failover().unwrap(),
        ] {
            let session_id = protection.session_id();
            let transfer =
                SessionTransfer::capture(&info, &fuse_init_state(), fuse_fd.as_fd(), &protection)
                    .unwrap();
            let (mut sender, mut receiver) = UnixStream::pair().unwrap();
            transfer.send(&mut sender, test_deadline()).unwrap();
            let opaque = receive_opaque_transfer(
                &mut receiver,
                1 + usize::from(session_id.is_some()),
                test_deadline(),
            )
            .unwrap();
            assert_eq!(
                SessionTransferMetadata::decode(&opaque.metadata)
                    .unwrap()
                    .session_id,
                session_id
            );
            assert_same_file(opaque.fds[0].as_fd(), fuse_fd.as_fd());
            if let Some(journal) = protection.journal() {
                assert_same_file(opaque.fds[1].as_fd(), journal.as_fd());
            }
            assert_cloexec(opaque.fds.iter().map(AsFd::as_fd));
            let (_, adopted_fd, adopted_protection) = transfer.into_adoption();
            assert_same_file(adopted_fd.as_fd(), fuse_fd.as_fd());
            assert_eq!(adopted_protection.session_id(), session_id);
            assert_eq!(adopted_protection.journal().is_some(), session_id.is_some());
        }
    }

    #[test]
    fn handoff_rejects_protection_changes_and_closes_received_descriptors() {
        let info = InstanceInfo::new("/mnt/nydus", &[1; 32]);
        for (advertised, transferred) in [
            (None, Some(Uuid::from_u128(1))),
            (Some(Uuid::from_u128(1)), None),
        ] {
            let mut metadata = metadata();
            metadata.session_id = transferred;
            let fd_count = 1 + usize::from(advertised.is_some());
            let (mut sender, mut receiver) = UnixStream::pair().unwrap();
            let (fds, peers): (Vec<_>, Vec<_>) =
                (0..fd_count).map(|_| UnixStream::pair().unwrap()).unzip();
            let borrowed: Vec<_> = fds.iter().map(AsFd::as_fd).collect();
            send_opaque_transfer(
                &mut sender,
                &metadata.encode().unwrap(),
                &borrowed,
                test_deadline(),
            )
            .unwrap();
            drop(fds);
            let error = SessionTransfer::receive(&mut receiver, test_deadline(), advertised, &info)
                .err()
                .expect("handoff must preserve INFO protection");
            let expected_error = if advertised.is_some() {
                "returned session"
            } else {
                "descriptor count does not match its protection"
            };
            assert!(
                error.report().to_string().contains(expected_error),
                "{error:?}"
            );
            for peer in peers {
                assert_peer_closed(peer);
            }
        }
    }

    #[test]
    fn opaque_transfer_preserves_metadata_descriptor_order_and_cloexec() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let first = tempfile::tempfile().unwrap();
        let second = tempfile::tempfile().unwrap();
        send_opaque_transfer(
            &mut sender,
            b"{\"opaque\":true}",
            &[first.as_fd(), second.as_fd()],
            test_deadline(),
        )
        .unwrap();
        let received = receive_opaque_transfer(&mut receiver, 2, test_deadline()).unwrap();
        assert_eq!(received.metadata, b"{\"opaque\":true}");
        assert_same_file(received.fds[0].as_fd(), first.as_fd());
        assert_same_file(received.fds[1].as_fd(), second.as_fd());
        assert_cloexec(received.fds.iter().map(AsFd::as_fd));
    }

    #[test]
    fn opaque_transfer_rejects_the_wrong_descriptor_count() {
        for (expected, actual) in [(1, 2), (2, 1)] {
            let (mut sender, mut receiver) = UnixStream::pair().unwrap();
            write_raw_frame_until(&mut sender, test_deadline(), b"{\"opaque\":true}").unwrap();
            let (fds, peers): (Vec<_>, Vec<_>) =
                (0..actual).map(|_| UnixStream::pair().unwrap()).unzip();
            let borrowed: Vec<_> = fds.iter().map(AsFd::as_fd).collect();
            send_fds_until(&sender, &borrowed, test_deadline()).unwrap();
            drop(fds);

            let error = receive_opaque_transfer(&mut receiver, expected, test_deadline())
                .err()
                .expect("wrong descriptor count must be rejected");
            assert_eq!(
                error.io_error().map(std::io::Error::kind),
                Some(std::io::ErrorKind::InvalidData)
            );
            for peer in peers {
                assert_peer_closed(peer);
            }
        }
    }
}
