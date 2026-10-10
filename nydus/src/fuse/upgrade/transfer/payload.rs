//! FUSE hot-upgrade metadata and connection validation.

use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;

use nydus_error::{Context, Error, Result};
use serde::{Deserialize, Serialize};

use crate::continuity::wire::Transfer;

use super::super::identity::InstanceInfo;
use super::super::{check_json_version, JSON_FORMAT_VERSION};
use super::state::FuseInitState;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct SessionTransferMetadata {
    pub(crate) version: u32,
    pub(crate) mountpoint: String,
    pub(crate) image_digest: String,
    pub(crate) fuse_session_state: FuseInitState,
}

impl SessionTransferMetadata {
    pub(in crate::fuse::upgrade) fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }

    pub(in crate::fuse::upgrade) fn decode(bytes: &[u8]) -> Result<Self> {
        let metadata: Self = serde_json::from_slice(bytes).map_err(|err| {
            Error::Protocol(format!("malformed session transfer metadata JSON: {err}"))
        })?;
        metadata.validate()?;
        Ok(metadata)
    }

    fn validate(&self) -> Result<()> {
        check_json_version(self.version)?;
        if !Path::new(&self.mountpoint).is_absolute() {
            return Err(Error::Protocol(
                "session transfer metadata mountpoint is not absolute".to_string(),
            ));
        }
        if self.image_digest.len() != 64
            || !self
                .image_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(Error::Protocol(
                "session transfer metadata image digest is not SHA-256 hex".to_string(),
            ));
        }
        self.fuse_session_state.validate()
    }

    fn check_expected(&self, expected: &InstanceInfo) -> Result<()> {
        if self.mountpoint != expected.mountpoint {
            return Err(Error::Protocol(format!(
                "session transfer mountpoint mismatch: transfer uses {}, expected {}",
                self.mountpoint, expected.mountpoint
            )));
        }
        if self.image_digest != expected.image_digest {
            return Err(Error::Protocol(format!(
                "session transfer image content mismatch: transfer {}, expected {}",
                self.image_digest, expected.image_digest
            )));
        }
        Ok(())
    }
}

/// A received session whose identity and resources have been validated for adoption.
pub(crate) struct SessionTransfer {
    metadata: SessionTransferMetadata,
    fuse_fd: OwnedFd,
}

impl SessionTransfer {
    /// Duplicates the live connection for handoff.
    pub(in crate::fuse::upgrade) fn capture(
        info: &InstanceInfo,
        fuse_session_state: &FuseInitState,
        fuse_fd: BorrowedFd<'_>,
    ) -> Result<Transfer> {
        let metadata = SessionTransferMetadata {
            version: JSON_FORMAT_VERSION,
            mountpoint: info.mountpoint.clone(),
            image_digest: info.image_digest.clone(),
            fuse_session_state: fuse_session_state.clone(),
        };
        let metadata = metadata.encode()?;
        let fuse_fd = fuse_fd
            .try_clone_to_owned()
            .context("failed to duplicate session transfer FUSE descriptor")?;
        Ok(Transfer {
            metadata,
            fds: vec![fuse_fd],
        })
    }

    pub(in crate::fuse::upgrade) fn from_opaque(
        opaque: Transfer,
        expected: &InstanceInfo,
    ) -> Result<Self> {
        let metadata = SessionTransferMetadata::decode(&opaque.metadata)
            .context("failed to decode session transfer metadata")?;
        metadata.check_expected(expected)?;
        if opaque.fds.len() != 1 {
            return Err(Error::Protocol(
                "FUSE handoff requires exactly one connection descriptor".to_string(),
            ));
        }
        let mut fds = opaque.fds.into_iter();
        let fuse_fd = fds.next().unwrap();
        validate_fuse_connection(fuse_fd.as_fd())
            .context("session transfer FUSE connection is unusable")?;
        Ok(Self { metadata, fuse_fd })
    }

    pub(crate) fn into_adoption(self) -> (SessionTransferMetadata, OwnedFd) {
        (self.metadata, self.fuse_fd)
    }
}

/// Checks that `fd` is a live, read-write `/dev/fuse` connection.
pub(crate) fn validate_fuse_connection(fd: BorrowedFd<'_>) -> std::io::Result<()> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat provides writable storage and fd stays borrowed throughout the call.
    if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a successful fstat initialized the entire structure.
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
    // SAFETY: F_GETFL reads flags from the borrowed descriptor without a variadic argument.
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
    use std::os::unix::net::UnixStream;

    use super::*;
    use crate::continuity::test_support::assert_peer_closed;
    use crate::fuse::upgrade::test_support::fuse_init_state;

    fn metadata() -> SessionTransferMetadata {
        SessionTransferMetadata {
            version: JSON_FORMAT_VERSION,
            mountpoint: "/mnt/nydus".to_string(),
            image_digest: "01".repeat(32),
            fuse_session_state: fuse_init_state(),
        }
    }

    #[test]
    fn metadata_round_trip_checks_version_and_tolerates_additions() {
        let metadata = metadata();
        let encoded = metadata.encode().unwrap();
        let json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(json["version"], 1);
        assert_eq!(SessionTransferMetadata::decode(&encoded).unwrap(), metadata);

        for version in [0, 2] {
            let mut unsupported = metadata.clone();
            unsupported.version = version;
            assert!(unsupported.encode().is_err());
            assert!(
                SessionTransferMetadata::decode(&serde_json::to_vec(&unsupported).unwrap())
                    .is_err()
            );
        }

        let mut extended = json.clone();
        extended["optional_extension"] = serde_json::json!(true);
        extended["fuse_session_state"]["optional_extension"] = serde_json::json!(true);
        assert!(SessionTransferMetadata::decode(&serde_json::to_vec(&extended).unwrap()).is_ok());

        let mut invalid_protocol = json;
        invalid_protocol["fuse_session_state"]["proto_major"] = serde_json::json!(8);
        assert!(
            SessionTransferMetadata::decode(&serde_json::to_vec(&invalid_protocol).unwrap())
                .is_err()
        );
    }

    #[test]
    fn mismatched_handoff_identity_closes_the_received_descriptor() {
        for (info, expected_error) in [
            (InstanceInfo::new("/other", &[1; 32]), "mountpoint mismatch"),
            (
                InstanceInfo::new("/mnt/nydus", &[2; 32]),
                "image content mismatch",
            ),
        ] {
            let (fd, peer) = UnixStream::pair().unwrap();
            let transfer = Transfer {
                metadata: metadata().encode().unwrap(),
                fds: vec![fd.into()],
            };
            let error = SessionTransfer::from_opaque(transfer, &info)
                .err()
                .expect("handoff must match the expected identity");
            assert!(
                error.report().to_string().contains(expected_error),
                "{error:?}"
            );
            assert_peer_closed(peer);
        }
    }

    #[test]
    fn invalid_handoff_descriptors_are_rejected_and_closed() {
        for count in [0, 1, 2] {
            let (fds, peers): (Vec<_>, Vec<_>) =
                (0..count).map(|_| UnixStream::pair().unwrap()).unzip();
            let transfer = Transfer {
                metadata: metadata().encode().unwrap(),
                fds: fds.into_iter().map(Into::into).collect(),
            };
            let error =
                SessionTransfer::from_opaque(transfer, &InstanceInfo::new("/mnt/nydus", &[1; 32]))
                    .err()
                    .expect("invalid handoff resources must be rejected");
            let expected = if count == 1 {
                "/dev/fuse"
            } else {
                "exactly one"
            };
            assert!(error.report().to_string().contains(expected), "{error:?}");
            for peer in peers {
                assert_peer_closed(peer);
            }
        }
    }
}
