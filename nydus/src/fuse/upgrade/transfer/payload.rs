//! FUSE transfer metadata and validation of the transferred descriptors.

use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;

use nydus_error::{Context, Error, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::continuity::wire::Transfer;

use super::super::identity::InstanceInfo;
use super::super::{check_json_version, JSON_FORMAT_VERSION};
use super::state::FuseInitState;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct SessionTransferMetadata {
    pub(crate) version: u32,
    /// The crash-failover session, `None` for a standalone session.
    pub(crate) session_id: Option<Uuid>,
    pub(crate) mountpoint: String,
    pub(crate) image_digest: String,
    pub(crate) fuse_session_state: FuseInitState,
    /// Whether fuser's inflight journal follows the FUSE devices; fuser keeps
    /// none where the kernel resends unanswered requests itself.
    pub(crate) inflight_journal: bool,
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
        if self.session_id.is_some_and(|id| id.is_nil()) {
            return Err(Error::Protocol(
                "session transfer metadata has a nil session identity".to_string(),
            ));
        }
        if self.inflight_journal && self.session_id.is_none() {
            return Err(Error::Protocol(
                "a standalone session transfer has no inflight journal".to_string(),
            ));
        }
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

    /// Checks the transfer against the expected identity. `session_id` is the one
    /// the peer advertised or the owner record holds; a standalone `None` must
    /// match too, so no transfer adds or drops protection.
    fn check_expected(&self, session_id: Option<Uuid>, expected: &InstanceInfo) -> Result<()> {
        if self.session_id != session_id {
            return Err(Error::Protocol(format!(
                "session transfer returned session {:?}, expected {:?}",
                self.session_id, session_id
            )));
        }
        if self.mountpoint != expected.mountpoint {
            return Err(Error::Protocol(format!(
                "session transfer mountpoint mismatch: transfer uses {}, expected {}",
                self.mountpoint, expected.mountpoint
            )));
        }
        let image_digest = expected.require_image_digest()?;
        if self.image_digest != image_digest {
            return Err(Error::Protocol(format!(
                "session transfer image content mismatch: transfer {}, expected {}",
                self.image_digest, image_digest
            )));
        }
        Ok(())
    }
}

/// A received session whose identity and resources have been validated for adoption.
pub(crate) struct SessionTransfer {
    /// The validated transfer metadata.
    metadata: SessionTransferMetadata,

    /// The FUSE devices, main device first.
    devices: Vec<OwnedFd>,

    /// The inflight journal, present when the metadata reports one.
    journal: Option<OwnedFd>,
}

impl SessionTransfer {
    /// Duplicates the session's FUSE devices, main device first, followed by the
    /// inflight journal of a protected session.
    pub(in crate::fuse::upgrade) fn capture(
        info: &InstanceInfo,
        fuse_session_state: &FuseInitState,
        devices: &[OwnedFd],
        protection: &SessionProtection,
    ) -> Result<Transfer> {
        let metadata = SessionTransferMetadata {
            version: JSON_FORMAT_VERSION,
            session_id: protection.session_id(),
            mountpoint: info.mountpoint.clone(),
            image_digest: info.require_image_digest()?.to_owned(),
            fuse_session_state: fuse_session_state.clone(),
            inflight_journal: protection.journal().is_some(),
        };
        let metadata = metadata.encode()?;
        let mut fds = devices
            .iter()
            .map(OwnedFd::try_clone)
            .collect::<std::io::Result<Vec<_>>>()
            .context("failed to duplicate session transfer FUSE devices")?;
        if let Some(journal) = protection.journal() {
            fds.push(
                journal
                    .try_clone()
                    .context("failed to duplicate inflight journal")?,
            );
        }
        Ok(Transfer { metadata, fds })
    }

    pub(in crate::fuse::upgrade) fn from_opaque(
        opaque: Transfer,
        session_id: Option<Uuid>,
        expected: &InstanceInfo,
    ) -> Result<Self> {
        let metadata = SessionTransferMetadata::decode(&opaque.metadata)
            .context("failed to decode session transfer metadata")?;
        metadata.check_expected(session_id, expected)?;
        // A standalone session hands over its main device; a protected one every
        // device its workers read, since only that device can answer a request read on it.
        let journals = usize::from(metadata.inflight_journal);
        let device_count = opaque
            .fds
            .len()
            .checked_sub(journals)
            .filter(|&count| count == 1 || (count > 1 && metadata.session_id.is_some()))
            .ok_or_else(|| {
                Error::Protocol(
                    "session transfer descriptors do not match its protection".to_string(),
                )
            })?;
        let mut devices = opaque.fds;
        let journal = devices.split_off(device_count).pop();
        for device in &devices {
            validate_fuse_connection(device.as_fd())
                .context("session transfer FUSE connection is unusable")?;
        }
        Ok(Self {
            metadata,
            devices,
            journal,
        })
    }

    /// Splits the transfer into its metadata, FUSE devices and inflight journal.
    pub(crate) fn into_adoption(self) -> (SessionTransferMetadata, Vec<OwnedFd>, Option<OwnedFd>) {
        (self.metadata, self.devices, self.journal)
    }
}

/// Optional crash-failover protection, preserved unchanged across hot upgrade.
#[derive(Clone)]
pub(crate) enum SessionProtection {
    /// The session has no Recovery Holder.
    Standalone,

    /// The session is retained by a Recovery Holder; `journal` is absent where
    /// the kernel resends unanswered requests itself.
    Failover {
        session_id: Uuid,
        journal: Option<Arc<OwnedFd>>,
    },
}

impl SessionProtection {
    /// Returns the crash-failover session ID, `None` for a standalone session.
    pub(crate) fn session_id(&self) -> Option<Uuid> {
        match self {
            Self::Standalone => None,
            Self::Failover { session_id, .. } => Some(*session_id),
        }
    }

    /// Returns the inflight journal of a protected session, if fuser keeps one.
    pub(crate) fn journal(&self) -> Option<&OwnedFd> {
        match self {
            Self::Standalone => None,
            Self::Failover { journal, .. } => journal.as_deref(),
        }
    }
}

/// Checks that `fd` is a live, read-write `/dev/fuse` connection.
fn validate_fuse_connection(fd: BorrowedFd<'_>) -> std::io::Result<()> {
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

    const SESSION: Option<Uuid> = Some(Uuid::from_u128(1));

    fn metadata(session_id: Option<Uuid>) -> SessionTransferMetadata {
        SessionTransferMetadata {
            version: JSON_FORMAT_VERSION,
            session_id,
            mountpoint: "/mnt/nydus".to_string(),
            image_digest: "01".repeat(32),
            fuse_session_state: fuse_init_state(),
            inflight_journal: session_id.is_some(),
        }
    }

    fn transfer(metadata: &SessionTransferMetadata, count: usize) -> (Transfer, Vec<UnixStream>) {
        let (fds, peers): (Vec<_>, Vec<_>) =
            (0..count).map(|_| UnixStream::pair().unwrap()).unzip();
        let transfer = Transfer {
            metadata: serde_json::to_vec(metadata).unwrap(),
            fds: fds.into_iter().map(Into::into).collect(),
        };
        (transfer, peers)
    }

    fn rejection(
        transfer: Transfer,
        session_id: Option<Uuid>,
        info: &InstanceInfo,
        peers: Vec<UnixStream>,
    ) -> String {
        let error = SessionTransfer::from_opaque(transfer, session_id, info)
            .err()
            .expect("the transfer must be rejected");
        for peer in peers {
            assert_peer_closed(peer);
        }
        let message = error.report().to_string();
        message
    }

    #[test]
    fn metadata_round_trip_checks_version_and_tolerates_additions() {
        let metadata = metadata(SESSION);
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

        let mut standalone = json.clone();
        standalone["session_id"] = serde_json::Value::Null;
        for (mut invalid, field, value) in [
            (json.clone(), "session_id", serde_json::json!(Uuid::nil())),
            (json.clone(), "mountpoint", serde_json::json!("relative")),
            (standalone, "inflight_journal", serde_json::json!(true)),
        ] {
            invalid[field] = value;
            assert!(
                SessionTransferMetadata::decode(&serde_json::to_vec(&invalid).unwrap()).is_err()
            );
        }
        let mut invalid_protocol = json;
        invalid_protocol["fuse_session_state"]["proto_major"] = serde_json::json!(8);
        assert!(
            SessionTransferMetadata::decode(&serde_json::to_vec(&invalid_protocol).unwrap())
                .is_err()
        );
    }

    #[test]
    fn mismatched_identity_or_protection_closes_the_received_descriptors() {
        let info = InstanceInfo::new("/mnt/nydus", Some(&[1; 32]));
        for (expected_info, advertised, transferred, expected_error) in [
            (
                InstanceInfo::new("/other", Some(&[1; 32])),
                None,
                None,
                "mountpoint mismatch",
            ),
            (
                InstanceInfo::new("/mnt/nydus", Some(&[2; 32])),
                None,
                None,
                "image content mismatch",
            ),
            (info.clone(), None, SESSION, "returned session"),
            (info.clone(), SESSION, None, "returned session"),
            (
                info.clone(),
                SESSION,
                Some(Uuid::from_u128(2)),
                "returned session",
            ),
        ] {
            let (transfer, peers) = transfer(&metadata(transferred), 2);
            let error = rejection(transfer, advertised, &expected_info, peers);
            assert!(error.contains(expected_error), "{error}");
        }
    }

    #[test]
    fn descriptor_layout_must_match_the_protection() {
        let info = InstanceInfo::new("/mnt/nydus", Some(&[1; 32]));
        let mut resending = metadata(SESSION);
        resending.inflight_journal = false;
        for (metadata, count, expected_error) in [
            (metadata(None), 0, "do not match its protection"),
            (metadata(None), 2, "do not match its protection"),
            (metadata(None), 1, "/dev/fuse"),
            (metadata(SESSION), 1, "do not match its protection"),
            (metadata(SESSION), 3, "/dev/fuse"),
            (resending.clone(), 0, "do not match its protection"),
            (resending, 2, "/dev/fuse"),
        ] {
            let session_id = metadata.session_id;
            let (transfer, peers) = transfer(&metadata, count);
            let error = rejection(transfer, session_id, &info, peers);
            assert!(error.contains(expected_error), "{count}: {error}");
        }
    }
}
