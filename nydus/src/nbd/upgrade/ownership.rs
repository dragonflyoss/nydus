use nydus_error::{Context, Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

use super::identity::InstanceInfo;
use crate::nbd::service::NbdOptions;

/// The persisted owner record format.
///
/// Unsupported versions are rejected without negotiation.
pub(super) const JSON_FORMAT_VERSION: u32 = 1;

/// The kernel session as seen through sysfs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Resource {
    /// The backend identity registered with the kernel.
    pub(super) backend: String,

    /// The device capacity in bytes.
    pub(super) bytes: u64,
}

/// The ownership record that lets a successor adopt the kernel session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct OwnerRecord {
    /// The record format version.
    pub(super) version: u32,

    /// The kernel device, `/dev/nbd<N>`.
    pub(super) device: String,

    /// The SHA-256 of the image metadata, in hex.
    pub(super) image_digest: String,

    /// The EROFS mountpoint of the session, if any.
    pub(super) mountpoint: Option<PathBuf>,

    /// The identity of the session, unchanged across owners; nil once the session was
    /// disconnected.
    pub(super) session_id: Uuid,

    /// The device capacity in bytes.
    pub(super) bytes: u64,

    /// The connection count and timeouts every owner inherits.
    pub(super) options: NbdOptions,
}

/// Implements the NBD ownership record.
impl OwnerRecord {
    /// Returns the kernel session the record describes.
    pub(super) fn resource(&self) -> Resource {
        Resource {
            backend: format!("nydus:{}:{}", self.image_digest, self.session_id),
            bytes: self.bytes,
        }
    }

    /// Checks the record against the starting daemon and the kernel session, returning the session id.
    pub(super) fn validate(
        &self,
        info: &InstanceInfo,
        resource: &Resource,
    ) -> Result<Option<Uuid>> {
        if self.version != JSON_FORMAT_VERSION {
            return Err(Error::Protocol(format!(
                "unsupported NBD continuity JSON version {}, expected {JSON_FORMAT_VERSION}",
                self.version
            )));
        }
        self.options.validate()?;

        // Refuse a session this daemon disconnected: a device that is still open, usually by
        // a mounted filesystem, keeps the kernel reporting its capacity and backend identity.
        if self.session_id.is_nil() {
            return Err(Error::Runtime(format!(
                "the NBD session on {} was disconnected but the device is still in use, usually by a mounted filesystem; unmount it before starting nydus again",
                self.device
            )));
        }
        if self.device != info.device
            || self.image_digest != info.image_digest
            || self.mountpoint != info.mountpoint
        {
            return Err(Error::Runtime(format!(
                "the retained NBD session on {0} serves another image or mountpoint; restart nydus with the original ones; to discard the session, unmount its filesystem and run `nbd-client -d {0}`",
                self.device
            )));
        }
        if self.resource() != *resource {
            return Err(Error::Runtime(format!(
                "NBD ownership record does not match the kernel session on {}",
                self.device
            )));
        }
        Ok(Some(self.session_id))
    }
}

/// Reads the kernel session of `/dev/nbd<index>` from sysfs without opening the device.
pub(super) fn kernel_resource(root: &Path, index: u32) -> Result<Option<Resource>> {
    let path = root.join(format!("nbd{index}"));
    let size = std::fs::read_to_string(path.join("size"))
        .with_context(|| format!("failed to inspect the capacity of nbd{index}"))?;
    let sectors: u64 = size
        .trim()
        .parse()
        .map_err(|_| Error::Protocol(format!("invalid sysfs capacity of nbd{index}")))?;
    if sectors == 0 {
        return Ok(None);
    }
    let unidentified = format!(
        "nbd{index} has a session without a kernel backend identity: another NBD client uses it, or the kernel predates Linux 5.14"
    );
    let backend =
        std::fs::read_to_string(path.join("backend")).with_context(|| unidentified.clone())?;
    let backend = backend.trim_end_matches('\n').to_string();
    if backend.is_empty() {
        return Err(Error::Runtime(unidentified));
    }
    let bytes = sectors
        .checked_mul(512)
        .ok_or_else(|| Error::Overflow(format!("capacity of nbd{index} overflows")))?;
    Ok(Some(Resource { backend, bytes }))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(in crate::nbd::upgrade) fn test_record() -> (InstanceInfo, OwnerRecord) {
        let info = InstanceInfo {
            pid: 1,
            version: "test".into(),
            device: "/dev/nbd0".into(),
            image_digest: "01".repeat(32),
            mountpoint: None,
        };
        let record = OwnerRecord {
            version: JSON_FORMAT_VERSION,
            device: info.device.clone(),
            image_digest: info.image_digest.clone(),
            mountpoint: info.mountpoint.clone(),
            session_id: Uuid::from_u128(42),
            bytes: 4096,
            options: NbdOptions {
                connections: 2,
                timeout_secs: 15,
                dead_conn_timeout_secs: 60,
            },
        };
        (info, record)
    }

    #[test]
    fn recovery_requires_matching_content_session_and_kernel_identity() {
        let (info, record) = test_record();
        let decoded: OwnerRecord =
            serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
        assert_eq!(decoded, record);
        let resource = record.resource();
        assert_eq!(
            record.validate(&info, &resource).unwrap(),
            Some(record.session_id)
        );

        let test_cases: Vec<fn(&mut OwnerRecord)> = vec![
            |record| record.version = 2,
            |record| record.device = "/dev/nbd1".into(),
            |record| record.image_digest = "02".repeat(32),
            |record| record.mountpoint = Some("/mnt/image".into()),
            |record| record.session_id = Uuid::nil(),
            |record| record.session_id = Uuid::from_u128(43),
            |record| record.bytes = 8192,
            |record| record.options.connections = 0,
        ];
        for change in test_cases {
            let mut changed = record.clone();
            change(&mut changed);
            assert!(changed.validate(&info, &resource).is_err(), "{changed:?}");
        }
    }

    #[test]
    fn inspection_reads_the_session_from_sysfs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nbd0");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("size"), "0\n").unwrap();
        assert!(kernel_resource(dir.path(), 0).unwrap().is_none());
        std::fs::write(path.join("size"), "8\n").unwrap();
        assert!(kernel_resource(dir.path(), 0).is_err());
        std::fs::write(path.join("backend"), "session\n").unwrap();
        assert_eq!(
            kernel_resource(dir.path(), 0).unwrap(),
            Some(Resource {
                backend: "session".into(),
                bytes: 4096
            })
        );
        std::fs::write(path.join("size"), "invalid\n").unwrap();
        assert!(kernel_resource(dir.path(), 0).is_err());
    }
}
