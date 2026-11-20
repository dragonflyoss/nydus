use nydus_error::{Error, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(crate) use crate::continuity::ownership::SessionOwner;

use super::identity::InstanceInfo;
use super::{check_json_version, JSON_FORMAT_VERSION};

/// FUSE mount identity recorded under lifetime ownership.
#[derive(Deserialize, Serialize)]
pub(super) struct OwnerRecord {
    version: u32,
    mountpoint: String,

    /// The image digest for hot upgrade and failover, absent when both are disabled.
    image_digest: Option<String>,

    mount_dev: String,

    /// The crash-failover session, absent for a standalone session.
    session_id: Option<Uuid>,
}

impl OwnerRecord {
    /// Creates the record of a mounted session, protected when `session_id` is set.
    pub(super) fn new(info: &InstanceInfo, mount_dev: &str, session_id: Option<Uuid>) -> Self {
        Self {
            version: JSON_FORMAT_VERSION,
            mountpoint: info.mountpoint.clone(),
            image_digest: info.image_digest.clone(),
            mount_dev: mount_dev.into(),
            session_id,
        }
    }

    /// Returns the recorded session ID once the record matches the mounted session.
    pub(super) fn validate(&self, info: &InstanceInfo, mount_dev: &str) -> Result<Option<Uuid>> {
        check_json_version(self.version)?;
        let image_digest = info.require_image_digest()?;
        if self.mountpoint != info.mountpoint
            || self.image_digest.as_deref() != Some(image_digest)
            || self.mount_dev != mount_dev
            || self.session_id.is_some_and(|id| id.is_nil())
        {
            return Err(Error::Runtime(
                "session ownership record does not match the mounted session".into(),
            ));
        }
        Ok(self.session_id)
    }

    /// Rejects a fresh start without a Holder over a recorded protected session.
    pub(super) fn ensure_standalone_fresh(&self) -> Result<()> {
        check_json_version(self.version)?;
        if self.session_id.is_some() {
            return Err(Error::Runtime(
                "a protected session is recorded; provide its --supervisor-socket to confirm Holder cleanup before fresh startup".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_preserve_the_wire_shape_and_require_the_same_session() {
        let info = InstanceInfo::new("/mnt/image", Some(&[1; 32]));
        let id = Some(Uuid::from_u128(42));
        let record = OwnerRecord::new(&info, "0:42", id);
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "version": 1,
                "mountpoint": "/mnt/image",
                "image_digest": "01".repeat(32),
                "mount_dev": "0:42",
                "session_id": id,
            })
        );
        let decoded: OwnerRecord = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.validate(&info, "0:42").unwrap(), id);
        for (peer, device) in [
            (info.clone(), "0:43"),
            (InstanceInfo::new("/other", Some(&[1; 32])), "0:42"),
            (InstanceInfo::new("/mnt/image", Some(&[2; 32])), "0:42"),
        ] {
            assert!(decoded.validate(&peer, device).is_err());
        }
        assert!(OwnerRecord::new(&info, "0:42", Some(Uuid::nil()))
            .validate(&info, "0:42")
            .is_err());
        assert!(record.ensure_standalone_fresh().is_err());
        OwnerRecord::new(&info, "0:42", None)
            .ensure_standalone_fresh()
            .unwrap();
    }

    #[test]
    fn records_require_a_supported_json_version() {
        let info = InstanceInfo::new("/mnt/image", Some(&[1; 32]));
        let mut record = OwnerRecord::new(&info, "0:42", None);
        for version in [0, 2] {
            record.version = version;
            assert!(record.validate(&info, "0:42").is_err());
            assert!(record.ensure_standalone_fresh().is_err());
        }
    }
}
