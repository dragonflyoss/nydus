use nydus_error::{Error, Result};
use serde::{Deserialize, Serialize};

pub(crate) use crate::continuity::ownership::SessionOwner;

use super::identity::InstanceInfo;
use super::{check_json_version, JSON_FORMAT_VERSION};

/// FUSE mount identity recorded under lifetime ownership.
#[derive(Deserialize, Serialize)]
pub(super) struct OwnerRecord {
    version: u32,
    mountpoint: String,
    image_digest: String,
    mount_dev: String,
}

impl OwnerRecord {
    pub(super) fn new(info: &InstanceInfo, mount_dev: &str) -> Self {
        Self {
            version: JSON_FORMAT_VERSION,
            mountpoint: info.mountpoint.clone(),
            image_digest: info.image_digest.clone(),
            mount_dev: mount_dev.into(),
        }
    }

    pub(super) fn validate(&self, info: &InstanceInfo, mount_dev: &str) -> Result<()> {
        check_json_version(self.version)?;
        if self.mountpoint != info.mountpoint
            || self.image_digest != info.image_digest
            || self.mount_dev != mount_dev
        {
            return Err(Error::Runtime(
                "session ownership record does not match the mounted session".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_require_the_same_mount_and_image() {
        let info = InstanceInfo::new("/mnt/image", &[1; 32]);
        let record = OwnerRecord::new(&info, "0:42");
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "version": 1,
                "mountpoint": "/mnt/image",
                "image_digest": "01".repeat(32),
                "mount_dev": "0:42",
            })
        );
        let decoded: OwnerRecord = serde_json::from_value(json).unwrap();
        decoded.validate(&info, "0:42").unwrap();
        for (peer, device) in [
            (info.clone(), "0:43"),
            (InstanceInfo::new("/other", &[1; 32]), "0:42"),
            (InstanceInfo::new("/mnt/image", &[2; 32]), "0:42"),
        ] {
            assert!(decoded.validate(&peer, device).is_err());
        }
    }

    #[test]
    fn records_require_a_supported_json_version() {
        let info = InstanceInfo::new("/mnt/image", &[1; 32]);
        let mut record = OwnerRecord::new(&info, "0:42");
        for version in [0, 2] {
            record.version = version;
            assert!(record.validate(&info, "0:42").is_err());
        }
    }
}
