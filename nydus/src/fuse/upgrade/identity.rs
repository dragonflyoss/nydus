use nydus_error::{Error, Result};
use serde::{Deserialize, Serialize};

use crate::api_server::ControlProtocol;
use crate::continuity::{Identity, Mode};

/// The identity a FUSE instance advertises to its continuity peers.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct InstanceInfo {
    pub(super) pid: u32,
    pub(super) version: String,
    pub(super) mountpoint: String,

    /// The image digest for hot upgrade, absent when upgrade is disabled.
    pub(super) image_digest: Option<String>,
}

impl InstanceInfo {
    /// Creates an instance identity with an optional image digest.
    pub(super) fn new(mountpoint: &str, image_digest: Option<&[u8]>) -> Self {
        Self {
            pid: std::process::id(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            mountpoint: mountpoint.to_string(),
            image_digest: image_digest.map(hex::encode),
        }
    }

    /// Returns the image digest required to validate or transfer a session.
    pub(super) fn require_image_digest(&self) -> Result<&str> {
        self.image_digest.as_deref().ok_or_else(|| {
            Error::InvalidParameter(format!(
                "missing image digest for FUSE upgrade at {}",
                self.mountpoint
            ))
        })
    }
}

impl Identity for InstanceInfo {
    const CONTROL: ControlProtocol = ControlProtocol {
        path: "/fuse/handoff",
        token: "nydus-fuse-control/1",
    };
    const MODE: Mode = Mode::Transfer;

    fn pid(&self) -> u32 {
        self.pid
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn protected(_session_id: Option<uuid::Uuid>) -> bool {
        false
    }

    fn check(&self, peer: &Self) -> Result<()> {
        if peer.mountpoint != self.mountpoint {
            return Err(Error::InvalidParameter(format!(
                "mountpoint mismatch: peer owns {}, expected {}",
                peer.mountpoint, self.mountpoint
            )));
        }
        let image_digest = self.require_image_digest()?;
        let peer_digest = peer.require_image_digest()?;
        if peer_digest != image_digest {
            return Err(Error::InvalidParameter(format!(
                "image content mismatch: peer {peer_digest}, expected {image_digest}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_check_rejects_a_mismatched_session() {
        let current = InstanceInfo::new("/mnt", Some(&[1; 32]));
        for peer in [
            InstanceInfo::new("/other", Some(&[1; 32])),
            InstanceInfo::new("/mnt", Some(&[2; 32])),
        ] {
            assert!(current.check(&peer).is_err());
        }
        assert!(current.check(&current).is_ok());
        let mut extended = serde_json::to_value(&current).unwrap();
        extended["optional_extension"] = serde_json::json!(true);
        current
            .check(&serde_json::from_value(extended).unwrap())
            .unwrap();
        assert!(current.check_pid(current.pid + 1).is_err());
    }
}
