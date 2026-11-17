use nydus_error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::api_server::ControlProtocol;
use crate::continuity::{Identity, Mode};

/// The identity a live NBD daemon advertises and checks in a handoff.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct InstanceInfo {
    /// The daemon process id.
    pub(super) pid: u32,

    /// The daemon software version.
    pub(super) version: String,

    /// The kernel device, `/dev/nbd<N>`.
    pub(super) device: String,

    /// The SHA-256 of the image metadata, in hex.
    pub(super) image_digest: String,

    /// The EROFS mountpoint the daemon owns, if any.
    pub(super) mountpoint: Option<PathBuf>,
}

/// Implements the continuity identity of an NBD daemon.
impl Identity for InstanceInfo {
    /// The HTTP upgrade path and token of NBD control.
    const CONTROL: ControlProtocol = ControlProtocol {
        path: "/nbd/handoff",
        token: "nydus-nbd-control/1",
    };

    /// The handoff mode: a live daemon passes its connections to its successor.
    const MODE: Mode = Mode::Transfer;

    /// The kernel retains the session of a crashed daemon, which a restart reattaches to.
    const RETAINED: bool = true;

    /// Returns the daemon process id.
    fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the daemon software version.
    fn version(&self) -> &str {
        &self.version
    }

    /// Checks that the peer serves the same device, image and mountpoint.
    fn check(&self, peer: &Self) -> Result<()> {
        if self.device != peer.device
            || self.image_digest != peer.image_digest
            || self.mountpoint != peer.mountpoint
        {
            return Err(Error::InvalidParameter(format!(
                "NBD device, image or mountpoint mismatch with daemon {}",
                peer.pid
            )));
        }
        Ok(())
    }
}
