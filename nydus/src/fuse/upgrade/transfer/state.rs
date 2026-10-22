use nydus_error::{Error, Result};
use serde::{Deserialize, Serialize};

/// The FUSE INIT negotiation a successor must reproduce on an adopted connection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct FuseInitState {
    pub(crate) proto_major: u32,
    pub(crate) proto_minor: u32,
    pub(crate) negotiated_init_flags: u64,
    pub(crate) kernel_init_flags: u64,
}

impl FuseInitState {
    pub(super) fn validate(&self) -> Result<()> {
        if self.proto_major != 7 || self.proto_minor < 6 {
            return Err(Error::Protocol(format!(
                "fuse continuity state has unsupported FUSE protocol version {}.{}",
                self.proto_major, self.proto_minor
            )));
        }
        if self.negotiated_init_flags & !self.kernel_init_flags != 0 {
            return Err(Error::Protocol(
                "fuse continuity state negotiated FUSE flags absent from kernel capabilities"
                    .to_string(),
            ));
        }
        Ok(())
    }
}
