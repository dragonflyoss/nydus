//! FUSE session continuity: hot upgrade and crash failover.

mod identity;
mod lifecycle;
mod ownership;
mod startup;
#[cfg(test)]
pub(super) mod test_support;
mod transfer;

const JSON_FORMAT_VERSION: u32 = 1;

fn check_json_version(version: u32) -> nydus_error::Result<()> {
    if version != JSON_FORMAT_VERSION {
        return Err(nydus_error::Error::Protocol(format!(
            "unsupported FUSE continuity JSON version {version}, expected {JSON_FORMAT_VERSION}"
        )));
    }
    Ok(())
}

pub use startup::{RunningSession, Startup};

pub(crate) use crate::continuity::HANDOFF_TIMEOUT;
pub(crate) use lifecycle::SessionRuntimeHandle;
pub(crate) use ownership::SessionOwner;
pub(crate) use transfer::{FuseInitState, SessionProtection, SessionTransfer};
