//! FUSE session continuity: hot upgrade and crash failover.

mod handoff;
mod startup;
#[cfg(test)]
mod test_support;
mod transfer;
mod wire;

pub const STANDALONE_UPGRADE_ERROR: &str =
    "Standalone Session does not support hot upgrade without a Recovery Holder";

pub use handoff::SessionRuntimeHandle;
pub use transfer::SessionTransfer;

#[cfg(test)]
pub(in crate::fuse) use handoff::SessionLifecycle;
pub(in crate::fuse) use handoff::{SessionOrigin, HANDOFF_TIMEOUT};
pub(in crate::fuse) use transfer::{validate_fuse_connection, FuseInitState, SessionProtection};
