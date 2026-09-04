//! FUSE session continuity: hot upgrade and crash failover.

use std::time::Duration;

mod handoff;
mod holder;
mod startup;
#[cfg(test)]
mod test_support;
mod transfer;
mod wire;

pub const STANDALONE_UPGRADE_ERROR: &str =
    "Standalone Session does not support hot upgrade without a Recovery Holder";

/// Bound for a local control-socket response and for confirming that a
/// successor exited after an abort could not be delivered.
pub(in crate::fuse) const CONTROL_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

pub use handoff::SessionRuntimeHandle;
pub use startup::{RunningSession, Startup, StartupMode};
pub use transfer::SessionTransfer;

#[cfg(test)]
pub(in crate::fuse) use handoff::SessionLifecycle;
pub(in crate::fuse) use handoff::{SessionOrigin, HANDOFF_TIMEOUT};
pub(in crate::fuse) use transfer::{validate_fuse_connection, FuseInitState, SessionProtection};
