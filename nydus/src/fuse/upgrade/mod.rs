//! FUSE session continuity: hot upgrade and crash failover.

use std::time::Duration;

mod handoff;
mod identity;
mod lifecycle;
mod startup;
#[cfg(test)]
mod test_support;
mod transfer;
mod wire;

/// Bound for a local control-socket response and for confirming that a
/// successor exited after an abort could not be delivered.
pub(in crate::fuse) const CONTROL_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
pub(in crate::fuse) use lifecycle::SessionLifecycle;
pub(in crate::fuse) use lifecycle::{SessionOrigin, SessionRuntimeHandle, HANDOFF_TIMEOUT};
pub(in crate::fuse) use transfer::{
    validate_fuse_connection, FuseInitState, SessionProtection, SessionTransfer,
};
