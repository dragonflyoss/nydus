//! FUSE session continuity: hot upgrade and crash failover.

mod handoff;
mod identity;
mod lifecycle;
mod startup;
#[cfg(test)]
mod test_support;
mod transfer;
mod wire;

#[cfg(test)]
pub(in crate::fuse) use lifecycle::SessionLifecycle;
pub(in crate::fuse) use lifecycle::{SessionOrigin, SessionRuntimeHandle, HANDOFF_TIMEOUT};
pub(in crate::fuse) use transfer::{
    validate_fuse_connection, FuseInitState, SessionProtection, SessionTransfer,
};
