//! Direct predecessor-to-successor handoff and the serving control endpoint.

mod identity;
mod lifecycle;
mod protocol;

pub(super) use identity::InstanceInfo;
pub use lifecycle::SessionRuntimeHandle;

pub(super) use identity::authenticate_peer;
#[cfg(test)]
pub(in crate::fuse) use lifecycle::SessionLifecycle;
pub(in crate::fuse) use lifecycle::{SessionOrigin, HANDOFF_TIMEOUT};
#[cfg(test)]
pub(super) use protocol::Request;
