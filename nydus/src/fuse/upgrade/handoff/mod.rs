//! Direct predecessor-to-successor handoff and the serving control endpoint.

mod identity;
mod protocol;

pub(super) use identity::InstanceInfo;

pub(super) use identity::authenticate_peer;
#[cfg(test)]
pub(super) use protocol::Request;
