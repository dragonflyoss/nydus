//! Direct predecessor-to-successor handoff and the serving control endpoint.

mod client;
mod protocol;
mod server;

pub(super) use client::{begin_handoff, probe_existing_instance};
pub(super) use server::ControlServer;

#[cfg(test)]
pub(super) use protocol::Request;
