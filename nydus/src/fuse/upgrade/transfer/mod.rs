//! Captures and adopts the resources required to continue a live FUSE session.

mod payload;
mod state;

pub(crate) use payload::{validate_fuse_connection, SessionTransfer};
pub(crate) use state::FuseInitState;

#[cfg(test)]
pub(super) use payload::SessionTransferMetadata;
