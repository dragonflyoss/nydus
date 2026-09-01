//! Captures and adopts the resources required to continue a live FUSE session.

mod payload;
mod state;

pub(in crate::fuse) use payload::SessionTransfer;
pub(in crate::fuse) use payload::{validate_fuse_connection, FuseFailoverSession};
pub(in crate::fuse) use state::FuseInitState;
