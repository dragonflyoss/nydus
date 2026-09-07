//! Captures and adopts the resources required to continue a live FUSE session.

mod payload;
mod state;

pub use payload::SessionTransfer;
pub(in crate::fuse) use payload::{validate_fuse_connection, SessionProtection};
pub(in crate::fuse) use state::FuseInitState;

#[cfg(test)]
pub(in crate::fuse) use payload::SessionTransferMetadata;
#[cfg(test)]
pub(in crate::fuse::upgrade) use payload::{
    receive_opaque_transfer, send_opaque_transfer, FuseFailoverSession, OpaqueSessionTransfer,
};
