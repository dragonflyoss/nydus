//! FUSE session continuity: hot upgrade and crash failover.

mod handoff;
mod startup;
#[cfg(test)]
mod test_support;
mod transfer;
mod wire;

pub use transfer::SessionTransfer;

pub(in crate::fuse) use transfer::{validate_fuse_connection, FuseFailoverSession, FuseInitState};
