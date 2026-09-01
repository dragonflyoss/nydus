//! FUSE session continuity: hot upgrade and crash failover.

mod handoff;
mod identity;
mod startup;
#[cfg(test)]
mod test_support;
mod transfer;
mod wire;

pub(in crate::fuse) use transfer::{
    validate_fuse_connection, FuseFailoverSession, FuseInitState, SessionTransfer,
};
