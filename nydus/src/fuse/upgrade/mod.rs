//! FUSE session continuity: hot upgrade and crash failover.

mod handoff;
mod startup;
#[cfg(test)]
mod test_support;
mod wire;
