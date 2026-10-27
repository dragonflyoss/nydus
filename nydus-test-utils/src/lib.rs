//! Test utilities for the nydus crates: full blob files, the uncompressed
//! data behind them, and the blob meta describing a data region, all
//! assembled through the production code in `nydus-format`.
//!
//! Fixtures panic instead of reporting errors. Only tests build on them,
//! and a fixture that cannot be built is a test failure.
//!
//! [`fault`] (feature `fault-backend`) adds a fault-injecting blob backend.
//! It depends on `nydus-backend`, which dev-depends on this crate, so the
//! feature is off by default: the crates above `nydus-backend` enable it,
//! while `nydus-backend`'s own unit tests cannot use it (they would see the
//! `Backend` trait of a second copy of the crate).

pub mod blob;
#[cfg(feature = "fault-backend")]
pub mod fault;
pub mod known_issue;
pub mod metadata;
