//! On-disk format layer for nydus images: blob layout (footer, blob meta),
//! EROFS metadata structures, and the byte-level utilities they share.
//!
//! This crate sits below both of nydus's error planes: the data plane
//! (`io::Result`) and the control plane consume the same parsers here and
//! convert [`Error`] at their own boundaries.
//!
//! # Naming gradient
//!
//! The same domain concepts appear at three layers across the workspace,
//! told apart by prefix: `Erofs*` types here are zero-copy views of on-disk
//! bytes ([`erofs::ErofsDirent`]); `Raw*` types in `nydus-core` are their
//! minimally-parsed, lifetime-free forms (`RawDirEntry`); bare names are the
//! owned, user-facing API (`DirEntry`).

pub mod blob;
pub mod erofs;
pub mod error;
pub mod utils;

pub use error::{Error, Result};
