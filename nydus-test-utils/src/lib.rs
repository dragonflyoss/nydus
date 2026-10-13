//! Test utilities for the nydus crates: full blob files, the blob meta
//! describing a data region, and minimal EROFS images, all assembled
//! through the production code in `nydus-format`.
//!
//! Fixtures panic instead of reporting errors. Only tests build on them,
//! and a fixture that cannot be built is a test failure.

pub mod blob;
pub mod erofs;
pub mod metadata;
