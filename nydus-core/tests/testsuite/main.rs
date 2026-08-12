//! Integration test suite for `nydus-core`, exercising the crate as an
//! external consumer: fixture images are built through the public `build`
//! module and served back through the public read APIs.
//!
//! One multi-file test target (the Cargo Book's `tests/multi-file-test/`
//! layout): new test areas join as sibling modules and shared helpers like
//! [`fixture`] are declared once.

mod fixture;

mod erofs_reader;
mod nydus_core;
