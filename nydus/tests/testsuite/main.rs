//! Integration test suite for `nydus-core`, exercising the crate as an
//! external consumer: fixture images are built through the public `build`
//! module and served back through the public read APIs.
//!
//! One multi-file test target (the Cargo Book's `tests/multi-file-test/`
//! layout): new test areas join as sibling modules. Shared fixtures come
//! from `nydus-test-utils`.

mod erofs_reader;
mod incremental_writer;
mod nydus_core;
