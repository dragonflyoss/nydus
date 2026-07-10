//! Device-level userfaultfd service for flattened Lepton virtio-pmem images.
//!
//! This module is feature-gated by `uffd` so builtin accessor users do not pull
//! in the tokio-based server stack.

pub mod core;
pub mod proto;
pub mod service;

pub use core::{UffdCore, UffdOptions};
pub use proto::{FaultPolicy, VmaRegion};
pub use service::UffdService;
