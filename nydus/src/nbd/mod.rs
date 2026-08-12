//! Network Block Device on-demand service for nydus images.
//!
//! Exposes the flattened EROFS image (bootstrap + all data blobs) as a single
//! read-only block device through the Linux NBD driver. The kernel reads
//! `/dev/nbdX`; each cold read fetches the covering blob ranges through
//! [`NydusCore`]'s on-demand backend into the per-blob sparse cache file.
//! Repeat reads are served by the page cache above the device; reads that do
//! reach the daemon again (after eviction) pread cache-resident ranges
//! locally without touching the backend.
//!
//! This mirrors the fanotify multi-device model's fill philosophy (idempotent
//! in-place cache writes, sticky fully-ready bypass) but routes guest reads
//! through the NBD socket protocol instead of fanotify pre-content hooks, so
//! it works on kernels without `FAN_CLASS_PRE_CONTENT` (Linux < 6.15).
//!
//! [`NydusCore`]: nydus_core::NydusCore

pub mod core;
pub mod mount;
pub mod proto;
pub mod service;

pub use core::NbdCore;
pub use mount::mount_nbd;
pub use service::NbdService;
