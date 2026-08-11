//! ublk block device target for flattened nydus images.
//!
//! This module is feature-gated by `ublk` so users that only need the core
//! or FUSE paths do not pull in the ublk/io_uring stack. It requires Linux 6.0
//! or later (`CONFIG_BLK_DEV_UBLK`).

pub mod core;
pub mod service;

pub use core::{UblkCore, UBLK_LOGICAL_BLOCK_SIZE};
pub use service::{
    default_queues, UblkHandle, UblkOptions, UblkService, DEFAULT_IO_BUF_BYTES,
    DEFAULT_QUEUE_DEPTH, MAX_DEFAULT_QUEUES,
};
