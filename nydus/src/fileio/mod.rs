// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! File-backed EROFS service for nydus images.
//!
//! The daemon exports the flattened image (bootstrap at the head, then each
//! blob at its mapped offset) as a single file over FUSE, and the kernel
//! EROFS driver mounts that file directly. Unlike [`crate::fuse`], which
//! answers every filesystem operation from userspace, here the kernel parses
//! the EROFS metadata itself: lookup, readdir, stat and xattr never leave the
//! kernel, and only cold byte ranges come back as FUSE reads. Unlike
//! [`crate::nbd`] and [`crate::ublk`], no block device is involved, so the
//! guest needs neither `nbd` nor `ublk_drv`. The flattened view itself comes
//! from [`nydus_core::flat`], shared with those services.
//!
//! Requires Linux >= 6.12 (`CONFIG_EROFS_FS_BACKED_BY_FILE`).

pub mod fs;
pub mod mount;
pub mod service;

pub use fs::{FlatImageFs, IMAGE_NAME};
pub use mount::mount_image_file;
pub use service::{image_path, warm_bootstrap, FileioService};
