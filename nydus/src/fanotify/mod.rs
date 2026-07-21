//! Fanotify pre-content on-demand service for native EROFS mounts (multi-device).
//!
//! nydus's native shape is multi-device EROFS: the **bootstrap is a real local
//! EROFS image** (superblock + all inode/dirent metadata + a device table) that
//! the operator mounts directly, and each data **blob is a separate EROFS device**
//! backed by the accessor's per-blob sparse cache file. This daemon marks the
//! blob devices and fills them on demand via [`NydusAccessor`]'s blob fetch.
//!
//! Consequences of the multi-device split: mount and metadata reads (`ls`,
//! `stat`) hit the real local bootstrap and never involve fanotify; only cold
//! blob-data reads fault. Contrast the flat single-image model (bootstrap+blobs
//! flattened into one sparse device), which would require on-demand filling even
//! of the superblock at mount time.
//!
//! **Status: implemented, e2e verified on Linux 6.15+.** fanotify pre-content
//! (FAN_CLASS_PRE_CONTENT + FAN_PRE_ACCESS) is the upstream-sanctioned replacement
//! for the (deprecated) EROFS-over-fscache path (dragonflyoss/nydus#1826). The
//! kernel-independent logic — event/RANGE parsing, deny-on-missing-range,
//! blob-device lookup, fetch-range alignment, admission, request coalescing,
//! and response ownership — is unit-tested; the full on-demand data path has
//! been verified end-to-end with a registry backend on a 6.15 kernel.
//!
//! [`NydusAccessor`]: crate::NydusAccessor

pub mod core;
pub mod event;
pub mod mount;
pub mod response;
pub mod service;

pub use core::{BlobDevice, FanotifyCore, Response};
pub use event::{EventIter, ParseError, ParseErrorKind, PreContentEvent, Range};
pub use mount::{mount_erofs, unmount_erofs};
pub use service::FanotifyService;
