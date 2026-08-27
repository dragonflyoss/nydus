//! Fill engine for the NBD service, flat single-device model.
//!
//! The core exposes the whole image as one flattened device view: the
//! bootstrap at the head, then each blob at its `mapped_offset`, with gaps
//! (and any redirect blob) reported as `/dev/zero`. [`NbdCore`] wraps that
//! view with a synchronous `read` that fetches the covering ranges and copies
//! bytes out of the resolved fds; the pwrite/dedup/fsync I/O lives in (and is
//! tested by) `nydus-core`.
//!
//! # Flattened superblock — kernel flatdev auto-detection
//!
//! A nydus EROFS image always carries a device table: chunk indexes store
//! blob-relative block addresses and each device slot carries the blob's
//! `mapped_blkaddr` in the flattened address space. When the kernel mounts a
//! device-table image without any `device=` option — the NBD mount never
//! passes one — it enables "flatdev" mode (`erofs_scan_devices`) and resolves
//! every chunk to `chunk address + slot uniaddr`, exactly the view this
//! module serves, so the bootstrap goes to the kernel **unmodified**. Do not
//! zero the device table instead: without it the kernel masks every chunk's
//! `device_id` to 0 and treats blob-relative addresses as flat offsets, so
//! files silently read back bootstrap bytes or holes.

use std::path::Path;
use std::sync::Arc;

use nydus_config::Config;
use nydus_core::flat::{FlatImage, BLOCK_SIZE};
use nydus_core::NydusCore;
use nydus_error::{Error, Result};

/// Read-side handle for the NBD on-demand service.
///
/// A thin protocol adapter over the shared [`FlatImage`]: it adds the range
/// check the NBD protocol guarantees (so a violated guarantee surfaces as an
/// error instead of silent zeros) and reports the geometry the driver needs.
pub struct NbdCore {
    image: FlatImage,
}

impl NbdCore {
    /// Parse the bootstrap and config and compute the flattened device size.
    /// No blob meta is downloaded and no cache file is created until a read
    /// first touches a blob, so this returns quickly even for large images.
    pub fn new(bootstrap: &Path, config: Config) -> Result<Self> {
        // The NBD device addresses in EROFS blocks, so no extra rounding.
        let image = FlatImage::open(bootstrap, config, BLOCK_SIZE)?;
        Ok(Self { image })
    }

    /// Total size in bytes of the flattened block device exposed to the kernel.
    pub fn device_size(&self) -> u64 {
        self.image.size()
    }

    /// Total block count (4 KiB units) reported to the NBD driver.
    pub fn block_count(&self) -> u64 {
        self.image.block_count()
    }

    /// Borrow the underlying core, e.g. to snapshot metrics.
    pub fn core(&self) -> &Arc<NydusCore> {
        self.image.core()
    }

    /// Fetch `[offset, offset + buf.len())` of the flattened device view and
    /// copy the resident bytes into `buf`, serving holes, redirect slots, and
    /// gaps as zeros. Both `offset` and `buf.len()` must be block-aligned (the
    /// NBD protocol guarantees this for valid requests). On success every byte
    /// of `buf` has been written.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let len = buf.len() as u64;
        let end = offset
            .checked_add(len)
            .ok_or_else(|| Error::Overflow("nbd read range overflow".to_string()))?;
        // The shared view would zero-fill past the end; for NBD that can only
        // mean a malformed request, so reject it instead.
        if end > self.device_size() {
            return Err(Error::InvalidParameter(format!(
                "nbd read [{offset}, +{len}) past flattened device size {}",
                self.device_size()
            )));
        }
        self.image.read_at(offset, buf)
    }
}
