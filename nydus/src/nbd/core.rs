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

use anyhow::{Context, Result};

use nydus_core::metadata::EROFS_BLOCK_SIZE;
use nydus_core::utils::pread_exact;
use nydus_core::{Config, NydusCore};

/// EROFS block size as u64 — reuses the canonical constant from the core.
const BLOCK_SIZE: u64 = EROFS_BLOCK_SIZE as u64;

/// Read-side handle for the NBD on-demand service.
///
/// Holds a shared core (so background prefetch keeps running) and the
/// flattened device size computed at construction. All read paths are
/// block-aligned by the NBD protocol, which matches the core's fetch
/// precondition.
pub struct NbdCore {
    core: Arc<NydusCore>,
    device_size: u64,
}

impl NbdCore {
    /// Parse the bootstrap and config and compute the flattened device size.
    /// No blob meta is downloaded and no cache file is created until a read
    /// first touches a blob, so this returns quickly even for large images.
    pub fn new(bootstrap: &Path, config: Config) -> Result<Self> {
        let core =
            Arc::new(NydusCore::new(bootstrap, config).context("failed to create nydus core")?);

        let flat_size = core.flat_size();
        if flat_size == 0 {
            anyhow::bail!("flattened image size is zero");
        }
        if flat_size % BLOCK_SIZE != 0 {
            anyhow::bail!(
                "flattened image size {flat_size} is not a multiple of the {BLOCK_SIZE} B EROFS block size"
            );
        }
        Ok(Self {
            core,
            device_size: flat_size,
        })
    }

    /// Total size in bytes of the flattened block device exposed to the kernel.
    pub fn device_size(&self) -> u64 {
        self.device_size
    }

    /// Total block count (4 KiB units) reported to the NBD driver.
    pub fn blocks(&self) -> u64 {
        self.device_size / BLOCK_SIZE
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
        debug_assert!(offset % BLOCK_SIZE == 0);
        debug_assert!((buf.len() as u64) % BLOCK_SIZE == 0);
        let len = buf.len() as u64;
        let end = offset
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("nbd read range overflow"))?;
        if end > self.device_size {
            anyhow::bail!(
                "nbd read [{offset}, +{len}) past flattened device size {}",
                self.device_size
            );
        }

        let ranges = self
            .core
            .fetch_flat_ranges(offset, len)
            .context("failed to fetch flat ranges for nbd read")?;
        let zero_fd = self.core.zero_fd();
        let mut written = 0usize;
        for range in ranges {
            // The fetch contract is a gapless cover of the request window;
            // check it explicitly so a contract drift surfaces as an error
            // instead of silently misplacing bytes.
            if range.source_offset != offset + written as u64 {
                anyhow::bail!(
                    "flat ranges are not contiguous: expected source offset {}, got {}",
                    offset + written as u64,
                    range.source_offset
                );
            }
            let seg_len = range.len as usize;
            if written + seg_len > buf.len() {
                anyhow::bail!(
                    "flat range segment overflows read buffer: written={written} seg_len={seg_len} buf={}",
                    buf.len()
                );
            }
            let seg = &mut buf[written..written + seg_len];
            if range.fd == zero_fd {
                // Hole / redirect slot / unfetched tail: serve zeros.
                seg.fill(0);
            } else {
                pread_exact(range.fd, seg, range.offset).with_context(|| {
                    format!(
                        "failed to pread {seg_len} bytes at offset {} from flat-range fd",
                        range.offset
                    )
                })?;
            }
            written += seg_len;
        }
        // The core resolves the whole requested window, so every byte is
        // accounted for; pad the tail with zeros defensively if it ever is not.
        if written < buf.len() {
            buf[written..].fill(0);
        }
        Ok(())
    }
}
