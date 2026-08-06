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

use std::os::fd::RawFd;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::metadata::EROFS_BLOCK_SIZE;
use crate::{Config, NydusCore};

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
    flat_size: u64,
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
        Ok(Self { core, flat_size })
    }

    /// Total size in bytes of the flattened block device exposed to the kernel.
    pub fn flat_size(&self) -> u64 {
        self.flat_size
    }

    /// Total block count (4 KiB units) reported to the NBD driver.
    pub fn blocks(&self) -> u64 {
        self.flat_size / BLOCK_SIZE
    }

    /// Fetch `[offset, offset + buf.len())` of the flattened device view and
    /// copy the resident bytes into `buf`, serving holes, redirect slots, and
    /// gaps as zeros. Both `offset` and `buf.len()` must be block-aligned (the
    /// NBD protocol guarantees this for valid requests). On success every byte
    /// of `buf` has been written.
    pub fn read(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        debug_assert!(offset % BLOCK_SIZE == 0);
        debug_assert!((buf.len() as u64) % BLOCK_SIZE == 0);
        let len = buf.len() as u64;
        let end = offset
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("nbd read range overflow"))?;
        if end > self.flat_size {
            anyhow::bail!(
                "nbd read [{offset}, +{len}) past flattened device size {}",
                self.flat_size
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

/// Read exactly `buf.len()` bytes from `fd` at `offset` without moving the
/// file position (safe on a shared fd). Zero-fills the remainder on EOF: the
/// cache file's block-aligned sizing should never produce one, but the NBD
/// reply must be full-length.
fn pread_exact(fd: RawFd, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let n = unsafe {
            libc::pread(
                fd,
                buf[filled..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - filled,
                (offset + filled as u64) as libc::off_t,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            // EOF before the expected length: zero-fill the rest.
            buf[filled..].fill(0);
            return Ok(());
        }
        filled += n as usize;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pread_exact_zero_len_is_noop() {
        // An empty buffer must return immediately without touching the fd.
        let mut buf = [0u8; 0];
        pread_exact(libc::STDIN_FILENO, &mut buf, 0).unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn pread_exact_zero_fills_past_eof_without_duplicating() {
        use std::io::Write as _;
        use std::os::fd::AsRawFd as _;

        let mut f = tempfile::tempfile().unwrap();
        let content: Vec<u8> = (0u8..100).collect();
        f.write_all(&content).unwrap();

        // Read [80, 144) from a 100-byte file: the first pread returns only
        // 20 bytes, so the loop must advance the offset, hit EOF, and
        // zero-fill the tail — not re-read the same 20 bytes forever.
        let mut buf = [0xAAu8; 64];
        pread_exact(f.as_raw_fd(), &mut buf, 80).unwrap();
        assert_eq!(&buf[..20], &content[80..]);
        assert!(
            buf[20..].iter().all(|&b| b == 0),
            "tail past EOF must be zero-filled, not duplicated file data"
        );
    }
}
