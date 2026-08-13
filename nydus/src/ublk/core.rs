//! Flattened block-device view of a nydus image.
//!
//! [`UblkCore`] turns [`NydusCore`]'s flattened device view into a plain
//! `read_at(offset, buf)` interface: the bootstrap is exposed at the beginning
//! of the address space, each blob at the `mapped_blkaddr` recorded in the
//! bootstrap device table, and the gaps in between as zeroes. That is exactly
//! the layout the kernel EROFS driver expects from a single block device, so
//! the resulting device can be mounted with `mount -t erofs /dev/ublkbN`.

use std::io;
use std::os::fd::RawFd;
use std::path::Path;

use nydus_core::config::Config;
use nydus_core::error::{Context, Error, Result};
use nydus_core::fs::{copy_ranges, FileMaps};
use nydus_core::metadata::EROFS_BLOCK_SIZE;
use nydus_core::utils::align_up;
use nydus_core::NydusCore;
use tracing::warn;

/// Logical block size exposed by the ublk device. Matching the EROFS block size
/// keeps every incoming request aligned to a whole number of EROFS blocks.
pub const UBLK_LOGICAL_BLOCK_SIZE: u64 = EROFS_BLOCK_SIZE as u64;

/// Read-only block device backed by a nydus image.
pub struct UblkCore {
    core: NydusCore,
    zero_fd: RawFd,
    device_size: u64,
    maps: FileMaps,
}

impl UblkCore {
    /// Open `bootstrap` with the storage `config` and expose it as a flattened
    /// read-only block device. All blobs referenced by the bootstrap device
    /// table are prepared up front, and background prefetch follows
    /// `config.prefetch`.
    pub fn new(bootstrap: &Path, config: Config) -> Result<Self> {
        let core = NydusCore::new(bootstrap, config)
            .context("failed to open nydus image for the ublk device")?;
        let zero_fd = core.zero_fd();
        // Round the device size up to a whole block: the kernel always reads in
        // block units, and the tail block of the last blob may be partial.
        let device_size = align_up(core.flat_size(), UBLK_LOGICAL_BLOCK_SIZE)
            .ok_or_else(|| Error::Overflow("flattened device size overflow".to_string()))?;
        // Preparing a blob downloads and validates its meta and sizes its cache
        // file, which takes seconds for a large image. Left to the first block
        // read it stalls whoever gets there first — typically `mount`, which
        // then appears to hang long after the device was announced as ready.
        core.blobs
            .flat_layout()
            .context("failed to prepare the blobs backing the device")?;

        Ok(Self {
            core,
            zero_fd,
            device_size,
            maps: FileMaps::default(),
        })
    }

    /// Size of the block device in bytes, always a multiple of
    /// [`UBLK_LOGICAL_BLOCK_SIZE`].
    pub fn device_size(&self) -> u64 {
        self.device_size
    }

    /// Borrow the underlying core, e.g. to snapshot metrics.
    pub fn core(&self) -> &NydusCore {
        &self.core
    }

    /// Read `buf.len()` bytes at `offset` of the flattened device.
    ///
    /// Ranges past the end of the image, gaps between blobs and holes in a
    /// partially fetched blob all read as zeroes, mirroring what a real block
    /// device with sparse backing would return. Missing blob data is fetched
    /// from the backend on demand before the copy.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        if offset >= self.device_size {
            buf.fill(0);
            return Ok(());
        }

        let len = (buf.len() as u64).min(self.device_size - offset);
        let ranges = self.core.fetch_flat_ranges(offset, len).map_err(|err| {
            // Recover the OS errno when the fetch failed on IO, so the ublk
            // reply carries the real code instead of collapsing to EIO. A
            // bare `from_raw_os_error` drops the context chain, so log it
            // here before converting.
            match err.io_error().and_then(|io_err| io_err.raw_os_error()) {
                Some(errno) => {
                    warn!("ublk fetch at {offset} (+{len}) failed: {err}");
                    io::Error::from_raw_os_error(errno)
                }
                None => io::Error::other(err),
            }
        })?;

        copy_ranges(&ranges, offset, self.zero_fd, buf, &self.maps)
    }
}
