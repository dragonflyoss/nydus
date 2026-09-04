//! Flattened block-device view of a nydus image.
//!
//! [`UblkCore`] turns [`NydusCore`]'s flattened device view into a plain
//! `read_at(offset, buf)` interface: the bootstrap is exposed at the beginning
//! of the address space, each blob at the `mapped_blkaddr` recorded in the
//! bootstrap device table, and the gaps in between as zeroes. That is exactly
//! the layout the kernel EROFS driver expects from a single block device, so
//! the resulting device can be mounted with `mount -t erofs /dev/ublkbN`.

use std::io;
use std::path::Path;
use std::sync::Arc;

use nydus_config::Config;
use nydus_core::flat::FlatImage;
use nydus_core::NydusCore;
use nydus_error::{Context, Result};
use nydus_format::erofs::EROFS_BLOCK_SIZE;
use tracing::warn;

/// Logical block size exposed by the ublk device. Matching the EROFS block size
/// keeps every incoming request aligned to a whole number of EROFS blocks.
pub const UBLK_LOGICAL_BLOCK_SIZE: u64 = EROFS_BLOCK_SIZE as u64;

/// Read-only block device backed by a nydus image.
pub struct UblkCore {
    image: FlatImage,
}

impl UblkCore {
    /// Open `bootstrap` with the storage `config` and expose it as a flattened
    /// read-only block device. All blobs referenced by the bootstrap device
    /// table are prepared up front, and background prefetch follows
    /// `config.prefetch`.
    pub fn new(bootstrap: &Path, config: Config) -> Result<Self> {
        // The kernel always reads in whole blocks, and the tail block of the
        // last blob may be partial, so the device is rounded up.
        let image = FlatImage::open(bootstrap, config, UBLK_LOGICAL_BLOCK_SIZE)?;
        // Warm the blob preparation (meta download + cache file sizing) in
        // the background so device creation and the EROFS mount are not
        // blocked on backend round trips. flat_layout() is single-flight: an
        // I/O arriving first simply joins the same preparation.
        let warm = image.core().clone();
        std::thread::Builder::new()
            .name("ublk-blob-warmup".to_string())
            .spawn(move || {
                if let Err(err) = warm.blobs.flat_layout() {
                    tracing::warn!("background blob preparation failed: {err:#}");
                }
            })
            .context("failed to spawn the blob warm-up thread")?;

        Ok(Self { image })
    }

    /// Size of the block device in bytes, always a multiple of
    /// [`UBLK_LOGICAL_BLOCK_SIZE`].
    pub fn device_size(&self) -> u64 {
        self.image.size()
    }

    /// Borrow the underlying core, e.g. to snapshot metrics.
    pub fn core(&self) -> &Arc<NydusCore> {
        self.image.core()
    }

    /// Read `buf.len()` bytes at `offset` of the flattened device.
    ///
    /// Ranges past the end of the image, gaps between blobs and holes in a
    /// partially fetched blob all read as zeroes, mirroring what a real block
    /// device with sparse backing would return. Missing blob data is fetched
    /// from the backend on demand before the copy.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.image.read_at(offset, buf).map_err(|err| {
            // Recover the OS errno when the fetch failed on IO, so the ublk
            // reply carries the real code instead of collapsing to EIO. A
            // bare `from_raw_os_error` drops the context chain, so log it
            // here before converting.
            match err.io_error().and_then(|io_err| io_err.raw_os_error()) {
                Some(errno) => {
                    warn!(
                        "ublk read at {offset} (+{}) failed: {}",
                        buf.len(),
                        err.report()
                    );
                    io::Error::from_raw_os_error(errno)
                }
                None => io::Error::other(err),
            }
        })
    }
}
