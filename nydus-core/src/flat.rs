// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! The flattened image view shared by the block-shaped mount services.
//!
//! The crate already supplies the primitives — [`NydusCore::fetch_flat_ranges`]
//! resolves a window of the flattened address space into mmap-ready extents,
//! and [`MmapCache`] copies them out — but every service that presents the
//! image as a linear byte range needs the same glue on top: an image size
//! rounded up to whatever the transport addresses in, and a read that fetches
//! the covering ranges, copies the resident bytes, and reports the rest as
//! zeros.
//!
//! This module is that glue. It lives here rather than in the service crate
//! so an embedder wiring the read path into a hypervisor (virtio-pmem, a
//! block target) gets an addressable image without pulling in FUSE, the CLI,
//! or any mount service.
//!
//! What stays in each service is what is genuinely protocol-specific: NBD
//! rejects out-of-range requests because its protocol guarantees they never
//! occur, ublk converts failures back into an `errno` for its completion
//! path, and uffd resolves ranges without copying because the kernel hands it
//! the destination pages.

use std::path::Path;
use std::sync::Arc;

use nydus_config::Config;
use nydus_error::{Context, Error, Result};
use nydus_format::erofs::EROFS_BLOCK_SIZE;
use nydus_format::utils::align_up_u64;

use crate::extent::{Extent, MmapCache};
use crate::NydusCore;

/// EROFS block size as u64 — the granularity every flattened read is aligned
/// to.
pub const BLOCK_SIZE: u64 = EROFS_BLOCK_SIZE as u64;

/// A nydus image presented as one linear, read-only byte range.
///
/// The layout is the one `nydus-core` defines: the bootstrap at the head,
/// then each blob at its mapped offset, with gaps and redirect blobs reading
/// as zeros.
pub struct FlatImage {
    core: Arc<NydusCore>,
    size: u64,
    maps: MmapCache,
}

impl FlatImage {
    /// Open `bootstrap` with `config` and expose it as a flattened image
    /// whose size is rounded up to `align` bytes.
    ///
    /// Pass [`BLOCK_SIZE`] for transports that address in EROFS blocks; a
    /// larger alignment (a ublk logical block, a uffd region) rounds up and
    /// the padding reads as zeros. No blob meta is downloaded and no cache
    /// file is created here, so this returns quickly even for large images.
    pub fn open(bootstrap: &Path, config: Config, align: u64) -> Result<Self> {
        let core = Arc::new(NydusCore::new(bootstrap, config)?);
        Self::with_core(core, align)
    }

    /// Wrap an already-open core, e.g. to share one image between a service
    /// and its metrics or prefetch machinery.
    pub fn with_core(core: Arc<NydusCore>, align: u64) -> Result<Self> {
        let flat_size = core.flat_size();
        if flat_size == 0 {
            return Err(Error::InvalidImage(
                "flattened image size is zero".to_string(),
            ));
        }
        if flat_size % BLOCK_SIZE != 0 {
            return Err(Error::InvalidImage(format!(
                "flattened image size {flat_size} is not a multiple of the {BLOCK_SIZE} B EROFS block size"
            )));
        }
        let size = align_up_u64(flat_size, align)
            .ok_or_else(|| Error::Overflow("flattened image size overflow".to_string()))?;

        Ok(Self {
            core,
            size,
            maps: MmapCache::default(),
        })
    }

    /// Size in bytes of the flattened view, rounded up to the alignment given
    /// at construction.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Size in [`BLOCK_SIZE`] units.
    pub fn block_count(&self) -> u64 {
        self.size / BLOCK_SIZE
    }

    /// Borrow the underlying core, e.g. to snapshot metrics, start prefetch,
    /// or locate the bootstrap region inside the view.
    pub fn core(&self) -> &Arc<NydusCore> {
        &self.core
    }

    /// The core-owned `/dev/zero` fd used to serve holes.
    pub fn zero_fd(&self) -> std::os::fd::RawFd {
        self.core.zero_fd()
    }

    /// Fetch `[offset, offset + buf.len())` and copy the resident bytes into
    /// `buf`, serving holes, redirect slots, gaps and any range past the end
    /// of the image as zeros.
    ///
    /// `offset` and `buf.len()` must both be [`BLOCK_SIZE`]-aligned: the fetch
    /// path rounds outward to whole block groups, so an unaligned window
    /// would silently pull in neighbouring data. On success every byte of
    /// `buf` has been written.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        debug_assert!(offset % BLOCK_SIZE == 0);
        debug_assert!((buf.len() as u64) % BLOCK_SIZE == 0);

        // Alignment padding lives past the flattened extent, so a request can
        // legitimately start there; it reads as zeros like any other hole.
        if offset >= self.size {
            buf.fill(0);
            return Ok(());
        }
        let len = (buf.len() as u64).min(self.size - offset);
        if len < buf.len() as u64 {
            buf[len as usize..].fill(0);
        }

        let ranges = self
            .core
            .fetch_flat_ranges(offset, len)
            .context("failed to fetch flat ranges")?;

        // The shared copy is gap-tolerant, so a drifted fetch contract would
        // show up as silently misplaced bytes rather than an error.
        self.validate_contiguous_ranges(&ranges, offset, len)?;
        self.maps
            .copy_ranges(
                &ranges,
                offset,
                self.core.zero_fd(),
                &mut buf[..len as usize],
            )
            .context("failed to copy flat ranges")?;
        Ok(())
    }

    fn validate_contiguous_ranges(&self, ranges: &[Extent], offset: u64, len: u64) -> Result<()> {
        let mut written = 0u64;
        for range in ranges {
            if range.source_offset != offset + written {
                return Err(Error::Runtime(format!(
                    "flat ranges are not contiguous: expected source offset {}, got {}",
                    offset + written,
                    range.source_offset
                )));
            }
            written += range.len;
            if written > len {
                return Err(Error::Runtime(format!(
                    "flat range segments overflow the read window: covered={written} len={len}"
                )));
            }
        }
        Ok(())
    }
}
