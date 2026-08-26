//! Blob identity and the blob table's preparation/fetch APIs.
//!
//! [`BlobId`] names a blob by digest, [`BlobInfo`] describes one entry of
//! the bootstrap device table in the flattened layout, and [`Blobs`] turns
//! the table into prepared caches with block-aligned fetch entry points.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};

use nydus_error::{Context, Error, Result};
use nydus_format::erofs::EROFS_BLOCK_SIZE;
use nydus_format::utils::{hex_string, parse_sha256_hex, SHA256_DIGEST_SIZE};

use crate::reader::{ErofsReader, RawBlobInfo};

/// Blob digest used by public core APIs.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BlobId([u8; SHA256_DIGEST_SIZE]);

impl BlobId {
    pub fn new(bytes: [u8; SHA256_DIGEST_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; SHA256_DIGEST_SIZE] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; SHA256_DIGEST_SIZE] {
        self.0
    }

    pub fn to_hex(self) -> String {
        hex_string(&self.0)
    }
}

impl From<[u8; SHA256_DIGEST_SIZE]> for BlobId {
    fn from(value: [u8; SHA256_DIGEST_SIZE]) -> Self {
        Self::new(value)
    }
}

impl From<BlobId> for [u8; SHA256_DIGEST_SIZE] {
    fn from(value: BlobId) -> Self {
        value.into_bytes()
    }
}

impl FromStr for BlobId {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Ok(Self(parse_sha256_hex(value)?))
    }
}

impl fmt::Display for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex_string(&self.0))
    }
}

/// One blob entry from the bootstrap device table.
#[derive(Clone, Debug)]
pub struct BlobInfo {
    /// 1-based blob index, matching the EROFS device table order.
    pub index: u16,
    /// Blob digest recorded in the device slot.
    pub id: BlobId,
    /// Start block of this blob in the flattened single-device layout.
    pub mapped_blkaddr: u64,
    /// Start byte offset of this blob in the flattened single-device layout.
    pub mapped_offset: u64,
    /// Dense uncompressed size in 4 KiB blocks (the pmem device size).
    pub blocks: u64,
    /// Size in bytes of the cache data file (`blocks * 4096`).
    pub cache_size: u64,
    /// Host path of the sparse cache data file backing the pmem device.
    pub cache_path: PathBuf,
    /// True when this is an "ondemand" redirect blob produced by
    /// `nydus optimize`. Its data file is never read by the guest (no chunk
    /// index points at it); it only feeds the phase-0 prefetch that warms the
    /// source blobs' caches.
    pub is_redirect: bool,
}

/// Blob table and decoded-cache preparation/fetch APIs.
pub struct Blobs {
    pub(crate) reader: Arc<ErofsReader>,
    pub(crate) raw_blob_infos: Vec<RawBlobInfo>,
    pub(crate) index_by_blob_id: HashMap<BlobId, u16>,
    /// Memoised result of [`Blobs::flat_layout`].
    pub(crate) flat_layout: OnceLock<Vec<BlobInfo>>,
}

impl Blobs {
    /// Describe every blob in device-table order, preparing each on first
    /// use: the blob meta is downloaded and validated, and the sparse cache
    /// data file is created and sized to the dense uncompressed address
    /// space. Idempotent.
    pub fn prepare_all(&self) -> Result<Vec<BlobInfo>> {
        let block_size = EROFS_BLOCK_SIZE as u64;
        self.raw_blob_infos
            .iter()
            .map(|info| {
                let mapped_offset = info
                    .mapped_blkaddr
                    .checked_mul(block_size)
                    .ok_or_else(|| Error::Overflow("mapped blob offset overflow".to_string()))?;
                let cache = self
                    .reader
                    .blob_cache(info.blob_index)
                    .with_context(|| format!("failed to open blob {}", info.blob_index))?;
                let cache_path = cache.prepare().with_context(|| {
                    format!("failed to prepare cache file for blob {}", info.blob_index)
                })?;
                let cache_size = info
                    .blocks
                    .checked_mul(block_size)
                    .ok_or_else(|| Error::Overflow("blob cache size overflow".to_string()))?;
                Ok(BlobInfo {
                    index: info.blob_index,
                    id: BlobId::from(info.blob_id),
                    mapped_blkaddr: info.mapped_blkaddr,
                    mapped_offset,
                    blocks: info.blocks,
                    cache_size,
                    cache_path,
                    is_redirect: cache.is_redirect(),
                })
            })
            .collect()
    }

    /// Describe the blobs that back the flattened single-device address
    /// space, sorted by `mapped_offset` and with redirect blobs removed.
    ///
    /// The layout is fixed for the lifetime of the core, so it is computed
    /// once and memoised: block-device style workloads resolve ranges on every
    /// I/O and must not pay for re-enumerating (and re-sorting) the blob table
    /// each time. The first call prepares every blob, exactly as
    /// [`Blobs::prepare_all`] does.
    pub fn flat_layout(&self) -> Result<&[BlobInfo]> {
        if let Some(layout) = self.flat_layout.get() {
            return Ok(layout);
        }
        let mut blobs = self.prepare_all()?;
        blobs.retain(|blob| !blob.is_redirect);
        blobs.sort_by_key(|blob| blob.mapped_offset);
        // A racing caller may have won the initialisation; either value is
        // equally valid because the layout is deterministic.
        let _ = self.flat_layout.set(blobs);
        Ok(self
            .flat_layout
            .get()
            .expect("flat layout is initialised above"))
    }

    /// Resolve a blob id to its device-table index and opened cache.
    fn blob_cache_for(
        &self,
        id: &BlobId,
    ) -> Result<(u16, Arc<dyn nydus_storage::cache::BlobCache>)> {
        let blob_index = *self.index_by_blob_id.get(id).ok_or_else(|| {
            Error::NotFound("blob is not referenced by the bootstrap".to_string())
        })?;
        let cache = self
            .reader
            .blob_cache(blob_index)
            .with_context(|| format!("failed to open blob {blob_index}"))?;
        Ok((blob_index, cache))
    }

    /// Ensure `[offset, offset + len)` of the blob's dense uncompressed
    /// address space is decoded, CRC-validated, and written to its cache data
    /// file, fetching missing block groups through the backend. Both `offset` and
    /// `len` must be 4 KiB block aligned; the fetch rounds outward to whole
    /// blob meta block groups. Idempotent and safe to call concurrently.
    pub fn fetch(&self, id: &BlobId, offset: u64, len: u64) -> Result<()> {
        let block_size = EROFS_BLOCK_SIZE as u64;
        if offset % block_size != 0 || len % block_size != 0 {
            return Err(Error::InvalidParameter(format!(
                "fetch range must be 4 KiB block aligned: offset={offset} len={len}"
            )));
        }
        if len == 0 {
            return Ok(());
        }

        let (blob_index, cache) = self.blob_cache_for(id)?;
        cache
            .ensure_range(offset, len)
            .with_context(|| format!("failed to fetch blob {blob_index} range [{offset}, +{len})"))
    }

    /// Return cache-ready byte intervals overlapping `[offset, offset + len)`
    /// without triggering a backend fetch. The block_group_map remains authoritative.
    pub fn ready_ranges(
        &self,
        id: &BlobId,
        offset: u64,
        len: u64,
    ) -> Result<Vec<std::ops::Range<u64>>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let (blob_index, cache) = self.blob_cache_for(id)?;
        cache.ready_ranges(offset, len).with_context(|| {
            format!("failed to inspect blob {blob_index} ready range [{offset}, +{len})")
        })
    }

    /// O(1) fast-path probe: true when every block group of the blob is already
    /// decoded into its local cache (a single shared-flag load, no bitmap
    /// scan). On-demand services (uffd, fanotify, FUSE) can consult this per
    /// event — or once per blob, since the answer is sticky — to bypass range
    /// readiness checks and fetch plumbing entirely for fully warmed blobs.
    pub fn is_all_ready(&self, id: &BlobId) -> Result<bool> {
        let (_, cache) = self.blob_cache_for(id)?;
        Ok(cache.is_all_ready())
    }
}
