//! Runtime core APIs for EROFS-based Nydus images.
//!
//! This crate provides the host-side building blocks used to serve Nydus
//! images at runtime: EROFS metadata parsing ([`metadata`]), an on-demand
//! blob cache and storage backends ([`storage`]), an image reader ([`fs`]),
//! an image builder ([`build`]), telemetry ([`telemetry`]), and the
//! high-level [`NydusCore`] entry point defined at the crate root.
//!
//! # NydusCore and virtio-pmem
//!
//! A guest kernel mounts the nydus bootstrap as an EROFS image whose external
//! devices are virtio-pmem devices backed by the host-side cache data files
//! (`{cache_dir}/{hex}.blob.data`). Each cache file mirrors the blob's dense
//! decoded block address space, so a guest read of block `N` lands at byte
//! `N * 4096` of the backing file. [`NydusCore`] exposes the device
//! table needed to wire up those pmem devices and a [`blobs.fetch`] entry point
//! that guarantees a block-aligned range is decoded and resident before the
//! guest touches it.
//!
//! Optional cargo features:
//! - `backend-registry`: container image registry backend (OCI distribution).
//! - `backend-dragonfly-proxy`: Dragonfly P2P SDK proxy for the registry
//!   backend.
//!
//! [`blobs.fetch`]: Blobs::fetch

#![warn(unreachable_pub)]

pub mod blob;
pub mod build;
pub mod config;
pub mod fs;
pub mod metadata;
pub mod optimize;
pub mod storage;
pub mod telemetry;
pub mod utils;

pub use config::Config;
pub use fs::{FdRange, FileType, ResolveMode};
pub use telemetry::access_trace::{TraceDocument, TraceEntry};

use std::collections::HashMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, OnceLock};

use anyhow::{bail, Context, Result};

use crate::fs::{
    checked_range_end, mapped_range_offset, push_blob_fd_ranges, push_fd_range, BlobRangeSpec,
    ErofsReader, ImageFs, RawBlobInfo,
};
use crate::metadata::EROFS_BLOCK_SIZE;
use crate::storage::backend::build_backend;
use crate::storage::prefetch::BlobPrefetcher;
use crate::telemetry::access_trace::TraceRecorder;
use crate::utils::{hex_string, parse_sha256_hex, SHA256_DIGEST_SIZE};

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
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
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

/// Read-side handle over a nydus image, split into blob data access and
/// static filesystem metadata/data access.
pub struct NydusCore {
    /// Size in bytes of the standalone bootstrap image passed to [`new`].
    ///
    /// [`new`]: Self::new
    pub bootstrap_size: u64,
    /// Blob table and decoded-cache preparation/fetch APIs.
    pub blobs: Blobs,
    /// Static path-based filesystem APIs.
    pub fs: ImageFs,
    bootstrap: Arc<File>,
    zero_file: Arc<File>,
    flat_size: u64,
    trace_recorder: Arc<TraceRecorder>,
}

/// Blob table and decoded-cache preparation/fetch APIs.
pub struct Blobs {
    reader: Arc<ErofsReader>,
    raw_blob_infos: Vec<RawBlobInfo>,
    index_by_blob_id: HashMap<BlobId, u16>,
    /// Memoised result of [`Blobs::flat_layout`].
    flat_layout: OnceLock<Vec<BlobInfo>>,
}

impl NydusCore {
    /// Parse the bootstrap and config and build the blob table,
    /// deferring all per-blob work: no blob meta is downloaded and no cache
    /// file is created until [`blobs`], [`fetch`], or [`prefetch`] first
    /// touches a blob.
    ///
    /// `config` uses the same structure as `nydus fuse --config` and must
    /// provide both the backend serving the blobs and a persistent local cache
    /// directory.
    ///
    /// When `config.prefetch.enable` is set, a background prefetch worker is
    /// spawned before returning: for an optimized image it streams the
    /// "ondemand" redirect blob first (priority) to warm the source blobs'
    /// caches in recorded access order, then prefetches the remaining blobs.
    /// The worker shares the reader's blob cache set, so callers that want
    /// network access (e.g. the virtio-pmem backend) must construct the core
    /// while the desired network namespace is active so the spawned thread
    /// inherits it.
    ///
    /// [`blobs`]: Self::blobs
    /// [`fetch`]: Self::fetch
    pub fn new(bootstrap: &Path, config: Config) -> Result<Self> {
        let bootstrap_file = Arc::new(
            OpenOptions::new()
                .read(true)
                .open(bootstrap)
                .with_context(|| format!("failed to open bootstrap: {}", bootstrap.display()))?,
        );
        let zero_file = Arc::new(
            OpenOptions::new()
                .read(true)
                .open("/dev/zero")
                .context("failed to open /dev/zero")?,
        );
        let bootstrap_size = bootstrap_file
            .metadata()
            .with_context(|| format!("failed to stat bootstrap: {}", bootstrap.display()))?
            .len();
        let prefetch_enable = config.prefetch.enable;
        let prefetch_threads = config.prefetch.threads;
        let prefetch_full = config.prefetch.full;
        let backend = build_backend(&config.backend).context("failed to build blob backend")?;
        let cache_dir = config
            .cache_dir()
            .context("failed to resolve cache directory from config")?;
        std::fs::create_dir_all(&cache_dir).with_context(|| {
            format!("failed to create cache directory: {}", cache_dir.display())
        })?;

        let trace_recorder = Arc::new(TraceRecorder::default());
        let reader = ErofsReader::open_with_trace(
            None,
            Some(bootstrap),
            Some(backend),
            Some(&cache_dir),
            Some(trace_recorder.clone()),
        )
        .context("failed to open nydus bootstrap")?;
        let raw_blob_infos = reader.blob_infos().context("failed to read blob table")?;
        if raw_blob_infos.is_empty() {
            bail!("bootstrap contains no blobs");
        }
        let flat_size = raw_blob_infos
            .iter()
            .try_fold(bootstrap_size, |size, info| {
                let offset = info
                    .mapped_blkaddr
                    .checked_mul(EROFS_BLOCK_SIZE as u64)
                    .context("mapped blob offset overflow")?;
                let len = info
                    .blocks
                    .checked_mul(EROFS_BLOCK_SIZE as u64)
                    .context("blob size overflow")?;
                Ok::<u64, anyhow::Error>(
                    size.max(
                        offset
                            .checked_add(len)
                            .context("flat blob range overflow")?,
                    ),
                )
            })?;
        let index_by_blob_id = raw_blob_infos
            .iter()
            .map(|info| (BlobId::from(info.blob_id), info.blob_index))
            .collect();
        let reader = Arc::new(reader);

        // Kick off background prefetch as soon as the core is built when the
        // config opts in. The worker holds its own `Arc` of the blob cache
        // set, so it keeps running (and keeps the caches alive) independently
        // of the returned core. The handle is detached: prefetch is
        // best-effort warmup and must never block core construction or
        // teardown.
        if prefetch_enable {
            let prefetcher = BlobPrefetcher::new(
                reader.blob_cache_set(),
                reader.prefetch_plan(),
                prefetch_threads,
                prefetch_full,
            );
            match prefetcher.spawn() {
                Ok(_handle) => {
                    tracing::info!(
                        "nydus core: background prefetch started (full={prefetch_full})"
                    );
                }
                Err(err) => {
                    tracing::warn!("nydus core: failed to start prefetch worker: {err}");
                }
            }
        }

        Ok(Self {
            bootstrap_size,
            blobs: Blobs {
                reader: reader.clone(),
                raw_blob_infos,
                index_by_blob_id,
                flat_layout: OnceLock::new(),
            },
            fs: ImageFs::new(reader, zero_file.clone()),
            bootstrap: bootstrap_file,
            zero_file,
            flat_size,
            trace_recorder,
        })
    }

    /// Return the bootstrap file backing this core.
    pub fn bootstrap(&self) -> &File {
        &self.bootstrap
    }

    /// Return the size of the flattened device view.
    pub fn flat_size(&self) -> u64 {
        self.flat_size
    }

    /// Return the core-owned `/dev/zero` fd used for zero-filled ranges.
    pub fn zero_fd(&self) -> RawFd {
        self.zero_file.as_raw_fd()
    }

    /// Fetch `[offset, offset + len)` in the flattened device view and return
    /// mmap-ready ranges. The bootstrap is exposed at the beginning of the
    /// view, and gaps between blob files are returned as `/dev/zero` ranges.
    pub fn fetch_flat_ranges(&self, offset: u64, len: u64) -> Result<Vec<FdRange>> {
        self.resolve_flat_ranges(offset, len, ResolveMode::Fetch)
    }

    /// Probe `[offset, offset + len)` in the flattened device view without
    /// downloading missing blob data. Bootstrap and gaps are returned when
    /// ready; cold blob cache ranges are omitted, so the result may be
    /// discontinuous.
    pub fn probe_flat_ranges(&self, offset: u64, len: u64) -> Result<Vec<FdRange>> {
        self.resolve_flat_ranges(offset, len, ResolveMode::Probe)
    }

    /// Return a stable snapshot of this core's on-demand group trace.
    pub fn trace_snapshot(&self) -> TraceDocument {
        self.trace_recorder.snapshot()
    }

    /// Serialize this core's on-demand group trace as optimize-compatible JSON.
    pub fn trace_json(&self) -> String {
        self.trace_recorder.encode_json()
    }

    fn resolve_flat_ranges(
        &self,
        offset: u64,
        len: u64,
        mode: ResolveMode,
    ) -> Result<Vec<FdRange>> {
        let end = match checked_range_end(offset, len)? {
            Some(end) => end.min(self.flat_size),
            None => return Ok(Vec::new()),
        };
        if offset >= end {
            return Ok(Vec::new());
        }

        let mut ranges = Vec::new();
        let mut pos = offset;
        let bootstrap_end = end.min(self.bootstrap_size);
        if pos < bootstrap_end {
            push_fd_range(
                &mut ranges,
                FdRange::new(self.bootstrap.as_raw_fd(), pos, bootstrap_end - pos, pos),
                self.zero_file.as_raw_fd(),
            );
            pos = bootstrap_end;
        }
        if pos >= end {
            return Ok(ranges);
        }

        let blobs = self
            .blobs
            .flat_layout()
            .context("failed to describe blob device layout")?;

        while pos < end {
            // `blobs` is sorted by `mapped_offset` and blob ranges never
            // overlap (device-table layout), so the only candidate containing
            // `pos` is the last blob starting at or before it — found with a
            // binary search instead of a linear scan (this runs per I/O).
            let after = blobs.partition_point(|blob| blob.mapped_offset <= pos);
            let covering = after
                .checked_sub(1)
                .map(|index| &blobs[index])
                .filter(|blob| {
                    mapped_range_offset(blob.mapped_offset, blob.cache_size, pos).is_some()
                });

            if let Some(blob) = covering {
                let blob_end = blob
                    .mapped_offset
                    .checked_add(blob.cache_size)
                    .context("blob device range overflow")?;
                let seg_end = end.min(blob_end);
                let blob_offset = pos - blob.mapped_offset;
                push_blob_fd_ranges(
                    &self.blobs.reader,
                    self.zero_file.as_raw_fd(),
                    &mut ranges,
                    BlobRangeSpec {
                        index: blob.index,
                        offset: blob_offset,
                        len: seg_end - pos,
                        source_offset: pos,
                    },
                    mode,
                )?;
                pos = seg_end;
            } else {
                // `blobs[after]` is the first blob starting after `pos`, so it
                // bounds the hole (or the view ends first).
                let next_blob = blobs
                    .get(after)
                    .map(|blob| blob.mapped_offset)
                    .unwrap_or(end);
                let hole_end = end.min(next_blob);
                if hole_end <= pos {
                    break;
                }
                push_fd_range(
                    &mut ranges,
                    FdRange::new(self.zero_file.as_raw_fd(), 0, hole_end - pos, pos),
                    self.zero_file.as_raw_fd(),
                );
                pos = hole_end;
            }
        }

        Ok(ranges)
    }
}

impl Blobs {
    /// Describe every blob in device-table order, preparing each on first
    /// use: the blob meta is downloaded and validated, and the sparse cache
    /// data file is created and sized to the dense uncompressed address
    /// space. Idempotent.
    pub fn prepare_entries(&self) -> Result<Vec<BlobInfo>> {
        let block_size = EROFS_BLOCK_SIZE as u64;
        self.raw_blob_infos
            .iter()
            .map(|info| {
                let mapped_offset = info
                    .mapped_blkaddr
                    .checked_mul(block_size)
                    .context("mapped blob offset overflow")?;
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
                    .context("blob cache size overflow")?;
                Ok(BlobInfo {
                    index: info.blob_index,
                    id: BlobId::from(info.blob_id),
                    mapped_blkaddr: info.mapped_blkaddr,
                    mapped_offset,
                    blocks: info.blocks,
                    cache_size,
                    cache_path,
                    is_redirect: cache.is_redirect_blob(),
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
    /// [`Blobs::prepare_entries`] does.
    pub fn flat_layout(&self) -> Result<&[BlobInfo]> {
        if let Some(layout) = self.flat_layout.get() {
            return Ok(layout);
        }
        let mut blobs = self.prepare_entries()?;
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
    ) -> Result<(u16, Arc<dyn crate::storage::cache::BlobCache>)> {
        let blob_index = *self
            .index_by_blob_id
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("blob is not referenced by the bootstrap"))?;
        let cache = self
            .reader
            .blob_cache(blob_index)
            .with_context(|| format!("failed to open blob {blob_index}"))?;
        Ok((blob_index, cache))
    }

    /// Ensure `[offset, offset + len)` of the blob's dense uncompressed
    /// address space is decoded, CRC-validated, and written to its cache data
    /// file, fetching missing groups through the backend. Both `offset` and
    /// `len` must be 4 KiB block aligned; the fetch rounds outward to whole
    /// blob meta groups. Idempotent and safe to call concurrently.
    pub fn fetch(&self, id: &BlobId, offset: u64, len: u64) -> Result<()> {
        let block_size = EROFS_BLOCK_SIZE as u64;
        if offset % block_size != 0 || len % block_size != 0 {
            bail!("fetch range must be 4 KiB block aligned: offset={offset} len={len}");
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
    /// without triggering a backend fetch. The group_map remains authoritative.
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

    /// O(1) fast-path probe: true when every group of the blob is already
    /// decoded into its local cache (a single shared-flag load, no bitmap
    /// scan). On-demand services (uffd, fanotify, FUSE) can consult this per
    /// event — or once per blob, since the answer is sticky — to bypass range
    /// readiness checks and fetch plumbing entirely for fully warmed blobs.
    pub fn is_all_ready(&self, id: &BlobId) -> Result<bool> {
        let (_, cache) = self.blob_cache_for(id)?;
        Ok(cache.is_all_ready())
    }
}
