//! Expose a nydus image as a mountable EROFS filesystem.
//!
//! Every view this crate assembles from the data plane
//! (`nydus-storage`/`nydus-backend`) exists to let a kernel or FUSE mount
//! the image: the file-tree reader ([`reader`] + [`entry`]) behind FUSE and
//! image inspection, and the flattened device views ([`NydusCore`] /
//! [`Blobs`]) that NBD / ublk / fanotify / userfaultfd hand to the kernel
//! EROFS driver.
//!
//! Naming gradient: `Erofs*` types (in `nydus-format`) are zero-copy on-disk
//! views, `Raw*` types here are minimally-parsed lifetime-free forms, and
//! bare names ([`DirEntry`](entry::DirEntry), [`BlobInfo`]) are the owned,
//! user-facing API.
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
//! [`blobs.fetch`]: crate::blob::Blobs::fetch

#![warn(unreachable_pub)]

pub mod blob;
pub mod entry;
pub mod extent;
pub mod reader;

pub use blob::{BlobId, BlobInfo, Blobs};
pub use entry::FileType;
pub use extent::{Extent, ResolveMode};
pub use reader::ErofsReader;

use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use nydus_config::Config;
use nydus_error::{Context, Error, Result};

use entry::ImageFs;
use extent::{clamped_range_end, mapped_range_offset, BlobRangeSpec, ExtentResolver};
use nydus_backend::build_backend;
use nydus_config::PrefetchScope;
use nydus_format::erofs::EROFS_BLOCK_SIZE;
use nydus_storage::access_trace::{TraceDocument, TraceRecorder};
use nydus_storage::prefetch::BlobPrefetcher;

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
    /// Stop flag of the detached background prefetch worker, raised on drop
    /// so the worker exits its retry/reschedule loop instead of holding the
    /// cache and backend alive forever after the core is gone.
    prefetch_stop: Option<Arc<AtomicBool>>,
}

impl NydusCore {
    /// Parse the bootstrap and config and build the blob table,
    /// deferring all per-blob work: no blob meta is downloaded and no cache
    /// file is created until [`blobs`], [`fetch`], or the prefetch worker
    /// first touches a blob.
    ///
    /// `config` uses the same structure as `nydus fuse --config` and must
    /// provide both the backend serving the blobs and a persistent local cache
    /// directory.
    ///
    /// Unless `config.prefetch.scope` is `none`, a background prefetch worker is
    /// spawned before returning: for an optimized image it streams the
    /// "ondemand" redirect blob first (priority) to warm the source blobs'
    /// caches in recorded access order, then prefetches the remaining blobs.
    /// Dropping the core raises the worker's stop flag so it winds down
    /// instead of retrying throttled prefetches forever.
    /// The worker shares the reader's blob cache set, so callers that want
    /// network access (e.g. the virtio-pmem backend) must construct the core
    /// while the desired network namespace is active so the spawned thread
    /// inherits it.
    ///
    /// [`blobs`]: Self::blobs
    /// [`fetch`]: Blobs::fetch
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
        let prefetch_concurrent_blob_count = config.prefetch.concurrent_blob_count;
        let prefetch_scope = config.prefetch.scope;
        let prefetch_timeout = config.prefetch.timeout;
        let prefetch_retry_delay_min = config.prefetch.retry_delay_min;
        let prefetch_retry_delay_max = config.prefetch.retry_delay_max;
        let backend = build_backend(&config.backend).context("failed to build blob backend")?;
        // The multi-device model hands each blob's cache file to the kernel
        // (as an EROFS device or fill target), so diskless mode cannot apply.
        let Some(cache_dir) = config.storage.dir.clone() else {
            return Err(Error::InvalidConfig(
                "storage.dir is required: the blob cache files back the kernel-served devices"
                    .to_string(),
            ));
        };
        std::fs::create_dir_all(&cache_dir).with_context(|| {
            format!("failed to create cache directory: {}", cache_dir.display())
        })?;

        let trace_recorder = Arc::new(TraceRecorder::default());
        let reader = ErofsReader::open_bootstrap(
            bootstrap,
            backend,
            Some(&cache_dir),
            Some(trace_recorder.clone()),
        )
        .context("failed to open nydus bootstrap")?;
        let raw_blob_infos = reader
            .blob_infos()
            .context("failed to read blob table")?
            .to_vec();
        if raw_blob_infos.is_empty() {
            return Err(Error::InvalidImage(
                "bootstrap contains no blobs".to_string(),
            ));
        }
        let flat_size = raw_blob_infos
            .iter()
            .try_fold(bootstrap_size, |size, info| {
                let offset = info
                    .mapped_blkaddr
                    .checked_mul(EROFS_BLOCK_SIZE as u64)
                    .ok_or_else(|| Error::Overflow("mapped blob offset overflow".to_string()))?;
                let len = info
                    .blocks
                    .checked_mul(EROFS_BLOCK_SIZE as u64)
                    .ok_or_else(|| Error::Overflow("blob size overflow".to_string()))?;
                Ok::<u64, Error>(
                    size.max(
                        offset.checked_add(len).ok_or_else(|| {
                            Error::Overflow("flat blob range overflow".to_string())
                        })?,
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
        // teardown. The core retains only the worker's stop flag, raised on
        // drop so the worker winds down instead of rescheduling throttled
        // prefetches forever.
        let mut prefetch_stop = None;
        if prefetch_scope != PrefetchScope::None {
            let prefetcher = BlobPrefetcher::new(
                reader.blob_caches(),
                reader.prefetch_plan(),
                prefetch_concurrent_blob_count,
                prefetch_scope,
                prefetch_timeout,
                prefetch_retry_delay_min,
                prefetch_retry_delay_max,
            );
            let stop_flag = prefetcher.stop_flag();
            match prefetcher.spawn() {
                Ok(_handle) => {
                    prefetch_stop = Some(stop_flag);
                    tracing::info!(
                        "nydus core: background prefetch started (scope={prefetch_scope:?})"
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
            prefetch_stop,
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
    pub fn fetch_flat_ranges(&self, offset: u64, len: u64) -> Result<Vec<Extent>> {
        self.resolve_flat_ranges(offset, len, ResolveMode::Fetch)
    }

    /// Probe `[offset, offset + len)` in the flattened device view without
    /// downloading missing blob data. Bootstrap and gaps are returned when
    /// ready; cold blob cache ranges are omitted, so the result may be
    /// discontinuous.
    pub fn probe_flat_ranges(&self, offset: u64, len: u64) -> Result<Vec<Extent>> {
        self.resolve_flat_ranges(offset, len, ResolveMode::Probe)
    }

    /// Return a stable snapshot of this core's on-demand block group trace.
    pub fn trace_snapshot(&self) -> TraceDocument {
        self.trace_recorder.snapshot()
    }

    /// Serialize this core's on-demand block group trace as optimize-compatible JSON.
    pub fn trace_json(&self) -> String {
        self.trace_recorder.encode_json()
    }

    fn resolve_flat_ranges(&self, offset: u64, len: u64, mode: ResolveMode) -> Result<Vec<Extent>> {
        let Some(end) = clamped_range_end(offset, len, self.flat_size)? else {
            return Ok(Vec::new());
        };

        let mut resolver = ExtentResolver::new(&self.blobs.reader, self.zero_file.as_raw_fd());
        let mut pos = offset;
        let bootstrap_end = end.min(self.bootstrap_size);
        if pos < bootstrap_end {
            resolver.push(Extent::new(
                self.bootstrap.as_raw_fd(),
                pos,
                bootstrap_end - pos,
                pos,
            ));
            pos = bootstrap_end;
        }
        if pos >= end {
            return Ok(resolver.finish());
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
                    .ok_or_else(|| Error::Overflow("blob device range overflow".to_string()))?;
                let seg_end = end.min(blob_end);
                let blob_offset = pos - blob.mapped_offset;
                resolver.push_blob(
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
                resolver.push(Extent::new(
                    self.zero_file.as_raw_fd(),
                    0,
                    hole_end - pos,
                    pos,
                ));
                pos = hole_end;
            }
        }

        Ok(resolver.finish())
    }
}

impl Drop for NydusCore {
    /// Raise the background prefetch worker's stop flag so it stops starting
    /// new work and exits its reschedule loop, instead of retrying throttled
    /// prefetches forever after the core is gone.
    fn drop(&mut self) {
        if let Some(stop) = &self.prefetch_stop {
            stop.store(true, Ordering::Relaxed);
        }
    }
}
