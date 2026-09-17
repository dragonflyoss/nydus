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
pub mod build;
pub mod entry;
pub mod extent;
pub mod flat;
mod layout;
pub mod reader;
pub mod writer;

pub use blob::{BlobId, BlobInfo, Blobs};
pub use entry::FileType;
pub use extent::{Extent, ResolveMode};
pub use flat::FlatImage;
pub use reader::ErofsReader;
pub use writer::{CreateFileOptions, IncrementalWriter, IncrementalWriterOptions};

use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use nydus_config::Config;
use nydus_error::{Context, Error, Result};

use entry::ImageFs;
use extent::{BlobRangeSpec, ExtentResolver};
use layout::{FlatLayout, Segment};
use nydus_backend::build_backend;
use nydus_config::PrefetchScope;
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
    reader: Arc<ErofsReader>,
    bootstrap: Arc<File>,
    zero_file: Arc<File>,
    address_layout: FlatLayout,
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
    /// provide the backend serving the blobs. A persistent cache directory is
    /// required unless every blob is a directly mappable local raw device.
    ///
    /// Unless `config.prefetch.scope` is `none`, a background prefetch worker is
    /// spawned before returning: for an optimized image it streams the
    /// "ondemand" blob first (priority), which holds the recorded working set
    /// in access order, then prefetches the remaining blobs.
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
        nydus_storage::cache::set_skip_verify_checksums(config.storage.skip_verify_checksums);
        nydus_storage::cache::set_fetch_size(config.storage.fetch_size);
        let backend = build_backend(&config.backend).context("failed to build blob backend")?;
        let cache_dir = config.storage.dir.clone();
        if let Some(cache_dir) = &cache_dir {
            std::fs::create_dir_all(cache_dir).with_context(|| {
                format!("failed to create cache directory: {}", cache_dir.display())
            })?;
        }

        let trace_recorder = Arc::new(TraceRecorder::default());
        let reader = ErofsReader::open_bootstrap(
            bootstrap,
            backend.clone(),
            cache_dir.as_deref(),
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
        if cache_dir.is_none() {
            for info in &raw_blob_infos {
                let mapped = backend
                    .raw_device_file(&info.blob_id)
                    .with_context(|| format!("failed to resolve blob {}", info.blob_index))?
                    .is_some_and(|file| file.data_offset == 0);
                if !mapped {
                    return Err(Error::InvalidConfig(format!(
                        "storage.dir is required: blob {} has no directly mappable local device",
                        BlobId::from(info.blob_id)
                    )));
                }
            }
        }
        let address_layout = FlatLayout::new(bootstrap_size, &raw_blob_infos)?;
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
                flat_layout_init: Mutex::new(()),
            },
            fs: ImageFs::new(reader.clone(), zero_file.clone()),
            reader,
            bootstrap: bootstrap_file,
            zero_file,
            address_layout,
            trace_recorder,
            prefetch_stop,
        })
    }

    /// Create an incremental writer that reuses this core's parent reader, backend, and cache.
    ///
    /// Each call returns an independent writer with its own staged overlay and
    /// output blob/bootstrap paths. The returned writer is a single-writer
    /// builder; serialize access externally if it is shared across threads.
    /// Reads through this `NydusCore` continue to expose the parent image and do
    /// not include staged writer changes. Open the committed child bootstrap to
    /// read the merged result.
    pub fn writer(&self, options: IncrementalWriterOptions) -> Result<IncrementalWriter> {
        IncrementalWriter::from_parent_reader(self.reader.clone(), options)
    }

    /// Return the bootstrap file backing this core.
    pub fn bootstrap(&self) -> &File {
        &self.bootstrap
    }

    /// Return the size of the flattened device view.
    pub fn flat_size(&self) -> u64 {
        self.address_layout.size()
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
    /// Only blobs intersecting the requested range are opened. Opening a
    /// blob may load its metadata, but does not fetch missing payload data.
    pub fn probe_flat_ranges(&self, offset: u64, len: u64) -> Result<Vec<Extent>> {
        self.resolve_flat_ranges(offset, len, ResolveMode::Probe)
    }

    /// Return a stable snapshot of this core's on-demand chunk group trace.
    pub fn trace_snapshot(&self) -> TraceDocument {
        self.trace_recorder.snapshot()
    }

    /// Serialize this core's on-demand chunk group trace as optimize-compatible JSON.
    pub fn trace_json(&self) -> String {
        self.trace_recorder.encode_json()
    }

    fn resolve_flat_ranges(&self, offset: u64, len: u64, mode: ResolveMode) -> Result<Vec<Extent>> {
        // Device geometry comes from the bootstrap. Resolving one range must
        // not prepare caches for unrelated devices, even on the first request.
        let segments = self.address_layout.segments(offset, len)?;
        let mut resolver = ExtentResolver::new(&self.blobs.reader, self.zero_file.as_raw_fd());
        if mode == ResolveMode::Fetch {
            let specs: Vec<BlobRangeSpec> = segments
                .clone()
                .filter_map(|segment| match segment {
                    Segment::Blob { range } => Some(range),
                    _ => None,
                })
                .collect();
            resolver.fetch_blobs(&specs)?;
        }
        for segment in segments {
            match segment {
                Segment::Bootstrap { offset, len } => {
                    resolver.push(Extent::new(self.bootstrap.as_raw_fd(), offset, len, offset))
                }
                Segment::Zero { offset, len } => {
                    resolver.push(Extent::new(self.zero_file.as_raw_fd(), 0, len, offset))
                }
                Segment::Blob { range } => resolver.push_blob(range, mode)?,
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
