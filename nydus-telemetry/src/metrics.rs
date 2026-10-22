//! The Prometheus metrics of a nydus image: [`Metrics`], grouped by the
//! module that records them, and the `collect_*_metrics` methods that move
//! them. Every opened image records into a [`Metrics`] of its own, held by
//! its blob backend; whoever serves `/metrics` encodes
//! `metrics.registry().gather()` with a [`prometheus::TextEncoder`].
//!
//! Every metric name is `nydus_<subsystem>_<operation>_<unit>`: the `nydus`
//! namespace, the module recording it as the subsystem, `backend` for the
//! blob backend reads, `storage` for the prefetch tasks, `cache` for the
//! chunk groups the local blob cache serves from the cache file and writes
//! into it, `fs` for the FUSE operations, then the operation in the
//! singular the way dragonfly-client-metric names them,
//! `nydus_backend_read_total`, `nydus_storage_prefetch_task_total`,
//! `nydus_cache_read_bytes_total`, `nydus_fs_op_total`. Counters end in
//! `_total`, byte counters in `_bytes_total`, duration histograms in
//! `_duration_milliseconds`, the gauge in its unit alone, `nydus_cache_bytes`;
//! a count with failures has a `_failure_total` twin counting them, and a
//! duration histogram observes the successes alone. Dimensions are labels,
//! each with a fixed vocabulary, the `Display` of the enum that names it:
//!
//! ```text
//! type      what triggered the backend read        ondemand | prefetch
//!           or what wrote the chunk group           ondemand | prefetch | ondemand_blob
//! source    where the backend read the bytes       local | origin | proxy | dragonfly | fallback
//! reason    why the cache write failed             decode | checksum | io | unknown_source
//! status    whether the image bytes are cached     cached | uncached
//! operation the FUSE operation                     lookup | read | getattr | ...
//! ```
//!
//! A label partitions one quantity, so that the sum over its values stays
//! meaningful, the way mysqld_exporter's buffer pool pages carry
//! `state="data|free|misc"` and nginx-module-vts's cache bytes carry their
//! cache `status`: `nydus_cache_bytes{status}` splits the image the cache
//! serves into the bytes it holds and the bytes it does not, and the image's
//! total is their sum. That gauge is the one metric not moved by a
//! `collect_*_metrics` call: the blob cache set registers a collector that
//! computes it when the registry is gathered, from the chunk group maps it
//! shares with every process using the cache directory, so it is never
//! stale across them.
//!
//! `source` is `local` for the local directory backend, `origin` for the
//! registry backend reading the origin registry itself, `proxy` for it
//! reading through an HTTP forward proxy, `dragonfly` for it reading the
//! Dragonfly seed peers and `fallback` for a read Dragonfly could not serve
//! that went back to the origin. `type` is `ondemand_blob` only on the cache
//! writes, for a chunk group filled into its source blob from the ondemand
//! blob. `reason` tells a corrupted chunk group (`checksum`, the
//! crc32c mismatched; `decode`, it did not decompress to its declared
//! size, or an ondemand source points past its source blob's chunk groups) from a
//! cache that cannot be written (`io`) and, on the ondemand blob fills, from a
//! an ondemand source naming a blob the image does not have (`unknown_source`).

use std::fmt;
use std::time::Duration;

use prometheus::{exponential_buckets, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry};

pub use nydus_config::ReadKind;

/// The metrics of one image, grouped by the module that records them and
/// every one registered in a [`Registry`] of its own.
///
/// Instances are independent: what one records never shows in another. The
/// backend of an image holds the instance and the caches, the prefetcher and
/// the filesystem above it record into the same one, every move a
/// `collect_*_metrics` call; readers take the values from [`Metrics::registry`].
///
/// ```text
/// Metrics
///   ├─ backend   BackendMetrics   nydus_backend_*   the blob backend's reads
///   ├─ storage   StorageMetrics   nydus_storage_*   the prefetch tasks
///   ├─ cache     CacheMetrics     nydus_cache_*     the local blob cache's reads and writes
///   └─ fs        FsMetrics        nydus_fs_*        the FUSE operations
/// ```
#[derive(Debug)]
pub struct Metrics {
    /// Used to register all metrics.
    registry: Registry,

    /// The metrics of the blob backend.
    pub backend: BackendMetrics,

    /// The metrics of the storage layer.
    pub storage: StorageMetrics,

    /// The metrics of the local blob cache.
    pub cache: CacheMetrics,

    /// The metrics of the FUSE filesystem.
    pub fs: FsMetrics,
}

/// Implements the default metrics.
impl Default for Metrics {
    /// Creates the metrics of an image.
    fn default() -> Self {
        Self::new()
    }
}

/// Implements the metrics.
impl Metrics {
    /// Creates the metrics of an image, every metric registered in a
    /// registry of its own.
    pub fn new() -> Self {
        let metrics = Self {
            registry: Registry::new(),
            backend: BackendMetrics::new(),
            storage: StorageMetrics::new(),
            cache: CacheMetrics::new(),
            fs: FsMetrics::new(),
        };
        metrics.register_custom_metrics();
        metrics
    }

    /// Returns the registry every metric is registered in, the one a
    /// `/metrics` handler gathers.
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Registers all metrics.
    fn register_custom_metrics(&self) {
        self.registry
            .register(Box::new(self.backend.read_count.clone()))
            .expect("metric can be registered");

        self.registry
            .register(Box::new(self.backend.read_failure_count.clone()))
            .expect("metric can be registered");

        self.registry
            .register(Box::new(self.backend.read_bytes.clone()))
            .expect("metric can be registered");

        self.registry
            .register(Box::new(self.backend.read_duration.clone()))
            .expect("metric can be registered");

        self.registry
            .register(Box::new(self.storage.prefetch_task_count.clone()))
            .expect("metric can be registered");

        self.registry
            .register(Box::new(self.storage.prefetch_task_failure_count.clone()))
            .expect("metric can be registered");

        self.registry
            .register(Box::new(self.cache.read_count.clone()))
            .expect("metric can be registered");

        self.registry
            .register(Box::new(self.cache.read_bytes.clone()))
            .expect("metric can be registered");

        self.registry
            .register(Box::new(self.cache.write_count.clone()))
            .expect("metric can be registered");

        self.registry
            .register(Box::new(self.cache.write_failure_count.clone()))
            .expect("metric can be registered");

        self.registry
            .register(Box::new(self.cache.write_bytes.clone()))
            .expect("metric can be registered");

        self.registry
            .register(Box::new(self.fs.op_count.clone()))
            .expect("metric can be registered");

        self.registry
            .register(Box::new(self.fs.op_failure_count.clone()))
            .expect("metric can be registered");

        self.registry
            .register(Box::new(self.fs.op_duration.clone()))
            .expect("metric can be registered");
    }
}

/// The metrics of the blob backend, subsystem `backend`: every read it
/// serves, by read kind and source.
#[derive(Debug)]
pub struct BackendMetrics {
    /// Used to count the number of backend reads.
    read_count: IntCounterVec,

    /// Used to count the failed number of backend reads.
    read_failure_count: IntCounterVec,

    /// Used to count the backend read bytes.
    read_bytes: IntCounterVec,

    /// Used to record the backend read duration.
    read_duration: HistogramVec,
}

/// Implements the backend metrics.
impl BackendMetrics {
    /// The subsystem of the metric names.
    const SUBSYSTEM: &'static str = "backend";

    /// Creates the metrics.
    fn new() -> Self {
        Self {
            read_count: IntCounterVec::new(
                Opts::new("read_total", "Counter of the number of the backend read.")
                    .namespace(nydus_config::NAME)
                    .subsystem(Self::SUBSYSTEM),
                &["type", "source"],
            )
            .expect("metric can be created"),
            read_failure_count: IntCounterVec::new(
                Opts::new(
                    "read_failure_total",
                    "Counter of the number of failed of the backend read.",
                )
                .namespace(nydus_config::NAME)
                .subsystem(Self::SUBSYSTEM),
                &["type", "source"],
            )
            .expect("metric can be created"),
            read_bytes: IntCounterVec::new(
                Opts::new(
                    "read_bytes_total",
                    "Counter of the bytes of the backend read.",
                )
                .namespace(nydus_config::NAME)
                .subsystem(Self::SUBSYSTEM),
                &["type", "source"],
            )
            .expect("metric can be created"),
            read_duration: HistogramVec::new(
                HistogramOpts::new(
                    "read_duration_milliseconds",
                    "Histogram of the backend read duration.",
                )
                .namespace(nydus_config::NAME)
                .subsystem(Self::SUBSYSTEM)
                .buckets(exponential_buckets(1.0, 2.0, 24).unwrap()),
                &["type", "source"],
            )
            .expect("metric can be created"),
        }
    }

    /// Collects the backend read finished metrics, `length` the compressed
    /// bytes read.
    pub fn collect_read_finished_metrics(
        &self,
        kind: ReadKind,
        source: Source,
        length: u64,
        cost: Duration,
    ) {
        self.read_count
            .with_label_values(&[&kind.to_string(), &source.to_string()])
            .inc();

        self.read_bytes
            .with_label_values(&[&kind.to_string(), &source.to_string()])
            .inc_by(length);

        self.read_duration
            .with_label_values(&[&kind.to_string(), &source.to_string()])
            .observe(cost.as_millis() as f64);
    }

    /// Collects the backend read failure metrics.
    pub fn collect_read_failure_metrics(&self, kind: ReadKind, source: Source) {
        self.read_count
            .with_label_values(&[&kind.to_string(), &source.to_string()])
            .inc();

        self.read_failure_count
            .with_label_values(&[&kind.to_string(), &source.to_string()])
            .inc();
    }
}

/// The metrics of the storage layer, subsystem `storage`: the blob prefetch
/// tasks and how many of them failed.
#[derive(Debug)]
pub struct StorageMetrics {
    /// Used to count the number of prefetch tasks.
    prefetch_task_count: IntCounterVec,

    /// Used to count the failed number of prefetch tasks.
    prefetch_task_failure_count: IntCounterVec,
}

/// Implements the storage metrics.
impl StorageMetrics {
    /// The subsystem of the metric names.
    const SUBSYSTEM: &'static str = "storage";

    /// Creates the metrics.
    fn new() -> Self {
        Self {
            prefetch_task_count: IntCounterVec::new(
                Opts::new(
                    "prefetch_task_total",
                    "Counter of the number of the prefetch task.",
                )
                .namespace(nydus_config::NAME)
                .subsystem(Self::SUBSYSTEM),
                &[],
            )
            .expect("metric can be created"),
            prefetch_task_failure_count: IntCounterVec::new(
                Opts::new(
                    "prefetch_task_failure_total",
                    "Counter of the number of failed of the prefetch task.",
                )
                .namespace(nydus_config::NAME)
                .subsystem(Self::SUBSYSTEM),
                &[],
            )
            .expect("metric can be created"),
        }
    }

    /// Collects the prefetch task finished metrics.
    pub fn collect_prefetch_task_finished_metrics(&self) {
        self.prefetch_task_count.with_label_values(&[]).inc();
    }

    /// Collects the prefetch task failure metrics.
    pub fn collect_prefetch_task_failure_metrics(&self) {
        self.prefetch_task_count.with_label_values(&[]).inc();

        self.prefetch_task_failure_count
            .with_label_values(&[])
            .inc();
    }
}

/// The metrics of the local blob cache, subsystem `cache`: the chunk groups
/// it serves and fills, counted and in uncompressed bytes.
#[derive(Debug)]
pub struct CacheMetrics {
    /// Used to count the number of cache reads.
    read_count: IntCounterVec,

    /// Used to count the cache read bytes.
    read_bytes: IntCounterVec,

    /// Used to count the number of cache writes.
    write_count: IntCounterVec,

    /// Used to count the failed number of cache writes.
    write_failure_count: IntCounterVec,

    /// Used to count the cache write bytes.
    write_bytes: IntCounterVec,
}

/// Implements the cache metrics.
impl CacheMetrics {
    /// The subsystem of the metric names, shared with the `nydus_cache_bytes`
    /// gauge the blob cache set collects.
    pub const SUBSYSTEM: &'static str = "cache";

    /// Creates the metrics.
    fn new() -> Self {
        Self {
            read_count: IntCounterVec::new(
                Opts::new("read_total", "Counter of the number of the cache read.")
                    .namespace(nydus_config::NAME)
                    .subsystem(Self::SUBSYSTEM),
                &[],
            )
            .expect("metric can be created"),
            read_bytes: IntCounterVec::new(
                Opts::new(
                    "read_bytes_total",
                    "Counter of the bytes of the cache read.",
                )
                .namespace(nydus_config::NAME)
                .subsystem(Self::SUBSYSTEM),
                &[],
            )
            .expect("metric can be created"),
            write_count: IntCounterVec::new(
                Opts::new("write_total", "Counter of the number of the cache write.")
                    .namespace(nydus_config::NAME)
                    .subsystem(Self::SUBSYSTEM),
                &["type"],
            )
            .expect("metric can be created"),
            write_failure_count: IntCounterVec::new(
                Opts::new(
                    "write_failure_total",
                    "Counter of the number of failed of the cache write.",
                )
                .namespace(nydus_config::NAME)
                .subsystem(Self::SUBSYSTEM),
                &["type", "reason"],
            )
            .expect("metric can be created"),
            write_bytes: IntCounterVec::new(
                Opts::new(
                    "write_bytes_total",
                    "Counter of the bytes of the cache write.",
                )
                .namespace(nydus_config::NAME)
                .subsystem(Self::SUBSYSTEM),
                &["type"],
            )
            .expect("metric can be created"),
        }
    }

    /// Collects the cache read metrics of one chunk group an on-demand read
    /// found in the cache, `length` its uncompressed bytes. Only on-demand
    /// reads read the cache; a chunk group it did not hold is a write, see
    /// [`collect_write_finished_metrics`], and a prefetch skipping a cached
    /// chunk group is no read at all.
    ///
    /// [`collect_write_finished_metrics`]: Self::collect_write_finished_metrics
    pub fn collect_read_metrics(&self, length: u64) {
        self.read_count.with_label_values(&[]).inc();

        self.read_bytes.with_label_values(&[]).inc_by(length);
    }

    /// Collects the cache write finished metrics of one chunk group,
    /// `length` its uncompressed bytes.
    pub fn collect_write_finished_metrics(&self, kind: WriteKind, length: u64) {
        self.write_count
            .with_label_values(&[&kind.to_string()])
            .inc();

        self.write_bytes
            .with_label_values(&[&kind.to_string()])
            .inc_by(length);
    }

    /// Collects the cache write failure metrics of one chunk group, `reason`
    /// why it did not reach the cache.
    pub fn collect_write_failure_metrics(&self, kind: WriteKind, reason: WriteFailureReason) {
        self.write_count
            .with_label_values(&[&kind.to_string()])
            .inc();

        self.write_failure_count
            .with_label_values(&[&kind.to_string(), &reason.to_string()])
            .inc();
    }
}

/// The metrics of the FUSE filesystem, subsystem `fs`: every operation it
/// answers, by op and result, and the read duration.
#[derive(Debug)]
pub struct FsMetrics {
    /// Used to count the number of filesystem operations.
    op_count: IntCounterVec,

    /// Used to count the failed number of filesystem operations.
    op_failure_count: IntCounterVec,

    /// Used to record the filesystem operation duration.
    op_duration: HistogramVec,
}

/// Implements the filesystem metrics.
impl FsMetrics {
    /// The subsystem of the metric names.
    const SUBSYSTEM: &'static str = "fs";

    /// Creates the metrics.
    fn new() -> Self {
        Self {
            op_count: IntCounterVec::new(
                Opts::new(
                    "op_total",
                    "Counter of the number of the filesystem operation.",
                )
                .namespace(nydus_config::NAME)
                .subsystem(Self::SUBSYSTEM),
                &["operation"],
            )
            .expect("metric can be created"),
            op_failure_count: IntCounterVec::new(
                Opts::new(
                    "op_failure_total",
                    "Counter of the number of failed of the filesystem operation.",
                )
                .namespace(nydus_config::NAME)
                .subsystem(Self::SUBSYSTEM),
                &["operation"],
            )
            .expect("metric can be created"),
            op_duration: HistogramVec::new(
                HistogramOpts::new(
                    "op_duration_milliseconds",
                    "Histogram of the filesystem operation duration.",
                )
                .namespace(nydus_config::NAME)
                .subsystem(Self::SUBSYSTEM)
                .buckets(exponential_buckets(1.0, 2.0, 24).unwrap()),
                &["operation"],
            )
            .expect("metric can be created"),
        }
    }

    /// Collects the filesystem operation finished metrics.
    pub fn collect_op_finished_metrics(&self, op: FsOp, cost: Duration) {
        self.op_count.with_label_values(&[&op.to_string()]).inc();

        self.op_duration
            .with_label_values(&[&op.to_string()])
            .observe(cost.as_millis() as f64);
    }

    /// Collects the filesystem operation failure metrics.
    pub fn collect_op_failure_metrics(&self, op: FsOp) {
        self.op_count.with_label_values(&[&op.to_string()]).inc();

        self.op_failure_count
            .with_label_values(&[&op.to_string()])
            .inc();
    }
}

/// Represents where a backend read fetched its bytes, the `source` label of
/// the backend metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The local directory backend's blob files.
    Local,

    /// The origin registry, reached directly.
    Origin,

    /// An HTTP forward proxy in front of the origin.
    Proxy,

    /// The Dragonfly seed peers.
    Dragonfly,

    /// The origin registry, reached after Dragonfly could not serve the read.
    Fallback,
}

/// Implements the Display trait.
impl fmt::Display for Source {
    /// fmt formats the Source.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Source::Local => write!(f, "local"),
            Source::Origin => write!(f, "origin"),
            Source::Proxy => write!(f, "proxy"),
            Source::Dragonfly => write!(f, "dragonfly"),
            Source::Fallback => write!(f, "fallback"),
        }
    }
}

/// Represents what wrote a chunk group into the local cache, the `type`
/// label of the cache writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteKind {
    /// An on-demand read that missed the cache.
    Ondemand,

    /// The prefetch of a regular blob.
    Prefetch,

    /// The fill of a source blob's chunk group from the ondemand
    /// blob.
    OndemandBlob,
}

/// Implements the conversion of the read kind that missed the cache into
/// the kind of the write filling it.
impl From<ReadKind> for WriteKind {
    /// Converts the read kind into the write kind.
    fn from(kind: ReadKind) -> Self {
        match kind {
            ReadKind::Ondemand => WriteKind::Ondemand,
            ReadKind::Prefetch => WriteKind::Prefetch,
        }
    }
}

/// Implements the Display trait.
impl fmt::Display for WriteKind {
    /// fmt formats the WriteKind.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WriteKind::Ondemand => write!(f, "ondemand"),
            WriteKind::Prefetch => write!(f, "prefetch"),
            WriteKind::OndemandBlob => write!(f, "ondemand_blob"),
        }
    }
}

/// Represents why a chunk group did not reach the local cache, the `reason`
/// label of the cache write failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteFailureReason {
    /// The chunk group did not decompress to its declared size, or the
    /// ondemand source points past its source blob's chunk groups.
    Decode,

    /// The decoded chunk group's crc32c did not match the blob meta.
    Checksum,

    /// The cache file could not be written.
    Io,

    /// The ondemand source names a source blob the image does not have.
    UnknownSource,
}

/// Implements the Display trait.
impl fmt::Display for WriteFailureReason {
    /// fmt formats the WriteFailureReason.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WriteFailureReason::Decode => write!(f, "decode"),
            WriteFailureReason::Checksum => write!(f, "checksum"),
            WriteFailureReason::Io => write!(f, "io"),
            WriteFailureReason::UnknownSource => write!(f, "unknown_source"),
        }
    }
}

/// Represents a FUSE filesystem operation, mirroring nydus `StatsFop` for
/// label parity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsOp {
    Getattr,
    Readlink,
    Open,
    Release,
    Read,
    Statfs,
    Getxattr,
    Listxattr,
    Opendir,
    Lookup,
    Readdir,
    Readdirplus,
    Access,
    Forget,
}

/// Implements the Display trait.
impl fmt::Display for FsOp {
    /// fmt formats the FsOp.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FsOp::Getattr => write!(f, "getattr"),
            FsOp::Readlink => write!(f, "readlink"),
            FsOp::Open => write!(f, "open"),
            FsOp::Release => write!(f, "release"),
            FsOp::Read => write!(f, "read"),
            FsOp::Statfs => write!(f, "statfs"),
            FsOp::Getxattr => write!(f, "getxattr"),
            FsOp::Listxattr => write!(f, "listxattr"),
            FsOp::Opendir => write!(f, "opendir"),
            FsOp::Lookup => write!(f, "lookup"),
            FsOp::Readdir => write!(f, "readdir"),
            FsOp::Readdirplus => write!(f, "readdirplus"),
            FsOp::Access => write!(f, "access"),
            FsOp::Forget => write!(f, "forget"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instances_record_apart() {
        let metrics = Metrics::new();
        metrics.storage.collect_prefetch_task_finished_metrics();

        assert_eq!(
            metrics
                .storage
                .prefetch_task_count
                .with_label_values(&[])
                .get(),
            1
        );
        assert_eq!(
            Metrics::default()
                .storage
                .prefetch_task_count
                .with_label_values(&[])
                .get(),
            0
        );
    }

    #[test]
    fn backend_reads_are_counted_by_type_and_source_with_their_failures() {
        let test_cases = vec![
            (ReadKind::Ondemand, Source::Local),
            (ReadKind::Prefetch, Source::Local),
            (ReadKind::Ondemand, Source::Origin),
            (ReadKind::Ondemand, Source::Proxy),
            (ReadKind::Prefetch, Source::Proxy),
            (ReadKind::Ondemand, Source::Dragonfly),
            (ReadKind::Ondemand, Source::Fallback),
        ];

        for (kind, source) in test_cases {
            let metrics = Metrics::new().backend;
            let kind_label = kind.to_string();
            let source_label = source.to_string();
            metrics.collect_read_finished_metrics(kind, source, 1024, Duration::from_millis(3));
            metrics.collect_read_finished_metrics(kind, source, 1024, Duration::from_millis(5));
            metrics.collect_read_failure_metrics(kind, source);

            assert_eq!(
                metrics
                    .read_count
                    .with_label_values(&[&kind_label, &source_label])
                    .get(),
                3,
                "kind: {kind:?}, source: {source:?}"
            );
            assert_eq!(
                metrics
                    .read_failure_count
                    .with_label_values(&[&kind_label, &source_label])
                    .get(),
                1
            );
            assert_eq!(
                metrics
                    .read_bytes
                    .with_label_values(&[&kind_label, &source_label])
                    .get(),
                2048
            );
            assert_eq!(
                metrics
                    .read_duration
                    .with_label_values(&[&kind_label, &source_label])
                    .get_sample_count(),
                2
            );
        }
    }

    #[test]
    fn labels_are_the_display_of_their_enums() {
        let test_cases: Vec<(&str, String)> = vec![
            ("ondemand", ReadKind::Ondemand.to_string()),
            ("prefetch", ReadKind::Prefetch.to_string()),
            ("local", Source::Local.to_string()),
            ("origin", Source::Origin.to_string()),
            ("proxy", Source::Proxy.to_string()),
            ("dragonfly", Source::Dragonfly.to_string()),
            ("fallback", Source::Fallback.to_string()),
            ("decode", WriteFailureReason::Decode.to_string()),
            ("checksum", WriteFailureReason::Checksum.to_string()),
            ("io", WriteFailureReason::Io.to_string()),
            (
                "unknown_source",
                WriteFailureReason::UnknownSource.to_string(),
            ),
            ("ondemand", WriteKind::Ondemand.to_string()),
            ("prefetch", WriteKind::Prefetch.to_string()),
            ("ondemand_blob", WriteKind::OndemandBlob.to_string()),
            ("ondemand", WriteKind::from(ReadKind::Ondemand).to_string()),
            ("prefetch", WriteKind::from(ReadKind::Prefetch).to_string()),
            ("readdirplus", FsOp::Readdirplus.to_string()),
        ];

        for (expected, label) in test_cases {
            assert_eq!(label, expected);
        }
    }

    #[test]
    fn prefetch_tasks_are_counted_with_their_failures() {
        let metrics = Metrics::new().storage;
        metrics.collect_prefetch_task_finished_metrics();
        metrics.collect_prefetch_task_failure_metrics();
        metrics.collect_prefetch_task_failure_metrics();

        assert_eq!(metrics.prefetch_task_count.with_label_values(&[]).get(), 3);
        assert_eq!(
            metrics
                .prefetch_task_failure_count
                .with_label_values(&[])
                .get(),
            2
        );
    }

    #[test]
    fn cache_reads_are_counted_with_their_bytes() {
        let metrics = Metrics::new().cache;
        metrics.collect_read_metrics(4096);
        metrics.collect_read_metrics(1024);

        assert_eq!(metrics.read_count.with_label_values(&[]).get(), 2);
        assert_eq!(metrics.read_bytes.with_label_values(&[]).get(), 5120);
    }

    #[test]
    fn cache_writes_are_counted_by_type_with_their_failures_by_reason() {
        let test_cases = vec![
            WriteKind::Ondemand,
            WriteKind::Prefetch,
            WriteKind::OndemandBlob,
        ];

        for kind in test_cases {
            let metrics = Metrics::new().cache;
            let kind_label = kind.to_string();
            metrics.collect_write_finished_metrics(kind, 4096);
            metrics.collect_write_failure_metrics(kind, WriteFailureReason::Checksum);
            metrics.collect_write_failure_metrics(kind, WriteFailureReason::Io);

            assert_eq!(
                metrics.write_count.with_label_values(&[&kind_label]).get(),
                3,
                "kind: {kind:?}"
            );
            assert_eq!(
                metrics
                    .write_failure_count
                    .with_label_values(&[&kind_label, "checksum"])
                    .get(),
                1
            );
            assert_eq!(
                metrics
                    .write_failure_count
                    .with_label_values(&[&kind_label, "io"])
                    .get(),
                1
            );
            assert_eq!(
                metrics.write_bytes.with_label_values(&[&kind_label]).get(),
                4096
            );
        }
    }

    #[test]
    fn fs_ops_are_counted_and_timed_by_op_with_their_failures() {
        let metrics = Metrics::new().fs;
        metrics.collect_op_finished_metrics(FsOp::Lookup, Duration::from_millis(1));
        metrics.collect_op_finished_metrics(FsOp::Read, Duration::from_millis(2));
        metrics.collect_op_failure_metrics(FsOp::Read);

        assert_eq!(metrics.op_count.with_label_values(&["lookup"]).get(), 1);
        assert_eq!(metrics.op_count.with_label_values(&["read"]).get(), 2);
        assert_eq!(
            metrics.op_failure_count.with_label_values(&["read"]).get(),
            1
        );
        assert_eq!(
            metrics
                .op_duration
                .with_label_values(&["lookup"])
                .get_sample_count(),
            1
        );
        assert_eq!(
            metrics
                .op_duration
                .with_label_values(&["read"])
                .get_sample_count(),
            1
        );
    }

    #[test]
    fn registry_gathers_every_metric_under_the_nydus_namespace() {
        let metrics = Metrics::new();
        metrics.backend.collect_read_finished_metrics(
            ReadKind::Ondemand,
            Source::Origin,
            10,
            Duration::from_millis(1),
        );
        metrics.storage.collect_prefetch_task_finished_metrics();
        metrics.cache.collect_read_metrics(10);
        metrics
            .cache
            .collect_write_finished_metrics(WriteKind::Ondemand, 10);
        metrics
            .fs
            .collect_op_finished_metrics(FsOp::Read, Duration::from_millis(1));

        let mut buffer = Vec::new();
        prometheus::Encoder::encode(
            &prometheus::TextEncoder::new(),
            &metrics.registry().gather(),
            &mut buffer,
        )
        .unwrap();
        let text = String::from_utf8(buffer).unwrap();

        let test_cases = vec![
            r#"nydus_backend_read_total{source="origin",type="ondemand"} 1"#,
            r#"nydus_backend_read_bytes_total{source="origin",type="ondemand"} 10"#,
            r#"nydus_backend_read_duration_milliseconds_count{source="origin",type="ondemand"} 1"#,
            r#"nydus_storage_prefetch_task_total 1"#,
            r#"nydus_cache_read_total 1"#,
            r#"nydus_cache_read_bytes_total 10"#,
            r#"nydus_cache_write_total{type="ondemand"} 1"#,
            r#"nydus_cache_write_bytes_total{type="ondemand"} 10"#,
            r#"nydus_fs_op_total{operation="read"} 1"#,
            r#"nydus_fs_op_duration_milliseconds_count{operation="read"} 1"#,
        ];

        for expected in test_cases {
            assert!(text.contains(expected), "missing {expected}\n{text}");
        }
    }
}
