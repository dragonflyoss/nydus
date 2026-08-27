//! Self-contained Prometheus metrics for nydus.
//!
//! This module owns a private [`prometheus::Registry`] and every metric the
//! daemon exports. Other modules never touch Prometheus types directly; they
//! only call the small set of `record_*` / `inc_*` helpers below and, for the
//! HTTP `/metrics` endpoint, [`encode_text`]. Keeping all metric definitions
//! here makes the exported surface easy to audit and keeps callers trivial.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use prometheus::{
    Encoder, Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};
use serde::Serialize;

/// Byte length of the SHA-256 digests used as blob cache keys. Defined
/// locally so this crate stays a dependency leaf.
const SHA256_DIGEST_SIZE: usize = 32;

/// Reads slower than this are counted as "high latency" for their source.
const HIGH_LATENCY_THRESHOLD: Duration = Duration::from_millis(250);

/// Exponential latency buckets covering 1ms up to ~8.19s.
fn latency_buckets() -> Vec<f64> {
    prometheus::exponential_buckets(0.001, 2.0, 14).expect("valid latency buckets")
}

/// Which side of the backend served a read: the origin registry directly, or a
/// proxy (HTTP mirror or Dragonfly SDK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendTarget {
    Origin,
    Proxy,
}

/// What kind of backend read this is — a user-triggered on-demand read or a
/// background prefetch. The storage layer keys retry, throttling and
/// proxy-priority policies off it (re-exported there as its policy type), and
/// metrics attribute reads to the on-demand or prefetch counter families by
/// it. Defined here so this crate stays a dependency leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReadKind {
    /// User-triggered read that blocks a FUSE request.
    #[default]
    OnDemand,
    /// Background prefetch read after mount.
    Prefetch,
}

impl ReadKind {
    fn as_str(self) -> &'static str {
        match self {
            ReadKind::OnDemand => "ondemand",
            ReadKind::Prefetch => "prefetch",
        }
    }

    const ALL: [ReadKind; 2] = [ReadKind::OnDemand, ReadKind::Prefetch];
}

/// Classification of a failed Dragonfly SDK read, labelling the
/// `backend_dragonfly_read_errors` counter. Mirrors the failure classes the
/// registry backend's load-shedding policy distinguishes. Defined here so
/// this crate stays a dependency leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DragonflyErrorClass {
    /// The Dragonfly proxy answered HTTP 429.
    RateLimited,
    /// The Dragonfly proxy answered HTTP 403.
    Forbidden,
    /// The request timed out.
    Timeout,
    /// The local dfdaemon could not be reached.
    Connect,
    /// The proxy or the backend behind it answered HTTP 5xx.
    ServerError,
    /// The response body failed mid-stream after a successful start.
    Stream,
    /// Any other SDK transport error.
    Other,
}

impl DragonflyErrorClass {
    fn as_str(self) -> &'static str {
        match self {
            DragonflyErrorClass::RateLimited => "rate_limited",
            DragonflyErrorClass::Forbidden => "forbidden",
            DragonflyErrorClass::Timeout => "timeout",
            DragonflyErrorClass::Connect => "connect",
            DragonflyErrorClass::ServerError => "server_error",
            DragonflyErrorClass::Stream => "stream",
            DragonflyErrorClass::Other => "other",
        }
    }

    /// All classes, used to pre-create label series so every class appears in
    /// the exposition output even before it is first hit.
    const ALL: [DragonflyErrorClass; 7] = [
        DragonflyErrorClass::RateLimited,
        DragonflyErrorClass::Forbidden,
        DragonflyErrorClass::Timeout,
        DragonflyErrorClass::Connect,
        DragonflyErrorClass::ServerError,
        DragonflyErrorClass::Stream,
        DragonflyErrorClass::Other,
    ];
}

/// A FUSE filesystem operation, mirroring nydus `StatsFop` for label parity.
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

impl FsOp {
    fn as_str(self) -> &'static str {
        match self {
            FsOp::Getattr => "getattr",
            FsOp::Readlink => "readlink",
            FsOp::Open => "open",
            FsOp::Release => "release",
            FsOp::Read => "read",
            FsOp::Statfs => "statfs",
            FsOp::Getxattr => "getxattr",
            FsOp::Listxattr => "listxattr",
            FsOp::Opendir => "opendir",
            FsOp::Lookup => "lookup",
            FsOp::Readdir => "readdir",
            FsOp::Readdirplus => "readdirplus",
            FsOp::Access => "access",
            FsOp::Forget => "forget",
        }
    }

    /// All operations, used to pre-create label series so every op appears in
    /// the exposition output even before it is first invoked.
    const ALL: [FsOp; 14] = [
        FsOp::Getattr,
        FsOp::Readlink,
        FsOp::Open,
        FsOp::Release,
        FsOp::Read,
        FsOp::Statfs,
        FsOp::Getxattr,
        FsOp::Listxattr,
        FsOp::Opendir,
        FsOp::Lookup,
        FsOp::Readdir,
        FsOp::Readdirplus,
        FsOp::Access,
        FsOp::Forget,
    ];
}

/// All metrics, registered into a single private registry.
struct Metrics {
    registry: Registry,

    backend_origin_read_count: IntCounter,
    backend_origin_read_errors: IntCounter,
    backend_proxy_read_count: IntCounter,
    backend_proxy_read_errors: IntCounter,
    backend_origin_read_latency: Histogram,
    backend_proxy_read_latency: Histogram,
    backend_origin_read_bytes: IntCounter,
    backend_proxy_read_bytes: IntCounter,

    backend_prefetch_read_count: IntCounter,
    backend_prefetch_read_bytes: IntCounter,
    backend_ondemand_read_count: IntCounter,
    backend_ondemand_read_bytes: IntCounter,
    backend_prefetch_read_errors: IntCounter,
    backend_prefetch_read_high_latency_count: IntCounter,
    backend_ondemand_read_errors: IntCounter,
    backend_ondemand_read_high_latency_count: IntCounter,

    backend_origin_crc_check_errors: IntCounter,
    backend_proxy_crc_check_errors: IntCounter,

    backend_redirect_read_count: IntCounter,
    backend_redirect_read_bytes: IntCounter,

    backend_dragonfly_read_errors: IntCounterVec,
    backend_fallback_read_count: IntCounter,
    backend_fallback_read_errors: IntCounter,
    backend_fallback_throttle_wait: Histogram,

    prefetch_reschedule_count: IntCounter,
    prefetch_reschedule_run_count: IntCounter,

    fs_op_count: IntCounterVec,
    fs_op_errors: IntCounterVec,
    fs_read_latency: Histogram,

    cache_opened_files: IntGauge,
    cache_hit_block_group: IntCounter,
    cache_total_block_group: IntGauge,
    cache_fill_block_group: IntCounter,
    cache_ondemand_fill_block_group: IntCounter,
    cache_redirect_fill_block_group: IntCounter,
    cache_redirect_skip_block_group: IntCounter,
}

impl Metrics {
    fn new() -> Self {
        let registry = Registry::new();

        fn counter(registry: &Registry, name: &str, help: &str) -> IntCounter {
            let counter = IntCounter::with_opts(Opts::new(name, help)).expect("valid counter");
            registry
                .register(Box::new(counter.clone()))
                .expect("register");
            counter
        }

        fn gauge(registry: &Registry, name: &str, help: &str) -> IntGauge {
            let gauge = IntGauge::with_opts(Opts::new(name, help)).expect("valid gauge");
            registry
                .register(Box::new(gauge.clone()))
                .expect("register");
            gauge
        }

        fn histogram(registry: &Registry, name: &str, help: &str) -> Histogram {
            let histogram =
                Histogram::with_opts(HistogramOpts::new(name, help).buckets(latency_buckets()))
                    .expect("valid histogram");
            registry
                .register(Box::new(histogram.clone()))
                .expect("register");
            histogram
        }

        let fs_op_count = IntCounterVec::new(
            Opts::new("fs_op_count", "Successful FUSE filesystem operations by op"),
            &["op"],
        )
        .expect("valid counter vec");
        registry
            .register(Box::new(fs_op_count.clone()))
            .expect("register");

        let fs_op_errors = IntCounterVec::new(
            Opts::new("fs_op_errors", "Failed FUSE filesystem operations by op"),
            &["op"],
        )
        .expect("valid counter vec");
        registry
            .register(Box::new(fs_op_errors.clone()))
            .expect("register");

        // Pre-create every op series so they appear in the output at zero.
        for op in FsOp::ALL {
            fs_op_count.with_label_values(&[op.as_str()]);
            fs_op_errors.with_label_values(&[op.as_str()]);
        }

        let backend_dragonfly_read_errors = IntCounterVec::new(
            Opts::new(
                "backend_dragonfly_read_errors",
                "Failed Dragonfly SDK reads by error class and read kind",
            ),
            &["class", "kind"],
        )
        .expect("valid counter vec");
        registry
            .register(Box::new(backend_dragonfly_read_errors.clone()))
            .expect("register");

        // Pre-create every class/kind series so they appear at zero.
        for class in DragonflyErrorClass::ALL {
            for kind in ReadKind::ALL {
                backend_dragonfly_read_errors.with_label_values(&[class.as_str(), kind.as_str()]);
            }
        }

        Self {
            backend_origin_read_count: counter(
                &registry,
                "backend_origin_read_count",
                "Backend reads served by the origin registry",
            ),
            backend_origin_read_errors: counter(
                &registry,
                "backend_origin_read_errors",
                "Failed backend reads against the origin registry",
            ),
            backend_proxy_read_count: counter(
                &registry,
                "backend_proxy_read_count",
                "Backend reads served by a proxy (HTTP mirror or Dragonfly)",
            ),
            backend_proxy_read_errors: counter(
                &registry,
                "backend_proxy_read_errors",
                "Failed backend reads against a proxy",
            ),
            backend_origin_read_latency: histogram(
                &registry,
                "backend_origin_read_latency",
                "Origin backend read latency in seconds",
            ),
            backend_proxy_read_latency: histogram(
                &registry,
                "backend_proxy_read_latency",
                "Proxy backend read latency in seconds",
            ),
            backend_origin_read_bytes: counter(
                &registry,
                "backend_origin_read_bytes",
                "Bytes read from the origin registry",
            ),
            backend_proxy_read_bytes: counter(
                &registry,
                "backend_proxy_read_bytes",
                "Bytes read from a proxy",
            ),
            backend_prefetch_read_count: counter(
                &registry,
                "backend_prefetch_read_count",
                "Backend reads triggered by prefetch",
            ),
            backend_prefetch_read_bytes: counter(
                &registry,
                "backend_prefetch_read_bytes",
                "Bytes read by prefetch",
            ),
            backend_ondemand_read_count: counter(
                &registry,
                "backend_ondemand_read_count",
                "Backend reads triggered on demand",
            ),
            backend_ondemand_read_bytes: counter(
                &registry,
                "backend_ondemand_read_bytes",
                "Bytes read on demand",
            ),
            backend_prefetch_read_errors: counter(
                &registry,
                "backend_prefetch_read_errors",
                "Failed prefetch backend reads",
            ),
            backend_prefetch_read_high_latency_count: counter(
                &registry,
                "backend_prefetch_read_high_latency_count",
                "Prefetch backend reads slower than the high-latency threshold",
            ),
            backend_ondemand_read_errors: counter(
                &registry,
                "backend_ondemand_read_errors",
                "Failed on-demand backend reads",
            ),
            backend_ondemand_read_high_latency_count: counter(
                &registry,
                "backend_ondemand_read_high_latency_count",
                "On-demand backend reads slower than the high-latency threshold",
            ),
            backend_origin_crc_check_errors: counter(
                &registry,
                "backend_origin_crc_check_errors",
                "CRC validation failures on data fetched from the origin",
            ),
            backend_proxy_crc_check_errors: counter(
                &registry,
                "backend_proxy_crc_check_errors",
                "CRC validation failures on data fetched from a proxy",
            ),
            backend_redirect_read_count: counter(
                &registry,
                "backend_redirect_read_count",
                "Backend reads that fetched ondemand (redirect) blob data",
            ),
            backend_redirect_read_bytes: counter(
                &registry,
                "backend_redirect_read_bytes",
                "Bytes of ondemand (redirect) blob data fetched from the backend",
            ),
            backend_dragonfly_read_errors,
            backend_fallback_read_count: counter(
                &registry,
                "backend_fallback_read_count",
                "Origin requests issued as Dragonfly fallbacks",
            ),
            backend_fallback_read_errors: counter(
                &registry,
                "backend_fallback_read_errors",
                "Failed origin requests issued as Dragonfly fallbacks",
            ),
            backend_fallback_throttle_wait: histogram(
                &registry,
                "backend_fallback_throttle_wait",
                "Seconds a Dragonfly fallback waited on the origin throttle",
            ),
            prefetch_reschedule_count: counter(
                &registry,
                "prefetch_reschedule_count",
                "Blob prefetches rescheduled after a throttled (429) backend failure",
            ),
            prefetch_reschedule_run_count: counter(
                &registry,
                "prefetch_reschedule_run_count",
                "Re-attempts of previously rescheduled blob prefetches",
            ),
            fs_op_count,
            fs_op_errors,
            fs_read_latency: histogram(
                &registry,
                "fs_read_latency",
                "FUSE read operation latency in seconds",
            ),
            cache_opened_files: gauge(
                &registry,
                "cache_opened_files",
                "Open blob data cache files (excluding .blob.meta and .group.map)",
            ),
            cache_hit_block_group: counter(
                &registry,
                "cache_hit_block_group",
                "Block groups served from cache without a backend read",
            ),
            cache_total_block_group: gauge(
                &registry,
                "cache_total_block_group",
                "Total block groups across loaded blob metas, counted once per blob",
            ),
            cache_fill_block_group: counter(
                &registry,
                "cache_fill_block_group",
                "Block groups written into a blob's own cache by regular blob prefetch",
            ),
            cache_ondemand_fill_block_group: counter(
                &registry,
                "cache_ondemand_fill_block_group",
                "Block groups written into a blob's own cache by an on-demand read",
            ),
            cache_redirect_fill_block_group: counter(
                &registry,
                "cache_redirect_fill_block_group",
                "Block groups written into a source blob's cache from a redirect (ondemand) blob",
            ),
            cache_redirect_skip_block_group: counter(
                &registry,
                "cache_redirect_skip_block_group",
                "Redirect block groups skipped during ondemand prefetch (decode/CRC/unknown-device/fill failures)",
            ),
            registry,
        }
    }
}

static METRICS: LazyLock<Metrics> = LazyLock::new(Metrics::new);

/// Record a single logical backend read: its target, kind, transferred byte
/// count (on success), duration and outcome. One call updates every relevant
/// origin/proxy and on-demand/prefetch counter, byte total and latency series.
pub fn record_backend_read(
    target: BackendTarget,
    kind: ReadKind,
    bytes: u64,
    duration: Duration,
    is_err: bool,
) {
    let metrics = &*METRICS;
    let secs = duration.as_secs_f64();
    let high_latency = duration >= HIGH_LATENCY_THRESHOLD;

    match target {
        BackendTarget::Origin => {
            metrics.backend_origin_read_count.inc();
            metrics.backend_origin_read_latency.observe(secs);
            if is_err {
                metrics.backend_origin_read_errors.inc();
            } else {
                metrics.backend_origin_read_bytes.inc_by(bytes);
            }
        }
        BackendTarget::Proxy => {
            metrics.backend_proxy_read_count.inc();
            metrics.backend_proxy_read_latency.observe(secs);
            if is_err {
                metrics.backend_proxy_read_errors.inc();
            } else {
                metrics.backend_proxy_read_bytes.inc_by(bytes);
            }
        }
    }

    match kind {
        ReadKind::OnDemand => {
            metrics.backend_ondemand_read_count.inc();
            if is_err {
                metrics.backend_ondemand_read_errors.inc();
            } else {
                metrics.backend_ondemand_read_bytes.inc_by(bytes);
            }
            if high_latency {
                metrics.backend_ondemand_read_high_latency_count.inc();
            }
        }
        ReadKind::Prefetch => {
            metrics.backend_prefetch_read_count.inc();
            if is_err {
                metrics.backend_prefetch_read_errors.inc();
            } else {
                metrics.backend_prefetch_read_bytes.inc_by(bytes);
            }
            if high_latency {
                metrics.backend_prefetch_read_high_latency_count.inc();
            }
        }
    }
}

/// Record a CRC validation failure on data fetched from `target`.
pub fn record_backend_crc_error(target: BackendTarget) {
    let metrics = &*METRICS;
    match target {
        BackendTarget::Origin => metrics.backend_origin_crc_check_errors.inc(),
        BackendTarget::Proxy => metrics.backend_proxy_crc_check_errors.inc(),
    }
}

/// Record the outcome of a FUSE operation, plus read latency for `read`.
pub fn record_fs_op(op: FsOp, duration: Duration, is_err: bool) {
    let metrics = &*METRICS;
    if is_err {
        metrics.fs_op_errors.with_label_values(&[op.as_str()]).inc();
    } else {
        metrics.fs_op_count.with_label_values(&[op.as_str()]).inc();
    }
    if op == FsOp::Read {
        metrics.fs_read_latency.observe(duration.as_secs_f64());
    }
}

/// Increment the count of open blob data cache files.
pub fn inc_cache_opened_files() {
    METRICS.cache_opened_files.inc();
}

/// Decrement the count of open blob data cache files.
pub fn dec_cache_opened_files() {
    METRICS.cache_opened_files.dec();
}

/// Blobs currently contributing to `cache_total_block_group`, with how many caches
/// hold each one. Blobs are keyed by cache key, so several caches over the
/// same blob — including ones reached through different images — only count
/// its block groups once.
static TRACKED_BLOBS: LazyLock<Mutex<HashMap<[u8; SHA256_DIGEST_SIZE], TrackedBlob>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

struct TrackedBlob {
    block_group_count: u64,
    holder_count: usize,
}

/// Count `block_groups` towards the total-block groups gauge for the blob `cache_key`,
/// unless another cache already counted it.
pub fn track_blob_block_groups(cache_key: [u8; SHA256_DIGEST_SIZE], block_group_count: u64) {
    // Telemetry is best-effort: recover from a poisoned lock instead of
    // propagating the panic (unlike the fail-fast `.unwrap()` policy used on
    // cache-state locks).
    let mut tracked = match TRACKED_BLOBS.lock() {
        Ok(tracked) => tracked,
        Err(poisoned) => poisoned.into_inner(),
    };
    let entry = tracked.entry(cache_key).or_insert(TrackedBlob {
        block_group_count,
        holder_count: 0,
    });
    entry.holder_count += 1;
    if entry.holder_count == 1 {
        METRICS
            .cache_total_block_group
            .add(entry.block_group_count as i64);
    }
}

/// Drop one cache's claim on the blob `cache_key`, uncounting its block groups once
/// the last cache over that blob is gone.
pub fn untrack_blob_block_groups(cache_key: &[u8; SHA256_DIGEST_SIZE]) {
    let mut tracked = match TRACKED_BLOBS.lock() {
        Ok(tracked) => tracked,
        Err(poisoned) => poisoned.into_inner(),
    };
    let Some(entry) = tracked.get_mut(cache_key) else {
        return;
    };
    entry.holder_count -= 1;
    if entry.holder_count == 0 {
        METRICS
            .cache_total_block_group
            .sub(entry.block_group_count as i64);
        tracked.remove(cache_key);
    }
}

/// Record a block group served from cache without a backend read.
pub fn inc_cache_hit_block_group() {
    METRICS.cache_hit_block_group.inc();
}

/// Record a backend read that fetched ondemand (redirect) blob data. These
/// reads are a subset of the prefetch reads and identify the phase-0 redirect
/// warmup traffic.
pub fn record_backend_redirect_read(bytes: u64) {
    let metrics = &*METRICS;
    metrics.backend_redirect_read_count.inc();
    metrics.backend_redirect_read_bytes.inc_by(bytes);
}

/// Record a block group decoded into a blob's own cache by regular blob prefetch.
pub fn inc_cache_fill_block_group() {
    METRICS.cache_fill_block_group.inc();
}

/// Record a block group decoded into a blob's own cache to satisfy an on-demand
/// read. Summing this across the processes sharing a cache directory shows how
/// much duplicate fetching they do.
pub fn inc_cache_ondemand_fill_block_group() {
    METRICS.cache_ondemand_fill_block_group.inc();
}

/// Record a block group decoded from a redirect (ondemand) blob and written into its
/// source blob's cache.
pub fn inc_cache_redirect_fill_block_group() {
    METRICS.cache_redirect_fill_block_group.inc();
}

/// Record a redirect block group skipped during ondemand prefetch (decode or CRC
/// failure, unknown source device, or a failed source-cache fill).
pub fn inc_cache_redirect_skip_block_group() {
    METRICS.cache_redirect_skip_block_group.inc();
}

/// Record a failed Dragonfly SDK read, attributed to its error class and to
/// the kind of read (on-demand or prefetch) that hit it.
pub fn record_dragonfly_error(class: DragonflyErrorClass, kind: ReadKind) {
    METRICS
        .backend_dragonfly_read_errors
        .with_label_values(&[class.as_str(), kind.as_str()])
        .inc();
}

/// Record an origin request issued as a Dragonfly fallback. These reads also
/// count towards the regular origin counters via [`record_backend_read`];
/// this pair isolates the fallback volume operators watch during Dragonfly
/// degradation.
pub fn record_fallback_read(is_err: bool) {
    METRICS.backend_fallback_read_count.inc();
    if is_err {
        METRICS.backend_fallback_read_errors.inc();
    }
}

/// Record how long a Dragonfly fallback waited on the origin throttle before
/// its request was allowed to start.
pub fn record_fallback_throttle_wait(wait: Duration) {
    METRICS
        .backend_fallback_throttle_wait
        .observe(wait.as_secs_f64());
}

/// Record a blob prefetch rescheduled for a delayed retry after a throttled
/// (429) backend failure.
pub fn inc_prefetch_reschedule() {
    METRICS.prefetch_reschedule_count.inc();
}

/// Record the execution of a previously rescheduled blob prefetch.
pub fn inc_prefetch_reschedule_run() {
    METRICS.prefetch_reschedule_run_count.inc();
}

/// How many caches currently claim the blob `cache_key`, for tests. The gauge
/// itself is process-global and other tests move it concurrently, so the
/// refcount is what can be asserted deterministically.
#[cfg(test)]
fn tracked_blob_refs(cache_key: &[u8; SHA256_DIGEST_SIZE]) -> Option<usize> {
    let tracked = match TRACKED_BLOBS.lock() {
        Ok(tracked) => tracked,
        Err(poisoned) => poisoned.into_inner(),
    };
    tracked.get(cache_key).map(|entry| entry.holder_count)
}

/// A serializable view over the live prometheus registry.
///
/// Rather than mirror every counter by hand, this wraps the gathered metric
/// families straight from the private `Metrics` struct's registry, so it always stays in sync
/// when metrics are added or removed. Serializing it yields a flat JSON object
/// mapping each metric name to its value, which embedders (e.g. a hypervisor's
/// stats endpoint) include to reason about runtime behavior: in particular
/// `backend_ondemand_read_count > 0` means the prefetch did not cover the
/// access pattern and the workload fell back to the network.
///
/// Encoding rules:
/// - counters serialize as unsigned integers, gauges as signed integers;
/// - histograms expand to `<name>_sum` (float) and `<name>_count` (integer);
/// - labeled series are keyed as `<name>{label="value",...}` so they never
///   collide under a single metric name.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    families: Vec<prometheus::proto::MetricFamily>,
}

impl Serialize for Snapshot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(None)?;
        for family in &self.families {
            let base = family.get_name();
            let field_type = family.get_field_type();
            for metric in family.get_metric() {
                let labels = metric.get_label();
                let key = if labels.is_empty() {
                    base.to_string()
                } else {
                    let pairs: Vec<String> = labels
                        .iter()
                        .map(|label| format!("{}=\"{}\"", label.get_name(), label.get_value()))
                        .collect();
                    format!("{}{{{}}}", base, pairs.join(","))
                };

                match field_type {
                    prometheus::proto::MetricType::COUNTER => {
                        map.serialize_entry(&key, &(metric.get_counter().get_value() as u64))?;
                    }
                    prometheus::proto::MetricType::GAUGE => {
                        map.serialize_entry(&key, &(metric.get_gauge().get_value() as i64))?;
                    }
                    prometheus::proto::MetricType::HISTOGRAM => {
                        let histogram = metric.get_histogram();
                        map.serialize_entry(&format!("{key}_sum"), &histogram.get_sample_sum())?;
                        map.serialize_entry(
                            &format!("{key}_count"),
                            &histogram.get_sample_count(),
                        )?;
                    }
                    _ => {}
                }
            }
        }
        map.end()
    }
}

/// Capture a serializable snapshot of every registered metric, sourced
/// directly from the prometheus registry inside the private `Metrics` struct.
pub fn snapshot() -> Snapshot {
    Snapshot {
        families: METRICS.registry.gather(),
    }
}

/// Current count of block groups filled into source blob caches from redirect blobs.
pub fn cache_redirect_fill_block_group_total() -> u64 {
    METRICS.cache_redirect_fill_block_group.get()
}

/// Current count of redirect block groups skipped during ondemand prefetch.
pub fn cache_redirect_skip_block_group_total() -> u64 {
    METRICS.cache_redirect_skip_block_group.get()
}

/// Current total bytes of ondemand (redirect) blob data fetched from the backend.
pub fn backend_redirect_read_bytes_total() -> u64 {
    METRICS.backend_redirect_read_bytes.get()
}

/// Current count of failed Dragonfly reads for one error class and read kind.
pub fn dragonfly_error_total(class: DragonflyErrorClass, kind: ReadKind) -> u64 {
    METRICS
        .backend_dragonfly_read_errors
        .with_label_values(&[class.as_str(), kind.as_str()])
        .get()
}

/// Current count of origin requests issued as Dragonfly fallbacks.
pub fn backend_fallback_read_total() -> u64 {
    METRICS.backend_fallback_read_count.get()
}

/// Current count of failed origin requests issued as Dragonfly fallbacks.
pub fn backend_fallback_read_error_total() -> u64 {
    METRICS.backend_fallback_read_errors.get()
}

/// Current count of backend reads attributed to `target`.
pub fn backend_read_total(target: BackendTarget) -> u64 {
    match target {
        BackendTarget::Origin => METRICS.backend_origin_read_count.get(),
        BackendTarget::Proxy => METRICS.backend_proxy_read_count.get(),
    }
}

/// Current count of CRC validation failures attributed to `target`.
pub fn backend_crc_error_total(target: BackendTarget) -> u64 {
    match target {
        BackendTarget::Origin => METRICS.backend_origin_crc_check_errors.get(),
        BackendTarget::Proxy => METRICS.backend_proxy_crc_check_errors.get(),
    }
}

/// Current count of blob prefetches rescheduled after a throttled failure.
pub fn prefetch_reschedule_total() -> u64 {
    METRICS.prefetch_reschedule_count.get()
}

/// Current count of re-attempts of rescheduled blob prefetches.
pub fn prefetch_reschedule_run_total() -> u64 {
    METRICS.prefetch_reschedule_run_count.get()
}

/// Encode all metrics in the Prometheus text exposition format.
pub fn encode_text() -> String {
    let metric_families = METRICS.registry.gather();
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    if encoder.encode(&metric_families, &mut buffer).is_err() {
        return String::new();
    }
    String::from_utf8(buffer).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_text_contains_registered_metrics() {
        record_backend_read(
            BackendTarget::Origin,
            ReadKind::OnDemand,
            1024,
            Duration::from_millis(5),
            false,
        );
        record_fs_op(FsOp::Read, Duration::from_millis(2), false);
        inc_cache_hit_block_group();
        track_blob_block_groups([7u8; SHA256_DIGEST_SIZE], 3);
        inc_cache_opened_files();

        let text = encode_text();
        assert!(text.contains("backend_origin_read_count"));
        assert!(text.contains("backend_ondemand_read_bytes"));
        assert!(text.contains("fs_op_count"));
        assert!(text.contains("fs_read_latency"));
        assert!(text.contains("cache_hit_block_group"));
        assert!(text.contains("cache_total_block_group"));
        assert!(text.contains("cache_opened_files"));
    }

    #[test]
    fn high_latency_counts_when_over_threshold() {
        record_backend_read(
            BackendTarget::Proxy,
            ReadKind::Prefetch,
            0,
            Duration::from_millis(500),
            true,
        );
        let text = encode_text();
        assert!(text.contains("backend_prefetch_read_high_latency_count"));
    }

    #[test]
    fn dragonfly_policy_metrics_move_and_expose() {
        let errors_before =
            dragonfly_error_total(DragonflyErrorClass::RateLimited, ReadKind::Prefetch);
        let fallbacks_before = backend_fallback_read_total();
        let fallback_errors_before = backend_fallback_read_error_total();
        let reschedules_before = prefetch_reschedule_total();
        let reschedule_runs_before = prefetch_reschedule_run_total();

        record_dragonfly_error(DragonflyErrorClass::RateLimited, ReadKind::Prefetch);
        record_fallback_read(false);
        record_fallback_read(true);
        record_fallback_throttle_wait(Duration::from_millis(10));
        inc_prefetch_reschedule();
        inc_prefetch_reschedule_run();

        assert_eq!(
            dragonfly_error_total(DragonflyErrorClass::RateLimited, ReadKind::Prefetch),
            errors_before + 1
        );
        assert_eq!(backend_fallback_read_total(), fallbacks_before + 2);
        assert_eq!(
            backend_fallback_read_error_total(),
            fallback_errors_before + 1
        );
        assert_eq!(prefetch_reschedule_total(), reschedules_before + 1);
        assert_eq!(prefetch_reschedule_run_total(), reschedule_runs_before + 1);

        let text = encode_text();
        assert!(
            text.contains(r#"backend_dragonfly_read_errors{class="rate_limited",kind="prefetch"}"#)
        );
        // Series for classes never hit are pre-created at zero.
        assert!(
            text.contains(r#"backend_dragonfly_read_errors{class="forbidden",kind="ondemand"}"#)
        );
        assert!(text.contains("backend_fallback_read_count"));
        assert!(text.contains("backend_fallback_read_errors"));
        assert!(text.contains("backend_fallback_throttle_wait"));
        assert!(text.contains("prefetch_reschedule_count"));
        assert!(text.contains("prefetch_reschedule_run_count"));
    }

    #[test]
    fn snapshot_serializes_metrics_as_json_object() {
        record_backend_read(
            BackendTarget::Origin,
            ReadKind::OnDemand,
            2048,
            Duration::from_millis(3),
            false,
        );
        record_fs_op(FsOp::Read, Duration::from_millis(1), false);

        let json = serde_json::to_value(snapshot()).expect("snapshot serializes");
        let obj = json.as_object().expect("snapshot is a JSON object");

        // Non-labeled counters keyed by their bare metric name.
        assert!(obj.contains_key("backend_ondemand_read_count"));
        assert!(json["backend_ondemand_read_count"].as_u64().unwrap() >= 1);
        // Gauges keyed by their bare name too.
        assert!(obj.contains_key("cache_total_block_group"));
        // Labeled series are disambiguated with a brace-suffixed key.
        assert!(obj.keys().any(|k| k.starts_with("fs_op_count{op=")));
        // Histograms expand to _sum / _count.
        assert!(obj.contains_key("fs_read_latency_count"));
        assert!(obj.contains_key("fs_read_latency_sum"));
    }

    #[test]
    fn blob_block_groups_are_counted_once_per_blob_and_released() {
        // The gauge moves with the refcount transitions asserted here, and is
        // itself process-global, so this pins the transitions instead.
        let key = [42u8; SHA256_DIGEST_SIZE];
        assert_eq!(tracked_blob_refs(&key), None);

        // A second cache over the same blob joins the existing entry rather
        // than counting the blob's block groups again.
        track_blob_block_groups(key, 10);
        assert_eq!(tracked_blob_refs(&key), Some(1));
        track_blob_block_groups(key, 10);
        assert_eq!(tracked_blob_refs(&key), Some(2));

        // The block groups stay counted until the last cache is gone.
        untrack_blob_block_groups(&key);
        assert_eq!(tracked_blob_refs(&key), Some(1));
        untrack_blob_block_groups(&key);
        assert_eq!(tracked_blob_refs(&key), None);
    }
}
