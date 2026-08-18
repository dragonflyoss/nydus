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

    fs_op_count: IntCounterVec,
    fs_op_errors: IntCounterVec,
    fs_read_latency: Histogram,

    cache_opened_files: IntGauge,
    cache_hit_group: IntCounter,
    cache_total_group: IntGauge,
    cache_fill_group: IntCounter,
    cache_ondemand_fill_group: IntCounter,
    cache_redirect_fill_group: IntCounter,
    cache_redirect_skip_group: IntCounter,
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
            cache_hit_group: counter(
                &registry,
                "cache_hit_group",
                "Groups served from cache without a backend read",
            ),
            cache_total_group: gauge(
                &registry,
                "cache_total_group",
                "Total groups across loaded blob metas, counted once per blob",
            ),
            cache_fill_group: counter(
                &registry,
                "cache_fill_group",
                "Groups written into a blob's own cache by regular blob prefetch",
            ),
            cache_ondemand_fill_group: counter(
                &registry,
                "cache_ondemand_fill_group",
                "Groups written into a blob's own cache by an on-demand read",
            ),
            cache_redirect_fill_group: counter(
                &registry,
                "cache_redirect_fill_group",
                "Groups written into a source blob's cache from a redirect (ondemand) blob",
            ),
            cache_redirect_skip_group: counter(
                &registry,
                "cache_redirect_skip_group",
                "Redirect groups skipped during ondemand prefetch (decode/CRC/unknown-device/fill failures)",
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

/// Blobs currently contributing to `cache_total_group`, with how many caches
/// hold each one. Blobs are keyed by cache key, so several caches over the
/// same blob — including ones reached through different images — only count
/// its groups once.
static TRACKED_BLOBS: LazyLock<Mutex<HashMap<[u8; SHA256_DIGEST_SIZE], TrackedBlob>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

struct TrackedBlob {
    group_count: u64,
    holder_count: usize,
}

/// Count `groups` towards the total-groups gauge for the blob `cache_key`,
/// unless another cache already counted it.
pub fn track_blob_groups(cache_key: [u8; SHA256_DIGEST_SIZE], group_count: u64) {
    // Telemetry is best-effort: recover from a poisoned lock instead of
    // propagating the panic (unlike the fail-fast `.unwrap()` policy used on
    // cache-state locks).
    let mut tracked = match TRACKED_BLOBS.lock() {
        Ok(tracked) => tracked,
        Err(poisoned) => poisoned.into_inner(),
    };
    let entry = tracked.entry(cache_key).or_insert(TrackedBlob {
        group_count,
        holder_count: 0,
    });
    entry.holder_count += 1;
    if entry.holder_count == 1 {
        METRICS.cache_total_group.add(entry.group_count as i64);
    }
}

/// Drop one cache's claim on the blob `cache_key`, uncounting its groups once
/// the last cache over that blob is gone.
pub fn untrack_blob_groups(cache_key: &[u8; SHA256_DIGEST_SIZE]) {
    let mut tracked = match TRACKED_BLOBS.lock() {
        Ok(tracked) => tracked,
        Err(poisoned) => poisoned.into_inner(),
    };
    let Some(entry) = tracked.get_mut(cache_key) else {
        return;
    };
    entry.holder_count -= 1;
    if entry.holder_count == 0 {
        METRICS.cache_total_group.sub(entry.group_count as i64);
        tracked.remove(cache_key);
    }
}

/// Record a group served from cache without a backend read.
pub fn inc_cache_hit_group() {
    METRICS.cache_hit_group.inc();
}

/// Record a backend read that fetched ondemand (redirect) blob data. These
/// reads are a subset of the prefetch reads and identify the phase-0 redirect
/// warmup traffic.
pub fn record_backend_redirect_read(bytes: u64) {
    let metrics = &*METRICS;
    metrics.backend_redirect_read_count.inc();
    metrics.backend_redirect_read_bytes.inc_by(bytes);
}

/// Record a group decoded into a blob's own cache by regular blob prefetch.
pub fn inc_cache_fill_group() {
    METRICS.cache_fill_group.inc();
}

/// Record a group decoded into a blob's own cache to satisfy an on-demand
/// read. Summing this across the processes sharing a cache directory shows how
/// much duplicate fetching they do.
pub fn inc_cache_ondemand_fill_group() {
    METRICS.cache_ondemand_fill_group.inc();
}

/// Record a group decoded from a redirect (ondemand) blob and written into its
/// source blob's cache.
pub fn inc_cache_redirect_fill_group() {
    METRICS.cache_redirect_fill_group.inc();
}

/// Record a redirect group skipped during ondemand prefetch (decode or CRC
/// failure, unknown source device, or a failed source-cache fill).
pub fn inc_cache_redirect_skip_group() {
    METRICS.cache_redirect_skip_group.inc();
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

/// Current count of groups filled into source blob caches from redirect blobs.
pub fn cache_redirect_fill_group_total() -> u64 {
    METRICS.cache_redirect_fill_group.get()
}

/// Current count of redirect groups skipped during ondemand prefetch.
pub fn cache_redirect_skip_group_total() -> u64 {
    METRICS.cache_redirect_skip_group.get()
}

/// Current total bytes of ondemand (redirect) blob data fetched from the backend.
pub fn backend_redirect_read_bytes_total() -> u64 {
    METRICS.backend_redirect_read_bytes.get()
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
        inc_cache_hit_group();
        track_blob_groups([7u8; SHA256_DIGEST_SIZE], 3);
        inc_cache_opened_files();

        let text = encode_text();
        assert!(text.contains("backend_origin_read_count"));
        assert!(text.contains("backend_ondemand_read_bytes"));
        assert!(text.contains("fs_op_count"));
        assert!(text.contains("fs_read_latency"));
        assert!(text.contains("cache_hit_group"));
        assert!(text.contains("cache_total_group"));
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
        assert!(obj.contains_key("cache_total_group"));
        // Labeled series are disambiguated with a brace-suffixed key.
        assert!(obj.keys().any(|k| k.starts_with("fs_op_count{op=")));
        // Histograms expand to _sum / _count.
        assert!(obj.contains_key("fs_read_latency_count"));
        assert!(obj.contains_key("fs_read_latency_sum"));
    }

    #[test]
    fn blob_groups_are_counted_once_per_blob_and_released() {
        // The gauge moves with the refcount transitions asserted here, and is
        // itself process-global, so this pins the transitions instead.
        let key = [42u8; SHA256_DIGEST_SIZE];
        assert_eq!(tracked_blob_refs(&key), None);

        // A second cache over the same blob joins the existing entry rather
        // than counting the blob's groups again.
        track_blob_groups(key, 10);
        assert_eq!(tracked_blob_refs(&key), Some(1));
        track_blob_groups(key, 10);
        assert_eq!(tracked_blob_refs(&key), Some(2));

        // The groups stay counted until the last cache is gone.
        untrack_blob_groups(&key);
        assert_eq!(tracked_blob_refs(&key), Some(1));
        untrack_blob_groups(&key);
        assert_eq!(tracked_blob_refs(&key), None);
    }
}
