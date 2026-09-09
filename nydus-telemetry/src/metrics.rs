//! The Prometheus metrics of the nydus daemon: [`REGISTRY`], every metric it
//! holds and the `collect_*_metrics` functions that move them. Whoever serves
//! `/metrics` encodes `REGISTRY.gather()` with a [`prometheus::TextEncoder`].
//!
//! Every metric name carries the `nydus_` namespace and is a verb followed by
//! what it acts on, `read_backend_total`, `validate_block_group_total`,
//! `prefetch_task_total`. Counters end in `_total`, failure counters in
//! `_failure_total`, byte counters in `_traffic`, duration histograms in
//! `_duration_milliseconds`. Dimensions are labels, each with a fixed
//! vocabulary:
//!
//! ```text
//! type      what triggered the operation           ondemand | prefetch
//! backend   the blob backend                       local | registry
//! protocol  how the registry backend fetched       http | dragonfly-http | dragonfly-sdk
//! storage   where a block group was read from      local | backend
//! op        the FUSE operation                     lookup | read | getattr | ...
//! ```
//!
//! `protocol` is `http` for the registry backend reading the origin,
//! `dragonfly-sdk` for it reading the Dragonfly seed peers, and
//! `dragonfly-http` for it reading the origin after Dragonfly could not serve
//! the read. The local backend has no protocol and leaves the label empty.
//! `storage` is `local` for a block group already in the local cache and
//! `backend` for one fetched from the backend into the cache.

use std::fmt;
use std::sync::LazyLock;
use std::time::Duration;

use prometheus::{exponential_buckets, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry};

pub use nydus_config::{Backend, Protocol, ReadKind};

/// Used to register all metrics.
pub static REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
    let registry = Registry::new();
    register_custom_metrics(&registry);
    registry
});

/// Used to count the number of read backends.
pub static READ_BACKEND_COUNT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "read_backend_total",
            "Counter of the number of the read backend.",
        )
        .namespace(nydus_config::NAME),
        &["type", "backend", "protocol"],
    )
    .expect("metric can be created")
});

/// Used to count the failed number of read backends.
pub static READ_BACKEND_FAILURE_COUNT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "read_backend_failure_total",
            "Counter of the number of failed of the read backend.",
        )
        .namespace(nydus_config::NAME),
        &["type", "backend", "protocol"],
    )
    .expect("metric can be created")
});

/// Used to record the read backend duration.
pub static READ_BACKEND_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    HistogramVec::new(
        HistogramOpts::new(
            "read_backend_duration_milliseconds",
            "Histogram of the read backend duration.",
        )
        .namespace(nydus_config::NAME)
        .buckets(exponential_buckets(1.0, 2.0, 24).unwrap()),
        &["type", "backend", "protocol"],
    )
    .expect("metric can be created")
});

/// Used to count the read backend traffic.
pub static READ_BACKEND_TRAFFIC: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "read_backend_traffic",
            "Counter of the number of the read backend traffic.",
        )
        .namespace(nydus_config::NAME),
        &["type", "backend", "protocol"],
    )
    .expect("metric can be created")
});

/// Used to count the number of validate block groups.
pub static VALIDATE_BLOCK_GROUP_COUNT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "validate_block_group_total",
            "Counter of the number of the validate block group.",
        )
        .namespace(nydus_config::NAME),
        &["backend", "protocol"],
    )
    .expect("metric can be created")
});

/// Used to count the failed number of validate block groups.
pub static VALIDATE_BLOCK_GROUP_FAILURE_COUNT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "validate_block_group_failure_total",
            "Counter of the number of failed of the validate block group.",
        )
        .namespace(nydus_config::NAME),
        &["backend", "protocol"],
    )
    .expect("metric can be created")
});

/// Used to count the number of prefetch tasks.
pub static PREFETCH_TASK_COUNT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "prefetch_task_total",
            "Counter of the number of the prefetch task.",
        )
        .namespace(nydus_config::NAME),
        &[],
    )
    .expect("metric can be created")
});

/// Used to count the failed number of prefetch tasks.
pub static PREFETCH_TASK_FAILURE_COUNT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "prefetch_task_failure_total",
            "Counter of the number of failed of the prefetch task.",
        )
        .namespace(nydus_config::NAME),
        &[],
    )
    .expect("metric can be created")
});

/// Used to count the number of rescheduled prefetch tasks.
pub static PREFETCH_TASK_RESCHEDULE_COUNT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "prefetch_task_reschedule_total",
            "Counter of the number of the rescheduled prefetch task.",
        )
        .namespace(nydus_config::NAME),
        &[],
    )
    .expect("metric can be created")
});

/// Used to count the number of filesystem operations.
pub static FS_OP_COUNT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "fs_op_total",
            "Counter of the number of the filesystem operation.",
        )
        .namespace(nydus_config::NAME),
        &["op"],
    )
    .expect("metric can be created")
});

/// Used to count the failed number of filesystem operations.
pub static FS_OP_FAILURE_COUNT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "fs_op_failure_total",
            "Counter of the number of failed of the filesystem operation.",
        )
        .namespace(nydus_config::NAME),
        &["op"],
    )
    .expect("metric can be created")
});

/// Used to record the filesystem read duration.
pub static FS_READ_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    HistogramVec::new(
        HistogramOpts::new(
            "fs_read_duration_milliseconds",
            "Histogram of the filesystem read duration.",
        )
        .namespace(nydus_config::NAME)
        .buckets(exponential_buckets(1.0, 2.0, 24).unwrap()),
        &[],
    )
    .expect("metric can be created")
});

/// Used to count the number of read block groups.
pub static READ_BLOCK_GROUP_COUNT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "read_block_group_total",
            "Counter of the number of the read block group.",
        )
        .namespace(nydus_config::NAME),
        &["type", "storage", "backend", "protocol"],
    )
    .expect("metric can be created")
});

/// Used to count the number of fill block groups from redirect blob.
pub static FILL_BLOCK_GROUP_FROM_REDIRECT_BLOB_COUNT: LazyLock<IntCounterVec> =
    LazyLock::new(|| {
        IntCounterVec::new(
            Opts::new(
                "fill_block_group_from_redirect_blob_total",
                "Counter of the number of the fill block group from redirect blob.",
            )
            .namespace(nydus_config::NAME),
            &[],
        )
        .expect("metric can be created")
    });

/// Used to count the failed number of fill block groups from redirect blob.
pub static FILL_BLOCK_GROUP_FROM_REDIRECT_BLOB_FAILURE_COUNT: LazyLock<IntCounterVec> =
    LazyLock::new(|| {
        IntCounterVec::new(
            Opts::new(
                "fill_block_group_from_redirect_blob_failure_total",
                "Counter of the number of failed of the fill block group from redirect blob.",
            )
            .namespace(nydus_config::NAME),
            &[],
        )
        .expect("metric can be created")
    });

/// Used to count the number of prefetch redirect blobs.
pub static PREFETCH_REDIRECT_BLOB_COUNT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "prefetch_redirect_blob_total",
            "Counter of the number of the prefetch redirect blob.",
        )
        .namespace(nydus_config::NAME),
        &[],
    )
    .expect("metric can be created")
});

/// Used to count the prefetch redirect blob traffic.
pub static PREFETCH_REDIRECT_BLOB_TRAFFIC: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "prefetch_redirect_blob_traffic",
            "Counter of the number of the prefetch redirect blob traffic.",
        )
        .namespace(nydus_config::NAME),
        &[],
    )
    .expect("metric can be created")
});

/// Registers all custom metrics.
fn register_custom_metrics(registry: &Registry) {
    registry
        .register(Box::new(READ_BACKEND_COUNT.clone()))
        .expect("metric can be registered");

    registry
        .register(Box::new(READ_BACKEND_FAILURE_COUNT.clone()))
        .expect("metric can be registered");

    registry
        .register(Box::new(READ_BACKEND_DURATION.clone()))
        .expect("metric can be registered");

    registry
        .register(Box::new(READ_BACKEND_TRAFFIC.clone()))
        .expect("metric can be registered");

    registry
        .register(Box::new(VALIDATE_BLOCK_GROUP_COUNT.clone()))
        .expect("metric can be registered");

    registry
        .register(Box::new(VALIDATE_BLOCK_GROUP_FAILURE_COUNT.clone()))
        .expect("metric can be registered");

    registry
        .register(Box::new(PREFETCH_TASK_COUNT.clone()))
        .expect("metric can be registered");

    registry
        .register(Box::new(PREFETCH_TASK_FAILURE_COUNT.clone()))
        .expect("metric can be registered");

    registry
        .register(Box::new(PREFETCH_TASK_RESCHEDULE_COUNT.clone()))
        .expect("metric can be registered");

    registry
        .register(Box::new(FS_OP_COUNT.clone()))
        .expect("metric can be registered");

    registry
        .register(Box::new(FS_OP_FAILURE_COUNT.clone()))
        .expect("metric can be registered");

    registry
        .register(Box::new(FS_READ_DURATION.clone()))
        .expect("metric can be registered");

    registry
        .register(Box::new(READ_BLOCK_GROUP_COUNT.clone()))
        .expect("metric can be registered");

    registry
        .register(Box::new(FILL_BLOCK_GROUP_FROM_REDIRECT_BLOB_COUNT.clone()))
        .expect("metric can be registered");

    registry
        .register(Box::new(
            FILL_BLOCK_GROUP_FROM_REDIRECT_BLOB_FAILURE_COUNT.clone(),
        ))
        .expect("metric can be registered");

    registry
        .register(Box::new(PREFETCH_REDIRECT_BLOB_COUNT.clone()))
        .expect("metric can be registered");

    registry
        .register(Box::new(PREFETCH_REDIRECT_BLOB_TRAFFIC.clone()))
        .expect("metric can be registered");
}

/// Represents where a block group was read from, the `storage` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    /// Already in the local cache, served without a backend read.
    Local,

    /// Fetched from the backend and written into the local cache.
    Backend,
}

/// Implements the Display trait.
impl fmt::Display for Storage {
    /// fmt formats the Storage.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Storage::Local => write!(f, "local"),
            Storage::Backend => write!(f, "backend"),
        }
    }
}

/// The `protocol` label value of a backend, empty when it has none.
fn protocol_label(protocol: Option<Protocol>) -> String {
    protocol
        .map(|protocol| protocol.to_string())
        .unwrap_or_default()
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

/// Collects the read backend finished metrics.
pub fn collect_read_backend_finished_metrics(
    kind: ReadKind,
    backend: Backend,
    protocol: Option<Protocol>,
    length: u64,
    cost: Duration,
) {
    let kind = kind.to_string();
    let backend = backend.to_string();
    let protocol = protocol_label(protocol);
    let labels = [kind.as_str(), backend.as_str(), protocol.as_str()];

    READ_BACKEND_COUNT.with_label_values(&labels).inc();

    READ_BACKEND_TRAFFIC
        .with_label_values(&labels)
        .inc_by(length);

    READ_BACKEND_DURATION
        .with_label_values(&labels)
        .observe(cost.as_millis() as f64);
}

/// Collects the read backend failure metrics.
pub fn collect_read_backend_failure_metrics(
    kind: ReadKind,
    backend: Backend,
    protocol: Option<Protocol>,
    cost: Duration,
) {
    let kind = kind.to_string();
    let backend = backend.to_string();
    let protocol = protocol_label(protocol);
    let labels = [kind.as_str(), backend.as_str(), protocol.as_str()];

    READ_BACKEND_COUNT.with_label_values(&labels).inc();

    READ_BACKEND_FAILURE_COUNT.with_label_values(&labels).inc();

    READ_BACKEND_DURATION
        .with_label_values(&labels)
        .observe(cost.as_millis() as f64);
}

/// Collects the validate block group started metrics.
pub fn collect_validate_block_group_started_metrics(backend: Backend, protocol: Option<Protocol>) {
    VALIDATE_BLOCK_GROUP_COUNT
        .with_label_values(&[backend.to_string().as_str(), &protocol_label(protocol)])
        .inc();
}

/// Collects the validate block group failure metrics.
pub fn collect_validate_block_group_failure_metrics(backend: Backend, protocol: Option<Protocol>) {
    VALIDATE_BLOCK_GROUP_FAILURE_COUNT
        .with_label_values(&[backend.to_string().as_str(), &protocol_label(protocol)])
        .inc();
}

/// Collects the prefetch task started metrics.
pub fn collect_prefetch_task_started_metrics() {
    PREFETCH_TASK_COUNT.with_label_values(&[]).inc();
}

/// Collects the prefetch task failure metrics.
pub fn collect_prefetch_task_failure_metrics() {
    PREFETCH_TASK_FAILURE_COUNT.with_label_values(&[]).inc();
}

/// Collects the prefetch task reschedule metrics.
pub fn collect_prefetch_task_reschedule_metrics() {
    PREFETCH_TASK_RESCHEDULE_COUNT.with_label_values(&[]).inc();
}

/// Collects the filesystem operation finished metrics.
pub fn collect_fs_op_finished_metrics(op: FsOp, cost: Duration) {
    FS_OP_COUNT
        .with_label_values(&[op.to_string().as_str()])
        .inc();

    if op == FsOp::Read {
        FS_READ_DURATION
            .with_label_values(&[])
            .observe(cost.as_millis() as f64);
    }
}

/// Collects the filesystem operation failure metrics.
pub fn collect_fs_op_failure_metrics(op: FsOp, cost: Duration) {
    FS_OP_FAILURE_COUNT
        .with_label_values(&[op.to_string().as_str()])
        .inc();

    if op == FsOp::Read {
        FS_READ_DURATION
            .with_label_values(&[])
            .observe(cost.as_millis() as f64);
    }
}

/// Collects the read block group metrics.
pub fn collect_read_block_group_metrics(
    kind: ReadKind,
    storage: Storage,
    backend: Backend,
    protocol: Option<Protocol>,
) {
    READ_BLOCK_GROUP_COUNT
        .with_label_values(&[
            kind.to_string().as_str(),
            storage.to_string().as_str(),
            backend.to_string().as_str(),
            &protocol_label(protocol),
        ])
        .inc();
}

/// Collects the fill block group from redirect blob finished metrics.
pub fn collect_fill_block_group_from_redirect_blob_finished_metrics() {
    FILL_BLOCK_GROUP_FROM_REDIRECT_BLOB_COUNT
        .with_label_values(&[])
        .inc();
}

/// Collects the fill block group from redirect blob failure metrics.
pub fn collect_fill_block_group_from_redirect_blob_failure_metrics() {
    FILL_BLOCK_GROUP_FROM_REDIRECT_BLOB_FAILURE_COUNT
        .with_label_values(&[])
        .inc();
}

/// Collects the prefetch redirect blob metrics.
pub fn collect_prefetch_redirect_blob_metrics(length: u64) {
    PREFETCH_REDIRECT_BLOB_COUNT.with_label_values(&[]).inc();

    PREFETCH_REDIRECT_BLOB_TRAFFIC
        .with_label_values(&[])
        .inc_by(length);
}

#[cfg(test)]
mod tests {
    use super::*;

    type Collect = fn();
    type Read = fn() -> u64;

    struct ReadSample {
        count: u64,
        failure: u64,
        traffic: u64,
        duration_count: u64,
        duration_sum: f64,
    }

    fn read_sample(kind: ReadKind, backend: Backend, protocol: Option<Protocol>) -> ReadSample {
        let kind = kind.to_string();
        let backend = backend.to_string();
        let protocol = protocol_label(protocol);
        let labels = [kind.as_str(), backend.as_str(), protocol.as_str()];
        ReadSample {
            count: READ_BACKEND_COUNT.with_label_values(&labels).get(),
            failure: READ_BACKEND_FAILURE_COUNT.with_label_values(&labels).get(),
            traffic: READ_BACKEND_TRAFFIC.with_label_values(&labels).get(),
            duration_count: READ_BACKEND_DURATION
                .with_label_values(&labels)
                .get_sample_count(),
            duration_sum: READ_BACKEND_DURATION
                .with_label_values(&labels)
                .get_sample_sum(),
        }
    }

    #[test]
    fn read_backends_are_counted_by_type_backend_and_protocol() {
        let test_cases = vec![
            (ReadKind::OnDemand, Backend::Local, None),
            (ReadKind::Prefetch, Backend::Local, None),
            (ReadKind::OnDemand, Backend::Registry, Some(Protocol::Http)),
            (
                ReadKind::Prefetch,
                Backend::Registry,
                Some(Protocol::DragonflySdk),
            ),
            (
                ReadKind::OnDemand,
                Backend::Registry,
                Some(Protocol::DragonflyHttp),
            ),
        ];

        for (kind, backend, protocol) in test_cases {
            let before = read_sample(kind, backend, protocol);
            collect_read_backend_finished_metrics(
                kind,
                backend,
                protocol,
                1024,
                Duration::from_millis(5),
            );
            collect_read_backend_failure_metrics(kind, backend, protocol, Duration::from_millis(7));
            let after = read_sample(kind, backend, protocol);

            assert!(
                after.count - before.count >= 2,
                "kind: {kind}, backend: {backend}, protocol: {protocol:?}"
            );
            assert_eq!(
                after.failure - before.failure,
                1,
                "kind: {kind}, backend: {backend}, protocol: {protocol:?}"
            );
            assert!(
                after.traffic - before.traffic >= 1024,
                "kind: {kind}, backend: {backend}, protocol: {protocol:?}"
            );
            assert!(
                after.duration_count - before.duration_count >= 2,
                "kind: {kind}, backend: {backend}, protocol: {protocol:?}"
            );
            assert!(
                after.duration_sum - before.duration_sum >= 12.0,
                "kind: {kind}, backend: {backend}, protocol: {protocol:?}"
            );
        }
    }

    #[test]
    fn validate_block_groups_are_counted_by_backend_and_protocol() {
        let test_cases = vec![
            (Backend::Local, None),
            (Backend::Registry, Some(Protocol::Http)),
            (Backend::Registry, Some(Protocol::DragonflySdk)),
        ];

        for (backend, protocol) in test_cases {
            let backend_label = backend.to_string();
            let protocol_label = protocol_label(protocol);
            let labels = [backend_label.as_str(), protocol_label.as_str()];
            let count_before = VALIDATE_BLOCK_GROUP_COUNT.with_label_values(&labels).get();
            let failure_before = VALIDATE_BLOCK_GROUP_FAILURE_COUNT
                .with_label_values(&labels)
                .get();

            collect_validate_block_group_started_metrics(backend, protocol);
            collect_validate_block_group_failure_metrics(backend, protocol);

            assert!(
                VALIDATE_BLOCK_GROUP_COUNT.with_label_values(&labels).get() > count_before,
                "backend: {backend}, protocol: {protocol:?}"
            );
            assert!(
                VALIDATE_BLOCK_GROUP_FAILURE_COUNT
                    .with_label_values(&labels)
                    .get()
                    > failure_before,
                "backend: {backend}, protocol: {protocol:?}"
            );
        }
    }

    #[test]
    fn fs_ops_are_counted_by_op_and_reads_are_timed() {
        let cost = Duration::from_millis(2);
        let test_cases = vec![
            (FsOp::Read, false, (1, 0, 1)),
            (FsOp::Read, true, (0, 1, 1)),
            (FsOp::Lookup, false, (1, 0, 0)),
            (FsOp::Getattr, true, (0, 1, 0)),
        ];

        for (op, failed, expected) in test_cases {
            let label = op.to_string();
            let histogram = FS_READ_DURATION.with_label_values(&[]);
            let count_before = FS_OP_COUNT.with_label_values(&[&label]).get();
            let failure_before = FS_OP_FAILURE_COUNT.with_label_values(&[&label]).get();
            let duration_count_before = histogram.get_sample_count();
            let duration_sum_before = histogram.get_sample_sum();

            if failed {
                collect_fs_op_failure_metrics(op, cost);
            } else {
                collect_fs_op_finished_metrics(op, cost);
            }

            let deltas = (
                FS_OP_COUNT.with_label_values(&[&label]).get() - count_before,
                FS_OP_FAILURE_COUNT.with_label_values(&[&label]).get() - failure_before,
                histogram.get_sample_count() - duration_count_before,
            );
            assert_eq!(deltas, expected, "op: {op}, failed: {failed}");
            assert_eq!(
                histogram.get_sample_sum() - duration_sum_before,
                expected.2 as f64 * cost.as_millis() as f64,
                "op: {op}, failed: {failed}"
            );
        }
    }

    #[test]
    fn read_block_groups_are_counted_by_type_storage_backend_and_protocol() {
        let test_cases = vec![
            (ReadKind::OnDemand, Storage::Local, Backend::Local, None),
            (ReadKind::OnDemand, Storage::Backend, Backend::Local, None),
            (
                ReadKind::Prefetch,
                Storage::Backend,
                Backend::Registry,
                Some(Protocol::Http),
            ),
            (
                ReadKind::Prefetch,
                Storage::Local,
                Backend::Registry,
                Some(Protocol::DragonflySdk),
            ),
        ];

        for (kind, storage, backend, protocol) in test_cases {
            let kind_label = kind.to_string();
            let storage_label = storage.to_string();
            let backend_label = backend.to_string();
            let protocol_label = protocol_label(protocol);
            let labels = [
                kind_label.as_str(),
                storage_label.as_str(),
                backend_label.as_str(),
                protocol_label.as_str(),
            ];
            let before = READ_BLOCK_GROUP_COUNT.with_label_values(&labels).get();

            collect_read_block_group_metrics(kind, storage, backend, protocol);

            assert!(
                READ_BLOCK_GROUP_COUNT.with_label_values(&labels).get() > before,
                "kind: {kind}, storage: {storage}, backend: {backend}, protocol: {protocol:?}"
            );
        }
    }

    #[test]
    fn prefetch_redirect_blobs_count_traffic() {
        let test_cases = vec![0, 4096];

        for length in test_cases {
            let count_before = PREFETCH_REDIRECT_BLOB_COUNT.with_label_values(&[]).get();
            let traffic_before = PREFETCH_REDIRECT_BLOB_TRAFFIC.with_label_values(&[]).get();

            collect_prefetch_redirect_blob_metrics(length);

            assert_eq!(
                PREFETCH_REDIRECT_BLOB_COUNT.with_label_values(&[]).get(),
                count_before + 1,
                "length: {length}"
            );
            assert_eq!(
                PREFETCH_REDIRECT_BLOB_TRAFFIC.with_label_values(&[]).get(),
                traffic_before + length,
                "length: {length}"
            );
        }
    }

    #[test]
    fn unlabeled_counters_move_by_one() {
        let test_cases: Vec<(Collect, Read)> = vec![
            (
                collect_fill_block_group_from_redirect_blob_finished_metrics,
                || {
                    FILL_BLOCK_GROUP_FROM_REDIRECT_BLOB_COUNT
                        .with_label_values(&[])
                        .get()
                },
            ),
            (
                collect_fill_block_group_from_redirect_blob_failure_metrics,
                || {
                    FILL_BLOCK_GROUP_FROM_REDIRECT_BLOB_FAILURE_COUNT
                        .with_label_values(&[])
                        .get()
                },
            ),
            (collect_prefetch_task_started_metrics, || {
                PREFETCH_TASK_COUNT.with_label_values(&[]).get()
            }),
            (collect_prefetch_task_failure_metrics, || {
                PREFETCH_TASK_FAILURE_COUNT.with_label_values(&[]).get()
            }),
            (collect_prefetch_task_reschedule_metrics, || {
                PREFETCH_TASK_RESCHEDULE_COUNT.with_label_values(&[]).get()
            }),
        ];

        for (index, (collect, read)) in test_cases.into_iter().enumerate() {
            let before = read();
            collect();
            assert!(read() > before, "index: {index}");
        }
    }

    #[test]
    fn registry_encodes_registered_metrics() {
        collect_read_backend_finished_metrics(
            ReadKind::Prefetch,
            Backend::Local,
            None,
            3,
            Duration::from_millis(500),
        );
        collect_validate_block_group_started_metrics(Backend::Local, None);
        collect_fs_op_finished_metrics(FsOp::Statfs, Duration::from_millis(1));
        let text = prometheus::TextEncoder::new()
            .encode_to_string(&REGISTRY.gather())
            .unwrap();

        let test_cases = vec![
            r#"nydus_read_backend_total{backend="local",protocol="",type="prefetch"}"#,
            r#"nydus_read_backend_traffic{backend="local",protocol="",type="prefetch"}"#,
            r#"nydus_read_backend_duration_milliseconds_bucket{"#,
            r#"nydus_validate_block_group_total{backend="local",protocol=""}"#,
            r#"nydus_fs_op_total{op="statfs"}"#,
        ];

        for name in test_cases {
            assert!(text.contains(name), "name: {name}");
        }
    }
}
