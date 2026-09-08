//! Telemetry for nydus, following the observability pillars:
//!
//! - [`metrics`]: the process-wide Prometheus registry and every metric the
//!   daemon exports;
//! - [`logging`] (feature `logging`): `tracing`-subscriber installation
//!   (stdout + rolling files + panic hook). Only binaries enable this —
//!   libraries emit through the `tracing` facade and never install
//!   subscribers.
//!
//! This crate depends on no nydus crate but [`nydus_config`], for the metric
//! namespace, so every layer (data plane and control plane alike) can record
//! metrics. Label vocabularies ([`metrics::Backend`], [`metrics::FsOp`])
//! are owned here; [`metrics::ReadKind`] is defined here for the same reason
//! and re-exported by the storage backend as its read-policy type.

#[cfg(feature = "logging")]
pub mod logging;
pub mod metrics;
