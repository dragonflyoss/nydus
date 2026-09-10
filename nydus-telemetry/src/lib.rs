//! Telemetry for nydus, following the observability pillars:
//!
//! - [`metrics`]: the process-wide Prometheus registry and every metric the
//!   daemon exports;
//! - [`logging`] (feature `logging`): `tracing`-subscriber installation
//!   (stdout + rolling files + panic hook). Only binaries enable this —
//!   libraries emit through the `tracing` facade and never install
//!   subscribers.
//!
//! This crate depends on no nydus crate but [`nydus_config`], so every layer
//! (data plane and control plane alike) can record metrics. The enums that
//! describe the configuration ([`nydus_config::Backend`],
//! [`nydus_config::Protocol`], [`nydus_config::ReadKind`]) are defined there
//! and re-exported from [`metrics`], which maps them to label values; the
//! enums that only exist for metrics ([`metrics::Storage`], [`metrics::FsOp`])
//! are owned here.

#[cfg(feature = "logging")]
pub mod logging;
pub mod metrics;
