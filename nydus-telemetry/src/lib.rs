//! Telemetry for nydus, following the observability pillars:
//!
//! - [`metrics`]: the Prometheus metrics of an image, one instance per
//!   opened image;
//! - [`logging`] (feature `logging`): `tracing`-subscriber installation
//!   (stdout + rolling files + panic hook). Only binaries enable this —
//!   libraries emit through the `tracing` facade and never install
//!   subscribers.
//!
//! This crate depends on no nydus crate but [`nydus_config`], so every layer
//! (data plane and control plane alike) can record metrics. The enum that
//! describes the configuration ([`nydus_config::ReadKind`]) is defined there
//! and re-exported from [`metrics`], which maps it to a label value; the
//! enums that only exist for metrics ([`metrics::Source`],
//! [`metrics::WriteKind`], [`metrics::WriteFailureReason`], [`metrics::FsOp`]) are
//! owned here. The [`prometheus`] crate is re-exported, so the crates that
//! register a collector of their own or encode a registry reach it through
//! this one.

#[cfg(feature = "logging")]
pub mod logging;
pub mod metrics;

pub use prometheus;
