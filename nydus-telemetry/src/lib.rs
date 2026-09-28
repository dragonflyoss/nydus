//! Telemetry for nydus, following the observability pillars:
//!
//! - [`metrics`]: independent Prometheus registries for opened images, plus a
//!   process-wide compatibility registry for legacy constructors;
//! - [`logging`] (feature `logging`): `tracing`-subscriber installation
//!   (stdout + rolling files + panic hook). Only binaries enable this —
//!   libraries emit through the `tracing` facade and never install
//!   subscribers.
//!
//! This crate is a dependency leaf: it must not depend on other nydus crates,
//! so every layer (data plane and control plane alike) can record metrics.
//! Label vocabularies ([`metrics::BackendTarget`], [`metrics::FsOp`]) are
//! owned here; [`metrics::ReadKind`] is defined here for the same reason and
//! re-exported by the storage backend as its read-policy type.

#[cfg(feature = "logging")]
pub mod logging;
pub mod metrics;
