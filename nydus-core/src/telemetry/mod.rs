//! Telemetry for nydus, following the three observability pillars:
//!
//! - [`logging`]: `tracing`-subscriber installation (stdout + rolling files
//!   + panic hook) for daemons and CLI commands;
//! - [`metrics`]: the process-wide Prometheus registry and every metric the
//!   daemon exports;
//! - [`access_trace`]: group-level on-demand access tracing, consumed by
//!   `nydus optimize` to reorder prefetch.

pub mod access_trace;
pub mod logging;
pub mod metrics;
