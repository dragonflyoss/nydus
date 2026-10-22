//! Local data plane for nydus images: sparse blob caches, chunk group-level
//! fill tracking, background prefetch and on-demand access tracing.
//!
//! Every API here returns `io::Result` so the OS errno survives to the
//! service edges; this crate never depends on the control-plane error type.
//! The on-disk formats and their codec come from [`nydus_format`], remote
//! reads through [`nydus_backend`], the `storage` and `prefetch` sections
//! the caches and the prefetcher follow from [`nydus_config`]; the assembly
//! that wires configs, bootstraps and caches together lives above, in
//! `nydus-core`.

pub mod access_trace;
pub mod cache;
pub mod prefetch;
