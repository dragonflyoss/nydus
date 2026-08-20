//! Local data plane for nydus images: sparse blob caches, block group-level fill
//! tracking, background prefetch and on-demand access tracing.
//!
//! Every API here returns `io::Result` so the OS errno survives to the
//! service edges; this crate must not depend on the control-plane error
//! type. Remote reads come through the [`nydus_backend`] crate; the
//! assembly that wires configs, bootstraps and caches together lives above,
//! in `nydus-core`.

pub mod access_trace;
pub mod block_group_map;
pub mod cache;
pub mod prefetch;
