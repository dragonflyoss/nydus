//! Local data plane for nydus images: sparse blob caches, chunk group-level fill
//! tracking, background prefetch and on-demand access tracing.
//!
//! Every API here returns `io::Result` so the OS errno survives to the
//! service edges; this crate must not depend on the control-plane error
//! type. Remote reads come through the [`nydus_backend`] crate; the
//! assembly that wires configs, bootstraps and caches together lives above,
//! in `nydus-core`.

pub mod cache;
pub mod chunk_group_map;
pub mod io;
pub mod ondemand;
pub mod prefetch;
