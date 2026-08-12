//! Runtime core APIs for EROFS-based Nydus images.
//!
//! This crate provides the host-side building blocks used to serve Nydus
//! images at runtime: EROFS metadata parsing ([`metadata`]), an on-demand
//! blob cache and storage backends ([`storage`]), an image reader ([`fs`]),
//! an image builder ([`build`]), and the high-level [`NydusCore`] entry
//! point ([`core`]).
//!
//! Optional cargo features:
//! - `backend-registry`: container image registry backend (OCI distribution).
//! - `backend-dragonfly-proxy`: Dragonfly P2P SDK proxy for the registry
//!   backend.

pub mod build;
pub mod config;
pub mod core;
pub mod fs;
pub mod metadata;
pub mod metrics;
pub mod storage;
pub mod utils;

pub use config::{Config, DEFAULT_PREFETCH_THREADS};
pub use core::{
    BlobId, BlobInfo, Blobs, DirEntry, FdRange, FileType, Fs, FsEntry, Metadata, NydusCore,
    ResolveMode,
};
pub use fs::prefetch::BlobPrefetcher;
pub use metadata::{
    is_rafs_v7_bootstrap, BlobMeta, BlobMetaChunk, BlobMetaGroup, BlobMetaHeader,
    BLOB_META_HEADER_SIZE, BLOB_META_MAGIC, EROFS_FEATURE_COMPAT_RAFS_V6,
};
pub use metrics::trace::{TraceDocument, TraceEntry, TraceRecorder, TRACE_DOCUMENT_VERSION};
pub use metrics::MetricsSnapshot;
#[cfg(feature = "backend-registry")]
pub use storage::backend::Registry;
pub use storage::backend::{build_backend, BlobBackend, LocalBackend, ReadKind};
pub use storage::group_map::GroupMap;
