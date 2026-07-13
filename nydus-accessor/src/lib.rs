//! Runtime accessor APIs for EROFS-based Nydus images.
//!
//! This crate provides the host-side building blocks used to serve Nydus
//! images at runtime: EROFS metadata parsing ([`metadata`]), an on-demand
//! blob cache and storage backends ([`storage`]), an image reader ([`fs`]),
//! and the high-level [`NydusAccessor`] entry point ([`accessor`]).
//!
//! Optional cargo features:
//! - `backend-registry`: container image registry backend (OCI distribution).
//! - `backend-dragonfly-proxy`: Dragonfly P2P SDK proxy for the registry
//!   backend.

pub mod accessor;
pub mod config;
pub mod fs;
pub mod metadata;
pub mod metrics;
pub mod storage;
pub mod utils;

pub use accessor::{
    BlobAccessor, BlobID, BlobInfo, DirEntry, FdRange, FileType, FsAccessor, FsEntry, Metadata,
    NydusAccessor,
};
pub use config::Config;
pub use metadata::{
    BlobMeta, BlobMetaChunk, BlobMetaGroup, BlobMetaHeader, BLOB_META_HEADER_SIZE, BLOB_META_MAGIC,
};
pub use metrics::trace::{TraceDocument, TracePattern, TraceRecorder};
pub use metrics::MetricsSnapshot;
#[cfg(feature = "backend-registry")]
pub use storage::backend::Registry;
pub use storage::backend::{build_backend, BlobBackend, LocalBackend, RequestSource};
pub use storage::groupmap::GroupMap;
pub use storage::prefetch::{BlobPrefetcher, DEFAULT_PREFETCH_THREADS};
