pub mod accessor;
pub mod build;
pub mod config;
pub mod fs;
pub mod merge;
pub mod metadata;
pub mod metrics;
pub mod storage;
#[cfg(feature = "cli")]
pub mod tracing;
#[cfg(feature = "uffd")]
pub mod uffd;
pub mod utils;

pub use accessor::{
    BlobAccessor, BlobID, BlobInfo, DirEntry, FileType, FsAccessor, FsEntry, LeptonAccessor,
    Metadata,
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
