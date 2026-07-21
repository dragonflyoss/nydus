// Re-export the accessor runtime modules so that in-crate paths like
// `crate::metadata` keep resolving for `build`, `merge`, `uffd` and the
// `nydus` binary after the split into the `nydus-accessor` crate.
pub use nydus_accessor::{accessor, config, fs, metadata, metrics, storage, utils};

pub mod build;
#[cfg(feature = "fanotify")]
pub mod fanotify;
#[cfg(feature = "fuse")]
pub mod fuse;
pub mod merge;
#[cfg(feature = "cli")]
pub mod tracing;
#[cfg(feature = "uffd")]
pub mod uffd;

#[cfg(feature = "fuse")]
pub use fuse::ErofsFs;

#[cfg(feature = "backend-registry")]
pub use nydus_accessor::Registry;
pub use nydus_accessor::{
    build_backend, BlobAccessor, BlobBackend, BlobID, BlobInfo, BlobMeta, BlobMetaChunk,
    BlobMetaGroup, BlobMetaHeader, BlobPrefetcher, Config, DirEntry, FdRange, FileType, FsAccessor,
    FsEntry, GroupMap, LocalBackend, Metadata, MetricsSnapshot, NydusAccessor, RequestSource,
    TraceDocument, TracePattern, TraceRecorder, BLOB_META_HEADER_SIZE, BLOB_META_MAGIC,
    DEFAULT_PREFETCH_THREADS,
};
