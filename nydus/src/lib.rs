// Re-export the core runtime modules so that in-crate paths like
// `crate::metadata` keep resolving for `build`, `merge`, `uffd` and the
// `nydus` binary after the split into the `nydus-core` crate.
pub use nydus_core::{config, core, fs, metadata, metrics, storage, utils};

pub mod build;
#[cfg(feature = "fanotify")]
pub mod fanotify;
#[cfg(feature = "fuse")]
pub mod fuse;
#[cfg(feature = "fuse")]
pub mod idmap;
pub mod merge;
#[cfg(feature = "nbd")]
pub mod nbd;
#[cfg(feature = "cli")]
pub mod tracing;
#[cfg(feature = "ublk")]
pub mod ublk;
#[cfg(feature = "uffd")]
pub mod uffd;
pub mod unpack;

#[cfg(feature = "fuse")]
pub use fuse::ErofsFs;

#[cfg(feature = "backend-registry")]
pub use nydus_core::Registry;
pub use nydus_core::{
    build_backend, BlobBackend, BlobId, BlobInfo, BlobMeta, BlobMetaChunk, BlobMetaGroup,
    BlobMetaHeader, BlobPrefetcher, Blobs, Config, DirEntry, FdRange, FileType, Fs, FsEntry,
    GroupMap, LocalBackend, Metadata, MetricsSnapshot, NydusCore, ReadKind, TraceDocument,
    TraceEntry, TraceRecorder, BLOB_META_HEADER_SIZE, BLOB_META_MAGIC, DEFAULT_PREFETCH_THREADS,
};
