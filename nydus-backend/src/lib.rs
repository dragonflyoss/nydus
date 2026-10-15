//! Data-plane blob backends for nydus: local directory and OCI registry, with
//! optional Dragonfly P2P reads.
//!
//! Every API here returns `io::Result` so the OS errno survives to the
//! service edges, and this crate never depends on the control-plane error
//! type. Registry auth and Dragonfly failures are `io::Error`s too, carrying
//! their message; the one kind the storage layer acts on is
//! [`io::ErrorKind::QuotaExceeded`], a prefetch read Dragonfly could not
//! serve, a `429`, `5xx`, `408` or a transport failure, which the storage
//! layer reschedules hours later instead of retrying now.

mod local;

#[cfg(feature = "backend-registry")]
mod registry;

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nydus_config::BackendConfig;
use nydus_format::blob::BlobMetadata;
use nydus_format::utils::SHA256_DIGEST_SIZE;

pub use local::Local;

#[cfg(feature = "backend-registry")]
pub(crate) use registry::Registry;

/// A registry backend runs on a [`Runtime`], one tokio runtime per read kind,
/// built from its `http` configuration; an embedding process builds one
/// itself, with the thread bounds and network namespace it needs, and shares
/// it across its backends through [`build_backend_with_runtime`].
#[cfg(feature = "backend-registry")]
pub use registry::{Netns, NetnsId, Runtime};

pub use nydus_config::{Backend, Protocol, ReadKind};

/// A raw EROFS device backed by the range
/// `[data_offset, data_offset + data_size)` of a local file.
pub struct RawDeviceFile {
    /// The path of the local file.
    pub path: PathBuf,

    /// The open file.
    pub file: Arc<File>,

    /// The offset of the device data in the file.
    pub data_offset: u64,

    /// The size of the device data.
    pub data_size: u64,
}

/// A blob backend resolves blob data and metadata by content digest.
///
/// ```text
///           BlobBackend
///        ┌───────┴───────┐
///      Local         Registry
///    directory     origin, P2P
/// ```
///
/// Every implementation reports its reads to [`nydus_telemetry::metrics`]
/// itself, once per [`read_range_into`](Self::read_range_into) call.
pub trait BlobBackend: Send + Sync {
    /// Returns which backend this is, the `backend` label of its metrics.
    fn backend(&self) -> Backend;

    /// Returns how this backend fetches bytes when nothing else is known, the
    /// `protocol` label of the metrics recorded outside a read, `None` for a
    /// backend without a protocol.
    fn protocol(&self) -> Option<Protocol>;

    /// Returns the digest naming the blob's cache files, the blob digest itself
    /// unless the backend stores the blob under another name.
    fn cache_key(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<[u8; SHA256_DIGEST_SIZE]> {
        Ok(*blob_id)
    }

    /// Returns the blob's metadata, `kind` attributing the reads that recover it.
    fn blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        kind: ReadKind,
    ) -> io::Result<BlobMetadata>;

    /// Returns whether the blob is a raw EROFS device without blob meta, a
    /// native `erofs-*` layer whose bytes are read as-is and never cached or
    /// decoded by nydus.
    ///
    /// Backends that cannot serve such blobs report an error instead of
    /// `Ok(true)`.
    fn is_raw_device(&self, _blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<bool> {
        Ok(false)
    }

    /// Returns the local file backing a raw device, `None` for a streamed or
    /// chunked blob.
    ///
    /// File resolution and open errors are propagated.
    fn raw_device_file(
        &self,
        _blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<Option<RawDeviceFile>> {
        Ok(None)
    }

    /// Writes the blob's metadata to `dst`, `kind` attributing the reads that
    /// recover it.
    fn save_blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        kind: ReadKind,
        dst: &Path,
    ) -> io::Result<()> {
        let blob_metadata = self.blob_metadata(blob_id, kind)?;
        blob_metadata.save(dst).map_err(io::Error::other)
    }

    /// Fills `dst` with the blob bytes from `offset`, `kind` attributing the
    /// read.
    fn read_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        dst: &mut [u8],
        kind: ReadKind,
    ) -> io::Result<()>;
}

/// Creates a blob backend from its configuration.
///
/// A registry backend runs on runtimes of its own, one per read kind, built
/// from the `http` section.
pub fn build_backend(config: &BackendConfig) -> io::Result<Arc<dyn BlobBackend>> {
    match config {
        BackendConfig::Local(local) => Ok(Arc::new(Local::new(local.dir.clone()))),
        #[cfg(feature = "backend-registry")]
        BackendConfig::Registry(registry) => {
            let runtime = Runtime::new(
                registry.http.worker_threads,
                registry.http.max_blocking_threads,
                None,
            )?;
            build_backend_with_runtime(config, Arc::new(runtime))
        }
        #[cfg(not(feature = "backend-registry"))]
        BackendConfig::Registry(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "registry backend requires the `backend-registry` feature",
        )),
    }
}

/// Creates a blob backend from its configuration, a registry backend on
/// `runtime` rather than on runtimes of its own.
///
/// An embedder builds the runtimes with the namespace its registries must be
/// reached from and hands them to every backend it opens.
#[cfg(feature = "backend-registry")]
pub fn build_backend_with_runtime(
    config: &BackendConfig,
    runtime: Arc<Runtime>,
) -> io::Result<Arc<dyn BlobBackend>> {
    let backend: Arc<dyn BlobBackend> = match config {
        BackendConfig::Local(local) => Arc::new(Local::new(local.dir.clone())),
        BackendConfig::Registry(registry) => Arc::new(Registry::new(registry.clone(), runtime)?),
    };
    Ok(backend)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_backend_builds_a_local_backend() {
        let config: BackendConfig =
            serde_yaml::from_str("type: local\nconfig:\n  dir: /blobs\n").unwrap();
        assert!(build_backend(&config).is_ok());
    }

    #[cfg(feature = "backend-registry")]
    #[test]
    fn build_backend_builds_a_registry_backend() {
        let config: BackendConfig = serde_yaml::from_str(
            "type: registry\nconfig:\n  addr: http://127.0.0.1:5000\n  repository: a/b\n",
        )
        .unwrap();
        assert!(build_backend(&config).is_ok());
    }

    #[cfg(not(feature = "backend-registry"))]
    #[test]
    fn build_backend_rejects_registry_without_the_feature() {
        let config: BackendConfig = serde_yaml::from_str(
            "type: registry\nconfig:\n  addr: http://127.0.0.1:5000\n  repository: a/b\n",
        )
        .unwrap();
        let err = build_backend(&config).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("backend-registry"));
    }
}
