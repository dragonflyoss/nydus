//! Data-plane blob backends for nydus: local directory and OCI registry, with
//! optional Dragonfly P2P reads.
//!
//! Every API here returns `io::Result` so the OS errno survives to the
//! service edges, and this crate never depends on the control-plane error
//! type. Backend-private errors, registry auth and Dragonfly classification,
//! are matched internally and fold into `io::Error` at the trait boundary. A
//! prefetch read Dragonfly could not serve, a `429`, `5xx`, `408` or a
//! transport failure, folds into [`io::ErrorKind::QuotaExceeded`] so the
//! storage layer reschedules it hours later without a cross-crate error type.

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

/// The registry backend's shared tokio runtime is process-wide; an embedding
/// process bounds its threads and pins their network namespace with
/// [`configure_runtime`] before constructing any registry backend.
#[cfg(feature = "backend-registry")]
pub use registry::{configure_runtime, Netns, NetnsId, RuntimeOptions};

pub use nydus_config::{Backend, Protocol, ReadKind};

/// A raw EROFS device backed by the range
/// `[data_offset, data_offset + data_size)` of a local file.
pub struct RawDeviceFile {
    pub path: PathBuf,
    pub file: Arc<File>,
    pub data_offset: u64,
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
    /// Which backend this is, the `backend` label of its metrics.
    fn backend(&self) -> Backend;

    /// How this backend fetches bytes when nothing else is known, the
    /// `protocol` label of the metrics recorded outside a read. `None` for a
    /// backend without a protocol.
    fn protocol(&self) -> Option<Protocol>;

    /// The digest naming the blob's cache files, the blob digest itself unless
    /// the backend stores the blob under another name.
    fn cache_key(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<[u8; SHA256_DIGEST_SIZE]> {
        Ok(*blob_id)
    }

    /// The blob's metadata, `kind` attributing the reads that recover it.
    fn blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        kind: ReadKind,
    ) -> io::Result<BlobMetadata>;

    /// Whether the blob is a raw EROFS device without blob meta (a native
    /// `erofs-*` layer): its bytes are read as-is and never cached or
    /// decoded by nydus. Backends that cannot serve such blobs report an
    /// error instead of `Ok(true)`.
    fn is_raw_device(&self, _blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<bool> {
        Ok(false)
    }

    /// The local file backing a raw device, `None` for a streamed or chunked
    /// blob. File resolution and open errors are propagated.
    fn raw_device_file(
        &self,
        _blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<Option<RawDeviceFile>> {
        Ok(None)
    }

    /// Write the blob's metadata to `dst`, `kind` attributing the reads that
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

    /// Fill `dst` with the blob bytes from `offset`, `kind` attributing the
    /// read.
    fn read_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        dst: &mut [u8],
        kind: ReadKind,
    ) -> io::Result<()>;
}

/// Construct a blob backend from its configuration.
pub fn build_backend(config: &BackendConfig) -> io::Result<Arc<dyn BlobBackend>> {
    let backend: Arc<dyn BlobBackend> = match config {
        BackendConfig::Local(local) => Arc::new(Local::new(local.dir.clone())),
        #[cfg(feature = "backend-registry")]
        BackendConfig::Registry(registry) => Arc::new(Registry::new(registry.clone())?),
        #[cfg(not(feature = "backend-registry"))]
        BackendConfig::Registry(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "registry backend requires the `backend-registry` feature",
            ))
        }
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
