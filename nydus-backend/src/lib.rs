//! Data-plane blob backends for nydus: local directory and OCI registry, with
//! optional Dragonfly P2P reads.
//!
//! Every API here returns `io::Result` so the OS errno survives to the
//! service edges, and this crate never depends on the control-plane error
//! type. Registry auth and Dragonfly failures are `io::Error`s too, carrying
//! their message. A prefetch read the origin or Dragonfly answered with a
//! `429`, `5xx` or `408` is sent once more after a random delay of hours
//! before it fails.

mod local;

#[cfg(feature = "registry")]
mod registry;

use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use nydus_config::BackendConfig;
use nydus_format::blob::BlobMetadata;
use nydus_format::utils::SHA256_DIGEST_SIZE;

pub use local::Local;

#[cfg(feature = "registry")]
pub(crate) use registry::Registry;

/// A registry backend runs on a [`Runtime`], one tokio runtime per read kind,
/// built from its `http` configuration; an embedding process builds one
/// itself, with the thread bounds and network namespace it needs, and shares
/// it across its backends through [`build_backend_with_runtime`].
#[cfg(feature = "registry")]
pub use registry::{Netns, NetnsId, Runtime};

pub use nydus_config::{BackendKind, Protocol, ReadKind};

/// A raw EROFS device backed by the range
/// `[data_offset, data_offset + data_size)` of a local file.
#[derive(Debug, Clone)]
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
///           Backend
///        ┌───────┴───────┐
///      Local         Registry
///    directory     origin, P2P
/// ```
///
/// Every implementation reports its reads to [`nydus_telemetry::metrics`]
/// itself, once per range read. A backend that serves an on-demand and a
/// prefetch read alike keeps the `prefetch_*` defaults, which forward to the
/// on-demand methods.
pub trait Backend: Send + Sync {
    /// Returns which backend this is, the `backend` label of its metrics.
    fn kind(&self) -> BackendKind;

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

    /// Reads the blob's metadata for an on-demand read.
    fn read_blob_metadata(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<BlobMetadata>;

    /// Reads the blob's metadata for a prefetch read.
    fn prefetch_blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<BlobMetadata> {
        self.read_blob_metadata(blob_id)
    }

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

    /// Fills `buf` with the blob bytes from `offset` for an on-demand read.
    fn read_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        buf: &mut [u8],
    ) -> io::Result<()>;

    /// Fills `buf` with the blob bytes from `offset` for a prefetch read.
    fn prefetch_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        buf: &mut [u8],
    ) -> io::Result<()> {
        self.read_range_into(blob_id, offset, buf)
    }
}

/// Creates a blob backend from its configuration.
///
/// A registry backend runs on runtimes of its own, one per read kind, built
/// from the `http` section.
pub fn build_backend(config: &BackendConfig) -> io::Result<Arc<dyn Backend>> {
    match config {
        BackendConfig::Local(local) => Ok(Arc::new(Local::new(local.dir.clone()))),
        #[cfg(feature = "registry")]
        BackendConfig::Registry(registry) => {
            let runtime = Runtime::new(
                registry.http.worker_threads,
                registry.http.max_blocking_threads,
                None,
            )?;
            build_backend_with_runtime(config, Arc::new(runtime))
        }
        #[cfg(not(feature = "registry"))]
        BackendConfig::Registry(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "registry backend requires the `registry` feature",
        )),
    }
}

/// Creates a blob backend from its configuration, a registry backend on
/// `runtime` rather than on runtimes of its own.
///
/// An embedder builds the runtimes with the namespace its registries must be
/// reached from and hands them to every backend it opens.
#[cfg(feature = "registry")]
pub fn build_backend_with_runtime(
    config: &BackendConfig,
    runtime: Arc<Runtime>,
) -> io::Result<Arc<dyn Backend>> {
    let backend: Arc<dyn Backend> = match config {
        BackendConfig::Local(local) => Arc::new(Local::new(local.dir.clone())),
        BackendConfig::Registry(registry) => {
            Arc::new(Registry::new((**registry).clone(), runtime)?)
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

    #[cfg(feature = "registry")]
    #[test]
    fn build_backend_builds_a_registry_backend() {
        let config: BackendConfig = serde_yaml::from_str(
            "type: registry\nconfig:\n  addr: http://127.0.0.1:5000\n  repository: a/b\n",
        )
        .unwrap();
        assert!(build_backend(&config).is_ok());
    }

    #[cfg(not(feature = "registry"))]
    #[test]
    fn build_backend_rejects_registry_without_the_feature() {
        let config: BackendConfig = serde_yaml::from_str(
            "type: registry\nconfig:\n  addr: http://127.0.0.1:5000\n  repository: a/b\n",
        )
        .unwrap();
        let err = build_backend(&config).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("registry"));
    }
}
