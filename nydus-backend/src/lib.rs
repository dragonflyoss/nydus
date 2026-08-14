//! Data-plane blob backends for nydus: local directory and OCI registry, with
//! optional Dragonfly SDK P2P reads.
//!
//! Every API here returns `io::Result` so the OS errno survives to the
//! service edges; this crate must not depend on the control-plane error
//! type. Backend-private errors (registry auth, Dragonfly classification) are
//! matched for retry decisions internally and fold into `io::Error` at the
//! trait boundary.

mod local;

#[cfg(feature = "backend-registry")]
mod registry;

use std::io;
use std::path::Path;
use std::sync::Arc;

use nydus_config::BackendConfig;
use nydus_format::blob::BlobMetadata;
use nydus_format::utils::SHA256_DIGEST_SIZE;

pub use local::Local;

#[cfg(feature = "backend-registry")]
pub(crate) use registry::Registry;

/// What kind of backend read this is, shared with the metrics layer. Policy
/// (retry, throttling, Dragonfly priority) keys off it here; its definition
/// lives in [`nydus_telemetry::metrics`] so that crate stays a dependency
/// leaf.
pub use nydus_telemetry::metrics::ReadKind;

/// The uncompressed span a backend read decodes to, when it maps to
/// blob-metadata groups.
#[derive(Debug, Clone, Copy)]
pub struct UncompressedSpan {
    pub offset: u64,
    pub size: u64,
}

/// Diagnostic context for a backend read: its kind plus the uncompressed
/// span it decodes to, when the read maps to blob-meta groups. Raw reads
/// (e.g. the blob footer or blob meta region) carry `None`.
#[derive(Debug, Clone, Copy)]
pub struct ReadContext {
    pub kind: ReadKind,
    pub uncompressed: Option<UncompressedSpan>,
}

impl ReadContext {
    /// Context for a read that decodes to a known uncompressed group span.
    pub fn group(kind: ReadKind, uncompressed_offset: u64, uncompressed_size: u64) -> Self {
        Self {
            kind,
            uncompressed: Some(UncompressedSpan {
                offset: uncompressed_offset,
                size: uncompressed_size,
            }),
        }
    }

    /// Context for a raw read with no associated uncompressed group span.
    pub fn raw(kind: ReadKind) -> Self {
        Self {
            kind,
            uncompressed: None,
        }
    }
}

/// A blob backend resolves blob data and metadata by content digest.
pub trait BlobBackend: Send + Sync {
    /// Which side serves this backend's reads, used to attribute read and CRC
    /// metrics. Defaults to the origin; proxied backends override it.
    fn backend_target(&self) -> nydus_telemetry::metrics::BackendTarget {
        nydus_telemetry::metrics::BackendTarget::Origin
    }

    fn cache_key(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<[u8; SHA256_DIGEST_SIZE]> {
        Ok(*blob_id)
    }

    fn blob_metadata(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<BlobMetadata>;

    fn save_blob_metadata(&self, blob_id: &[u8; SHA256_DIGEST_SIZE], dst: &Path) -> io::Result<()> {
        let blob_metadata = self.blob_metadata(blob_id)?;
        blob_metadata.save(dst).map_err(io::Error::other)
    }

    fn read_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        dst: &mut [u8],
        context: ReadContext,
    ) -> io::Result<()>;
}

/// Wrap `backend` so every read it serves reports to [`nydus_telemetry::metrics`].
///
/// Metering lives here rather than in each backend so all of them report the
/// same counters; an individual backend must not report reads on its own or
/// they would be counted twice. Apply this exactly once, where the backend is
/// constructed.
pub fn metered(backend: Arc<dyn BlobBackend>) -> Arc<dyn BlobBackend> {
    Arc::new(MeteredBackend { inner: backend })
}

struct MeteredBackend {
    inner: Arc<dyn BlobBackend>,
}

impl MeteredBackend {
    fn record<T>(
        &self,
        context: ReadContext,
        bytes: u64,
        read: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        let start = std::time::Instant::now();
        let result = read();
        nydus_telemetry::metrics::record_backend_read(
            self.inner.backend_target(),
            context.kind,
            bytes,
            start.elapsed(),
            result.is_err(),
        );
        result
    }
}

impl BlobBackend for MeteredBackend {
    fn backend_target(&self) -> nydus_telemetry::metrics::BackendTarget {
        self.inner.backend_target()
    }

    fn cache_key(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<[u8; SHA256_DIGEST_SIZE]> {
        self.inner.cache_key(blob_id)
    }

    fn blob_metadata(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<BlobMetadata> {
        self.inner.blob_metadata(blob_id)
    }

    fn save_blob_metadata(&self, blob_id: &[u8; SHA256_DIGEST_SIZE], dst: &Path) -> io::Result<()> {
        self.inner.save_blob_metadata(blob_id, dst)
    }

    fn read_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        dst: &mut [u8],
        context: ReadContext,
    ) -> io::Result<()> {
        if dst.is_empty() {
            return Ok(());
        }
        let bytes = dst.len() as u64;
        self.record(context, bytes, || {
            self.inner.read_range_into(blob_id, offset, dst, context)
        })
    }
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
    Ok(metered(backend))
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
        let err = build_backend(&config)
            .err()
            .expect("registry config must be rejected without the feature");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("backend-registry"));
    }
}
