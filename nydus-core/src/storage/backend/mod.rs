mod local;

// Shared HTTP transport stack, reusable by any HTTP-based backend.
#[cfg(feature = "backend-registry")]
mod dns;
#[cfg(feature = "backend-dragonfly-proxy")]
mod dragonfly_sdk;
#[cfg(feature = "backend-registry")]
mod http;
#[cfg(feature = "backend-registry")]
mod proxy;
#[cfg(feature = "backend-registry")]
mod request;

#[cfg(feature = "backend-registry")]
mod registry;

use std::io;
use std::path::Path;
use std::sync::Arc;

use crate::blob::BlobMeta;
use crate::config::BackendConfig;
use crate::utils::SHA256_DIGEST_SIZE;

pub use local::LocalBackend;

#[cfg(feature = "backend-registry")]
pub(crate) use registry::Registry;

/// What kind of backend read this is — a user-triggered on-demand read or a
/// background prefetch — used to apply different retry, throttling and
/// proxy-priority policies to user-triggered versus background reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReadKind {
    /// User-triggered read that blocks a FUSE request.
    #[default]
    OnDemand,
    /// Background prefetch read after mount.
    Prefetch,
}

/// Diagnostic context for a backend read: its kind plus the uncompressed
/// `(offset, size)` span it decodes to, when the read maps to blob-meta groups.
/// Raw reads (e.g. the blob footer or blob meta region) carry `None`.
#[derive(Debug, Clone, Copy)]
pub struct ReadContext {
    pub kind: ReadKind,
    pub uncompressed: Option<(u64, u64)>,
}

impl ReadContext {
    /// Context for a read that decodes to a known uncompressed group span.
    pub fn group(kind: ReadKind, uncompressed_offset: u64, uncompressed_size: u64) -> Self {
        Self {
            kind,
            uncompressed: Some((uncompressed_offset, uncompressed_size)),
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
    fn backend_target(&self) -> crate::telemetry::metrics::BackendTarget {
        crate::telemetry::metrics::BackendTarget::Origin
    }

    fn cache_key(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<[u8; SHA256_DIGEST_SIZE]> {
        Ok(*blob_id)
    }

    fn blob_meta(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<BlobMeta>;

    fn blob_meta_to(&self, blob_id: &[u8; SHA256_DIGEST_SIZE], dst: &Path) -> io::Result<()> {
        let blob_meta = self.blob_meta(blob_id)?;
        blob_meta.save(dst).map_err(io::Error::other)
    }

    fn read_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        dst: &mut [u8],
        ctx: ReadContext,
    ) -> io::Result<()>;
}

/// Wrap `backend` so every read it serves reports to [`crate::telemetry::metrics`].
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
        ctx: ReadContext,
        bytes: u64,
        read: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        let start = std::time::Instant::now();
        let result = read();
        crate::telemetry::metrics::record_backend_read(
            self.inner.backend_target(),
            ctx.kind,
            bytes,
            start.elapsed(),
            result.is_err(),
        );
        result
    }
}

impl BlobBackend for MeteredBackend {
    fn backend_target(&self) -> crate::telemetry::metrics::BackendTarget {
        self.inner.backend_target()
    }

    fn cache_key(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<[u8; SHA256_DIGEST_SIZE]> {
        self.inner.cache_key(blob_id)
    }

    fn blob_meta(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<BlobMeta> {
        self.inner.blob_meta(blob_id)
    }

    fn blob_meta_to(&self, blob_id: &[u8; SHA256_DIGEST_SIZE], dst: &Path) -> io::Result<()> {
        self.inner.blob_meta_to(blob_id, dst)
    }

    fn read_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        dst: &mut [u8],
        ctx: ReadContext,
    ) -> io::Result<()> {
        if dst.is_empty() {
            return Ok(());
        }
        let bytes = dst.len() as u64;
        self.record(ctx, bytes, || {
            self.inner.read_range_into(blob_id, offset, dst, ctx)
        })
    }
}

/// Construct a blob backend from its configuration.
pub fn build_backend(config: &BackendConfig) -> io::Result<Arc<dyn BlobBackend>> {
    let backend: Arc<dyn BlobBackend> = match config.kind.as_str() {
        "local" => Arc::new(LocalBackend::from_value(&config.config)?),
        #[cfg(feature = "backend-registry")]
        "registry" => Arc::new(Registry::from_value(&config.config)?),
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported backend type: {other}"),
            ))
        }
    };
    Ok(metered(backend))
}
