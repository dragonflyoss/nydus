//! Data-plane blob backends for nydus: local directory and OCI registry, with
//! optional Dragonfly SDK P2P reads.
//!
//! Every API here returns `io::Result` so the OS errno survives to the
//! service edges; this crate must not depend on the control-plane error
//! type. Backend-private errors (registry auth, Dragonfly classification) are
//! matched for retry decisions internally and fold into `io::Error` at the
//! trait boundary. The one deliberately typed escape hatch is the
//! backend-throttled marker ([`throttled_error`] / [`is_backend_throttled`]),
//! which lets the storage layer reschedule throttled prefetches.

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
/// blob-metadata block groups.
#[derive(Debug, Clone, Copy)]
pub struct UncompressedSpan {
    pub offset: u64,
    pub size: u64,
}

/// Diagnostic context for a backend read: its kind plus the uncompressed
/// span it decodes to, when the read maps to blob-meta block groups. Raw reads
/// (e.g. the blob footer or blob meta region) carry `None`.
#[derive(Debug, Clone, Copy)]
pub struct ReadContext {
    pub kind: ReadKind,
    pub uncompressed: Option<UncompressedSpan>,
}

impl ReadContext {
    /// Context for a read that decodes to a known uncompressed block group span.
    pub fn block_group(kind: ReadKind, uncompressed_offset: u64, uncompressed_size: u64) -> Self {
        Self {
            kind,
            uncompressed: Some(UncompressedSpan {
                offset: uncompressed_offset,
                size: uncompressed_size,
            }),
        }
    }

    /// Context for a raw read with no associated uncompressed block group span.
    pub fn raw(kind: ReadKind) -> Self {
        Self {
            kind,
            uncompressed: None,
        }
    }
}

/// Marker error wrapped in an [`io::Error`] when the backend throttled a read
/// (a prefetch rejected by a Dragonfly proxy `429` under the load-shedding
/// policy), so the storage layer can distinguish "throttled — reschedule
/// later" from an ordinary failure via [`is_backend_throttled`].
#[derive(Debug)]
struct BackendThrottled {
    message: String,
}

impl std::fmt::Display for BackendThrottled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "backend throttled the read: {}", self.message)
    }
}

impl std::error::Error for BackendThrottled {}

/// Build the [`io::Error`] denoting a backend-throttled read. Public so tests
/// in dependent crates can fabricate throttled failures.
pub fn throttled_error(message: impl Into<String>) -> io::Error {
    io::Error::other(BackendThrottled {
        message: message.into(),
    })
}

/// Whether an error denotes a read the backend throttled (Dragonfly `429`).
pub fn is_backend_throttled(err: &io::Error) -> bool {
    err.get_ref()
        .is_some_and(|inner| inner.is::<BackendThrottled>())
}

thread_local! {
    /// Set while a metered read is being served when part of it was diverted
    /// to a different target than the backend's static one — e.g. a Dragonfly
    /// read that fell back to the origin — so the read is attributed to the
    /// side that actually served it. Reads run synchronously on the calling
    /// thread and the cell is reset when the next read starts, so it always
    /// describes the most recent read; it deliberately outlives the read
    /// itself so post-read validation (decode + CRC) can attribute failures
    /// to the side that served the bytes via [`last_read_served_by`].
    static READ_SERVED_BY: std::cell::Cell<Option<nydus_telemetry::metrics::BackendTarget>> =
        const { std::cell::Cell::new(None) };
}

/// Attribute the in-flight metered read to `target` instead of the backend's
/// static [`BlobBackend::backend_target`].
#[cfg_attr(not(feature = "backend-registry"), allow(dead_code))]
pub(crate) fn note_read_served_by(target: nydus_telemetry::metrics::BackendTarget) {
    READ_SERVED_BY.with(|cell| cell.set(Some(target)));
}

/// The side that actually served the most recent metered read on this thread,
/// when it diverged from the backend's static target. Valid until the next
/// read starts on this thread.
pub fn last_read_served_by() -> Option<nydus_telemetry::metrics::BackendTarget> {
    READ_SERVED_BY.with(|cell| cell.get())
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
        READ_SERVED_BY.with(|cell| cell.set(None));
        let result = read();
        // Peek rather than take: the override must survive until the caller's
        // decode + CRC validation of these bytes (see `last_read_served_by`).
        let target = READ_SERVED_BY
            .with(|cell| cell.get())
            .unwrap_or_else(|| self.inner.backend_target());
        nydus_telemetry::metrics::record_backend_read(
            target,
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

    #[test]
    fn throttled_marker_survives_io_error_round_trip() {
        let err = throttled_error("proxy answered 429");
        assert!(is_backend_throttled(&err));
        assert!(err.to_string().contains("429"));
        assert!(!is_backend_throttled(&io::Error::other("ordinary failure")));
    }

    /// A backend that optionally diverts each read's attribution to `serve_as`.
    struct DivertingBackend {
        serve_as: Option<nydus_telemetry::metrics::BackendTarget>,
    }

    impl BlobBackend for DivertingBackend {
        fn backend_target(&self) -> nydus_telemetry::metrics::BackendTarget {
            nydus_telemetry::metrics::BackendTarget::Proxy
        }

        fn blob_metadata(&self, _blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<BlobMetadata> {
            Err(io::Error::other("unused"))
        }

        fn read_range_into(
            &self,
            _blob_id: &[u8; SHA256_DIGEST_SIZE],
            _offset: u64,
            dst: &mut [u8],
            _context: ReadContext,
        ) -> io::Result<()> {
            if let Some(target) = self.serve_as {
                note_read_served_by(target);
            }
            dst.fill(0);
            Ok(())
        }
    }

    #[test]
    fn served_by_override_survives_until_the_next_read() {
        use nydus_telemetry::metrics::BackendTarget;

        let mut dst = [0u8; 4];
        let context = ReadContext::raw(ReadKind::OnDemand);

        // A diverted read leaves its target visible after the read returns,
        // so decode + CRC validation can attribute failures to it.
        let diverted = metered(Arc::new(DivertingBackend {
            serve_as: Some(BackendTarget::Origin),
        }));
        diverted
            .read_range_into(&[0u8; SHA256_DIGEST_SIZE], 0, &mut dst, context)
            .unwrap();
        assert_eq!(last_read_served_by(), Some(BackendTarget::Origin));

        // The next read resets the override.
        let undiverted = metered(Arc::new(DivertingBackend { serve_as: None }));
        undiverted
            .read_range_into(&[0u8; SHA256_DIGEST_SIZE], 0, &mut dst, context)
            .unwrap();
        assert_eq!(last_read_served_by(), None);
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
