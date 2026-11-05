//! Data-plane blob backends for nydus: local directory and OCI registry, with
//! optional Dragonfly P2P reads.
//!
//! Every API here returns `io::Result` so the OS errno survives to the
//! service edges; this crate never depends on the control-plane error type.

mod local;
mod netns;

#[cfg(feature = "registry")]
mod registry;

use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use nydus_config::{BackendConfig, PrefetchConfig};
use nydus_format::blob::BlobMetadata;
use nydus_format::utils::SHA256_DIGEST_SIZE;
use nydus_telemetry::metrics::Metrics;

pub use local::Local;
pub use netns::{Netns, NetnsId};

#[cfg(feature = "registry")]
pub(crate) use registry::Registry;

pub use nydus_config::ReadKind;
pub use nydus_telemetry::metrics::Source;

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
/// Backend
///   ├─ Local      full blobs in a directory, named by their digest
///   └─ Registry   an OCI registry, blob GETs over one transport
///        ├─ Http        the origin, with the token fetches of both
///        └─ Dragonfly   the seed peers, back to the origin when they cannot serve
/// ```
///
/// Every implementation records its own read metrics. The `prefetch_*`
/// defaults forward to the on-demand methods for a backend that serves both
/// reads alike.
pub trait Backend: Send + Sync {
    /// Returns the metrics of the image the backend serves, which its reads
    /// and the caches, prefetcher and filesystem above it record into.
    fn metrics(&self) -> &Arc<Metrics>;

    /// Returns the full blob digest of `blob_id`, the digest the blob's cache
    /// files are named by.
    ///
    /// A full blob file is `[data region][bootstrap][blob meta][footer]` and
    /// has two digests: the digest of the whole file, which is the OCI layer
    /// digest a registry serves it under and a merged bootstrap names it by,
    /// and the digest of its data region alone. The bootstrap embedded in the
    /// file itself was written before the file was complete, so it can only
    /// name the blob by its data region digest. A `blob_id` is therefore the
    /// full blob digest except when a self-contained full blob is mounted on
    /// its own, and this maps either back to the full blob digest so the cache
    /// files of a layer share one name however it was mounted. Two blobs built
    /// from the same data with different blob meta share a data region digest
    /// but not a full blob digest, which is why the latter names the cache.
    fn full_blob_id(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<[u8; SHA256_DIGEST_SIZE]> {
        Ok(*blob_id)
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

    /// Opens the local file backing a raw device, `None` for a streamed or
    /// chunked blob.
    fn open_raw_device_file(
        &self,
        _blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<Option<RawDeviceFile>> {
        Ok(None)
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

/// Implements the blob backend construction.
impl dyn Backend {
    /// Creates the blob backend `config` describes, recording into
    /// `metrics`, its prefetch reads following `prefetch`, a registry
    /// backend reaching the registry from `netns` when one is given, the
    /// caller's network namespace otherwise.
    #[cfg_attr(not(feature = "registry"), allow(unused_variables))]
    pub fn new(
        config: &BackendConfig,
        prefetch: &PrefetchConfig,
        netns: Option<Netns>,
        metrics: Arc<Metrics>,
    ) -> io::Result<Arc<dyn Backend>> {
        match config {
            BackendConfig::Local(local) => Ok(Arc::new(Local::new(local.dir.clone(), metrics))),
            #[cfg(feature = "registry")]
            BackendConfig::Registry(registry) => Ok(Arc::new(Registry::new(
                (**registry).clone(),
                prefetch,
                netns,
                metrics,
            )?)),
            #[cfg(not(feature = "registry"))]
            BackendConfig::Registry(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "registry backend requires the `registry` feature",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_builds_a_local_backend() {
        let config: BackendConfig =
            serde_yaml::from_str("type: local\nconfig:\n  dir: /blobs\n").unwrap();
        assert!(<dyn Backend>::new(
            &config,
            &PrefetchConfig::default(),
            None,
            Arc::new(Metrics::new())
        )
        .is_ok());
    }

    #[cfg(feature = "registry")]
    #[test]
    fn new_builds_a_registry_backend() {
        let config: BackendConfig = serde_yaml::from_str(
            "type: registry\nconfig:\n  addr: http://127.0.0.1:5000\n  repository: a/b\n",
        )
        .unwrap();
        assert!(<dyn Backend>::new(
            &config,
            &PrefetchConfig::default(),
            None,
            Arc::new(Metrics::new())
        )
        .is_ok());
    }

    #[cfg(not(feature = "registry"))]
    #[test]
    fn new_rejects_a_registry_backend_without_the_feature() {
        let config: BackendConfig = serde_yaml::from_str(
            "type: registry\nconfig:\n  addr: http://127.0.0.1:5000\n  repository: a/b\n",
        )
        .unwrap();
        let err = <dyn Backend>::new(
            &config,
            &PrefetchConfig::default(),
            None,
            Arc::new(Metrics::new()),
        )
        .err()
        .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("registry"));
    }
}
