//! The blob backends: a local directory, or an OCI registry with optional
//! Dragonfly P2P reads. Every API returns `io::Result` to keep the OS errno.

mod local;
mod netns;

#[cfg(feature = "registry")]
mod registry;

use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use nydus_config::{BackendConfig, Config};
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

/// The blob backend, reading blob data and metadata by digest.
///
/// ```text
/// Backend
///   ├─ Local      full blobs in a directory, named by digest
///   └─ Registry   an OCI registry
///        ├─ Http        the origin
///        └─ Dragonfly   the seed peers, falling back to the origin
/// ```
pub trait Backend: Send + Sync {
    /// Returns the metrics of the image, shared with the layers above.
    fn metrics(&self) -> &Arc<Metrics>;

    /// Returns the full blob digest of `blob_id`, which names the cache files.
    ///
    /// ```text
    /// [data region][bootstrap][blob meta][footer]
    /// ├───────────────── full blob digest ──────┤  the OCI layer digest
    /// ├─ data digest ┤                             how the embedded bootstrap names the blob
    /// ```
    ///
    /// `blob_id` is the full blob digest, except for a self-contained full blob
    /// mounted alone.
    fn full_blob_id(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<[u8; SHA256_DIGEST_SIZE]> {
        Ok(*blob_id)
    }

    /// Returns whether the blob is a raw EROFS device, a native `erofs-*` layer
    /// read as is, never cached or decoded.
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
    /// Creates the blob backend the `backend` section of `config` describes.
    #[cfg_attr(not(feature = "registry"), allow(unused_variables))]
    pub fn new(
        config: &Config,
        netns: Option<Netns>,
        metrics: Arc<Metrics>,
    ) -> io::Result<Arc<dyn Backend>> {
        match &config.backend {
            BackendConfig::Local(local) => Ok(Arc::new(Local::new(local.dir.clone(), metrics))),
            #[cfg(feature = "registry")]
            BackendConfig::Registry(_) => Ok(Arc::new(Registry::new(config, netns, metrics)?)),
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
        let config: Config =
            serde_yaml::from_str("backend:\n  type: local\n  config:\n    dir: /blobs\n").unwrap();
        assert!(<dyn Backend>::new(&config, None, Arc::new(Metrics::new())).is_ok());
    }

    #[cfg(feature = "registry")]
    #[test]
    fn new_builds_a_registry_backend() {
        let config: Config = serde_yaml::from_str(
            "backend:\n  type: registry\n  config:\n    addr: http://127.0.0.1:5000\n    repository: a/b\n",
        )
        .unwrap();
        assert!(<dyn Backend>::new(&config, None, Arc::new(Metrics::new())).is_ok());
    }

    #[cfg(not(feature = "registry"))]
    #[test]
    fn new_rejects_a_registry_backend_without_the_feature() {
        let config: Config = serde_yaml::from_str(
            "backend:\n  type: registry\n  config:\n    addr: http://127.0.0.1:5000\n    repository: a/b\n",
        )
        .unwrap();
        let err = <dyn Backend>::new(&config, None, Arc::new(Metrics::new()))
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("registry"));
    }
}
