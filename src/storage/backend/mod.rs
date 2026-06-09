mod local;

#[cfg(feature = "backend-registry")]
mod pauser;
#[cfg(feature = "backend-registry")]
mod registry;

use std::io;
use std::path::Path;
use std::sync::Arc;

use crate::metadata::{BlobMeta, EROFS_BLOB_ID_SIZE};
use crate::storage::config::BackendConfig;

pub use local::LocalBackend;

#[cfg(feature = "backend-registry")]
pub use pauser::BACKEND_PAUSER;
#[cfg(feature = "backend-registry")]
pub use registry::Registry;

/// Origin of a backend read, used to apply different retry, throttling and
/// proxy-priority policies to user-triggered versus background reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RequestSource {
    /// User-triggered read that blocks a FUSE request.
    #[default]
    OnDemand,
    /// Background prefetch read after mount.
    Prefetch,
}

/// Diagnostic context for a backend read: its origin plus the uncompressed
/// `(offset, size)` span it decodes to, when the read maps to blob-meta groups.
/// Raw reads (e.g. the blob footer or blob meta region) carry `None`.
#[derive(Debug, Clone, Copy)]
pub struct ReadContext {
    pub source: RequestSource,
    pub uncompressed: Option<(u64, u64)>,
}

impl ReadContext {
    /// Context for a read that decodes to a known uncompressed group span.
    pub fn group(source: RequestSource, uncompressed_offset: u64, uncompressed_size: u64) -> Self {
        Self {
            source,
            uncompressed: Some((uncompressed_offset, uncompressed_size)),
        }
    }

    /// Context for a raw read with no associated uncompressed group span.
    pub fn raw(source: RequestSource) -> Self {
        Self {
            source,
            uncompressed: None,
        }
    }
}

/// A blob backend resolves blob data and metadata by content digest.
pub trait BlobBackend: Send + Sync {
    fn cache_key(
        &self,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
    ) -> io::Result<[u8; EROFS_BLOB_ID_SIZE]> {
        Ok(*blob_id)
    }

    fn load_blob_meta(&self, blob_id: &[u8; EROFS_BLOB_ID_SIZE]) -> io::Result<BlobMeta>;

    fn download_blob_meta(&self, blob_id: &[u8; EROFS_BLOB_ID_SIZE], dst: &Path) -> io::Result<()> {
        let blob_meta = self.load_blob_meta(blob_id)?;
        blob_meta.save(dst).map_err(io::Error::other)
    }

    fn read_range_into(
        &self,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
        offset: u64,
        dst: &mut [u8],
        ctx: ReadContext,
    ) -> io::Result<()> {
        let data = self.read_range(blob_id, offset, dst.len() as u32, ctx)?;
        if data.len() != dst.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "backend returned short range",
            ));
        }
        dst.copy_from_slice(&data);
        Ok(())
    }

    fn read_range(
        &self,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
        offset: u64,
        len: u32,
        ctx: ReadContext,
    ) -> io::Result<Vec<u8>>;
}

/// Construct a blob backend from its configuration.
pub fn build_backend(config: &BackendConfig) -> io::Result<Arc<dyn BlobBackend>> {
    match config.kind.as_str() {
        "local" => Ok(Arc::new(LocalBackend::from_value(&config.config)?)),
        #[cfg(feature = "backend-registry")]
        "registry" => Ok(Arc::new(Registry::from_value(&config.config)?)),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported backend type: {other}"),
        )),
    }
}
