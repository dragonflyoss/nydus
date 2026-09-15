//! Direct reads of a raw device blob: a native `erofs-*` layer whose data
//! region is the EROFS device itself. Nothing is decoded, cached or
//! prefetched; every read goes straight to the backend, which for such
//! blobs is a local store. The kernel-facing services (uffd, nbd, ublk,
//! fanotify) need a cache file and therefore cannot serve these blobs.

use std::io;
use std::sync::Arc;
use std::time::Instant;

use nydus_backend::{BlobBackend, ReadContext, ReadKind};
use nydus_format::utils::SHA256_DIGEST_SIZE;

use super::BlobCache;

/// A blob cache that passes reads through to the backend unchanged.
pub struct RawDeviceBlobCache {
    blob_id: [u8; SHA256_DIGEST_SIZE],
    backend: Arc<dyn BlobBackend>,
}

impl RawDeviceBlobCache {
    /// Wrap `backend` for the raw device blob `blob_id`.
    pub fn new(blob_id: [u8; SHA256_DIGEST_SIZE], backend: Arc<dyn BlobBackend>) -> Self {
        Self { blob_id, backend }
    }
}

impl BlobCache for RawDeviceBlobCache {
    fn read_at(&self, offset: u64, dst: &mut [u8]) -> io::Result<()> {
        if dst.is_empty() {
            return Ok(());
        }
        self.backend.read_range_into(
            &self.blob_id,
            offset,
            dst,
            ReadContext::raw(ReadKind::OnDemand),
        )
    }

    /// A raw device holds no chunk groups to warm.
    fn prefetch_all(&self, _workers: usize, _deadline: Option<Instant>) -> io::Result<()> {
        Ok(())
    }

    fn ensure_range(&self, _offset: u64, _len: u64) -> io::Result<()> {
        Err(unsupported())
    }

    fn prepare(&self) -> io::Result<std::path::PathBuf> {
        Err(unsupported())
    }

    fn cache_fd(&self) -> io::Result<std::os::fd::RawFd> {
        Err(unsupported())
    }
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "native EROFS layer has no local cache file; mount it through the kernel",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_backend::Local;
    use nydus_format::utils::sha256_bytes;
    use tempfile::tempdir;

    #[test]
    fn raw_device_reads_pass_through_and_cache_operations_are_unsupported() {
        let dir = tempdir().unwrap();
        // Data region of 8192 bytes, then a one-block bootstrap and the footer.
        let payload: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        let mut blob = payload.clone();
        let bootstrap = vec![0u8; 4096];
        nydus_format::blob::finish_full_blob(&mut blob, payload.len() as u64, &bootstrap, None)
            .unwrap();
        let blob_id = sha256_bytes(&blob);
        std::fs::write(
            dir.path().join(nydus_format::utils::hex_string(&blob_id)),
            &blob,
        )
        .unwrap();
        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(dir.path().to_path_buf()));
        assert!(backend.is_raw_device(&blob_id).unwrap());
        assert!(backend.blob_metadata(&blob_id).is_err());

        let cache = RawDeviceBlobCache::new(blob_id, backend);
        let mut out = vec![0u8; 100];
        cache.read_at(4000, &mut out).unwrap();
        assert_eq!(out, &payload[4000..4100]);
        cache.read_at(0, &mut []).unwrap();
        assert!(cache.read_at(8192 - 50, &mut out).is_err());
        cache.prefetch_all(1, None).unwrap();
        assert!(!cache.is_redirect());
        assert!(!cache.is_all_ready());
        for result in [cache.ensure_range(0, 4096), cache.prepare().map(drop)] {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
        }
        assert_eq!(
            cache.cache_fd().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
}
