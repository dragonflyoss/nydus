//! Direct reads of a raw device blob: a native `erofs-*` layer whose data
//! region is the EROFS device itself. Nothing is decoded, cached or
//! prefetched; every read goes straight to the backend, which for such
//! blobs is a local store. Kernel-facing services map the original file
//! when its data region starts at offset zero; streamed blobs remain
//! unsupported by the cache-file interface.

use std::io;
use std::ops::Range;
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use nydus_backend::{BlobBackend, RawDeviceFile, ReadContext, ReadKind};
use nydus_format::utils::SHA256_DIGEST_SIZE;

use super::BlobCache;

/// A blob cache that passes reads through to the backend unchanged.
pub struct RawDeviceBlobCache {
    blob_id: [u8; SHA256_DIGEST_SIZE],
    backend: Arc<dyn BlobBackend>,
    file: Option<RawDeviceFile>,
}

impl RawDeviceBlobCache {
    /// Wrap `backend` for the raw device blob `blob_id`.
    pub fn new(blob_id: [u8; SHA256_DIGEST_SIZE], backend: Arc<dyn BlobBackend>) -> Self {
        let file = backend
            .raw_device_file(&blob_id)
            .ok()
            .flatten()
            .filter(|file| file.data_offset == 0);
        Self {
            blob_id,
            backend,
            file,
        }
    }

    fn mapped(&self) -> io::Result<&RawDeviceFile> {
        self.file.as_ref().ok_or_else(unsupported)
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

    fn ensure_range(&self, offset: u64, len: u64) -> io::Result<()> {
        let file = self.mapped()?;
        let end = offset.checked_add(len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob range offset overflow")
        })?;
        if end > file.data_size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "range exceeds the raw device data region",
            ));
        }
        Ok(())
    }

    fn ready_ranges(&self, offset: u64, len: u64) -> io::Result<Vec<Range<u64>>> {
        let file = self.mapped()?;
        let end = offset.saturating_add(len).min(file.data_size);
        Ok((offset < end).then_some(offset..end).into_iter().collect())
    }

    fn prepare(&self) -> io::Result<PathBuf> {
        Ok(self.mapped()?.path.clone())
    }

    fn cache_fd(&self) -> io::Result<RawFd> {
        Ok(self.mapped()?.file.as_raw_fd())
    }

    fn is_all_ready(&self) -> bool {
        self.file.is_some()
    }
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "native EROFS layer has no local file to map; mount it through the kernel",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_backend::{metered, Local};
    use nydus_format::blob::BlobMetadata;
    use nydus_format::utils::{hex_string, pread_exact, sha256_bytes};
    use tempfile::tempdir;

    fn write_raw_device_blob(dir: &std::path::Path) -> (Vec<u8>, [u8; SHA256_DIGEST_SIZE]) {
        let payload: Vec<u8> = (0..8192u32).map(|index| (index % 251) as u8).collect();
        let mut blob = payload.clone();
        let bootstrap = vec![0u8; 4096];
        nydus_format::blob::finish_full_blob(&mut blob, payload.len() as u64, &bootstrap, None)
            .unwrap();
        let blob_id = sha256_bytes(&blob);
        std::fs::write(dir.join(hex_string(&blob_id)), &blob).unwrap();
        (payload, blob_id)
    }

    #[test]
    fn local_raw_device_maps_the_store_file_directly() {
        let dir = tempdir().unwrap();
        let (payload, blob_id) = write_raw_device_blob(dir.path());
        let backend = metered(Arc::new(Local::new(dir.path().to_path_buf())));
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

        assert!(cache.is_all_ready());
        assert_eq!(
            cache.prepare().unwrap(),
            dir.path().join(hex_string(&blob_id))
        );
        cache.ensure_range(0, 8192).unwrap();
        assert_eq!(
            cache.ensure_range(4096, 8192).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            cache.ensure_range(u64::MAX, 1).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(cache.ready_ranges(4096, 8192).unwrap(), vec![4096..8192]);
        assert!(cache.ready_ranges(8192, 4096).unwrap().is_empty());
        pread_exact(cache.cache_fd().unwrap(), &mut out, 4000).unwrap();
        assert_eq!(out, &payload[4000..4100]);
    }

    struct Streamed(Local);

    impl BlobBackend for Streamed {
        fn blob_metadata(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<BlobMetadata> {
            self.0.blob_metadata(blob_id)
        }

        fn read_range_into(
            &self,
            blob_id: &[u8; SHA256_DIGEST_SIZE],
            offset: u64,
            dst: &mut [u8],
            context: ReadContext,
        ) -> io::Result<()> {
            self.0.read_range_into(blob_id, offset, dst, context)
        }
    }

    #[test]
    fn streamed_raw_device_cache_operations_are_unsupported() {
        let dir = tempdir().unwrap();
        let (payload, blob_id) = write_raw_device_blob(dir.path());
        let cache = RawDeviceBlobCache::new(
            blob_id,
            Arc::new(Streamed(Local::new(dir.path().to_path_buf()))),
        );
        let mut out = vec![0; 100];
        cache.read_at(4000, &mut out).unwrap();
        assert_eq!(out, &payload[4000..4100]);
        assert!(!cache.is_all_ready());
        for result in [
            cache.ensure_range(0, 4096),
            cache.prepare().map(drop),
            cache.ready_ranges(0, 4096).map(drop),
        ] {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
        }
        assert_eq!(
            cache.cache_fd().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
}
