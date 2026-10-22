//! The pass-through cache of a raw device blob: a native `erofs-*` layer
//! whose data region is the EROFS device itself, nothing decoded, cached or
//! prefetched.

use std::fs::File;
use std::io;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use nydus_backend::{Backend, RawDeviceFile};
use nydus_format::utils::SHA256_DIGEST_SIZE;

use super::BlobCache;

/// A blob cache passing every read through to the backend unchanged.
///
/// The kernel-facing services map the backend's own file when its data
/// region starts at offset zero; a streamed raw device has no file to hand
/// to the kernel and rejects the file-oriented operations.
pub(crate) struct RawDeviceBlobCache {
    /// The blob id.
    blob_id: [u8; SHA256_DIGEST_SIZE],

    /// The backend serving the blob.
    backend: Arc<dyn Backend>,

    /// The backend's local file when its data region starts at offset zero.
    file: Option<RawDeviceFile>,
}

/// Implements the raw device blob cache.
impl RawDeviceBlobCache {
    /// Creates the cache of the raw device blob `blob_id` over `backend`.
    pub(crate) fn new(blob_id: [u8; SHA256_DIGEST_SIZE], backend: Arc<dyn Backend>) -> Self {
        let file = backend
            .open_raw_device_file(&blob_id)
            .ok()
            .flatten()
            .filter(|file| file.data_offset == 0);
        Self {
            blob_id,
            backend,
            file,
        }
    }

    /// Returns the backend's local file, failing with
    /// [`io::ErrorKind::Unsupported`] for a streamed raw device.
    fn mapped(&self) -> io::Result<&RawDeviceFile> {
        self.file.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "native EROFS layer has no local file to map; mount it through the kernel",
            )
        })
    }
}

/// Implements the blob cache over the raw device.
impl BlobCache for RawDeviceBlobCache {
    /// Fills `buf` straight from the backend.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        self.backend.read_range_into(&self.blob_id, offset, buf)
    }

    /// Does nothing: a raw device holds no chunk groups to warm.
    fn prefetch_all(&self, _workers: usize, _deadline: Option<Instant>) -> io::Result<()> {
        Ok(())
    }

    /// Checks the range against the data region: the file is always ready.
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

    /// Returns the range clipped to the data region: the file is always
    /// ready.
    fn ready_ranges(&self, offset: u64, len: u64) -> io::Result<Vec<Range<u64>>> {
        let file = self.mapped()?;
        let end = offset.saturating_add(len).min(file.data_size);
        Ok((offset < end).then_some(offset..end).into_iter().collect())
    }

    /// Returns the path of the backend's local file.
    fn prepare(&self) -> io::Result<PathBuf> {
        Ok(self.mapped()?.path.clone())
    }

    /// Returns the backend's local file.
    fn cache_file(&self) -> io::Result<Arc<File>> {
        Ok(self.mapped()?.file.clone())
    }

    /// Returns whether the backend's local file is mappable.
    fn is_all_ready(&self) -> bool {
        self.file.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_backend::Local;
    use nydus_format::blob::BlobMetadata;
    use nydus_telemetry::metrics::Metrics;
    use nydus_test_utils::blob::FullBlob;
    use std::os::unix::fs::FileExt;
    use std::path::Path;
    use tempfile::tempdir;

    fn write_raw_device_blob(dir: &Path) -> (Vec<u8>, [u8; SHA256_DIGEST_SIZE]) {
        let payload: Vec<u8> = (0..8192u32).map(|index| (index % 251) as u8).collect();
        let blob_id = FullBlob::new(&payload).save_in(dir);
        (payload, blob_id)
    }

    #[test]
    fn a_local_raw_device_maps_the_store_file_directly() {
        let dir = tempdir().unwrap();
        let (payload, blob_id) = write_raw_device_blob(dir.path());
        let backend: Arc<dyn Backend> = Arc::new(Local::new(
            dir.path().to_path_buf(),
            Arc::new(Metrics::new()),
        ));
        assert!(backend.is_raw_device(&blob_id).unwrap());
        assert!(backend.read_blob_metadata(&blob_id).is_err());

        let cache = RawDeviceBlobCache::new(blob_id, backend);
        let mut buf = vec![0u8; 100];
        cache.read_at(4000, &mut buf).unwrap();
        assert_eq!(buf, &payload[4000..4100]);
        cache.read_at(0, &mut []).unwrap();
        assert!(cache.read_at(8192 - 50, &mut buf).is_err());
        cache.prefetch_all(1, None).unwrap();
        assert!(!cache.is_ondemand());

        assert!(cache.is_all_ready());
        assert_eq!(
            cache.prepare().unwrap(),
            dir.path().join(hex::encode(blob_id))
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
        cache
            .cache_file()
            .unwrap()
            .read_exact_at(&mut buf, 4000)
            .unwrap();
        assert_eq!(buf, &payload[4000..4100]);
    }

    struct Streamed(Local);

    impl Backend for Streamed {
        fn metrics(&self) -> &Arc<Metrics> {
            self.0.metrics()
        }

        fn read_blob_metadata(
            &self,
            blob_id: &[u8; SHA256_DIGEST_SIZE],
        ) -> io::Result<BlobMetadata> {
            self.0.read_blob_metadata(blob_id)
        }

        fn read_range_into(
            &self,
            blob_id: &[u8; SHA256_DIGEST_SIZE],
            offset: u64,
            buf: &mut [u8],
        ) -> io::Result<()> {
            self.0.read_range_into(blob_id, offset, buf)
        }
    }

    #[test]
    fn a_streamed_raw_device_rejects_the_file_oriented_operations() {
        let dir = tempdir().unwrap();
        let (payload, blob_id) = write_raw_device_blob(dir.path());
        let cache = RawDeviceBlobCache::new(
            blob_id,
            Arc::new(Streamed(Local::new(
                dir.path().to_path_buf(),
                Arc::new(Metrics::new()),
            ))),
        );
        let mut buf = vec![0; 100];
        cache.read_at(4000, &mut buf).unwrap();
        assert_eq!(buf, &payload[4000..4100]);
        assert!(!cache.is_all_ready());
        for result in [
            cache.ensure_range(0, 4096),
            cache.prepare().map(drop),
            cache.ready_ranges(0, 4096).map(drop),
        ] {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
        }
        assert_eq!(
            cache.cache_file().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
}
