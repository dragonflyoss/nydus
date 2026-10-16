//! The local directory backend: full blobs stored under their digest in one
//! directory.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use nydus_format::blob::{BlobFooter, BlobMetadata};
use nydus_format::utils::{sha256_reader, SHA256_DIGEST_SIZE};
use nydus_telemetry::metrics::{
    collect_read_backend_failure_metrics, collect_read_backend_finished_metrics,
};

use crate::{Backend, BackendKind, Protocol, RawDeviceFile, ReadKind};

/// An open full blob file, its footer locating the data and blob metadata
/// regions inside it.
#[derive(Debug)]
struct Blob {
    /// The path of the full blob file.
    path: PathBuf,

    /// The digest of the whole file, resolved once since it can mean hashing
    /// the file.
    full_blob_id: [u8; SHA256_DIGEST_SIZE],

    /// The validated footer, the layout of the file.
    footer: BlobFooter,

    /// The open file, shared with the raw device it may back.
    file: Arc<File>,
}

/// Implements the full blob file.
impl Blob {
    /// Opens the full blob at `path`, the whole file digesting to
    /// `full_blob_id`, its footer read and validated.
    fn new(path: &Path, full_blob_id: [u8; SHA256_DIGEST_SIZE]) -> io::Result<Self> {
        let footer = BlobFooter::from_blob_path(path).map_err(|err| {
            io::Error::other(format!("invalid nydus blob {}: {err}", path.display()))
        })?;

        Ok(Self {
            path: path.to_path_buf(),
            full_blob_id,
            footer,
            file: Arc::new(File::open(path)?),
        })
    }
}

/// A blob backend over a directory of full blobs named by their digest.
#[derive(Debug)]
pub struct Local {
    /// The directory of full blobs named by their digest.
    dir: PathBuf,

    /// The opened blobs by digest.
    blobs: RwLock<HashMap<[u8; SHA256_DIGEST_SIZE], Arc<Blob>>>,
}

/// Implements the local directory backend.
impl Local {
    /// Creates a backend over the full blobs in `dir`.
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            blobs: RwLock::new(HashMap::new()),
        }
    }

    /// Creates a backend over `dir` that also serves `blob_id`, the digest of
    /// a full blob's data region, from the full blob at `path`.
    ///
    /// The data region is verified against `blob_id` and the whole file hashed
    /// for its full blob digest.
    pub fn with_blob(
        dir: PathBuf,
        blob_id: [u8; SHA256_DIGEST_SIZE],
        path: &Path,
    ) -> io::Result<Self> {
        // Hash the whole file for its full blob digest and read its footer.
        let mut file = File::open(path).map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("failed to open full blob {}: {err}", path.display()),
            )
        })?;
        let full_blob_id = sha256_reader(&file).map_err(io::Error::other)?;
        let blob = Blob::new(path, full_blob_id)?;

        // Verify the data region against the blob id.
        file.seek(SeekFrom::Start(blob.footer.compressed_data_offset()))?;
        let digest = sha256_reader((&file).take(blob.footer.compressed_data_size()))
            .map_err(io::Error::other)?;
        if digest != blob_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("full blob data digest mismatch: {}", path.display()),
            ));
        }

        let backend = Self::new(dir);
        backend.insert_blob(blob_id, blob);
        Ok(backend)
    }

    /// Remembers `blob` as `blob_id`, keeping an existing blob when a racing
    /// open won.
    fn insert_blob(&self, blob_id: [u8; SHA256_DIGEST_SIZE], blob: Blob) -> Arc<Blob> {
        self.blobs
            .write()
            .unwrap()
            .entry(blob_id)
            .or_insert_with(|| Arc::new(blob))
            .clone()
    }

    /// Returns the blob of `blob_id`, opened from `dir/<hex>` on first use.
    ///
    /// The directory is content-addressed, so the file name is trusted as the
    /// full blob digest rather than hashing the file on every daemon start,
    /// corruption being caught by the CRC over every chunk group read.
    fn blob(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<Arc<Blob>> {
        if let Some(blob) = self.blobs.read().unwrap().get(blob_id).cloned() {
            return Ok(blob);
        }

        let path = self.dir.join(hex::encode(blob_id));
        if !path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "blob {} not found in {}",
                    hex::encode(blob_id),
                    self.dir.display()
                ),
            ));
        }

        Ok(self.insert_blob(*blob_id, Blob::new(&path, *blob_id)?))
    }

    /// Returns the sidecar blob metadata path of the blob at `path`, in `dir`.
    fn blob_metadata_path(&self, path: &Path) -> io::Result<PathBuf> {
        let file_name = path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("blob path has no file name: {}", path.display()),
            )
        })?;

        Ok(self.dir.join(format!(
            "{}{}",
            file_name.to_string_lossy(),
            BlobMetadata::SUFFIX
        )))
    }

    /// Fills `buf` with the blob bytes from `offset` of the data region for
    /// an on-demand read.
    fn read_blob_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        buf: &mut [u8],
    ) -> io::Result<()> {
        let blob = self.blob(blob_id)?;
        let end = offset.checked_add(buf.len() as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob range offset overflow")
        })?;
        if end > blob.footer.compressed_data_size() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "backend range read exceeds data region",
            ));
        }

        blob.file
            .read_exact_at(buf, blob.footer.compressed_data_offset() + offset)
    }

    /// Fills `buf` with the blob bytes from `offset` of the data region for
    /// a prefetch read.
    fn prefetch_blob_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        buf: &mut [u8],
    ) -> io::Result<()> {
        let blob = self.blob(blob_id)?;
        let end = offset.checked_add(buf.len() as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob range offset overflow")
        })?;
        if end > blob.footer.compressed_data_size() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "backend range read exceeds data region",
            ));
        }

        blob.file
            .read_exact_at(buf, blob.footer.compressed_data_offset() + offset)
    }
}

/// Implements the blob backend over the local directory.
impl Backend for Local {
    /// Returns [`BackendKind::Local`].
    fn kind(&self) -> BackendKind {
        BackendKind::Local
    }

    /// Returns `None`, a local read having no protocol.
    fn protocol(&self) -> Option<Protocol> {
        None
    }

    /// Returns the digest of the whole blob file.
    fn full_blob_id(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<[u8; SHA256_DIGEST_SIZE]> {
        Ok(self.blob(blob_id)?.full_blob_id)
    }

    /// Returns the footer's `RAW_DEVICE` flag.
    fn is_raw_device(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<bool> {
        Ok(self.blob(blob_id)?.footer.is_raw_device())
    }

    /// Opens the full blob file and names its data region for a raw device
    /// blob.
    fn open_raw_device_file(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<Option<RawDeviceFile>> {
        let blob = self.blob(blob_id)?;
        if !blob.footer.is_raw_device() {
            return Ok(None);
        }

        Ok(Some(RawDeviceFile {
            path: blob.path.clone(),
            file: blob.file.clone(),
            data_offset: blob.footer.compressed_data_offset(),
            data_size: blob.footer.compressed_data_size(),
        }))
    }

    /// Reads the blob's metadata for an on-demand read from the sidecar file
    /// when present, otherwise from the region embedded in the full blob.
    fn read_blob_metadata(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<BlobMetadata> {
        let blob = self.blob(blob_id)?;
        if blob.footer.is_raw_device() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "native EROFS layer has no blob meta: {}",
                    blob.path.display()
                ),
            ));
        }

        let blob_metadata_path = self.blob_metadata_path(&blob.path)?;
        let buf = if blob_metadata_path.is_file() {
            fs::read(&blob_metadata_path)?
        } else {
            let mut buf = vec![0u8; blob.footer.blob_metadata_size() as usize];
            blob.file
                .read_exact_at(&mut buf, blob.footer.blob_metadata_offset())?;
            buf
        };

        BlobMetadata::from_bytes(buf).map_err(io::Error::other)
    }

    /// Reads the blob's metadata for a prefetch read from the sidecar file
    /// when present, otherwise from the region embedded in the full blob.
    fn prefetch_blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<BlobMetadata> {
        let blob = self.blob(blob_id)?;
        if blob.footer.is_raw_device() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "native EROFS layer has no blob meta: {}",
                    blob.path.display()
                ),
            ));
        }

        let blob_metadata_path = self.blob_metadata_path(&blob.path)?;
        let buf = if blob_metadata_path.is_file() {
            fs::read(&blob_metadata_path)?
        } else {
            let mut buf = vec![0u8; blob.footer.blob_metadata_size() as usize];
            blob.file
                .read_exact_at(&mut buf, blob.footer.blob_metadata_offset())?;
            buf
        };

        BlobMetadata::from_bytes(buf).map_err(io::Error::other)
    }

    /// Fills `buf` from the data region for an on-demand read, recording the
    /// read's metrics.
    fn read_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        buf: &mut [u8],
    ) -> io::Result<()> {
        let start = Instant::now();
        let result = self.read_blob_into(blob_id, offset, buf);
        match &result {
            Ok(()) => collect_read_backend_finished_metrics(
                ReadKind::OnDemand,
                BackendKind::Local,
                None,
                buf.len() as u64,
                start.elapsed(),
            ),
            Err(_) => collect_read_backend_failure_metrics(
                ReadKind::OnDemand,
                BackendKind::Local,
                None,
                start.elapsed(),
            ),
        }
        result
    }

    /// Fills `buf` from the data region for a prefetch read, recording the
    /// read's metrics.
    fn prefetch_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        buf: &mut [u8],
    ) -> io::Result<()> {
        let start = Instant::now();
        let result = self.prefetch_blob_into(blob_id, offset, buf);
        match &result {
            Ok(()) => collect_read_backend_finished_metrics(
                ReadKind::Prefetch,
                BackendKind::Local,
                None,
                buf.len() as u64,
                start.elapsed(),
            ),
            Err(_) => collect_read_backend_failure_metrics(
                ReadKind::Prefetch,
                BackendKind::Local,
                None,
                start.elapsed(),
            ),
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use nydus_test_utils::blob::FullBlob;
    use nydus_test_utils::metadata::single_chunk_group;
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    #[test]
    fn read_blob_metadata_uses_the_sidecar_file_or_the_embedded_region() {
        let test_cases = vec![true, false];

        for sidecar in test_cases {
            let dir = tempdir().unwrap();
            let payload = vec![0xabu8; 4096];
            let blob_metadata = single_chunk_group(&payload);
            let mut blob = FullBlob::new(&payload).with_blob_metadata(&blob_metadata);
            if sidecar {
                blob = blob.with_blob_metadata_file();
            }
            let full_blob_id = blob.save_in(dir.path());
            let data_blob_id: [u8; SHA256_DIGEST_SIZE] = Sha256::digest(&payload).into();
            let backend = Local::new(dir.path().to_path_buf());

            let blob_metadata = backend.read_blob_metadata(&full_blob_id).unwrap();
            let mut data = vec![0u8; 4096];
            backend
                .read_range_into(&full_blob_id, 0, &mut data)
                .unwrap();

            assert_eq!(blob_metadata.chunk_count(), 1, "sidecar={sidecar}");
            assert_eq!(data, payload, "sidecar={sidecar}");
            assert!(backend.read_blob_metadata(&data_blob_id).is_err());
        }
    }

    #[test]
    fn with_blob_verifies_the_data_digest() {
        let dir = tempdir().unwrap();
        let payload = vec![0xcdu8; 4096];
        let blob_metadata = single_chunk_group(&payload);
        let full_blob_id = FullBlob::new(&payload)
            .with_blob_metadata(&blob_metadata)
            .save_in(dir.path());
        let path = dir.path().join(hex::encode(full_blob_id));
        let data_blob_id: [u8; SHA256_DIGEST_SIZE] = Sha256::digest(&payload).into();

        let backend = Local::with_blob(dir.path().to_path_buf(), data_blob_id, &path).unwrap();
        assert_eq!(backend.full_blob_id(&data_blob_id).unwrap(), full_blob_id);
        assert!(Local::with_blob(dir.path().to_path_buf(), full_blob_id, &path).is_err());
    }
}
