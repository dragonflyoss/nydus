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
use nydus_telemetry::metrics::Metrics;

use crate::{Backend, RawDeviceFile, ReadKind, Source};

/// An open full blob file, its footer locating the data and blob metadata
/// regions inside it.
#[derive(Debug)]
struct FullBlob {
    /// The path of the file.
    path: PathBuf,

    /// The digest of the whole file, the full blob digest the blob's cache
    /// files are named by. Trusted from the file name in a content-addressed
    /// directory, hashed once from the file for a self-contained full blob.
    id: [u8; SHA256_DIGEST_SIZE],

    /// The validated footer, the layout of the file.
    footer: BlobFooter,

    /// The open file, shared with the raw device it may back.
    file: Arc<File>,
}

/// Implements the full blob file.
impl FullBlob {
    /// Opens the full blob at `path`, the whole file digesting to `id`, its
    /// footer read and validated.
    fn new(path: &Path, id: [u8; SHA256_DIGEST_SIZE]) -> io::Result<Self> {
        let footer = BlobFooter::from_blob_path(path).map_err(|err| {
            io::Error::other(format!("invalid nydus blob {}: {err}", path.display()))
        })?;

        Ok(Self {
            path: path.to_path_buf(),
            id,
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

    /// The opened full blobs by blob digest.
    full_blobs: RwLock<HashMap<[u8; SHA256_DIGEST_SIZE], Arc<FullBlob>>>,

    /// The metrics of the image the backend serves.
    metrics: Arc<Metrics>,
}

/// Implements the local directory backend.
impl Local {
    /// Creates a backend over the full blobs in `dir`, recording into
    /// `metrics`.
    pub fn new(dir: PathBuf, metrics: Arc<Metrics>) -> Self {
        Self {
            dir,
            full_blobs: RwLock::new(HashMap::new()),
            metrics,
        }
    }

    /// Creates a backend from the self-contained full blob at `path`, serving
    /// `blob_id` from the file itself and any other blob from the file's
    /// directory, recording into `metrics`.
    ///
    /// `blob_id` comes from the bootstrap embedded in the file, which names
    /// the blob by the digest of its data region rather than of the whole
    /// file, see [`Backend::full_blob_id`]. This reads the file twice before
    /// serving anything: once whole, for the full blob digest its cache files
    /// are named by, and once over the data region, to verify it against
    /// `blob_id`.
    pub fn from_full_blob(
        blob_id: [u8; SHA256_DIGEST_SIZE],
        path: &Path,
        metrics: Arc<Metrics>,
    ) -> io::Result<Self> {
        let mut file = File::open(path).map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("failed to open full blob {}: {err}", path.display()),
            )
        })?;
        let id = sha256_reader(&file).map_err(io::Error::other)?;
        let full_blob = FullBlob::new(path, id)?;

        file.seek(SeekFrom::Start(full_blob.footer.compressed_data_offset()))?;
        let digest = sha256_reader((&file).take(full_blob.footer.compressed_data_size()))
            .map_err(io::Error::other)?;
        if digest != blob_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("full blob data digest mismatch: {}", path.display()),
            ));
        }

        let backend = Self::new(
            path.parent().unwrap_or(Path::new(".")).to_path_buf(),
            metrics,
        );
        backend
            .full_blobs
            .write()
            .unwrap()
            .insert(blob_id, Arc::new(full_blob));
        Ok(backend)
    }

    /// Returns the full blob of `blob_id`, opened from `dir/<hex>` on first
    /// use.
    ///
    /// The directory is content-addressed, so `blob_id` is the full blob
    /// digest and the file name is trusted rather than the file hashed on
    /// every daemon start, corruption being caught by the CRC over every chunk
    /// group read.
    fn full_blob(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<Arc<FullBlob>> {
        if let Some(full_blob) = self.full_blobs.read().unwrap().get(blob_id).cloned() {
            return Ok(full_blob);
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

        let full_blob = FullBlob::new(&path, *blob_id)?;
        Ok(self
            .full_blobs
            .write()
            .unwrap()
            .entry(*blob_id)
            .or_insert_with(|| Arc::new(full_blob))
            .clone())
    }

    /// Returns the sidecar blob metadata path of the full blob at `path`, in
    /// `dir`.
    fn blob_metadata_path(&self, path: &Path) -> io::Result<PathBuf> {
        let file_name = path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("full blob path has no file name: {}", path.display()),
            )
        })?;

        Ok(self.dir.join(format!(
            "{}{}",
            file_name.to_string_lossy(),
            BlobMetadata::SUFFIX
        )))
    }
}

/// Implements the blob backend over the local directory.
impl Backend for Local {
    /// Returns the metrics of the image.
    fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// Returns the digest of the whole blob file: `blob_id` itself for a blob
    /// of the directory, the hashed file for a self-contained full blob.
    fn full_blob_id(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<[u8; SHA256_DIGEST_SIZE]> {
        Ok(self.full_blob(blob_id)?.id)
    }

    /// Returns the footer's `RAW_DEVICE` flag.
    fn is_raw_device(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<bool> {
        Ok(self.full_blob(blob_id)?.footer.is_raw_device())
    }

    /// Opens the full blob file and names its data region for a raw device
    /// blob.
    fn open_raw_device_file(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<Option<RawDeviceFile>> {
        let full_blob = self.full_blob(blob_id)?;
        if !full_blob.footer.is_raw_device() {
            return Ok(None);
        }

        Ok(Some(RawDeviceFile {
            path: full_blob.path.clone(),
            file: full_blob.file.clone(),
            data_offset: full_blob.footer.compressed_data_offset(),
            data_size: full_blob.footer.compressed_data_size(),
        }))
    }

    /// Reads the blob's metadata for an on-demand read from the sidecar file
    /// when present, otherwise from the region embedded in the full blob.
    fn read_blob_metadata(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<BlobMetadata> {
        let full_blob = self.full_blob(blob_id)?;
        let blob_metadata_path = self.blob_metadata_path(&full_blob.path)?;
        let buf = if blob_metadata_path.is_file() {
            fs::read(&blob_metadata_path)?
        } else {
            let mut buf = vec![0u8; full_blob.footer.blob_metadata_size() as usize];
            full_blob
                .file
                .read_exact_at(&mut buf, full_blob.footer.blob_metadata_offset())?;
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
        let full_blob = self.full_blob(blob_id)?;
        let blob_metadata_path = self.blob_metadata_path(&full_blob.path)?;
        let buf = if blob_metadata_path.is_file() {
            fs::read(&blob_metadata_path)?
        } else {
            let mut buf = vec![0u8; full_blob.footer.blob_metadata_size() as usize];
            full_blob
                .file
                .read_exact_at(&mut buf, full_blob.footer.blob_metadata_offset())?;
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
        self.full_blob(blob_id)
            .and_then(|full_blob| {
                let end = offset.checked_add(buf.len() as u64).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "blob range offset overflow")
                })?;
                if end > full_blob.footer.compressed_data_size() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "backend range read exceeds data region",
                    ));
                }

                full_blob
                    .file
                    .read_exact_at(buf, full_blob.footer.compressed_data_offset() + offset)
            })
            .inspect(|()| {
                self.metrics.backend.collect_read_finished_metrics(
                    ReadKind::OnDemand,
                    Source::Local,
                    buf.len() as u64,
                    start.elapsed(),
                )
            })
            .inspect_err(|_| {
                self.metrics
                    .backend
                    .collect_read_failure_metrics(ReadKind::OnDemand, Source::Local)
            })
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
        self.full_blob(blob_id)
            .and_then(|full_blob| {
                let end = offset.checked_add(buf.len() as u64).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "blob range offset overflow")
                })?;
                if end > full_blob.footer.compressed_data_size() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "backend range read exceeds data region",
                    ));
                }

                full_blob
                    .file
                    .read_exact_at(buf, full_blob.footer.compressed_data_offset() + offset)
            })
            .inspect(|()| {
                self.metrics.backend.collect_read_finished_metrics(
                    ReadKind::Prefetch,
                    Source::Local,
                    buf.len() as u64,
                    start.elapsed(),
                )
            })
            .inspect_err(|_| {
                self.metrics
                    .backend
                    .collect_read_failure_metrics(ReadKind::Prefetch, Source::Local)
            })
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
            let backend = Local::new(dir.path().to_path_buf(), Arc::new(Metrics::new()));

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
    fn from_full_blob_verifies_the_data_digest() {
        let dir = tempdir().unwrap();
        let payload = vec![0xcdu8; 4096];
        let blob_metadata = single_chunk_group(&payload);
        let full_blob_id = FullBlob::new(&payload)
            .with_blob_metadata(&blob_metadata)
            .save_in(dir.path());
        let path = dir.path().join(hex::encode(full_blob_id));
        let data_blob_id: [u8; SHA256_DIGEST_SIZE] = Sha256::digest(&payload).into();

        let backend = Local::from_full_blob(data_blob_id, &path, Arc::new(Metrics::new())).unwrap();
        assert_eq!(backend.full_blob_id(&data_blob_id).unwrap(), full_blob_id);
        assert!(Local::from_full_blob(full_blob_id, &path, Arc::new(Metrics::new())).is_err());
    }
}
