//! The local directory backend: full blobs stored under their digest in one
//! directory.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};

use std::time::Instant;

use nydus_format::blob::{BlobFooter, BlobMetadata, NYDUS_BLOB_METADATA_SUFFIX};
use nydus_format::utils::{hex_string, sha256_file, sha256_file_range, SHA256_DIGEST_SIZE};
use nydus_telemetry::metrics::{
    collect_read_backend_failure_metrics, collect_read_backend_finished_metrics,
};

use crate::{Backend, BlobBackend, Protocol, ReadKind};

/// A byte region embedded in a larger file.
#[derive(Clone, Copy)]
struct EmbeddedRegion {
    offset: u64,
    size: u64,
}

/// A full blob file and where its data and blob metadata sit inside it.
#[derive(Clone)]
struct Source {
    path: PathBuf,
    /// The digest naming this blob's cache files, resolved once since it can
    /// mean hashing the whole file.
    cache_key: [u8; SHA256_DIGEST_SIZE],
    data_offset: u64,
    data_size: u64,
    /// The embedded blob metadata, absent for a bare data file.
    blob_metadata_region: Option<EmbeddedRegion>,
}

/// A source and its lazily opened file, looked up together so a read pays a
/// single lock round-trip.
struct SourceSlot {
    source: Source,
    /// Opened on the first data read, a failed open being retried.
    file: OnceLock<Arc<File>>,
}

impl SourceSlot {
    /// The open source file, opening it on first use.
    fn open_file(&self) -> io::Result<Arc<File>> {
        if let Some(file) = self.file.get() {
            return Ok(file.clone());
        }
        let file = Arc::new(File::open(&self.source.path)?);
        Ok(self.file.get_or_init(|| file).clone())
    }
}

/// A blob backend over a directory of full blobs named by their digest.
pub struct Local {
    root: PathBuf,
    sources: RwLock<HashMap<[u8; SHA256_DIGEST_SIZE], Arc<SourceSlot>>>,
}

impl Local {
    /// A backend over the full blobs in `root`.
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            sources: RwLock::new(HashMap::new()),
        }
    }

    /// A backend over `root` that also serves `blob_id`, the digest of a full
    /// blob's data region, from the full blob at `path`. The data region is
    /// verified against `blob_id` and the whole file hashed for the cache key.
    pub fn with_full_blob_source(
        root: PathBuf,
        blob_id: [u8; SHA256_DIGEST_SIZE],
        path: &Path,
    ) -> io::Result<Self> {
        let cache_key = sha256_file(path).map_err(io::Error::other)?;
        let source = parse_full_blob(path, cache_key)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("nydus blob footer not found: {}", path.display()),
            )
        })?;
        if sha256_file_range(path, source.data_offset, source.data_size)
            .map_err(io::Error::other)?
            != blob_id
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("full blob data digest mismatch: {}", path.display()),
            ));
        }

        let backend = Self::new(root);
        backend.insert_source(blob_id, source);
        Ok(backend)
    }

    /// The sidecar blob metadata path of the source at `path`, in `root`.
    fn blob_metadata_path(&self, path: &Path) -> io::Result<PathBuf> {
        let file_name = path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("source path has no file name: {}", path.display()),
            )
        })?;

        let blob_metadata_name = format!(
            "{}{NYDUS_BLOB_METADATA_SUFFIX}",
            file_name.to_string_lossy()
        );
        Ok(self.root.join(blob_metadata_name))
    }

    /// Remember `source` as `blob_id`, keeping an existing slot and its open
    /// file when a racing resolution won.
    fn insert_source(&self, blob_id: [u8; SHA256_DIGEST_SIZE], source: Source) -> Arc<SourceSlot> {
        self.sources
            .write()
            .unwrap()
            .entry(blob_id)
            .or_insert_with(|| {
                Arc::new(SourceSlot {
                    source,
                    file: OnceLock::new(),
                })
            })
            .clone()
    }

    /// The slot of `blob_id`, resolved from `root/<hex>` on first use. The
    /// store is content-addressed, so the file name is trusted as the cache
    /// key rather than hashing the file on every daemon start, corruption
    /// being caught by the CRC over every block group read.
    fn source(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<Arc<SourceSlot>> {
        if let Some(slot) = self.sources.read().unwrap().get(blob_id).cloned() {
            return Ok(slot);
        }

        let path = self.root.join(hex_string(blob_id));
        if path.is_file() {
            let source = parse_full_blob(&path, *blob_id)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("nydus blob footer not found: {}", path.display()),
                )
            })?;
            return Ok(self.insert_source(*blob_id, source));
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "failed to resolve local source blob {}",
                hex_string(blob_id)
            ),
        ))
    }

    /// Fill `dst` with the blob bytes from `offset` of the data region.
    fn read_range(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        dst: &mut [u8],
    ) -> io::Result<()> {
        let slot = self.source(blob_id)?;
        let end = offset.checked_add(dst.len() as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob range offset overflow")
        })?;
        if end > slot.source.data_size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "backend range read exceeds data region",
            ));
        }
        slot.open_file()?
            .read_exact_at(dst, slot.source.data_offset + offset)
    }

    /// The raw blob metadata of `source`: the sidecar file when present,
    /// otherwise the region embedded in the full blob.
    fn read_blob_metadata_bytes(&self, source: &Source) -> io::Result<Vec<u8>> {
        let blob_metadata_path = self.blob_metadata_path(&source.path)?;
        if blob_metadata_path.is_file() {
            return fs::read(&blob_metadata_path);
        }

        if let Some(region) = source.blob_metadata_region {
            let file = File::open(&source.path)?;
            let mut data = vec![0u8; region.size as usize];
            file.read_exact_at(&mut data, region.offset)?;
            return Ok(data);
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("blob meta not found: {}", blob_metadata_path.display()),
        ))
    }
}

impl BlobBackend for Local {
    fn backend(&self) -> Backend {
        Backend::Local
    }

    fn protocol(&self) -> Option<Protocol> {
        None
    }

    fn cache_key(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<[u8; SHA256_DIGEST_SIZE]> {
        Ok(self.source(blob_id)?.source.cache_key)
    }

    fn blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        _kind: ReadKind,
    ) -> io::Result<BlobMetadata> {
        let slot = self.source(blob_id)?;
        let data = self.read_blob_metadata_bytes(&slot.source)?;
        BlobMetadata::from_bytes(&data, false).map_err(io::Error::other)
    }

    fn save_blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        _kind: ReadKind,
        dst: &Path,
    ) -> io::Result<()> {
        let slot = self.source(blob_id)?;
        let data = self.read_blob_metadata_bytes(&slot.source)?;
        let mut file = File::create(dst)?;
        file.write_all(&data)?;
        file.flush()
    }

    fn read_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        dst: &mut [u8],
        kind: ReadKind,
    ) -> io::Result<()> {
        if dst.is_empty() {
            return Ok(());
        }
        let start = Instant::now();
        let result = self.read_range(blob_id, offset, dst);
        match &result {
            Ok(()) => collect_read_backend_finished_metrics(
                kind,
                Backend::Local,
                None,
                dst.len() as u64,
                start.elapsed(),
            ),
            Err(_) => {
                collect_read_backend_failure_metrics(kind, Backend::Local, None, start.elapsed())
            }
        }
        result
    }
}

/// Parse the full blob at `path` into a source named by `cache_key`, `None`
/// when the file carries no nydus footer.
fn parse_full_blob(path: &Path, cache_key: [u8; SHA256_DIGEST_SIZE]) -> io::Result<Option<Source>> {
    let footer = match BlobFooter::from_blob_path(path) {
        Ok(footer) => footer,
        Err(_) => return Ok(None),
    };
    Ok(Some(Source {
        path: path.to_path_buf(),
        cache_key,
        data_offset: footer.compressed_data_offset(),
        data_size: footer.compressed_data_size(),
        blob_metadata_region: Some(EmbeddedRegion {
            offset: footer.blob_metadata_offset(),
            size: footer.blob_metadata_size(),
        }),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use nydus_format::blob::{
        BlobMetadataBlockGroup, BlobMetadataChunk, BlobMetadataCompressor, BlobMetadataDigester,
    };
    use nydus_format::utils::{sha256_bytes, write_minimal_full_blob};
    use tempfile::tempdir;

    fn blob_metadata(payload: &[u8]) -> BlobMetadata {
        BlobMetadata::new(
            BlobMetadataCompressor::None,
            BlobMetadataDigester::Blake3,
            1,
            vec![BlobMetadataChunk::new(*blake3::hash(payload).as_bytes(), 0, 1).unwrap()],
            vec![
                BlobMetadataBlockGroup::new(0, 1, 0, 4096, crc32c::crc32c(payload), 0, 0, false)
                    .unwrap(),
            ],
            false,
        )
        .unwrap()
    }

    #[test]
    fn reads_full_blob_file_and_sidecar_meta() {
        let dir = tempdir().unwrap();
        let payload = vec![0xabu8; 4096];
        let full_blob_id =
            write_minimal_full_blob(dir.path(), &payload, &blob_metadata(&payload), true);

        let backend = Local::new(dir.path().to_path_buf());
        let blob_metadata = backend
            .blob_metadata(&full_blob_id, ReadKind::OnDemand)
            .unwrap();
        let mut data = vec![0u8; 4096];
        backend
            .read_range_into(&full_blob_id, 0, &mut data, ReadKind::OnDemand)
            .unwrap();

        assert_eq!(blob_metadata.header().chunk_count(), 1);
        assert_eq!(data, payload);
    }

    #[test]
    fn reads_embedded_blob_metadata_from_full_blob() {
        let dir = tempdir().unwrap();
        let payload = vec![0xcdu8; 4096];
        let data_blob_id = sha256_bytes(&payload);
        let full_blob_id =
            write_minimal_full_blob(dir.path(), &payload, &blob_metadata(&payload), false);
        let backend = Local::new(dir.path().to_path_buf());

        let blob_metadata = backend
            .blob_metadata(&full_blob_id, ReadKind::OnDemand)
            .unwrap();
        let mut data = vec![0u8; 4096];
        backend
            .read_range_into(&full_blob_id, 0, &mut data, ReadKind::OnDemand)
            .unwrap();

        assert_eq!(blob_metadata.header().chunk_count(), 1);
        assert_eq!(data, payload);
        assert!(backend
            .blob_metadata(&data_blob_id, ReadKind::OnDemand)
            .is_err());
    }
}
