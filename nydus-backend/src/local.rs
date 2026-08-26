use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};

use super::{BlobBackend, ReadContext};
use nydus_format::blob::{BlobFooter, BlobMetadata, NYDUS_BLOB_METADATA_SUFFIX};
use nydus_format::utils::{hex_string, sha256_file, sha256_file_range, SHA256_DIGEST_SIZE};

#[derive(Clone)]
struct ResolvedSource {
    path: PathBuf,
    /// Digest naming this blob's cache files. Resolved once, because deriving
    /// it means hashing the whole source file.
    cache_key: [u8; SHA256_DIGEST_SIZE],
    data_offset: u64,
    data_size: u64,
    /// Byte region of the embedded blob metadata inside a full blob, absent
    /// for bare data sources.
    blob_metadata_region: Option<EmbeddedRegion>,
}

/// A byte region embedded in a larger file.
#[derive(Clone, Copy)]
struct EmbeddedRegion {
    offset: u64,
    size: u64,
}

/// A resolved source and its lazily opened file handle, looked up together so
/// the per-read hot path pays a single lock round-trip.
struct SourceEntry {
    resolved: ResolvedSource,
    /// Opened on first data read; a failed open is not cached and retried.
    file: OnceLock<Arc<File>>,
}

impl SourceEntry {
    fn open_file(&self) -> io::Result<Arc<File>> {
        if let Some(file) = self.file.get() {
            return Ok(file.clone());
        }
        // A racing open wastes at most one descriptor, which is dropped below.
        let file = Arc::new(File::open(&self.resolved.path)?);
        Ok(self.file.get_or_init(|| file).clone())
    }
}

pub struct Local {
    root: PathBuf,
    sources: RwLock<HashMap<[u8; SHA256_DIGEST_SIZE], Arc<SourceEntry>>>,
}

impl Local {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            sources: RwLock::new(HashMap::new()),
        }
    }

    #[doc(hidden)]
    pub fn with_full_blob_source(
        root: PathBuf,
        blob_id: [u8; SHA256_DIGEST_SIZE],
        path: &Path,
    ) -> io::Result<Self> {
        // `blob_id` only covers the data region here, so the cache key is the
        // digest of the whole file and has to be computed.
        let cache_key = sha256_file(path).map_err(io::Error::other)?;
        let source = probe_full_blob_source(path, cache_key)?.ok_or_else(|| {
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

    fn blob_metadata_path_for_source(&self, source: &Path) -> io::Result<PathBuf> {
        let file_name = source.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("source path has no file name: {}", source.display()),
            )
        })?;

        let blob_metadata_name = format!(
            "{}{NYDUS_BLOB_METADATA_SUFFIX}",
            file_name.to_string_lossy()
        );
        Ok(self.root.join(blob_metadata_name))
    }

    /// Insert a resolved source, keeping an existing entry (and its opened
    /// file) if a racing resolution won.
    fn insert_source(
        &self,
        blob_id: [u8; SHA256_DIGEST_SIZE],
        resolved: ResolvedSource,
    ) -> Arc<SourceEntry> {
        self.sources
            .write()
            .unwrap()
            .entry(blob_id)
            .or_insert_with(|| {
                Arc::new(SourceEntry {
                    resolved,
                    file: OnceLock::new(),
                })
            })
            .clone()
    }

    /// Look up (or resolve and memoise) the source entry for `blob_id`. The
    /// hit path is a single read-lock round-trip; resolution runs without
    /// holding the lock, exactly as before.
    fn source_entry(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<Arc<SourceEntry>> {
        if let Some(entry) = self.sources.read().unwrap().get(blob_id).cloned() {
            return Ok(entry);
        }

        let exact = self.root.join(hex_string(blob_id));
        if exact.is_file() {
            // The store is content-addressed: the file name is the digest
            // claim and doubles as the cache key. No full-file hash here —
            // it costs an O(blob) cold read on every daemon start (the
            // dominant part of ublk/fanotify mount-ready and FUSE/NBD
            // first-read latency). The store is populated by digest-verified
            // downloads, and runtime corruption is caught by the mandatory
            // per-block-group CRC32C on every data read and the CRC32 over
            // the blob meta.
            let source = probe_full_blob_source(&exact, *blob_id)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("nydus blob footer not found: {}", exact.display()),
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

    fn resolved_source(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<ResolvedSource> {
        Ok(self.source_entry(blob_id)?.resolved.clone())
    }

    fn read_blob_metadata_bytes(&self, source: &ResolvedSource) -> io::Result<Vec<u8>> {
        let blob_metadata_path = self.blob_metadata_path_for_source(&source.path)?;
        if blob_metadata_path.is_file() {
            return fs::read(&blob_metadata_path);
        }

        if let Some(region) = source.blob_metadata_region {
            let (offset, size) = (region.offset, region.size);
            let file = File::open(&source.path)?;
            let mut data = vec![0u8; size as usize];
            file.read_exact_at(&mut data, offset)?;
            return Ok(data);
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("blob meta not found: {}", blob_metadata_path.display()),
        ))
    }
}

impl BlobBackend for Local {
    fn cache_key(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<[u8; SHA256_DIGEST_SIZE]> {
        Ok(self.resolved_source(blob_id)?.cache_key)
    }

    fn blob_metadata(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<BlobMetadata> {
        let source = self.resolved_source(blob_id)?;
        let data = self.read_blob_metadata_bytes(&source)?;
        BlobMetadata::from_bytes(&data, false).map_err(io::Error::other)
    }

    fn save_blob_metadata(&self, blob_id: &[u8; SHA256_DIGEST_SIZE], dst: &Path) -> io::Result<()> {
        let source = self.resolved_source(blob_id)?;
        let data = self.read_blob_metadata_bytes(&source)?;
        let mut file = File::create(dst)?;
        file.write_all(&data)?;
        file.flush()
    }

    fn read_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        dst: &mut [u8],
        _context: ReadContext,
    ) -> io::Result<()> {
        // One lock round-trip resolves both the source metadata and the file.
        let entry = self.source_entry(blob_id)?;
        let end = offset.checked_add(dst.len() as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob range offset overflow")
        })?;
        if end > entry.resolved.data_size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "backend range read exceeds data region",
            ));
        }
        entry
            .open_file()?
            .read_exact_at(dst, entry.resolved.data_offset + offset)
    }
}

fn probe_full_blob_source(
    path: &Path,
    cache_key: [u8; SHA256_DIGEST_SIZE],
) -> io::Result<Option<ResolvedSource>> {
    let footer = match BlobFooter::from_blob_path(path) {
        Ok(footer) => footer,
        Err(_) => return Ok(None),
    };
    Ok(Some(ResolvedSource {
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
    use crate::ReadKind;
    use nydus_format::blob::{BlobMetadataBlockGroup, BlobMetadataChunk, BlobMetadataCompressor};
    use nydus_format::utils::sha256_bytes;
    use tempfile::tempdir;

    fn blob_metadata(payload: &[u8]) -> BlobMetadata {
        BlobMetadata::new(
            BlobMetadataCompressor::None,
            1,
            vec![BlobMetadataChunk::new(*blake3::hash(payload).as_bytes(), 0, 1).unwrap()],
            vec![BlobMetadataBlockGroup::new(0, 1, 0, 4096, crc32c::crc32c(payload)).unwrap()],
        )
        .unwrap()
    }

    use nydus_format::utils::write_minimal_full_blob;

    #[test]
    fn local_backend_reads_full_blob_file_and_sidecar_meta() {
        let dir = tempdir().unwrap();
        let payload = vec![0xabu8; 4096];
        let full_blob_id =
            write_minimal_full_blob(dir.path(), &payload, &blob_metadata(&payload), true);

        let backend = Local::new(dir.path().to_path_buf());
        let blob_metadata = backend.blob_metadata(&full_blob_id).unwrap();
        let mut data = vec![0u8; 4096];
        backend
            .read_range_into(
                &full_blob_id,
                0,
                &mut data,
                ReadContext::raw(ReadKind::OnDemand),
            )
            .unwrap();

        assert_eq!(blob_metadata.header().chunk_count(), 1);
        assert_eq!(data, payload);
    }

    #[test]
    fn local_backend_reads_embedded_blob_metadata_from_full_blob() {
        let dir = tempdir().unwrap();
        let payload = vec![0xcdu8; 4096];
        let data_blob_id = sha256_bytes(&payload);
        let full_blob_id =
            write_minimal_full_blob(dir.path(), &payload, &blob_metadata(&payload), false);
        let backend = Local::new(dir.path().to_path_buf());

        let blob_metadata = backend.blob_metadata(&full_blob_id).unwrap();
        let mut data = vec![0u8; 4096];
        backend
            .read_range_into(
                &full_blob_id,
                0,
                &mut data,
                ReadContext::raw(ReadKind::OnDemand),
            )
            .unwrap();

        assert_eq!(blob_metadata.header().chunk_count(), 1);
        assert_eq!(data, payload);
        assert!(backend.blob_metadata(&data_blob_id).is_err());
    }
}
