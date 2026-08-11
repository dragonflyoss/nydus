use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::{BlobBackend, ReadContext};
use crate::metadata::{BlobFooter, BlobMeta, EROFS_BLOB_ID_SIZE};
use crate::utils::{hex_string, sha256_file, sha256_file_range};

#[derive(Clone)]
struct ResolvedSource {
    path: PathBuf,
    /// Digest naming this blob's cache files. Resolved once, because deriving
    /// it means hashing the whole source file.
    cache_key: [u8; EROFS_BLOB_ID_SIZE],
    data_offset: u64,
    data_size: u64,
    blob_meta_offset: Option<u64>,
    blob_meta_size: Option<u64>,
}

pub struct LocalBackend {
    root: PathBuf,
    resolved_sources: Mutex<HashMap<[u8; EROFS_BLOB_ID_SIZE], ResolvedSource>>,
    source_files: Mutex<HashMap<[u8; EROFS_BLOB_ID_SIZE], Arc<File>>>,
}

impl LocalBackend {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            resolved_sources: Mutex::new(HashMap::new()),
            source_files: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn with_full_blob_source(
        root: PathBuf,
        blob_id: [u8; EROFS_BLOB_ID_SIZE],
        path: &Path,
    ) -> io::Result<Self> {
        // `blob_id` only covers the data region here, so the cache key is the
        // digest of the whole file and has to be computed.
        let cache_key = sha256_file(path).map_err(io::Error::other)?;
        let source = inspect_full_blob_source(path, cache_key)?.ok_or_else(|| {
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
        backend
            .resolved_sources
            .lock()
            .unwrap()
            .insert(blob_id, source);
        Ok(backend)
    }

    /// Build a `LocalBackend` from its YAML configuration, which only carries
    /// the `dir` field pointing at the blob source directory.
    pub fn from_value(config: &serde_yaml::Value) -> io::Result<Self> {
        #[derive(serde::Deserialize)]
        struct LocalDirConfig {
            dir: PathBuf,
        }
        let cfg: LocalDirConfig = serde_yaml::from_value(config.clone()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid local backend config: {e}"),
            )
        })?;
        Ok(Self::new(cfg.dir))
    }

    fn blob_meta_path_for_source(&self, source: &Path) -> io::Result<PathBuf> {
        let file_name = source.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("source path has no file name: {}", source.display()),
            )
        })?;

        let blob_meta_name = format!("{}.blob.meta", file_name.to_string_lossy());
        Ok(self.root.join(blob_meta_name))
    }

    fn resolve_source(&self, blob_id: &[u8; EROFS_BLOB_ID_SIZE]) -> io::Result<ResolvedSource> {
        if let Some(source) = self.resolved_sources.lock().unwrap().get(blob_id).cloned() {
            return Ok(source);
        }

        let exact = self.root.join(hex_string(blob_id));
        if exact.is_file() {
            if sha256_file(&exact).map_err(io::Error::other)? != *blob_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("local source blob digest mismatch: {}", exact.display()),
                ));
            }
            // The check above proves the whole file hashes to `blob_id`, so it
            // doubles as the cache key.
            let source = inspect_full_blob_source(&exact, *blob_id)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("nydus blob footer not found: {}", exact.display()),
                )
            })?;
            self.resolved_sources
                .lock()
                .unwrap()
                .insert(*blob_id, source.clone());
            return Ok(source);
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "failed to resolve local source blob {}",
                hex_string(blob_id)
            ),
        ))
    }

    fn source_file(&self, blob_id: &[u8; EROFS_BLOB_ID_SIZE]) -> io::Result<Arc<File>> {
        if let Some(file) = self.source_files.lock().unwrap().get(blob_id).cloned() {
            return Ok(file);
        }

        let source = self.resolve_source(blob_id)?;
        let file = Arc::new(File::open(&source.path)?);
        self.source_files
            .lock()
            .unwrap()
            .insert(*blob_id, file.clone());
        Ok(file)
    }

    fn read_blob_meta_bytes(&self, source: &ResolvedSource) -> io::Result<Vec<u8>> {
        let blob_meta_path = self.blob_meta_path_for_source(&source.path)?;
        if blob_meta_path.is_file() {
            return fs::read(&blob_meta_path);
        }

        if let (Some(offset), Some(size)) = (source.blob_meta_offset, source.blob_meta_size) {
            let file = File::open(&source.path)?;
            let mut data = vec![0u8; size as usize];
            file.read_exact_at(&mut data, offset)?;
            return Ok(data);
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("blob meta not found: {}", blob_meta_path.display()),
        ))
    }
}

impl BlobBackend for LocalBackend {
    fn cache_key(
        &self,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
    ) -> io::Result<[u8; EROFS_BLOB_ID_SIZE]> {
        Ok(self.resolve_source(blob_id)?.cache_key)
    }

    fn blob_meta(&self, blob_id: &[u8; EROFS_BLOB_ID_SIZE]) -> io::Result<BlobMeta> {
        let source = self.resolve_source(blob_id)?;
        let data = self.read_blob_meta_bytes(&source)?;
        BlobMeta::loader()
            .blob_id(*blob_id)
            .from_bytes(&data)
            .map_err(io::Error::other)
    }

    fn blob_meta_to(&self, blob_id: &[u8; EROFS_BLOB_ID_SIZE], dst: &Path) -> io::Result<()> {
        let source = self.resolve_source(blob_id)?;
        let data = self.read_blob_meta_bytes(&source)?;
        let mut file = File::create(dst)?;
        file.write_all(&data)?;
        file.flush()
    }

    fn read_range_into(
        &self,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
        offset: u64,
        dst: &mut [u8],
        _ctx: ReadContext,
    ) -> io::Result<()> {
        let source = self.resolve_source(blob_id)?;
        let end = offset.checked_add(dst.len() as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob range offset overflow")
        })?;
        if end > source.data_size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "backend range read exceeds data region",
            ));
        }
        let file = self.source_file(blob_id)?;
        file.read_exact_at(dst, source.data_offset + offset)
    }
}

fn inspect_full_blob_source(
    path: &Path,
    cache_key: [u8; EROFS_BLOB_ID_SIZE],
) -> io::Result<Option<ResolvedSource>> {
    let footer = match BlobFooter::read_from_path(path) {
        Ok(footer) => footer,
        Err(_) => return Ok(None),
    };
    Ok(Some(ResolvedSource {
        path: path.to_path_buf(),
        cache_key,
        data_offset: footer.compressed_data_offset(),
        data_size: footer.compressed_data_size(),
        blob_meta_offset: Some(footer.blob_meta_offset()),
        blob_meta_size: Some(footer.blob_meta_size()),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{BlobMetaChunk, BlobMetaGroup};
    use crate::storage::backend::ReadKind;
    use crate::utils::sha256_bytes;
    use tempfile::tempdir;

    fn blob_meta(blob_id: [u8; EROFS_BLOB_ID_SIZE], payload: &[u8]) -> BlobMeta {
        BlobMeta::from_parts(
            blob_id,
            1,
            vec![BlobMetaGroup::new(0, 1, 0, 4096, crc32c::crc32c(payload)).unwrap()],
            vec![BlobMetaChunk::new(*blake3::hash(payload).as_bytes(), 0, 1).unwrap()],
        )
        .unwrap()
    }

    use crate::storage::test_util::write_minimal_full_blob;

    #[test]
    fn local_backend_reads_full_blob_file_and_sidecar_meta() {
        let dir = tempdir().unwrap();
        let payload = vec![0xabu8; 4096];
        let data_blob_id = sha256_bytes(&payload);
        let full_blob_id = write_minimal_full_blob(
            dir.path(),
            &payload,
            &blob_meta(data_blob_id, &payload),
            true,
        );

        let backend = LocalBackend::new(dir.path().to_path_buf());
        let blob_meta = backend.blob_meta(&full_blob_id).unwrap();
        let data = backend
            .read_range(&full_blob_id, 0, 4096, ReadContext::raw(ReadKind::OnDemand))
            .unwrap();

        assert_eq!(blob_meta.header().chunk_count(), 1);
        assert_eq!(data, payload);
    }

    #[test]
    fn local_backend_reads_embedded_blob_meta_from_full_blob() {
        let dir = tempdir().unwrap();
        let payload = vec![0xcdu8; 4096];
        let data_blob_id = sha256_bytes(&payload);
        let full_blob_id = write_minimal_full_blob(
            dir.path(),
            &payload,
            &blob_meta(data_blob_id, &payload),
            false,
        );
        let backend = LocalBackend::new(dir.path().to_path_buf());

        let blob_meta = backend.blob_meta(&full_blob_id).unwrap();
        let data = backend
            .read_range(&full_blob_id, 0, 4096, ReadContext::raw(ReadKind::OnDemand))
            .unwrap();

        assert_eq!(blob_meta.header().chunk_count(), 1);
        assert_eq!(data, payload);
        assert!(backend.blob_meta(&data_blob_id).is_err());
    }
}
