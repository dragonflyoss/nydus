use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::BlobBackend;
use crate::metadata::{BlobFooter, BlobMeta, EROFS_BLOB_ID_SIZE};
use crate::utils::{hex_string, sha256_file, sha256_file_range};

#[derive(Clone)]
struct ResolvedSource {
    path: PathBuf,
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
        if exact.is_file() && sha256_file(&exact).map_err(io::Error::other)? == *blob_id {
            let source = ResolvedSource {
                path: exact.clone(),
                data_offset: 0,
                data_size: exact.metadata()?.len(),
                blob_meta_offset: None,
                blob_meta_size: None,
            };
            self.resolved_sources
                .lock()
                .unwrap()
                .insert(*blob_id, source.clone());
            return Ok(source);
        }

        for entry in fs::read_dir(&self.root)? {
            let path = entry?.path();
            if !path.is_file() {
                continue;
            }

            let Some(source) = inspect_full_blob_source(&path)? else {
                continue;
            };

            if sha256_file_range(&path, source.data_offset, source.data_size)
                .map_err(io::Error::other)?
                == *blob_id
            {
                self.resolved_sources
                    .lock()
                    .unwrap()
                    .insert(*blob_id, source.clone());
                return Ok(source);
            }
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
            read_exact_at(&file, offset, &mut data)?;
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
        let source = self.resolve_source(blob_id)?;
        sha256_file(&source.path).map_err(io::Error::other)
    }

    fn load_blob_meta(&self, blob_id: &[u8; EROFS_BLOB_ID_SIZE]) -> io::Result<BlobMeta> {
        let source = self.resolve_source(blob_id)?;
        let data = self.read_blob_meta_bytes(&source)?;
        BlobMeta::from_bytes_with_blob_id(&data, *blob_id).map_err(io::Error::other)
    }

    fn download_blob_meta(&self, blob_id: &[u8; EROFS_BLOB_ID_SIZE], dst: &Path) -> io::Result<()> {
        let source = self.resolve_source(blob_id)?;
        let data = self.read_blob_meta_bytes(&source)?;
        let mut file = File::create(dst)?;
        file.write_all(&data)?;
        file.flush()
    }

    fn read_range(
        &self,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
        offset: u64,
        len: u32,
    ) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len as usize];
        self.read_range_into(blob_id, offset, &mut buf)?;
        Ok(buf)
    }

    fn read_range_into(
        &self,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
        offset: u64,
        dst: &mut [u8],
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
        read_exact_at(&file, source.data_offset + offset, dst)
    }
}

fn inspect_full_blob_source(path: &Path) -> io::Result<Option<ResolvedSource>> {
    let footer = match BlobFooter::read_from_path(path) {
        Ok(footer) => footer,
        Err(_) => return Ok(None),
    };
    Ok(Some(ResolvedSource {
        path: path.to_path_buf(),
        data_offset: footer.compressed_data_offset(),
        data_size: footer.compressed_data_size(),
        blob_meta_offset: Some(footer.blob_meta_offset()),
        blob_meta_size: Some(footer.blob_meta_size()),
    }))
}

fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    let mut read_total = 0usize;
    while read_total < buf.len() {
        let read = file.read_at(&mut buf[read_total..], offset + read_total as u64)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "backend range read ended early",
            ));
        }
        read_total += read;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{
        BlobMetaChunk, BlobMetaGroup, ErofsSuperblock, EROFS_BLOCK_SIZE, EROFS_SUPER_OFFSET,
    };
    use crate::utils::sha256_bytes;
    use std::io::Write;
    use tempfile::tempdir;

    fn blobmeta(blob_id: [u8; EROFS_BLOB_ID_SIZE], payload: &[u8]) -> BlobMeta {
        BlobMeta::from_parts(
            blob_id,
            1,
            vec![BlobMetaGroup::new(0, 1, 0, 4096, crc32c::crc32c(payload)).unwrap()],
            vec![BlobMetaChunk::new(*blake3::hash(payload).as_bytes(), 0, 0, 1).unwrap()],
        )
        .unwrap()
    }

    #[test]
    fn local_backend_reads_exact_blob_file_and_blob_meta() {
        let dir = tempdir().unwrap();
        let payload = vec![0xabu8; 4096];
        let blob_id = sha256_bytes(&payload);
        let blob_path = dir.path().join(hex_string(&blob_id));
        let blob_meta_path = dir
            .path()
            .join(format!("{}.blob.meta", hex_string(&blob_id)));
        fs::write(&blob_path, &payload).unwrap();
        blobmeta(blob_id, &payload).save(&blob_meta_path).unwrap();

        let backend = LocalBackend::new(dir.path().to_path_buf());
        let blob_meta = backend.load_blob_meta(&blob_id).unwrap();
        let data = backend.read_range(&blob_id, 0, 4096).unwrap();

        assert_eq!(blob_meta.header().chunk_count(), 1);
        assert_eq!(data, payload);
    }

    #[test]
    fn local_backend_loads_blob_meta_named_after_full_blob_sha() {
        let dir = tempdir().unwrap();
        let payload = vec![0xcdu8; 4096];
        let blob_id = sha256_bytes(&payload);

        let mut bootstrap = vec![0u8; 8192];
        let sb = ErofsSuperblock::new(0, 0, 0, 0, 0, 2, 1, 0, 0, &[0u8; 16]);
        let sb_start = EROFS_SUPER_OFFSET as usize;
        let sb_end = sb_start + sb.as_bytes().len();
        bootstrap[sb_start..sb_end].copy_from_slice(sb.as_bytes());
        let blob_meta = blobmeta(blob_id, &payload);
        let footer = BlobFooter::new(
            0,
            payload.len() as u64,
            payload.len() as u64,
            (bootstrap.len() as u64 / EROFS_BLOCK_SIZE as u64) as u32,
            payload.len() as u64 + bootstrap.len() as u64,
            (blob_meta.metadata_size() / EROFS_BLOCK_SIZE as u64) as u32,
        )
        .unwrap();

        let temp_full_blob_path = dir.path().join("full-blob.bin");
        let mut full_blob = File::create(&temp_full_blob_path).unwrap();
        full_blob.write_all(&payload).unwrap();
        full_blob.write_all(&bootstrap).unwrap();
        blob_meta.write_to(&mut full_blob).unwrap();
        footer.write_to(&mut full_blob).unwrap();
        let full_blob_id = sha256_file(&temp_full_blob_path).unwrap();
        let full_blob_path = dir.path().join(hex_string(&full_blob_id));
        fs::rename(&temp_full_blob_path, &full_blob_path).unwrap();

        let backend = LocalBackend::new(dir.path().to_path_buf());
        let blob_meta = backend.load_blob_meta(&blob_id).unwrap();
        let data = backend.read_range(&blob_id, 0, 4096).unwrap();

        assert_eq!(blob_meta.header().chunk_count(), 1);
        assert_eq!(data, payload);
    }
}
