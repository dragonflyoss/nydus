use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use memmap2::Mmap;

use super::BlobBackend;
use crate::metadata::{
    cast_ref, BlobMeta, ErofsSuperblock, EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE, EROFS_SB_BASE_SIZE,
    EROFS_SUPER_MAGIC_V1, EROFS_SUPER_OFFSET,
};
use crate::utils::{hex_string, sha256_file, sha256_file_region};

pub struct LocalBackend {
    root: PathBuf,
    resolved_sources: Mutex<HashMap<[u8; EROFS_BLOB_ID_SIZE], PathBuf>>,
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

    fn resolve_source_path(&self, blob_id: &[u8; EROFS_BLOB_ID_SIZE]) -> io::Result<PathBuf> {
        if let Some(path) = self.resolved_sources.lock().unwrap().get(blob_id).cloned() {
            return Ok(path);
        }

        let exact = self.root.join(hex_string(blob_id));
        if exact.is_file() && sha256_file(&exact).map_err(io::Error::other)? == *blob_id {
            self.resolved_sources
                .lock()
                .unwrap()
                .insert(*blob_id, exact.clone());
            return Ok(exact);
        }

        for entry in fs::read_dir(&self.root)? {
            let path = entry?.path();
            if !path.is_file() {
                continue;
            }

            let Some(offset) = data_region_offset(&path)? else {
                continue;
            };

            if sha256_file_region(&path, offset).map_err(io::Error::other)? == *blob_id {
                self.resolved_sources
                    .lock()
                    .unwrap()
                    .insert(*blob_id, path.clone());
                return Ok(path);
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

        let path = self.resolve_source_path(blob_id)?;
        let file = Arc::new(File::open(&path)?);
        self.source_files
            .lock()
            .unwrap()
            .insert(*blob_id, file.clone());
        Ok(file)
    }
}

impl BlobBackend for LocalBackend {
    fn cache_key(
        &self,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
    ) -> io::Result<[u8; EROFS_BLOB_ID_SIZE]> {
        let source_path = self.resolve_source_path(blob_id)?;
        sha256_file(&source_path).map_err(io::Error::other)
    }

    fn load_blob_meta(&self, blob_id: &[u8; EROFS_BLOB_ID_SIZE]) -> io::Result<BlobMeta> {
        let source_path = self.resolve_source_path(blob_id)?;
        let blob_meta_path = self.blob_meta_path_for_source(&source_path)?;
        BlobMeta::load_with_blob_id(&blob_meta_path, *blob_id).map_err(io::Error::other)
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
        let file = self.source_file(blob_id)?;
        read_exact_at(&file, offset, dst)
    }
}

fn data_region_offset(path: &Path) -> io::Result<Option<u64>> {
    let file = File::open(path)?;
    let mapped = unsafe { Mmap::map(&file) }?;
    if mapped.len() < EROFS_SUPER_OFFSET as usize + EROFS_SB_BASE_SIZE {
        return Ok(None);
    }

    let sb = cast_ref::<ErofsSuperblock>(&mapped[EROFS_SUPER_OFFSET as usize..]);
    if sb.magic() != EROFS_SUPER_MAGIC_V1 {
        return Ok(None);
    }

    let bytes = sb
        .blocks()
        .checked_mul(EROFS_BLOCK_SIZE as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "blob size overflow"))?;
    if bytes as usize > mapped.len() {
        return Ok(None);
    }
    Ok(Some(bytes))
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
    use crate::metadata::{BlobMetaChunk, ErofsSuperblock, EROFS_SUPER_OFFSET};
    use crate::utils::sha256_bytes;
    use tempfile::tempdir;

    fn blobmeta_chunk(
        uncompressed_offset: u64,
        uncompressed_size: u32,
        compressed_offset: u64,
        compressed_size: u32,
        payload: &[u8],
    ) -> BlobMetaChunk {
        BlobMetaChunk::new(
            uncompressed_offset,
            uncompressed_size,
            compressed_offset,
            compressed_size,
            *blake3::hash(payload).as_bytes(),
            crc32c::crc32c(payload),
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
        BlobMeta::from_chunks(blob_id, vec![blobmeta_chunk(0, 4096, 0, 4096, &payload)])
            .save(&blob_meta_path)
            .unwrap();

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

        let mut full_blob = vec![0u8; 8192];
        let sb = ErofsSuperblock::new(0, 0, 0, 0, 0, 2, 1, 0, 0, &[0u8; 16]);
        let sb_start = EROFS_SUPER_OFFSET as usize;
        let sb_end = sb_start + sb.as_bytes().len();
        full_blob[sb_start..sb_end].copy_from_slice(sb.as_bytes());
        full_blob.extend_from_slice(&payload);

        let temp_full_blob_path = dir.path().join("full-blob.bin");
        fs::write(&temp_full_blob_path, &full_blob).unwrap();
        let full_blob_id = sha256_file(&temp_full_blob_path).unwrap();
        let full_blob_path = dir.path().join(hex_string(&full_blob_id));
        fs::rename(&temp_full_blob_path, &full_blob_path).unwrap();

        BlobMeta::from_chunks(blob_id, vec![blobmeta_chunk(0, 4096, 8192, 4096, &payload)])
            .save(
                &dir.path()
                    .join(format!("{}.blob.meta", hex_string(&full_blob_id))),
            )
            .unwrap();

        let backend = LocalBackend::new(dir.path().to_path_buf());
        let blob_meta = backend.load_blob_meta(&blob_id).unwrap();
        let data = backend.read_range(&blob_id, 8192, 4096).unwrap();

        assert_eq!(blob_meta.header().chunk_count(), 1);
        assert_eq!(data, payload);
    }
}
