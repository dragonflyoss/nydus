use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::metadata::{BlobMeta, EROFS_BLOB_ID_SIZE};
use crate::storage::backend::BlobBackend;
use crate::storage::chunkmap::ChunkMap;
use crate::utils::hex_string;

pub struct CachedBlobDevice {
    blob_id: [u8; EROFS_BLOB_ID_SIZE],
    chunkmap: ChunkMap,
    blobmeta: BlobMeta,
    cache_file: File,
    backend: Arc<dyn BlobBackend>,
    fetch_lock: Mutex<()>,
}

impl CachedBlobDevice {
    pub fn open(
        blob_id: [u8; EROFS_BLOB_ID_SIZE],
        cache_dir: &Path,
        backend: Arc<dyn BlobBackend>,
    ) -> io::Result<Self> {
        fs::create_dir_all(cache_dir)?;

        let blob_id_hex = hex_string(&blob_id);
        let blobmeta_path = cache_dir.join(format!("{}.blob.meta", blob_id_hex));
        let blobmeta = if blobmeta_path.is_file() {
            BlobMeta::load_with_blob_id(&blobmeta_path, blob_id).map_err(io::Error::other)?
        } else {
            let blobmeta = backend.load_blobmeta(&blob_id)?;
            blobmeta.save(&blobmeta_path).map_err(io::Error::other)?;
            BlobMeta::load_with_blob_id(&blobmeta_path, blob_id).map_err(io::Error::other)?
        };

        let cache_blob_path = cache_dir.join(format!("{}.blob.data", blob_id_hex));
        let cache_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&cache_blob_path)?;
        cache_file.set_len(blobmeta.cache_size())?;

        let chunkmap_path = cache_dir.join(format!("{}.chunkmap", blob_id_hex));
        let chunkmap = ChunkMap::open(&chunkmap_path, blobmeta.chunks().len())?;

        Ok(Self {
            blob_id,
            chunkmap,
            blobmeta,
            cache_file,
            backend,
            fetch_lock: Mutex::new(()),
        })
    }

    pub fn read_into(&self, source_offset: u64, chunk_off: u64, dst: &mut [u8]) -> io::Result<()> {
        let (chunk_index, chunk) = self
            .blobmeta
            .chunk_for_source_offset(source_offset)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "blob meta entry not found for blob {} source offset {}",
                        hex_string(&self.blob_id),
                        source_offset
                    ),
                )
            })?;

        if !self.chunkmap.is_ready(chunk_index)? {
            let _guard = self.fetch_lock.lock().unwrap();
            if !self.chunkmap.is_ready(chunk_index)? {
                let data = self.backend.read_range(
                    &self.blob_id,
                    chunk.compressed_offset(),
                    chunk.compressed_size(),
                )?;
                if data.len() != chunk.compressed_size() as usize {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "backend returned unexpected range length",
                    ));
                }
                write_all_at(&self.cache_file, chunk.uncompressed_offset(), &data)?;
                self.chunkmap.set_ready(chunk_index)?;
            }
        }

        read_exact_at(
            &self.cache_file,
            chunk.uncompressed_offset() + chunk_off,
            dst,
        )
    }
}

fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    let mut read_total = 0usize;
    while read_total < buf.len() {
        let read = file.read_at(&mut buf[read_total..], offset + read_total as u64)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "cache file read ended early",
            ));
        }
        read_total += read;
    }
    Ok(())
}

fn write_all_at(file: &File, offset: u64, buf: &[u8]) -> io::Result<()> {
    let mut written = 0usize;
    while written < buf.len() {
        let n = file.write_at(&buf[written..], offset + written as u64)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "cache file write returned zero",
            ));
        }
        written += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{BlobMetaChunk, ErofsSuperblock, EROFS_SUPER_OFFSET};
    use crate::storage::backend::LocalBackend;
    use crate::utils::sha256_bytes;
    use tempfile::tempdir;

    #[test]
    fn cached_blob_device_fetches_from_local_backend() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0xceu8; 4096];
        let blob_id = sha256_bytes(&payload);
        let blob_path = backend_dir.path().join(hex_string(&blob_id));
        fs::write(&blob_path, &payload).unwrap();
        BlobMeta::from_chunks(blob_id, vec![BlobMetaChunk::new(0, 4096, 0, 4096).unwrap()])
            .save(
                &backend_dir
                    .path()
                    .join(format!("{}.blob.meta", hex_string(&blob_id))),
            )
            .unwrap();

        let backend: Arc<dyn BlobBackend> =
            Arc::new(LocalBackend::new(backend_dir.path().to_path_buf()));
        let cached = CachedBlobDevice::open(blob_id, cache_dir.path(), backend).unwrap();

        let mut buf = vec![0u8; 1024];
        cached.read_into(0, 512, &mut buf).unwrap();

        assert_eq!(buf, payload[512..1536]);
        assert!(cached.chunkmap.is_ready(0).unwrap());
    }

    #[test]
    fn cached_blob_device_reads_biased_source_offsets() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x3du8; 4096];
        let blob_id = sha256_bytes(&payload);
        let mut full_blob = vec![0u8; 8192];
        let sb = ErofsSuperblock::new(0, 0, 0, 0, 0, 2, 1, 0, 0, &[0u8; 16]);
        let sb_start = EROFS_SUPER_OFFSET as usize;
        let sb_end = sb_start + sb.as_bytes().len();
        full_blob[sb_start..sb_end].copy_from_slice(sb.as_bytes());
        full_blob.extend_from_slice(&payload);

        fs::write(backend_dir.path().join("full-blob.bin"), &full_blob).unwrap();
        BlobMeta::from_chunks(
            blob_id,
            vec![BlobMetaChunk::new(0, 4096, 8192, 4096).unwrap()],
        )
        .save(
            &backend_dir
                .path()
                .join(format!("{}.blob.meta", hex_string(&blob_id))),
        )
        .unwrap();

        let backend: Arc<dyn BlobBackend> =
            Arc::new(LocalBackend::new(backend_dir.path().to_path_buf()));
        let cached = CachedBlobDevice::open(blob_id, cache_dir.path(), backend).unwrap();

        let mut buf = vec![0u8; 512];
        cached.read_into(8192, 256, &mut buf).unwrap();

        assert_eq!(buf, payload[256..768]);
        assert!(cached.chunkmap.is_ready(0).unwrap());
    }
}
