use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::metadata::{BlobMeta, BlobMetaChunk, EROFS_BLOB_ID_SIZE};
use crate::storage::backend::BlobBackend;
use crate::storage::chunkmap::ChunkMap;
use crate::utils::hex_string;

use super::{
    chunks_for_range, fetch_decode_validate_into, range_in_chunk, BlobCache, BlobCacheBuffers,
};

pub struct LocalBlobCache {
    blob_id: [u8; EROFS_BLOB_ID_SIZE],
    chunkmap: ChunkMap,
    blobmeta: BlobMeta,
    cache_blob_path: PathBuf,
    cache_file: Mutex<Option<Arc<File>>>,
    backend: Arc<dyn BlobBackend>,
    fetch_lock: Mutex<()>,
    buffers: Mutex<BlobCacheBuffers>,
}

impl LocalBlobCache {
    pub fn open(
        blob_id: [u8; EROFS_BLOB_ID_SIZE],
        cache_dir: &Path,
        backend: Arc<dyn BlobBackend>,
    ) -> io::Result<Self> {
        fs::create_dir_all(cache_dir)?;

        let cache_key = backend.cache_key(&blob_id)?;
        let cache_key_hex = hex_string(&cache_key);
        let blobmeta_path = cache_dir.join(format!("{}.blob.meta", cache_key_hex));
        let blobmeta = if blobmeta_path.is_file() {
            BlobMeta::load_with_blob_id(&blobmeta_path, blob_id).map_err(io::Error::other)?
        } else {
            let blobmeta = backend.load_blob_meta(&blob_id)?;
            blobmeta.save(&blobmeta_path).map_err(io::Error::other)?;
            BlobMeta::load_with_blob_id(&blobmeta_path, blob_id).map_err(io::Error::other)?
        };

        let cache_blob_path = cache_dir.join(format!("{}.blob.data", cache_key_hex));

        let chunkmap_path = cache_dir.join(format!("{}.chunkmap", cache_key_hex));
        let chunkmap = ChunkMap::open(&chunkmap_path, blobmeta.chunk_count())?;

        Ok(Self {
            blob_id,
            chunkmap,
            blobmeta,
            cache_blob_path,
            cache_file: Mutex::new(None),
            backend,
            fetch_lock: Mutex::new(()),
            buffers: Mutex::new(BlobCacheBuffers::default()),
        })
    }

    fn cache_file(&self) -> io::Result<Arc<File>> {
        let mut cache_file = self.cache_file.lock().unwrap();
        if let Some(file) = cache_file.as_ref() {
            return Ok(file.clone());
        }

        let file = Arc::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&self.cache_blob_path)?,
        );
        file.set_len(self.blobmeta.cache_size())?;
        *cache_file = Some(file.clone());
        Ok(file)
    }

    fn ensure_chunk(
        &self,
        chunk_index: usize,
        chunk: &BlobMetaChunk,
        cache_file: &File,
    ) -> io::Result<()> {
        if self.chunkmap.is_ready(chunk_index)? {
            return Ok(());
        }

        let _guard = self.fetch_lock.lock().unwrap();
        if self.chunkmap.is_ready(chunk_index)? {
            return Ok(());
        }

        let mut buffers = self.buffers.lock().unwrap();
        let decoded = fetch_decode_validate_into(
            &self.blob_id,
            &self.blobmeta,
            &self.backend,
            chunk,
            &mut buffers,
        )?;
        write_all_at(cache_file, chunk.uncompressed_offset(), decoded)?;
        self.chunkmap.set_ready(chunk_index)
    }
}

impl BlobCache for LocalBlobCache {
    fn read_at(&self, offset: u64, dst: &mut [u8]) -> io::Result<()> {
        if dst.is_empty() {
            return Ok(());
        }

        let chunks = chunks_for_range(&self.blobmeta, offset, dst.len())?;
        let cache_file = self.cache_file()?;
        let mut logical_offset = offset;
        let mut dst_offset = 0usize;

        for (chunk_index, chunk) in chunks {
            self.ensure_chunk(chunk_index, &chunk, cache_file.as_ref())?;
            let (chunk_offset, to_read) =
                range_in_chunk(&chunk, logical_offset, dst.len() - dst_offset);
            read_exact_at(
                cache_file.as_ref(),
                chunk.uncompressed_offset() + chunk_offset as u64,
                &mut dst[dst_offset..dst_offset + to_read],
            )?;
            logical_offset += to_read as u64;
            dst_offset += to_read;
        }

        Ok(())
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
    fn local_blob_cache_fetches_from_local_backend() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0xceu8; 4096];
        let blob_id = sha256_bytes(&payload);
        let blob_path = backend_dir.path().join(hex_string(&blob_id));
        fs::write(&blob_path, &payload).unwrap();
        BlobMeta::from_chunks(blob_id, vec![blobmeta_chunk(0, 4096, 0, 4096, &payload)])
            .save(
                &backend_dir
                    .path()
                    .join(format!("{}.blob.meta", hex_string(&blob_id))),
            )
            .unwrap();

        let backend: Arc<dyn BlobBackend> =
            Arc::new(LocalBackend::new(backend_dir.path().to_path_buf()));
        let cached = LocalBlobCache::open(blob_id, cache_dir.path(), backend).unwrap();

        let mut buf = vec![0u8; 1024];
        cached.read_at(512, &mut buf).unwrap();

        assert_eq!(buf, payload[512..1536]);
        assert!(cached.chunkmap.is_ready(0).unwrap());
    }

    #[test]
    fn local_blob_cache_rejects_bad_crc32_before_marking_chunk_ready() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0xacu8; 4096];
        let blob_id = sha256_bytes(&payload);
        let blob_path = backend_dir.path().join(hex_string(&blob_id));
        fs::write(&blob_path, &payload).unwrap();
        let chunk = BlobMetaChunk::new(
            0,
            4096,
            0,
            4096,
            *blake3::hash(&payload).as_bytes(),
            crc32c::crc32c(&payload).wrapping_add(1),
        )
        .unwrap();
        BlobMeta::from_chunks(blob_id, vec![chunk])
            .save(
                &backend_dir
                    .path()
                    .join(format!("{}.blob.meta", hex_string(&blob_id))),
            )
            .unwrap();

        let backend: Arc<dyn BlobBackend> =
            Arc::new(LocalBackend::new(backend_dir.path().to_path_buf()));
        let cached = LocalBlobCache::open(blob_id, cache_dir.path(), backend).unwrap();

        let mut buf = vec![0u8; 1024];
        let err = cached.read_at(512, &mut buf).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("crc32"));
        assert!(!cached.chunkmap.is_ready(0).unwrap());
    }

    #[test]
    fn local_blob_cache_reads_biased_compressed_offsets() {
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
        let full_blob_id = sha256_bytes(&full_blob);

        fs::write(
            backend_dir.path().join(hex_string(&full_blob_id)),
            &full_blob,
        )
        .unwrap();
        BlobMeta::from_chunks(blob_id, vec![blobmeta_chunk(0, 4096, 8192, 4096, &payload)])
            .save(
                &backend_dir
                    .path()
                    .join(format!("{}.blob.meta", hex_string(&full_blob_id))),
            )
            .unwrap();

        let backend: Arc<dyn BlobBackend> =
            Arc::new(LocalBackend::new(backend_dir.path().to_path_buf()));
        let cached = LocalBlobCache::open(blob_id, cache_dir.path(), backend).unwrap();

        let mut buf = vec![0u8; 512];
        cached.read_at(256, &mut buf).unwrap();

        assert_eq!(buf, payload[256..768]);
        assert!(cached.chunkmap.is_ready(0).unwrap());
        assert!(cache_dir
            .path()
            .join(format!("{}.blob.data", hex_string(&full_blob_id)))
            .is_file());
        assert!(cache_dir
            .path()
            .join(format!("{}.blob.meta", hex_string(&full_blob_id)))
            .is_file());
        assert!(cache_dir
            .path()
            .join(format!("{}.chunkmap", hex_string(&full_blob_id)))
            .is_file());
        assert!(!cache_dir
            .path()
            .join(format!("{}.blob.data", hex_string(&blob_id)))
            .exists());
    }
}
