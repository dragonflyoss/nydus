use std::io;
use std::sync::{Arc, Mutex};

use crate::metadata::{BlobMeta, EROFS_BLOB_ID_SIZE};
use crate::storage::backend::BlobBackend;

use super::{
    chunks_for_range, fetch_decode_validate_into, range_in_chunk, BlobCache, BlobCacheBuffers,
};

pub struct DummyBlobCache {
    blob_id: [u8; EROFS_BLOB_ID_SIZE],
    blobmeta: BlobMeta,
    backend: Arc<dyn BlobBackend>,
    buffers: Mutex<BlobCacheBuffers>,
}

impl DummyBlobCache {
    pub fn open(
        blob_id: [u8; EROFS_BLOB_ID_SIZE],
        backend: Arc<dyn BlobBackend>,
    ) -> io::Result<Self> {
        let blobmeta = backend.load_blob_meta(&blob_id)?;
        Ok(Self {
            blob_id,
            blobmeta,
            backend,
            buffers: Mutex::new(BlobCacheBuffers::default()),
        })
    }
}

impl BlobCache for DummyBlobCache {
    fn read_at(&self, offset: u64, dst: &mut [u8]) -> io::Result<()> {
        if dst.is_empty() {
            return Ok(());
        }

        let chunks = chunks_for_range(&self.blobmeta, offset, dst.len())?;
        let mut logical_offset = offset;
        let mut dst_offset = 0usize;
        let mut buffers = self.buffers.lock().unwrap();

        for (_, chunk) in chunks {
            let decoded = fetch_decode_validate_into(
                &self.blob_id,
                &self.blobmeta,
                &self.backend,
                &chunk,
                &mut buffers,
            )?;
            let (chunk_offset, to_read) =
                range_in_chunk(&chunk, logical_offset, dst.len() - dst_offset);
            dst[dst_offset..dst_offset + to_read]
                .copy_from_slice(&decoded[chunk_offset..chunk_offset + to_read]);
            logical_offset += to_read as u64;
            dst_offset += to_read;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{
        BlobMeta, BlobMetaChunk, BlobMetaCompressor, BLOB_META_DEFAULT_CHUNK_SIZE,
    };
    use crate::storage::backend::LocalBackend;
    use crate::utils::{hex_string, sha256_bytes};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn dummy_blob_cache_fetches_and_validates_without_persistence() {
        let backend_dir = tempdir().unwrap();
        let payload = vec![0x7bu8; 4096];
        let blob_id = sha256_bytes(&payload);
        fs::write(backend_dir.path().join(hex_string(&blob_id)), &payload).unwrap();
        let chunk = BlobMetaChunk::new(
            0,
            4096,
            0,
            4096,
            *blake3::hash(&payload).as_bytes(),
            crc32c::crc32c(&payload),
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
        let cache = DummyBlobCache::open(blob_id, backend).unwrap();

        let mut buf = vec![0u8; 128];
        cache.read_at(64, &mut buf).unwrap();

        assert_eq!(buf, payload[64..192]);
    }

    #[test]
    fn dummy_blob_cache_rejects_backend_chunk_with_bad_crc32() {
        let backend_dir = tempdir().unwrap();
        let payload = vec![0xa5u8; 4096];
        let blob_id = sha256_bytes(&payload);
        fs::write(backend_dir.path().join(hex_string(&blob_id)), &payload).unwrap();
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
        let cache = DummyBlobCache::open(blob_id, backend).unwrap();

        let mut buf = vec![0u8; 128];
        let err = cache.read_at(64, &mut buf).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("crc32"));
    }

    #[test]
    fn dummy_blob_cache_skips_decompression_for_plain_zstd_chunk() {
        let backend_dir = tempdir().unwrap();
        let payload = vec![0x5du8; 4096];
        let blob_id = sha256_bytes(&payload);
        fs::write(backend_dir.path().join(hex_string(&blob_id)), &payload).unwrap();
        let chunk = BlobMetaChunk::new(
            0,
            4096,
            0,
            4096,
            *blake3::hash(&payload).as_bytes(),
            crc32c::crc32c(&payload),
        )
        .unwrap();
        BlobMeta::from_chunks_with_options(
            blob_id,
            BLOB_META_DEFAULT_CHUNK_SIZE,
            BlobMetaCompressor::Zstd,
            vec![chunk],
        )
        .unwrap()
        .save(
            &backend_dir
                .path()
                .join(format!("{}.blob.meta", hex_string(&blob_id))),
        )
        .unwrap();

        let backend: Arc<dyn BlobBackend> =
            Arc::new(LocalBackend::new(backend_dir.path().to_path_buf()));
        let cache = DummyBlobCache::open(blob_id, backend).unwrap();

        let mut buf = vec![0u8; 128];
        cache.read_at(64, &mut buf).unwrap();

        assert_eq!(buf, payload[64..192]);
    }
}
