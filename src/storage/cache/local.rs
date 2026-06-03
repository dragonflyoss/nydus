use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::metadata::{BlobMeta, BlobMetaGroup, BLOB_META_DEFAULT_CHUNK_SIZE, EROFS_BLOB_ID_SIZE};
use crate::storage::backend::BlobBackend;
use crate::storage::groupmap::GroupMap;
use crate::utils::hex_string;

use super::{
    chunks_for_range, decode_group_from_window, fetch_decode_validate_group_into,
    plan_prefetch_batches, range_in_chunk, BlobCache, BlobCacheBuffers,
};

pub struct LocalBlobCache {
    blob_id: [u8; EROFS_BLOB_ID_SIZE],
    groupmap: GroupMap,
    blob_meta: BlobMeta,
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
        let blob_meta_path = cache_dir.join(format!("{}.blob.meta", cache_key_hex));
        let blob_meta = load_cached_blob_meta(blob_id, cache_dir, &blob_meta_path, &backend)?;

        let cache_blob_path = cache_dir.join(format!("{}.blob.data", cache_key_hex));

        let groupmap_path = cache_dir.join(format!("{}.groupmap", cache_key_hex));
        let groupmap = GroupMap::open(&groupmap_path, blob_meta.group_count())?;

        Ok(Self {
            blob_id,
            groupmap,
            blob_meta,
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
        file.set_len(self.blob_meta.cache_size())?;
        *cache_file = Some(file.clone());
        Ok(file)
    }

    fn ensure_group(
        &self,
        group_index: usize,
        group: &BlobMetaGroup,
        cache_file: &File,
    ) -> io::Result<()> {
        if self.groupmap.is_ready(group_index)? {
            return Ok(());
        }

        let _guard = self.fetch_lock.lock().unwrap();
        if self.groupmap.is_ready(group_index)? {
            return Ok(());
        }

        let mut buffers = self.buffers.lock().unwrap();
        let decoded = fetch_decode_validate_group_into(
            &self.blob_id,
            &self.blob_meta,
            &self.backend,
            group,
            &mut buffers,
        )?;
        write_all_at(cache_file, group.uncompressed_byte_offset(), decoded)?;
        self.groupmap.set_ready(group_index)
    }
}

impl BlobCache for LocalBlobCache {
    fn prefetch_all(&self) -> io::Result<()> {
        let groups = self.blob_meta.groups();
        if groups.is_empty() {
            return Ok(());
        }

        let cache_file = self.cache_file()?;
        // Prefetch owns its decode buffers and does not take `fetch_lock`, so it
        // never blocks on-demand FUSE reads. The groupmap is internally locked
        // and `set_ready` is idempotent, so racing with a read at worst decodes
        // the same group twice into identical bytes at the same cache offset.
        let mut decoded = Vec::new();
        let mut window = Vec::new();

        for batch in plan_prefetch_batches(groups, BLOB_META_DEFAULT_CHUNK_SIZE as u64) {
            if batch
                .clone()
                .map(|index| self.groupmap.is_ready(index))
                .collect::<io::Result<Vec<_>>>()?
                .into_iter()
                .all(|ready| ready)
            {
                continue;
            }

            let window_base = groups[batch.start].compressed_byte_offset();
            let window_end = groups[batch.end - 1].compressed_byte_end();
            let window_len = usize::try_from(window_end - window_base).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "blob prefetch window size exceeds usize",
                )
            })?;
            window.resize(window_len, 0);
            self.backend
                .read_range_into(&self.blob_id, window_base, &mut window)?;

            for index in batch {
                if self.groupmap.is_ready(index)? {
                    continue;
                }
                let group = &groups[index];
                decode_group_from_window(
                    &self.blob_meta,
                    group,
                    window_base,
                    &window,
                    &mut decoded,
                )?;
                write_all_at(
                    cache_file.as_ref(),
                    group.uncompressed_byte_offset(),
                    &decoded,
                )?;
                self.groupmap.set_ready(index)?;
            }
        }

        Ok(())
    }

    fn read_at(&self, offset: u64, dst: &mut [u8]) -> io::Result<()> {
        if dst.is_empty() {
            return Ok(());
        }

        let chunks = chunks_for_range(&self.blob_meta, offset, dst.len())?;
        let cache_file = self.cache_file()?;
        let mut logical_offset = offset;
        let mut dst_offset = 0usize;

        for (chunk_index, chunk) in chunks {
            let group_index = chunk.group_index() as usize;
            let group = *self.blob_meta.group_at(group_index).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "blob meta group not found")
            })?;
            self.ensure_group(group_index, &group, cache_file.as_ref())?;
            let (chunk_offset, to_read) = range_in_chunk(
                &self.blob_meta,
                chunk_index,
                &chunk,
                logical_offset,
                dst.len() - dst_offset,
            );
            read_exact_at(
                cache_file.as_ref(),
                group.uncompressed_byte_offset()
                    + chunk.group_uncompressed_byte_offset()
                    + chunk_offset as u64,
                &mut dst[dst_offset..dst_offset + to_read],
            )?;
            logical_offset += to_read as u64;
            dst_offset += to_read;
        }

        Ok(())
    }
}

fn load_cached_blob_meta(
    blob_id: [u8; EROFS_BLOB_ID_SIZE],
    cache_dir: &Path,
    blob_meta_path: &Path,
    backend: &Arc<dyn BlobBackend>,
) -> io::Result<BlobMeta> {
    if !blob_meta_path.is_file() {
        let tmp_path = cache_dir.join(format!(".blob-meta-{}.tmp", Uuid::new_v4()));
        backend.download_blob_meta(&blob_id, &tmp_path)?;
        if let Err(err) = BlobMeta::load_checked_crc32_with_blob_id(&tmp_path, blob_id) {
            let _ = fs::remove_file(&tmp_path);
            return Err(io::Error::other(err));
        }
        fs::rename(&tmp_path, blob_meta_path)?;
    }

    BlobMeta::load_checked_crc32_with_blob_id(blob_meta_path, blob_id).map_err(io::Error::other)
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
    use crate::metadata::{
        BlobFooter, BlobMetaChunk, BlobMetaGroup, ErofsSuperblock, EROFS_BLOCK_SIZE,
        EROFS_SUPER_OFFSET,
    };
    use crate::storage::backend::LocalBackend;
    use crate::utils::sha256_bytes;
    use std::io::Write;
    use tempfile::tempdir;

    fn blob_meta(blob_id: [u8; EROFS_BLOB_ID_SIZE], payload: &[u8]) -> BlobMeta {
        blob_meta_with_crc32(blob_id, payload, crc32c::crc32c(payload))
    }

    fn blob_meta_with_crc32(
        blob_id: [u8; EROFS_BLOB_ID_SIZE],
        payload: &[u8],
        crc32: u32,
    ) -> BlobMeta {
        BlobMeta::from_parts(
            blob_id,
            1,
            vec![BlobMetaGroup::new(0, 1, 0, 4096, crc32).unwrap()],
            vec![BlobMetaChunk::new(*blake3::hash(payload).as_bytes(), 0, 0, 1).unwrap()],
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
        blob_meta(blob_id, &payload)
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
        assert!(cached.groupmap.is_ready(0).unwrap());
    }

    #[test]
    fn local_blob_cache_rejects_bad_blob_meta_header_crc32() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0xbdu8; 4096];
        let blob_id = sha256_bytes(&payload);
        let blob_path = backend_dir.path().join(hex_string(&blob_id));
        let blob_meta_path = backend_dir
            .path()
            .join(format!("{}.blob.meta", hex_string(&blob_id)));
        fs::write(&blob_path, &payload).unwrap();
        blob_meta(blob_id, &payload).save(&blob_meta_path).unwrap();
        let mut raw = fs::read(&blob_meta_path).unwrap();
        raw[8] ^= 0xff;
        fs::write(&blob_meta_path, raw).unwrap();

        let backend: Arc<dyn BlobBackend> =
            Arc::new(LocalBackend::new(backend_dir.path().to_path_buf()));
        let err = match LocalBlobCache::open(blob_id, cache_dir.path(), backend) {
            Ok(_) => panic!("corrupted blob meta crc32 should be rejected"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(err.to_string().contains("crc32"));
        assert!(!cache_dir
            .path()
            .join(format!("{}.blob.meta", hex_string(&blob_id)))
            .exists());
    }

    #[test]
    fn local_blob_cache_rejects_bad_crc32_before_marking_chunk_ready() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0xacu8; 4096];
        let blob_id = sha256_bytes(&payload);
        let blob_path = backend_dir.path().join(hex_string(&blob_id));
        fs::write(&blob_path, &payload).unwrap();
        blob_meta_with_crc32(blob_id, &payload, crc32c::crc32c(&payload).wrapping_add(1))
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
        assert!(!cached.groupmap.is_ready(0).unwrap());
    }

    #[test]
    fn local_blob_cache_reads_data_region_relative_compressed_offsets() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let payload = vec![0x3du8; 4096];
        let blob_id = sha256_bytes(&payload);
        let mut bootstrap = vec![0u8; 8192];
        let sb = ErofsSuperblock::new(0, 0, 0, 0, 0, 2, 1, 0, 0, &[0u8; 16]);
        let sb_start = EROFS_SUPER_OFFSET as usize;
        let sb_end = sb_start + sb.as_bytes().len();
        bootstrap[sb_start..sb_end].copy_from_slice(sb.as_bytes());

        let blob_meta = blob_meta(blob_id, &payload);
        let footer = BlobFooter::new(
            0,
            payload.len() as u64,
            payload.len() as u64,
            (bootstrap.len() as u64 / EROFS_BLOCK_SIZE as u64) as u32,
            payload.len() as u64 + bootstrap.len() as u64,
            (blob_meta.metadata_size() / EROFS_BLOCK_SIZE as u64) as u32,
        )
        .unwrap();

        let mut full_blob = Vec::new();
        full_blob.write_all(&payload).unwrap();
        full_blob.write_all(&bootstrap).unwrap();
        blob_meta.write_to(&mut full_blob).unwrap();
        footer.write_to(&mut full_blob).unwrap();
        let full_blob_id = sha256_bytes(&full_blob);

        fs::write(
            backend_dir.path().join(hex_string(&full_blob_id)),
            &full_blob,
        )
        .unwrap();

        let backend: Arc<dyn BlobBackend> =
            Arc::new(LocalBackend::new(backend_dir.path().to_path_buf()));
        let cached = LocalBlobCache::open(blob_id, cache_dir.path(), backend).unwrap();

        let mut buf = vec![0u8; 512];
        cached.read_at(256, &mut buf).unwrap();

        assert_eq!(buf, payload[256..768]);
        assert!(cached.groupmap.is_ready(0).unwrap());
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
            .join(format!("{}.groupmap", hex_string(&full_blob_id)))
            .is_file());
        assert!(!cache_dir
            .path()
            .join(format!("{}.blob.data", hex_string(&blob_id)))
            .exists());
    }
}
