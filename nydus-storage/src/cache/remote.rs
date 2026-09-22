//! Diskless blob access: every read fetches, decodes, and validates the
//! chunk groups it touches from the backend directly, holding the bytes
//! only in memory. Selected when no storage directory is configured.
//! Repeated reads of the same group fetch it again — the kernel page cache
//! above the mount is the only reuse layer. Modes that hand a cache file to
//! the kernel (fanotify, NBD, ublk, userfaultfd, virtio-pmem) cannot run
//! diskless and reject this mode through the file-oriented [`BlobCache`]
//! defaults.

use std::io;
use std::sync::Arc;

use nydus_backend::{BlobBackend, ReadContext, ReadKind};
use nydus_format::blob::BlobMetadata;
use nydus_format::utils::SHA256_DIGEST_SIZE;

use super::{
    decode_chunk_group_into, validate_chunk_group_with_metrics, BlobCache, ChunkGroupBuffers,
};

/// A diskless blob cache: reads are served straight from the backend with
/// nothing written to disk.
pub struct RemoteBlobCache {
    blob_id: [u8; SHA256_DIGEST_SIZE],
    blob_metadata: BlobMetadata,
    backend: Arc<dyn BlobBackend>,
}

impl RemoteBlobCache {
    /// Open the blob's metadata from the backend; no local file is created.
    pub fn open(
        blob_id: [u8; SHA256_DIGEST_SIZE],
        backend: Arc<dyn BlobBackend>,
    ) -> io::Result<Self> {
        let blob_metadata = backend.blob_metadata(&blob_id)?;
        Ok(Self {
            blob_id,
            blob_metadata,
            backend,
        })
    }
}

/// Only the dense read path is supported; every file-oriented operation
/// keeps the trait's `Unsupported` default.
impl BlobCache for RemoteBlobCache {
    fn read_at(&self, offset: u64, dst: &mut [u8]) -> io::Result<()> {
        if dst.is_empty() {
            return Ok(());
        }
        let end = offset.checked_add(dst.len() as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob read range overflow")
        })?;
        let not_found = || io::Error::new(io::ErrorKind::NotFound, "blob chunk group not found");
        let meta = &self.blob_metadata;
        let first = meta.chunk_group_index_of(offset).ok_or_else(not_found)?;
        let last = meta.chunk_group_index_of(end - 1).ok_or_else(not_found)?;
        let head = meta.chunk_group(first).expect("group within the table");
        let tail = meta.chunk_group(last).expect("group within the table");

        // The touched groups are consecutive in the blob: one read covers
        // them all, then each decodes on its own (into a group-span-sized
        // scratch, which no group's payload exceeds).
        let encoded_len = usize::try_from(tail.compressed_range().end - head.compressed_offset())
            .map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "group span exceeds usize")
        })?;
        let decoded_len = meta.group_span() as usize;
        let mut buffers = ChunkGroupBuffers::default();
        let (encoded, decoded) = buffers.resize_pair(encoded_len, decoded_len)?;
        self.backend.read_range_into(
            &self.blob_id,
            head.compressed_offset(),
            encoded,
            ReadContext::chunk_group(
                ReadKind::OnDemand,
                head.uncompressed_offset(),
                tail.uncompressed_range().end - head.uncompressed_offset(),
            ),
        )?;

        dst.fill(0);
        for index in first..=last {
            let group = meta.chunk_group(index).expect("group within the table");
            let start = (group.compressed_offset() - head.compressed_offset()) as usize;
            let stop = start + group.compressed_size() as usize;
            let payload: &[u8] = if meta.is_plain(&group) {
                &encoded[start..stop]
            } else {
                let out = &mut decoded[..meta.payload_size(&group) as usize];
                decode_chunk_group_into(meta.compressor(), &encoded[start..stop], out)?;
                out
            };
            validate_chunk_group_with_metrics(&self.backend, meta, &group, payload)?;
            meta.for_each_decoded_chunk(index, payload, &mut |chunk_offset, bytes| {
                let copy_start = offset.max(chunk_offset);
                let copy_end = end.min(chunk_offset + bytes.len() as u64);
                if copy_start < copy_end {
                    let source_start = (copy_start - chunk_offset) as usize;
                    let target_start = (copy_start - offset) as usize;
                    let length = (copy_end - copy_start) as usize;
                    dst[target_start..target_start + length]
                        .copy_from_slice(&bytes[source_start..source_start + length]);
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    fn prefetch_all(
        &self,
        _workers: usize,
        _deadline: Option<std::time::Instant>,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "prefetch requires a storage directory: diskless reads have no cache to warm",
        ))
    }

    fn is_redirect(&self) -> bool {
        self.blob_metadata.is_redirect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_util::{encode_blob, padded_image};
    use super::*;
    use nydus_backend::Local;
    use nydus_format::blob::BlobMetadataCompressor;
    use nydus_format::utils::write_minimal_full_blob;
    use tempfile::tempdir;

    #[test]
    fn remote_blob_cache_reads_without_touching_disk() {
        let backend_dir = tempdir().unwrap();
        let payload = vec![0xabu8; 4096];
        let (data, meta) = encode_blob(
            BlobMetadataCompressor::None,
            4096,
            &[vec![payload.clone()]],
            false,
        );
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &data, &meta, true);

        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));
        let remote = RemoteBlobCache::open(full_blob_id, backend).unwrap();

        let mut buf = vec![0u8; 1024];
        remote.read_at(512, &mut buf).unwrap();
        assert_eq!(buf, payload[512..1536]);

        // No cache file exists anywhere: the backend directory still holds
        // only the blob source files it started with.
        let entries: Vec<_> = std::fs::read_dir(backend_dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".blob.data"))
            .collect();
        assert!(entries.is_empty());
    }

    #[test]
    fn remote_reads_dense_chunks_and_padding_across_groups() {
        let backend_dir = tempdir().unwrap();
        // Two zstd groups of sub-block chunks, so reads cross chunk padding,
        // a group's zero tail and the group boundary (the first group's
        // chunks take 1 + 2 + 1 blocks, so the second starts at block 4).
        let groups = vec![
            vec![vec![0xabu8; 100], vec![0xcdu8; 5000], vec![0xefu8; 1]],
            vec![vec![0x12u8; 4097]],
        ];
        let (data, meta) = encode_blob(BlobMetadataCompressor::Zstd, 16384, &groups, true);
        let image = padded_image(&groups);
        assert_eq!(image.len(), 6 * 4096);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &data, &meta, true);
        let backend = Arc::new(Local::new(backend_dir.path().to_path_buf()));
        let remote = RemoteBlobCache::open(full_blob_id, backend).unwrap();
        let mut all = vec![0xffu8; image.len()];
        remote.read_at(0, &mut all).unwrap();
        assert_eq!(all, image);
        let mut bytes = [0xff; 3];
        remote.read_at(4 * 4096 - 1, &mut bytes).unwrap();
        assert_eq!(bytes, [0, 0x12, 0x12]);
        remote.read_at(99, &mut bytes).unwrap();
        assert_eq!(bytes, [0xab, 0, 0]);
        assert!(remote.read_at(image.len() as u64 - 1, &mut bytes).is_err());
    }

    #[test]
    fn remote_blob_cache_rejects_file_oriented_operations() {
        let backend_dir = tempdir().unwrap();
        let payload = vec![0x11u8; 4096];
        let (data, meta) = encode_blob(BlobMetadataCompressor::None, 4096, &[vec![payload]], false);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &data, &meta, true);

        let backend: Arc<dyn BlobBackend> = Arc::new(Local::new(backend_dir.path().to_path_buf()));
        let remote = RemoteBlobCache::open(full_blob_id, backend).unwrap();

        assert_eq!(
            remote.prepare().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            remote.cache_fd().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            remote.prefetch_all(1, None).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert!(!remote.is_redirect());
    }
}
