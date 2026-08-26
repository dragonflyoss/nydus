//! Diskless blob access: every read fetches, decodes, and validates its
//! block groups from the backend directly, holding the bytes only in memory.
//! Selected when no storage directory is configured. Repeated reads of the
//! same block group fetch it again — the kernel page cache above the mount is the
//! only reuse layer. Modes that hand a cache file to the kernel (fanotify,
//! NBD, ublk, userfaultfd, virtio-pmem) cannot run diskless and reject this
//! mode through the file-oriented [`BlobCache`] defaults.

use std::io;
use std::sync::Arc;

use nydus_backend::{BlobBackend, ReadKind};
use nydus_format::blob::BlobMetadata;
use nydus_format::utils::SHA256_DIGEST_SIZE;

use super::{fetch_decode_validate_block_group_into, BlobCache, BlockGroupBuffers};

/// A diskless blob cache: reads are served straight from the backend with
/// nothing written to disk.
pub struct RemoteBlobCache {
    blob_id: [u8; SHA256_DIGEST_SIZE],
    blob_metadata: BlobMetadata,
    backend: Arc<dyn BlobBackend>,
}

/// Implement RemoteBlobCache.
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

/// Implement the BlobCache trait for RemoteBlobCache. Only the dense read
/// path is supported; every file-oriented operation keeps the trait's
/// `Unsupported` default.
impl BlobCache for RemoteBlobCache {
    fn read_at(&self, offset: u64, dst: &mut [u8]) -> io::Result<()> {
        if dst.is_empty() {
            return Ok(());
        }
        // Redirect (ondemand) blobs have a non-uniform block group layout and no
        // dense readable address space, exactly as in the local cache.
        if self.blob_metadata.is_redirect() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "redirect blob has no dense readable address space",
            ));
        }

        let end = offset.checked_add(dst.len() as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob read range overflow")
        })?;
        let first = self
            .blob_metadata
            .block_group_index_from_uncompressed_offset(offset)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "blob meta block group not found")
            })?;
        let last = self
            .blob_metadata
            .block_group_index_from_uncompressed_offset(end - 1)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "blob meta block group not found")
            })?;

        let mut buffers = BlockGroupBuffers::default();
        for block_group_index in first..=last {
            let block_group = *self
                .blob_metadata
                .block_group(block_group_index)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "blob meta block group not found",
                    )
                })?;
            let decoded = fetch_decode_validate_block_group_into(
                &self.blob_id,
                &self.blob_metadata,
                &self.backend,
                &block_group,
                &mut buffers,
                ReadKind::OnDemand,
            )?;

            // Copy the overlap between this block group's span and the request.
            let block_group_start = block_group.uncompressed_offset();
            let copy_start = offset.max(block_group_start);
            let copy_end = end.min(block_group_start + block_group.uncompressed_size());
            let source = &decoded[(copy_start - block_group_start) as usize..]
                [..(copy_end - copy_start) as usize];
            let dst_start = (copy_start - offset) as usize;
            dst[dst_start..dst_start + source.len()].copy_from_slice(source);
        }
        Ok(())
    }

    fn prefetch_all(&self, _deadline: Option<std::time::Instant>) -> io::Result<()> {
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
    use super::*;
    use nydus_backend::Local;
    use nydus_format::blob::{BlobMetadataBlockGroup, BlobMetadataChunk, BlobMetadataCompressor};
    use nydus_format::utils::write_minimal_full_blob;
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

    #[test]
    fn remote_blob_cache_reads_without_touching_disk() {
        let backend_dir = tempdir().unwrap();
        let payload = vec![0xabu8; 4096];
        let meta = blob_metadata(&payload);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, true);

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
    fn remote_blob_cache_rejects_file_oriented_operations() {
        let backend_dir = tempdir().unwrap();
        let payload = vec![0x11u8; 4096];
        let meta = blob_metadata(&payload);
        let full_blob_id = write_minimal_full_blob(backend_dir.path(), &payload, &meta, true);

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
            remote.prefetch_all(None).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
}
