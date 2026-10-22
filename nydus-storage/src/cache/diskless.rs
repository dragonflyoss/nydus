//! The diskless blob cache: reads fetch, decode and verify the chunk groups
//! they touch from the backend and hold the bytes in memory only.
//!
//! Selected when no storage directory is configured. The recently decoded
//! chunk groups are kept in a bounded in-memory LRU, one budget per blob
//! set, so a run of small reads within a chunk group, a tar export pulling
//! 8 KiB at a time or FUSE's 128 KiB requests, fetches and decodes it once
//! instead of once per read. The modes that hand a cache file to the kernel
//! cannot run diskless and are rejected through the file-oriented
//! [`BlobCache`] defaults.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use nydus_backend::Backend;
use nydus_format::blob::{BlobMetadata, BlobMetadataChunkGroupExtent};
use nydus_format::utils::SHA256_DIGEST_SIZE;

use super::decode::{verify_chunk_group, ChunkGroupBuffer};
use super::BlobCache;

/// A blob's chunk group: the blob id and the chunk group's table index.
type ChunkGroupKey = ([u8; SHA256_DIGEST_SIZE], u32);

/// A chunk group's uncompressed bytes, verified against their crc32c.
struct DecodedChunkGroup {
    /// The buffer holding the bytes.
    buffer: ChunkGroupBuffer,

    /// The number of bytes.
    len: usize,
}

/// Implements the decoded chunk group.
impl DecodedChunkGroup {
    /// Returns the bytes.
    fn bytes(&self) -> &[u8] {
        self.buffer.bytes(self.len)
    }
}

/// The bounded LRU of verified decoded chunk groups, shared by the diskless
/// caches of one blob set so the memory bound holds however many layers the
/// set mounts.
///
/// Blob data never changes under an id, so entries are never invalidated,
/// only evicted. Concurrent misses on one chunk group may both decode it;
/// the second insert is dropped.
pub(crate) struct DecodedChunkGroupCache {
    /// The most decoded bytes kept at once.
    max_bytes: usize,

    /// The most chunk groups kept at once, bounding the LRU scan.
    max_entries: usize,

    /// The entries, least recently used first.
    state: Mutex<DecodedChunkGroupState>,
}

/// The entries of the LRU and their size.
#[derive(Default)]
struct DecodedChunkGroupState {
    /// The entries, least recently used first.
    entries: VecDeque<(ChunkGroupKey, Arc<DecodedChunkGroup>)>,

    /// The decoded bytes of the entries.
    bytes: usize,
}

/// Implements the default cache, with the default limits.
impl Default for DecodedChunkGroupCache {
    fn default() -> Self {
        Self::with_limits(Self::DEFAULT_MAX_BYTES, Self::DEFAULT_MAX_ENTRIES)
    }
}

/// Implements the decoded chunk group cache.
impl DecodedChunkGroupCache {
    /// The default decoded bytes the diskless caches of one blob set keep in
    /// memory, 32 MiB.
    const DEFAULT_MAX_BYTES: usize = 32 * 1024 * 1024;

    /// The default most chunk groups kept at once.
    const DEFAULT_MAX_ENTRIES: usize = 128;

    /// Creates an empty cache keeping at most `max_bytes` decoded bytes and
    /// `max_entries` chunk groups.
    fn with_limits(max_bytes: usize, max_entries: usize) -> Self {
        Self {
            max_bytes,
            max_entries,
            state: Mutex::default(),
        }
    }

    /// Returns whether a chunk group of `len` decoded bytes is kept: at most
    /// a quarter of the budget, which admits the largest chunk group of the
    /// default layout, four times the 2 MiB minimum, without flushing
    /// everything else.
    fn admits(&self, len: usize) -> bool {
        len <= self.max_bytes / 4
    }

    /// Returns the chunk group of `key`, now the most recently used.
    fn get(&self, key: &ChunkGroupKey) -> Option<Arc<DecodedChunkGroup>> {
        let mut state = self.state.lock().unwrap();
        let index = state.entries.iter().position(|(entry, _)| entry == key)?;
        let entry = state.entries.remove(index)?;
        let group = entry.1.clone();
        state.entries.push_back(entry);
        Some(group)
    }

    /// Inserts the chunk group of `key`, evicting the least recently used
    /// ones until it fits; a chunk group too large to admit or already
    /// present is dropped.
    fn insert(&self, key: ChunkGroupKey, group: DecodedChunkGroup) {
        if !self.admits(group.len) {
            return;
        }

        let mut state = self.state.lock().unwrap();
        if state.entries.iter().any(|(entry, _)| *entry == key) {
            return;
        }

        while state.bytes + group.len > self.max_bytes || state.entries.len() >= self.max_entries {
            match state.entries.pop_front() {
                Some((_, evicted)) => state.bytes -= evicted.len,
                None => break,
            }
        }

        state.bytes += group.len;
        state.entries.push_back((key, Arc::new(group)));
    }
}

/// A diskless blob cache: reads are served from the backend, or the blob
/// set's in-memory [`DecodedChunkGroupCache`], with nothing written to disk.
pub(crate) struct DisklessBlobCache {
    /// The blob id.
    blob_id: [u8; SHA256_DIGEST_SIZE],

    /// The blob's metadata: chunk groups, chunks, compressor.
    blob_metadata: BlobMetadata,

    /// The backend serving the blob.
    backend: Arc<dyn Backend>,

    /// The decoded chunk groups, shared with the other blobs of the set.
    decoded_chunk_groups: Arc<DecodedChunkGroupCache>,

    /// Skip the crc32c check of decoded chunk groups.
    skip_verify_checksums: bool,
}

/// Implements the diskless blob cache.
impl DisklessBlobCache {
    /// Creates the cache of the blob `blob_id` described by `blob_metadata`
    /// over `backend`, keeping its decoded chunk groups in
    /// `decoded_chunk_groups`, which the other blobs of the set share, and
    /// skipping their crc32c check when `skip_verify_checksums`.
    pub(crate) fn new(
        blob_id: [u8; SHA256_DIGEST_SIZE],
        blob_metadata: BlobMetadata,
        backend: Arc<dyn Backend>,
        decoded_chunk_groups: Arc<DecodedChunkGroupCache>,
        skip_verify_checksums: bool,
    ) -> Self {
        Self {
            blob_id,
            blob_metadata,
            backend,
            decoded_chunk_groups,
            skip_verify_checksums,
        }
    }
}

/// Copies the part of `group`'s chunks, cut out of its uncompressed
/// `payload`, that overlaps `[offset, offset + buf.len())` into `buf`.
fn copy_chunk_group_chunks(
    blob_metadata: &BlobMetadata,
    group: &BlobMetadataChunkGroupExtent,
    payload: &[u8],
    offset: u64,
    buf: &mut [u8],
) -> io::Result<()> {
    let end = offset + buf.len() as u64;
    for (chunk_offset, bytes) in group
        .chunks(blob_metadata, payload)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
    {
        let copy_start = offset.max(chunk_offset);
        let copy_end = end.min(chunk_offset + bytes.len() as u64);
        if copy_start >= copy_end {
            continue;
        }

        let source_start = (copy_start - chunk_offset) as usize;
        let target_start = (copy_start - offset) as usize;
        let length = (copy_end - copy_start) as usize;
        buf[target_start..target_start + length]
            .copy_from_slice(&bytes[source_start..source_start + length]);
    }

    Ok(())
}

/// Implements the blob cache over the backend alone: the dense read path,
/// every file-oriented operation keeping the trait's `Unsupported` default.
impl BlobCache for DisklessBlobCache {
    /// Fills `buf` from the decoded chunk groups kept in memory, the missed
    /// ones fetched in one backend read and decoded into buffers of their
    /// own that the cache keeps.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        let end = offset.checked_add(buf.len() as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob read range overflow")
        })?;
        let not_found = || io::Error::new(io::ErrorKind::NotFound, "blob chunk group not found");
        let blob_metadata = &self.blob_metadata;
        let first = blob_metadata
            .chunk_group_index(offset)
            .ok_or_else(not_found)?;
        let last = blob_metadata
            .chunk_group_index(end - 1)
            .ok_or_else(not_found)?;

        // Serve the cached chunk groups first; the cache lock covers the
        // lookup alone, the copy runs on the returned reference.
        buf.fill(0);
        let mut missed = Vec::new();
        for index in first..=last {
            let group = blob_metadata
                .chunk_group(index)
                .expect("chunk group index within the blob meta");
            match self
                .decoded_chunk_groups
                .get(&(self.blob_id, group.index()))
            {
                Some(cached) => {
                    copy_chunk_group_chunks(blob_metadata, &group, cached.bytes(), offset, buf)?
                }
                None => missed.push(group),
            }
        }

        let (Some(head), Some(tail)) = (missed.first(), missed.last()) else {
            return Ok(());
        };

        // The missed chunk groups lie between two table indexes, so one read
        // covers them all, and any cached chunk group in between, which is
        // not decoded again; each decodes into a buffer of its own that the
        // cache keeps.
        let encoded_len = usize::try_from(tail.compressed_range().end - head.compressed_offset())
            .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk group range exceeds usize",
            )
        })?;
        let mut encoded = ChunkGroupBuffer::default();
        let encoded = encoded.resize(encoded_len)?;
        self.backend
            .read_range_into(&self.blob_id, head.compressed_offset(), encoded)?;

        for group in &missed {
            let start = (group.compressed_offset() - head.compressed_offset()) as usize;
            let stop = start + group.compressed_size() as usize;
            let len = group.uncompressed_size() as usize;
            let mut decoded = ChunkGroupBuffer::default();
            let payload = decoded.resize(len)?;
            if group.is_uncompressed(blob_metadata) {
                payload.copy_from_slice(&encoded[start..stop]);
            } else {
                blob_metadata
                    .compressor()
                    .decompress_into(&encoded[start..stop], payload)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            }
            verify_chunk_group(group, payload, self.skip_verify_checksums)?;
            copy_chunk_group_chunks(blob_metadata, group, payload, offset, buf)?;
            if !self.decoded_chunk_groups.admits(len) {
                continue;
            }

            self.decoded_chunk_groups.insert(
                (self.blob_id, group.index()),
                DecodedChunkGroup {
                    buffer: decoded,
                    len,
                },
            );
        }

        Ok(())
    }

    /// Fails: diskless reads have no cache to warm.
    fn prefetch_all(&self, _workers: usize, _deadline: Option<Instant>) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "prefetch requires a storage directory: diskless reads have no cache to warm",
        ))
    }

    /// Returns whether the blob meta is a redirect table.
    fn is_ondemand(&self) -> bool {
        self.blob_metadata.is_ondemand()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_backend::Local;
    use nydus_format::blob::{BlobMetadataCompressor, BlobMetadataDigester};
    use nydus_telemetry::metrics::Metrics;
    use nydus_test_utils::blob::{uncompressed_data, FullBlob};
    use nydus_test_utils::metadata::from_chunk_groups;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tempfile::tempdir;

    struct Counting {
        inner: Local,
        reads: AtomicUsize,
        corrupt_next: AtomicBool,
    }

    impl Counting {
        fn new(dir: &Path) -> Arc<Self> {
            Arc::new(Self {
                inner: Local::new(dir.to_path_buf(), Arc::new(Metrics::new())),
                reads: AtomicUsize::new(0),
                corrupt_next: AtomicBool::new(false),
            })
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl Backend for Counting {
        fn metrics(&self) -> &Arc<Metrics> {
            self.inner.metrics()
        }

        fn read_blob_metadata(
            &self,
            blob_id: &[u8; SHA256_DIGEST_SIZE],
        ) -> io::Result<BlobMetadata> {
            self.inner.read_blob_metadata(blob_id)
        }

        fn read_range_into(
            &self,
            blob_id: &[u8; SHA256_DIGEST_SIZE],
            offset: u64,
            buf: &mut [u8],
        ) -> io::Result<()> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.read_range_into(blob_id, offset, buf)?;
            if self.corrupt_next.swap(false, Ordering::SeqCst) {
                buf[0] ^= 0xff;
            }
            Ok(())
        }
    }

    fn groups(count: u8) -> Vec<Vec<Vec<u8>>> {
        (0..count)
            .map(|group| {
                (0..2u8)
                    .map(|chunk| vec![group * 2 + chunk + 1; 4096])
                    .collect()
            })
            .collect()
    }

    fn open(
        dir: &Path,
        compressor: BlobMetadataCompressor,
        groups: &[Vec<Vec<u8>>],
        decoded_chunk_groups: Arc<DecodedChunkGroupCache>,
    ) -> (DisklessBlobCache, Arc<Counting>) {
        let (data, blob_metadata) = from_chunk_groups(compressor, 8192, groups, None);
        let blob_id = FullBlob::new(&data)
            .with_blob_metadata(&blob_metadata)
            .with_blob_metadata_file()
            .save_in(dir);
        let backend = Counting::new(dir);
        let remote = DisklessBlobCache::new(
            blob_id,
            backend.read_blob_metadata(&blob_id).unwrap(),
            backend.clone(),
            decoded_chunk_groups,
            false,
        );
        (remote, backend)
    }

    #[test]
    fn read_at_touches_no_disk() {
        let backend_dir = tempdir().unwrap();
        let payload = vec![0xabu8; 4096];
        let (remote, _) = open(
            backend_dir.path(),
            BlobMetadataCompressor::None,
            &[vec![payload.clone()]],
            Arc::default(),
        );

        let mut buf = vec![0u8; 1024];
        remote.read_at(512, &mut buf).unwrap();
        assert_eq!(buf, payload[512..1536]);

        let cache_files = std::fs::read_dir(backend_dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".blob.data"))
            .count();
        assert_eq!(cache_files, 0);
    }

    #[test]
    fn read_at_reads_dense_chunks_and_padding_across_chunk_groups() {
        let backend_dir = tempdir().unwrap();
        let groups = vec![
            vec![vec![0xabu8; 100], vec![0xcdu8; 5000], vec![0xefu8; 1]],
            vec![vec![0x12u8; 4097]],
        ];
        let (data, blob_metadata) = from_chunk_groups(
            BlobMetadataCompressor::Zstd,
            16384,
            &groups,
            Some(BlobMetadataDigester::Blake3),
        );
        let image = uncompressed_data(&groups);
        assert_eq!(image.len(), 6 * 4096);
        let blob_id = FullBlob::new(&data)
            .with_blob_metadata(&blob_metadata)
            .with_blob_metadata_file()
            .save_in(backend_dir.path());
        let backend = Arc::new(Local::new(
            backend_dir.path().to_path_buf(),
            Arc::new(Metrics::new()),
        ));
        let remote = DisklessBlobCache::new(
            blob_id,
            backend.read_blob_metadata(&blob_id).unwrap(),
            backend,
            Arc::default(),
            false,
        );

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
    fn the_file_oriented_operations_are_unsupported() {
        let backend_dir = tempdir().unwrap();
        let (remote, _) = open(
            backend_dir.path(),
            BlobMetadataCompressor::None,
            &groups(1),
            Arc::default(),
        );

        assert_eq!(
            remote.prepare().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            remote.cache_file().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            remote.prefetch_all(1, None).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert!(!remote.is_ondemand());
    }

    #[test]
    fn small_reads_within_a_chunk_group_fetch_it_once() {
        let test_cases = vec![BlobMetadataCompressor::None, BlobMetadataCompressor::Zstd];

        for compressor in test_cases {
            let dir = tempdir().unwrap();
            let groups = groups(3);
            let image = uncompressed_data(&groups);
            let (remote, backend) = open(dir.path(), compressor, &groups, Arc::default());
            for (index, expected) in image.chunks(1024).enumerate() {
                let mut buf = [0u8; 1024];
                remote.read_at(index as u64 * 1024, &mut buf).unwrap();
                assert_eq!(buf, expected);
            }
            assert_eq!(backend.reads(), 3, "{compressor:?}");

            let mut all = vec![0u8; image.len()];
            remote.read_at(0, &mut all).unwrap();
            assert_eq!(all, image);
            assert_eq!(backend.reads(), 3, "{compressor:?}");
        }
    }

    #[test]
    fn a_read_across_chunk_groups_fetches_only_the_missed_ones() {
        let dir = tempdir().unwrap();
        let groups = groups(3);
        let image = uncompressed_data(&groups);
        let (remote, backend) = open(
            dir.path(),
            BlobMetadataCompressor::Zstd,
            &groups,
            Arc::default(),
        );
        let mut buf = vec![0u8; 100];
        remote.read_at(8192 + 10, &mut buf).unwrap();
        assert_eq!(buf, image[8192 + 10..8192 + 110]);
        assert_eq!(backend.reads(), 1);

        let mut all = vec![0u8; image.len()];
        remote.read_at(0, &mut all).unwrap();
        assert_eq!(all, image);
        assert_eq!(backend.reads(), 2);
        remote.read_at(0, &mut all).unwrap();
        assert_eq!(all, image);
        assert_eq!(backend.reads(), 2);
    }

    #[test]
    fn chunk_groups_over_a_quarter_of_the_budget_are_not_cached() {
        let test_cases = vec![(32 * 1024, 1), (31 * 1024, 2)];

        let groups = groups(3);
        let image = uncompressed_data(&groups);
        for (budget, fetches) in test_cases {
            let dir = tempdir().unwrap();
            let cache = Arc::new(DecodedChunkGroupCache::with_limits(budget, 16));
            let (remote, backend) = open(dir.path(), BlobMetadataCompressor::Zstd, &groups, cache);
            let mut buf = vec![0u8; 4096];
            remote.read_at(0, &mut buf).unwrap();
            remote.read_at(4096, &mut buf).unwrap();
            assert_eq!(buf, image[4096..8192]);
            assert_eq!(backend.reads(), fetches, "budget {budget}");
        }
    }

    #[test]
    fn eviction_is_lru_within_the_byte_and_entry_bounds() {
        let test_cases = vec![(32 * 1024, 128, 4u8), (1 << 20, 2, 2)];

        for (max_bytes, max_entries, capacity) in test_cases {
            let dir = tempdir().unwrap();
            let groups = groups(capacity + 1);
            let cache = Arc::new(DecodedChunkGroupCache::with_limits(max_bytes, max_entries));
            let (remote, backend) = open(
                dir.path(),
                BlobMetadataCompressor::Zstd,
                &groups,
                cache.clone(),
            );
            let read_group = |group: u8| {
                let mut buf = [0u8; 1];
                remote.read_at(group as u64 * 8192, &mut buf).unwrap();
                assert_eq!(buf[0], group * 2 + 1);
            };
            let fetches = capacity as usize;
            (0..capacity).for_each(read_group);
            assert_eq!(backend.reads(), fetches);
            read_group(0);
            read_group(capacity);
            assert_eq!(backend.reads(), fetches + 1);
            read_group(0);
            read_group(capacity);
            assert_eq!(backend.reads(), fetches + 1);
            read_group(1);
            assert_eq!(backend.reads(), fetches + 2);
            let state = cache.state.lock().unwrap();
            assert_eq!(state.entries.len(), capacity as usize);
            assert_eq!(state.bytes, capacity as usize * 8192);
        }
    }

    #[test]
    fn the_blobs_of_one_set_share_the_budget() {
        let groups = groups(3);
        let cache = Arc::new(DecodedChunkGroupCache::with_limits(32 * 1024, 16));
        let first = tempdir().unwrap();
        let second = tempdir().unwrap();
        let (a, _) = open(
            first.path(),
            BlobMetadataCompressor::Zstd,
            &groups,
            cache.clone(),
        );
        let mut other = groups.clone();
        other[0][0][0] = 0xee;
        let (b, _) = open(
            second.path(),
            BlobMetadataCompressor::Zstd,
            &other,
            cache.clone(),
        );
        let mut buf = [0u8; 1];
        for group in 0..3 {
            a.read_at(group * 8192, &mut buf).unwrap();
            b.read_at(group * 8192, &mut buf).unwrap();
        }
        b.read_at(0, &mut buf).unwrap();
        assert_eq!(buf[0], 0xee);
        let state = cache.state.lock().unwrap();
        assert_eq!(state.entries.len(), 4);
        assert_eq!(state.bytes, 32 * 1024);
    }

    #[test]
    fn a_chunk_group_failing_verification_is_not_cached() {
        let dir = tempdir().unwrap();
        let groups = groups(3);
        let (remote, backend) = open(
            dir.path(),
            BlobMetadataCompressor::None,
            &groups,
            Arc::default(),
        );
        backend.corrupt_next.store(true, Ordering::SeqCst);
        let mut buf = [0u8; 16];
        assert!(remote.read_at(0, &mut buf).is_err());
        remote.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, [1u8; 16]);
        remote.read_at(16, &mut buf).unwrap();
        assert_eq!(backend.reads(), 2);
    }
}
