//! Diskless blob access: reads fetch, decode, and validate the chunk groups
//! they touch from the backend directly, holding the bytes only in memory.
//! Selected when no storage directory is configured. Nothing is written to
//! disk; the recently decoded groups are kept in a small in-memory LRU
//! ([`DecodedGroupCache`], one budget per blob set) so a run of small reads
//! within a group — a tar export pulling 8 KiB at a time, or FUSE's 128 KiB
//! requests — fetches and decodes the group once instead of once per read.
//! Modes that hand a cache file to the kernel (fanotify, NBD, ublk,
//! userfaultfd, virtio-pmem) cannot run diskless and reject this mode through
//! the file-oriented [`BlobCache`] defaults.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};

use nydus_backend::{Backend, ReadKind};
use nydus_format::blob::{BlobMetadata, BlobMetadataChunkGroupExtent};
use nydus_format::utils::SHA256_DIGEST_SIZE;

use super::{decode_chunk_group_into, validate_decoded_chunk_group, BlobCache, ChunkGroupBuffer};

/// Decoded bytes the diskless caches of one blob set keep in memory.
const DECODED_GROUP_CACHE_BYTES: usize = 32 << 20;
/// Most decoded groups kept at once, bounding the LRU scan.
const DECODED_GROUP_CACHE_ENTRIES: usize = 128;

/// A blob's chunk group: the blob id and the group's table index.
type GroupKey = ([u8; SHA256_DIGEST_SIZE], u32);

/// A chunk group's uncompressed bytes, already checked against its crc32c
/// (and digests, when verification is on).
struct DecodedGroup {
    buffer: ChunkGroupBuffer,
    len: usize,
}

impl DecodedGroup {
    fn bytes(&self) -> &[u8] {
        self.buffer.bytes(self.len)
    }
}

/// A bounded LRU of validated decoded chunk groups, shared by the diskless
/// caches of one blob set so the memory bound holds however many layers the
/// set mounts. Blob data never changes under an id, so entries are never
/// invalidated, only evicted. Concurrent misses on one group may both decode
/// it; the second insert is dropped.
pub(crate) struct DecodedGroupCache {
    max_bytes: usize,
    max_entries: usize,
    state: Mutex<DecodedGroupState>,
}

#[derive(Default)]
struct DecodedGroupState {
    entries: VecDeque<(GroupKey, Arc<DecodedGroup>)>,
    bytes: usize,
}

impl Default for DecodedGroupCache {
    fn default() -> Self {
        Self::with_limits(DECODED_GROUP_CACHE_BYTES, DECODED_GROUP_CACHE_ENTRIES)
    }
}

impl DecodedGroupCache {
    fn with_limits(max_bytes: usize, max_entries: usize) -> Self {
        Self {
            max_bytes,
            max_entries,
            state: Mutex::default(),
        }
    }

    /// Whether a group of `len` decoded bytes is kept: at most a quarter of
    /// the budget, which admits the largest group of the default layout
    /// (four times the 2 MiB group minimum) without flushing everything else.
    fn admits(&self, len: usize) -> bool {
        len <= self.max_bytes / 4
    }

    fn get(&self, key: &GroupKey) -> Option<Arc<DecodedGroup>> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let index = state.entries.iter().position(|(entry, _)| entry == key)?;
        let entry = state.entries.remove(index)?;
        let group = Arc::clone(&entry.1);
        state.entries.push_back(entry);
        Some(group)
    }

    fn insert(&self, key: GroupKey, group: DecodedGroup) {
        if !self.admits(group.len) {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
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

/// A diskless blob cache: reads are served from the backend (or the blob
/// set's in-memory [`DecodedGroupCache`]) with nothing written to disk.
pub struct RemoteBlobCache {
    blob_id: [u8; SHA256_DIGEST_SIZE],
    blob_metadata: BlobMetadata,
    backend: Arc<dyn Backend>,
    decoded_groups: Arc<DecodedGroupCache>,
    /// Skip the crc32c check of decoded chunk groups.
    skip_verify_checksums: bool,
}

impl RemoteBlobCache {
    /// Open the blob's metadata from the backend, `kind` attributing that
    /// fetch; no local file is created. Decoded groups are kept in
    /// `decoded_groups`, which other blobs of the same set share, and their
    /// crc32c check is skipped when `skip_verify_checksums`.
    pub(crate) fn open(
        blob_id: [u8; SHA256_DIGEST_SIZE],
        backend: Arc<dyn Backend>,
        decoded_groups: Arc<DecodedGroupCache>,
        kind: ReadKind,
        skip_verify_checksums: bool,
    ) -> io::Result<Self> {
        let blob_metadata = match kind {
            ReadKind::Ondemand => backend.read_blob_metadata(&blob_id)?,
            ReadKind::Prefetch => backend.prefetch_blob_metadata(&blob_id)?,
        };
        Ok(Self {
            blob_id,
            blob_metadata,
            backend,
            decoded_groups,
            skip_verify_checksums,
        })
    }
}

/// Copy the part of `group`'s chunks, cut out of its uncompressed `payload`,
/// that overlaps `[offset, offset + dst.len())` into `dst`.
fn copy_group_chunks(
    meta: &BlobMetadata,
    group: &BlobMetadataChunkGroupExtent,
    payload: &[u8],
    offset: u64,
    dst: &mut [u8],
) -> io::Result<()> {
    let end = offset + dst.len() as u64;
    for (chunk_offset, bytes) in group
        .chunks(meta, payload)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
    {
        let copy_start = offset.max(chunk_offset);
        let copy_end = end.min(chunk_offset + bytes.len() as u64);
        if copy_start < copy_end {
            let source_start = (copy_start - chunk_offset) as usize;
            let target_start = (copy_start - offset) as usize;
            let length = (copy_end - copy_start) as usize;
            dst[target_start..target_start + length]
                .copy_from_slice(&bytes[source_start..source_start + length]);
        }
    }
    Ok(())
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
        let first = meta.chunk_group_index(offset).ok_or_else(not_found)?;
        let last = meta.chunk_group_index(end - 1).ok_or_else(not_found)?;

        // Serve the cached groups first; the cache lock only covers the
        // lookup, the copy runs on the returned reference.
        dst.fill(0);
        let mut missed = Vec::new();
        for index in first..=last {
            let group = meta.chunk_group(index).expect("group within the table");
            match self.decoded_groups.get(&(self.blob_id, group.index())) {
                Some(cached) => copy_group_chunks(meta, &group, cached.bytes(), offset, dst)?,
                None => missed.push(group),
            }
        }
        let (Some(head), Some(tail)) = (missed.first(), missed.last()) else {
            return Ok(());
        };

        // The missed groups lie between two table indexes, so one read covers
        // them all (and any cached group in between, which is not decoded
        // again); then each decodes into a buffer of its own that the cache
        // keeps.
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
            let payload: &[u8] = if group.is_uncompressed(meta) {
                &encoded[start..stop]
            } else {
                let out = decoded.resize(len)?;
                decode_chunk_group_into(meta.compressor(), &encoded[start..stop], out)?;
                out
            };
            validate_decoded_chunk_group(group, payload, self.skip_verify_checksums)?;
            copy_group_chunks(meta, group, payload, offset, dst)?;
            if !self.decoded_groups.admits(len) {
                continue;
            }
            if group.is_uncompressed(meta) {
                decoded.resize(len)?.copy_from_slice(&encoded[start..stop]);
            }
            self.decoded_groups.insert(
                (self.blob_id, group.index()),
                DecodedGroup {
                    buffer: decoded,
                    len,
                },
            );
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tempfile::tempdir;

    /// A local backend that counts reads and can corrupt the next one.
    struct Counting {
        inner: Local,
        reads: AtomicUsize,
        corrupt_next: AtomicBool,
    }

    impl Counting {
        fn new(dir: &std::path::Path) -> Arc<Self> {
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
            dst: &mut [u8],
        ) -> io::Result<()> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.read_range_into(blob_id, offset, dst)?;
            if self.corrupt_next.swap(false, Ordering::SeqCst) {
                dst[0] ^= 0xff;
            }
            Ok(())
        }
    }

    /// `count` groups of two 4 KiB chunks each (8 KiB decoded), every chunk
    /// a distinct byte: group `n` starts with `2n + 1`.
    fn groups(count: u8) -> Vec<Vec<Vec<u8>>> {
        (0..count)
            .map(|group| {
                (0..2u8)
                    .map(|chunk| vec![group * 2 + chunk + 1; 4096])
                    .collect()
            })
            .collect()
    }

    fn open_counting(
        dir: &std::path::Path,
        compressor: BlobMetadataCompressor,
        groups: &[Vec<Vec<u8>>],
        decoded_groups: Arc<DecodedGroupCache>,
    ) -> (RemoteBlobCache, Arc<Counting>) {
        let (data, meta) = from_chunk_groups(compressor, 8192, groups, None);
        let blob_id = FullBlob::new(&data)
            .with_blob_metadata(&meta)
            .with_blob_metadata_file()
            .save_in(dir);
        let backend = Counting::new(dir);
        let remote = RemoteBlobCache::open(
            blob_id,
            backend.clone(),
            decoded_groups,
            ReadKind::Ondemand,
            false,
        )
        .unwrap();
        (remote, backend)
    }

    #[test]
    fn remote_blob_cache_reads_without_touching_disk() {
        let backend_dir = tempdir().unwrap();
        let payload = vec![0xabu8; 4096];
        let (data, meta) = from_chunk_groups(
            BlobMetadataCompressor::None,
            4096,
            &[vec![payload.clone()]],
            None,
        );
        let full_blob_id = FullBlob::new(&data)
            .with_blob_metadata(&meta)
            .with_blob_metadata_file()
            .save_in(backend_dir.path());

        let backend: Arc<dyn Backend> = Arc::new(Local::new(
            backend_dir.path().to_path_buf(),
            Arc::new(Metrics::new()),
        ));
        let remote = RemoteBlobCache::open(
            full_blob_id,
            backend,
            Arc::default(),
            ReadKind::Ondemand,
            false,
        )
        .unwrap();

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
        let (data, meta) = from_chunk_groups(
            BlobMetadataCompressor::Zstd,
            16384,
            &groups,
            Some(BlobMetadataDigester::Blake3),
        );
        let image = uncompressed_data(&groups);
        assert_eq!(image.len(), 6 * 4096);
        let full_blob_id = FullBlob::new(&data)
            .with_blob_metadata(&meta)
            .with_blob_metadata_file()
            .save_in(backend_dir.path());
        let backend = Arc::new(Local::new(
            backend_dir.path().to_path_buf(),
            Arc::new(Metrics::new()),
        ));
        let remote = RemoteBlobCache::open(
            full_blob_id,
            backend,
            Arc::default(),
            ReadKind::Ondemand,
            false,
        )
        .unwrap();
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
        let (data, meta) =
            from_chunk_groups(BlobMetadataCompressor::None, 4096, &[vec![payload]], None);
        let full_blob_id = FullBlob::new(&data)
            .with_blob_metadata(&meta)
            .with_blob_metadata_file()
            .save_in(backend_dir.path());

        let backend: Arc<dyn Backend> = Arc::new(Local::new(
            backend_dir.path().to_path_buf(),
            Arc::new(Metrics::new()),
        ));
        let remote = RemoteBlobCache::open(
            full_blob_id,
            backend,
            Arc::default(),
            ReadKind::Ondemand,
            false,
        )
        .unwrap();

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
        assert!(!remote.is_ondemand());
    }

    #[test]
    fn small_reads_within_a_group_fetch_it_once() {
        for compressor in [BlobMetadataCompressor::None, BlobMetadataCompressor::Zstd] {
            let dir = tempdir().unwrap();
            let groups = groups(3);
            let image = uncompressed_data(&groups);
            let (remote, backend) = open_counting(dir.path(), compressor, &groups, Arc::default());
            // Walk the whole image 1 KiB at a time: one fetch per group.
            for (index, expected) in image.chunks(1024).enumerate() {
                let mut buf = [0u8; 1024];
                remote.read_at(index as u64 * 1024, &mut buf).unwrap();
                assert_eq!(buf, expected);
            }
            assert_eq!(backend.reads(), 3, "{compressor:?}");
            // Everything is cached now, reads across groups included.
            let mut all = vec![0u8; image.len()];
            remote.read_at(0, &mut all).unwrap();
            assert_eq!(all, image);
            assert_eq!(backend.reads(), 3, "{compressor:?}");
        }
    }

    #[test]
    fn a_read_across_groups_fetches_only_the_missed_ones() {
        let dir = tempdir().unwrap();
        let groups = groups(3);
        let image = uncompressed_data(&groups);
        let (remote, backend) = open_counting(
            dir.path(),
            BlobMetadataCompressor::Zstd,
            &groups,
            Arc::default(),
        );
        let mut buf = vec![0u8; 100];
        remote.read_at(8192 + 10, &mut buf).unwrap();
        assert_eq!(buf, image[8192 + 10..8192 + 110]);
        assert_eq!(backend.reads(), 1);
        // Groups 0 and 2 miss around the cached group 1: one fetch spans
        // them, group 1 is served from the cache.
        let mut all = vec![0u8; image.len()];
        remote.read_at(0, &mut all).unwrap();
        assert_eq!(all, image);
        assert_eq!(backend.reads(), 2);
        remote.read_at(0, &mut all).unwrap();
        assert_eq!(all, image);
        assert_eq!(backend.reads(), 2);
    }

    #[test]
    fn groups_over_a_quarter_of_the_budget_are_not_cached() {
        let groups = groups(3);
        let image = uncompressed_data(&groups);
        // Each group decodes to 8 KiB: a 32 KiB budget keeps them, 31 KiB
        // does not.
        for (budget, fetches) in [(32 * 1024, 1), (31 * 1024, 2)] {
            let dir = tempdir().unwrap();
            let cache = Arc::new(DecodedGroupCache::with_limits(budget, 16));
            let (remote, backend) =
                open_counting(dir.path(), BlobMetadataCompressor::Zstd, &groups, cache);
            let mut buf = vec![0u8; 4096];
            remote.read_at(0, &mut buf).unwrap();
            remote.read_at(4096, &mut buf).unwrap();
            assert_eq!(buf, image[4096..8192]);
            assert_eq!(backend.reads(), fetches, "budget {budget}");
        }
    }

    #[test]
    fn eviction_is_lru_within_the_byte_and_entry_bounds() {
        // 32 KiB holds four 8 KiB groups by bytes; two entries cap a 1 MiB
        // budget at two groups.
        for (max_bytes, max_entries, capacity) in [(32 * 1024, 128, 4u8), (1 << 20, 2, 2)] {
            let dir = tempdir().unwrap();
            let groups = groups(capacity + 1);
            let cache = Arc::new(DecodedGroupCache::with_limits(max_bytes, max_entries));
            let (remote, backend) = open_counting(
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
            read_group(0); // group 0 becomes the most recent
            read_group(capacity); // evicts group 1, the least recent
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
    fn blobs_of_one_set_share_the_budget() {
        let groups = groups(3);
        let cache = Arc::new(DecodedGroupCache::with_limits(32 * 1024, 16));
        let first = tempdir().unwrap();
        let second = tempdir().unwrap();
        let (a, _) = open_counting(
            first.path(),
            BlobMetadataCompressor::Zstd,
            &groups,
            cache.clone(),
        );
        // A different payload gives the second blob its own id.
        let mut other = groups.clone();
        other[0][0][0] = 0xee;
        let (b, _) = open_counting(
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
    fn a_group_failing_validation_is_not_cached() {
        let dir = tempdir().unwrap();
        let groups = groups(3);
        let (remote, backend) = open_counting(
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
