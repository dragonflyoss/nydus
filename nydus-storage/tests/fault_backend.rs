//! Backend faults seen through the blob caches. A failed, truncated,
//! corrupted or slow backend read either fails the cache read or is waited
//! out; it never publishes a group, never returns wrong bytes, and never
//! sticks, so the next read fetches again. The faults come from
//! [`FaultBackend`].

use std::fs;
use std::io;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nydus_backend::ReadKind;
use nydus_format::blob::{BlobMetadata, BlobMetadataCompressor, BlobMetadataDigester};
use nydus_storage::cache::{self, BlobCache, BlobCaches, CacheOptions, LocalBlobCache};
use nydus_test_utils::blob::uncompressed_data;
use nydus_test_utils::fault::{Fault, FaultBackend, FaultRule};
use nydus_test_utils::metadata::from_chunk_groups;
use tempfile::tempdir;

const BLOB_ID: [u8; 32] = [0x5a; 32];

fn options() -> CacheOptions {
    CacheOptions {
        fetch_size: 0,
        ..Default::default()
    }
}

/// A blob of four 16 KiB chunk groups, each three 4 KiB chunks and one 100
/// bytes short of a block, with BLAKE3 digests.
struct Blob {
    data: Vec<u8>,
    meta: BlobMetadata,
    /// What the filled cache file holds.
    image: Vec<u8>,
}

impl Blob {
    /// Compressible groups are stored zstd-compressed; `random` groups do
    /// not compress and are stored plain, so a corrupted byte reaches the
    /// CRC32C check instead of the decoder.
    fn new(random: bool) -> Self {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut chunk = |fill: u8, len: usize| -> Vec<u8> {
            (0..len)
                .map(|_| {
                    if !random {
                        return fill;
                    }
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect()
        };
        let groups: Vec<Vec<Vec<u8>>> = (1..=4u8)
            .map(|group| {
                vec![
                    chunk(0x10 * group, 4096),
                    chunk(0x10 * group + 1, 4096),
                    chunk(0x10 * group + 2, 4096),
                    chunk(0x10 * group + 3, 4096 - 100),
                ]
            })
            .collect();
        let (data, meta) = from_chunk_groups(
            BlobMetadataCompressor::Zstd,
            16384,
            &groups,
            Some(BlobMetadataDigester::Blake3),
        );
        let blob = Self {
            data,
            meta,
            image: uncompressed_data(&groups),
        };
        for group in 0..4 {
            let extent = blob.meta.chunk_group(group).expect("four groups");
            assert_eq!(extent.is_uncompressed(&blob.meta), random);
        }
        blob
    }

    /// Where group `group` sits in the data region the backend serves.
    fn compressed(&self, group: usize) -> Range<u64> {
        self.meta
            .chunk_group(group)
            .expect("group exists")
            .compressed_range()
    }

    /// Where group `group` sits in the cache's address space.
    fn logical(&self, group: usize) -> Range<u64> {
        self.meta
            .chunk_group(group)
            .expect("group exists")
            .logical_range()
    }

    /// The bytes of `range` of the cache's address space.
    fn expected(&self, range: Range<u64>) -> &[u8] {
        &self.image[range.start as usize..range.end as usize]
    }

    fn backend(&self) -> Arc<FaultBackend> {
        Arc::new(FaultBackend::in_memory().with_blob(BLOB_ID, self.data.clone(), &self.meta))
    }
}

fn open_local(backend: &Arc<FaultBackend>, cache_dir: &Path) -> LocalBlobCache {
    LocalBlobCache::open(BLOB_ID, 1, cache_dir, backend.clone(), options())
        .expect("open the blob cache")
}

fn read(cache: &dyn BlobCache, range: Range<u64>) -> io::Result<Vec<u8>> {
    let mut buf = vec![0xeeu8; (range.end - range.start) as usize];
    cache.read_at(range.start, &mut buf)?;
    Ok(buf)
}

/// A backend error fails the read with the backend's error kind and leaves
/// the group cold; the neighbors are unaffected and the next read fetches
/// again. A failed window publishes none of its groups.
#[test]
fn backend_errors_fail_the_read_and_leave_groups_cold() {
    let blob = Blob::new(false);
    let backend = blob.backend();
    let cache_dir = tempdir().unwrap();
    let cached = open_local(&backend, cache_dir.path());
    backend.inject(
        FaultRule::read(Fault::Error(io::ErrorKind::ConnectionReset))
            .overlapping(blob.compressed(1))
            .times(1),
    );

    let err = read(&cached, blob.logical(1)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    assert!(!cached.is_chunk_group_ready(1));
    let everything = 0..blob.image.len() as u64;
    assert!(cached
        .ready_ranges(everything.start, everything.end)
        .unwrap()
        .is_empty());
    assert_eq!(
        read(&cached, blob.logical(0)).unwrap(),
        blob.expected(blob.logical(0))
    );
    assert_eq!(
        read(&cached, blob.logical(1)).unwrap(),
        blob.expected(blob.logical(1))
    );
    assert!(cached.is_chunk_group_ready(1));
    assert_eq!(backend.reads_overlapping(blob.compressed(1)), 2);

    // A window spanning the whole blob fails as a unit.
    let cache_dir = tempdir().unwrap();
    let cached = LocalBlobCache::open(
        BLOB_ID,
        1,
        cache_dir.path(),
        backend.clone(),
        CacheOptions {
            fetch_size: 1 << 20,
            ..options()
        },
    )
    .unwrap();
    backend.inject(FaultRule::read(Fault::Error(io::ErrorKind::TimedOut)).times(1));
    let err = read(&cached, blob.logical(0)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!((0..4).all(|group| !cached.is_chunk_group_ready(group)));
    assert_eq!(read(&cached, everything.clone()).unwrap(), blob.image);
    assert!(cached.is_all_ready());
}

/// A short read or a flipped bit is caught before the group is published,
/// with checksum verification enabled: by the decoder for a compressed
/// group, by the CRC32C for a plain one. The fault does not stick.
#[test]
fn truncated_or_corrupted_reads_are_rejected_not_served() {
    for random in [false, true] {
        let blob = Blob::new(random);
        let group = blob.compressed(2);
        let faults = [
            Fault::ShortRead {
                len: ((group.end - group.start) / 2) as usize,
            },
            Fault::FlipBit {
                offset: (group.start + group.end) / 2,
                bit: 5,
            },
        ];
        for fault in faults {
            let what = format!(
                "{fault:?} on a {} group",
                ["zstd", "plain"][random as usize]
            );
            let backend = blob.backend();
            let cache_dir = tempdir().unwrap();
            let cached = open_local(&backend, cache_dir.path());
            backend.inject(FaultRule::read(fault).overlapping(group.clone()).times(1));

            let err = read(&cached, blob.logical(2))
                .err()
                .unwrap_or_else(|| panic!("{what} must fail the read"));
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{what}: {err}");
            if random {
                assert!(cache::is_chunk_group_crc_mismatch(&err), "{what}: {err}");
            }
            assert!(!cached.is_chunk_group_ready(2), "{what}");
            assert_eq!(
                read(&cached, blob.logical(2)).unwrap(),
                blob.expected(blob.logical(2)),
                "{what}"
            );
            assert_eq!(backend.read_calls(), 2, "{what}");
        }
    }
}

/// Concurrent misses on one group wait for the read in flight instead of
/// each fetching it.
#[test]
fn concurrent_misses_wait_for_one_backend_read() {
    let blob = Blob::new(true);
    let backend = blob.backend();
    let cache_dir = tempdir().unwrap();
    let cached = open_local(&backend, cache_dir.path());
    let delay = Duration::from_millis(100);
    backend.inject(FaultRule::read(Fault::Delay(delay)).overlapping(blob.compressed(1)));

    let start = Instant::now();
    std::thread::scope(|scope| {
        let readers: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| read(&cached, blob.logical(1))))
            .collect();
        for reader in readers {
            assert_eq!(
                reader.join().unwrap().unwrap(),
                blob.expected(blob.logical(1))
            );
        }
    });
    assert!(start.elapsed() >= delay);
    assert_eq!(backend.read_calls(), 1);
}

/// Prefetch failures propagate without holding back on-demand reads.
#[test]
fn prefetch_reads_are_tagged_and_report_errors() {
    let blob = Blob::new(false);
    let backend = blob.backend();
    let cache_dir = tempdir().unwrap();
    let cached = open_local(&backend, cache_dir.path());
    backend
        .inject(FaultRule::read(Fault::Error(io::ErrorKind::TimedOut)).on_kind(ReadKind::Prefetch));

    let err = cached.prefetch_all(1, None).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
    assert!(!cached.is_all_ready());
    assert_eq!(
        read(&cached, blob.logical(3)).unwrap(),
        blob.expected(blob.logical(3))
    );

    backend.clear_faults();
    cached.prefetch_all(2, None).unwrap();
    assert!(cached.is_all_ready());
    assert_eq!(
        read(&cached, 0..blob.image.len() as u64).unwrap(),
        blob.image
    );
    let reads = backend.reads();
    assert_eq!(reads[0].kind, ReadKind::Prefetch);
    assert!(reads[0].faulted);
    assert_eq!(reads[1].kind, ReadKind::Ondemand);
    assert!(reads[2..]
        .iter()
        .all(|read| read.kind == ReadKind::Prefetch));
    // The group the on-demand read published is not fetched again.
    assert_eq!(backend.reads_overlapping(blob.compressed(3)), 1);
}

/// A failed blob meta lookup fails the open and leaves no sidecar behind;
/// the next open looks it up again, and a cached sidecar spares later
/// opens the lookup.
#[test]
fn failed_blob_meta_lookups_fail_the_open_and_are_retried() {
    let blob = Blob::new(false);
    let backend = blob.backend();
    let cache_dir = tempdir().unwrap();
    backend.inject(FaultRule::metadata(Fault::Error(io::ErrorKind::NotFound)).times(1));

    let err = LocalBlobCache::open(BLOB_ID, 1, cache_dir.path(), backend.clone(), options())
        .err()
        .expect("a failed blob meta lookup fails the open");
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
    let sidecars = fs::read_dir(cache_dir.path())
        .unwrap()
        .filter(|entry| {
            let name = entry.as_ref().unwrap().file_name();
            name.to_string_lossy().ends_with(BlobMetadata::SUFFIX)
        })
        .count();
    assert_eq!(sidecars, 0);

    let cached = open_local(&backend, cache_dir.path());
    assert_eq!(
        read(&cached, blob.logical(0)).unwrap(),
        blob.expected(blob.logical(0))
    );
    assert_eq!(backend.metadata_calls(), 2);
    let _reopened = open_local(&backend, cache_dir.path());
    assert_eq!(backend.metadata_calls(), 2);
}

/// The diskless cache rejects corrupted and failed reads the same way, and
/// keeps only validated groups in memory.
#[test]
fn remote_cache_rejects_faulted_groups_without_caching_them() {
    let blob = Blob::new(true);
    let backend = blob.backend();
    let caches = BlobCaches::new([(1, BLOB_ID)], backend.clone(), None, None, options()).unwrap();
    let remote = caches
        .cache(1, nydus_backend::ReadKind::Ondemand)
        .expect("open the remote cache");
    let group = blob.compressed(1);
    backend.inject(
        FaultRule::read(Fault::FlipBit {
            offset: group.start + 7,
            bit: 0,
        })
        .times(1),
    );
    backend.inject(
        FaultRule::read(Fault::Error(io::ErrorKind::BrokenPipe))
            .overlapping(group.clone())
            .times(1),
    );

    let err = read(remote.as_ref(), blob.logical(1)).unwrap_err();
    assert!(cache::is_chunk_group_crc_mismatch(&err), "{err}");
    let err = read(remote.as_ref(), blob.logical(1)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(
        read(remote.as_ref(), blob.logical(1)).unwrap(),
        blob.expected(blob.logical(1))
    );
    let served = backend.read_calls();
    assert_eq!(served, 3);
    assert_eq!(
        read(remote.as_ref(), blob.logical(1)).unwrap(),
        blob.expected(blob.logical(1))
    );
    assert_eq!(backend.read_calls(), served, "the validated group is kept");
}
