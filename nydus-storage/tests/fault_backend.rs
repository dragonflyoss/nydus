#![allow(clippy::type_complexity)]

use std::fs;
use std::io;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;
use std::thread;
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

struct Blob {
    data: Vec<u8>,
    meta: BlobMetadata,
    image: Vec<u8>,
}

impl Blob {
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
            let extent = blob.meta.chunk_group(group).unwrap();
            assert_eq!(extent.is_uncompressed(&blob.meta), random);
        }
        blob
    }

    fn compressed(&self, group: usize) -> Range<u64> {
        self.meta.chunk_group(group).unwrap().compressed_range()
    }

    fn logical(&self, group: usize) -> Range<u64> {
        self.meta.chunk_group(group).unwrap().logical_range()
    }

    fn expected(&self, range: Range<u64>) -> &[u8] {
        &self.image[range.start as usize..range.end as usize]
    }

    fn backend(&self) -> Arc<FaultBackend> {
        Arc::new(FaultBackend::in_memory().with_blob(BLOB_ID, self.data.clone(), &self.meta))
    }
}

fn open_local(backend: &Arc<FaultBackend>, cache_dir: &Path) -> LocalBlobCache {
    LocalBlobCache::open(BLOB_ID, 1, cache_dir, backend.clone(), options()).unwrap()
}

fn read(cache: &dyn BlobCache, range: Range<u64>) -> io::Result<Vec<u8>> {
    let mut buf = vec![0xeeu8; (range.end - range.start) as usize];
    cache.read_at(range.start, &mut buf)?;
    Ok(buf)
}

#[test]
fn read_at_fails_on_a_backend_error_and_leaves_the_group_cold() {
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
    assert!(cached
        .ready_ranges(0, blob.image.len() as u64)
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
}

#[test]
fn read_at_fails_the_whole_fetch_window_on_a_backend_error() {
    let blob = Blob::new(false);
    let backend = blob.backend();
    let cache_dir = tempdir().unwrap();
    let options = CacheOptions {
        fetch_size: 1 << 20,
        ..options()
    };
    let cached =
        LocalBlobCache::open(BLOB_ID, 1, cache_dir.path(), backend.clone(), options).unwrap();
    backend.inject(FaultRule::read(Fault::Error(io::ErrorKind::TimedOut)).times(1));

    let err = read(&cached, blob.logical(0)).unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!((0..4).all(|group| !cached.is_chunk_group_ready(group)));
    assert_eq!(
        read(&cached, 0..blob.image.len() as u64).unwrap(),
        blob.image
    );
    assert!(cached.is_all_ready());
}

#[test]
fn read_at_rejects_a_truncated_or_corrupted_group() {
    let test_cases: Vec<(bool, fn(Range<u64>) -> Fault)> = vec![
        (false, |group| Fault::ShortRead {
            len: ((group.end - group.start) / 2) as usize,
        }),
        (false, |group| Fault::FlipBit {
            offset: (group.start + group.end) / 2,
            bit: 5,
        }),
        (true, |group| Fault::ShortRead {
            len: ((group.end - group.start) / 2) as usize,
        }),
        (true, |group| Fault::FlipBit {
            offset: (group.start + group.end) / 2,
            bit: 5,
        }),
    ];

    for (random, fault) in test_cases {
        let blob = Blob::new(random);
        let backend = blob.backend();
        let cache_dir = tempdir().unwrap();
        let cached = open_local(&backend, cache_dir.path());
        let fault = fault(blob.compressed(2));
        let case = format!("random={random} fault={fault:?}");
        backend.inject(
            FaultRule::read(fault)
                .overlapping(blob.compressed(2))
                .times(1),
        );

        let err = read(&cached, blob.logical(2)).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{case}");
        if random {
            assert!(cache::is_chunk_group_crc_mismatch(&err), "{case}");
        }
        assert!(!cached.is_chunk_group_ready(2), "{case}");
        assert_eq!(
            read(&cached, blob.logical(2)).unwrap(),
            blob.expected(blob.logical(2)),
            "{case}"
        );
        assert_eq!(backend.read_calls(), 2, "{case}");
    }
}

#[test]
fn read_at_coalesces_concurrent_misses_into_one_backend_read() {
    let blob = Blob::new(true);
    let backend = blob.backend();
    let cache_dir = tempdir().unwrap();
    let cached = open_local(&backend, cache_dir.path());
    let delay = Duration::from_millis(100);
    backend.inject(FaultRule::read(Fault::Delay(delay)).overlapping(blob.compressed(1)));

    let start = Instant::now();
    thread::scope(|scope| {
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

#[test]
fn prefetch_all_reports_backend_errors_without_blocking_ondemand_reads() {
    let blob = Blob::new(false);
    let backend = blob.backend();
    let cache_dir = tempdir().unwrap();
    let cached = open_local(&backend, cache_dir.path());
    backend
        .inject(FaultRule::read(Fault::Error(io::ErrorKind::TimedOut)).on_kind(ReadKind::Prefetch));

    let err = cached.prefetch_all(1, None).unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
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
    assert_eq!(backend.reads_overlapping(blob.compressed(3)), 1);
}

#[test]
fn open_fails_on_a_blob_metadata_error_and_looks_it_up_again() {
    let blob = Blob::new(false);
    let backend = blob.backend();
    let cache_dir = tempdir().unwrap();
    backend.inject(FaultRule::metadata(Fault::Error(io::ErrorKind::NotFound)).times(1));

    let err = LocalBlobCache::open(BLOB_ID, 1, cache_dir.path(), backend.clone(), options())
        .err()
        .unwrap();

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

    open_local(&backend, cache_dir.path());

    assert_eq!(backend.metadata_calls(), 2);
}

#[test]
fn remote_read_at_rejects_faulted_groups_and_keeps_only_validated_ones() {
    let blob = Blob::new(true);
    let backend = blob.backend();
    let caches = BlobCaches::new([(1, BLOB_ID)], backend.clone(), None, None, options()).unwrap();
    let remote = caches.cache(1, ReadKind::Ondemand).unwrap();
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
            .overlapping(group)
            .times(1),
    );

    let err = read(remote.as_ref(), blob.logical(1)).unwrap_err();
    assert!(cache::is_chunk_group_crc_mismatch(&err));

    let err = read(remote.as_ref(), blob.logical(1)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

    assert_eq!(
        read(remote.as_ref(), blob.logical(1)).unwrap(),
        blob.expected(blob.logical(1))
    );
    assert_eq!(backend.read_calls(), 3);

    assert_eq!(
        read(remote.as_ref(), blob.logical(1)).unwrap(),
        blob.expected(blob.logical(1))
    );
    assert_eq!(backend.read_calls(), 3);
}
