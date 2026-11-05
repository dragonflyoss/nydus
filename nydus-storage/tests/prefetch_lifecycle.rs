use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use nydus_config::PrefetchScope;
use nydus_format::blob::BlobMetadataCompressor;
use nydus_storage::cache::{BlobCaches, CacheOptions};
use nydus_storage::prefetch::{BlobPrefetcher, PrefetchPlan};
use nydus_test_utils::fault::{Fault, FaultBackend, FaultRule};
use nydus_test_utils::metadata::from_chunk_groups;
use tempfile::{tempdir, TempDir};

fn three_blob_caches() -> (TempDir, Arc<FaultBackend>, Arc<BlobCaches>) {
    let dir = tempdir().unwrap();
    let groups = vec![vec![vec![0x5a; 4096]]];
    let (data, blob_metadata) =
        from_chunk_groups(BlobMetadataCompressor::Zstd, 4096, &groups, None);
    let backend = Arc::new(
        FaultBackend::in_memory()
            .with_blob([1; 32], data.clone(), &blob_metadata)
            .with_blob([2; 32], data.clone(), &blob_metadata)
            .with_blob([3; 32], data, &blob_metadata),
    );
    let caches = Arc::new(
        BlobCaches::new(
            [(1, [1; 32]), (2, [2; 32]), (3, [3; 32])],
            backend.clone(),
            Some(dir.path()),
            None,
            CacheOptions::default(),
        )
        .unwrap(),
    );
    (dir, backend, caches)
}

fn wait_for(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn spawn_after_stop_opens_no_metadata_and_reads_nothing() {
    let test_cases = vec![
        PrefetchScope::All,
        PrefetchScope::Ondemand,
        PrefetchScope::Auto,
    ];

    for scope in test_cases {
        let (_dir, backend, caches) = three_blob_caches();
        let prefetcher = BlobPrefetcher::new(
            caches,
            PrefetchPlan {
                priority: vec![1, 2],
                rest: vec![3],
            },
            1,
            scope,
            Duration::from_secs(1),
        );
        prefetcher.stop_flag().store(true, Ordering::Relaxed);

        prefetcher.spawn().unwrap().join().unwrap();

        assert_eq!(backend.metadata_calls(), 0, "scope={scope:?}");
        assert!(backend.reads().is_empty(), "scope={scope:?}");
    }
}

#[test]
fn spawn_stopped_during_a_read_finishes_only_the_inflight_blob_and_releases_caches() {
    let (_dir, backend, caches) = three_blob_caches();
    backend.inject(FaultRule::read(Fault::Delay(Duration::from_millis(200))).times(1));
    let weak = Arc::downgrade(&caches);
    let prefetcher = BlobPrefetcher::new(
        caches.clone(),
        PrefetchPlan {
            priority: vec![],
            rest: vec![1, 2, 3],
        },
        1,
        PrefetchScope::All,
        Duration::from_secs(1),
    );
    let stop = prefetcher.stop_flag();

    let handle = prefetcher.spawn().unwrap();
    wait_for(|| !backend.reads().is_empty());
    stop.store(true, Ordering::Relaxed);
    drop(caches);
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || tx.send(handle.join()).unwrap());
    rx.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();

    assert_eq!(backend.reads().len(), 1);
    assert_eq!(backend.metadata_calls(), 1);
    assert!(weak.upgrade().is_none());
}

#[test]
fn spawn_stopped_during_priority_metadata_skips_the_remaining_priority_blobs() {
    let (_dir, backend, caches) = three_blob_caches();
    backend.inject(FaultRule::metadata(Fault::Delay(Duration::from_millis(200))).times(1));
    let prefetcher = BlobPrefetcher::new(
        caches,
        PrefetchPlan {
            priority: vec![1, 2, 3],
            rest: vec![],
        },
        1,
        PrefetchScope::All,
        Duration::from_secs(1),
    );
    let stop = prefetcher.stop_flag();

    let handle = prefetcher.spawn().unwrap();
    wait_for(|| backend.metadata_calls() == 1);
    stop.store(true, Ordering::Relaxed);
    handle.join().unwrap();

    assert_eq!(backend.metadata_calls(), 1);
    assert!(backend.reads().is_empty());
}

#[test]
fn spawn_stopped_during_the_priority_scan_joins_delayed_metadata_openers() {
    let (_dir, backend, caches) = three_blob_caches();
    backend.inject(
        FaultRule::metadata(Fault::Delay(Duration::from_millis(100)))
            .on_blob([1; 32])
            .times(1),
    );
    backend.inject(
        FaultRule::metadata(Fault::Delay(Duration::from_millis(400)))
            .on_blob([2; 32])
            .times(1),
    );
    let weak = Arc::downgrade(&caches);
    let prefetcher = BlobPrefetcher::new(
        caches,
        PrefetchPlan {
            priority: vec![1],
            rest: vec![2, 3],
        },
        2,
        PrefetchScope::Ondemand,
        Duration::from_secs(1),
    );
    let stop = prefetcher.stop_flag();

    let handle = prefetcher.spawn().unwrap();
    wait_for(|| backend.metadata_calls() >= 2);
    stop.store(true, Ordering::Relaxed);
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || tx.send(handle.join()).unwrap());
    rx.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();

    assert_eq!(backend.metadata_calls(), 2);
    assert!(backend.reads().is_empty());
    assert!(weak.upgrade().is_none());
}
