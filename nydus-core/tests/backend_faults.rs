//! Backend faults under the image reader. `NydusCore::new` builds its
//! backend from the config and offers no way to hand it another one, so
//! these tests open the same bootstrap through [`ErofsReader`], which takes
//! the backend as an argument, with a [`FaultBackend`] around the local
//! backend. Every fault surfaces as an error, never as wrong bytes, and a
//! transient one does not stick.

mod common;

use std::io;
use std::path::Path;
use std::sync::Arc;

use common::{Image, FILE_NAME};
use nydus_backend::Local;
use nydus_core::ErofsReader;
use nydus_storage::cache::CacheOptions;
use nydus_telemetry::metrics::Metrics;
use nydus_test_utils::fault::{Fault, FaultBackend, FaultRule};
use tempfile::tempdir;

fn open(image: &Image, backend: &Arc<FaultBackend>, cache_dir: &Path) -> ErofsReader {
    ErofsReader::open_bootstrap(
        &image.bootstrap,
        backend.clone(),
        Some(cache_dir),
        None,
        CacheOptions::default(),
    )
    .expect("open the bootstrap")
}

fn faulty(image: &Image) -> Arc<FaultBackend> {
    Arc::new(FaultBackend::wrap(Arc::new(Local::new(
        image.blob_dir.clone(),
        Arc::new(Metrics::new()),
    ))))
}

/// Read `len` bytes at `offset` of [`FILE_NAME`] through the reader's file
/// data path.
fn read_file(reader: &ErofsReader, offset: u64, len: u32) -> io::Result<Vec<u8>> {
    let root = reader.superblock().root_nid();
    let root_inode = reader.inode(root)?;
    let nid = reader
        .lookup_dir_entry(root, &root_inode, FILE_NAME.as_bytes())?
        .expect("the file exists");
    let inode = reader.inode(nid)?;
    reader.read_file_data(nid, &inode, offset, len)
}

/// An error, a short read and a flipped bit each fail the blob fetch the
/// virtio-pmem path issues and the file read the FUSE path issues, leave
/// the group out of the resident ranges, and are gone on the next read.
#[test]
fn backend_faults_fail_reads_and_never_serve_wrong_bytes() {
    let image = Image::build();
    let group = image.logical(2);
    let compressed = image.compressed(2);
    let expected = &image.dense[group.start as usize..group.end as usize];
    let faults = [
        Fault::Error(io::ErrorKind::ConnectionReset),
        // Relative to the read: whatever window the cache fetches, only its
        // first block arrives.
        Fault::ShortRead { len: 4096 },
        Fault::FlipBit {
            offset: compressed.start + 1,
            bit: 2,
        },
    ];
    for fault in faults {
        let what = format!("{fault:?}");
        let backend = faulty(&image);
        let cache_dir = tempdir().unwrap();
        let reader = open(&image, &backend, cache_dir.path());
        let cache = reader
            .blob_caches()
            .cache(1, nydus_backend::ReadKind::Ondemand)
            .unwrap();
        let rule = FaultRule::read(fault).overlapping(compressed.clone());
        backend.inject(rule.clone().times(2));

        let err = cache
            .ensure_range(group.start, group.end - group.start)
            .expect_err(&what);
        let kind = if what.starts_with("Error") {
            io::ErrorKind::ConnectionReset
        } else {
            io::ErrorKind::InvalidData
        };
        assert_eq!(err.kind(), kind, "{what}: {err}");
        let ready = cache.ready_ranges(group.start, group.end - group.start);
        assert!(ready.unwrap().is_empty(), "{what}");
        let err = read_file(&reader, group.start + 10, 100).expect_err(&what);
        assert_eq!(err.kind(), kind, "{what}: {err}");

        // Both firings are spent: the group reads back intact.
        let mut buf = vec![0u8; expected.len()];
        cache.read_at(group.start, &mut buf).unwrap();
        assert!(
            buf == expected,
            "{what}: wrong bytes after the fault cleared"
        );
        assert_eq!(
            read_file(&reader, group.start + 10, 100).unwrap(),
            image.file[group.start as usize + 10..group.start as usize + 110]
        );
        assert_eq!(backend.reads_overlapping(compressed.clone()), 3, "{what}");
    }
}

/// A failed blob meta lookup fails opening the blob's cache, and the next
/// access looks it up again instead of keeping the failure.
#[test]
fn blob_meta_lookup_failures_are_retried() {
    let image = Image::build();
    let backend = faulty(&image);
    let cache_dir = tempdir().unwrap();
    let reader = open(&image, &backend, cache_dir.path());
    backend.inject(FaultRule::metadata(Fault::Error(io::ErrorKind::TimedOut)).times(1));

    let err = reader
        .blob_caches()
        .cache(1, nydus_backend::ReadKind::Ondemand)
        .err()
        .expect("the lookup failure fails the open");
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    let cache = reader
        .blob_caches()
        .cache(1, nydus_backend::ReadKind::Ondemand)
        .unwrap();
    let group = image.logical(0);
    let mut buf = vec![0u8; 64];
    cache.read_at(group.start, &mut buf).unwrap();
    assert_eq!(buf, image.dense[..64]);
    assert_eq!(backend.metadata_calls(), 2);
}
