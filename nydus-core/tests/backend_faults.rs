mod common;

use std::io;
use std::path::Path;
use std::sync::Arc;

use common::{Image, FILE_NAME};
use nydus_backend::{Local, ReadKind};
use nydus_core::ErofsReader;
use nydus_storage::cache::CacheOptions;
use nydus_telemetry::metrics::Metrics;
use nydus_test_utils::fault::{Fault, FaultBackend, FaultRule};
use tempfile::tempdir;

fn open(image: &Image, cache_dir: &Path) -> (Arc<FaultBackend>, ErofsReader) {
    let backend = Arc::new(FaultBackend::wrap(Arc::new(Local::new(
        image.blob_dir.clone(),
        Arc::new(Metrics::new()),
    ))));
    let reader = ErofsReader::open_bootstrap(
        &image.bootstrap,
        backend.clone(),
        Some(cache_dir),
        None,
        CacheOptions::default(),
    )
    .unwrap();
    (backend, reader)
}

fn read_file(reader: &ErofsReader, offset: u64, len: u32) -> io::Result<Vec<u8>> {
    let root = reader.superblock().root_nid();
    let root_inode = reader.inode(root)?;
    let nid = reader
        .lookup_dir_entry(root, &root_inode, FILE_NAME.as_bytes())?
        .unwrap();
    let inode = reader.inode(nid)?;
    reader.read_file_data(nid, &inode, offset, len)
}

#[test]
fn ensure_range_and_read_file_data_fail_on_a_backend_fault_until_it_is_spent() {
    let image = Image::build();
    let group = image.logical(2);
    let compressed = image.compressed(2);
    let len = group.end - group.start;
    let offset = group.start as usize + 10;
    let test_cases = vec![
        (
            Fault::Error(io::ErrorKind::ConnectionReset),
            io::ErrorKind::ConnectionReset,
        ),
        (Fault::ShortRead { len: 4096 }, io::ErrorKind::InvalidData),
        (
            Fault::FlipBit {
                offset: compressed.start + 1,
                bit: 2,
            },
            io::ErrorKind::InvalidData,
        ),
    ];

    for (fault, kind) in test_cases {
        let cache_dir = tempdir().unwrap();
        let (backend, reader) = open(&image, cache_dir.path());
        let cache = reader.blob_caches().cache(1, ReadKind::Ondemand).unwrap();
        backend.inject(
            FaultRule::read(fault.clone())
                .overlapping(compressed.clone())
                .times(2),
        );

        let err = cache.ensure_range(group.start, len).unwrap_err();
        assert_eq!(err.kind(), kind, "{fault:?}");
        assert!(
            cache.ready_ranges(group.start, len).unwrap().is_empty(),
            "{fault:?}"
        );
        let err = read_file(&reader, group.start + 10, 100).unwrap_err();
        assert_eq!(err.kind(), kind, "{fault:?}");

        let mut buf = vec![0u8; len as usize];
        cache.read_at(group.start, &mut buf).unwrap();
        assert!(
            buf == image.dense[group.start as usize..group.end as usize],
            "{fault:?}"
        );
        assert_eq!(
            read_file(&reader, group.start + 10, 100).unwrap(),
            image.file[offset..offset + 100],
            "{fault:?}"
        );
        assert_eq!(
            backend.reads_overlapping(compressed.clone()),
            3,
            "{fault:?}"
        );
    }
}

#[test]
fn cache_retries_a_failed_blob_metadata_lookup() {
    let image = Image::build();
    let cache_dir = tempdir().unwrap();
    let (backend, reader) = open(&image, cache_dir.path());
    backend.inject(FaultRule::metadata(Fault::Error(io::ErrorKind::TimedOut)).times(1));

    let err = reader
        .blob_caches()
        .cache(1, ReadKind::Ondemand)
        .err()
        .unwrap();
    let cache = reader.blob_caches().cache(1, ReadKind::Ondemand).unwrap();
    let mut buf = vec![0u8; 64];
    cache.read_at(image.logical(0).start, &mut buf).unwrap();

    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert_eq!(buf, image.dense[..64]);
    assert_eq!(backend.metadata_calls(), 2);
}
