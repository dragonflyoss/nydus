//! The [`NydusCore`] library API an embedding VMM drives in-process: the
//! flattened device view (`fetch_flat_ranges` / `probe_flat_ranges`), the
//! blob table, and the static file API, read back byte for byte, and
//! corrupted blob bytes rejected rather than mapped.
//!
//! Every core here uses the default storage settings.

mod common;

use std::fs;
use std::os::unix::fs::FileExt;

use common::{read_flat, Image, FILE_NAME};
use nydus_core::BlobId;
use nydus_format::erofs::EROFS_BLOCK_SIZE;
use nydus_storage::cache::is_chunk_group_crc_mismatch;
use tempfile::tempdir;

const BLOCK: u64 = EROFS_BLOCK_SIZE as u64;

/// The flattened device is the bootstrap, zeros up to the blob's mapped
/// offset, then the blob's dense address space; an unaligned read in the
/// middle and a whole-device read return exactly those bytes, and so does
/// the file API.
#[test]
fn core_reads_exact_bytes_through_the_flat_view_and_the_file_api() {
    let image = Image::build();
    let cache_dir = tempdir().unwrap();
    let core = image.core(cache_dir.path(), &[]);
    let blobs = core.blobs.prepare_all().unwrap();
    assert_eq!(blobs.len(), 1);
    let blob = &blobs[0];
    assert_eq!(blob.id, BlobId::from(image.blob_id));
    assert_eq!(blob.cache_size, image.dense.len() as u64);
    assert_eq!(core.flat_size(), blob.mapped_offset + blob.cache_size);
    assert!(blob.mapped_offset >= core.bootstrap_size);

    // Cold: an unaligned range across a group boundary fetches on demand.
    let start = image.logical(1).end - 1000;
    let middle = read_flat(&core, blob.mapped_offset + start, 3000).unwrap();
    assert_eq!(middle, image.dense[start as usize..start as usize + 3000]);
    let probed = core
        .probe_flat_ranges(blob.mapped_offset + start, 3000)
        .unwrap();
    assert_eq!(probed.iter().map(|extent| extent.len).sum::<u64>(), 3000);

    let device = read_flat(&core, 0, core.flat_size()).unwrap();
    let bootstrap = fs::read(&image.bootstrap).unwrap();
    let mapped = blob.mapped_offset as usize;
    assert_eq!(device[..bootstrap.len()], bootstrap[..]);
    assert!(device[bootstrap.len()..mapped]
        .iter()
        .all(|byte| *byte == 0));
    assert!(
        device[mapped..] == image.dense[..],
        "dense blob bytes differ"
    );
    assert!(core.blobs.is_all_ready(&blob.id).unwrap());
    assert_eq!(fs::read(&blob.cache_path).unwrap(), image.dense);

    let node = core.fs.open(FILE_NAME).unwrap();
    assert_eq!(node.metadata().unwrap().size, image.file.len() as u64);
    assert!(node.read().unwrap() == image.file, "file bytes differ");
    let mut buf = vec![0u8; 5000];
    let offset = u64::from(common::CHUNK_SIZE) - 2500;
    assert_eq!(node.read_at(offset, &mut buf).unwrap(), 5000);
    assert_eq!(buf, image.file[offset as usize..offset as usize + 5000]);
    let tail = image.file.len() as u64 - 100;
    assert_eq!(node.read_at(tail, &mut buf).unwrap(), 100);
    assert_eq!(buf[..100], image.file[tail as usize..]);
}

/// `blobs.fetch`, the virtio-pmem entry point, makes exactly the requested
/// groups resident in the cache file the guest maps.
#[test]
fn blob_fetch_fills_the_cache_file_the_guest_maps() {
    let image = Image::build();
    let cache_dir = tempdir().unwrap();
    let core = image.core(cache_dir.path(), &[]);
    let blob = core.blobs.prepare_all().unwrap().remove(0);
    let group = image.logical(2);
    core.blobs
        .fetch(&blob.id, group.start, group.end - group.start)
        .unwrap();

    let cache = fs::File::open(&blob.cache_path).unwrap();
    let mut resident = vec![0u8; (group.end - group.start) as usize];
    cache.read_exact_at(&mut resident, group.start).unwrap();
    assert_eq!(
        resident,
        image.dense[group.start as usize..group.end as usize]
    );
    let ready = core
        .blobs
        .ready_ranges(&blob.id, 0, blob.cache_size)
        .unwrap();
    assert!(ready
        .iter()
        .any(|range| range.start <= group.start && group.end <= range.end));
    assert_eq!(group.start % BLOCK, 0);
}

/// A corrupted byte in the blob store fails the fetch (by CRC32C) and is neither
/// mapped nor published.
#[test]
fn corrupted_blob_bytes_fail_the_fetch_instead_of_being_mapped() {
    let image = Image::build();
    let corrupt = image.compressed(1);
    let blob_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(image.blob_path())
        .unwrap();
    let at = (corrupt.start + corrupt.end) / 2;
    let mut byte = [0u8];
    blob_file.read_exact_at(&mut byte, at).unwrap();
    blob_file.write_all_at(&[byte[0] ^ 0x40], at).unwrap();

    let cache_dir = tempdir().unwrap();
    let core = image.core(cache_dir.path(), &[]);
    let blob = core.blobs.prepare_all().unwrap().remove(0);
    let group = image.logical(1);
    let offset = blob.mapped_offset + group.start;
    let len = group.end - group.start;
    let err = read_flat(&core, offset, len).expect_err("a corrupted group must fail the fetch");
    let io = err.io_error().expect("an I/O error");
    assert!(is_chunk_group_crc_mismatch(io), "{err:?}");
    assert!(core.probe_flat_ranges(offset, len).unwrap().is_empty());
    let node = core.fs.open(FILE_NAME).unwrap();
    let mut buf = vec![0u8; 4096];
    assert!(node.read_at(group.start + 4096, &mut buf).is_err());
}
