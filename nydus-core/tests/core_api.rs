mod common;

use std::fs;
use std::os::unix::fs::FileExt;
use std::sync::Arc;

use common::{read_flat, Image, CHUNK_SIZE, FILE_NAME};
use nydus_core::flat::{FlatImage, BLOCK_SIZE};
use nydus_core::BlobId;
use nydus_format::erofs::EROFS_BLOCK_SIZE;
use nydus_storage::cache::is_chunk_group_crc_mismatch;
use tempfile::tempdir;

#[test]
fn prepare_all_maps_the_one_blob_after_the_bootstrap() {
    let image = Image::build();
    let cache_dir = tempdir().unwrap();
    let core = image.core(cache_dir.path(), &[]);

    let blobs = core.blobs.prepare_all().unwrap();

    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].id, BlobId::from(image.blob_id));
    assert_eq!(blobs[0].id.as_bytes(), &image.blob_id);
    assert_eq!(blobs[0].id.to_hex(), hex::encode(image.blob_id));
    assert_eq!(<[u8; 32]>::from(blobs[0].id), image.blob_id);
    assert_eq!(blobs[0].cache_size, image.dense.len() as u64);
    assert_eq!(
        core.flat_size(),
        blobs[0].mapped_offset + blobs[0].cache_size
    );
    assert!(blobs[0].mapped_offset >= core.bootstrap_size);
}

#[test]
fn fetch_flat_ranges_serves_the_bootstrap_then_zeros_then_the_dense_blob() {
    let image = Image::build();
    let cache_dir = tempdir().unwrap();
    let core = image.core(cache_dir.path(), &[]);
    let blob = core.blobs.prepare_all().unwrap().remove(0);
    let bootstrap = fs::read(&image.bootstrap).unwrap();
    let mapped = blob.mapped_offset as usize;
    let start = image.logical(1).end - 1000;

    let middle = read_flat(&core, blob.mapped_offset + start, 3000).unwrap();
    let probed = core
        .probe_flat_ranges(blob.mapped_offset + start, 3000)
        .unwrap();
    let device = read_flat(&core, 0, core.flat_size()).unwrap();

    assert_eq!(middle, image.dense[start as usize..start as usize + 3000]);
    assert_eq!(probed.iter().map(|extent| extent.len).sum::<u64>(), 3000);
    assert_eq!(device[..bootstrap.len()], bootstrap[..]);
    assert!(device[bootstrap.len()..mapped]
        .iter()
        .all(|byte| *byte == 0));
    assert!(device[mapped..] == image.dense[..]);
    assert!(core.blobs.is_all_ready(&blob.id).unwrap());
    assert_eq!(fs::read(&blob.cache_path).unwrap(), image.dense);
}

#[test]
fn a_flat_image_pads_its_view_to_the_alignment_with_zeros() {
    let image = Image::build();
    let cache_dir = tempdir().unwrap();
    let core = Arc::new(image.core(cache_dir.path(), &[]));
    let flat_size = core.flat_size() as usize;
    let device = read_flat(&core, 0, flat_size as u64).unwrap();
    let align = 1 << 20;

    let flat = FlatImage::with_core(Arc::clone(&core), align).unwrap();

    let size = flat.size() as usize;
    assert_eq!(size, flat_size.next_multiple_of(align as usize));
    assert!(size > flat_size);
    assert_eq!(flat.block_count(), flat.size() / BLOCK_SIZE);
    assert_eq!(flat.zero_fd(), core.zero_fd());
    let mut view = vec![0xaa; size + BLOCK_SIZE as usize];
    flat.read_at(0, &mut view).unwrap();
    assert!(view[..flat_size] == device[..]);
    assert!(view[flat_size..].iter().all(|byte| *byte == 0));
    let mut past = vec![0xaa; BLOCK_SIZE as usize];
    flat.read_at(flat.size(), &mut past).unwrap();
    assert!(past.iter().all(|byte| *byte == 0));
    flat.read_at(0, &mut []).unwrap();
}

#[test]
fn read_returns_the_whole_file() {
    let image = Image::build();
    let cache_dir = tempdir().unwrap();
    let core = image.core(cache_dir.path(), &[]);

    let node = core.fs.open(FILE_NAME).unwrap();

    assert_eq!(node.metadata().unwrap().size, image.file.len() as u64);
    assert!(node.read().unwrap() == image.file);
}

#[test]
fn chunk_size_uses_the_existing_reader_without_blob_access() {
    let image = Image::build();
    let cache_dir = tempdir().unwrap();
    let core = image.core(cache_dir.path(), &[]);
    let node = core.fs.open(FILE_NAME).unwrap();
    fs::remove_file(&image.bootstrap).unwrap();
    fs::remove_file(image.blob_path()).unwrap();

    assert_eq!(node.chunk_size().unwrap(), u64::from(CHUNK_SIZE));
}

#[test]
fn chunk_size_rejects_non_chunk_based_entries() {
    let image = Image::build();
    let cache_dir = tempdir().unwrap();
    let core = image.core(cache_dir.path(), &[]);
    let root = core.fs.open("/").unwrap();

    assert!(matches!(
        root.chunk_size(),
        Err(nydus_error::Error::Unsupported(_))
    ));
}

#[test]
fn read_at_returns_the_file_bytes_up_to_the_end() {
    let image = Image::build();
    let cache_dir = tempdir().unwrap();
    let core = image.core(cache_dir.path(), &[]);
    let node = core.fs.open(FILE_NAME).unwrap();
    let test_cases = vec![
        (u64::from(CHUNK_SIZE) - 2500, 5000),
        (image.file.len() as u64 - 100, 100),
    ];

    for (offset, len) in test_cases {
        let mut buf = vec![0u8; 5000];
        assert_eq!(node.read_at(offset, &mut buf).unwrap(), len);
        assert_eq!(
            buf[..len],
            image.file[offset as usize..offset as usize + len]
        );
    }
}

#[test]
fn read_at_fills_a_buffer_of_4gib_with_what_the_file_holds() {
    let image = Image::build();
    let cache_dir = tempdir().unwrap();
    let core = image.core(cache_dir.path(), &[]);
    let node = core.fs.open(FILE_NAME).unwrap();
    // Zeroed pages the test never touches past the file: no memory is used.
    let mut buf = vec![0u8; 1 << 32];

    let len = node.read_at(0, &mut buf).unwrap();

    assert_eq!(len, image.file.len());
    assert_eq!(buf[..len], image.file[..]);
}

#[test]
fn fetch_makes_the_requested_groups_resident_in_the_cache_file() {
    let image = Image::build();
    let cache_dir = tempdir().unwrap();
    let core = image.core(cache_dir.path(), &[]);
    let blob = core.blobs.prepare_all().unwrap().remove(0);
    let group = image.logical(2);

    core.blobs
        .fetch(&blob.id, group.start, group.end - group.start)
        .unwrap();

    let mut resident = vec![0u8; (group.end - group.start) as usize];
    fs::File::open(&blob.cache_path)
        .unwrap()
        .read_exact_at(&mut resident, group.start)
        .unwrap();
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
    assert_eq!(group.start % u64::from(EROFS_BLOCK_SIZE), 0);
}

#[test]
fn fetch_flat_ranges_rejects_corrupted_blob_bytes() {
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

    let err = read_flat(&core, offset, len).unwrap_err();

    assert!(is_chunk_group_crc_mismatch(err.io_error().unwrap()));
    assert!(core.probe_flat_ranges(offset, len).unwrap().is_empty());
    let mut buf = vec![0u8; 4096];
    assert!(core
        .fs
        .open(FILE_NAME)
        .unwrap()
        .read_at(group.start + 4096, &mut buf)
        .is_err());
}
