//! Integration tests for the `NydusAccessor` public API. They live in
//! `tests/` (not as unit tests) because building fixture images requires the
//! `nydus` builder, which itself depends on this crate.

mod common;

use common::{align_u64, bytes_to_blocks, write_zero_padding};

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use crc32c::crc32c_append;
use nydus::build::blob_chunk::BlobWriter;
use nydus::build::bootstrap::{
    render_bootstrap, render_flattened_bootstrap, FLATTENED_BLOB_ALIGNMENT,
};
use nydus::build::inode::{build_tree, set_root_prefetch_blobs_xattr};
use nydus_accessor::config::Config;
use nydus_accessor::fs::ErofsReader;
use nydus_accessor::metadata::{
    BlobFooter, BlobMetaCompressor, ErofsDeviceSlot, NYDUS_BLOB_FOOTER_ALIGNMENT,
};
use nydus_accessor::metadata::{EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE};
use nydus_accessor::utils::{hex_string, sha256_file};
use nydus_accessor::{BlobID, FileType, NydusAccessor};
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::symlink;
use tempfile::tempdir;

/// Build a minimal single-blob nydus image (blob dir + bootstrap +
/// config) and return (bootstrap, config, data blob id, expected file bytes).
fn build_test_image(
    root: &Path,
) -> (
    PathBuf,
    Config,
    [u8; EROFS_BLOB_ID_SIZE],
    HashMap<String, Vec<u8>>,
) {
    build_test_image_with_layout(root, false)
}

fn build_flattened_test_image(
    root: &Path,
) -> (
    PathBuf,
    Config,
    [u8; EROFS_BLOB_ID_SIZE],
    HashMap<String, Vec<u8>>,
) {
    build_test_image_with_layout(root, true)
}

fn build_test_image_with_layout(
    root: &Path,
    flattened: bool,
) -> (
    PathBuf,
    Config,
    [u8; EROFS_BLOB_ID_SIZE],
    HashMap<String, Vec<u8>>,
) {
    let corpus_dir = root.join("corpus");
    fs::create_dir_all(&corpus_dir).unwrap();
    // Two ~1.1 MiB incompressible-ish files so the blob spans multiple
    // 1 MiB groups.
    let mut corpus = HashMap::new();
    for seed in 1u64..=2 {
        let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let mut data = vec![0u8; (1 << 20) + 64 * 1024];
        for byte in data.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        fs::write(corpus_dir.join(format!("file{seed}")), &data).unwrap();
        corpus.insert(format!("file{seed}"), data);
    }
    fs::create_dir_all(corpus_dir.join("dir")).unwrap();
    fs::write(corpus_dir.join("dir/small.txt"), b"small file").unwrap();
    corpus.insert("dir/small.txt".to_string(), b"small file".to_vec());
    fs::write(corpus_dir.join("tiny.txt"), b"hello").unwrap();
    corpus.insert("tiny.txt".to_string(), b"hello".to_vec());
    fs::write(corpus_dir.join("empty.txt"), b"").unwrap();
    corpus.insert("empty.txt".to_string(), Vec::new());
    symlink("file1", corpus_dir.join("link_to_file1")).unwrap();

    let blob_dir = root.join("blobs");
    fs::create_dir_all(&blob_dir).unwrap();
    let staging = blob_dir.join("staging");
    let mut writer = BlobWriter::new_with_compressor(
        &staging,
        nydus_accessor::metadata::BLOB_META_DEFAULT_CHUNK_SIZE,
        BlobMetaCompressor::Zstd,
    )
    .unwrap();
    let mut inodes = build_tree(
        &corpus_dir,
        &mut writer,
        nydus_accessor::metadata::BLOB_META_DEFAULT_CHUNK_SIZE,
        &HashSet::new(),
    )
    .unwrap();
    writer.finish().unwrap();

    let data_blob_id = writer.data_digest();
    let blob_meta = writer.blob_meta(data_blob_id, 0).unwrap();
    let blocks = writer.total_blocks();
    set_root_prefetch_blobs_xattr(&mut inodes[0], &[1]).unwrap();
    let embedded_device_slots = [ErofsDeviceSlot::with_blob_id(blocks, &data_blob_id)];
    let embedded_bootstrap_bytes = render_bootstrap(
        &mut inodes,
        0,
        nydus_accessor::metadata::BLOB_META_DEFAULT_CHUNK_SIZE.trailing_zeros(),
        &embedded_device_slots,
        &[0u8; 16],
    )
    .unwrap();
    assert_eq!(
        embedded_bootstrap_bytes.len() % EROFS_BLOCK_SIZE as usize,
        0
    );

    let full_blob_id = write_full_blob(&staging, &blob_dir, &embedded_bootstrap_bytes, &blob_meta);

    let device_slots = [ErofsDeviceSlot::with_blob_id(blocks, &full_blob_id)];
    let bootstrap_bytes = if flattened {
        render_flattened_bootstrap(
            &mut inodes,
            0,
            nydus_accessor::metadata::BLOB_META_DEFAULT_CHUNK_SIZE.trailing_zeros(),
            &device_slots,
            &[0u8; 16],
        )
        .unwrap()
    } else {
        render_bootstrap(
            &mut inodes,
            0,
            nydus_accessor::metadata::BLOB_META_DEFAULT_CHUNK_SIZE.trailing_zeros(),
            &device_slots,
            &[0u8; 16],
        )
        .unwrap()
    };
    let bootstrap = root.join("bootstrap");
    fs::write(&bootstrap, &bootstrap_bytes).unwrap();

    let config = Config::from_yaml(&format!(
        "backend:\n  type: local\n  config:\n    dir: {}\ncache:\n  type: local\n  config:\n    dir: {}\nprefetch:\n  enable: false\n",
        blob_dir.display(),
        root.join("cache").display(),
    ))
    .unwrap();

    (bootstrap, config, full_blob_id, corpus)
}

fn write_full_blob(
    data_path: &Path,
    blob_dir: &Path,
    bootstrap_bytes: &[u8],
    blob_meta: &nydus_accessor::metadata::BlobMeta,
) -> [u8; EROFS_BLOB_ID_SIZE] {
    let data = fs::read(data_path).unwrap();
    let data_size = data.len() as u64;
    let bootstrap_offset = align_u64(data_size, NYDUS_BLOB_FOOTER_ALIGNMENT);
    let bootstrap_blocks = bytes_to_blocks(bootstrap_bytes.len() as u64);
    let blob_meta_offset = align_u64(
        bootstrap_offset + bootstrap_bytes.len() as u64,
        NYDUS_BLOB_FOOTER_ALIGNMENT,
    );
    let blob_meta_blocks = bytes_to_blocks(blob_meta.metadata_size());
    let footer = BlobFooter::new(
        0,
        data_size,
        bootstrap_offset,
        bootstrap_blocks,
        blob_meta_offset,
        blob_meta_blocks,
    )
    .unwrap();

    let full_blob_path = blob_dir.join("full.blob");
    let mut full_blob = fs::File::create(&full_blob_path).unwrap();
    full_blob.write_all(&data).unwrap();
    write_zero_padding(&mut full_blob, data_size, bootstrap_offset).unwrap();
    full_blob.write_all(bootstrap_bytes).unwrap();
    write_zero_padding(
        &mut full_blob,
        bootstrap_offset + bootstrap_bytes.len() as u64,
        blob_meta_offset,
    )
    .unwrap();
    blob_meta.write_to(&mut full_blob).unwrap();
    footer.write_to(&mut full_blob).unwrap();
    drop(full_blob);

    let full_blob_id = sha256_file(&full_blob_path).unwrap();
    let final_blob_path = blob_dir.join(hex_string(&full_blob_id));
    fs::rename(&full_blob_path, &final_blob_path).unwrap();
    blob_meta
        .save(&blob_dir.join(format!("{}.blob.meta", hex_string(&full_blob_id))))
        .unwrap();
    fs::remove_file(data_path).unwrap();
    full_blob_id
}

#[test]
fn accessor_describes_devices_and_fetches_aligned_ranges() {
    let dir = tempdir().unwrap();
    let (bootstrap, config, blob_id, _corpus) = build_flattened_test_image(dir.path());
    let blob_id = BlobID::from(blob_id);

    let accessor = NydusAccessor::new(&bootstrap, config).unwrap();
    assert_eq!(
        accessor.bootstrap_size,
        fs::metadata(&bootstrap).unwrap().len()
    );
    assert_eq!(accessor.bootstrap_size % EROFS_BLOCK_SIZE as u64, 0);
    let blobs = accessor.blob.entries().unwrap();
    assert_eq!(blobs.len(), 1);
    let descriptor = &blobs[0];
    assert_eq!(descriptor.index, 1);
    assert_eq!(descriptor.id, blob_id);
    assert!(!descriptor.is_redirect);
    assert_eq!(
        descriptor.cache_size,
        descriptor.blocks * EROFS_BLOCK_SIZE as u64
    );
    assert!(descriptor.mapped_offset >= accessor.bootstrap_size);
    assert_eq!(
        descriptor.mapped_offset,
        descriptor.mapped_blkaddr * EROFS_BLOCK_SIZE as u64
    );
    let meta = fs::metadata(&descriptor.cache_path).unwrap();
    assert_eq!(meta.len(), descriptor.cache_size);
    assert_eq!(
        accessor.flat_size(),
        descriptor.mapped_offset + descriptor.cache_size
    );
    assert_eq!(
        accessor.bootstrap().metadata().unwrap().len(),
        accessor.bootstrap_size
    );
    assert!(accessor.zero_fd() >= 0);
    let bootstrap_ranges = accessor
        .fetch_flat_ranges(0, EROFS_BLOCK_SIZE as u64)
        .unwrap();
    assert_eq!(bootstrap_ranges.len(), 1);
    assert_eq!(bootstrap_ranges[0].fd, accessor.bootstrap().as_raw_fd());
    assert_eq!(bootstrap_ranges[0].offset, 0);
    assert_eq!(bootstrap_ranges[0].source_offset, 0);
    assert_eq!(bootstrap_ranges[0].len, EROFS_BLOCK_SIZE as u64);

    // Fetch a block-aligned range in the middle; the cache file should be
    // populated for that range and a second fetch is idempotent. The dense
    // blob address space is independent of path order, so exact file
    // content is covered by the static read API test below.
    let block = EROFS_BLOCK_SIZE as u64;
    let (blob_offset, len) = (256 * block, 16 * block);
    let offset = descriptor.mapped_offset + blob_offset;
    assert!(accessor.probe_flat_ranges(offset, len).unwrap().is_empty());
    let fd_ranges = accessor.fetch_flat_ranges(offset, len).unwrap();
    assert_eq!(fd_ranges.len(), 1);
    assert_eq!(fd_ranges[0].offset, blob_offset);
    assert_eq!(fd_ranges[0].len, len);
    assert_eq!(fd_ranges[0].source_offset, offset);
    assert_ne!(fd_ranges[0].fd, accessor.zero_fd());
    accessor.blob.fetch(&blob_id, blob_offset, len).unwrap();
    let cached = fs::read(&descriptor.cache_path).unwrap();
    assert!(cached[blob_offset as usize..(blob_offset + len) as usize]
        .iter()
        .any(|byte| *byte != 0));
    assert_eq!(accessor.probe_flat_ranges(offset, len).unwrap(), fd_ranges);

    // Idempotent re-fetch and zero-length fetch are fine.
    accessor.blob.fetch(&blob_id, offset, len).unwrap();
    accessor.blob.fetch(&blob_id, 0, 0).unwrap();

    let trace = accessor.trace_snapshot();
    assert_eq!(trace.patterns.len(), 1);
    assert_eq!(trace.patterns[0].blob_index, 1);
    assert_eq!(trace.patterns[0].group_index, 1);
    assert_eq!(
        accessor.trace_json(),
        "{\"version\":1,\"patterns\":[{\"blob_index\":1,\"group_index\":1}]}"
    );

    // Unaligned ranges and unknown blobs are rejected.
    assert!(accessor.blob.fetch(&blob_id, 1, block).is_err());
    assert!(accessor.blob.fetch(&blob_id, 0, block + 1).is_err());
    assert!(accessor
        .blob
        .fetch(&BlobID::from([0u8; 32]), 0, block)
        .is_err());

    // Out-of-range fetch fails rather than fabricating data.
    assert!(accessor
        .blob
        .fetch(&blob_id, descriptor.cache_size, block)
        .is_err());
}

#[test]
fn flattened_bootstrap_records_mapped_device_slots() {
    let dir = tempdir().unwrap();
    let (bootstrap, _config, blob_id, _corpus) = build_test_image(dir.path());
    let reader = ErofsReader::open_layer(&bootstrap).unwrap();
    let blob_infos = reader.blob_infos().unwrap();
    assert_eq!(blob_infos.len(), 1);
    assert_eq!(blob_infos[0].blob_id, blob_id);
    assert_eq!(blob_infos[0].mapped_blkaddr, 0);

    let corpus_dir = dir.path().join("corpus");
    let blob_dir = dir.path().join("second-blobs");
    fs::create_dir_all(&blob_dir).unwrap();
    let staging = blob_dir.join("staging");
    let mut writer = BlobWriter::new_with_compressor(
        &staging,
        nydus_accessor::metadata::BLOB_META_DEFAULT_CHUNK_SIZE,
        BlobMetaCompressor::Zstd,
    )
    .unwrap();
    let mut inodes = build_tree(
        &corpus_dir,
        &mut writer,
        nydus_accessor::metadata::BLOB_META_DEFAULT_CHUNK_SIZE,
        &HashSet::new(),
    )
    .unwrap();
    writer.finish().unwrap();

    let second_blob_id = writer.data_digest();
    let device_slots = [
        ErofsDeviceSlot::with_blob_id(blob_infos[0].blocks, &blob_id),
        ErofsDeviceSlot::with_blob_id(writer.total_blocks(), &second_blob_id),
    ];
    set_root_prefetch_blobs_xattr(&mut inodes[0], &[1, 2]).unwrap();
    let flattened = render_flattened_bootstrap(
        &mut inodes,
        0,
        nydus_accessor::metadata::BLOB_META_DEFAULT_CHUNK_SIZE.trailing_zeros(),
        &device_slots,
        &[0u8; 16],
    )
    .unwrap();
    assert_eq!(flattened.len() % EROFS_BLOCK_SIZE as usize, 0);

    let sb_offset = nydus_accessor::metadata::EROFS_SUPER_OFFSET as usize;
    let checksum = u32::from_le_bytes(flattened[sb_offset + 4..sb_offset + 8].try_into().unwrap());
    let mut block0 = flattened[sb_offset..EROFS_BLOCK_SIZE as usize].to_vec();
    block0[4..8].fill(0);
    assert_eq!(checksum, !crc32c_append(0u32, &block0));

    let flattened_path = dir.path().join("flattened.bootstrap");
    fs::write(&flattened_path, flattened).unwrap();
    let flattened_reader = ErofsReader::open_layer(&flattened_path).unwrap();
    let infos = flattened_reader.blob_infos().unwrap();
    assert_eq!(infos.len(), 2);

    let first_offset = (fs::metadata(&flattened_path).unwrap().len() + FLATTENED_BLOB_ALIGNMENT
        - 1)
        & !(FLATTENED_BLOB_ALIGNMENT - 1);
    let second_offset =
        (first_offset + infos[0].blocks * EROFS_BLOCK_SIZE as u64 + FLATTENED_BLOB_ALIGNMENT - 1)
            & !(FLATTENED_BLOB_ALIGNMENT - 1);
    assert_eq!(
        infos[0].mapped_blkaddr,
        first_offset / EROFS_BLOCK_SIZE as u64
    );
    assert_eq!(
        infos[1].mapped_blkaddr,
        second_offset / EROFS_BLOCK_SIZE as u64
    );
    assert!(infos[1].mapped_blkaddr > infos[0].mapped_blkaddr);
}

#[test]
fn accessor_static_filesystem_api_reads_metadata_and_data() {
    let dir = tempdir().unwrap();
    let (bootstrap, config, blob_id, corpus) = build_test_image(dir.path());
    let blob_id = BlobID::from(blob_id);

    let accessor = NydusAccessor::new(&bootstrap, config).unwrap();

    let root_entry = accessor.fs.open("/").unwrap();
    let root = root_entry.metadata().unwrap();
    assert_eq!(root.file_type, FileType::Directory);

    let entries = root_entry.read_dir().unwrap();
    let names = entries
        .iter()
        .map(|entry| entry.name.as_str())
        .collect::<Vec<_>>();
    assert!(names.contains(&"file1"));
    assert!(names.contains(&"dir"));
    assert!(names.contains(&"link_to_file1"));

    let file1_entry = accessor.fs.open("file1").unwrap();
    let file1 = file1_entry.metadata().unwrap();
    assert_eq!(file1.file_type, FileType::RegularFile);
    assert!(file1.size >= corpus["file1"].len() as u64);

    let all = file1_entry.read().unwrap();
    assert_eq!(&all[..corpus["file1"].len()], corpus["file1"].as_slice());
    assert!(all[corpus["file1"].len()..].iter().all(|byte| *byte == 0));

    let mut buf = vec![0u8; 4097];
    let read = file1_entry.read_at(12345, &mut buf).unwrap();
    assert_eq!(read, buf.len());
    assert_eq!(&buf, &corpus["file1"][12345..12345 + read]);
    let mut second = vec![0u8; 32];
    let read = file1_entry.read_at(777, &mut second).unwrap();
    assert_eq!(read, second.len());
    assert_eq!(&second, &corpus["file1"][777..777 + read]);

    let tiny = accessor.fs.open("tiny.txt").unwrap().read().unwrap();
    assert_eq!(
        &tiny[..corpus["tiny.txt"].len()],
        corpus["tiny.txt"].as_slice()
    );
    assert!(tiny[corpus["tiny.txt"].len()..]
        .iter()
        .all(|byte| *byte == 0));
    assert!(accessor
        .fs
        .open("empty.txt")
        .unwrap()
        .read()
        .unwrap()
        .is_empty());
    let small = accessor.fs.open("dir/small.txt").unwrap().read().unwrap();
    assert_eq!(
        &small[..corpus["dir/small.txt"].len()],
        corpus["dir/small.txt"].as_slice()
    );
    assert!(small[corpus["dir/small.txt"].len()..]
        .iter()
        .all(|byte| *byte == 0));

    let link_entry = accessor.fs.open("link_to_file1").unwrap();
    let link = link_entry.read_link().unwrap();
    assert_eq!(link, b"file1");
    assert_eq!(link_entry.read_link().unwrap(), b"file1");
    let link_meta = link_entry.metadata().unwrap();
    assert_eq!(link_meta.file_type, FileType::Symlink);

    let xattrs = root_entry.xattrs().unwrap();
    assert!(xattrs.iter().any(|(name, value)| {
        name.as_slice() == b"trusted.nydus.prefetch.blobs" && value.as_slice() == b"1"
    }));

    let blobs = accessor.blob.entries().unwrap();
    let cached = fs::read(&blobs[0].cache_path).unwrap();
    assert!(cached.iter().any(|byte| *byte != 0));
    assert_eq!(blobs[0].id, blob_id);
}

#[test]
fn fs_entry_fetch_populates_blob_cache_without_reading_data() {
    let dir = tempdir().unwrap();
    let (bootstrap, config, _blob_id, _corpus) = build_test_image(dir.path());

    let accessor = NydusAccessor::new(&bootstrap, config).unwrap();
    let blobs = accessor.blob.entries().unwrap();
    let before = fs::read(&blobs[0].cache_path).unwrap();
    assert!(before.iter().all(|byte| *byte == 0));

    let file1_entry = accessor.fs.open("file1").unwrap();
    assert!(file1_entry.probe_ranges(12345, 4097).unwrap().is_empty());
    let ranges = file1_entry.fetch_ranges(12345, 4097).unwrap();
    assert!(!ranges.is_empty());
    assert_eq!(ranges[0].source_offset, 12345);
    assert_ne!(ranges[0].fd, accessor.zero_fd());
    file1_entry.fetch(12345, 4097).unwrap();
    assert_eq!(file1_entry.probe_ranges(12345, 4097).unwrap(), ranges);

    let after = fs::read(&blobs[0].cache_path).unwrap();
    assert!(after.iter().any(|byte| *byte != 0));
    file1_entry.fetch(0, 0).unwrap();
    accessor.fs.open("/").unwrap().fetch(0, 4096).unwrap_err();
}
