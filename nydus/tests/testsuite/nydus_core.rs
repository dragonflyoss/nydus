//! Tests for the [`nydus_core::NydusCore`] public API: fixture images are
//! built through the public `build` module and served back through
//! `NydusCore`.

use crate::fixture;

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use crc32c::crc32c_append;
use nydus::build::blob_chunk::BlobWriter;
use nydus::build::bootstrap::{
    render_bootstrap, render_flattened_bootstrap, FLATTENED_BLOB_ALIGNMENT,
};
use nydus::build::inode::{build_tree, set_root_prefetch_blobs_xattr};
use nydus_config::Config;
use nydus_core::ErofsReader;
use nydus_core::{BlobId, FileType, NydusCore};
use nydus_format::blob::BlobMetadataCompressor;
use nydus_format::erofs::ErofsDeviceSlot;
use nydus_format::erofs::{EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE};
use nydus_format::utils::hex_string;
use std::collections::HashSet;
use std::fs;
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

fn build_duplicate_corpus_test_image(
    root: &Path,
) -> (
    PathBuf,
    Config,
    [u8; EROFS_BLOB_ID_SIZE],
    HashMap<String, Vec<u8>>,
) {
    build_test_image_full(root, false, true)
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
    build_test_image_full(root, flattened, false)
}

fn build_test_image_full(
    root: &Path,
    flattened: bool,
    dedup_corpus: bool,
) -> (
    PathBuf,
    Config,
    [u8; EROFS_BLOB_ID_SIZE],
    HashMap<String, Vec<u8>>,
) {
    let corpus_dir = root.join("corpus");
    fs::create_dir_all(&corpus_dir).unwrap();
    // Two ~1.1 MiB incompressible-ish files so the blob spans multiple
    // 1 MiB block groups.
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

    if dedup_corpus {
        let mut shifted = b"shifted-header:".to_vec();
        shifted.extend_from_slice(&corpus["file1"]);
        fs::write(corpus_dir.join("file1_shifted"), &shifted).unwrap();
        corpus.insert("file1_shifted".to_string(), shifted);
        fs::write(corpus_dir.join("file1_copy"), &corpus["file1"]).unwrap();
        corpus.insert("file1_copy".to_string(), corpus["file1"].clone());
        let mut holey = vec![0u8; 3 << 20];
        holey[..4096].copy_from_slice(&corpus["file2"][..4096]);
        holey[(2 << 20) + 5..(2 << 20) + 4101].copy_from_slice(&corpus["file2"][..4096]);
        fs::write(corpus_dir.join("holey"), &holey).unwrap();
        corpus.insert("holey".to_string(), holey);
    }

    let blob_dir = root.join("blobs");
    fs::create_dir_all(&blob_dir).unwrap();
    let staging = blob_dir.join("staging");
    // Block group size pinned to 1 MiB (the chunk size) so the corpus above
    // actually spans several block groups.
    let mut writer = BlobWriter::from_writer(
        fs::File::create(&staging).unwrap(),
        nydus_format::blob::DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
        nydus_format::blob::DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
        BlobMetadataCompressor::Zstd,
    )
    .unwrap();
    let mut inodes = build_tree(
        &corpus_dir,
        &mut writer,
        nydus_format::blob::DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
        &HashSet::new(),
    )
    .unwrap();
    writer.finish().unwrap();

    let data_blob_id = writer.data_digest();
    let blob_metadata = writer.blob_metadata(0).unwrap();
    let blocks = writer.total_blocks();
    set_root_prefetch_blobs_xattr(&mut inodes[0], &[1]).unwrap();
    let embedded_device_slots = [ErofsDeviceSlot::with_blob_id(blocks, &data_blob_id)];
    let embedded_bootstrap_bytes =
        render_bootstrap(&mut inodes, 0, &embedded_device_slots, &[0u8; 16]).unwrap();
    assert_eq!(
        embedded_bootstrap_bytes.len() % EROFS_BLOCK_SIZE as usize,
        0
    );

    let full_blob_digest = write_full_blob(
        &staging,
        &blob_dir,
        &embedded_bootstrap_bytes,
        &blob_metadata,
    );

    let device_slots = [ErofsDeviceSlot::with_blob_id(blocks, &full_blob_digest)];
    let bootstrap_bytes = if flattened {
        render_flattened_bootstrap(&mut inodes, 0, &device_slots, &[0u8; 16]).unwrap()
    } else {
        render_bootstrap(&mut inodes, 0, &device_slots, &[0u8; 16]).unwrap()
    };
    let bootstrap = root.join("bootstrap");
    fs::write(&bootstrap, &bootstrap_bytes).unwrap();

    let config = Config::from_yaml(&format!(
        "backend:\n  type: local\n  config:\n    dir: {}\nstorage:\n  dir: {}\nprefetch:\n  scope: none\n",
        blob_dir.display(),
        root.join("cache").display(),
    ))
    .unwrap();

    (bootstrap, config, full_blob_digest, corpus)
}

fn write_full_blob(
    data_path: &Path,
    blob_dir: &Path,
    bootstrap_bytes: &[u8],
    blob_metadata: &nydus_format::blob::BlobMetadata,
) -> [u8; EROFS_BLOB_ID_SIZE] {
    let data = fs::read(data_path).unwrap();
    let full_blob_digest =
        fixture::assemble_full_blob(blob_dir, &data, bootstrap_bytes, blob_metadata);
    blob_metadata
        .save(&blob_dir.join(format!("{}.blob.meta", hex_string(&full_blob_digest))))
        .unwrap();
    fs::remove_file(data_path).unwrap();
    full_blob_digest
}

#[test]
fn core_describes_devices_and_fetches_aligned_ranges() {
    let dir = tempdir().unwrap();
    let (bootstrap, config, blob_id, _corpus) = build_flattened_test_image(dir.path());
    let blob_id = BlobId::from(blob_id);

    let core = NydusCore::new(&bootstrap, config).unwrap();
    assert_eq!(core.bootstrap_size, fs::metadata(&bootstrap).unwrap().len());
    assert_eq!(core.bootstrap_size % EROFS_BLOCK_SIZE as u64, 0);
    let blobs = core.blobs.prepare_all().unwrap();
    assert_eq!(blobs.len(), 1);
    let descriptor = &blobs[0];
    assert_eq!(descriptor.index, 1);
    assert_eq!(descriptor.id, blob_id);
    assert!(!descriptor.is_redirect);
    assert_eq!(
        descriptor.cache_size,
        descriptor.blocks * EROFS_BLOCK_SIZE as u64
    );
    assert!(descriptor.mapped_offset >= core.bootstrap_size);
    assert_eq!(
        descriptor.mapped_offset,
        descriptor.mapped_blkaddr * EROFS_BLOCK_SIZE as u64
    );
    let meta = fs::metadata(&descriptor.cache_path).unwrap();
    assert_eq!(meta.len(), descriptor.cache_size);
    assert_eq!(
        core.flat_size(),
        descriptor.mapped_offset + descriptor.cache_size
    );
    assert_eq!(
        core.bootstrap().metadata().unwrap().len(),
        core.bootstrap_size
    );
    assert!(core.zero_fd() >= 0);
    let bootstrap_ranges = core.fetch_flat_ranges(0, EROFS_BLOCK_SIZE as u64).unwrap();
    assert_eq!(bootstrap_ranges.len(), 1);
    assert_eq!(bootstrap_ranges[0].fd, core.bootstrap().as_raw_fd());
    assert_eq!(bootstrap_ranges[0].offset, 0);
    assert_eq!(bootstrap_ranges[0].source_offset, 0);
    assert_eq!(bootstrap_ranges[0].len, EROFS_BLOCK_SIZE as u64);

    // Fetch a block-aligned range spanning more than one block group's worth
    // of data; the cache file should be populated for that range and a second
    // fetch is idempotent. The dense blob address space is independent of
    // path order, so exact file content is covered by the static read API
    // test below.
    let block = EROFS_BLOCK_SIZE as u64;
    let (blob_offset, len) = (block, 272 * block);
    let offset = descriptor.mapped_offset + blob_offset;
    assert!(core.probe_flat_ranges(offset, len).unwrap().is_empty());
    let fd_ranges = core.fetch_flat_ranges(offset, len).unwrap();
    assert_eq!(fd_ranges.len(), 1);
    assert_eq!(fd_ranges[0].offset, blob_offset);
    assert_eq!(fd_ranges[0].len, len);
    assert_eq!(fd_ranges[0].source_offset, offset);
    assert_ne!(fd_ranges[0].fd, core.zero_fd());
    core.blobs.fetch(&blob_id, blob_offset, len).unwrap();
    let cached = fs::read(&descriptor.cache_path).unwrap();
    assert!(cached[blob_offset as usize..(blob_offset + len) as usize]
        .iter()
        .any(|byte| *byte != 0));
    assert_eq!(core.probe_flat_ranges(offset, len).unwrap(), fd_ranges);

    // Idempotent re-fetch and zero-length fetch are fine.
    core.blobs.fetch(&blob_id, offset, len).unwrap();
    core.blobs.fetch(&blob_id, 0, 0).unwrap();

    let trace = core.trace_snapshot();
    assert_eq!(trace.entries.len(), 2);
    assert!(trace.entries.iter().all(|entry| entry.blob_index == 1));
    assert_eq!(trace.entries[0].block_group_index, 0);
    assert_eq!(trace.entries[1].block_group_index, 1);
    assert_eq!(
        core.trace_json(),
        "{\"version\":1,\"patterns\":[{\"blob_index\":1,\"block_group_index\":0},{\"blob_index\":1,\"block_group_index\":1}]}"
    );

    // Unaligned ranges and unknown blobs are rejected.
    assert!(core.blobs.fetch(&blob_id, 1, block).is_err());
    assert!(core.blobs.fetch(&blob_id, 0, block + 1).is_err());
    assert!(core
        .blobs
        .fetch(&BlobId::from([0u8; 32]), 0, block)
        .is_err());

    // Out-of-range fetch fails rather than fabricating data.
    assert!(core
        .blobs
        .fetch(&blob_id, descriptor.cache_size, block)
        .is_err());
}

#[test]
fn flattened_bootstrap_records_mapped_device_slots() {
    let dir = tempdir().unwrap();
    let (bootstrap, _config, blob_id, _corpus) = build_test_image(dir.path());
    let reader = ErofsReader::open_metadata_only(&bootstrap).unwrap();
    let blob_infos = reader.blob_infos().unwrap();
    assert_eq!(blob_infos.len(), 1);
    assert_eq!(blob_infos[0].blob_id, blob_id);
    assert_eq!(blob_infos[0].mapped_blkaddr, 0);

    let corpus_dir = dir.path().join("corpus");
    let blob_dir = dir.path().join("second-blobs");
    fs::create_dir_all(&blob_dir).unwrap();
    let staging = blob_dir.join("staging");
    // Same pinned 1 MiB block group geometry as build_test_image_with_layout.
    let mut writer = BlobWriter::from_writer(
        fs::File::create(&staging).unwrap(),
        nydus_format::blob::DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
        nydus_format::blob::DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
        BlobMetadataCompressor::Zstd,
    )
    .unwrap();
    let mut inodes = build_tree(
        &corpus_dir,
        &mut writer,
        nydus_format::blob::DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
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
    let flattened = render_flattened_bootstrap(&mut inodes, 0, &device_slots, &[0u8; 16]).unwrap();
    assert_eq!(flattened.len() % EROFS_BLOCK_SIZE as usize, 0);

    let sb_offset = nydus_format::erofs::EROFS_SUPER_OFFSET as usize;
    let checksum = u32::from_le_bytes(flattened[sb_offset + 4..sb_offset + 8].try_into().unwrap());
    let mut block0 = flattened[sb_offset..EROFS_BLOCK_SIZE as usize].to_vec();
    block0[4..8].fill(0);
    assert_eq!(checksum, !crc32c_append(0u32, &block0));

    let flattened_path = dir.path().join("flattened.bootstrap");
    fs::write(&flattened_path, flattened).unwrap();
    let flattened_reader = ErofsReader::open_metadata_only(&flattened_path).unwrap();
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
fn core_static_filesystem_api_reads_metadata_and_data() {
    let dir = tempdir().unwrap();
    let (bootstrap, config, blob_id, corpus) = build_test_image(dir.path());
    let blob_id = BlobId::from(blob_id);

    let core = NydusCore::new(&bootstrap, config).unwrap();

    let root_entry = core.fs.open("/").unwrap();
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

    let file1_entry = core.fs.open("file1").unwrap();
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

    let tiny = core.fs.open("tiny.txt").unwrap().read().unwrap();
    assert_eq!(
        &tiny[..corpus["tiny.txt"].len()],
        corpus["tiny.txt"].as_slice()
    );
    assert!(tiny[corpus["tiny.txt"].len()..]
        .iter()
        .all(|byte| *byte == 0));
    assert!(core
        .fs
        .open("empty.txt")
        .unwrap()
        .read()
        .unwrap()
        .is_empty());
    let small = core.fs.open("dir/small.txt").unwrap().read().unwrap();
    assert_eq!(
        &small[..corpus["dir/small.txt"].len()],
        corpus["dir/small.txt"].as_slice()
    );
    assert!(small[corpus["dir/small.txt"].len()..]
        .iter()
        .all(|byte| *byte == 0));

    let link_entry = core.fs.open("link_to_file1").unwrap();
    let link = link_entry.read_link().unwrap();
    assert_eq!(link, b"file1");
    assert_eq!(link_entry.read_link().unwrap(), b"file1");
    let link_meta = link_entry.metadata().unwrap();
    assert_eq!(link_meta.file_type, FileType::Symlink);

    let xattrs = root_entry.xattrs().unwrap();
    assert!(xattrs.iter().any(|(name, value)| {
        name.as_slice() == b"trusted.nydus.prefetch.blobs" && value.as_slice() == b"1"
    }));

    let blobs = core.blobs.prepare_all().unwrap();
    let cached = fs::read(&blobs[0].cache_path).unwrap();
    assert!(cached.iter().any(|byte| *byte != 0));
    assert_eq!(blobs[0].id, blob_id);
}

#[test]
fn node_fetch_populates_blob_cache_without_reading_data() {
    let dir = tempdir().unwrap();
    let (bootstrap, config, _blob_id, _corpus) = build_test_image(dir.path());

    let core = NydusCore::new(&bootstrap, config).unwrap();
    let blobs = core.blobs.prepare_all().unwrap();
    let before = fs::read(&blobs[0].cache_path).unwrap();
    assert!(before.iter().all(|byte| *byte == 0));

    let file1_entry = core.fs.open("file1").unwrap();
    assert!(file1_entry.probe_ranges(12345, 4097).unwrap().is_empty());
    let ranges = file1_entry.fetch_ranges(12345, 4097).unwrap();
    assert!(!ranges.is_empty());
    assert_eq!(ranges[0].source_offset, 12345);
    assert_ne!(ranges[0].fd, core.zero_fd());
    file1_entry.fetch(12345, 4097).unwrap();
    assert_eq!(file1_entry.probe_ranges(12345, 4097).unwrap(), ranges);

    let after = fs::read(&blobs[0].cache_path).unwrap();
    assert!(after.iter().any(|byte| *byte != 0));
    file1_entry.fetch(0, 0).unwrap();
    core.fs.open("/").unwrap().fetch(0, 4096).unwrap_err();
}

#[test]
fn core_reads_back_duplicate_corpus_image() {
    let dir = tempdir().unwrap();
    let (bootstrap, config, _blob_id, corpus) = build_duplicate_corpus_test_image(dir.path());

    let core = NydusCore::new(&bootstrap, config).unwrap();

    for (name, expected) in &corpus {
        let entry = core.fs.open(name).unwrap();
        let all = entry.read().unwrap();
        assert_eq!(
            &all[..expected.len()],
            expected.as_slice(),
            "content mismatch for {name}"
        );
        assert!(
            all[expected.len()..].iter().all(|byte| *byte == 0),
            "tail padding not zero for {name}"
        );
    }

    let entry = core.fs.open("file1_shifted").unwrap();
    let mut buf = vec![0u8; 100_000];
    let read = entry.read_at(123_457, &mut buf).unwrap();
    assert_eq!(read, buf.len());
    assert_eq!(&buf, &corpus["file1_shifted"][123_457..123_457 + read]);

    let file1_entry = core.fs.open("file1").unwrap();
    file1_entry.fetch(12345, 4097).unwrap();
    assert!(!file1_entry.probe_ranges(12345, 4097).unwrap().is_empty());
}
