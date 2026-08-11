//! Integration tests for `ErofsReader`. They live in `tests/` (not as unit
//! tests) because building fixture images requires the `nydus` builder,
//! which itself depends on this crate.

mod common;


use std::collections::HashSet;
use std::fs;
use std::io::Write;

use tempfile::{tempdir, NamedTempFile};

use nydus::build::blob_chunk::BlobWriter;
use nydus::build::bootstrap::render_bootstrap;
use nydus::build::inode::{build_tree, DirEntry as BuildDirEntry, InodeData, InodeInfo};
use nydus_core::fs::ErofsReader;
use nydus_core::metadata::{
    erofs_xattr_ibody_size, ChunkIndex, ErofsDeviceSlot, EROFS_BLKSZBITS,
    EROFS_BLOCK_SIZE, EROFS_FT_REG_FILE, EROFS_XATTR_INDEX_USER,
};
use nydus_core::utils::sha256_file;

#[test]
fn reads_large_xattrs_and_chunk_indexes_after_large_ibody() {
    let file_xattrs: Vec<(u8, Vec<u8>, Vec<u8>)> = (0..8)
        .map(|index| {
            (
                EROFS_XATTR_INDEX_USER,
                format!("large_{index:02}").into_bytes(),
                vec![b'A' + index as u8; 700],
            )
        })
        .collect();
    assert!(erofs_xattr_ibody_size(&file_xattrs) > EROFS_BLOCK_SIZE as usize);

    let mut inodes = vec![
        InodeInfo {
            mode: 0o040755,
            uid: 0,
            gid: 0,
            size: 0,
            mtime: 1_700_000_000,
            mtime_nsec: 0,
            nlink: 2,
            ino: 1,
            nid: 0,
            meta_offset: 0,
            is_extended: true,
            data: InodeData::Directory {
                children: vec![BuildDirEntry {
                    name: "huge_xattrs".into(),
                    file_type: EROFS_FT_REG_FILE,
                    inode_index: 1,
                }],
                startblk: 0,
                data_size: 0,
                parent_nid: 0,
            },
            xattrs: Vec::new(),
        },
        InodeInfo {
            mode: 0o100644,
            uid: 0,
            gid: 0,
            size: (EROFS_BLOCK_SIZE as u64) * 2,
            mtime: 1_700_000_123,
            mtime_nsec: 123_456_789,
            nlink: 1,
            ino: 2,
            nid: 0,
            meta_offset: 0,
            is_extended: false,
            data: InodeData::RegularFile {
                chunk_index_entries: vec![
                    ChunkIndex {
                        blkaddr: 11,
                        device_id: 0,
                    },
                    ChunkIndex {
                        blkaddr: 22,
                        device_id: 0,
                    },
                ],
                chunk_size_bits: EROFS_BLKSZBITS as u32,
            },
            xattrs: file_xattrs.clone(),
        },
    ];

    let bootstrap = render_bootstrap(
        &mut inodes,
        1_700_000_000,
        EROFS_BLKSZBITS as u32,
        &[],
        &[0u8; 16],
    )
    .expect("render bootstrap");
    let mut image = NamedTempFile::new().expect("create temp image");
    image.write_all(&bootstrap).expect("write bootstrap");

    let reader = ErofsReader::open_metadata_only(image.path()).expect("open bootstrap");
    let file_nid = inodes[1].nid;
    let inode = reader.inode(file_nid).expect("read inode");

    let xattrs = reader.read_xattrs(file_nid, &inode).expect("read xattrs");
    assert_eq!(xattrs.len(), file_xattrs.len());
    for ((name, value), (_, suffix, expected_value)) in xattrs.iter().zip(file_xattrs.iter()) {
        let expected_name = [b"user.".as_slice(), suffix.as_slice()].concat();
        assert_eq!(name, &expected_name);
        assert_eq!(value, expected_value);
    }

    let chunk_index_entries = reader
        .read_chunk_index_entries(file_nid, &inode)
        .expect("read chunk indexes");
    assert_eq!(chunk_index_entries.len(), 2);
    assert_eq!(chunk_index_entries[0].blkaddr, 11);
    assert_eq!(chunk_index_entries[0].device_id, 0);
    assert_eq!(chunk_index_entries[1].blkaddr, 22);
    assert_eq!(chunk_index_entries[1].device_id, 0);
}

#[test]
fn reads_chunk_data_from_footer_based_full_blob() {
    let dir = tempdir().expect("create temp dir");
    let source_dir = dir.path().join("src");
    fs::create_dir(&source_dir).expect("create source dir");
    fs::write(source_dir.join("hello.txt"), b"hello nydus\n").expect("write source");

    let data_path = dir.path().join("data.blob");
    let mut blob_writer = BlobWriter::new(&data_path, EROFS_BLOCK_SIZE).expect("blob writer");
    let mut inodes = build_tree(
        &source_dir,
        &mut blob_writer,
        EROFS_BLOCK_SIZE,
        &HashSet::new(),
    )
    .expect("build tree");
    blob_writer.finish().expect("finish blob writer");

    let data_blob_id = sha256_file(&data_path).expect("hash data blob");
    let embedded_device_slots = [ErofsDeviceSlot::with_blob_id(
        blob_writer.total_blocks(),
        &data_blob_id,
    )];
    let embedded_bootstrap = render_bootstrap(
        &mut inodes,
        1_700_000_000,
        EROFS_BLKSZBITS as u32,
        &embedded_device_slots,
        &[0u8; 16],
    )
    .expect("render embedded bootstrap");
    let blob_meta = blob_writer.blob_meta(data_blob_id, 0).expect("blob meta");

    let data = fs::read(&data_path).expect("read data blob");
    let full_blob_id = common::assemble_full_blob(dir.path(), &data, &embedded_bootstrap, &blob_meta);

    let standalone_device_slots = [ErofsDeviceSlot::with_blob_id(
        blob_writer.total_blocks(),
        &full_blob_id,
    )];
    let bootstrap = render_bootstrap(
        &mut inodes,
        1_700_000_000,
        EROFS_BLKSZBITS as u32,
        &standalone_device_slots,
        &[0u8; 16],
    )
    .expect("render standalone bootstrap");

    let bootstrap_path = dir.path().join("bootstrap");
    fs::write(&bootstrap_path, &bootstrap).expect("write bootstrap file");

    let backend: std::sync::Arc<dyn nydus_core::storage::backend::BlobBackend> =
        std::sync::Arc::new(nydus_core::storage::backend::LocalBackend::new(
            dir.path().to_path_buf(),
        ));
    let reader =
        ErofsReader::open(None, Some(&bootstrap_path), Some(backend), None).expect("open reader");
    let root = reader.inode(reader.sb().root_nid()).expect("root inode");
    let entries = reader
        .read_dir(reader.sb().root_nid(), &root)
        .expect("read root dir");
    let file_nid = entries
        .iter()
        .find(|entry| entry.name == b"hello.txt")
        .expect("hello entry")
        .nid;
    let inode = reader.inode(file_nid).expect("file inode");
    let data = reader
        .read_file_data(file_nid, &inode, 0, inode.size() as u32)
        .expect("read file data");

    assert_eq!(data, b"hello nydus\n");
}
