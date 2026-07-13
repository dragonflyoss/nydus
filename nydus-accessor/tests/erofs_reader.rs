//! Integration tests for `ErofsReader`. They live in `tests/` (not as unit
//! tests) because building fixture images requires the `nydus` builder,
//! which itself depends on this crate.

mod common;

use common::{align_u64, bytes_to_blocks, write_zero_padding};

use std::collections::HashSet;
use std::fs;
use std::io::Write;

use tempfile::{tempdir, NamedTempFile};

use nydus::build::blob_chunk::BlobWriter;
use nydus::build::bootstrap::render_bootstrap;
use nydus::build::inode::{build_tree, DirEntry as BuildDirEntry, InodeData, InodeInfo};
use nydus_accessor::fs::ErofsReader;
use nydus_accessor::metadata::{
    erofs_xattr_ibody_size, BlobFooter, ChunkIndex, ErofsDeviceSlot, EROFS_BLKSZBITS,
    EROFS_BLOCK_SIZE, EROFS_FT_REG_FILE, EROFS_XATTR_INDEX_USER, NYDUS_BLOB_FOOTER_ALIGNMENT,
};
use nydus_accessor::utils::sha256_file;

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
                chunk_indexes: vec![
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

    let reader = ErofsReader::open_layer(image.path()).expect("open bootstrap");
    let file_nid = inodes[1].nid;
    let inode = reader.inode(file_nid).expect("read inode");

    let xattrs = reader.read_xattrs(file_nid, &inode).expect("read xattrs");
    assert_eq!(xattrs.len(), file_xattrs.len());
    for ((name, value), (_, suffix, expected_value)) in xattrs.iter().zip(file_xattrs.iter()) {
        let expected_name = [b"user.".as_slice(), suffix.as_slice()].concat();
        assert_eq!(name, &expected_name);
        assert_eq!(value, expected_value);
    }

    let chunk_indexes = reader
        .read_chunk_indexes(file_nid, &inode)
        .expect("read chunk indexes");
    assert_eq!(chunk_indexes.len(), 2);
    assert_eq!(chunk_indexes[0].blkaddr, 11);
    assert_eq!(chunk_indexes[0].device_id, 0);
    assert_eq!(chunk_indexes[1].blkaddr, 22);
    assert_eq!(chunk_indexes[1].device_id, 0);
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

    let data_size = fs::metadata(&data_path).expect("stat data blob").len();
    let bootstrap_offset = align_u64(data_size, NYDUS_BLOB_FOOTER_ALIGNMENT);
    let bootstrap_blocks = bytes_to_blocks(embedded_bootstrap.len() as u64);
    let blob_meta_offset = align_u64(
        bootstrap_offset + embedded_bootstrap.len() as u64,
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
    .expect("footer");

    let full_blob_path = dir.path().join("full.blob");
    let mut full_blob = fs::File::create(&full_blob_path).expect("create full blob");
    let data = fs::read(&data_path).expect("read data blob");
    full_blob.write_all(&data).expect("write data blob");
    write_zero_padding(&mut full_blob, data_size, bootstrap_offset).expect("pad data");
    full_blob
        .write_all(&embedded_bootstrap)
        .expect("write bootstrap");
    write_zero_padding(
        &mut full_blob,
        bootstrap_offset + embedded_bootstrap.len() as u64,
        blob_meta_offset,
    )
    .expect("pad bootstrap");
    blob_meta.write_to(&mut full_blob).expect("write blob meta");
    footer.write_to(&mut full_blob).expect("write footer");
    drop(full_blob);

    let full_blob_id = sha256_file(&full_blob_path).expect("hash full blob");
    let final_full_blob_path = dir
        .path()
        .join(nydus_accessor::utils::hex_string(&full_blob_id));
    fs::rename(&full_blob_path, final_full_blob_path).expect("rename full blob");

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

    let backend: std::sync::Arc<dyn nydus_accessor::storage::backend::BlobBackend> =
        std::sync::Arc::new(nydus_accessor::storage::backend::LocalBackend::new(
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
        .find(|entry| entry.name == "hello.txt")
        .expect("hello entry")
        .nid;
    let inode = reader.inode(file_nid).expect("file inode");
    let data = reader
        .read_file_data_sync(file_nid, &inode, 0, inode.size() as u32)
        .expect("read file data");

    assert_eq!(data, b"hello nydus\n");
}
