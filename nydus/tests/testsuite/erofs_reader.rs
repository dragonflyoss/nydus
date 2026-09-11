//! Tests for `ErofsReader`: fixture images are built through the public
//! `build` module and then read back through the reader.

use crate::fixture;

use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use tempfile::{tempdir, NamedTempFile};

use nydus::build::blob_chunk::BlobWriter;
use nydus::build::bootstrap::render_bootstrap;
use nydus::build::inode::{build_tree, ChildRef, InodeData, InodeInfo};
use nydus::build::{build_image, BuildImageOptions};
use nydus_backend::{BlobBackend, Local, ReadContext};
use nydus_core::ErofsReader;
use nydus_format::blob::{BlobMetadata, BlobMetadataCompressor};
use nydus_format::erofs::{
    erofs_xattr_ibody_size, ErofsChunkAddr, ErofsDeviceSlot, XattrEntry, ZAlgorithm,
    EROFS_BLKSZBITS, EROFS_BLOCK_SIZE, EROFS_FT_REG_FILE, EROFS_XATTR_INDEX_USER,
};
use nydus_format::utils::{hex_string, sha256_file};

struct CountingBackend {
    local: Local,
    reads: AtomicUsize,
    fail_next: AtomicBool,
}

impl BlobBackend for CountingBackend {
    fn blob_metadata(&self, blob_id: &[u8; 32]) -> io::Result<BlobMetadata> {
        self.local.blob_metadata(blob_id)
    }

    fn read_range_into(
        &self,
        blob_id: &[u8; 32],
        offset: u64,
        dst: &mut [u8],
        context: ReadContext,
    ) -> io::Result<()> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if self.fail_next.swap(false, Ordering::Relaxed) {
            return Err(io::Error::other("injected read failure"));
        }
        self.local.read_range_into(blob_id, offset, dst, context)
    }
}

#[test]
fn z_fragments_reuse_decoded_pclusters_across_files_and_threads() {
    for algorithm in [ZAlgorithm::Lz4, ZAlgorithm::Zstd] {
        let dir = tempdir().unwrap();
        let source = dir.path().join("src");
        fs::create_dir(&source).unwrap();
        let first = vec![b'A'; 16_000];
        let second = vec![b'B'; 16_000];
        let mut random = 17u32;
        let large: Vec<u8> = (0..(5 << 20) + 123)
            .map(|position| {
                random ^= random << 13;
                random ^= random >> 17;
                random ^= random << 5;
                if position % 4096 < 1024 {
                    random as u8
                } else {
                    0
                }
            })
            .collect();
        fs::write(source.join("first"), &first).unwrap();
        fs::write(source.join("duplicate"), &first).unwrap();
        fs::set_permissions(
            source.join("duplicate"),
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .unwrap();
        fs::write(source.join("second"), &second).unwrap();
        fs::write(source.join("large"), &large).unwrap();
        let options = BuildImageOptions::new(
            source,
            EROFS_BLOCK_SIZE,
            1 << 20,
            BlobMetadataCompressor::None,
            HashSet::new(),
            true,
        )
        .unwrap()
        .with_z_erofs(algorithm, 1 << 20, 0)
        .unwrap();
        let mut blob = Vec::new();
        let image = build_image(&options, &mut blob).unwrap();
        fs::write(dir.path().join(hex_string(&image.full_blob_digest)), blob).unwrap();
        let bootstrap = dir.path().join("bootstrap");
        fs::write(&bootstrap, image.standalone_bootstrap.unwrap()).unwrap();
        let backend = Arc::new(CountingBackend {
            local: Local::new(dir.path().to_path_buf()),
            reads: AtomicUsize::new(0),
            fail_next: AtomicBool::new(true),
        });
        let reader = ErofsReader::open_bootstrap(&bootstrap, backend.clone(), None, None).unwrap();
        assert!(reader.superblock().packed_nid().is_some());
        let root_nid = reader.superblock().root_nid();
        let root = reader.inode(root_nid).unwrap();
        let first_nid = reader
            .lookup_dir_entry(root_nid, &root, b"first")
            .unwrap()
            .unwrap();
        let second_nid = reader
            .lookup_dir_entry(root_nid, &root, b"second")
            .unwrap()
            .unwrap();
        let inode = reader.inode(first_nid).unwrap();
        let duplicate_nid = reader
            .lookup_dir_entry(root_nid, &root, b"duplicate")
            .unwrap()
            .unwrap();
        assert_ne!(duplicate_nid, first_nid);
        let duplicate_inode = reader.inode(duplicate_nid).unwrap();
        assert_eq!(duplicate_inode.mode() & 0o777, 0o600);
        assert_eq!(
            reader.read_z_inode_tail(first_nid, &inode).unwrap(),
            reader
                .read_z_inode_tail(duplicate_nid, &duplicate_inode)
                .unwrap()
        );
        let mut output = Vec::new();
        assert!(reader
            .write_file_data_to(first_nid, &inode, 0, first.len() as u32, &mut output)
            .is_err());
        assert!(output.is_empty());
        reader
            .write_file_data_to(first_nid, &inode, 0, first.len() as u32, &mut output)
            .unwrap();
        assert_eq!(output, first);
        let reads = backend.reads.load(Ordering::Relaxed);
        assert!(reads > 0);
        let mut duplicate_output = Vec::new();
        reader
            .write_file_data_to(
                duplicate_nid,
                &duplicate_inode,
                0,
                first.len() as u32,
                &mut duplicate_output,
            )
            .unwrap();
        assert_eq!(duplicate_output, first);
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let inode = reader.inode(second_nid).unwrap();
                    let mut output = Vec::new();
                    reader
                        .write_file_data_to(second_nid, &inode, 0, second.len() as u32, &mut output)
                        .unwrap();
                    assert_eq!(output, second);
                })
                .join()
                .unwrap();
        });
        assert_eq!(
            backend.reads.load(Ordering::Relaxed),
            reads,
            "a shared pcluster must not be fetched and decoded again: {algorithm}"
        );
        let large_nid = reader
            .lookup_dir_entry(root_nid, &root, b"large")
            .unwrap()
            .unwrap();
        std::thread::scope(|scope| {
            for offset in [0, 4093, 65_531, 131_069, (4 << 20) - 13, large.len() - 83] {
                let reader = &reader;
                let large = &large;
                scope.spawn(move || {
                    let inode = reader.inode(large_nid).unwrap();
                    let mut output = Vec::new();
                    let written = reader
                        .write_file_data_to(
                            large_nid,
                            &inode,
                            offset as u64,
                            256 << 10,
                            &mut output,
                        )
                        .unwrap();
                    assert_eq!(written, output.len());
                    assert_eq!(
                        &output,
                        &large[offset..(offset + (256 << 10)).min(large.len())]
                    );
                });
            }
        });
        let reads = backend.reads.load(Ordering::Relaxed);
        let other = ErofsReader::open_bootstrap(&bootstrap, backend.clone(), None, None).unwrap();
        let inode = other.inode(first_nid).unwrap();
        let mut output = Vec::new();
        other
            .write_file_data_to(first_nid, &inode, 0, first.len() as u32, &mut output)
            .unwrap();
        assert_eq!(output, first);
        assert!(
            backend.reads.load(Ordering::Relaxed) > reads,
            "each reader owns its cache"
        );
    }
}

#[test]
fn optimize_preserves_z_files_fragments_and_compression_config() {
    use nydus::optimize::{build_ondemand_blob, BlockGroupRef};

    for algorithm in [ZAlgorithm::Lz4, ZAlgorithm::Zstd] {
        let dir = tempdir().unwrap();
        let source = dir.path().join("src");
        fs::create_dir(&source).unwrap();
        let files = [("small", vec![42; 700]), ("large", vec![51; 300_000])];
        for (name, data) in &files {
            fs::write(source.join(name), data).unwrap();
        }
        let options = BuildImageOptions::new(
            source,
            EROFS_BLOCK_SIZE,
            1 << 20,
            BlobMetadataCompressor::None,
            HashSet::new(),
            true,
        )
        .unwrap()
        .with_z_erofs(algorithm, 1 << 20, 0)
        .unwrap();
        let mut blob = Vec::new();
        let image = build_image(&options, &mut blob).unwrap();
        fs::write(dir.path().join(hex_string(&image.full_blob_digest)), blob).unwrap();
        let parent = dir.path().join("parent");
        fs::write(&parent, image.standalone_bootstrap.unwrap()).unwrap();
        let backend = Arc::new(Local::new(dir.path().to_path_buf()));
        let optimized = build_ondemand_blob(
            &parent,
            &[BlockGroupRef {
                blob_index: 1,
                block_group_index: 0,
            }],
            backend.clone(),
            &dir.path().join("build-cache"),
        )
        .unwrap();
        fs::write(
            dir.path().join(hex_string(&optimized.full_blob_digest)),
            &optimized.artifact,
        )
        .unwrap();
        let bootstrap = dir.path().join("optimized");
        fs::write(&bootstrap, &optimized.bootstrap).unwrap();
        let backend = Arc::new(CountingBackend {
            local: Local::new(dir.path().to_path_buf()),
            reads: AtomicUsize::new(0),
            fail_next: AtomicBool::new(false),
        });
        let reader = ErofsReader::open_bootstrap(
            &bootstrap,
            backend.clone(),
            Some(&dir.path().join("read-cache")),
            None,
        )
        .unwrap();
        assert!(reader.z_compr_cfgs().unwrap().unwrap().has(algorithm));
        assert!(reader.superblock().packed_nid().is_some());
        assert_eq!(reader.blob_infos().unwrap().len(), 2);
        assert_eq!(reader.read_prefetch_order()[0], 2);
        reader
            .blob_caches()
            .prefetch_blob(2, 2, std::time::Duration::from_secs(10))
            .unwrap();
        backend.fail_next.store(true, Ordering::Relaxed);
        let root_nid = reader.superblock().root_nid();
        let root = reader.inode(root_nid).unwrap();
        for (name, expected) in &files {
            let nid = reader
                .lookup_dir_entry(root_nid, &root, name.as_bytes())
                .unwrap()
                .unwrap();
            let inode = reader.inode(nid).unwrap();
            let mut data = Vec::new();
            reader
                .write_file_data_to(nid, &inode, 0, expected.len() as u32, &mut data)
                .unwrap();
            assert_eq!(&data, expected, "{algorithm}: {name}");
        }
        assert!(
            backend.fail_next.load(Ordering::Relaxed),
            "prefetch must populate the source cache"
        );
    }
}

#[test]
fn reads_large_xattrs_and_chunk_indexes_after_large_ibody() {
    let file_xattrs: Vec<XattrEntry> = (0..8)
        .map(|index| XattrEntry {
            name_index: EROFS_XATTR_INDEX_USER,
            suffix: format!("large_{index:02}").into_bytes(),
            value: vec![b'A' + index as u8; 700],
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
                children: vec![ChildRef {
                    name: "huge_xattrs".into(),
                    file_type: EROFS_FT_REG_FILE,
                    inode_index: 1,
                }],
                startblk: 0,
                data_size: 0,
                parent_nid: 0,
                inline_len: 0,
                inline_tail: Vec::new(),
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
                    ErofsChunkAddr {
                        blkaddr: 11,
                        device_id: 0,
                    },
                    ErofsChunkAddr {
                        blkaddr: 22,
                        device_id: 0,
                    },
                ],
                chunk_size_bits: EROFS_BLKSZBITS as u32,
            },
            xattrs: file_xattrs.clone(),
        },
    ];

    let bootstrap =
        render_bootstrap(&mut inodes, 1_700_000_000, &[], &[0u8; 16]).expect("render bootstrap");
    let mut image = NamedTempFile::new().expect("create temp image");
    image.write_all(&bootstrap).expect("write bootstrap");

    let reader = ErofsReader::open_metadata_only(image.path()).expect("open bootstrap");
    let file_nid = inodes[1].nid;
    let inode = reader.inode(file_nid).expect("read inode");

    let xattrs = reader.read_xattrs(file_nid, &inode).expect("read xattrs");
    assert_eq!(xattrs.len(), file_xattrs.len());
    for ((name, value), expected) in xattrs.iter().zip(file_xattrs.iter()) {
        let expected_name = [b"user.".as_slice(), expected.suffix.as_slice()].concat();
        assert_eq!(name, &expected_name);
        assert_eq!(value, &expected.value);
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
    let embedded_device_slots =
        [ErofsDeviceSlot::with_blob_id(blob_writer.total_blocks(), &data_blob_id).unwrap()];
    let embedded_bootstrap = render_bootstrap(
        &mut inodes,
        1_700_000_000,
        &embedded_device_slots,
        &[0u8; 16],
    )
    .expect("render embedded bootstrap");
    let blob_metadata = blob_writer.blob_metadata(0).expect("blob meta");

    let data = fs::read(&data_path).expect("read data blob");
    let full_blob_digest =
        fixture::assemble_full_blob(dir.path(), &data, &embedded_bootstrap, &blob_metadata);

    let standalone_device_slots =
        [ErofsDeviceSlot::with_blob_id(blob_writer.total_blocks(), &full_blob_digest).unwrap()];
    let bootstrap = render_bootstrap(
        &mut inodes,
        1_700_000_000,
        &standalone_device_slots,
        &[0u8; 16],
    )
    .expect("render standalone bootstrap");

    let bootstrap_path = dir.path().join("bootstrap");
    fs::write(&bootstrap_path, &bootstrap).expect("write bootstrap file");

    let backend: std::sync::Arc<dyn nydus_backend::BlobBackend> =
        std::sync::Arc::new(nydus_backend::Local::new(dir.path().to_path_buf()));
    let reader =
        ErofsReader::open_bootstrap(&bootstrap_path, backend, None, None).expect("open reader");
    let root = reader
        .inode(reader.superblock().root_nid())
        .expect("root inode");
    let entries = reader
        .read_dir(reader.superblock().root_nid(), &root)
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
