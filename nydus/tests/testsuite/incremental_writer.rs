#![allow(clippy::type_complexity)]

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::Arc;

use nydus::build::{build_image, BuildImageOptions, DEFAULT_CHUNK_GROUP_MIN_SIZE};
use nydus_config::Config;
use nydus_core::writer::{CreateFileOptions, IncrementalWriter, IncrementalWriterOptions};
use nydus_core::{BlobId, CacheOptions, ErofsReader, Metrics, NydusCore};
use nydus_format::blob::{BlobMetadata, BlobMetadataCompressor, BlobMetadataDigester};
use nydus_format::erofs::{
    ErofsChunkAddr, ErofsChunkIndex, EROFS_BLOCK_SIZE, EROFS_CHUNK_INDEX_SIZE, EROFS_NULL_ADDR,
    EROFS_SLOTSIZE,
};
use tempfile::tempdir;

const DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE: u32 = BlobMetadata::DEFAULT_CHUNK_SIZE;

#[test]
fn incremental_writer_is_send() {
    fn assert_send<T: Send>() {}

    assert_send::<IncrementalWriter>();
}

fn find_path(reader: &ErofsReader, path: &str) -> u64 {
    let mut nid = reader.superblock().root_nid();
    for component in Path::new(path).components() {
        let std::path::Component::Normal(name) = component else {
            continue;
        };
        let inode = reader.inode(nid).unwrap();
        let entries = reader.read_dir(nid, &inode).unwrap();
        nid = entries
            .into_iter()
            .find(|entry| entry.name == name.as_encoded_bytes())
            .unwrap_or_else(|| panic!("missing path component {name:?}"))
            .nid;
    }
    nid
}

fn build_parent_blob(temp: &tempfile::TempDir, data: &[u8]) -> (PathBuf, [u8; 32]) {
    let source = temp.path().join("source-parent");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("memory.bin"), data).unwrap();

    let parent_blob = temp.path().join("parent.blob");
    let parent = build_image(
        &BuildImageOptions::new(
            source,
            DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
            BlobMetadataCompressor::None,
            HashSet::new(),
            true,
        )
        .unwrap(),
        fs::File::create(&parent_blob).unwrap(),
    )
    .unwrap();
    let parent_bootstrap = temp.path().join("parent-write-at.boot");
    fs::write(&parent_bootstrap, parent.standalone_bootstrap.unwrap()).unwrap();
    fs::rename(
        &parent_blob,
        temp.path().join(hex::encode(parent.full_blob_digest)),
    )
    .unwrap();
    (parent_bootstrap, parent.full_blob_digest)
}

fn writer_options(output_dir: PathBuf) -> IncrementalWriterOptions {
    IncrementalWriterOptions::new(output_dir)
}

#[test]
fn incremental_writer_options_match_build_defaults() {
    let options = IncrementalWriterOptions::new(PathBuf::from("output"));

    assert_eq!(options.chunk_size, DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE);
    assert_eq!(options.chunk_group_min_size, DEFAULT_CHUNK_GROUP_MIN_SIZE);
    assert_eq!(options.compressor, BlobMetadataCompressor::Zstd);
    assert_eq!(options.digester, Some(BlobMetadataDigester::Blake3));
    assert!(!options.prune);
}

fn local_config(blob_dir: &Path, cache_dir: &Path) -> Config {
    serde_yaml::from_str::<Config>(&format!(
        "backend:\n  type: local\n  config:\n    dir: {}\nstorage:\n  dir: {}\nprefetch:\n  scope: none\n",
        blob_dir.display(),
        cache_dir.display(),
    ))
    .unwrap()
}

fn create_parentless_writer(temp: &tempfile::TempDir) -> (IncrementalWriter, PathBuf) {
    let output_dir = temp.path().to_path_buf();
    let writer = IncrementalWriter::create(writer_options(output_dir.clone())).unwrap();
    (writer, output_dir)
}

fn open_metadata_writer(
    temp: &tempfile::TempDir,
    parent_bootstrap: &Path,
) -> (IncrementalWriter, PathBuf) {
    let output_dir = temp.path().to_path_buf();
    let writer =
        IncrementalWriter::open_metadata_only(parent_bootstrap, writer_options(output_dir.clone()))
            .unwrap();
    (writer, output_dir)
}

fn open_data_writer(
    temp: &tempfile::TempDir,
    parent_bootstrap: &Path,
) -> (IncrementalWriter, PathBuf) {
    let output_dir = temp.path().to_path_buf();
    let config = local_config(temp.path(), &temp.path().join("cache"));
    let core = NydusCore::new(parent_bootstrap, config, None).unwrap();
    let writer = core.writer(writer_options(output_dir.clone())).unwrap();
    (writer, output_dir)
}

fn file_names(dir: &Path) -> HashSet<OsString> {
    fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect()
}

fn assert_no_temporary_blob(output_dir: &Path) {
    assert!(!fs::read_dir(output_dir).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".nydus-incremental-")
    }));
}

struct CommittedImage {
    bootstrap_path: PathBuf,
    blob_path: Option<PathBuf>,
    blob_metadata_path: Option<PathBuf>,
}

fn blob_metadata_path(blob_path: &Path) -> PathBuf {
    let mut path = blob_path.to_path_buf().into_os_string();
    path.push(BlobMetadata::SUFFIX);
    path.into()
}

fn commit_upper_blob(output_dir: &Path, writer: IncrementalWriter) -> CommittedImage {
    let existing: HashSet<_> = if output_dir.exists() {
        fs::read_dir(output_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect()
    } else {
        HashSet::new()
    };
    writer.commit().unwrap();
    let bootstrap_path = output_dir.join("image.boot");
    assert!(bootstrap_path.exists());

    let reader = ErofsReader::open_metadata_only(&bootstrap_path).unwrap();
    let blob_infos = reader.blob_infos().unwrap();
    let blob_path = blob_infos
        .last()
        .map(|info| output_dir.join(hex::encode(info.blob_id)))
        .filter(|path| path.exists() && !existing.contains(path));
    let blob_metadata_path = blob_path.as_ref().map(|path| {
        let path = blob_metadata_path(path);
        assert!(path.exists());
        path
    });

    CommittedImage {
        bootstrap_path,
        blob_path,
        blob_metadata_path,
    }
}

fn commit_and_read_memory(
    temp: &tempfile::TempDir,
    output_dir: &Path,
    writer: IncrementalWriter,
) -> Vec<u8> {
    let commit = commit_upper_blob(output_dir, writer);
    let reader_backend: Arc<dyn nydus_backend::Backend> = Arc::new(nydus_backend::Local::new(
        temp.path().to_path_buf(),
        Arc::new(Metrics::new()),
    ));
    let reader = ErofsReader::open_bootstrap(
        &commit.bootstrap_path,
        reader_backend,
        None,
        None,
        CacheOptions::default(),
    )
    .unwrap();
    let nid = find_path(&reader, "memory.bin");
    let inode = reader.inode(nid).unwrap();
    reader
        .read_file_data(nid, &inode, 0, inode.size() as u32)
        .unwrap()
}

#[test]
fn incremental_writer_creates_parentless_image_with_one_data_blob() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let (mut writer, output_dir) = create_parentless_writer(&temp);

    writer
        .create_file(
            Path::new("state.bin"),
            chunk_size as u64,
            CreateFileOptions::default(),
        )
        .unwrap();
    writer
        .write_at(Path::new("state.bin"), 17, b"first-layer")
        .unwrap();
    writer
        .create_file(
            Path::new("rootfs.img"),
            chunk_size as u64,
            CreateFileOptions::default(),
        )
        .unwrap();
    writer
        .write_at(Path::new("rootfs.img"), 0, &vec![b'R'; chunk_size])
        .unwrap();
    writer.commit().unwrap();

    let bootstrap = output_dir.join("image.boot");
    let metadata_reader = ErofsReader::open_metadata_only(&bootstrap).unwrap();
    let blob_infos = metadata_reader.blob_infos().unwrap();
    assert_eq!(blob_infos.len(), 1);
    assert!(metadata_reader.read_prefetch_order().is_empty());
    for info in blob_infos {
        let blob = output_dir.join(hex::encode(info.blob_id));
        assert!(blob.exists());
        assert!(blob_metadata_path(&blob).exists());
    }

    let state_nid = find_path(&metadata_reader, "state.bin");
    let state_inode = metadata_reader.inode(state_nid).unwrap();
    let state_chunks = metadata_reader
        .read_chunk_index_entries(state_nid, &state_inode)
        .unwrap();
    assert_eq!(state_chunks[0].device_id, 1);
    let rootfs_nid = find_path(&metadata_reader, "rootfs.img");
    let rootfs_inode = metadata_reader.inode(rootfs_nid).unwrap();
    let rootfs_chunks = metadata_reader
        .read_chunk_index_entries(rootfs_nid, &rootfs_inode)
        .unwrap();
    assert_eq!(rootfs_chunks[0].device_id, 1);

    let backend: Arc<dyn nydus_backend::Backend> = Arc::new(nydus_backend::Local::new(
        output_dir,
        Arc::new(Metrics::new()),
    ));
    let reader =
        ErofsReader::open_bootstrap(&bootstrap, backend, None, None, CacheOptions::default())
            .unwrap();
    let state = reader
        .read_file_data(state_nid, &state_inode, 0, chunk_size as u32)
        .unwrap();
    assert_eq!(&state[17..28], b"first-layer");
    let rootfs = reader
        .read_file_data(rootfs_nid, &rootfs_inode, 0, chunk_size as u32)
        .unwrap();
    assert_eq!(rootfs, vec![b'R'; chunk_size]);
}

#[test]
fn incremental_writer_parentless_null_only_image_has_empty_blob() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let (mut writer, output_dir) = create_parentless_writer(&temp);
    writer
        .create_file(
            Path::new("zero.bin"),
            chunk_size as u64,
            CreateFileOptions::default(),
        )
        .unwrap();
    writer.commit().unwrap();

    let bootstrap = output_dir.join("image.boot");
    let metadata_reader = ErofsReader::open_metadata_only(&bootstrap).unwrap();
    let blob_infos = metadata_reader.blob_infos().unwrap();
    assert_eq!(blob_infos.len(), 1);
    let blob = output_dir.join(hex::encode(blob_infos[0].blob_id));
    assert!(blob.exists());
    assert!(blob_metadata_path(&blob).exists());

    let core = NydusCore::new(
        &bootstrap,
        local_config(&output_dir, &output_dir.join("runtime-cache")),
        None,
    )
    .unwrap();
    assert_eq!(
        core.fs.open("zero.bin").unwrap().read().unwrap(),
        vec![0; chunk_size]
    );
}

#[test]
fn incremental_writer_adds_file_to_parent_image() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'P'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_metadata_writer(&temp, &parent_bootstrap);
    let new_size = chunk_size + 17;

    let mut file = writer
        .create_file(
            Path::new("new.bin"),
            new_size as u64,
            CreateFileOptions::default(),
        )
        .unwrap();
    file.write_at(0, &vec![b'N'; chunk_size]).unwrap();
    file.write_at_owned(chunk_size as u64, vec![b'T'; 17])
        .unwrap();
    writer.commit().unwrap();

    let bootstrap = output_dir.join("image.boot");
    let backend: Arc<dyn nydus_backend::Backend> = Arc::new(nydus_backend::Local::new(
        output_dir,
        Arc::new(Metrics::new()),
    ));
    let reader =
        ErofsReader::open_bootstrap(&bootstrap, backend, None, None, CacheOptions::default())
            .unwrap();
    assert_eq!(reader.read_prefetch_order(), vec![1]);
    let parent_nid = find_path(&reader, "memory.bin");
    let parent_inode = reader.inode(parent_nid).unwrap();
    assert_eq!(
        reader
            .read_file_data(parent_nid, &parent_inode, 0, chunk_size as u32)
            .unwrap(),
        parent_data
    );

    let new_nid = find_path(&reader, "new.bin");
    let new_inode = reader.inode(new_nid).unwrap();
    let mut expected = vec![b'N'; chunk_size];
    expected.extend_from_slice(&[b'T'; 17]);
    assert_eq!(
        reader
            .read_file_data(new_nid, &new_inode, 0, new_size as u32)
            .unwrap(),
        expected
    );
    let chunks = reader
        .read_chunk_index_entries(new_nid, &new_inode)
        .unwrap();
    assert_eq!(chunks.len(), 2);
    assert!(chunks.iter().all(|chunk| chunk.device_id == 2));
}

#[test]
fn incremental_writer_preserves_flattened_parent_mapping() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'P'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let flattened_bootstrap = temp.path().join("flattened-parent.boot");
    let parent_reader = ErofsReader::open_metadata_only(&parent_bootstrap).unwrap();
    let parent_mapping = parent_reader.blob_infos().unwrap()[0].mapped_blkaddr;
    assert_ne!(parent_mapping, 0);
    let parent_nid = find_path(&parent_reader, "memory.bin");
    let parent_inode = parent_reader.inode(parent_nid).unwrap();
    let parent_chunk = parent_reader
        .read_chunk_index_entries(parent_nid, &parent_inode)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let flattened_chunk = ErofsChunkIndex::new(ErofsChunkAddr {
        blkaddr: parent_mapping + parent_chunk.blkaddr,
        device_id: 0,
    })
    .unwrap();
    let inode_offset = parent_reader.superblock().meta_blkaddr() as usize
        * EROFS_BLOCK_SIZE as usize
        + parent_nid as usize * EROFS_SLOTSIZE as usize;
    let chunk_index_offset = inode_offset
        + (parent_inode.header_size() + parent_inode.xattr_size())
            .next_multiple_of(EROFS_CHUNK_INDEX_SIZE);
    let mut flattened = fs::read(&parent_bootstrap).unwrap();
    flattened[chunk_index_offset..chunk_index_offset + EROFS_CHUNK_INDEX_SIZE]
        .copy_from_slice(flattened_chunk.as_bytes());
    fs::write(&flattened_bootstrap, flattened).unwrap();

    let flattened_reader = ErofsReader::open_metadata_only(&flattened_bootstrap).unwrap();
    let flattened_inode = flattened_reader.inode(parent_nid).unwrap();
    assert_eq!(
        flattened_reader
            .read_chunk_index_entries(parent_nid, &flattened_inode)
            .unwrap()[0]
            .device_id,
        0
    );

    let (mut writer, output_dir) = open_metadata_writer(&temp, &flattened_bootstrap);
    writer
        .replace_file(Path::new("new.bin"), b"new data".to_vec())
        .unwrap();
    writer.commit().unwrap();

    let bootstrap = output_dir.join("image.boot");
    let backend: Arc<dyn nydus_backend::Backend> = Arc::new(nydus_backend::Local::new(
        output_dir,
        Arc::new(Metrics::new()),
    ));
    let reader =
        ErofsReader::open_bootstrap(&bootstrap, backend, None, None, CacheOptions::default())
            .unwrap();
    assert_eq!(
        reader.blob_infos().unwrap()[0].mapped_blkaddr,
        parent_mapping
    );
    let nid = find_path(&reader, "memory.bin");
    let inode = reader.inode(nid).unwrap();
    assert_eq!(
        reader
            .read_file_data(nid, &inode, 0, chunk_size as u32)
            .unwrap(),
        parent_data
    );
}

#[test]
fn incremental_writer_replace_file_creates_missing_file() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'P'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_metadata_writer(&temp, &parent_bootstrap);
    let replacement = vec![b'N'; chunk_size + 17];

    writer
        .replace_file(Path::new("new.bin"), replacement.clone())
        .unwrap();
    writer.commit().unwrap();

    let bootstrap = output_dir.join("image.boot");
    let backend: Arc<dyn nydus_backend::Backend> = Arc::new(nydus_backend::Local::new(
        output_dir,
        Arc::new(Metrics::new()),
    ));
    let reader =
        ErofsReader::open_bootstrap(&bootstrap, backend, None, None, CacheOptions::default())
            .unwrap();
    let nid = find_path(&reader, "new.bin");
    let inode = reader.inode(nid).unwrap();
    assert_eq!(inode.size(), replacement.len() as u64);
    assert_eq!(inode.mode() & 0o7777, 0o644);
    assert_eq!(inode.uid(), 0);
    assert_eq!(inode.gid(), 0);
    assert_eq!(
        reader
            .read_file_data(nid, &inode, 0, replacement.len() as u32)
            .unwrap(),
        replacement
    );
}

#[test]
fn incremental_writer_create_file_preserves_metadata_order_and_tail() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let (mut writer, output_dir) = create_parentless_writer(&temp);
    writer
        .create_file(Path::new("z-empty"), 0, CreateFileOptions::default())
        .unwrap();
    writer
        .create_file(
            Path::new("a-data"),
            (chunk_size + 17) as u64,
            CreateFileOptions {
                mode: 0o640,
                uid: 70_000,
                gid: 80_000,
                mtime: 123_456,
                mtime_nsec: 789,
            },
        )
        .unwrap();
    assert_eq!(
        writer
            .write_at_owned(Path::new("a-data"), chunk_size as u64, vec![b'T'; 17])
            .unwrap(),
        17
    );
    assert_eq!(
        writer
            .write_at(Path::new("a-data"), (chunk_size + 15) as u64, b"ABCDE")
            .unwrap(),
        2
    );
    assert_eq!(
        writer
            .write_at(Path::new("a-data"), (chunk_size + 17) as u64, b"ignored")
            .unwrap(),
        0
    );
    writer.commit().unwrap();

    let bootstrap = output_dir.join("image.boot");
    let backend: Arc<dyn nydus_backend::Backend> = Arc::new(nydus_backend::Local::new(
        output_dir,
        Arc::new(Metrics::new()),
    ));
    let reader =
        ErofsReader::open_bootstrap(&bootstrap, backend, None, None, CacheOptions::default())
            .unwrap();
    let root_nid = reader.superblock().root_nid();
    let root = reader.inode(root_nid).unwrap();
    let names = reader
        .read_dir(root_nid, &root)
        .unwrap()
        .into_iter()
        .filter(|entry| entry.name != b"." && entry.name != b"..")
        .map(|entry| entry.name)
        .collect::<Vec<_>>();
    assert_eq!(names, vec![b"a-data".to_vec(), b"z-empty".to_vec()]);

    let nid = find_path(&reader, "a-data");
    let inode = reader.inode(nid).unwrap();
    assert_eq!(inode.mode() & 0o7777, 0o640);
    assert_eq!(inode.uid(), 70_000);
    assert_eq!(inode.gid(), 80_000);
    assert_eq!(inode.mtime(reader.superblock().epoch()), 123_456);
    assert_eq!(inode.mtime_nsec(reader.superblock().fixed_nsec()), 789);
    let data = reader
        .read_file_data(nid, &inode, 0, (chunk_size + 17) as u32)
        .unwrap();
    assert!(data[..chunk_size].iter().all(|byte| *byte == 0));
    assert_eq!(&data[chunk_size..chunk_size + 15], &[b'T'; 15]);
    assert_eq!(&data[chunk_size + 15..], b"AB");
}

#[test]
fn incremental_writer_create_file_rejects_invalid_paths() {
    let temp = tempfile::tempdir().unwrap();
    let (mut writer, _output_dir) = create_parentless_writer(&temp);

    let long_name = "n".repeat(256);
    for path in [
        "",
        "/absolute",
        "../outside",
        "missing/child",
        long_name.as_str(),
    ] {
        assert!(writer
            .create_file(Path::new(path), 0, CreateFileOptions::default())
            .is_err());
    }
    writer
        .create_file(Path::new(&long_name[1..]), 0, CreateFileOptions::default())
        .unwrap();
    writer
        .create_file(Path::new("file"), 0, CreateFileOptions::default())
        .unwrap();
    assert!(writer
        .create_file(Path::new("file"), 0, CreateFileOptions::default())
        .err()
        .unwrap()
        .to_string()
        .contains("already exists"));
    assert!(writer
        .create_file(Path::new("file/child"), 0, CreateFileOptions::default())
        .err()
        .unwrap()
        .to_string()
        .contains("not a directory"));
}

#[test]
fn incremental_writer_failed_commit_cleans_temporary_blob() {
    let dir = tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'P'; chunk_size * 2];
    let (parent_bootstrap, parent_digest) = build_parent_blob(&dir, &parent_data);
    let parent_blob = dir.path().join(hex::encode(parent_digest));
    let parent_before = (
        fs::read(&parent_bootstrap).unwrap(),
        fs::read(&parent_blob).unwrap(),
    );
    let (mut writer, output_dir) = open_metadata_writer(&dir, &parent_bootstrap);
    let source_path = dir.path().join("short-commit-source");
    fs::write(&source_path, vec![b'S'; chunk_size + 5]).unwrap();
    let source = Arc::new(fs::File::open(source_path).unwrap());
    writer
        .write_file_range(
            Path::new("memory.bin"),
            0,
            source,
            0,
            parent_data.len() as u64,
        )
        .unwrap();
    let entries = file_names(&output_dir);

    let err = writer.commit().unwrap_err();

    assert!(err
        .to_string()
        .contains("short read from source file range"));
    assert_no_temporary_blob(&output_dir);
    assert_eq!(file_names(&output_dir), entries);
    assert!(!output_dir.join("image.boot").exists());
    assert_eq!(fs::read(&parent_bootstrap).unwrap(), parent_before.0);
    assert_eq!(fs::read(&parent_blob).unwrap(), parent_before.1);
    let core = NydusCore::new(
        &parent_bootstrap,
        local_config(dir.path(), &dir.path().join("cache")),
        None,
    )
    .unwrap();
    assert_eq!(
        core.fs.open("memory.bin").unwrap().read().unwrap(),
        parent_data
    );
}

#[test]
fn incremental_writer_finalization_failures_allow_a_fresh_retry() {
    let dir = tempdir().unwrap();
    let parent_data = vec![b'P'; DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize];
    let replacement = vec![b'U'; parent_data.len()];
    let (parent_bootstrap, parent_digest) = build_parent_blob(&dir, &parent_data);
    let parent_blob = dir.path().join(hex::encode(parent_digest));
    let parent_before = (
        fs::read(&parent_bootstrap).unwrap(),
        fs::read(&parent_blob).unwrap(),
    );
    let stage = |output: &Path| {
        let mut writer = IncrementalWriter::open_metadata_only(
            &parent_bootstrap,
            writer_options(output.to_path_buf()),
        )
        .unwrap();
        writer
            .write_at(Path::new("memory.bin"), 0, &replacement)
            .unwrap();
        writer
    };
    let reference = dir.path().join("reference");
    let image = commit_upper_blob(&reference, stage(&reference));
    let blob = image.blob_path.unwrap();
    let sidecar = image.blob_metadata_path.unwrap();
    let test_cases = vec![
        (
            blob.file_name().unwrap(),
            libc::EISDIR,
            Some("failed to rename blob"),
            vec![],
        ),
        (
            sidecar.file_name().unwrap(),
            libc::EISDIR,
            None,
            vec![&blob],
        ),
        (
            sidecar.file_name().unwrap(),
            libc::ENOSPC,
            None,
            vec![&blob],
        ),
        (
            OsStr::new("image.boot"),
            libc::EISDIR,
            Some("failed to publish bootstrap"),
            vec![&blob, &sidecar],
        ),
    ];

    for (obstruction, errno, context, published) in test_cases {
        let output = tempdir().unwrap();
        let obstruction = output.path().join(obstruction);
        if errno == libc::EISDIR {
            fs::create_dir(&obstruction).unwrap();
        } else {
            symlink("/dev/full", &obstruction).unwrap();
        }

        let err = stage(output.path()).commit().unwrap_err();

        if let Some(context) = context {
            assert!(err.to_string().contains(context), "{err}");
        }
        assert_eq!(err.io_error().unwrap().raw_os_error(), Some(errno), "{err}");
        assert_no_temporary_blob(output.path());
        assert!(!output.path().join("image.boot").is_file(), "{err}");
        for artifact in [&blob, &sidecar] {
            let path = output.path().join(artifact.file_name().unwrap());
            if published.contains(&artifact) {
                assert_eq!(
                    fs::read(path).unwrap(),
                    fs::read(artifact).unwrap(),
                    "{err}"
                );
            } else {
                assert!(!path.is_file(), "{err}");
            }
        }
        assert_eq!(fs::read(&parent_bootstrap).unwrap(), parent_before.0);
        assert_eq!(fs::read(&parent_blob).unwrap(), parent_before.1);

        if errno == libc::EISDIR {
            fs::remove_dir(&obstruction).unwrap();
        } else {
            fs::remove_file(&obstruction).unwrap();
        }
        stage(output.path()).commit().unwrap();

        assert_no_temporary_blob(output.path());
        fs::copy(
            &parent_blob,
            output.path().join(parent_blob.file_name().unwrap()),
        )
        .unwrap();
        let core = NydusCore::new(
            &output.path().join("image.boot"),
            local_config(output.path(), &output.path().join("cache")),
            None,
        )
        .unwrap();
        assert_eq!(
            core.fs.open("memory.bin").unwrap().read().unwrap(),
            replacement
        );
    }

    let parent = NydusCore::new(
        &parent_bootstrap,
        local_config(dir.path(), &dir.path().join("parent-cache")),
        None,
    )
    .unwrap();
    assert_eq!(
        parent.fs.open("memory.bin").unwrap().read().unwrap(),
        parent_data
    );
}

#[test]
fn incremental_writer_replaces_one_chunk_with_upper_blob_data() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let mut parent_data = vec![b'L'; chunk_size];
    parent_data.extend(vec![b'M'; chunk_size]);
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_metadata_writer(&temp, &parent_bootstrap);

    writer
        .write_at(
            Path::new("memory.bin"),
            chunk_size as u64,
            &vec![b'U'; chunk_size],
        )
        .unwrap();
    let commit = commit_upper_blob(&output_dir, writer);
    let upper_blob = commit.blob_path.as_ref().unwrap();
    assert!(upper_blob.metadata().unwrap().len() > 0);
    assert!(commit.blob_metadata_path.as_ref().unwrap().exists());

    let reader = ErofsReader::open_metadata_only(&commit.bootstrap_path).unwrap();
    assert_eq!(reader.blob_infos().unwrap().len(), 2);
    assert_eq!(
        reader.blob_infos().unwrap()[1].blob_id,
        commit
            .blob_path
            .as_ref()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .parse::<BlobId>()
            .unwrap()
            .into_bytes()
    );

    let nid = find_path(&reader, "memory.bin");
    let inode = reader.inode(nid).unwrap();
    let chunks = reader.read_chunk_index_entries(nid, &inode).unwrap();
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].device_id, 1);
    assert_eq!(chunks[1].device_id, 2);
    assert_eq!(chunks[1].blkaddr, 0);
    assert!(ErofsReader::open_metadata_only(upper_blob).is_err());
}

#[test]
fn incremental_writer_prune_is_opt_in() {
    for prune in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let chunk = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
        let (parent, _) = build_parent_blob(&temp, &vec![b'A'; chunk]);
        let mut options = writer_options(temp.path().join("child"));
        options.prune = prune;
        let output = options.output_dir.clone();
        let mut writer = IncrementalWriter::open_metadata_only(&parent, options).unwrap();
        writer
            .replace_file(Path::new("memory.bin"), vec![b'B'; chunk])
            .unwrap();
        let image = commit_upper_blob(&output, writer);
        let reader = ErofsReader::open_metadata_only(&image.bootstrap_path).unwrap();
        assert_eq!(
            reader.blob_infos().unwrap().len(),
            if prune { 1 } else { 2 }
        );
    }
}

#[test]
fn incremental_writer_repack_prunes_without_blob_data_before_compact_limit() {
    let temp = tempfile::tempdir().unwrap();
    let chunk = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let (parent, _) = build_parent_blob(&temp, &vec![b'A'; chunk]);
    let (mut writer, output) = open_metadata_writer(&temp, &parent);
    writer
        .replace_file(Path::new("memory.bin"), vec![b'B'; chunk])
        .unwrap();
    let image = commit_upper_blob(&output, writer);
    let original = fs::read(&image.bootstrap_path).unwrap();
    assert_eq!(
        ErofsReader::open_metadata_only(&image.bootstrap_path)
            .unwrap()
            .blob_infos()
            .unwrap()
            .len(),
        2
    );
    let empty = temp.path().join("no-data");
    fs::create_dir(&empty).unwrap();
    let core = NydusCore::new(
        &image.bootstrap_path,
        local_config(&empty, &temp.path().join("empty-cache")),
        None,
    )
    .unwrap();

    for (prune, limit, expected) in [(false, 0, false), (true, 0, true), (false, 1, true)] {
        let output = temp.path().join(format!("repack-{prune}-{limit}"));
        let mut options = writer_options(output.clone());
        options.prune = prune;
        let result = core
            .repack(options, limit, |plan| {
                assert_eq!(plan.pruned, expected);
                assert!(!plan.compacted);
                assert_eq!(plan.blobs.len(), if expected { 1 } else { 2 });
                Ok(())
            })
            .unwrap();
        assert_eq!(result.pruned, expected);
        assert!(!result.compacted);
        assert_eq!(output.join("image.boot").exists(), expected);
        if expected {
            let reader = ErofsReader::open_metadata_only(&output.join("image.boot")).unwrap();
            assert_eq!(reader.blob_infos().unwrap().len(), 1);
        }
        assert_eq!(fs::read(&image.bootstrap_path).unwrap(), original);
    }
}

fn open_pruning_writer(temp: &tempfile::TempDir, bootstrap: &Path) -> (IncrementalWriter, PathBuf) {
    let output_dir = temp.path().to_path_buf();
    let mut options = writer_options(output_dir.clone());
    options.prune = true;
    let writer = IncrementalWriter::open_metadata_only(bootstrap, options).unwrap();
    (writer, output_dir)
}

#[test]
fn incremental_writer_prunes_superseded_blobs_across_generations() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'A'; chunk_size * 2];
    let (parent, parent_digest) = build_parent_blob(&temp, &parent_data);
    let mut bootstrap = parent;
    for value in [b'B', b'C', b'D'] {
        let (mut writer, output_dir) = open_pruning_writer(&temp, &bootstrap);
        writer
            .write_at(
                Path::new("memory.bin"),
                chunk_size as u64,
                &vec![value; chunk_size],
            )
            .unwrap();
        let image = commit_upper_blob(&output_dir, writer);
        let reader = ErofsReader::open_metadata_only(&image.bootstrap_path).unwrap();
        let blobs = reader.blob_infos().unwrap();
        assert_eq!(blobs.len(), 2);
        assert_eq!(blobs[0].blob_id, parent_digest);
        let nid = find_path(&reader, "memory.bin");
        let inode = reader.inode(nid).unwrap();
        let chunks = reader.read_chunk_index_entries(nid, &inode).unwrap();
        assert_eq!(chunks[0].device_id, 1);
        assert_eq!(chunks[1].device_id, 2);
        let config = local_config(temp.path(), &temp.path().join(format!("cache-{value}")));
        let core = NydusCore::new(&image.bootstrap_path, config, None).unwrap();
        let mut expected = vec![b'A'; chunk_size];
        expected.extend(vec![value; chunk_size]);
        assert_eq!(
            core.fs.open("memory.bin").unwrap().read().unwrap(),
            expected
        );
        bootstrap = image.bootstrap_path;
    }

    // Keep a flattened reference to the second device while removing the first.
    let reader = ErofsReader::open_metadata_only(&bootstrap).unwrap();
    let mapping = 1 << 20;
    let mut slots: Vec<_> = reader
        .blob_infos()
        .unwrap()
        .iter()
        .map(|info| {
            nydus_format::erofs::ErofsDeviceSlot::with_blob_id_and_mapped_blkaddr(
                info.blocks,
                &info.blob_id,
                info.mapped_blkaddr,
            )
            .unwrap()
        })
        .collect();
    slots[1].set_mapped_blkaddr(mapping).unwrap();
    let nid = find_path(&reader, "memory.bin");
    let inode = reader.inode(nid).unwrap();
    let chunks = reader.read_chunk_index_entries(nid, &inode).unwrap();
    let inode_offset = reader.superblock().meta_blkaddr() as usize * EROFS_BLOCK_SIZE as usize
        + nid as usize * EROFS_SLOTSIZE as usize;
    let index_offset = inode_offset
        + (inode.header_size() + inode.xattr_size()).next_multiple_of(EROFS_CHUNK_INDEX_SIZE)
        + EROFS_CHUNK_INDEX_SIZE;
    let flattened = ErofsChunkIndex::new(ErofsChunkAddr {
        blkaddr: mapping + chunks[1].blkaddr,
        device_id: 0,
    })
    .unwrap();
    let mut data = fs::read(&bootstrap).unwrap();
    nydus_core::build::bootstrap::patch_device_slots(&mut data, &slots).unwrap();
    data[index_offset..index_offset + EROFS_CHUNK_INDEX_SIZE].copy_from_slice(flattened.as_bytes());
    fs::write(&bootstrap, data).unwrap();
    let (mut writer, output_dir) = open_pruning_writer(&temp, &bootstrap);
    writer
        .write_at(Path::new("memory.bin"), 0, &vec![b'X'; chunk_size])
        .unwrap();
    let image = commit_upper_blob(&output_dir, writer);
    let reader = ErofsReader::open_metadata_only(&image.bootstrap_path).unwrap();
    assert_eq!(reader.blob_infos().unwrap().len(), 2);
    assert_eq!(reader.blob_infos().unwrap()[0].mapped_blkaddr, mapping);
    assert!(reader.read_prefetch_order().is_empty());
    let config = local_config(temp.path(), &temp.path().join("cache-flattened"));
    let core = NydusCore::new(&image.bootstrap_path, config, None).unwrap();
    let mut expected = vec![b'X'; chunk_size];
    expected.extend(vec![b'D'; chunk_size]);
    assert_eq!(
        core.fs.open("memory.bin").unwrap().read().unwrap(),
        expected
    );
    bootstrap = image.bootstrap_path;

    let (mut writer, output_dir) = open_pruning_writer(&temp, &bootstrap);
    writer
        .replace_file(Path::new("memory.bin"), vec![b'Z'; chunk_size])
        .unwrap();
    let image = commit_upper_blob(&output_dir, writer);
    let reader = ErofsReader::open_metadata_only(&image.bootstrap_path).unwrap();
    assert_eq!(reader.blob_infos().unwrap().len(), 1);
    let nid = find_path(&reader, "memory.bin");
    let inode = reader.inode(nid).unwrap();
    assert_eq!(
        reader.read_chunk_index_entries(nid, &inode).unwrap()[0].device_id,
        1
    );
    let config = local_config(temp.path(), &temp.path().join("cache-replaced"));
    let core = NydusCore::new(&image.bootstrap_path, config, None).unwrap();
    assert_eq!(
        core.fs.open("memory.bin").unwrap().read().unwrap(),
        vec![b'Z'; chunk_size]
    );

    let (mut writer, output_dir) = open_pruning_writer(&temp, &image.bootstrap_path);
    writer
        .replace_file(Path::new("memory.bin"), vec![0; chunk_size])
        .unwrap();
    let image = commit_upper_blob(&output_dir, writer);
    let reader = ErofsReader::open_metadata_only(&image.bootstrap_path).unwrap();
    assert!(reader.blob_infos().unwrap().is_empty());
    assert!(image.blob_path.is_none());
    let empty_blobs = temp.path().join("empty-blobs");
    fs::create_dir(&empty_blobs).unwrap();
    for cached in [false, true] {
        let mut config = local_config(&empty_blobs, &temp.path().join("cache-null-only"));
        if !cached {
            config.storage.dir = None;
        }
        let core = NydusCore::new(&image.bootstrap_path, config, None).unwrap();
        let file = core.fs.open("memory.bin").unwrap();
        assert_eq!(file.read().unwrap(), vec![0; chunk_size]);
        file.fetch(0, chunk_size as u64).unwrap();
        for ranges in [
            file.probe_ranges(0, chunk_size as u64).unwrap(),
            file.fetch_ranges(0, chunk_size as u64).unwrap(),
        ] {
            assert_eq!(
                ranges.iter().map(|range| range.len).sum::<u64>(),
                chunk_size as u64
            );
            assert!(ranges
                .iter()
                .all(|range| range.fd == core.zero_fd() && range.offset == 0));
        }

        // A partial write must patch the parent's logical zeros without blobs.
        let next_dir = temp.path().join(format!("after-null-{cached}"));
        let mut writer = core.writer(writer_options(next_dir.clone())).unwrap();
        writer
            .write_at(Path::new("memory.bin"), 7, b"next")
            .unwrap();
        writer.commit().unwrap();
        let next = NydusCore::new(
            &next_dir.join("image.boot"),
            local_config(
                &next_dir,
                &temp.path().join(format!("cache-after-null-{cached}")),
            ),
            None,
        )
        .unwrap();
        let mut expected = vec![0; chunk_size];
        expected[7..11].copy_from_slice(b"next");
        assert_eq!(
            next.fs.open("memory.bin").unwrap().read().unwrap(),
            expected
        );
    }
}

#[test]
fn incremental_writer_replace_file_does_not_require_parent_data() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'A'; chunk_size * 2];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_metadata_writer(&temp, &parent_bootstrap);

    writer
        .replace_file(Path::new("memory.bin"), vec![b'R'; chunk_size])
        .unwrap();
    let commit = commit_upper_blob(&output_dir, writer);

    let reader = ErofsReader::open_metadata_only(&commit.bootstrap_path).unwrap();
    let nid = find_path(&reader, "memory.bin");
    let inode = reader.inode(nid).unwrap();
    let chunks = reader.read_chunk_index_entries(nid, &inode).unwrap();
    assert_eq!(inode.size(), chunk_size as u64);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].device_id, 2);
    assert_eq!(
        reader.read_prefetch_order(),
        ErofsReader::open_metadata_only(&parent_bootstrap)
            .unwrap()
            .read_prefetch_order()
    );
    assert!(commit.blob_path.as_ref().unwrap().exists());
    assert!(commit.blob_metadata_path.as_ref().unwrap().exists());
}

#[test]
fn incremental_writer_encodes_zero_chunk_as_null_without_blob() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'L'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_metadata_writer(&temp, &parent_bootstrap);

    writer
        .write_at(Path::new("memory.bin"), 0, &vec![0; chunk_size])
        .unwrap();
    let commit = commit_upper_blob(&output_dir, writer);
    assert!(commit.blob_path.is_none());
    assert!(commit.blob_metadata_path.is_none());

    let reader = ErofsReader::open_metadata_only(&commit.bootstrap_path).unwrap();
    let nid = find_path(&reader, "memory.bin");
    let inode = reader.inode(nid).unwrap();
    let chunks = reader.read_chunk_index_entries(nid, &inode).unwrap();
    assert_eq!(chunks[0].blkaddr, EROFS_NULL_ADDR);
}

#[test]
fn incremental_writer_elides_zero_source_chunks_without_blob() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'L'; chunk_size * 2];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_metadata_writer(&temp, &parent_bootstrap);

    let source_path = temp.path().join("zero-source");
    fs::write(&source_path, vec![0; chunk_size]).unwrap();
    let source = Arc::new(fs::File::open(&source_path).unwrap());
    let mut memory = vec![0; chunk_size];
    let ptr = NonNull::new(memory.as_mut_ptr()).unwrap();

    assert_eq!(
        writer
            .write_file_range(Path::new("memory.bin"), 0, source, 0, chunk_size as u64)
            .unwrap(),
        chunk_size
    );
    let written = unsafe {
        writer
            .write_memory_range(Path::new("memory.bin"), chunk_size as u64, ptr, chunk_size)
            .unwrap()
    };
    assert_eq!(written, chunk_size);

    let commit = commit_upper_blob(&output_dir, writer);
    assert!(commit.blob_path.is_none());
    assert!(commit.blob_metadata_path.is_none());

    let reader = ErofsReader::open_metadata_only(&commit.bootstrap_path).unwrap();
    let nid = find_path(&reader, "memory.bin");
    let inode = reader.inode(nid).unwrap();
    let chunks = reader.read_chunk_index_entries(nid, &inode).unwrap();
    assert_eq!(chunks[0].blkaddr, EROFS_NULL_ADDR);
    assert_eq!(chunks[1].blkaddr, EROFS_NULL_ADDR);
}

#[test]
fn incremental_writer_creates_upper_blob_only_on_commit() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'A'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_metadata_writer(&temp, &parent_bootstrap);

    assert!(!output_dir.join("image.boot").exists());
    writer
        .write_at(Path::new("memory.bin"), 0, &vec![b'X'; chunk_size])
        .unwrap();
    assert!(!output_dir.join("image.boot").exists());
    let commit = commit_upper_blob(&output_dir, writer);
    let blob_metadata =
        nydus_format::blob::BlobMetadata::from_path(commit.blob_metadata_path.as_ref().unwrap())
            .unwrap();
    assert!(blob_metadata.is_incremental());
    assert_eq!(
        blob_metadata.digester().unwrap(),
        Some(BlobMetadataDigester::Blake3)
    );
    assert_eq!(
        blob_metadata.bytes_per_chunk_group_index(),
        DEFAULT_CHUNK_GROUP_MIN_SIZE
    );
    assert_eq!(
        blob_metadata.chunk_group_digests().count(),
        blob_metadata.chunk_group_count()
    );
    assert!(commit.blob_path.as_ref().unwrap().exists());
}

#[test]
fn incremental_writer_can_disable_chunk_digests() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'A'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let output_dir = temp.path().join("digest-free-child");
    let mut options = writer_options(output_dir.clone());
    options.digester = None;
    options.chunk_group_min_size = EROFS_BLOCK_SIZE;
    let mut writer = IncrementalWriter::open_metadata_only(&parent_bootstrap, options).unwrap();

    writer
        .write_at(Path::new("memory.bin"), 0, &vec![b'N'; chunk_size])
        .unwrap();
    let commit = commit_upper_blob(&output_dir, writer);
    let blob_metadata =
        nydus_format::blob::BlobMetadata::from_path(commit.blob_metadata_path.as_ref().unwrap())
            .unwrap();

    assert_eq!(blob_metadata.digester().unwrap(), None);
    assert_eq!(
        blob_metadata.bytes_per_chunk_group_index(),
        EROFS_BLOCK_SIZE
    );
    assert_eq!(blob_metadata.chunk_count(), 1);
    assert_eq!(blob_metadata.chunk_group_digests().count(), 0);
}

#[test]
fn incremental_writer_write_at_owned_moves_full_chunk() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'A'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_metadata_writer(&temp, &parent_bootstrap);

    assert_eq!(
        writer
            .write_at_owned(Path::new("memory.bin"), 0, vec![b'O'; chunk_size])
            .unwrap(),
        chunk_size
    );
    writer
        .write_at_owned(Path::new("memory.bin"), 7, vec![b'P'; 1])
        .unwrap();

    let data = commit_and_read_memory(&temp, &output_dir, writer);
    let mut expected = vec![b'O'; chunk_size];
    expected[7] = b'P';
    assert_eq!(data, expected);
}

#[test]
fn incremental_writer_write_file_range_stages_full_chunk() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let mut parent_data = vec![b'A'; chunk_size];
    parent_data.extend(vec![b'B'; chunk_size]);
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_metadata_writer(&temp, &parent_bootstrap);
    let source_path = temp.path().join("range-source");
    let mut source_data = vec![b'S'; chunk_size];
    source_data.extend(vec![b'F'; chunk_size]);
    fs::write(&source_path, &source_data).unwrap();
    let source = Arc::new(fs::File::open(&source_path).unwrap());

    assert_eq!(
        writer
            .write_file_range(
                Path::new("memory.bin"),
                chunk_size as u64,
                source,
                chunk_size as u64,
                chunk_size as u64,
            )
            .unwrap(),
        chunk_size
    );

    let data = commit_and_read_memory(&temp, &output_dir, writer);
    let mut expected = vec![b'A'; chunk_size];
    expected.extend(vec![b'F'; chunk_size]);
    assert_eq!(data, expected);
}

#[test]
fn incremental_writer_write_memory_range_stages_full_chunk() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'A'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_metadata_writer(&temp, &parent_bootstrap);
    let mut memory = vec![b'M'; chunk_size];
    let ptr = NonNull::new(memory.as_mut_ptr()).unwrap();

    let written = unsafe {
        writer
            .write_memory_range(Path::new("memory.bin"), 0, ptr, memory.len())
            .unwrap()
    };
    assert_eq!(written, chunk_size);

    let data = commit_and_read_memory(&temp, &output_dir, writer);
    assert_eq!(data, memory);
}

#[test]
fn incremental_writer_open_file_reuses_resolved_inode_for_writes() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let mut parent_data = vec![b'A'; chunk_size];
    parent_data.extend(vec![b'B'; chunk_size]);
    parent_data.extend(vec![b'C'; chunk_size]);
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_data_writer(&temp, &parent_bootstrap);

    let source_path = temp.path().join("opened-file-source");
    let source_data = vec![b'F'; chunk_size];
    fs::write(&source_path, &source_data).unwrap();
    let source = Arc::new(fs::File::open(&source_path).unwrap());
    let mut memory = vec![b'M'; chunk_size];
    let ptr = NonNull::new(memory.as_mut_ptr()).unwrap();

    {
        let mut file = writer.open_file(Path::new("./memory.bin")).unwrap();
        assert_eq!(file.write_at(64, b"HH").unwrap(), 2);
        assert_eq!(
            file.write_file_range(chunk_size as u64, source, 0, chunk_size as u64)
                .unwrap(),
            chunk_size
        );
        let written = unsafe {
            file.write_memory_range((2 * chunk_size) as u64, ptr, chunk_size)
                .unwrap()
        };
        assert_eq!(written, chunk_size);
    }

    let data = commit_and_read_memory(&temp, &output_dir, writer);
    let mut expected = vec![b'A'; chunk_size];
    expected[64..66].copy_from_slice(b"HH");
    expected.extend(source_data);
    expected.extend(memory);
    assert_eq!(data, expected);
}

#[test]
fn incremental_writer_rejects_empty_commit() {
    let dir = tempdir().unwrap();
    let parent_data = vec![b'A'; DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize];
    let (parent_bootstrap, _) = build_parent_blob(&dir, &parent_data);
    let test_cases = vec![false, true];

    for parentless in test_cases {
        let output_dir = dir.path().join(format!("empty-output-{parentless}"));
        let options = writer_options(output_dir.clone());
        let writer = if parentless {
            IncrementalWriter::create(options).unwrap()
        } else {
            IncrementalWriter::open_metadata_only(&parent_bootstrap, options).unwrap()
        };

        let err = writer.commit().unwrap_err();

        assert!(err.to_string().contains("no changes"), "{parentless}");
        assert!(!output_dir.exists(), "{parentless}");
    }
}

#[test]
fn incremental_writer_ignores_empty_and_out_of_bounds_writes() {
    let dir = tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as u64;
    let (parent_bootstrap, _) = build_parent_blob(&dir, &vec![b'A'; chunk_size as usize]);
    let source = Arc::new(fs::File::open(dir.path().join("source-parent/memory.bin")).unwrap());
    let mut memory = [b'X'];
    let ptr = NonNull::new(memory.as_mut_ptr()).unwrap();
    let output_dir = dir.path().join("noop-output");
    let mut writer = IncrementalWriter::open_metadata_only(
        &parent_bootstrap,
        writer_options(output_dir.clone()),
    )
    .unwrap();
    let path = Path::new("memory.bin");
    let test_cases = vec![(0, 0), (chunk_size, 1), (u64::MAX, 1)];

    for (offset, len) in test_cases {
        assert_eq!(
            writer.write_at(path, offset, &memory[..len]).unwrap(),
            0,
            "{offset} {len}"
        );
        assert_eq!(
            writer
                .write_at_owned(path, offset, memory[..len].to_vec())
                .unwrap(),
            0,
            "{offset} {len}"
        );
        assert_eq!(
            writer
                .write_file_range(path, offset, source.clone(), 0, len as u64)
                .unwrap(),
            0,
            "{offset} {len}"
        );
        // SAFETY: `memory` outlives the writer and is not mutated before commit.
        let written = unsafe { writer.write_memory_range(path, offset, ptr, len) }.unwrap();
        assert_eq!(written, 0, "{offset} {len}");
    }

    assert!(writer
        .commit()
        .unwrap_err()
        .to_string()
        .contains("no changes"));
    assert!(!output_dir.exists());
}

#[test]
fn incremental_writer_commits_empty_file_changes_without_upper_blob() {
    let dir = tempdir().unwrap();
    let parent_data = vec![b'P'; DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize];
    let (parent_bootstrap, parent_digest) = build_parent_blob(&dir, &parent_data);
    let test_cases: Vec<(&str, fn(&mut IncrementalWriter, &Path), Vec<u8>)> = vec![
        (
            "empty.bin",
            |writer, path| {
                writer
                    .create_file(path, 0, CreateFileOptions::default())
                    .unwrap();
            },
            parent_data.clone(),
        ),
        (
            "memory.bin",
            |writer, path| writer.replace_file(path, Vec::new()).unwrap(),
            Vec::new(),
        ),
    ];

    for (path, change, memory) in test_cases {
        let output = tempdir().unwrap();
        let mut writer = IncrementalWriter::open_metadata_only(
            &parent_bootstrap,
            writer_options(output.path().to_path_buf()),
        )
        .unwrap();
        change(&mut writer, Path::new(path));

        writer.commit().unwrap();

        assert_eq!(
            file_names(output.path()),
            HashSet::from([OsString::from("image.boot")]),
            "{path}"
        );
        let bootstrap = output.path().join("image.boot");
        let reader = ErofsReader::open_metadata_only(&bootstrap).unwrap();
        let blobs = reader.blob_infos().unwrap();
        assert_eq!(blobs.len(), 1, "{path}");
        assert_eq!(blobs[0].blob_id, parent_digest, "{path}");
        let nid = find_path(&reader, path);
        let inode = reader.inode(nid).unwrap();
        assert_eq!(inode.size(), 0, "{path}");
        assert!(reader
            .read_chunk_index_entries(nid, &inode)
            .unwrap()
            .is_empty());
        let core = NydusCore::new(
            &bootstrap,
            local_config(dir.path(), &output.path().join("cache")),
            None,
        )
        .unwrap();
        assert!(
            core.fs.open(path).unwrap().read().unwrap().is_empty(),
            "{path}"
        );
        assert_eq!(
            core.fs.open("memory.bin").unwrap().read().unwrap(),
            memory,
            "{path}"
        );
    }
}

#[test]
fn incremental_writer_rejects_source_range_overflow_without_staging_changes() {
    let dir = tempdir().unwrap();
    let parent_data = vec![b'P'; DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize];
    let (parent_bootstrap, _) = build_parent_blob(&dir, &parent_data);
    let output_dir = dir.path().join("overflow-output");
    let mut writer = IncrementalWriter::open_metadata_only(
        &parent_bootstrap,
        writer_options(output_dir.clone()),
    )
    .unwrap();
    let source = Arc::new(fs::File::open(dir.path().join("source-parent/memory.bin")).unwrap());
    let test_cases = vec![(u64::MAX, 1), (u64::MAX - 1, 2)];

    for (source_offset, len) in test_cases {
        let err = writer
            .write_file_range(
                Path::new("memory.bin"),
                0,
                source.clone(),
                source_offset,
                len,
            )
            .unwrap_err();

        assert!(
            err.to_string().contains("source file range overflow"),
            "{source_offset} {len}"
        );
    }

    assert!(writer
        .commit()
        .unwrap_err()
        .to_string()
        .contains("no changes"));
    assert!(!output_dir.exists());
}

#[test]
fn incremental_writer_deferred_partial_writes_require_parent_reader() {
    let dir = tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let (parent_bootstrap, _) = build_parent_blob(&dir, &vec![b'P'; chunk_size]);
    let source = Arc::new(fs::File::open(dir.path().join("source-parent/memory.bin")).unwrap());
    let mut memory = vec![b'M'; chunk_size];
    let ptr = NonNull::new(memory.as_mut_ptr()).unwrap();
    let test_cases = vec![false, true];

    for from_memory in test_cases {
        let (mut writer, output_dir) = open_metadata_writer(&dir, &parent_bootstrap);

        let err = if from_memory {
            // SAFETY: `memory` outlives the writer and is not mutated before commit.
            unsafe { writer.write_memory_range(Path::new("memory.bin"), 1, ptr, 1) }
        } else {
            writer.write_file_range(Path::new("memory.bin"), 1, source.clone(), 0, 1)
        }
        .unwrap_err();

        assert!(
            err.to_string().contains("data-capable parent reader"),
            "{from_memory}"
        );
        assert!(
            writer
                .commit()
                .unwrap_err()
                .to_string()
                .contains("no changes"),
            "{from_memory}"
        );
        assert!(!output_dir.join("image.boot").exists(), "{from_memory}");
        assert_no_temporary_blob(&output_dir);
    }
}

#[test]
fn incremental_writer_rejects_invalid_chunk_size_before_creating_output() {
    let temp = tempfile::tempdir().unwrap();
    let output_dir = temp.path().join("invalid-output");
    let err = match IncrementalWriter::create(IncrementalWriterOptions {
        chunk_size: EROFS_BLOCK_SIZE * 3,
        ..IncrementalWriterOptions::new(output_dir.clone())
    }) {
        Ok(_) => panic!("expected invalid chunk size"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("power of two"));
    assert!(!output_dir.exists());

    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let (parent_bootstrap, _) = build_parent_blob(&temp, &vec![b'A'; chunk_size]);
    let metadata_output = temp.path().join("invalid-metadata-output");
    let err = match IncrementalWriter::open_metadata_only(
        &parent_bootstrap,
        IncrementalWriterOptions {
            chunk_size: EROFS_BLOCK_SIZE * 3,
            ..IncrementalWriterOptions::new(metadata_output.clone())
        },
    ) {
        Ok(_) => panic!("expected invalid chunk size"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("power of two"));
    assert!(!metadata_output.exists());

    let group_output = temp.path().join("invalid-group-output");
    let err = match IncrementalWriter::create(IncrementalWriterOptions {
        chunk_group_min_size: EROFS_BLOCK_SIZE * 3,
        ..IncrementalWriterOptions::new(group_output.clone())
    }) {
        Ok(_) => panic!("expected invalid chunk group minimum size"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("chunk group minimum size"));
    assert!(!group_output.exists());
}

#[test]
fn incremental_writer_rejects_metadata_updates_with_mismatched_chunk_size() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'A'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let writer_chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE / 2;
    let mut writer = IncrementalWriter::open_metadata_only(
        &parent_bootstrap,
        IncrementalWriterOptions {
            chunk_size: writer_chunk_size,
            ..IncrementalWriterOptions::new(temp.path().to_path_buf())
        },
    )
    .unwrap();

    assert!(writer
        .write_at(Path::new("memory.bin"), 0, b"B")
        .unwrap_err()
        .to_string()
        .contains("chunk size"));
    assert!(writer
        .replace_file(Path::new("memory.bin"), b"replacement".to_vec())
        .unwrap_err()
        .to_string()
        .contains("chunk size"));
}

#[test]
fn incremental_writer_rejects_partial_metadata_only_write() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'A'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, _output_dir) = open_metadata_writer(&temp, &parent_bootstrap);

    let err = writer
        .write_at(Path::new("memory.bin"), 1, b"partial")
        .unwrap_err();
    assert!(err.to_string().contains("data-capable parent reader"));
    assert!(writer
        .commit()
        .unwrap_err()
        .to_string()
        .contains("no changes"));
}

#[test]
fn incremental_writer_write_at_patches_partial_parent_chunk() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let mut parent_data = vec![b'A'; chunk_size];
    parent_data.extend(vec![b'B'; chunk_size]);
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_data_writer(&temp, &parent_bootstrap);

    let offset = chunk_size as u64 + 123;
    let written = writer
        .write_at(Path::new("memory.bin"), offset, b"PATCH")
        .unwrap();
    assert_eq!(written, 5);
    let commit = commit_upper_blob(&output_dir, writer);

    let reader_backend: Arc<dyn nydus_backend::Backend> = Arc::new(nydus_backend::Local::new(
        temp.path().to_path_buf(),
        Arc::new(Metrics::new()),
    ));
    let reader = ErofsReader::open_bootstrap(
        &commit.bootstrap_path,
        reader_backend,
        None,
        None,
        CacheOptions::default(),
    )
    .unwrap();
    let nid = find_path(&reader, "memory.bin");
    let inode = reader.inode(nid).unwrap();
    let data = reader
        .read_file_data(nid, &inode, 0, inode.size() as u32)
        .unwrap();
    let mut streamed = Vec::new();
    reader
        .write_file_data_to(nid, &inode, 0, inode.size() as u32, &mut streamed)
        .unwrap();

    let mut expected = parent_data;
    expected[offset as usize..offset as usize + 5].copy_from_slice(b"PATCH");
    assert_eq!(data, expected);
    assert_eq!(streamed, expected);

    let chunks = reader.read_chunk_index_entries(nid, &inode).unwrap();
    assert_eq!(chunks[0].device_id, 1);
    assert_eq!(chunks[1].device_id, 2);
}

#[test]
fn incremental_writer_write_at_crosses_chunk_boundary() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let mut parent_data = vec![b'A'; chunk_size];
    parent_data.extend(vec![b'B'; chunk_size]);
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_data_writer(&temp, &parent_bootstrap);

    let offset = chunk_size as u64 - 2;
    let written = writer
        .write_at(Path::new("memory.bin"), offset, b"WXYZ")
        .unwrap();
    assert_eq!(written, 4);
    let commit = commit_upper_blob(&output_dir, writer);

    let reader_backend: Arc<dyn nydus_backend::Backend> = Arc::new(nydus_backend::Local::new(
        temp.path().to_path_buf(),
        Arc::new(Metrics::new()),
    ));
    let reader = ErofsReader::open_bootstrap(
        &commit.bootstrap_path,
        reader_backend,
        None,
        None,
        CacheOptions::default(),
    )
    .unwrap();
    let nid = find_path(&reader, "memory.bin");
    let inode = reader.inode(nid).unwrap();
    let data = reader
        .read_file_data(nid, &inode, 0, inode.size() as u32)
        .unwrap();

    let mut expected = parent_data;
    expected[offset as usize..offset as usize + 4].copy_from_slice(b"WXYZ");
    assert_eq!(data, expected);

    let chunks = reader.read_chunk_index_entries(nid, &inode).unwrap();
    assert_eq!(chunks[0].device_id, 2);
    assert_eq!(chunks[1].device_id, 2);
}

#[test]
fn nydus_core_creates_incremental_writer_reusing_parent_reader() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let mut parent_data = vec![b'A'; chunk_size];
    parent_data.extend(vec![b'B'; chunk_size]);
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let config = local_config(temp.path(), &temp.path().join("cache"));
    let core = NydusCore::new(&parent_bootstrap, config, None).unwrap();

    let output_dir = temp.path().to_path_buf();
    let mut writer = core
        .writer(IncrementalWriterOptions::new(output_dir.clone()))
        .unwrap();

    let offset = 777u64;
    let written = writer
        .write_at(Path::new("memory.bin"), offset, b"CORE")
        .unwrap();
    assert_eq!(written, 4);
    let commit = commit_upper_blob(&output_dir, writer);

    let reader_backend: Arc<dyn nydus_backend::Backend> = Arc::new(nydus_backend::Local::new(
        temp.path().to_path_buf(),
        Arc::new(Metrics::new()),
    ));
    let reader = ErofsReader::open_bootstrap(
        &commit.bootstrap_path,
        reader_backend,
        None,
        None,
        CacheOptions::default(),
    )
    .unwrap();
    let nid = find_path(&reader, "memory.bin");
    let inode = reader.inode(nid).unwrap();
    let data = reader
        .read_file_data(nid, &inode, 0, inode.size() as u32)
        .unwrap();

    let mut expected = parent_data;
    expected[offset as usize..offset as usize + 4].copy_from_slice(b"CORE");
    assert_eq!(data, expected);
}

#[test]
fn incremental_writer_write_at_keeps_multiple_partial_writes_to_same_chunk() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'A'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_data_writer(&temp, &parent_bootstrap);

    assert_eq!(
        writer
            .write_at(Path::new("memory.bin"), 100, b"ONE")
            .unwrap(),
        3
    );
    assert_eq!(
        writer
            .write_at(Path::new("memory.bin"), 200, b"TWO")
            .unwrap(),
        3
    );

    let data = commit_and_read_memory(&temp, &output_dir, writer);
    let mut expected = parent_data;
    expected[100..103].copy_from_slice(b"ONE");
    expected[200..203].copy_from_slice(b"TWO");
    assert_eq!(data, expected);
}

#[test]
fn incremental_writer_applies_deferred_file_and_memory_patches_in_order() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'A'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_data_writer(&temp, &parent_bootstrap);

    let source_path = temp.path().join("partial-source");
    fs::write(&source_path, b"FILE").unwrap();
    let source = Arc::new(fs::File::open(&source_path).unwrap());
    assert_eq!(
        writer
            .write_file_range(Path::new("memory.bin"), 100, source, 0, 4)
            .unwrap(),
        4
    );

    let mut memory = *b"MEM";
    let ptr = NonNull::new(memory.as_mut_ptr()).unwrap();
    assert_eq!(
        unsafe {
            writer
                .write_memory_range(Path::new("memory.bin"), 102, ptr, memory.len())
                .unwrap()
        },
        memory.len()
    );
    assert_eq!(
        writer
            .write_at(Path::new("memory.bin"), 103, b"XY")
            .unwrap(),
        2
    );

    let data = commit_and_read_memory(&temp, &output_dir, writer);
    let mut expected = parent_data;
    expected[100..104].copy_from_slice(b"FILE");
    expected[102..105].copy_from_slice(b"MEM");
    expected[103..105].copy_from_slice(b"XY");
    assert_eq!(data, expected);
}

#[test]
fn incremental_writer_drops_fully_covered_deferred_patch() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'A'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, _output_dir) = open_data_writer(&temp, &parent_bootstrap);

    let source_path = temp.path().join("covered-source");
    fs::write(&source_path, b"old patch").unwrap();
    let source = Arc::new(fs::File::open(&source_path).unwrap());
    let weak = Arc::downgrade(&source);
    writer
        .write_file_range(Path::new("memory.bin"), 32, source, 0, 9)
        .unwrap();
    assert!(weak.upgrade().is_some());

    writer
        .write_at(Path::new("memory.bin"), 31, b"new patch data")
        .unwrap();
    assert!(weak.upgrade().is_none());

    let source = Arc::new(fs::File::open(&source_path).unwrap());
    let weak = Arc::downgrade(&source);
    writer
        .write_file_range(Path::new("memory.bin"), 64, source, 0, 9)
        .unwrap();
    writer
        .write_at(Path::new("memory.bin"), 68, b"partial overlap")
        .unwrap();
    assert!(weak.upgrade().is_some());

    writer
        .write_at(Path::new("memory.bin"), 0, &vec![b'B'; chunk_size])
        .unwrap();
    assert!(weak.upgrade().is_none());
}

#[test]
fn incremental_writer_write_at_patches_existing_dirty_full_chunk() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'A'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_metadata_writer(&temp, &parent_bootstrap);

    writer
        .write_at(Path::new("memory.bin"), 0, &vec![b'C'; chunk_size])
        .unwrap();
    assert_eq!(
        writer
            .write_at(Path::new("memory.bin"), 123, b"PATCH")
            .unwrap(),
        5
    );

    let data = commit_and_read_memory(&temp, &output_dir, writer);
    let mut expected = vec![b'C'; chunk_size];
    expected[123..128].copy_from_slice(b"PATCH");
    assert_eq!(data, expected);
}

#[test]
fn incremental_writer_write_at_patches_replaced_file_data() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'A'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_metadata_writer(&temp, &parent_bootstrap);

    let replacement = vec![b'R'; chunk_size / 2];
    writer
        .replace_file(Path::new("memory.bin"), replacement.clone())
        .unwrap();
    assert_eq!(
        writer.write_at(Path::new("memory.bin"), 55, b"XX").unwrap(),
        2
    );

    let data = commit_and_read_memory(&temp, &output_dir, writer);
    let mut expected = replacement;
    expected[55..57].copy_from_slice(b"XX");
    assert_eq!(data, expected);
}

#[test]
fn incremental_writer_write_at_patches_replaced_file_tail_chunk() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'A'; chunk_size * 2];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_metadata_writer(&temp, &parent_bootstrap);

    let mut replacement = vec![b'R'; chunk_size + chunk_size / 2];
    writer
        .replace_file(Path::new("memory.bin"), replacement.clone())
        .unwrap();
    let offset = chunk_size as u64 + 55;
    assert_eq!(
        writer
            .write_at(Path::new("memory.bin"), offset, b"TAIL")
            .unwrap(),
        4
    );

    let data = commit_and_read_memory(&temp, &output_dir, writer);
    replacement[offset as usize..offset as usize + 4].copy_from_slice(b"TAIL");
    assert_eq!(data, replacement);
}

#[test]
fn incremental_writer_write_at_truncates_at_eof() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'A'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_data_writer(&temp, &parent_bootstrap);

    assert_eq!(
        writer
            .write_at(Path::new("memory.bin"), chunk_size as u64 - 2, b"ABCDE")
            .unwrap(),
        2
    );

    let data = commit_and_read_memory(&temp, &output_dir, writer);
    let mut expected = parent_data;
    expected[chunk_size - 2..chunk_size].copy_from_slice(b"AB");
    assert_eq!(data, expected);
}

#[test]
fn incremental_writer_rejects_invalid_parent_device_ids() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let (bootstrap, _) = build_parent_blob(&temp, &vec![b'A'; chunk_size * 2]);
    let reader = ErofsReader::open_metadata_only(&bootstrap).unwrap();
    let nid = find_path(&reader, "memory.bin");
    let inode = reader.inode(nid).unwrap();
    let chunks = reader.read_chunk_index_entries(nid, &inode).unwrap();
    let inode_offset = reader.superblock().meta_blkaddr() as usize * EROFS_BLOCK_SIZE as usize
        + nid as usize * EROFS_SLOTSIZE as usize;
    let index_offset = inode_offset
        + (inode.header_size() + inode.xattr_size()).next_multiple_of(EROFS_CHUNK_INDEX_SIZE)
        + EROFS_CHUNK_INDEX_SIZE;
    let original = fs::read(&bootstrap).unwrap();
    // The first chunk keeps device 1 live; the later invalid ID must still
    // be rejected even though liveness analysis can finish after that first chunk.
    for device_id in [2, u16::MAX] {
        let mut data = original.clone();
        let entry = ErofsChunkIndex::new(ErofsChunkAddr {
            blkaddr: chunks[1].blkaddr,
            device_id,
        })
        .unwrap();
        data[index_offset..index_offset + EROFS_CHUNK_INDEX_SIZE].copy_from_slice(entry.as_bytes());
        fs::write(&bootstrap, data).unwrap();
        let result = IncrementalWriter::open_metadata_only(
            &bootstrap,
            writer_options(temp.path().join(format!("invalid-{device_id}"))),
        );
        assert!(
            result.is_err(),
            "accepted missing parent device {device_id}"
        );
    }
}

#[test]
fn compact_merges_live_parent_and_upper_chunks_preserving_holes() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let mut parent_data = vec![b'A'; chunk_size * 2];
    parent_data.extend(vec![0; chunk_size]);
    let (parent, _) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_metadata_writer(&temp, &parent);
    writer
        .write_at(
            Path::new("memory.bin"),
            chunk_size as u64,
            &vec![b'B'; chunk_size],
        )
        .unwrap();
    let child = commit_upper_blob(&output_dir, writer);
    let config = local_config(temp.path(), &temp.path().join("source-cache"));
    let core = NydusCore::new(&child.bootstrap_path, config, None).unwrap();
    let output = temp.path().join("compact");
    core.repack(writer_options(output.clone()), 1, |_| Ok(()))
        .unwrap();
    let boot = output.join("image.boot");
    let reader = ErofsReader::open_metadata_only(&boot).unwrap();
    assert_eq!(reader.blob_infos().unwrap().len(), 1);
    let nid = find_path(&reader, "memory.bin");
    let inode = reader.inode(nid).unwrap();
    let chunks = reader.read_chunk_index_entries(nid, &inode).unwrap();
    assert_eq!(chunks[0].device_id, 1);
    assert_eq!(chunks[1].device_id, 1);
    assert!(chunks[2].is_hole());
    let config = local_config(&output, &temp.path().join("compact-cache"));
    let compacted = NydusCore::new(&boot, config, None).unwrap();
    parent_data[chunk_size..chunk_size * 2].fill(b'B');
    assert_eq!(
        compacted.fs.open("memory.bin").unwrap().read().unwrap(),
        parent_data
    );
    assert_eq!(
        core.fs.open("memory.bin").unwrap().read().unwrap(),
        parent_data
    );
    assert_eq!(
        ErofsReader::open_metadata_only(&child.bootstrap_path)
            .unwrap()
            .blob_infos()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn repack_prunes_then_compacts_live_data_with_deferred_blob_preparation() {
    let temp = tempfile::tempdir().unwrap();
    let chunk = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let (parent, parent_id) = build_parent_blob(&temp, &vec![b'A'; chunk * 2]);
    let (mut writer, output) = open_metadata_writer(&temp, &parent);
    writer
        .write_at(Path::new("memory.bin"), chunk as u64, &vec![b'B'; chunk])
        .unwrap();
    let child = commit_upper_blob(&output, writer);
    let (mut writer, output) = open_metadata_writer(&temp, &child.bootstrap_path);
    writer
        .write_at(Path::new("memory.bin"), chunk as u64, &vec![b'C'; chunk])
        .unwrap();
    let final_image = commit_upper_blob(&output, writer);
    assert_eq!(
        ErofsReader::open_metadata_only(&final_image.bootstrap_path)
            .unwrap()
            .blob_infos()
            .unwrap()
            .len(),
        3
    );

    let staged = temp.path().join("staged");
    fs::create_dir(&staged).unwrap();
    let config = local_config(&staged, &temp.path().join("repack-cache"));
    let core = NydusCore::new(&final_image.bootstrap_path, config, None).unwrap();
    let output = temp.path().join("repacked");
    let result = core
        .repack(writer_options(output.clone()), 1, |plan| {
            assert!(plan.pruned);
            assert!(plan.compacted);
            assert_eq!(plan.blobs.len(), 2);
            assert_eq!(plan.blobs[0], BlobId::from(parent_id));
            // Backend starts empty: only the live blobs are made available here.
            for id in &plan.blobs {
                fs::copy(
                    temp.path().join(id.to_string()),
                    staged.join(id.to_string()),
                )?;
            }
            Ok(())
        })
        .unwrap();
    assert!(result.pruned && result.compacted);
    assert_eq!(result.blobs.len(), 1);
    let core = NydusCore::new(
        &output.join("image.boot"),
        local_config(&output, &temp.path().join("result-cache")),
        None,
    )
    .unwrap();
    let mut expected = vec![b'A'; chunk];
    expected.extend(vec![b'C'; chunk]);
    assert_eq!(
        core.fs.open("memory.bin").unwrap().read().unwrap(),
        expected
    );
}

#[test]
fn compact_publishes_in_place_without_invalidating_source_readers() {
    for alias in ["same", "hardlink", "symlink"] {
        let temp = tempfile::tempdir().unwrap();
        let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
        let parent_data = vec![b'A'; chunk_size * 2];
        let (parent, _) = build_parent_blob(&temp, &parent_data);
        let (mut writer, output_dir) = open_metadata_writer(&temp, &parent);
        writer
            .write_at(
                Path::new("memory.bin"),
                chunk_size as u64,
                &vec![b'B'; chunk_size],
            )
            .unwrap();
        let child = commit_upper_blob(&output_dir, writer);
        let core = NydusCore::new(
            &child.bootstrap_path,
            local_config(temp.path(), &temp.path().join("source-cache")),
            None,
        )
        .unwrap();
        let output = if alias == "same" {
            output_dir
        } else {
            let dir = temp.path().join(alias);
            fs::create_dir(&dir).unwrap();
            if alias == "hardlink" {
                fs::hard_link(&child.bootstrap_path, dir.join("image.boot")).unwrap();
            } else {
                std::os::unix::fs::symlink(&child.bootstrap_path, dir.join("image.boot")).unwrap();
            }
            dir
        };
        core.repack(writer_options(output.clone()), 1, |_| Ok(()))
            .unwrap();
        let mut expected = vec![b'A'; chunk_size];
        expected.extend(vec![b'B'; chunk_size]);
        assert_eq!(
            core.fs.open("memory.bin").unwrap().read().unwrap(),
            expected
        );
        let boot = output.join("image.boot");
        let reader = ErofsReader::open_metadata_only(&boot).unwrap();
        let infos = reader.blob_infos().unwrap();
        assert_eq!(infos.len(), 1);
        // The newly published bootstrap must use only the compact output blob.
        let result = NydusCore::new(
            &boot,
            local_config(&output, &temp.path().join("result-cache")),
            None,
        )
        .unwrap();
        assert_eq!(
            result.fs.open("memory.bin").unwrap().read().unwrap(),
            expected
        );
        assert!(!fs::read_dir(&output).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".nydus-bootstrap-")));
    }
}

#[test]
fn failed_in_place_compact_keeps_original_bootstrap() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let (parent, parent_digest) = build_parent_blob(&temp, &vec![b'A'; chunk_size * 2]);
    let (mut writer, output_dir) = open_metadata_writer(&temp, &parent);
    writer
        .write_at(
            Path::new("memory.bin"),
            chunk_size as u64,
            &vec![b'B'; chunk_size],
        )
        .unwrap();
    let child = commit_upper_blob(&output_dir, writer);
    let before = fs::read(&child.bootstrap_path).unwrap();
    let partial = temp.path().join("partial-blobs");
    fs::create_dir(&partial).unwrap();
    let parent_name = hex::encode(parent_digest);
    fs::hard_link(temp.path().join(&parent_name), partial.join(&parent_name)).unwrap();
    let core = NydusCore::new(
        &child.bootstrap_path,
        local_config(&partial, &temp.path().join("partial-cache")),
        None,
    )
    .unwrap();
    assert!(core
        .repack(writer_options(output_dir.clone()), 1, |_| Ok(()))
        .is_err());
    assert_eq!(fs::read(&child.bootstrap_path).unwrap(), before);
    assert_no_temporary_blob(&output_dir);
}

#[test]
fn compact_copies_live_encoded_groups_without_decoded_cache() {
    let temp = tempfile::tempdir().unwrap();
    let pool = temp.path().join("pool");
    let chunk = EROFS_BLOCK_SIZE as usize;
    let options = |output_dir| {
        let mut options = writer_options(output_dir);
        options.chunk_size = EROFS_BLOCK_SIZE;
        options.chunk_group_min_size = EROFS_BLOCK_SIZE * 2;
        options
    };
    let mut writer = IncrementalWriter::create(options(pool.clone())).unwrap();
    writer
        .create_file(
            Path::new("memory.bin"),
            (chunk * 16) as u64,
            CreateFileOptions::default(),
        )
        .unwrap();
    for index in 0..16 {
        writer
            .write_at_owned(
                Path::new("memory.bin"),
                (index * chunk) as u64,
                vec![b'A'; chunk],
            )
            .unwrap();
    }
    let parent = commit_upper_blob(&pool, writer);
    let parent_blob = parent.blob_path.unwrap();
    let parent_metadata =
        BlobMetadata::from_path(parent.blob_metadata_path.as_ref().unwrap()).unwrap();
    assert_eq!(parent_metadata.chunk_group_count(), 2);

    let mut writer =
        IncrementalWriter::open_metadata_only(&parent.bootstrap_path, options(pool.clone()))
            .unwrap();
    writer
        .write_at_owned(Path::new("memory.bin"), chunk as u64, vec![b'E'; chunk])
        .unwrap();
    writer
        .write_at_owned(
            Path::new("memory.bin"),
            (chunk * 2) as u64,
            vec![0; chunk * 14],
        )
        .unwrap();
    let child = commit_upper_blob(&pool, writer);
    let upper_blob = child.blob_path.unwrap();
    let upper_metadata =
        BlobMetadata::from_path(child.blob_metadata_path.as_ref().unwrap()).unwrap();
    let source_cache = temp.path().join("source-cache");
    let core = NydusCore::new(
        &child.bootstrap_path,
        local_config(&pool, &source_cache),
        None,
    )
    .unwrap();
    let output = temp.path().join("compact");
    core.repack(options(output.clone()), 1, |_| Ok(())).unwrap();

    // Raw compaction must not materialize a decoded source blob cache.
    if source_cache.exists() {
        assert!(!fs::read_dir(&source_cache).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".blob.data")
        }));
    }
    let bootstrap = output.join("image.boot");
    let reader = ErofsReader::open_metadata_only(&bootstrap).unwrap();
    let infos = reader.blob_infos().unwrap();
    assert_eq!(infos.len(), 1);
    let blob = output.join(hex::encode(infos[0].blob_id));
    let metadata = BlobMetadata::from_path(&blob_metadata_path(&blob)).unwrap();
    assert_eq!(metadata.chunk_group_count(), 2);
    // The first pack is retained whole with only one live member; the second is removed.
    assert_eq!(metadata.chunk_count(), 9);
    let bytes = fs::read(&blob).unwrap();
    for (index, (source, source_metadata)) in [
        (&parent_blob, &parent_metadata),
        (&upper_blob, &upper_metadata),
    ]
    .into_iter()
    .enumerate()
    {
        let old = source_metadata.chunk_group(0).unwrap();
        let new = metadata.chunk_group(index).unwrap();
        assert!(!old.is_uncompressed(source_metadata));
        let source_bytes = fs::read(source).unwrap();
        assert_eq!(
            &bytes[new.compressed_range().start as usize..new.compressed_range().end as usize],
            &source_bytes
                [old.compressed_range().start as usize..old.compressed_range().end as usize],
        );
        assert_eq!(new.uncompressed_crc32(), old.uncompressed_crc32());
        assert_eq!(
            metadata.chunk_group_digest(index),
            source_metadata.chunk_group_digest(0)
        );
    }
    let compacted = NydusCore::new(
        &bootstrap,
        local_config(&output, &temp.path().join("result-cache")),
        None,
    )
    .unwrap();
    let mut expected = vec![b'A'; chunk];
    expected.extend(vec![b'E'; chunk]);
    expected.extend(vec![0; chunk * 14]);
    assert_eq!(
        compacted.fs.open("memory.bin").unwrap().read().unwrap(),
        expected
    );
}

#[test]
fn compact_reencodes_when_compressor_or_digest_is_incompatible() {
    for (missing_digest, target_compressor) in [
        (false, BlobMetadataCompressor::Lz4Block),
        (false, BlobMetadataCompressor::None),
        (true, BlobMetadataCompressor::Zstd),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let pool = temp.path().join("pool");
        let mut options = writer_options(pool.clone());
        options.chunk_size = EROFS_BLOCK_SIZE;
        if missing_digest {
            options.digester = None;
        }
        let data = vec![b'A'; EROFS_BLOCK_SIZE as usize * 2 + 31];
        let mut writer = IncrementalWriter::create(options).unwrap();
        writer
            .replace_file(Path::new("memory.bin"), data.clone())
            .unwrap();
        let parent = commit_upper_blob(&pool, writer);
        let mut writer = IncrementalWriter::open_metadata_only(
            &parent.bootstrap_path,
            writer_options(pool.clone()),
        )
        .unwrap();
        writer
            .replace_file(Path::new("extra"), vec![b'B'; EROFS_BLOCK_SIZE as usize])
            .unwrap();
        writer.commit().unwrap();
        let core = NydusCore::new(
            &parent.bootstrap_path,
            local_config(&pool, &temp.path().join("source-cache")),
            None,
        )
        .unwrap();
        let output = temp.path().join("compact");
        let mut options = writer_options(output.clone());
        options.chunk_size = EROFS_BLOCK_SIZE;
        if missing_digest {
            options.digester = Some(BlobMetadataDigester::Blake3);
        } else {
            options.compressor = target_compressor;
        }
        let expected_compressor = options.compressor;
        core.repack(options, 1, |_| Ok(())).unwrap();
        let bootstrap = output.join("image.boot");
        let reader = ErofsReader::open_metadata_only(&bootstrap).unwrap();
        let infos = reader.blob_infos().unwrap();
        assert_eq!(infos.len(), 1);
        let blob = output.join(hex::encode(infos[0].blob_id));
        let metadata = BlobMetadata::from_path(&blob_metadata_path(&blob)).unwrap();
        assert_eq!(metadata.compressor(), expected_compressor);
        assert_eq!(
            metadata.digester().unwrap(),
            Some(BlobMetadataDigester::Blake3)
        );
        let compacted = NydusCore::new(
            &bootstrap,
            local_config(&output, &temp.path().join("result-cache")),
            None,
        )
        .unwrap();
        assert_eq!(
            compacted.fs.open("memory.bin").unwrap().read().unwrap(),
            data
        );
        assert_eq!(
            compacted.fs.open("extra").unwrap().read().unwrap(),
            vec![b'B'; EROFS_BLOCK_SIZE as usize]
        );
    }
}

#[test]
fn compact_rejects_invalid_geometry_before_creating_output() {
    let temp = tempfile::tempdir().unwrap();
    let (parent, _) = build_parent_blob(&temp, &vec![b'A'; EROFS_BLOCK_SIZE as usize]);
    let core = NydusCore::new(
        &parent,
        local_config(temp.path(), &temp.path().join("cache")),
        None,
    )
    .unwrap();
    for (index, (chunk_size, minimum)) in [
        (0, EROFS_BLOCK_SIZE),
        (EROFS_BLOCK_SIZE, EROFS_BLOCK_SIZE + 1),
    ]
    .into_iter()
    .enumerate()
    {
        let output = temp.path().join(format!("invalid-{index}"));
        let mut options = writer_options(output.clone());
        options.chunk_size = chunk_size;
        options.chunk_group_min_size = minimum;
        assert!(core.repack(options, 1, |_| Ok(())).is_err());
        assert!(!output.exists());
    }
}

#[test]
fn compact_handles_flattened_chunks_and_mixed_group_sizes() {
    let temp = tempfile::tempdir().unwrap();
    let chunk = EROFS_BLOCK_SIZE as usize;
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    let mut expected = vec![b'A'; chunk * 6 + 31];
    fs::write(source.join("memory.bin"), &expected).unwrap();
    let path = temp.path().join("parent.blob");
    let parent = build_image(
        &BuildImageOptions::new(
            source,
            EROFS_BLOCK_SIZE,
            BlobMetadataCompressor::Zstd,
            HashSet::new(),
            true,
        )
        .unwrap()
        .with_chunk_group_min_size(EROFS_BLOCK_SIZE)
        .unwrap(),
        fs::File::create(&path).unwrap(),
    )
    .unwrap();
    fs::rename(path, temp.path().join(hex::encode(parent.full_blob_digest))).unwrap();
    let boot = temp.path().join("parent.boot");
    fs::write(&boot, parent.standalone_bootstrap.unwrap()).unwrap();
    let mut options = writer_options(temp.path().to_path_buf());
    options.chunk_size = EROFS_BLOCK_SIZE;
    options.chunk_group_min_size = EROFS_BLOCK_SIZE * 2;
    let mut writer = IncrementalWriter::open_metadata_only(&boot, options).unwrap();
    writer
        .write_at_owned(Path::new("memory.bin"), chunk as u64, vec![b'E'; chunk * 2])
        .unwrap();
    writer.commit().unwrap();
    expected[chunk..chunk * 3].fill(b'E');

    let boot = temp.path().join("image.boot");
    let reader = ErofsReader::open_metadata_only(&boot).unwrap();
    let mapping = reader.blob_infos().unwrap()[0].mapped_blkaddr;
    assert_ne!(mapping, 0);
    let nid = find_path(&reader, "memory.bin");
    let inode = reader.inode(nid).unwrap();
    let entries = reader.read_chunk_index_entries(nid, &inode).unwrap();
    let base = reader.superblock().meta_blkaddr() as usize * chunk
        + nid as usize * EROFS_SLOTSIZE as usize
        + (inode.header_size() + inode.xattr_size()).next_multiple_of(EROFS_CHUNK_INDEX_SIZE);
    let mut bytes = fs::read(&boot).unwrap();
    for (index, entry) in entries.into_iter().enumerate() {
        if entry.device_id == 1 {
            let flattened = ErofsChunkIndex::new(ErofsChunkAddr {
                device_id: 0,
                blkaddr: mapping + entry.blkaddr,
            })
            .unwrap();
            let offset = base + index * EROFS_CHUNK_INDEX_SIZE;
            bytes[offset..offset + EROFS_CHUNK_INDEX_SIZE].copy_from_slice(flattened.as_bytes());
        }
    }
    fs::write(&boot, bytes).unwrap();
    let cache = temp.path().join("source-cache");
    let core = NydusCore::new(&boot, local_config(temp.path(), &cache), None).unwrap();
    let output = temp.path().join("compact");
    core.repack(writer_options(output.clone()), 1, |_| Ok(()))
        .unwrap();
    let result_boot = output.join("image.boot");
    let result_reader = ErofsReader::open_metadata_only(&result_boot).unwrap();
    let infos = result_reader.blob_infos().unwrap();
    assert_eq!(infos.len(), 1);
    let metadata = BlobMetadata::from_path(&blob_metadata_path(
        &output.join(hex::encode(infos[0].blob_id)),
    ))
    .unwrap();
    let sizes: HashSet<_> = metadata
        .chunk_groups()
        .map(|group| group.logical_block_count())
        .collect();
    assert!(sizes.contains(&1) && sizes.contains(&2));
    assert!(!fs::read_dir(&cache).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .ends_with(".blob.data")));
    let result = NydusCore::new(
        &result_boot,
        local_config(&output, &temp.path().join("result-cache")),
        None,
    )
    .unwrap();
    assert_eq!(
        result.fs.open("memory.bin").unwrap().read().unwrap(),
        expected
    );
}

#[test]
fn compact_defers_unique_short_tail_to_preserve_index_stride() {
    let temp = tempfile::tempdir().unwrap();
    let chunk = EROFS_BLOCK_SIZE as usize * 2;
    let options = |output| {
        let mut options = writer_options(output);
        options.chunk_size = chunk as u32;
        options.chunk_group_min_size = chunk as u32;
        options
    };
    let mut writer = IncrementalWriter::create(options(temp.path().to_path_buf())).unwrap();
    writer
        .replace_file(Path::new("memory.bin"), vec![b'A'; chunk + chunk / 2])
        .unwrap();
    writer.commit().unwrap();
    let bootstrap = temp.path().join("image.boot");
    let mut writer =
        IncrementalWriter::open_metadata_only(&bootstrap, options(temp.path().to_path_buf()))
            .unwrap();
    writer
        .replace_file(Path::new("extra"), vec![b'B'; chunk])
        .unwrap();
    writer.commit().unwrap();
    let core = NydusCore::new(
        &bootstrap,
        local_config(temp.path(), &temp.path().join("cache")),
        None,
    )
    .unwrap();
    let output = temp.path().join("compact");
    core.repack(options(output.clone()), 1, |_| Ok(())).unwrap();
    let bootstrap = output.join("image.boot");
    let reader = ErofsReader::open_metadata_only(&bootstrap).unwrap();
    let infos = reader.blob_infos().unwrap();
    assert_eq!(infos.len(), 1);
    let metadata = BlobMetadata::from_path(&blob_metadata_path(
        &output.join(hex::encode(infos[0].blob_id)),
    ))
    .unwrap();
    assert_eq!(metadata.blocks_per_chunk_group_index(), 2);
    assert_eq!(
        metadata
            .chunk_groups()
            .map(|group| group.logical_block_count())
            .collect::<Vec<_>>(),
        [2, 2, 1]
    );
    let result = NydusCore::new(
        &bootstrap,
        local_config(&output, &temp.path().join("result-cache")),
        None,
    )
    .unwrap();
    assert_eq!(
        result.fs.open("memory.bin").unwrap().read().unwrap(),
        vec![b'A'; chunk + chunk / 2]
    );
    assert_eq!(
        result.fs.open("extra").unwrap().read().unwrap(),
        vec![b'B'; chunk]
    );
}

#[test]
fn compact_repairs_truncated_sidecar_on_retry() {
    for compressor in [
        BlobMetadataCompressor::Zstd,
        BlobMetadataCompressor::Lz4Block,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let pool = temp.path().join("pool");
        let mut writer = IncrementalWriter::create(writer_options(pool.clone())).unwrap();
        writer
            .replace_file(
                Path::new("memory.bin"),
                vec![b'A'; EROFS_BLOCK_SIZE as usize],
            )
            .unwrap();
        writer.commit().unwrap();
        let mut writer = IncrementalWriter::open_metadata_only(
            &pool.join("image.boot"),
            writer_options(pool.clone()),
        )
        .unwrap();
        writer
            .replace_file(Path::new("extra"), vec![b'B'; EROFS_BLOCK_SIZE as usize])
            .unwrap();
        writer.commit().unwrap();
        let core = NydusCore::new(
            &pool.join("image.boot"),
            local_config(&pool, &temp.path().join("cache")),
            None,
        )
        .unwrap();
        let output = temp.path().join("compact");
        let options = || {
            let mut options = writer_options(output.clone());
            options.compressor = compressor;
            options
        };
        core.repack(options(), 1, |_| Ok(())).unwrap();
        let reader = ErofsReader::open_metadata_only(&output.join("image.boot")).unwrap();
        let blob = output.join(hex::encode(reader.blob_infos().unwrap()[0].blob_id));
        let metadata = blob_metadata_path(&blob);
        let expected = fs::read(&metadata).unwrap();
        let blob_before = fs::read(&blob).unwrap();
        fs::write(&metadata, b"truncated").unwrap();
        core.repack(options(), 1, |_| Ok(())).unwrap();
        assert_eq!(fs::read(metadata).unwrap(), expected);
        assert_eq!(fs::read(blob).unwrap(), blob_before);
        assert_no_temporary_blob(&output);
    }
}

#[test]
fn incremental_writer_atomically_replaces_bootstrap_symlink() {
    let temp = tempfile::tempdir().unwrap();
    let (parent, _) = build_parent_blob(
        &temp,
        &vec![b'A'; DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize],
    );
    let output = temp.path().join("child");
    fs::create_dir(&output).unwrap();
    let target = temp.path().join("untouched");
    fs::write(&target, b"sentinel").unwrap();
    std::os::unix::fs::symlink(&target, output.join("image.boot")).unwrap();
    let mut writer =
        IncrementalWriter::open_metadata_only(&parent, writer_options(output.clone())).unwrap();
    writer
        .replace_file(Path::new("memory.bin"), vec![b'B'; 4096])
        .unwrap();
    writer.commit().unwrap();
    assert_eq!(fs::read(target).unwrap(), b"sentinel");
    assert!(!fs::symlink_metadata(output.join("image.boot"))
        .unwrap()
        .file_type()
        .is_symlink());
    ErofsReader::open_metadata_only(&output.join("image.boot")).unwrap();
    assert_no_temporary_blob(&output);
}

#[test]
fn compact_rolls_back_new_artifacts_on_late_publication_failure() {
    for compressor in [
        BlobMetadataCompressor::Zstd,
        BlobMetadataCompressor::Lz4Block,
    ] {
        for failure in ["bootstrap-new", "bootstrap-dedup", "sidecar"] {
            let temp = tempfile::tempdir().unwrap();
            let pool = temp.path().join("pool");
            let mut writer = IncrementalWriter::create(writer_options(pool.clone())).unwrap();
            writer
                .replace_file(
                    Path::new("memory.bin"),
                    vec![b'A'; EROFS_BLOCK_SIZE as usize],
                )
                .unwrap();
            writer.commit().unwrap();
            let mut writer = IncrementalWriter::open_metadata_only(
                &pool.join("image.boot"),
                writer_options(pool.clone()),
            )
            .unwrap();
            writer
                .replace_file(Path::new("extra"), vec![b'B'; EROFS_BLOCK_SIZE as usize])
                .unwrap();
            writer.commit().unwrap();
            let bootstrap = pool.join("image.boot");
            let input_before = fs::read(&bootstrap).unwrap();
            let core = NydusCore::new(
                &bootstrap,
                local_config(&pool, &temp.path().join("cache")),
                None,
            )
            .unwrap();
            let output = temp.path().join("compact");
            let options = || {
                let mut options = writer_options(output.clone());
                options.compressor = compressor;
                options
            };
            // Establish the deterministic digest for sidecar failure injection
            // and exercise dedup hits without allowing cleanup to remove them.
            core.repack(options(), 1, |_| Ok(())).unwrap();
            let result_reader =
                ErofsReader::open_metadata_only(&output.join("image.boot")).unwrap();
            let digest = hex::encode(result_reader.blob_infos().unwrap()[0].blob_id);
            drop(result_reader);
            let blob = output.join(digest);
            let sidecar = blob_metadata_path(&blob);
            fs::remove_file(output.join("image.boot")).unwrap();
            if failure != "bootstrap-dedup" {
                fs::remove_file(&blob).unwrap();
                fs::remove_file(&sidecar).unwrap();
            }
            if failure == "sidecar" {
                fs::create_dir(&sidecar).unwrap();
                fs::write(output.join("image.boot"), b"previous bootstrap").unwrap();
            } else {
                fs::create_dir(output.join("image.boot")).unwrap();
            }
            let snapshot = || {
                let mut entries: Vec<_> = fs::read_dir(&output)
                    .unwrap()
                    .map(|entry| {
                        let path = entry.unwrap().path();
                        let data = path.is_file().then(|| fs::read(&path).unwrap());
                        (path.file_name().unwrap().to_os_string(), data)
                    })
                    .collect();
                entries.sort();
                entries
            };
            let before = snapshot();
            assert!(
                core.repack(options(), 1, |_| Ok(())).is_err(),
                "{compressor:?}/{failure}"
            );
            assert_eq!(snapshot(), before, "{compressor:?}/{failure}");
            assert_eq!(fs::read(&bootstrap).unwrap(), input_before);
        }
    }
}
