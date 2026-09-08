use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::Arc;

use nydus::build::{build_image, BuildImageOptions, DEFAULT_CHUNK_GROUP_MIN_SIZE};
use nydus_config::Config;
use nydus_core::writer::{CreateFileOptions, IncrementalWriter, IncrementalWriterOptions};
use nydus_core::{ErofsReader, NydusCore};
use nydus_format::blob::{
    BlobMetadataCompressor, BlobMetadataDigester, DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
};
use nydus_format::erofs::{
    ErofsChunkIndex, EROFS_BLOCK_SIZE, EROFS_CHUNK_INDEX_SIZE, EROFS_NULL_ADDR, EROFS_SLOTSIZE,
};
use nydus_format::utils::hex_string;

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
        temp.path().join(hex_string(&parent.full_blob_digest)),
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
    assert_eq!(options.digester, BlobMetadataDigester::Blake3);
}

fn create_parentless_writer(temp: &tempfile::TempDir) -> (IncrementalWriter, PathBuf) {
    let output_dir = temp.path().to_path_buf();
    let writer = IncrementalWriter::create(writer_options(output_dir.clone())).unwrap();
    (writer, output_dir)
}

fn local_config(blob_dir: &Path, cache_dir: &Path) -> Config {
    Config::from_yaml(&format!(
        "backend:\n  type: local\n  config:\n    dir: {}\nstorage:\n  dir: {}\nprefetch:\n  scope: none\n",
        blob_dir.display(),
        cache_dir.display(),
    ))
    .unwrap()
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
    let core = NydusCore::new(parent_bootstrap, config).unwrap();
    let writer = core.writer(writer_options(output_dir.clone())).unwrap();
    (writer, output_dir)
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
    path.push(nydus_format::blob::NYDUS_BLOB_METADATA_SUFFIX);
    path.into()
}

fn commit_upper_blob(output_dir: &Path, writer: IncrementalWriter) -> CommittedImage {
    writer.commit().unwrap();
    let bootstrap_path = output_dir.join("image.boot");
    assert!(bootstrap_path.exists());

    let reader = ErofsReader::open_metadata_only(&bootstrap_path).unwrap();
    let blob_infos = reader.blob_infos().unwrap();
    let blob_path = if blob_infos.len() > 1 {
        let path = output_dir.join(hex_string(&blob_infos.last().unwrap().blob_id));
        assert!(path.exists());
        Some(path)
    } else {
        None
    };
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
    let reader_backend: Arc<dyn nydus_backend::BlobBackend> =
        Arc::new(nydus_backend::Local::new(temp.path().to_path_buf()));
    let reader =
        ErofsReader::open_bootstrap(&commit.bootstrap_path, reader_backend, None, None).unwrap();
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
        let blob = output_dir.join(hex_string(&info.blob_id));
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

    let backend: Arc<dyn nydus_backend::BlobBackend> =
        Arc::new(nydus_backend::Local::new(output_dir));
    let reader = ErofsReader::open_bootstrap(&bootstrap, backend, None, None).unwrap();
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
    let blob = output_dir.join(hex_string(&blob_infos[0].blob_id));
    assert!(blob.exists());
    assert!(blob_metadata_path(&blob).exists());

    let core = NydusCore::new(
        &bootstrap,
        local_config(&output_dir, &output_dir.join("runtime-cache")),
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
    let backend: Arc<dyn nydus_backend::BlobBackend> =
        Arc::new(nydus_backend::Local::new(output_dir));
    let reader = ErofsReader::open_bootstrap(&bootstrap, backend, None, None).unwrap();
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
    let flattened_chunk = ErofsChunkIndex::new(parent_mapping + parent_chunk.blkaddr, 0).unwrap();
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
    let backend: Arc<dyn nydus_backend::BlobBackend> =
        Arc::new(nydus_backend::Local::new(output_dir));
    let reader = ErofsReader::open_bootstrap(&bootstrap, backend, None, None).unwrap();
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
    let backend: Arc<dyn nydus_backend::BlobBackend> =
        Arc::new(nydus_backend::Local::new(output_dir));
    let reader = ErofsReader::open_bootstrap(&bootstrap, backend, None, None).unwrap();
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
    let backend: Arc<dyn nydus_backend::BlobBackend> =
        Arc::new(nydus_backend::Local::new(output_dir));
    let reader = ErofsReader::open_bootstrap(&bootstrap, backend, None, None).unwrap();
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
    assert_eq!(
        inode.effective_mtime_nsec(reader.superblock().fixed_nsec()),
        789
    );
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

    for path in ["", "/absolute", "../outside", "missing/child"] {
        assert!(writer
            .create_file(Path::new(path), 0, CreateFileOptions::default())
            .is_err());
    }
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
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'P'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_metadata_writer(&temp, &parent_bootstrap);
    let source_path = temp.path().join("short-commit-source");
    fs::write(&source_path, b"short").unwrap();
    let source = Arc::new(fs::File::open(source_path).unwrap());
    writer
        .write_file_range(Path::new("memory.bin"), 0, source, 0, chunk_size as u64)
        .unwrap();

    assert!(writer.commit().is_err());
    assert_no_temporary_blob(&output_dir);
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
        nydus_format::utils::parse_sha256_hex(
            commit
                .blob_path
                .as_ref()
                .unwrap()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
        )
        .unwrap()
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
    assert_eq!(blob_metadata.digester(), BlobMetadataDigester::Blake3);
    assert_eq!(blob_metadata.lookup_granule(), DEFAULT_CHUNK_GROUP_MIN_SIZE);
    assert_eq!(blob_metadata.digest_count(), blob_metadata.chunk_count());
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
    options.digester = BlobMetadataDigester::None;
    options.chunk_group_min_size = EROFS_BLOCK_SIZE;
    let mut writer = IncrementalWriter::open_metadata_only(&parent_bootstrap, options).unwrap();

    writer
        .write_at(Path::new("memory.bin"), 0, &vec![b'N'; chunk_size])
        .unwrap();
    let commit = commit_upper_blob(&output_dir, writer);
    let blob_metadata =
        nydus_format::blob::BlobMetadata::from_path(commit.blob_metadata_path.as_ref().unwrap())
            .unwrap();

    assert_eq!(blob_metadata.digester(), BlobMetadataDigester::None);
    assert_eq!(blob_metadata.lookup_granule(), EROFS_BLOCK_SIZE);
    assert_eq!(blob_metadata.chunk_count(), 1);
    assert_eq!(blob_metadata.digest_count(), 0);
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
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'A'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (writer, _output_dir) = open_metadata_writer(&temp, &parent_bootstrap);

    assert!(writer
        .commit()
        .unwrap_err()
        .to_string()
        .contains("no changes"));
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

    let reader_backend: Arc<dyn nydus_backend::BlobBackend> =
        Arc::new(nydus_backend::Local::new(temp.path().to_path_buf()));
    let reader =
        ErofsReader::open_bootstrap(&commit.bootstrap_path, reader_backend, None, None).unwrap();
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

    let reader_backend: Arc<dyn nydus_backend::BlobBackend> =
        Arc::new(nydus_backend::Local::new(temp.path().to_path_buf()));
    let reader =
        ErofsReader::open_bootstrap(&commit.bootstrap_path, reader_backend, None, None).unwrap();
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
    let config = Config::from_yaml(&format!(
        "backend:\n  type: local\n  config:\n    dir: {}\nstorage:\n  dir: {}\nprefetch:\n  scope: none\n",
        temp.path().display(),
        temp.path().join("cache").display(),
    ))
    .unwrap();
    let core = NydusCore::new(&parent_bootstrap, config).unwrap();

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

    let reader_backend: Arc<dyn nydus_backend::BlobBackend> =
        Arc::new(nydus_backend::Local::new(temp.path().to_path_buf()));
    let reader =
        ErofsReader::open_bootstrap(&commit.bootstrap_path, reader_backend, None, None).unwrap();
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
