use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nydus::build::{build_image, BuildImageOptions};
use nydus_config::Config;
use nydus_core::writer::{IncrementalWriter, IncrementalWriterOptions};
use nydus_core::{ErofsReader, NydusCore};
use nydus_format::blob::{BlobMetadataCompressor, DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE};
use nydus_format::erofs::EROFS_NULL_ADDR;
use nydus_format::utils::hex_string;

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

fn open_metadata_writer(
    temp: &tempfile::TempDir,
    parent_bootstrap: &Path,
) -> (IncrementalWriter, PathBuf) {
    let output_dir = temp.path().to_path_buf();
    let writer = IncrementalWriter::open_metadata_only(
        parent_bootstrap,
        IncrementalWriterOptions {
            output_dir: output_dir.clone(),
            chunk_size: DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
            compress_size: DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
            compressor: BlobMetadataCompressor::None,
        },
    )
    .unwrap();
    (writer, output_dir)
}

fn open_data_writer(
    temp: &tempfile::TempDir,
    parent_bootstrap: &Path,
) -> (IncrementalWriter, PathBuf) {
    let output_dir = temp.path().to_path_buf();
    let config = Config::from_yaml(&format!(
        "backend:\n  type: local\n  config:\n    dir: {}\nstorage:\n  dir: {}\nprefetch:\n  scope: none\n",
        temp.path().display(),
        temp.path().join("cache").display(),
    ))
    .unwrap();
    let core = NydusCore::new(parent_bootstrap, config).unwrap();
    let writer = core
        .writer(IncrementalWriterOptions {
            output_dir: output_dir.clone(),
            chunk_size: DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
            compress_size: DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
            compressor: BlobMetadataCompressor::None,
        })
        .unwrap();
    (writer, output_dir)
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
    assert!(upper_blob.metadata().unwrap().len() > chunk_size as u64);
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
        .replace_file(Path::new("memory.bin"), &vec![b'R'; chunk_size])
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
    let blob_metadata = nydus_format::blob::BlobMetadata::from_path(
        commit.blob_metadata_path.as_ref().unwrap(),
        false,
    )
    .unwrap();
    assert!(blob_metadata.is_incremental());
    assert!(commit.blob_path.as_ref().unwrap().exists());
}

#[test]
fn incremental_writer_rejects_empty_commit() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'A'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (writer, _output_dir) = open_metadata_writer(&temp, &parent_bootstrap);

    assert!(writer.commit().is_err());
}

#[test]
fn incremental_writer_rejects_invalid_compress_size_before_writes() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'A'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);

    let err = match IncrementalWriter::open_metadata_only(
        &parent_bootstrap,
        IncrementalWriterOptions {
            output_dir: temp.path().to_path_buf(),
            chunk_size: DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
            compress_size: DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE - 1,
            compressor: BlobMetadataCompressor::None,
        },
    ) {
        Ok(_) => panic!("expected invalid compress size"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("compress size"));
}

#[test]
fn incremental_writer_rejects_metadata_write_with_mismatched_chunk_size() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'A'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let writer_chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE / 2;
    let mut writer = IncrementalWriter::open_metadata_only(
        &parent_bootstrap,
        IncrementalWriterOptions {
            output_dir: temp.path().to_path_buf(),
            chunk_size: writer_chunk_size,
            compress_size: writer_chunk_size,
            compressor: BlobMetadataCompressor::None,
        },
    )
    .unwrap();

    assert!(writer.write_at(Path::new("memory.bin"), 0, b"B").is_err());
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
        .writer(IncrementalWriterOptions {
            output_dir: output_dir.clone(),
            chunk_size: DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
            compress_size: DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
            compressor: BlobMetadataCompressor::None,
        })
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
fn incremental_writer_write_at_patches_existing_dirty_full_chunk() {
    let temp = tempfile::tempdir().unwrap();
    let chunk_size = DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize;
    let parent_data = vec![b'A'; chunk_size];
    let (parent_bootstrap, _parent_digest) = build_parent_blob(&temp, &parent_data);
    let (mut writer, output_dir) = open_data_writer(&temp, &parent_bootstrap);

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
    let (mut writer, output_dir) = open_data_writer(&temp, &parent_bootstrap);

    let replacement = vec![b'R'; chunk_size / 2];
    writer
        .replace_file(Path::new("memory.bin"), &replacement)
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
    let (mut writer, output_dir) = open_data_writer(&temp, &parent_bootstrap);

    let mut replacement = vec![b'R'; chunk_size + chunk_size / 2];
    writer
        .replace_file(Path::new("memory.bin"), &replacement)
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
