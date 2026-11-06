#![allow(dead_code)]

use std::collections::HashSet;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};

use nydus_config::Config;
use nydus_core::build::blob_chunk::{BlobLayout, BlobWriter};
use nydus_core::build::bootstrap::render_flattened_bootstrap;
use nydus_core::build::inode::{build_tree, resolve_chunk_addrs};
use nydus_core::extent::MmapCache;
use nydus_core::NydusCore;
use nydus_format::blob::{BlobMetadata, BlobMetadataCompressor, BlobMetadataDigester};
use nydus_format::erofs::{ErofsDeviceSlot, EROFS_BLOCK_SIZE};
use nydus_test_utils::blob::FullBlob;
use nydus_test_utils::metadata::with_wrong_chunk_group_checksum;
use tempfile::{tempdir, TempDir};

pub const CHUNK_SIZE: u32 = 64 * 1024;
pub const FILE_NAME: &str = "file";
const FILE_SIZE: usize = 5 * CHUNK_SIZE as usize + 1234;

pub struct Image {
    pub dir: TempDir,
    pub bootstrap: PathBuf,
    pub blob_dir: PathBuf,
    pub blob_id: [u8; 32],
    pub blob_metadata: BlobMetadata,
    pub file: Vec<u8>,
    pub dense: Vec<u8>,
}

impl Image {
    pub fn build() -> Self {
        let dir = tempdir().unwrap();
        let corpus = dir.path().join("corpus");
        let blob_dir = dir.path().join("blobs");
        fs::create_dir_all(&corpus).unwrap();
        fs::create_dir_all(&blob_dir).unwrap();
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let file: Vec<u8> = (0..FILE_SIZE)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        fs::write(corpus.join(FILE_NAME), &file).unwrap();

        let staging = dir.path().join("staging");
        let mut writer = BlobWriter::new(
            fs::File::create(&staging).unwrap(),
            CHUNK_SIZE,
            BlobMetadataCompressor::Zstd,
            Some(BlobMetadataDigester::Blake3),
            true,
            BlobLayout::ChunkGroups {
                chunk_group_min_size: CHUNK_SIZE,
            },
        )
        .unwrap();
        let mut inodes = build_tree(&corpus, &mut writer, CHUNK_SIZE, &HashSet::new()).unwrap();
        writer.finish().unwrap();
        resolve_chunk_addrs(&mut inodes, &writer).unwrap();
        let blob_metadata = writer.blob_metadata().unwrap();
        let blocks = writer.total_block_count();

        let data = fs::read(&staging).unwrap();
        let blob_id = FullBlob::new(&data)
            .with_blob_metadata(&blob_metadata)
            .with_blob_metadata_file()
            .save_in(&blob_dir);
        let slots = [ErofsDeviceSlot::with_blob_id(blocks, &blob_id).unwrap()];
        let bootstrap_bytes =
            render_flattened_bootstrap(&mut inodes, 0, &slots, &[0u8; 16]).unwrap();
        let bootstrap = dir.path().join("bootstrap");
        fs::write(&bootstrap, bootstrap_bytes).unwrap();

        let mut dense = file.clone();
        dense.resize(
            FILE_SIZE.div_ceil(EROFS_BLOCK_SIZE as usize) * EROFS_BLOCK_SIZE as usize,
            0,
        );
        assert_eq!(blocks * u64::from(EROFS_BLOCK_SIZE), dense.len() as u64);
        assert_eq!(blob_metadata.chunk_group_count(), 6);

        Self {
            dir,
            bootstrap,
            blob_dir,
            blob_id,
            blob_metadata,
            file,
            dense,
        }
    }

    pub fn core(&self, cache_dir: &Path, storage: &[&str]) -> NydusCore {
        let storage: String = storage.iter().map(|line| format!("  {line}\n")).collect();
        let config = Config::from_yaml(&format!(
            "backend:\n  type: local\n  config:\n    dir: {}\nstorage:\n  dir: {}\n{storage}prefetch:\n  scope: none\n",
            self.blob_dir.display(),
            cache_dir.display(),
        ))
        .unwrap();
        NydusCore::new(&self.bootstrap, config, None).unwrap()
    }

    pub fn logical(&self, group: usize) -> Range<u64> {
        self.blob_metadata
            .chunk_group(group)
            .unwrap()
            .logical_range()
    }

    pub fn compressed(&self, group: usize) -> Range<u64> {
        self.blob_metadata
            .chunk_group(group)
            .unwrap()
            .compressed_range()
    }

    pub fn blob_path(&self) -> PathBuf {
        self.blob_dir.join(hex::encode(self.blob_id))
    }

    pub fn tamper_chunk_group_checksum(&self, group: usize) {
        let mut sidecar = self.blob_path().into_os_string();
        sidecar.push(BlobMetadata::SUFFIX);
        with_wrong_chunk_group_checksum(&self.blob_metadata, group)
            .save(Path::new(&sidecar))
            .unwrap();
    }
}

pub fn read_flat(core: &NydusCore, offset: u64, len: u64) -> nydus_error::Result<Vec<u8>> {
    let extents = core.fetch_flat_ranges(offset, len)?;
    let mut buf = vec![0xeeu8; len as usize];
    MmapCache::default().copy_ranges(&extents, offset, core.zero_fd(), &mut buf)?;
    Ok(buf)
}
