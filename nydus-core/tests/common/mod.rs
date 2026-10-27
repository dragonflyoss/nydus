//! The image the nydus-core integration tests read: one file of random
//! bytes in 64 KiB chunks, each chunk a chunk group of its own, built
//! through the nydus-core build helpers into a flattened bootstrap and one
//! full blob in a local blob store.

// Every test binary uses a different part of the fixture.
#![allow(dead_code)]

use std::collections::HashSet;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};

use nydus_config::Config;
use nydus_core::build::blob_chunk::{BlobLayout, BlobWriter};
use nydus_core::build::bootstrap::render_flattened_bootstrap;
use nydus_core::build::inode::{build_tree, resolve_chunk_addrs};
use nydus_core::NydusCore;
use nydus_format::blob::{BlobMetadata, BlobMetadataCompressor, BlobMetadataDigester};
use nydus_format::erofs::{ErofsDeviceSlot, EROFS_BLOCK_SIZE};
use nydus_test_utils::blob::FullBlob;
use nydus_test_utils::metadata::with_wrong_chunk_group_checksum;
use tempfile::TempDir;

/// The chunk size, which is also the chunk group minimum: every full chunk
/// is a group of its own.
pub const CHUNK_SIZE: u32 = 64 * 1024;

/// The one file in the image.
pub const FILE_NAME: &str = "file";

/// Five full chunks and a short tail chunk.
const FILE_SIZE: usize = 5 * CHUNK_SIZE as usize + 1234;

pub struct Image {
    /// Owns everything below.
    pub dir: TempDir,
    pub bootstrap: PathBuf,
    /// The local backend's blob store.
    pub blob_dir: PathBuf,
    /// The full blob's digest, the id in the bootstrap's device slot.
    pub blob_id: [u8; 32],
    pub blob_metadata: BlobMetadata,
    /// The content of [`FILE_NAME`].
    pub file: Vec<u8>,
    /// The blob's dense address space, what the filled cache file holds:
    /// the file zero-padded to whole blocks.
    pub dense: Vec<u8>,
}

impl Image {
    pub fn build() -> Self {
        let dir = tempfile::tempdir().expect("create the image dir");
        let corpus = dir.path().join("corpus");
        let blob_dir = dir.path().join("blobs");
        fs::create_dir_all(&corpus).expect("create the corpus dir");
        fs::create_dir_all(&blob_dir).expect("create the blob dir");
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let file: Vec<u8> = (0..FILE_SIZE)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        fs::write(corpus.join(FILE_NAME), &file).expect("write the corpus file");

        let staging = dir.path().join("staging");
        let mut writer = BlobWriter::new(
            fs::File::create(&staging).expect("create the staging blob"),
            CHUNK_SIZE,
            BlobMetadataCompressor::Zstd,
            Some(BlobMetadataDigester::Blake3),
            true,
            BlobLayout::ChunkGroups {
                chunk_group_min_size: CHUNK_SIZE,
            },
        )
        .expect("create the blob writer");
        let mut inodes =
            build_tree(&corpus, &mut writer, CHUNK_SIZE, &HashSet::new()).expect("build the tree");
        writer.finish().expect("finish the blob");
        resolve_chunk_addrs(&mut inodes, &writer).expect("resolve chunk addresses");
        let blob_metadata = writer.blob_metadata().expect("blob meta");
        let blocks = writer.total_block_count();

        let data = fs::read(&staging).expect("read the staging blob");
        let blob_id = FullBlob::new(&data)
            .with_blob_metadata(&blob_metadata)
            .with_blob_metadata_file()
            .save_in(&blob_dir);
        let slots = [ErofsDeviceSlot::with_blob_id(blocks, &blob_id).expect("device slot")];
        let bootstrap_bytes = render_flattened_bootstrap(&mut inodes, 0, &slots, &[0u8; 16])
            .expect("render the bootstrap");
        let bootstrap = dir.path().join("bootstrap");
        fs::write(&bootstrap, bootstrap_bytes).expect("write the bootstrap");

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

    /// A config serving the image from its blob store through a cache in
    /// `cache_dir`, with background prefetch off. `storage` holds extra
    /// `storage:` keys, one `key: value` per line.
    pub fn config(&self, cache_dir: &Path, storage: &[&str]) -> Config {
        let storage: String = storage.iter().map(|line| format!("  {line}\n")).collect();
        Config::from_yaml(&format!(
            "backend:\n  type: local\n  config:\n    dir: {}\nstorage:\n  dir: {}\n{storage}prefetch:\n  scope: none\n",
            self.blob_dir.display(),
            cache_dir.display(),
        ))
        .expect("parse the config")
    }

    /// A core over the image with a cache of its own.
    pub fn core(&self, cache_dir: &Path, storage: &[&str]) -> NydusCore {
        NydusCore::new(&self.bootstrap, self.config(cache_dir, storage), None)
            .expect("open the core")
    }

    /// Where chunk group `group` sits in the blob's dense address space.
    pub fn logical(&self, group: usize) -> Range<u64> {
        self.blob_metadata
            .chunk_group(group)
            .expect("group exists")
            .logical_range()
    }

    /// Where chunk group `group` sits in the blob's data region, which
    /// starts the full blob file.
    pub fn compressed(&self, group: usize) -> Range<u64> {
        self.blob_metadata
            .chunk_group(group)
            .expect("group exists")
            .compressed_range()
    }

    pub fn blob_path(&self) -> PathBuf {
        self.blob_dir.join(hex::encode(self.blob_id))
    }

    /// Replace the blob meta sidecar the local backend prefers with one
    /// claiming a wrong CRC32C for group `group`. The blob id is unchanged.
    pub fn tamper_chunk_group_checksum(&self, group: usize) {
        let mut sidecar = self.blob_path().into_os_string();
        sidecar.push(BlobMetadata::SUFFIX);
        with_wrong_chunk_group_checksum(&self.blob_metadata, group)
            .save(Path::new(&sidecar))
            .expect("save the tampered blob meta");
    }
}

/// Copy `[offset, offset + len)` of the core's flattened device out of the
/// extents `fetch_flat_ranges` returns.
pub fn read_flat(core: &NydusCore, offset: u64, len: u64) -> nydus_error::Result<Vec<u8>> {
    let extents = core.fetch_flat_ranges(offset, len)?;
    let mut buf = vec![0xeeu8; len as usize];
    nydus_core::extent::MmapCache::default().copy_ranges(
        &extents,
        offset,
        core.zero_fd(),
        &mut buf,
    )?;
    Ok(buf)
}
