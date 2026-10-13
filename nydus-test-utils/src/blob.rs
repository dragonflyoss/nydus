//! Full blob files on disk, named by their SHA-256 the way a blob store
//! names them, and the uncompressed data their data region decodes to.

use nydus_format::blob::{finish_full_blob, BlobMetadata};
use nydus_format::erofs::{ErofsSuperblock, EROFS_BLOCK_SIZE, EROFS_SUPER_OFFSET};
use nydus_format::utils::SHA256_DIGEST_SIZE;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// The bootstrap region of a [`FullBlob`].
#[derive(Clone, Copy, Debug)]
enum Bootstrap<'a> {
    /// A superblock-only image no test reads, present so the blob has the
    /// ordinary layout.
    SuperblockOnly,

    /// No region, the ondemand layout.
    None,

    /// A real bootstrap the test rendered.
    Bytes(&'a [u8]),
}

/// A full blob to save: `data`, then the regions the test asks for,
/// assembled by the production [`finish_full_blob`].
///
/// A new blob carries a superblock-only bootstrap and no blob meta, which
/// is the raw device layout. [`Self::with_blob_metadata`] makes it an
/// ordinary full blob, [`Self::without_bootstrap`] an ondemand one.
#[derive(Clone, Debug)]
pub struct FullBlob<'a> {
    data: &'a [u8],
    bootstrap: Bootstrap<'a>,
    blob_metadata: Option<&'a BlobMetadata>,
    save_blob_metadata_file: bool,
}

/// Configures the regions and saves the blob.
impl<'a> FullBlob<'a> {
    /// Creates a blob of `data` with a superblock-only bootstrap.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            bootstrap: Bootstrap::SuperblockOnly,
            blob_metadata: None,
            save_blob_metadata_file: false,
        }
    }

    /// Embeds `bootstrap` instead of the superblock-only one.
    pub fn with_bootstrap(mut self, bootstrap: &'a [u8]) -> Self {
        self.bootstrap = Bootstrap::Bytes(bootstrap);
        self
    }

    /// Embeds no bootstrap, the ondemand layout.
    pub fn without_bootstrap(mut self) -> Self {
        self.bootstrap = Bootstrap::None;
        self
    }

    /// Embeds `blob_metadata`.
    pub fn with_blob_metadata(mut self, blob_metadata: &'a BlobMetadata) -> Self {
        self.blob_metadata = Some(blob_metadata);
        self
    }

    /// Also saves the blob meta to the `<blob>.blob.meta` file next to the
    /// blob, the one [`BlobMetadata::save`] writes.
    pub fn with_blob_metadata_file(mut self) -> Self {
        self.save_blob_metadata_file = true;
        self
    }

    /// Saves the blob into `dir` under its hex SHA-256 and returns that
    /// digest, the blob id. The blob meta file goes next to it when asked.
    pub fn save_in(&self, dir: &Path) -> [u8; SHA256_DIGEST_SIZE] {
        let bootstrap = match self.bootstrap {
            Bootstrap::SuperblockOnly => Some(superblock_only()),
            Bootstrap::None => None,
            Bootstrap::Bytes(bytes) => Some(bytes.to_vec()),
        };
        let mut blob = self.data.to_vec();
        finish_full_blob(
            &mut blob,
            self.data.len() as u64,
            bootstrap.as_deref(),
            self.blob_metadata,
        )
        .unwrap();

        let blob_id: [u8; SHA256_DIGEST_SIZE] = Sha256::digest(&blob).into();
        let path = dir.join(hex::encode(blob_id));
        fs::write(&path, &blob).unwrap();
        if self.save_blob_metadata_file {
            let blob_metadata = self
                .blob_metadata
                .expect("a blob meta file needs blob meta");
            let mut blob_metadata_path = path.into_os_string();
            blob_metadata_path.push(BlobMetadata::SUFFIX);
            blob_metadata.save(Path::new(&blob_metadata_path)).unwrap();
        }
        blob_id
    }
}

/// The uncompressed data the data region of `chunk_groups` decodes to,
/// every chunk padded to its own blocks and the groups back to back: what a
/// fully filled cache file holds.
pub fn uncompressed_data(chunk_groups: &[Vec<Vec<u8>>]) -> Vec<u8> {
    let block_size = EROFS_BLOCK_SIZE as usize;
    let block_count: usize = chunk_groups
        .iter()
        .flatten()
        .map(|chunk| chunk.len().div_ceil(block_size))
        .sum();
    let mut data = vec![0u8; block_count * block_size];
    let mut offset = 0;
    for chunk in chunk_groups.iter().flatten() {
        data[offset..offset + chunk.len()].copy_from_slice(chunk);
        offset += chunk.len().div_ceil(block_size) * block_size;
    }
    data
}

/// Two blocks holding nothing but a valid superblock, the bootstrap a full
/// blob embeds when no test reads it.
fn superblock_only() -> Vec<u8> {
    let superblock = ErofsSuperblock::new(0, 0, 0, 0, 0, 2, 1, 0, 0, &[0u8; 16]).unwrap();
    let mut bootstrap = vec![0u8; 2 * EROFS_BLOCK_SIZE as usize];
    let offset = EROFS_SUPER_OFFSET as usize;
    bootstrap[offset..offset + superblock.as_bytes().len()].copy_from_slice(superblock.as_bytes());
    bootstrap
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata;
    use nydus_format::blob::BlobFooter;
    use tempfile::tempdir;

    #[test]
    fn save_in_names_the_blob_by_its_digest_and_saves_the_blob_meta_file_on_request() {
        let payload = vec![0xab; 4096];
        let blob_metadata = metadata::single_chunk_group(&payload);

        let test_cases = vec![(false, false), (true, false), (true, true)];

        for (bootstrap, blob_metadata_file) in test_cases {
            let dir = tempdir().unwrap();
            let mut blob = FullBlob::new(&payload).with_blob_metadata(&blob_metadata);
            if !bootstrap {
                blob = blob.without_bootstrap();
            }
            if blob_metadata_file {
                blob = blob.with_blob_metadata_file();
            }
            let blob_id = blob.save_in(dir.path());
            let path = dir.path().join(hex::encode(blob_id));
            let bytes = fs::read(&path).unwrap();
            let footer = BlobFooter::from_blob_bytes(&bytes).unwrap();

            let digest: [u8; SHA256_DIGEST_SIZE] = Sha256::digest(&bytes).into();
            assert_eq!(digest, blob_id);
            assert_eq!(&bytes[..4096], &payload[..]);
            assert_eq!(footer.compressed_data_size(), 4096);
            assert_eq!(footer.bootstrap_size() > 0, bootstrap);
            assert_eq!(footer.blob_metadata_size(), blob_metadata.size());
            assert_eq!(
                BlobMetadata::from_path(Path::new(&format!(
                    "{}{}",
                    path.display(),
                    BlobMetadata::SUFFIX
                )))
                .is_ok(),
                blob_metadata_file
            );
        }
    }

    #[test]
    fn save_in_lays_out_raw_device_and_ondemand_blobs() {
        let payload = vec![0xcd; 100];
        let blob_metadata = metadata::single_chunk_group(&payload);
        let bootstrap = superblock_only();
        let dir = tempdir().unwrap();

        let test_cases: Vec<(FullBlob<'_>, bool, u64)> = vec![
            (FullBlob::new(&payload), true, 4096),
            (
                FullBlob::new(&payload).with_bootstrap(&bootstrap),
                true,
                4096,
            ),
            (
                FullBlob::new(&payload)
                    .without_bootstrap()
                    .with_blob_metadata(&blob_metadata),
                false,
                0,
            ),
        ];

        for (blob, raw_device, bootstrap_size) in test_cases {
            let blob_id = blob.save_in(dir.path());
            let path = dir.path().join(hex::encode(blob_id));
            let footer = BlobFooter::from_blob_path(&path).unwrap();

            let digest: [u8; SHA256_DIGEST_SIZE] = Sha256::digest(fs::read(&path).unwrap()).into();
            assert_eq!(digest, blob_id);
            assert_eq!(footer.is_raw_device(), raw_device);
            assert_eq!(footer.bootstrap_size(), bootstrap_size);
            assert_eq!(footer.compressed_data_size(), 100);
        }
    }

    #[test]
    fn uncompressed_data_pads_every_chunk_to_its_own_blocks() {
        let chunk_groups = vec![
            vec![vec![0x11; 4096], vec![0x22; 100]],
            vec![vec![0x33; 4096 - 1]],
        ];
        let data = uncompressed_data(&chunk_groups);
        assert_eq!(data.len(), 3 * 4096);
        assert_eq!(&data[..4096], &[0x11; 4096]);
        assert_eq!(&data[4096..4096 + 100], &[0x22; 100]);
        assert!(data[4096 + 100..8192].iter().all(|byte| *byte == 0));
        assert_eq!(&data[8192..8192 + 4095], &[0x33; 4095]);
        assert_eq!(data[12287], 0);
    }
}
