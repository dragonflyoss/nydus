//! Full blob files on disk, named by their SHA-256 the way a blob store
//! names them.

use crate::erofs;
use nydus_format::blob::{finish_full_blob, BlobMetadata};
use nydus_format::utils::SHA256_DIGEST_SIZE;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::fs;
use std::path::Path;

/// A full blob to write: `data`, then whatever regions the test asks for,
/// assembled by the production [`finish_full_blob`].
///
/// Without a bootstrap the blob has the ondemand layout, without metadata
/// the raw device layout. [`Self::minimal`] is the common store entry: a
/// bootstrap no test reads plus the metadata describing `data`.
#[derive(Clone, Debug)]
pub struct FullBlob<'a> {
    data: &'a [u8],
    bootstrap: Option<Cow<'a, [u8]>>,
    metadata: Option<&'a BlobMetadata>,
    sidecar: bool,
}

/// Configures the regions and saves the blob.
impl<'a> FullBlob<'a> {
    /// A blob of `data` with no other region yet.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            bootstrap: None,
            metadata: None,
            sidecar: false,
        }
    }

    /// A blob of `data` described by `metadata`, with a superblock-only
    /// bootstrap embedded.
    pub fn minimal(data: &'a [u8], metadata: &'a BlobMetadata) -> Self {
        Self::new(data)
            .with_minimal_bootstrap()
            .with_metadata(metadata)
    }

    /// Embeds `bootstrap`.
    pub fn with_bootstrap(mut self, bootstrap: &'a [u8]) -> Self {
        self.bootstrap = Some(Cow::Borrowed(bootstrap));
        self
    }

    /// Embeds a two-block bootstrap holding nothing but a superblock.
    pub fn with_minimal_bootstrap(mut self) -> Self {
        self.bootstrap = Some(Cow::Owned(erofs::superblock_image(2)));
        self
    }

    /// Embeds `metadata`.
    pub fn with_metadata(mut self, metadata: &'a BlobMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Also saves the metadata as the `.blob.meta` sidecar next to the blob.
    pub fn with_sidecar(mut self) -> Self {
        self.sidecar = true;
        self
    }

    /// The blob's bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut blob = self.data.to_vec();
        finish_full_blob(
            &mut blob,
            self.data.len() as u64,
            self.bootstrap.as_deref(),
            self.metadata,
        )
        .unwrap();
        blob
    }

    /// Saves the blob into `dir` under its hex SHA-256 and returns that
    /// digest, the blob id.
    pub fn save_in(&self, dir: &Path) -> [u8; SHA256_DIGEST_SIZE] {
        let blob = self.to_bytes();
        let blob_id: [u8; SHA256_DIGEST_SIZE] = Sha256::digest(&blob).into();
        self.save_bytes(&blob, &dir.join(hex::encode(blob_id)));
        blob_id
    }

    /// Saves the blob to `path` and returns its SHA-256, the blob id.
    pub fn save(&self, path: &Path) -> [u8; SHA256_DIGEST_SIZE] {
        let blob = self.to_bytes();
        self.save_bytes(&blob, path);
        Sha256::digest(&blob).into()
    }

    /// Saves `blob` to `path`, and the sidecar next to it when asked.
    fn save_bytes(&self, blob: &[u8], path: &Path) {
        fs::write(path, blob).unwrap();
        if self.sidecar {
            let metadata = self.metadata.expect("a sidecar needs metadata");
            let mut sidecar = path.as_os_str().to_owned();
            sidecar.push(BlobMetadata::SUFFIX);
            metadata.save(Path::new(&sidecar)).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata;
    use nydus_format::blob::BlobFooter;
    use tempfile::tempdir;

    #[test]
    fn save_in_names_the_blob_by_its_digest_and_saves_the_sidecar_on_request() {
        let payload = vec![0xab; 4096];
        let metadata = metadata::single_chunk(&payload);

        let test_cases = vec![(false, false), (true, false), (true, true)];

        for (minimal, sidecar) in test_cases {
            let dir = tempdir().unwrap();
            let mut blob = if minimal {
                FullBlob::minimal(&payload, &metadata)
            } else {
                FullBlob::new(&payload).with_metadata(&metadata)
            };
            if sidecar {
                blob = blob.with_sidecar();
            }
            let blob_id = blob.save_in(dir.path());
            let path = dir.path().join(hex::encode(blob_id));
            let bytes = fs::read(&path).unwrap();
            let footer = BlobFooter::from_blob_bytes(&bytes).unwrap();

            let digest: [u8; SHA256_DIGEST_SIZE] = Sha256::digest(&bytes).into();
            assert_eq!(digest, blob_id);
            assert_eq!(&bytes[..4096], &payload[..]);
            assert_eq!(footer.compressed_data_size(), 4096);
            assert_eq!(footer.bootstrap_size() > 0, minimal);
            assert_eq!(footer.blob_metadata_size(), metadata.size());
            assert_eq!(
                BlobMetadata::from_path(Path::new(&format!(
                    "{}{}",
                    path.display(),
                    BlobMetadata::SUFFIX
                )))
                .is_ok(),
                sidecar
            );
        }
    }

    #[test]
    fn save_lays_out_raw_device_and_ondemand_blobs() {
        let payload = vec![0xcd; 100];
        let metadata = metadata::single_chunk(&payload);
        let bootstrap = erofs::superblock_image(1);
        let dir = tempdir().unwrap();

        let test_cases: Vec<(FullBlob<'_>, bool, u64)> = vec![
            (
                FullBlob::new(&payload).with_bootstrap(&bootstrap),
                true,
                4096,
            ),
            (FullBlob::new(&payload).with_metadata(&metadata), false, 0),
        ];

        for (blob, raw_device, bootstrap_size) in test_cases {
            let path = dir.path().join("blob");
            let blob_id = blob.save(&path);
            let footer = BlobFooter::from_blob_path(&path).unwrap();

            let digest: [u8; SHA256_DIGEST_SIZE] = Sha256::digest(fs::read(&path).unwrap()).into();
            assert_eq!(digest, blob_id);
            assert_eq!(footer.is_raw_device(), raw_device);
            assert_eq!(footer.bootstrap_size(), bootstrap_size);
            assert_eq!(footer.compressed_data_size(), 100);
        }
    }
}
