//! Low-level helpers for building nydus images.
//!
//! The public surface here is intentionally small; high-level build orchestration
//! lives in the `nydus` crate, while incremental writer internals reuse these
//! helpers inside `nydus-core`. These modules are exported for the in-tree
//! builder/merge crates and are not intended as the stable user-facing API;
//! prefer [`NydusCore::writer`](crate::NydusCore::writer) for incremental image
//! updates.

pub mod blob_chunk;
pub mod bootstrap;
pub(crate) mod dir;
pub(crate) mod image;
pub mod inode;
pub(crate) mod layout;

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use nydus_error::{Context, Error, Result};
use nydus_format::blob::{
    BlobFooter, BlobMetadata, NYDUS_BLOB_FOOTER_SIZE, NYDUS_BLOB_METADATA_SUFFIX,
};
use nydus_format::erofs::{EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE};
use nydus_format::utils::{hex_string, sha256_bytes};
use sha2::{Digest, Sha256};

/// A writer that hashes every byte it forwards to the inner writer.
pub struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
}

impl<W: Write> HashingWriter<W> {
    pub fn new(inner: W, hasher: Sha256) -> Self {
        Self { inner, hasher }
    }

    pub fn finish(mut self) -> io::Result<[u8; EROFS_BLOB_ID_SIZE]> {
        self.inner.flush()?;
        let mut digest = [0u8; EROFS_BLOB_ID_SIZE];
        digest.copy_from_slice(&self.hasher.finalize());
        Ok(digest)
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.hasher.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub fn validate_chunk_geometry(chunk_size: u32, compress_size: u32) -> Result<()> {
    if chunk_size < EROFS_BLOCK_SIZE {
        return Err(Error::InvalidParameter(format!(
            "chunk size {chunk_size} must be >= block size {EROFS_BLOCK_SIZE}"
        )));
    }
    if !chunk_size.is_power_of_two() {
        return Err(Error::InvalidParameter(format!(
            "chunk size {chunk_size} must be a power of two"
        )));
    }
    if chunk_size % EROFS_BLOCK_SIZE != 0 {
        return Err(Error::InvalidParameter(format!(
            "chunk size {chunk_size} must be block aligned"
        )));
    }
    if !compress_size.is_power_of_two() || compress_size < 512 * 1024 {
        return Err(Error::InvalidParameter(format!(
            "compress size {compress_size} must be a power of two and at least 512KiB"
        )));
    }
    if compress_size < chunk_size {
        return Err(Error::InvalidParameter(format!(
            "compress size {compress_size} must be >= chunk size {chunk_size}"
        )));
    }
    Ok(())
}

fn digest_named_blob_path(blob_dir: &Path, full_blob_digest: &[u8; EROFS_BLOB_ID_SIZE]) -> PathBuf {
    blob_dir.join(hex_string(full_blob_digest))
}

fn blob_metadata_sidecar_path(full_blob_path: &Path) -> PathBuf {
    let mut path = full_blob_path.to_path_buf().into_os_string();
    path.push(NYDUS_BLOB_METADATA_SUFFIX);
    path.into()
}

pub fn save_blob_metadata_sidecar(
    blob_metadata: &BlobMetadata,
    full_blob_path: &Path,
) -> Result<PathBuf> {
    let blob_metadata_path = blob_metadata_sidecar_path(full_blob_path);
    blob_metadata.save(&blob_metadata_path)?;
    Ok(blob_metadata_path)
}

pub fn finalize_digest_named_blob(
    temp_blob_path: &Path,
    blob_dir: &Path,
    full_blob_digest: &[u8; EROFS_BLOB_ID_SIZE],
) -> Result<PathBuf> {
    let full_blob_path = digest_named_blob_path(blob_dir, full_blob_digest);
    if full_blob_path.exists() {
        fs::remove_file(temp_blob_path).with_context(|| {
            format!(
                "failed to remove temporary blob after dedup hit: {}",
                temp_blob_path.display()
            )
        })?;

        return Ok(full_blob_path);
    }

    fs::rename(temp_blob_path, &full_blob_path).with_context(|| {
        format!(
            "failed to rename blob {} to {}",
            temp_blob_path.display(),
            full_blob_path.display()
        )
    })?;

    Ok(full_blob_path)
}

/// Assemble an ondemand artifact `[group data][blob.meta][footer]` (no
/// embedded bootstrap) and return its bytes, full SHA256 digest, and footer.
pub fn assemble_ondemand_artifact(
    data: &[u8],
    blob_metadata: &BlobMetadata,
) -> Result<(Vec<u8>, [u8; EROFS_BLOB_ID_SIZE], BlobFooter)> {
    let mut artifact = Vec::with_capacity(
        usize::try_from(data.len() as u64 + blob_metadata.padded_size())
            .map_err(|err| Error::Overflow(format!("artifact exceeds usize: {err}")))?
            + NYDUS_BLOB_FOOTER_SIZE,
    );
    artifact.extend_from_slice(data);
    let footer =
        nydus_format::blob::finish_full_blob(&mut artifact, data.len() as u64, &[], blob_metadata)?;

    let digest = sha256_bytes(&artifact);
    Ok((artifact, digest, footer))
}
