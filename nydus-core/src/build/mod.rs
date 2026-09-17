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

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use nydus_error::Result;
use nydus_format::blob::{BlobMetadata, NYDUS_BLOB_METADATA_SUFFIX};
use nydus_format::erofs::EROFS_BLOB_ID_SIZE;
use sha2::{Digest, Sha256};

/// A writer that hashes every byte it forwards when a hasher is supplied.
pub struct HashingWriter<W> {
    inner: W,
    hasher: Option<Sha256>,
}

impl<W: Write> HashingWriter<W> {
    pub fn new(inner: W, hasher: Option<Sha256>) -> Self {
        Self { inner, hasher }
    }

    pub fn finish(mut self) -> io::Result<Option<[u8; EROFS_BLOB_ID_SIZE]>> {
        self.inner.flush()?;
        Ok(self.hasher.map(|hasher| {
            let mut digest = [0u8; EROFS_BLOB_ID_SIZE];
            digest.copy_from_slice(&hasher.finalize());
            digest
        }))
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        if let Some(hasher) = self.hasher.as_mut() {
            hasher.update(&buf[..written]);
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
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
