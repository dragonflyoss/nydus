// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap};
use std::fs::OpenOptions;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use nydus_utils::digest::RafsDigest;
use rafs::metadata::layout::v5::{RafsV5BlobTable, RafsV5ChunkInfo};
use rafs::metadata::{RafsMode, RafsSuper};

use crate::core::node::ChunkWrapper;
use crate::core::tree::Tree;

pub trait ChunkDict: Sync + Send + 'static {
    fn add_chunk(&mut self, chunk: ChunkWrapper);
    fn get_chunk(&self, digest: &RafsDigest) -> Option<&ChunkWrapper>;
    fn get_blobs(&self) -> Arc<RafsV5BlobTable>;
    fn set_real_blob_idx(&self, inner_idx: u32, out_idx: u32);
    fn get_real_blob_idx(&self, inner_idx: u32) -> u32;
}

impl ChunkDict for () {
    fn add_chunk(&mut self, _chunk: ChunkWrapper) {}

    fn get_chunk(&self, _digest: &RafsDigest) -> Option<&ChunkWrapper> {
        None
    }
}

#[derive(Default)]
pub struct HashChunkDict {
    m: HashMap<RafsDigest, ChunkWrapper>,
    blobs: Arc<RafsV5BlobTable>,
    blob_idx_m: Mutex<BTreeMap<u32, u32>>,
}

impl ChunkDict for HashChunkDict {
    fn add_chunk(&mut self, chunk: ChunkWrapper) {
        self.m.insert(chunk.id().to_owned(), chunk);
    }

    fn get_chunk(&self, digest: &RafsDigest) -> Option<&ChunkWrapper> {
        self.m.get(digest)
    }

    fn get_blobs(&self) -> Arc<RafsV5BlobTable> {
        self.blobs.clone()
    }

    fn set_real_blob_idx(&self, inner_idx: u32, out_idx: u32) {
        self.blob_idx_m.lock().unwrap().insert(inner_idx, out_idx);
    }

    fn get_real_blob_idx(&self, inner_idx: u32) -> u32 {
        *self
            .blob_idx_m
            .lock()
            .unwrap()
            .get(&inner_idx)
            .unwrap_or(&inner_idx)
    }
}

impl HashChunkDict {
    fn from_bootstrap_file(path: &str) -> Result<Self> {
        let rs = RafsSuper::load_from_metadata(path, RafsMode::Direct, true)
            .with_context(|| format!("failed to open bootstrap file {:?}", path))?;
        let mut d = HashChunkDict {
            m: HashMap::new(),
            blobs: rs.superblock.get_blob_table(),
            blob_idx_m: Mutex::new(BTreeMap::new()),
        };

        Tree::from_bootstrap(&rs, &mut d).context("failed to build tree from bootstrap")?;

        Ok(d)
    }
}

/// Load a chunk dictionary from external source.
///
/// # Argument
/// `arg` may be in inform of:
/// - type=path: type of external source and corresponding path
/// - path: type default to "bootstrap"
///
/// for example:
///     bootstrap=image.boot
///     image.boot
///     ~/image/image.boot
///     boltdb=/var/db/dict.db (not supported yet)
pub(crate) fn import_chunk_dict(arg: &str) -> Result<Arc<dyn ChunkDict>> {
    let (file_type, file_path) = match arg.find('=') {
        None => ("bootstrap", arg),
        Some(idx) => (&arg[0..idx], &arg[idx + 1..]),
    };

    info!("import chunk dict file {}={}", file_type, file_path);
    match file_type {
        "bootstrap" => {
            HashChunkDict::from_bootstrap_file(file_path).map(|d| Arc::new(d) as Arc<dyn ChunkDict>)
        }
        _ => Err(std::io::Error::from_raw_os_error(libc::EINVAL))
            .with_context(|| format!("invalid chunk dict type {}", file_type)),
    }
}

<<<<<<< HEAD
impl BootstrapChunkDict {
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::RafsVersion;
    use std::path::PathBuf;

    #[test]
    fn test_null_dict() {
        let mut dict = Box::new(()) as Box<dyn ChunkDict>;

        let chunk = ChunkWrapper::new(RafsVersion::V5);
        dict.add_chunk(chunk.clone());
        assert!(dict.get_chunk(chunk.id()).is_none());
    }

    #[test]
    fn test_chunk_dict() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(root_dir);
        source_path.push("tests/texture/bootstrap/image_v2.boot");
        let path = source_path.to_str().unwrap();
        let dict = import_chunk_dict(path).unwrap();

        assert!(dict.get_chunk(&RafsDigest::default()).is_none());
    }
}
