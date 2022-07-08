// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap};
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use nydus_utils::digest::RafsDigest;
use rafs::metadata::layout::v5::RafsV5ChunkInfo;
use rafs::metadata::RafsSuper;
use storage::device::BlobInfo;

use crate::core::node::ChunkWrapper;
use crate::core::tree::Tree;
#[derive(Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct DigestWithBlobIndex(pub RafsDigest, pub u32);

pub trait ChunkDict: Sync + Send + 'static {
    fn add_chunk(&mut self, chunk: ChunkWrapper);
    fn get_chunk(&self, digest: &RafsDigest) -> Option<&ChunkWrapper>;
    fn get_blobs(&self) -> Vec<Arc<BlobInfo>>;
    fn get_blobs_by_inner_idx(&self, idx: u32) -> Option<&BlobInfo>;
    fn set_real_blob_idx(&self, inner_idx: u32, out_idx: u32);
    fn get_real_blob_idx(&self, inner_idx: u32) -> u32;
}

impl ChunkDict for () {
    fn add_chunk(&mut self, _chunk: ChunkWrapper) {}

    fn get_chunk(&self, _digest: &RafsDigest) -> Option<&ChunkWrapper> {
        None
    }

    fn get_blobs(&self) -> Vec<Arc<BlobInfo>> {
        Vec::new()
    }

    fn get_blobs_by_inner_idx(&self, _idx: u32) -> Option<&BlobInfo> {
        None
    }

    fn set_real_blob_idx(&self, _inner_idx: u32, _out_idx: u32) {
        panic!("()::set_real_blob_idx() should not be invoked");
    }

    fn get_real_blob_idx(&self, inner_idx: u32) -> u32 {
        inner_idx
    }
}

#[derive(Default)]
pub struct HashChunkDict {
    pub m: HashMap<RafsDigest, (ChunkWrapper, AtomicU32)>,
    blobs: Vec<Arc<BlobInfo>>,
    blob_idx_m: Mutex<BTreeMap<u32, u32>>,
}

impl ChunkDict for HashChunkDict {
    fn add_chunk(&mut self, chunk: ChunkWrapper) {
        if let Some(e) = self.m.get(chunk.id()) {
            e.1.fetch_add(1, Ordering::AcqRel);
        } else {
            self.m
                .insert(chunk.id().to_owned(), (chunk, AtomicU32::new(1)));
        }
    }

    fn get_chunk(&self, digest: &RafsDigest) -> Option<&ChunkWrapper> {
        self.m.get(digest).map(|e| &e.0)
    }

    fn get_blobs(&self) -> Vec<Arc<BlobInfo>> {
        self.blobs.clone()
    }

    fn get_blobs_by_inner_idx(&self, idx: u32) -> Option<&BlobInfo> {
        self.blobs.get(idx as usize).map(|b| b.as_ref())
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
    fn from_bootstrap_file(path: &Path) -> Result<Self> {
        let rs = RafsSuper::load_chunk_dict_from_metadata(path)
            .with_context(|| format!("failed to open bootstrap file {:?}", path))?;
        let mut d = HashChunkDict {
            m: HashMap::new(),
            blobs: rs.superblock.get_blob_infos(),
            blob_idx_m: Mutex::new(BTreeMap::new()),
        };

        if rs.meta.is_v5() {
            Tree::from_bootstrap(&rs, &mut d).context("failed to build tree from bootstrap")?;
        } else if rs.meta.is_v6() {
            Self::load_chunk_table(&rs, &mut d).context("failed to load chunk table")?;
        } else {
            unimplemented!()
        }

        Ok(d)
    }

    fn load_chunk_table(rs: &RafsSuper, chunk_dict: &mut dyn ChunkDict) -> Result<()> {
        let size = rs.meta.chunk_table_size as usize;
        if size == 0 {
            return Ok(());
        }

        let unit_size = size_of::<RafsV5ChunkInfo>();
        if size % unit_size != 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL)).with_context(|| {
                format!(
                    "load_chunk_table: invalid rafs v6 chunk table size {}",
                    size
                )
            });
        }

        for idx in 0..(size / unit_size) {
            let chunk = rs.superblock.get_chunk_info(idx)?;
            chunk_dict.add_chunk(ChunkWrapper::from_chunk_info(chunk.as_ref()));
        }

        Ok(())
    }
}

/// Parse a chunk dictionary argument string.
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
pub fn parse_chunk_dict_arg(arg: &str) -> Result<PathBuf> {
    let (file_type, file_path) = match arg.find('=') {
        None => ("bootstrap", arg),
        Some(idx) => (&arg[0..idx], &arg[idx + 1..]),
    };

    info!("parse chunk dict argument {}={}", file_type, file_path);

    match file_type {
        "bootstrap" => Ok(PathBuf::from(file_path)),
        _ => {
            bail!("invalid chunk dict type {}", file_type);
        }
    }
}

/// Load a chunk dictionary from external source.
pub(crate) fn import_chunk_dict(arg: &str) -> Result<Arc<dyn ChunkDict>> {
    let file_path = parse_chunk_dict_arg(arg)?;
    HashChunkDict::from_bootstrap_file(&file_path).map(|d| Arc::new(d) as Arc<dyn ChunkDict>)
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
        assert_eq!(dict.get_blobs().len(), 0);
        assert_eq!(dict.get_real_blob_idx(5), 5);
    }

    #[test]
    fn test_chunk_dict() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(root_dir);
        source_path.push("tests/texture/bootstrap/image_v2.boot");
        let path = source_path.to_str().unwrap();
        let dict = import_chunk_dict(path).unwrap();

        assert!(dict.get_chunk(&RafsDigest::default()).is_none());
        assert_eq!(dict.get_blobs().len(), 18);
        dict.set_real_blob_idx(0, 10);
        assert_eq!(dict.get_real_blob_idx(0), 10);
        assert_eq!(dict.get_real_blob_idx(1), 1);
    }
}
