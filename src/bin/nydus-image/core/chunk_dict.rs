// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap};
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use nydus_api::ConfigV2;
use nydus_rafs::metadata::chunk::ChunkWrapper;
use nydus_rafs::metadata::layout::v5::RafsV5ChunkInfo;
use nydus_rafs::metadata::{RafsSuper, RafsSuperConfig};
use nydus_storage::device::BlobInfo;
use nydus_utils::digest::{self, RafsDigest};

use crate::core::tree::Tree;

#[derive(Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct DigestWithBlobIndex(pub RafsDigest, pub u32);

pub trait ChunkDict: Sync + Send + 'static {
    fn add_chunk(&mut self, chunk: ChunkWrapper, digester: digest::Algorithm);
    fn get_chunk(&self, digest: &RafsDigest, uncompressed_size: u32) -> Option<&ChunkWrapper>;
    fn get_blobs(&self) -> Vec<Arc<BlobInfo>>;
    fn get_blob_by_inner_idx(&self, idx: u32) -> Option<&BlobInfo>;
    fn set_real_blob_idx(&self, inner_idx: u32, out_idx: u32);
    fn get_real_blob_idx(&self, inner_idx: u32) -> Option<u32>;
    fn digester(&self) -> digest::Algorithm;
}

impl ChunkDict for () {
    fn add_chunk(&mut self, _chunk: ChunkWrapper, _digester: digest::Algorithm) {}

    fn get_chunk(&self, _digest: &RafsDigest, _uncompressed_size: u32) -> Option<&ChunkWrapper> {
        None
    }

    fn get_blobs(&self) -> Vec<Arc<BlobInfo>> {
        Vec::new()
    }

    fn get_blob_by_inner_idx(&self, _idx: u32) -> Option<&BlobInfo> {
        None
    }

    fn set_real_blob_idx(&self, _inner_idx: u32, _out_idx: u32) {
        panic!("()::set_real_blob_idx() should not be invoked");
    }

    fn get_real_blob_idx(&self, inner_idx: u32) -> Option<u32> {
        Some(inner_idx)
    }

    fn digester(&self) -> digest::Algorithm {
        digest::Algorithm::Sha256
    }
}

pub struct HashChunkDict {
    pub m: HashMap<RafsDigest, (ChunkWrapper, AtomicU32)>,
    blobs: Vec<Arc<BlobInfo>>,
    blob_idx_m: Mutex<BTreeMap<u32, u32>>,
    digester: digest::Algorithm,
}

impl ChunkDict for HashChunkDict {
    fn add_chunk(&mut self, chunk: ChunkWrapper, digester: digest::Algorithm) {
        if self.digester == digester {
            if let Some(e) = self.m.get(chunk.id()) {
                e.1.fetch_add(1, Ordering::AcqRel);
            } else {
                self.m
                    .insert(chunk.id().to_owned(), (chunk, AtomicU32::new(1)));
            }
        }
    }

    fn get_chunk(&self, digest: &RafsDigest, uncompressed_size: u32) -> Option<&ChunkWrapper> {
        if let Some((chunk, _)) = self.m.get(digest) {
            if chunk.uncompressed_size() == 0 || chunk.uncompressed_size() == uncompressed_size {
                return Some(chunk);
            }
        }
        None
    }

    fn get_blobs(&self) -> Vec<Arc<BlobInfo>> {
        self.blobs.clone()
    }

    fn get_blob_by_inner_idx(&self, idx: u32) -> Option<&BlobInfo> {
        self.blobs.get(idx as usize).map(|b| b.as_ref())
    }

    fn set_real_blob_idx(&self, inner_idx: u32, out_idx: u32) {
        self.blob_idx_m.lock().unwrap().insert(inner_idx, out_idx);
    }

    fn get_real_blob_idx(&self, inner_idx: u32) -> Option<u32> {
        self.blob_idx_m.lock().unwrap().get(&inner_idx).copied()
    }

    fn digester(&self) -> digest::Algorithm {
        self.digester
    }
}

impl HashChunkDict {
    pub fn new(digester: digest::Algorithm) -> Self {
        HashChunkDict {
            m: Default::default(),
            blobs: vec![],
            blob_idx_m: Mutex::new(Default::default()),
            digester,
        }
    }

    fn from_bootstrap_file(
        path: &Path,
        config: Arc<ConfigV2>,
        rafs_config: &RafsSuperConfig,
    ) -> Result<Self> {
        let (rs, _) = RafsSuper::load_from_file(path, config, true, true)
            .with_context(|| format!("failed to open bootstrap file {:?}", path))?;
        let mut d = HashChunkDict {
            m: HashMap::new(),
            blobs: rs.superblock.get_blob_infos(),
            blob_idx_m: Mutex::new(BTreeMap::new()),
            digester: rafs_config.digester,
        };

        rafs_config.check_compatibility(&rs.meta)?;
        if rs.meta.is_v5() || rs.meta.has_inlined_chunk_digest() {
            Tree::from_bootstrap(&rs, &mut d).context("failed to build tree from bootstrap")?;
        } else if rs.meta.is_v6() {
            d.load_chunk_table(&rs)
                .context("failed to load chunk table")?;
        } else {
            unimplemented!()
        }

        Ok(d)
    }

    fn load_chunk_table(&mut self, rs: &RafsSuper) -> Result<()> {
        let size = rs.meta.chunk_table_size as usize;
        if size == 0 || self.digester != rs.meta.get_digester() {
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
            self.add_chunk(ChunkWrapper::from_chunk_info(chunk.as_ref()), self.digester);
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

    debug!("parse chunk dict argument {}={}", file_type, file_path);

    match file_type {
        "bootstrap" => Ok(PathBuf::from(file_path)),
        _ => bail!("invalid chunk dict type {}", file_type),
    }
}

/// Load a chunk dictionary from external source.
pub(crate) fn import_chunk_dict(
    arg: &str,
    config: Arc<ConfigV2>,
    rafs_config: &RafsSuperConfig,
) -> Result<Arc<dyn ChunkDict>> {
    let file_path = parse_chunk_dict_arg(arg)?;
    HashChunkDict::from_bootstrap_file(&file_path, config, rafs_config)
        .map(|d| Arc::new(d) as Arc<dyn ChunkDict>)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_rafs::metadata::RafsVersion;
    use nydus_utils::{compress, digest};
    use std::path::PathBuf;

    #[test]
    fn test_null_dict() {
        let mut dict = Box::new(()) as Box<dyn ChunkDict>;

        let chunk = ChunkWrapper::new(RafsVersion::V5);
        dict.add_chunk(chunk.clone(), digest::Algorithm::Sha256);
        assert!(dict.get_chunk(chunk.id(), 0).is_none());
        assert_eq!(dict.get_blobs().len(), 0);
        assert_eq!(dict.get_real_blob_idx(5).unwrap(), 5);
    }

    #[test]
    fn test_chunk_dict() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(root_dir);
        source_path.push("tests/texture/bootstrap/rafs-v5.boot");
        let path = source_path.to_str().unwrap();
        let rafs_config = RafsSuperConfig {
            version: RafsVersion::V5,
            compressor: compress::Algorithm::Lz4Block,
            digester: digest::Algorithm::Blake3,
            chunk_size: 0x100000,
            explicit_uidgid: true,
        };
        let dict = import_chunk_dict(path, Arc::new(ConfigV2::default()), &rafs_config).unwrap();

        assert!(dict.get_chunk(&RafsDigest::default(), 0).is_none());
        assert_eq!(dict.get_blobs().len(), 18);
        dict.set_real_blob_idx(0, 10);
        assert_eq!(dict.get_real_blob_idx(0), Some(10));
        assert_eq!(dict.get_real_blob_idx(1), None);
    }
}
