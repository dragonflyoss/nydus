// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap};
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use nydus_api::ConfigV2;
use nydus_rafs::metadata::chunk::ChunkWrapper;
use nydus_rafs::metadata::layout::v5::RafsV5ChunkInfo;
use nydus_rafs::metadata::{RafsSuper, RafsSuperConfig};
use nydus_storage::device::BlobInfo;
use nydus_utils::digest::{self, RafsDigest};

use crate::Tree;

#[derive(Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct DigestWithBlobIndex(pub RafsDigest, pub u32, pub Option<u32>);

/// Trait to manage chunk cache for chunk deduplication.
pub trait ChunkDict: Sync + Send + 'static {
    /// Add a chunk into the cache.
    fn add_chunk(&mut self, chunk: Arc<ChunkWrapper>, digester: digest::Algorithm);

    /// Get a cached chunk from the cache.
    fn get_chunk(&self, digest: &RafsDigest, uncompressed_size: u32) -> Option<&Arc<ChunkWrapper>>;

    /// Get all `BlobInfo` objects referenced by cached chunks.
    fn get_blobs(&self) -> Vec<Arc<BlobInfo>>;

    /// Get the `BlobInfo` object with inner index `idx`.
    fn get_blob_by_inner_idx(&self, idx: u32) -> Option<&Arc<BlobInfo>>;

    /// Associate an external index with the inner index.
    fn set_real_blob_idx(&self, inner_idx: u32, out_idx: u32);

    /// Get the external index associated with an inner index.
    fn get_real_blob_idx(&self, inner_idx: u32) -> Option<u32>;

    /// Get the digest algorithm used to generate chunk digest.
    fn digester(&self) -> digest::Algorithm;
}

impl ChunkDict for () {
    fn add_chunk(&mut self, _chunk: Arc<ChunkWrapper>, _digester: digest::Algorithm) {}

    fn get_chunk(
        &self,
        _digest: &RafsDigest,
        _uncompressed_size: u32,
    ) -> Option<&Arc<ChunkWrapper>> {
        None
    }

    fn get_blobs(&self) -> Vec<Arc<BlobInfo>> {
        Vec::new()
    }

    fn get_blob_by_inner_idx(&self, _idx: u32) -> Option<&Arc<BlobInfo>> {
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

/// An implementation of [ChunkDict] based on [HashMap].
pub struct HashChunkDict {
    m: HashMap<RafsDigest, (Arc<ChunkWrapper>, AtomicU32)>,
    blobs: Vec<Arc<BlobInfo>>,
    blob_idx_m: Mutex<BTreeMap<u32, u32>>,
    digester: digest::Algorithm,
}

impl ChunkDict for HashChunkDict {
    fn add_chunk(&mut self, chunk: Arc<ChunkWrapper>, digester: digest::Algorithm) {
        if self.digester == digester {
            if let Some(e) = self.m.get(chunk.id()) {
                e.1.fetch_add(1, Ordering::AcqRel);
            } else {
                self.m
                    .insert(chunk.id().to_owned(), (chunk, AtomicU32::new(1)));
            }
        }
    }

    fn get_chunk(&self, digest: &RafsDigest, uncompressed_size: u32) -> Option<&Arc<ChunkWrapper>> {
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

    fn get_blob_by_inner_idx(&self, idx: u32) -> Option<&Arc<BlobInfo>> {
        self.blobs.get(idx as usize)
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
    /// Create a new instance of [HashChunkDict].
    pub fn new(digester: digest::Algorithm) -> Self {
        HashChunkDict {
            m: Default::default(),
            blobs: vec![],
            blob_idx_m: Mutex::new(Default::default()),
            digester,
        }
    }

    /// Get an immutable reference to the internal `HashMap`.
    pub fn hashmap(&self) -> &HashMap<RafsDigest, (Arc<ChunkWrapper>, AtomicU32)> {
        &self.m
    }

    /// Parse commandline argument for chunk dictionary and load chunks into the dictionary.
    pub fn from_commandline_arg(
        arg: &str,
        config: Arc<ConfigV2>,
        rafs_config: &RafsSuperConfig,
    ) -> Result<Arc<dyn ChunkDict>> {
        let file_path = parse_chunk_dict_arg(arg)?;
        HashChunkDict::from_bootstrap_file(&file_path, config, rafs_config)
            .map(|d| Arc::new(d) as Arc<dyn ChunkDict>)
    }

    /// Load chunks from the RAFS filesystem into the chunk dictionary.
    pub fn from_bootstrap_file(
        path: &Path,
        config: Arc<ConfigV2>,
        rafs_config: &RafsSuperConfig,
    ) -> Result<Self> {
        let (rs, _) = RafsSuper::load_from_file(path, config, true)
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
            let chunk_info = Arc::new(ChunkWrapper::from_chunk_info(chunk));
            self.add_chunk(chunk_info, self.digester);
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

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_rafs::metadata::RafsVersion;
    use nydus_utils::{compress, digest};
    use std::path::PathBuf;

    #[test]
    fn test_null_dict() {
        let mut dict = Box::new(()) as Box<dyn ChunkDict>;

        let chunk = Arc::new(ChunkWrapper::new(RafsVersion::V5));
        dict.add_chunk(chunk.clone(), digest::Algorithm::Sha256);
        assert!(dict.get_chunk(chunk.id(), 0).is_none());
        assert_eq!(dict.get_blobs().len(), 0);
        assert_eq!(dict.get_real_blob_idx(5).unwrap(), 5);
    }

    #[test]
    fn test_chunk_dict() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/bootstrap/rafs-v5.boot");
        let path = source_path.to_str().unwrap();
        let rafs_config = RafsSuperConfig {
            version: RafsVersion::V5,
            compressor: compress::Algorithm::Lz4Block,
            digester: digest::Algorithm::Blake3,
            chunk_size: 0x100000,
            batch_size: 0,
            explicit_uidgid: true,
            is_tarfs_mode: false,
        };
        let dict =
            HashChunkDict::from_commandline_arg(path, Arc::new(ConfigV2::default()), &rafs_config)
                .unwrap();

        assert!(dict.get_chunk(&RafsDigest::default(), 0).is_none());
        assert_eq!(dict.get_blobs().len(), 18);
        dict.set_real_blob_idx(0, 10);
        assert_eq!(dict.get_real_blob_idx(0), Some(10));
        assert_eq!(dict.get_real_blob_idx(1), None);
    }

    #[test]
    fn test_parse_chunk_dict_arg() {
        // Test with bootstrap type
        let result = parse_chunk_dict_arg("bootstrap=/path/to/file").unwrap();
        assert_eq!(result, PathBuf::from("/path/to/file"));

        // Test without type prefix (defaults to bootstrap)
        let result = parse_chunk_dict_arg("/path/to/file").unwrap();
        assert_eq!(result, PathBuf::from("/path/to/file"));

        // Test with relative path
        let result = parse_chunk_dict_arg("~/image/image.boot").unwrap();
        assert_eq!(result, PathBuf::from("~/image/image.boot"));

        // Test with invalid type
        let result = parse_chunk_dict_arg("boltdb=/var/db/dict.db");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid chunk dict type"));
    }

    #[test]
    fn test_hash_chunk_dict_new() {
        let dict = HashChunkDict::new(digest::Algorithm::Blake3);
        assert_eq!(dict.digester(), digest::Algorithm::Blake3);
        assert!(dict.hashmap().is_empty());
        assert_eq!(dict.get_blobs().len(), 0);
    }

    #[test]
    fn test_hash_chunk_dict_add_chunk() {
        let mut dict = HashChunkDict::new(digest::Algorithm::Sha256);
        let chunk1 = Arc::new(ChunkWrapper::new(RafsVersion::V5));

        // Add chunk first time
        dict.add_chunk(chunk1.clone(), digest::Algorithm::Sha256);
        assert_eq!(dict.hashmap().len(), 1);
        assert_eq!(
            dict.hashmap()
                .get(chunk1.id())
                .unwrap()
                .1
                .load(Ordering::Acquire),
            1
        );

        // Add same chunk again (should increment counter)
        dict.add_chunk(chunk1.clone(), digest::Algorithm::Sha256);
        assert_eq!(dict.hashmap().len(), 1);
        assert_eq!(
            dict.hashmap()
                .get(chunk1.id())
                .unwrap()
                .1
                .load(Ordering::Acquire),
            2
        );

        // Add chunk with different digester (should be ignored)
        let chunk2 = Arc::new(ChunkWrapper::new(RafsVersion::V5));
        dict.add_chunk(chunk2.clone(), digest::Algorithm::Blake3);
        assert_eq!(dict.hashmap().len(), 1);
    }

    #[test]
    fn test_hash_chunk_dict_get_chunk() {
        let mut dict = HashChunkDict::new(digest::Algorithm::Sha256);
        let chunk = Arc::new(ChunkWrapper::new(RafsVersion::V5));

        // Chunk not in dict
        assert!(dict.get_chunk(chunk.id(), 0).is_none());

        // Add chunk and retrieve it
        dict.add_chunk(chunk.clone(), digest::Algorithm::Sha256);
        assert!(dict.get_chunk(chunk.id(), 0).is_some());
        assert!(dict
            .get_chunk(chunk.id(), chunk.uncompressed_size())
            .is_some());
    }

    #[test]
    fn test_hash_chunk_dict_blob_management() {
        let dict = HashChunkDict::new(digest::Algorithm::Sha256);

        // No blobs initially
        assert_eq!(dict.get_blobs().len(), 0);
        assert!(dict.get_blob_by_inner_idx(0).is_none());

        // Test blob index mapping
        dict.set_real_blob_idx(0, 5);
        assert_eq!(dict.get_real_blob_idx(0), Some(5));

        dict.set_real_blob_idx(1, 10);
        assert_eq!(dict.get_real_blob_idx(1), Some(10));

        // Non-existent mapping
        assert_eq!(dict.get_real_blob_idx(99), None);
    }

    #[test]
    fn test_null_dict_digester() {
        let dict = Box::new(()) as Box<dyn ChunkDict>;
        assert_eq!(dict.digester(), digest::Algorithm::Sha256);
    }

    #[test]
    fn test_digest_with_blob_index() {
        let digest = RafsDigest::default();
        let d1 = DigestWithBlobIndex(digest, 0, None);
        let d2 = DigestWithBlobIndex(digest, 1, None);
        let d3 = DigestWithBlobIndex(digest, 0, Some(5));

        // Test ordering and equality
        assert_ne!(d1, d2);
        assert_ne!(d1, d3);
        assert!(d1 != d2); // They should be ordered differently
    }
}
