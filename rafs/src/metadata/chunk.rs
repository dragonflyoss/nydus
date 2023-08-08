// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021-2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{self, Debug, Display, Formatter};
use std::ops::Deref;
use std::sync::Arc;

use anyhow::{Context, Result};
use nydus_storage::device::v5::BlobV5ChunkInfo;
use nydus_storage::device::{BlobChunkFlags, BlobChunkInfo};
use nydus_storage::meta::BlobMetaChunk;
use nydus_utils::digest::RafsDigest;
use serde::{Deserialize, Serialize};

use crate::metadata::cached_v5::CachedChunkInfoV5;
use crate::metadata::direct_v5::DirectChunkInfoV5;
use crate::metadata::direct_v6::{DirectChunkInfoV6, TarfsChunkInfoV6};
use crate::metadata::layout::v5::RafsV5ChunkInfo;
use crate::metadata::{RafsStore, RafsVersion};
use crate::RafsIoWrite;

/// A wrapper to encapsulate different versions of chunk information objects.
#[derive(Clone, Deserialize, Serialize)]
pub enum ChunkWrapper {
    /// Chunk info for RAFS v5.
    V5(RafsV5ChunkInfo),
    /// Chunk info RAFS v6, reuse `RafsV5ChunkInfo` as IR for v6.
    V6(RafsV5ChunkInfo),
    /// Reference to a `BlobChunkInfo` object.
    #[serde(skip_deserializing, skip_serializing)]
    Ref(Arc<dyn BlobChunkInfo>),
}

impl Debug for ChunkWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::V5(c) => write!(f, "{:?}", c),
            Self::V6(c) => write!(f, "{:?}", c),
            Self::Ref(c) => {
                let chunk = to_rafs_v5_chunk_info(as_blob_v5_chunk_info(c.deref()));
                write!(f, "{:?}", chunk)
            }
        }
    }
}

impl Display for ChunkWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "id {}, index {}, blob_index {}, file_offset {}, compressed {}/{}, uncompressed {}/{}",
            self.id(),
            self.index(),
            self.blob_index(),
            self.file_offset(),
            self.compressed_offset(),
            self.compressed_size(),
            self.uncompressed_offset(),
            self.uncompressed_size(),
        )
    }
}

impl ChunkWrapper {
    /// Create a new `ChunkWrapper` object with default value.
    pub fn new(version: RafsVersion) -> Self {
        match version {
            RafsVersion::V5 => ChunkWrapper::V5(RafsV5ChunkInfo::default()),
            RafsVersion::V6 => ChunkWrapper::V6(RafsV5ChunkInfo::default()),
        }
    }

    /// Create a `ChunkWrapper` object from a `BlobChunkInfo` trait object.
    pub fn from_chunk_info(cki: Arc<dyn BlobChunkInfo>) -> Self {
        Self::Ref(cki)
    }

    /// Get digest of chunk data, which is also used as chunk ID.
    pub fn id(&self) -> &RafsDigest {
        match self {
            ChunkWrapper::V5(c) => &c.block_id,
            ChunkWrapper::V6(c) => &c.block_id,
            ChunkWrapper::Ref(c) => c.chunk_id(),
        }
    }

    /// Set digest of chunk data, which is also used as chunk ID.
    pub fn set_id(&mut self, id: RafsDigest) {
        self.ensure_owned();
        match self {
            ChunkWrapper::V5(c) => c.block_id = id,
            ChunkWrapper::V6(c) => c.block_id = id,
            ChunkWrapper::Ref(_c) => panic!("unexpected"),
        }
    }

    /// Get index of the data blob associated with the chunk.
    pub fn blob_index(&self) -> u32 {
        match self {
            ChunkWrapper::V5(c) => c.blob_index,
            ChunkWrapper::V6(c) => c.blob_index,
            ChunkWrapper::Ref(c) => c.blob_index(),
        }
    }

    /// Set index of the data blob associated with the chunk.
    pub fn set_blob_index(&mut self, index: u32) {
        self.ensure_owned();
        match self {
            ChunkWrapper::V5(c) => c.blob_index = index,
            ChunkWrapper::V6(c) => c.blob_index = index,
            ChunkWrapper::Ref(_c) => panic!("unexpected"),
        }
    }

    /// Get offset into the compressed data blob to fetch chunk data.
    pub fn compressed_offset(&self) -> u64 {
        match self {
            ChunkWrapper::V5(c) => c.compressed_offset,
            ChunkWrapper::V6(c) => c.compressed_offset,
            ChunkWrapper::Ref(c) => c.compressed_offset(),
        }
    }

    /// Set offset into the compressed data blob to fetch chunk data.
    pub fn set_compressed_offset(&mut self, offset: u64) {
        self.ensure_owned();
        match self {
            ChunkWrapper::V5(c) => c.compressed_offset = offset,
            ChunkWrapper::V6(c) => c.compressed_offset = offset,
            ChunkWrapper::Ref(_c) => panic!("unexpected"),
        }
    }

    /// Get size of compressed chunk data.
    pub fn compressed_size(&self) -> u32 {
        match self {
            ChunkWrapper::V5(c) => c.compressed_size,
            ChunkWrapper::V6(c) => c.compressed_size,
            ChunkWrapper::Ref(c) => c.compressed_size(),
        }
    }

    /// Set size of compressed chunk data.
    pub fn set_compressed_size(&mut self, size: u32) {
        self.ensure_owned();
        match self {
            ChunkWrapper::V5(c) => c.compressed_size = size,
            ChunkWrapper::V6(c) => c.compressed_size = size,
            ChunkWrapper::Ref(_c) => panic!("unexpected"),
        }
    }

    /// Get offset into the uncompressed data blob file to get chunk data.
    pub fn uncompressed_offset(&self) -> u64 {
        match self {
            ChunkWrapper::V5(c) => c.uncompressed_offset,
            ChunkWrapper::V6(c) => c.uncompressed_offset,
            ChunkWrapper::Ref(c) => c.uncompressed_offset(),
        }
    }

    /// Set offset into the uncompressed data blob file to get chunk data.
    pub fn set_uncompressed_offset(&mut self, offset: u64) {
        self.ensure_owned();
        match self {
            ChunkWrapper::V5(c) => c.uncompressed_offset = offset,
            ChunkWrapper::V6(c) => c.uncompressed_offset = offset,
            ChunkWrapper::Ref(_c) => panic!("unexpected"),
        }
    }

    /// Get size of uncompressed chunk data.
    pub fn uncompressed_size(&self) -> u32 {
        match self {
            ChunkWrapper::V5(c) => c.uncompressed_size,
            ChunkWrapper::V6(c) => c.uncompressed_size,
            ChunkWrapper::Ref(c) => c.uncompressed_size(),
        }
    }

    /// Set size of uncompressed chunk data.
    pub fn set_uncompressed_size(&mut self, size: u32) {
        self.ensure_owned();
        match self {
            ChunkWrapper::V5(c) => c.uncompressed_size = size,
            ChunkWrapper::V6(c) => c.uncompressed_size = size,
            ChunkWrapper::Ref(_c) => panic!("unexpected"),
        }
    }

    /// Get chunk index into the RAFS chunk information array, used by RAFS v5.
    pub fn index(&self) -> u32 {
        match self {
            ChunkWrapper::V5(c) => c.index,
            ChunkWrapper::V6(c) => c.index,
            ChunkWrapper::Ref(c) => as_blob_v5_chunk_info(c.deref()).index(),
        }
    }

    /// Set chunk index into the RAFS chunk information array, used by RAFS v5.
    pub fn set_index(&mut self, index: u32) {
        self.ensure_owned();
        match self {
            ChunkWrapper::V5(c) => c.index = index,
            ChunkWrapper::V6(c) => c.index = index,
            ChunkWrapper::Ref(_c) => panic!("unexpected"),
        }
    }

    /// Get chunk offset in the file it belongs to, RAFS v5.
    pub fn file_offset(&self) -> u64 {
        match self {
            ChunkWrapper::V5(c) => c.file_offset,
            ChunkWrapper::V6(c) => c.file_offset,
            ChunkWrapper::Ref(c) => as_blob_v5_chunk_info(c.deref()).file_offset(),
        }
    }

    /// Set chunk offset in the file it belongs to, RAFS v5.
    pub fn set_file_offset(&mut self, offset: u64) {
        self.ensure_owned();
        match self {
            ChunkWrapper::V5(c) => c.file_offset = offset,
            ChunkWrapper::V6(c) => c.file_offset = offset,
            ChunkWrapper::Ref(_c) => panic!("unexpected"),
        }
    }

    /// Check whether the chunk is compressed or not.
    pub fn is_compressed(&self) -> bool {
        match self {
            ChunkWrapper::V5(c) => c.flags.contains(BlobChunkFlags::COMPRESSED),
            ChunkWrapper::V6(c) => c.flags.contains(BlobChunkFlags::COMPRESSED),
            ChunkWrapper::Ref(c) => as_blob_v5_chunk_info(c.deref())
                .flags()
                .contains(BlobChunkFlags::COMPRESSED),
        }
    }

    /// Set flag for whether chunk is compressed.
    pub fn set_compressed(&mut self, compressed: bool) {
        self.ensure_owned();
        match self {
            ChunkWrapper::V5(c) => c.flags.set(BlobChunkFlags::COMPRESSED, compressed),
            ChunkWrapper::V6(c) => c.flags.set(BlobChunkFlags::COMPRESSED, compressed),
            ChunkWrapper::Ref(_c) => panic!("unexpected"),
        }
    }

    /// Check whether the chunk is encrypted or not.
    pub fn is_encrypted(&self) -> bool {
        match self {
            ChunkWrapper::V5(c) => c.flags.contains(BlobChunkFlags::ENCYPTED),
            ChunkWrapper::V6(c) => c.flags.contains(BlobChunkFlags::ENCYPTED),
            ChunkWrapper::Ref(c) => as_blob_v5_chunk_info(c.deref())
                .flags()
                .contains(BlobChunkFlags::ENCYPTED),
        }
    }

    /// Check whether the chunk is deduped or not.
    pub fn is_deduped(&self) -> bool {
        match self {
            ChunkWrapper::V5(c) => c.flags.contains(BlobChunkFlags::DEDUPED),
            ChunkWrapper::V6(c) => c.flags.contains(BlobChunkFlags::DEDUPED),
            ChunkWrapper::Ref(c) => as_blob_v5_chunk_info(c.deref())
                .flags()
                .contains(BlobChunkFlags::DEDUPED),
        }
    }

    /// Set flag for whether chunk is deduped.
    pub fn set_deduped(&mut self, deduped: bool) {
        self.ensure_owned();
        match self {
            ChunkWrapper::V5(c) => c.flags.set(BlobChunkFlags::DEDUPED, deduped),
            ChunkWrapper::V6(c) => c.flags.set(BlobChunkFlags::DEDUPED, deduped),
            ChunkWrapper::Ref(_c) => panic!("unexpected"),
        }
    }

    /// Set flag for whether chunk is encrypted.
    pub fn set_encrypted(&mut self, encrypted: bool) {
        self.ensure_owned();
        match self {
            ChunkWrapper::V5(c) => c.flags.set(BlobChunkFlags::ENCYPTED, encrypted),
            ChunkWrapper::V6(c) => c.flags.set(BlobChunkFlags::ENCYPTED, encrypted),
            ChunkWrapper::Ref(_c) => panic!("unexpected"),
        }
    }

    /// Set flag for whether chunk is batch chunk.
    pub fn set_batch(&mut self, batch: bool) {
        self.ensure_owned();
        match self {
            ChunkWrapper::V5(c) => c.flags.set(BlobChunkFlags::BATCH, batch),
            ChunkWrapper::V6(c) => c.flags.set(BlobChunkFlags::BATCH, batch),
            ChunkWrapper::Ref(_c) => panic!("unexpected"),
        }
    }

    /// Check whether the chunk is batch chunk or not.
    pub fn is_batch(&self) -> bool {
        match self {
            ChunkWrapper::V5(c) => c.flags.contains(BlobChunkFlags::BATCH),
            ChunkWrapper::V6(c) => c.flags.contains(BlobChunkFlags::BATCH),
            ChunkWrapper::Ref(c) => as_blob_v5_chunk_info(c.deref())
                .flags()
                .contains(BlobChunkFlags::BATCH),
        }
    }

    #[allow(clippy::too_many_arguments)]
    /// Set a group of chunk information fields.
    pub fn set_chunk_info(
        &mut self,
        blob_index: u32,
        chunk_index: u32,
        file_offset: u64,
        uncompressed_offset: u64,
        uncompressed_size: u32,
        compressed_offset: u64,
        compressed_size: u32,
        is_compressed: bool,
        is_encrypted: bool,
    ) -> Result<()> {
        self.ensure_owned();
        match self {
            ChunkWrapper::V5(c) => {
                c.index = chunk_index;
                c.blob_index = blob_index;
                c.file_offset = file_offset;
                c.compressed_offset = compressed_offset;
                c.compressed_size = compressed_size;
                c.uncompressed_offset = uncompressed_offset;
                c.uncompressed_size = uncompressed_size;
                if is_compressed {
                    c.flags |= BlobChunkFlags::COMPRESSED;
                }
            }
            ChunkWrapper::V6(c) => {
                c.index = chunk_index;
                c.blob_index = blob_index;
                c.file_offset = file_offset;
                c.compressed_offset = compressed_offset;
                c.compressed_size = compressed_size;
                c.uncompressed_offset = uncompressed_offset;
                c.uncompressed_size = uncompressed_size;
                if is_compressed {
                    c.flags |= BlobChunkFlags::COMPRESSED;
                }
                if is_encrypted {
                    c.flags |= BlobChunkFlags::ENCYPTED;
                }
            }
            ChunkWrapper::Ref(_c) => panic!("unexpected"),
        }

        Ok(())
    }

    /// Copy chunk information from another `ChunkWrapper` object.
    pub fn copy_from(&mut self, other: &Self) {
        self.ensure_owned();
        match (self, other) {
            (ChunkWrapper::V5(s), ChunkWrapper::V5(o)) => s.clone_from(o),
            (ChunkWrapper::V6(s), ChunkWrapper::V6(o)) => s.clone_from(o),
            (ChunkWrapper::V5(s), ChunkWrapper::V6(o)) => s.clone_from(o),
            (ChunkWrapper::V6(s), ChunkWrapper::V5(o)) => s.clone_from(o),
            (ChunkWrapper::V5(s), ChunkWrapper::Ref(o)) => {
                s.clone_from(&to_rafs_v5_chunk_info(as_blob_v5_chunk_info(o.deref())))
            }
            (ChunkWrapper::V6(s), ChunkWrapper::Ref(o)) => {
                s.clone_from(&to_rafs_v5_chunk_info(as_blob_v5_chunk_info(o.deref())))
            }
            (ChunkWrapper::Ref(_s), ChunkWrapper::V5(_o)) => panic!("unexpected"),
            (ChunkWrapper::Ref(_s), ChunkWrapper::V6(_o)) => panic!("unexpected"),
            (ChunkWrapper::Ref(_s), ChunkWrapper::Ref(_o)) => panic!("unexpected"),
        }
    }

    /// Store the chunk information object into RAFS metadata blob.
    pub fn store(&self, w: &mut dyn RafsIoWrite) -> Result<usize> {
        match self {
            ChunkWrapper::V5(c) => c.store(w).context("failed to store rafs v5 chunk"),
            ChunkWrapper::V6(c) => c.store(w).context("failed to store rafs v6 chunk"),
            ChunkWrapper::Ref(c) => {
                let chunk = to_rafs_v5_chunk_info(as_blob_v5_chunk_info(c.deref()));
                chunk.store(w).context("failed to store rafs v6 chunk")
            }
        }
    }

    fn ensure_owned(&mut self) {
        if let Self::Ref(cki) = self {
            if let Some(cki_v6) = cki.as_any().downcast_ref::<BlobMetaChunk>() {
                *self = Self::V6(to_rafs_v5_chunk_info(cki_v6));
            } else if let Some(cki_v6) = cki.as_any().downcast_ref::<DirectChunkInfoV6>() {
                *self = Self::V6(to_rafs_v5_chunk_info(cki_v6));
            } else if let Some(cki_v6) = cki.as_any().downcast_ref::<TarfsChunkInfoV6>() {
                *self = Self::V6(to_rafs_v5_chunk_info(cki_v6));
            } else if let Some(cki_v5) = cki.as_any().downcast_ref::<CachedChunkInfoV5>() {
                *self = Self::V5(to_rafs_v5_chunk_info(cki_v5));
            } else if let Some(cki_v5) = cki.as_any().downcast_ref::<DirectChunkInfoV5>() {
                *self = Self::V5(to_rafs_v5_chunk_info(cki_v5));
            } else {
                panic!("unknown chunk information struct");
            }
        }
    }
}

fn as_blob_v5_chunk_info(cki: &dyn BlobChunkInfo) -> &dyn BlobV5ChunkInfo {
    if let Some(cki_v6) = cki.as_any().downcast_ref::<BlobMetaChunk>() {
        cki_v6
    } else if let Some(cki_v6) = cki.as_any().downcast_ref::<DirectChunkInfoV6>() {
        cki_v6
    } else if let Some(cki_v6) = cki.as_any().downcast_ref::<TarfsChunkInfoV6>() {
        cki_v6
    } else if let Some(cki_v5) = cki.as_any().downcast_ref::<CachedChunkInfoV5>() {
        cki_v5
    } else if let Some(cki_v5) = cki.as_any().downcast_ref::<DirectChunkInfoV5>() {
        cki_v5
    } else {
        panic!("unknown chunk information struct");
    }
}

/// Construct a `RafsV5ChunkInfo` object from a `dyn BlobChunkInfo` object.
fn to_rafs_v5_chunk_info(cki: &dyn BlobV5ChunkInfo) -> RafsV5ChunkInfo {
    RafsV5ChunkInfo {
        block_id: *cki.chunk_id(),
        blob_index: cki.blob_index(),
        flags: cki.flags(),
        compressed_size: cki.compressed_size(),
        uncompressed_size: cki.uncompressed_size(),
        compressed_offset: cki.compressed_offset(),
        uncompressed_offset: cki.uncompressed_offset(),
        file_offset: cki.file_offset(),
        index: cki.index(),
        reserved: 0u32,
    }
}

pub fn convert_ref_to_rafs_v5_chunk_info(cki: &dyn BlobChunkInfo) -> RafsV5ChunkInfo {
    let chunk = to_rafs_v5_chunk_info(as_blob_v5_chunk_info(cki.deref()));
    chunk
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockChunkInfo;
    use nydus_utils::digest;

    fn test_chunk_wrapper(mut wrapper: ChunkWrapper) {
        let dig = RafsDigest::from_buf([0xc; 32].as_slice(), digest::Algorithm::Blake3);
        wrapper.set_id(dig);
        assert_eq!(wrapper.id().to_owned(), dig);
        wrapper.set_blob_index(1024);
        assert_eq!(wrapper.blob_index(), 1024);
        wrapper.set_compressed_offset(1024);
        assert_eq!(wrapper.compressed_offset(), 1024);
        wrapper.set_compressed_size(1024);
        assert_eq!(wrapper.compressed_size(), 1024);
        wrapper.set_uncompressed_offset(1024);
        assert_eq!(wrapper.uncompressed_offset(), 1024);
        wrapper.set_uncompressed_size(1024);
        assert_eq!(wrapper.uncompressed_size(), 1024);
        wrapper.set_index(1024);
        assert_eq!(wrapper.index(), 1024);
        wrapper.set_file_offset(1024);
        assert_eq!(wrapper.file_offset(), 1024);
        wrapper.set_compressed(true);
        assert!(wrapper.is_compressed());
        wrapper.set_batch(true);
        assert!(wrapper.is_batch());
        wrapper
            .set_chunk_info(2048, 2048, 2048, 2048, 2048, 2048, 2048, true, true)
            .unwrap();
        assert_eq!(wrapper.blob_index(), 2048);
        assert_eq!(wrapper.compressed_offset(), 2048);
        assert_eq!(wrapper.compressed_size(), 2048);
        assert_eq!(wrapper.uncompressed_offset(), 2048);
        assert_eq!(wrapper.uncompressed_size(), 2048);
        assert_eq!(wrapper.file_offset(), 2048);
        assert!(wrapper.is_compressed());
    }

    #[test]
    fn test_chunk_wrapper_v5() {
        let wrapper = ChunkWrapper::new(RafsVersion::V5);
        test_chunk_wrapper(wrapper);
        let wrapper = ChunkWrapper::Ref(Arc::new(CachedChunkInfoV5::default()));
        test_chunk_wrapper(wrapper);
    }

    #[test]
    fn test_chunk_wrapper_v6() {
        let wrapper = ChunkWrapper::new(RafsVersion::V6);
        test_chunk_wrapper(wrapper);
        let wrapper = ChunkWrapper::Ref(Arc::new(TarfsChunkInfoV6::new(0, 0, 0, 0)));
        test_chunk_wrapper(wrapper);
    }

    #[test]
    #[should_panic]
    fn test_chunk_wrapper_ref() {
        let wrapper = ChunkWrapper::Ref(Arc::new(MockChunkInfo::default()));
        assert_eq!(wrapper.id().to_owned(), RafsDigest::default());
        assert_eq!(wrapper.blob_index(), 0);
        assert_eq!(wrapper.compressed_offset(), 0);
        assert_eq!(wrapper.compressed_size(), 0);
        assert_eq!(wrapper.uncompressed_offset(), 0);
        assert_eq!(wrapper.uncompressed_size(), 0);
        assert_eq!(wrapper.index(), 0);
        assert_eq!(wrapper.file_offset(), 0);
        assert!(!wrapper.is_compressed());
        assert!(!wrapper.is_batch());
    }

    #[test]
    #[should_panic]
    fn test_chunk_wrapper_ref_set_id() {
        let mut wrapper = ChunkWrapper::Ref(Arc::new(MockChunkInfo::default()));
        let dig = RafsDigest::from_buf([0xc; 32].as_slice(), digest::Algorithm::Blake3);
        wrapper.set_id(dig);
    }

    #[test]
    #[should_panic]
    fn test_chunk_wrapper_ref_set_blob_index() {
        let mut wrapper = ChunkWrapper::Ref(Arc::new(MockChunkInfo::default()));
        wrapper.set_blob_index(1024);
    }

    #[test]
    #[should_panic]
    fn test_chunk_wrapper_ref_set_compressed_offset() {
        let mut wrapper = ChunkWrapper::Ref(Arc::new(MockChunkInfo::default()));
        wrapper.set_compressed_offset(2048);
    }

    #[test]
    #[should_panic]
    fn test_chunk_wrapper_ref_set_uncompressed_size() {
        let mut wrapper = ChunkWrapper::Ref(Arc::new(MockChunkInfo::default()));
        wrapper.set_uncompressed_size(1024);
    }

    #[test]
    #[should_panic]
    fn test_chunk_wrapper_ref_set_uncompressed_offset() {
        let mut wrapper = ChunkWrapper::Ref(Arc::new(MockChunkInfo::default()));
        wrapper.set_uncompressed_offset(1024);
    }

    #[test]
    #[should_panic]
    fn test_chunk_wrapper_ref_set_compressed_size() {
        let mut wrapper = ChunkWrapper::Ref(Arc::new(MockChunkInfo::default()));
        wrapper.set_compressed_size(2048);
    }

    #[test]
    #[should_panic]
    fn test_chunk_wrapper_ref_set_index() {
        let mut wrapper = ChunkWrapper::Ref(Arc::new(MockChunkInfo::default()));
        wrapper.set_index(2048);
    }
    #[test]
    #[should_panic]
    fn test_chunk_wrapper_ref_set_file_offset() {
        let mut wrapper = ChunkWrapper::Ref(Arc::new(MockChunkInfo::default()));
        wrapper.set_file_offset(1024);
    }
    #[test]
    #[should_panic]
    fn test_chunk_wrapper_ref_set_compressed() {
        let mut wrapper = ChunkWrapper::Ref(Arc::new(MockChunkInfo::default()));
        wrapper.set_compressed(true);
    }
    #[test]
    #[should_panic]
    fn test_chunk_wrapper_ref_set_batch() {
        let mut wrapper = ChunkWrapper::Ref(Arc::new(MockChunkInfo::default()));
        wrapper.set_batch(true);
    }

    #[test]
    #[should_panic]
    fn test_chunk_wrapper_ref_set_chunk_info() {
        let mut wrapper = ChunkWrapper::Ref(Arc::new(MockChunkInfo::default()));
        wrapper
            .set_chunk_info(2048, 2048, 2048, 2048, 2048, 2048, 2048, true, true)
            .unwrap();
    }

    #[test]
    #[should_panic]
    fn test_chunk_wrapper_ref_ensure_owned() {
        let mut wrapper = ChunkWrapper::Ref(Arc::new(MockChunkInfo::default()));
        wrapper.ensure_owned();
    }

    fn test_copy_from(mut w1: ChunkWrapper, w2: ChunkWrapper) {
        w1.copy_from(&w2);
        assert_eq!(w1.blob_index(), w2.blob_index());
        assert_eq!(w1.compressed_offset(), w2.compressed_offset());
        assert_eq!(w1.compressed_size(), w2.compressed_size());
        assert_eq!(w1.uncompressed_offset(), w2.uncompressed_offset());
        assert_eq!(w1.uncompressed_size(), w2.uncompressed_size());
    }

    #[test]
    fn test_chunk_wrapper_copy_from() {
        let wrapper_v6 = ChunkWrapper::Ref(Arc::new(TarfsChunkInfoV6::new(0, 1, 128, 256)));
        let wrapper_v5 = ChunkWrapper::Ref(Arc::new(CachedChunkInfoV5::new()));
        test_copy_from(wrapper_v5.clone(), wrapper_v5.clone());
        test_copy_from(wrapper_v5.clone(), wrapper_v6.clone());
        test_copy_from(wrapper_v6.clone(), wrapper_v5);
        test_copy_from(wrapper_v6.clone(), wrapper_v6);
    }

    #[test]
    #[should_panic]
    fn test_ref_copy1() {
        let wrapper_ref = ChunkWrapper::Ref(Arc::new(MockChunkInfo::default()));
        test_copy_from(wrapper_ref.clone(), wrapper_ref);
    }

    #[test]
    #[should_panic]
    fn test_ref_copy2() {
        let wrapper_ref = ChunkWrapper::Ref(Arc::new(MockChunkInfo::default()));
        let wrapper_v5 = ChunkWrapper::Ref(Arc::new(CachedChunkInfoV5::default()));
        test_copy_from(wrapper_ref, wrapper_v5);
    }

    #[test]
    #[should_panic]
    fn test_ref_copy3() {
        let wrapper_ref = ChunkWrapper::Ref(Arc::new(MockChunkInfo::default()));
        let wrapper_v6 = ChunkWrapper::Ref(Arc::new(TarfsChunkInfoV6::new(0, 0, 0, 0)));
        test_copy_from(wrapper_ref, wrapper_v6);
    }

    #[test]
    #[should_panic]
    fn test_ref_copy4() {
        let wrapper_ref = ChunkWrapper::Ref(Arc::new(MockChunkInfo::default()));
        let wrapper_v6 = ChunkWrapper::Ref(Arc::new(TarfsChunkInfoV6::new(0, 0, 0, 0)));
        test_copy_from(wrapper_v6, wrapper_ref);
    }

    #[test]
    #[should_panic]
    fn test_ref_copy5() {
        let wrapper_ref = ChunkWrapper::Ref(Arc::new(MockChunkInfo::default()));
        let wrapper_v5 = ChunkWrapper::Ref(Arc::new(CachedChunkInfoV5::default()));
        test_copy_from(wrapper_v5, wrapper_ref);
    }

    #[test]
    fn test_set_deduped_for_chunk_v5() {
        let mut chunk = ChunkWrapper::new(RafsVersion::V5);
        assert!(!chunk.is_deduped());

        chunk.set_deduped(true);
        assert!(chunk.is_deduped());
    }

    #[test]
    fn test_set_deduped_for_chunk_v6() {
        let mut chunk = ChunkWrapper::new(RafsVersion::V6);
        assert!(!chunk.is_deduped());

        chunk.set_deduped(true);
        assert!(chunk.is_deduped());
    }
}
