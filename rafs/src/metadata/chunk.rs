// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021-2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::fmt::{Display, Formatter};

use anyhow::{Context, Result};
use nydus_utils::digest::RafsDigest;
use storage::device::v5::BlobV5ChunkInfo;
use storage::device::{BlobChunkFlags, BlobChunkInfo};

use crate::metadata::cached_v5::CachedChunkInfoV5;
use crate::metadata::direct_v5::DirectChunkInfoV5;
use crate::metadata::direct_v6::DirectChunkInfoV6;
use crate::metadata::layout::v5::RafsV5ChunkInfo;
use crate::metadata::{RafsStore, RafsVersion};
use crate::RafsIoWrite;

#[derive(Clone, Debug)]
pub enum ChunkWrapper {
    V5(RafsV5ChunkInfo),
    // Reuse `RafsV5ChunkInfo` for v6 with a different wrapper to reduce duplicated code.
    V6(RafsV5ChunkInfo),
}

impl ChunkWrapper {
    pub fn new(version: RafsVersion) -> Self {
        match version {
            RafsVersion::V5 => ChunkWrapper::V5(RafsV5ChunkInfo::default()),
            RafsVersion::V6 => ChunkWrapper::V6(RafsV5ChunkInfo::default()),
        }
    }

    pub fn from_chunk_info(cki: &dyn BlobChunkInfo) -> Self {
        if let Some(cki_v5) = cki.as_any().downcast_ref::<CachedChunkInfoV5>() {
            ChunkWrapper::V5(to_rafsv5_chunk_info(cki_v5))
        } else if let Some(cki_v5) = cki.as_any().downcast_ref::<DirectChunkInfoV5>() {
            ChunkWrapper::V5(to_rafsv5_chunk_info(cki_v5))
        } else if let Some(cki_v6) = cki.as_any().downcast_ref::<DirectChunkInfoV6>() {
            ChunkWrapper::V6(to_rafsv5_chunk_info(cki_v6))
        } else {
            panic!("unknown chunk information struct");
        }
    }

    pub fn id(&self) -> &RafsDigest {
        match self {
            ChunkWrapper::V5(c) => &c.block_id,
            ChunkWrapper::V6(c) => &c.block_id,
        }
    }

    pub fn set_id(&mut self, id: RafsDigest) {
        match self {
            ChunkWrapper::V5(c) => c.block_id = id,
            ChunkWrapper::V6(c) => c.block_id = id,
        }
    }

    pub fn index(&self) -> u32 {
        match self {
            ChunkWrapper::V5(c) => c.index,
            ChunkWrapper::V6(c) => c.index,
        }
    }

    pub fn set_index(&mut self, index: u32) {
        match self {
            ChunkWrapper::V5(c) => c.index = index,
            ChunkWrapper::V6(c) => c.index = index,
        }
    }

    pub fn blob_index(&self) -> u32 {
        match self {
            ChunkWrapper::V5(c) => c.blob_index,
            ChunkWrapper::V6(c) => c.blob_index,
        }
    }

    pub fn set_blob_index(&mut self, index: u32) {
        match self {
            ChunkWrapper::V5(c) => c.blob_index = index,
            ChunkWrapper::V6(c) => c.blob_index = index,
        }
    }

    pub fn compressed_offset(&self) -> u64 {
        match self {
            ChunkWrapper::V5(c) => c.compressed_offset,
            ChunkWrapper::V6(c) => c.compressed_offset,
        }
    }

    pub fn set_compressed_offset(&mut self, offset: u64) {
        match self {
            ChunkWrapper::V5(c) => c.compressed_offset = offset,
            ChunkWrapper::V6(c) => c.compressed_offset = offset,
        }
    }

    pub fn compressed_size(&self) -> u32 {
        match self {
            ChunkWrapper::V5(c) => c.compressed_size,
            ChunkWrapper::V6(c) => c.compressed_size,
        }
    }

    pub fn uncompressed_offset(&self) -> u64 {
        match self {
            ChunkWrapper::V5(c) => c.uncompressed_offset,
            ChunkWrapper::V6(c) => c.uncompressed_offset,
        }
    }

    pub fn set_uncompressed_offset(&mut self, offset: u64) {
        match self {
            ChunkWrapper::V5(c) => c.uncompressed_offset = offset,
            ChunkWrapper::V6(c) => c.uncompressed_offset = offset,
        }
    }

    pub fn uncompressed_size(&self) -> u32 {
        match self {
            ChunkWrapper::V5(c) => c.uncompressed_size,
            ChunkWrapper::V6(c) => c.uncompressed_size,
        }
    }

    pub fn file_offset(&self) -> u64 {
        match self {
            ChunkWrapper::V5(c) => c.file_offset,
            ChunkWrapper::V6(c) => c.file_offset,
        }
    }

    pub fn set_file_offset(&mut self, offset: u64) {
        match self {
            ChunkWrapper::V5(c) => c.file_offset = offset,
            ChunkWrapper::V6(c) => c.file_offset = offset,
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[inline]
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
    ) -> Result<()> {
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
            }
        }

        Ok(())
    }

    pub fn copy_from(&mut self, other: &Self) {
        match (self, other) {
            (ChunkWrapper::V5(s), ChunkWrapper::V5(o)) => {
                s.clone_from(o);
            }
            (ChunkWrapper::V6(s), ChunkWrapper::V6(o)) => {
                s.clone_from(o);
            }
            (ChunkWrapper::V5(s), ChunkWrapper::V6(o)) => {
                s.clone_from(o);
            }
            (ChunkWrapper::V6(s), ChunkWrapper::V5(o)) => {
                s.clone_from(o);
            }
        }
    }

    pub fn store(&self, w: &mut dyn RafsIoWrite) -> Result<usize> {
        match self {
            ChunkWrapper::V5(c) => c.store(w).context("failed to store rafs v5 chunk"),
            ChunkWrapper::V6(c) => c.store(w).context("failed to store rafs v6 chunk"),
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

/// Construct a `RafsV5ChunkInfo` object from a `dyn BlobChunkInfo` object.
fn to_rafsv5_chunk_info(cki: &dyn BlobV5ChunkInfo) -> RafsV5ChunkInfo {
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
