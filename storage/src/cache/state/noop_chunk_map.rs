// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;

use crate::cache::state::{ChunkIndexGetter, ChunkMap};
use crate::device::BlobChunkInfo;

use super::RangeMap;

/// A dummy implementation of the [ChunkMap] trait.
///
/// The `NoopChunkMap` is an dummy implementation of [ChunkMap], which just reports every chunk as
/// always ready to use or not. It may be used to support disk based backend storage.
pub struct NoopChunkMap {
    all_chunk_ready: bool,
}

impl NoopChunkMap {
    /// Create a new instance of `NoopChunkMap`.
    pub fn new(all_chunk_ready: bool) -> Self {
        Self { all_chunk_ready }
    }
}

impl ChunkMap for NoopChunkMap {
    fn is_ready(&self, _chunk: &dyn BlobChunkInfo) -> Result<bool> {
        Ok(self.all_chunk_ready)
    }

    fn set_ready_and_clear_pending(&self, _chunk: &dyn BlobChunkInfo) -> Result<()> {
        Ok(())
    }

    fn check_ready_and_mark_pending(
        &self,
        _chunk: &dyn BlobChunkInfo,
    ) -> crate::StorageResult<bool> {
        Ok(true)
    }

    fn is_persist(&self) -> bool {
        true
    }

    fn as_range_map(&self) -> Option<&dyn RangeMap<I = u32>> {
        Some(self)
    }

    fn is_pending(&self, _chunk: &dyn BlobChunkInfo) -> Result<bool> {
        Ok(false)
    }

    fn is_ready_or_pending(&self, chunk: &dyn BlobChunkInfo) -> Result<bool> {
        if matches!(self.is_pending(chunk), Ok(true)) {
            Ok(true)
        } else {
            self.is_ready(chunk)
        }
    }

    fn clear_pending(&self, _chunk: &dyn BlobChunkInfo) {
        panic!("no support of clear_pending()");
    }
}

impl ChunkIndexGetter for NoopChunkMap {
    type Index = u32;

    fn get_index(chunk: &dyn BlobChunkInfo) -> Self::Index {
        chunk.id()
    }
}

impl RangeMap for NoopChunkMap {
    type I = u32;

    #[inline]
    fn is_range_all_ready(&self) -> bool {
        self.all_chunk_ready
    }

    fn is_range_ready(&self, _start_index: u32, _count: u32) -> Result<bool> {
        Ok(self.all_chunk_ready)
    }

    fn check_range_ready_and_mark_pending(
        &self,
        _start_index: u32,
        _count: u32,
    ) -> Result<Option<Vec<u32>>> {
        Ok(None)
    }

    fn set_range_ready_and_clear_pending(&self, _start_index: u32, _count: u32) -> Result<()> {
        Ok(())
    }
}
