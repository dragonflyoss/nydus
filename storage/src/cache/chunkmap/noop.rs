// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;

use super::{ChunkIndexGetter, ChunkMap, NoWaitSupport};
use crate::device::BlobChunkInfo;

pub struct NoopChunkMap {}

impl NoopChunkMap {
    /// Create a new instance of `NoopChunkMap`.
    pub fn new() -> Self {
        Self {}
    }
}

impl ChunkMap for NoopChunkMap {
    fn is_ready(&self, _chunk: &dyn BlobChunkInfo, _wait: bool) -> Result<bool> {
        Ok(true)
    }

    fn set_ready(&self, _chunk: &dyn BlobChunkInfo) -> Result<()> {
        Ok(())
    }
}

impl NoWaitSupport for NoopChunkMap {}

impl ChunkIndexGetter for NoopChunkMap {
    type Index = u32;

    fn get_index(chunk: &dyn BlobChunkInfo) -> Self::Index {
        chunk.id()
    }
}
