// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! A no-operation chunk state tracking driver.
//!
//! This module provides a no-operation chunk state tracking driver, which just reports every chunk
//! as always ready to use. It may be used to support disk based backend storage.
use std::io::Result;

use crate::cache::chunkmap::{ChunkIndexGetter, ChunkMap};
use crate::device::BlobChunkInfo;

/// A dummy implementation of [ChunkMap](../trait.ChunkMap.html).
///
/// The `NoopChunkMap` is an dummy implementation of [ChunkMap](../trait.ChunkMap.html), which just
/// reports every chunk as always ready to use. It may be used to support disk based backend
/// storage.
pub struct NoopChunkMap {
    cached: bool,
}

impl NoopChunkMap {
    /// Create a new instance of `NoopChunkMap`.
    pub fn new(cached: bool) -> Self {
        Self { cached }
    }
}

impl ChunkMap for NoopChunkMap {
    fn is_ready(&self, _chunk: &dyn BlobChunkInfo) -> Result<bool> {
        Ok(self.cached)
    }

    fn set_ready_and_clear_pending(&self, _chunk: &dyn BlobChunkInfo) -> Result<()> {
        Ok(())
    }
}

impl ChunkIndexGetter for NoopChunkMap {
    type Index = u32;

    fn get_index(chunk: &dyn BlobChunkInfo) -> Self::Index {
        chunk.id()
    }
}
