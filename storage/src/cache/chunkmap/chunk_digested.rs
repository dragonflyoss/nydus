// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::io::Result;
use std::sync::RwLock;

use nydus_utils::digest::RafsDigest;

use super::ChunkMap;
use crate::cache::chunkmap::{ChunkIndexGetter, NoWaitSupport};
use crate::device::BlobChunkInfo;

/// A `ChunkMap` implementation based on `HashSet<RafsDigest>`.
///
/// The `DigestedChunkMap` is an implementation of `ChunkMap` which uses a hash set
/// (HashSet<chunk_digest>) to record whether a chunk has already been cached by the blob cache.
/// The implementation is memory and computation heavy, so it is used only to keep backward
/// compatibility with the previous old nydus bootstrap format. For new clients, please use other
/// alternative implementations.
#[derive(Default)]
pub struct DigestedChunkMap {
    cache: RwLock<HashSet<RafsDigest>>,
}

impl DigestedChunkMap {
    /// Create a new instance of `DigestedChunkMap`.
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashSet::new()),
        }
    }
}

impl ChunkMap for DigestedChunkMap {
    fn is_ready(&self, chunk: &dyn BlobChunkInfo, _wait: bool) -> Result<bool> {
        // Do not expect poisoned lock.
        Ok(self.cache.read().unwrap().contains(chunk.block_id()))
    }

    fn set_ready(&self, chunk: &dyn BlobChunkInfo) -> Result<()> {
        // Do not expect poisoned lock.
        self.cache.write().unwrap().insert(*chunk.block_id());
        Ok(())
    }
}

impl NoWaitSupport for DigestedChunkMap {}

impl ChunkIndexGetter for DigestedChunkMap {
    type Index = RafsDigest;

    fn get_index(chunk: &dyn BlobChunkInfo) -> Self::Index {
        *chunk.block_id()
    }
}
