// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::Result;
use std::sync::RwLock;

use nydus_utils::digest::RafsDigest;

use super::ChunkMap;
use crate::cache::chunkmap::{ChunkIndexGetter, NoWaitSupport};
use crate::device::RafsChunkInfo;

/// The DigestedChunkMap is an implementation that uses a hash map
/// (HashMap<chunk_digest, has_ready>) to records whether a chunk has been
/// cached by the blobcache. it is used to be compatible with the previous
/// old nydus bootstrap format.
#[derive(Default)]
pub struct DigestedChunkMap {
    /// HashMap<chunk_digest, has_ready>
    cache: RwLock<HashMap<RafsDigest, bool>>,
}

impl NoWaitSupport for DigestedChunkMap {}

impl DigestedChunkMap {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
        }
    }
}

impl ChunkMap for DigestedChunkMap {
    fn has_ready(&self, chunk: &dyn RafsChunkInfo, _wait: bool) -> Result<bool> {
        Ok(self.cache.read().unwrap().get(chunk.block_id()).is_some())
    }

    fn set_ready(&self, chunk: &dyn RafsChunkInfo) -> Result<()> {
        self.cache.write().unwrap().insert(*chunk.block_id(), true);
        Ok(())
    }
}

impl ChunkIndexGetter for DigestedChunkMap {
    type Index = RafsDigest;

    fn get_index(chunk: &dyn RafsChunkInfo) -> Self::Index {
        *chunk.block_id()
    }
}
