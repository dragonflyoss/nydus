// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::Result;
use std::sync::{Arc, RwLock};

use nydus_utils::digest::RafsDigest;
use nydus_utils::metrics::{BlobcacheMetrics, Metric};

use super::ChunkMap;
use crate::device::RafsChunkInfo;

/// The DigestedChunkMap is an implementation that uses a hash map
/// (HashMap<chunk_digest, has_ready>) to records whether a chunk has been
/// cached by the blobcache. it is used to be compatible with the previous
/// old nydus bootstrap format.
#[derive(Default)]
pub struct DigestedChunkMap {
    metrics: Arc<BlobcacheMetrics>,
    /// HashMap<chunk_digest, has_ready>
    cache: RwLock<HashMap<RafsDigest, bool>>,
}

impl DigestedChunkMap {
    pub fn new(metrics: Arc<BlobcacheMetrics>) -> Self {
        Self {
            metrics,
            cache: RwLock::new(HashMap::new()),
        }
    }
}

impl ChunkMap for DigestedChunkMap {
    fn has_ready(&self, chunk: &dyn RafsChunkInfo) -> Result<bool> {
        Ok(self.cache.read().unwrap().get(chunk.block_id()).is_some())
    }

    fn set_ready(&self, chunk: &dyn RafsChunkInfo) -> Result<()> {
        if self.has_ready(chunk)? {
            self.metrics.entries_count.inc();
            return Ok(());
        }
        self.cache.write().unwrap().insert(*chunk.block_id(), true);
        Ok(())
    }
}
