// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;

use crate::cache::state::{ChunkIndexGetter, ChunkMap};
use crate::device::BlobChunkInfo;

/// A dummy implementation of the [ChunkMap] trait.
///
/// The `NoopChunkMap` is an dummy implementation of [ChunkMap], which just reports every chunk as
/// always ready to use or not. It may be used to support disk based backend storage.
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
}

impl ChunkIndexGetter for NoopChunkMap {
    type Index = u32;

    fn get_index(chunk: &dyn BlobChunkInfo) -> Self::Index {
        chunk.id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::MockChunkInfo;

    #[test]
    fn test_noop_chunk_map_ready_state() {
        let chunk = MockChunkInfo {
            index: 7,
            ..Default::default()
        };

        let ready_map = NoopChunkMap::new(true);
        assert!(ready_map.is_ready(&chunk).unwrap());

        let not_ready_map = NoopChunkMap::new(false);
        assert!(!not_ready_map.is_ready(&chunk).unwrap());
    }

    #[test]
    fn test_noop_chunk_map_index_getter() {
        let chunk = MockChunkInfo {
            index: 42,
            ..Default::default()
        };

        assert_eq!(NoopChunkMap::get_index(&chunk), 42);
    }
}
