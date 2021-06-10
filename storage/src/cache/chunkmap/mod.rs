// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;

use crate::device::RafsChunkInfo;

pub mod digested;
pub mod indexed;

/// The chunk map checks whether a chunk data has been cached in
/// blob cache based on the chunk info.
pub trait ChunkMap {
    fn has_ready(&self, chunk: &dyn RafsChunkInfo) -> Result<bool>;
    fn set_ready(&self, chunk: &dyn RafsChunkInfo) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;
    use std::time::Instant;

    use vmm_sys_util::tempdir::TempDir;

    use super::digested::DigestedChunkMap;
    use super::indexed::IndexedChunkMap;
    use super::*;
    use crate::device::{RafsChunkFlags, RafsChunkInfo};
    use nydus_utils::digest::{Algorithm, RafsDigest};

    struct Chunk {
        index: u32,
        digest: RafsDigest,
    }

    impl Chunk {
        fn new(index: u32) -> Arc<Self> {
            Arc::new(Self {
                index,
                digest: RafsDigest::from_buf(
                    unsafe { std::slice::from_raw_parts(&index as *const u32 as *const u8, 4) },
                    Algorithm::Blake3,
                ),
            })
        }
    }

    impl RafsChunkInfo for Chunk {
        fn block_id(&self) -> &RafsDigest {
            &self.digest
        }

        fn index(&self) -> u32 {
            self.index
        }

        fn blob_index(&self) -> u32 {
            unimplemented!();
        }

        fn compress_offset(&self) -> u64 {
            unimplemented!();
        }

        fn compress_size(&self) -> u32 {
            unimplemented!();
        }

        fn decompress_offset(&self) -> u64 {
            unimplemented!();
        }

        fn decompress_size(&self) -> u32 {
            unimplemented!();
        }

        fn file_offset(&self) -> u64 {
            unimplemented!();
        }

        fn is_compressed(&self) -> bool {
            unimplemented!();
        }

        fn is_hole(&self) -> bool {
            unimplemented!();
        }

        fn flags(&self) -> RafsChunkFlags {
            unimplemented!();
        }
    }

    #[test]
    fn test_chunk_map() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.as_path().join("blob-1");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();
        let chunk_count = 1000000;
        let skip_index = 77;

        let indexed_chunk_map1 = Arc::new(IndexedChunkMap::new(&blob_path, chunk_count).unwrap());
        let indexed_chunk_map2 = Arc::new(IndexedChunkMap::new(&blob_path, chunk_count).unwrap());
        let indexed_chunk_map3 = Arc::new(IndexedChunkMap::new(&blob_path, chunk_count).unwrap());

        let now = Instant::now();

        let h1 = thread::spawn(move || {
            for idx in 0..chunk_count {
                let chunk = Chunk::new(idx);
                if idx % skip_index != 0 {
                    indexed_chunk_map1.set_ready(chunk.as_ref()).unwrap();
                }
            }
        });

        let h2 = thread::spawn(move || {
            for idx in 0..chunk_count {
                let chunk = Chunk::new(idx);
                if idx % skip_index != 0 {
                    indexed_chunk_map2.set_ready(chunk.as_ref()).unwrap();
                }
            }
        });

        h1.join().unwrap();
        h2.join().unwrap();

        println!(
            "IndexedChunkMap Concurrency: {}ms",
            now.elapsed().as_millis()
        );

        for idx in 0..chunk_count {
            let chunk = Chunk::new(idx);

            let has_ready = indexed_chunk_map3.has_ready(chunk.as_ref()).unwrap();
            if idx % skip_index == 0 {
                if has_ready {
                    panic!("indexed chunk map: index {} shouldn't be ready", idx);
                }
            } else if !has_ready {
                panic!("indexed chunk map: index {} should be ready", idx);
            }
        }
    }

    fn iterate(chunks: &[Arc<Chunk>], chunk_map: &dyn ChunkMap, chunk_count: u32) {
        for idx in 0..chunk_count {
            chunk_map.set_ready(chunks[idx as usize].as_ref()).unwrap();
        }
        for idx in 0..chunk_count {
            assert_eq!(
                chunk_map.has_ready(chunks[idx as usize].as_ref()).unwrap(),
                true
            );
        }
    }

    #[test]
    fn test_chunk_map_perf() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.as_path().join("blob-1");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();
        let chunk_count = 1000000;

        let mut chunks = Vec::new();
        for idx in 0..chunk_count {
            chunks.push(Chunk::new(idx))
        }

        let indexed_chunk_map = IndexedChunkMap::new(&blob_path, chunk_count).unwrap();
        let now = Instant::now();
        iterate(&chunks, &indexed_chunk_map as &dyn ChunkMap, chunk_count);
        let elapsed1 = now.elapsed().as_millis();

        let digested_chunk_map = DigestedChunkMap::new();
        let now = Instant::now();
        iterate(&chunks, &digested_chunk_map as &dyn ChunkMap, chunk_count);
        let elapsed2 = now.elapsed().as_millis();

        println!(
            "IndexedChunkMap vs DigestedChunkMap: {}ms vs {}ms",
            elapsed1, elapsed2
        );
    }
}
