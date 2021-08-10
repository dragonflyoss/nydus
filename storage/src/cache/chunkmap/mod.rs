// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;

use crate::cache::blobcache::SINGLE_INFLIGHT_WAIT_TIMEOUT;
use crate::device::RafsChunkInfo;
use crate::{StorageError, StorageResult};
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::sync::{Arc, Condvar, Mutex, WaitTimeoutResult};
use std::time::Duration;

pub mod digested;
pub mod indexed;

/// only to mark ChunkMap who doesn't support wait
pub trait NoWaitSupport {}

/// The chunk map checks whether a chunk data has been cached in
/// blob cache based on the chunk info.
pub trait ChunkMap {
    fn has_ready(&self, chunk: &dyn RafsChunkInfo, wait: bool) -> Result<bool>;
    fn set_ready(&self, chunk: &dyn RafsChunkInfo) -> Result<()>;
    fn finish(&self, _chunk: &dyn RafsChunkInfo) {}
    fn has_ready_nowait(&self, _chunk: &dyn RafsChunkInfo) -> Result<bool> {
        Ok(false)
    }
}

/// convert RafsChunkInfo to ChunkMap inner index
pub trait ChunkIndexGetter {
    type Index;

    fn get_index(chunk: &dyn RafsChunkInfo) -> Self::Index;
}

#[derive(PartialEq)]
enum Status {
    Inflight,
    Complete,
}

struct ChunkSlot {
    on_trip: Mutex<Status>,
    condvar: Condvar,
}

impl ChunkSlot {
    fn new() -> Self {
        ChunkSlot {
            on_trip: Mutex::new(Status::Inflight),
            condvar: Condvar::new(),
        }
    }

    fn notify(&self) {
        self.condvar.notify_all();
    }

    fn done(&self) {
        // Not expect poisoned lock here
        *self.on_trip.lock().unwrap() = Status::Complete;
        self.notify();
    }

    fn wait_for_inflight(&self, timeout: Duration) -> StorageResult<()> {
        let mut inflight = self.on_trip.lock().unwrap();
        let mut tor: WaitTimeoutResult;
        while *inflight == Status::Inflight {
            // Do not expect poisoned lock, so unwrap here.
            let r = self.condvar.wait_timeout(inflight, timeout).unwrap();
            inflight = r.0;
            tor = r.1;
            if tor.timed_out() {
                return Err(StorageError::Timeout);
            }
        }

        Ok(())
    }
}

/// general chunk map
/// support single inflight io if backend ChunkMap doesn't support
pub struct BlobChunkMap<C, I> {
    c: C,
    inflight_tracer: Mutex<HashMap<I, Arc<ChunkSlot>>>,
}

// TODO: Use chunk's compress offset a.k.a blob address as key, so we don't need
// ChunkIndexGetter<Index = I> anymore.
impl<C, I> BlobChunkMap<C, I>
where
    C: ChunkMap + ChunkIndexGetter<Index = I> + NoWaitSupport,
    I: Eq + Hash + Display,
{
    pub fn from(c: C) -> Self {
        Self {
            c,
            inflight_tracer: Mutex::new(HashMap::new()),
        }
    }
}

impl<C, I> ChunkMap for BlobChunkMap<C, I>
where
    C: ChunkMap + ChunkIndexGetter<Index = I> + NoWaitSupport,
    I: Eq + Hash + Display,
{
    fn has_ready(&self, chunk: &dyn RafsChunkInfo, wait: bool) -> Result<bool> {
        let ready = self.c.has_ready(chunk, false)?;

        if !ready {
            let index = C::get_index(chunk);
            let mut guard = self.inflight_tracer.lock().unwrap();
            trace!("chunk index {}, tracer scale {}", index, guard.len());
            if let Some(i) = guard.get(&index).cloned() {
                if wait {
                    drop(guard);
                    return match i
                        .wait_for_inflight(Duration::from_millis(SINGLE_INFLIGHT_WAIT_TIMEOUT))
                    {
                        Err(StorageError::Timeout) => {
                            // Notice that lock of tracer is already dropped.
                            let mut t = self.inflight_tracer.lock().unwrap();
                            t.remove(&index);
                            i.notify();
                            warn!(
                                "Waiting for another backend IO expires. chunk index {}, \
                            compressed offset {}, tracer scale {}",
                                index,
                                chunk.compress_offset(),
                                t.len()
                            );
                            // TODO: Take argument `true` or `false` is strange since it is not used.
                            self.c.has_ready(chunk, false)
                        }
                        _ => self.c.has_ready(chunk, false),
                    };
                }
            } else {
                // Double check to close the window where prior slot was just
                // removed after backend IO returned.
                if self.c.has_ready(chunk, false)? {
                    return Ok(true);
                }
                guard.insert(index, Arc::new(ChunkSlot::new()));
            }
        }
        Ok(ready)
    }

    fn set_ready(&self, chunk: &dyn RafsChunkInfo) -> Result<()> {
        self.c.set_ready(chunk).map(|_| {
            self.finish(chunk);
        })
    }

    fn finish(&self, chunk: &dyn RafsChunkInfo) {
        let index = C::get_index(chunk);
        let mut guard = self.inflight_tracer.lock().unwrap();
        if let Some(i) = guard.remove(&index) {
            i.done();
        }
    }

    fn has_ready_nowait(&self, chunk: &dyn RafsChunkInfo) -> Result<bool> {
        self.c.has_ready(chunk, false)
    }
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
    use crate::cache::blobcache::blob_cache_tests::MockChunkInfo;
    use crate::device::{RafsChunkFlags, RafsChunkInfo};
    use nydus_utils::digest::Algorithm::Blake3;
    use nydus_utils::digest::{Algorithm, RafsDigest};
    use vmm_sys_util::tempfile::TempFile;

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

        h1.join()
            .map_err(|e| {
                error!("Join error {:?}", e);
                e
            })
            .unwrap();
        h2.join()
            .map_err(|e| {
                error!("Join error {:?}", e);
                e
            })
            .unwrap();

        println!(
            "IndexedChunkMap Concurrency: {}ms",
            now.elapsed().as_millis()
        );

        for idx in 0..chunk_count {
            let chunk = Chunk::new(idx);

            let has_ready = indexed_chunk_map3.has_ready(chunk.as_ref(), false).unwrap();
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
                chunk_map
                    .has_ready(chunks[idx as usize].as_ref(), false)
                    .unwrap(),
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

    #[test]
    fn test_inflight_tracer() {
        let chunk_1: Arc<dyn RafsChunkInfo> = Arc::new({
            let mut c = MockChunkInfo::new();
            c.index = 1;
            c.block_id = RafsDigest::from_buf("hello world".as_bytes(), Blake3);
            c
        });
        let chunk_2: Arc<dyn RafsChunkInfo> = Arc::new({
            let mut c = MockChunkInfo::new();
            c.index = 2;
            c.block_id = RafsDigest::from_buf("hello world 2".as_bytes(), Blake3);
            c
        });
        // indexed ChunkMap
        let tmp_file = TempFile::new().unwrap();
        let index_map = Arc::new(BlobChunkMap::from(
            IndexedChunkMap::new(tmp_file.as_path().to_str().unwrap(), 10).unwrap(),
        ));
        index_map.has_ready(chunk_1.as_ref(), false).unwrap();
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 1);
        index_map.has_ready(chunk_2.as_ref(), false).unwrap();
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 2);
        assert_eq!(index_map.has_ready(chunk_1.as_ref(), false).unwrap(), false);
        assert_eq!(index_map.has_ready(chunk_2.as_ref(), false).unwrap(), false);
        index_map.set_ready(chunk_1.as_ref()).unwrap();
        assert_eq!(index_map.has_ready(chunk_1.as_ref(), false).unwrap(), true);
        index_map.finish(chunk_2.as_ref());
        assert_eq!(index_map.has_ready(chunk_2.as_ref(), false).unwrap(), false);
        index_map.finish(chunk_2.as_ref());
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 0);
        // digested ChunkMap
        let digest_map = Arc::new(BlobChunkMap::from(DigestedChunkMap::new()));
        digest_map.has_ready(chunk_1.as_ref(), false).unwrap();
        assert_eq!(digest_map.inflight_tracer.lock().unwrap().len(), 1);
        digest_map.has_ready(chunk_2.as_ref(), false).unwrap();
        assert_eq!(digest_map.inflight_tracer.lock().unwrap().len(), 2);
        assert_eq!(
            digest_map.has_ready(chunk_1.as_ref(), false).unwrap(),
            false
        );
        assert_eq!(
            digest_map.has_ready(chunk_2.as_ref(), false).unwrap(),
            false
        );
        digest_map.set_ready(chunk_1.as_ref()).unwrap();
        assert_eq!(digest_map.has_ready(chunk_1.as_ref(), false).unwrap(), true);
        digest_map.finish(chunk_2.as_ref());
        assert_eq!(
            digest_map.has_ready(chunk_2.as_ref(), false).unwrap(),
            false
        );
        digest_map.finish(chunk_2.as_ref());
        assert_eq!(digest_map.inflight_tracer.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_inflight_tracer_race() {
        let tmp_file = TempFile::new().unwrap();
        let map = Arc::new(BlobChunkMap::from(
            IndexedChunkMap::new(tmp_file.as_path().to_str().unwrap(), 10).unwrap(),
        ));

        let chunk_4: Arc<dyn RafsChunkInfo> = Arc::new({
            let mut c = MockChunkInfo::new();
            c.index = 4;
            c
        });

        map.as_ref().has_ready(chunk_4.as_ref(), false).unwrap();
        let map_cloned = map.clone();

        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 1);

        let chunk_4_cloned = chunk_4.clone();
        let t1 = thread::Builder::new()
            .spawn(move || {
                for _ in 0..4 {
                    let ready = map_cloned.has_ready(chunk_4_cloned.as_ref(), true).unwrap();
                    assert_eq!(ready, true);
                }
            })
            .unwrap();

        let map_cloned_2 = map.clone();
        let chunk_4_cloned_2 = chunk_4.clone();
        let t2 = thread::Builder::new()
            .spawn(move || {
                for _ in 0..2 {
                    let ready = map_cloned_2
                        .has_ready(chunk_4_cloned_2.as_ref(), true)
                        .unwrap();
                    assert_eq!(ready, true);
                }
            })
            .unwrap();

        thread::sleep(Duration::from_secs(1));

        map.set_ready(chunk_4.as_ref()).unwrap();

        // Fuzz
        map.set_ready(chunk_4.as_ref()).unwrap();
        map.set_ready(chunk_4.as_ref()).unwrap();

        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 0);

        t1.join().unwrap();
        t2.join().unwrap();
    }

    #[test]
    /// Case description:
    ///     Never invoke `set_ready` method, thus to let each caller of `has_ready` reach
    ///     a point of timeout.
    /// Expect:
    ///     The chunk of index 4 is never marked as ready/downloaded.
    ///     Each caller of `has_ready` can escape from where it is blocked.
    ///     After timeout, no slot is left in inflight tracer.
    fn test_inflight_tracer_timeout() {
        let tmp_file = TempFile::new().unwrap();
        let map = Arc::new(BlobChunkMap::from(
            IndexedChunkMap::new(tmp_file.as_path().to_str().unwrap(), 10).unwrap(),
        ));

        let chunk_4: Arc<dyn RafsChunkInfo> = Arc::new({
            let mut c = MockChunkInfo::new();
            c.index = 4;
            c
        });

        map.as_ref().has_ready(chunk_4.as_ref(), false).unwrap();
        let map_cloned = map.clone();

        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 1);

        let chunk_4_cloned = chunk_4.clone();
        let t1 = thread::Builder::new()
            .spawn(move || {
                for _ in 0..4 {
                    map_cloned.has_ready(chunk_4_cloned.as_ref(), true).unwrap();
                }
            })
            .unwrap();

        t1.join().unwrap();

        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 1);

        let ready = map.as_ref().has_ready(chunk_4.as_ref(), false).unwrap();
        assert_eq!(ready, false);

        map.finish(chunk_4.as_ref());
        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 0);
    }
}
