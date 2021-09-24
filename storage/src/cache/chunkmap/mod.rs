// Copyright 2021 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Chunk readiness state tracking drivers.
//!
//! To cache data from remote backend storage onto local storage, a chunk state tracking mechanism
//! is needed to track whether a specific chunk is ready on local storage and to cooperate on
//! concurrent data downloading. The [ChunkMap](trait.ChunkMap.html) is the main interface to
//! track chunk state. And [BlobChunkMap](struct.BlobChunkMap.html) is a wrapper implementation of
//! [ChunkMap] to support concurrent data downloading, which is based on a base [ChunkMap]
//! implementation to track chunk readiness state.
//!
//! There are several base implementation of the [ChunkMap] trait to track chunk readiness state:
//! - [DigestedChunkMap](chunk_digested/struct.DigestedChunkMap.html): a chunk state tracking driver
//!   for legacy Rafs images without chunk array, which uses chunk digest as the id to track chunk
//!   readiness state. The [DigestedChunkMap] is not optimal in case of performance and memory
//!   consumption.
//! - [IndexedChunkMap](chunk_indexed/struct.IndexedChunkMap.html): a chunk state tracking driver
//!   based on a bitmap file. There's a state bit in the bitmap file for each chunk, and atomic
//!   operations are used to manipulate the bitmap. So it supports concurrent downloading. It's the
//!   recommended state tracking driver.
//! - [NoopChunkMap](noop/struct.NoopChunkMap.html): a no-operation chunk state tracking driver,
//!   which just reports every chunk as always ready to use. It may be used to support disk based
//!   backend storage.

use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::io::Result;
use std::sync::{Arc, Condvar, Mutex, WaitTimeoutResult};
use std::time::Duration;

use crate::cache::SINGLE_INFLIGHT_WAIT_TIMEOUT;
use crate::device::BlobChunkInfo;
use crate::{StorageError, StorageResult};

mod chunk_digested;
mod chunk_indexed;
mod noop;

pub use chunk_digested::DigestedChunkMap;
pub use chunk_indexed::IndexedChunkMap;
pub use noop::NoopChunkMap;

/// Marker trait for [ChunkMap] which supports
/// [is_ready_nowait()](trait.ChunkMap.html#method.is_ready_nowait).
pub trait NoWaitSupport {}

/// Trait to query and manage chunk readiness state.
pub trait ChunkMap: Send + Sync {
    /// Check whether the chunk is ready for use.
    fn is_ready(&self, chunk: &dyn BlobChunkInfo, wait: bool) -> Result<bool>;

    /// Check whether the chunk is ready for use without waiting.
    fn is_ready_nowait(&self, chunk: &dyn BlobChunkInfo) -> Result<bool> {
        self.is_ready(chunk, false)
    }

    /// Set chunk to ready state.
    fn set_ready(&self, chunk: &dyn BlobChunkInfo) -> Result<()>;

    /// Notify that the chunk is ready for use.
    fn notify_ready(&self, _chunk: &dyn BlobChunkInfo) {}
}

/// Trait to convert [BlobChunkInfo](../../device/trait.BlobChunkInfo.html) to index needed by
/// [ChunkMap]
pub trait ChunkIndexGetter {
    /// Type of index needed by [ChunkMap].
    type Index;

    /// Get the chunk's id/key for state tracking.
    fn get_index(chunk: &dyn BlobChunkInfo) -> Self::Index;
}

#[derive(PartialEq, Copy, Clone)]
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

    fn wait_for_inflight(&self, timeout: Duration) -> StorageResult<Status> {
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

        Ok(*inflight)
    }
}

/// Struct to enable concurrent downloading based on a base implementation of [ChunkMap].
///
/// The base implementation of [ChunkMap] needs to support chunk state tacking, and `BlobChunkMap`
/// add concurrent downloading over the base implementation. Internally, `BlobChunkMap` uses
/// an in memory inflight chunk tracker using `Mutex<HashMap>`.
pub struct BlobChunkMap<C, I> {
    c: C,
    inflight_tracer: Mutex<HashMap<I, Arc<ChunkSlot>>>,
}

impl<C, I> From<C> for BlobChunkMap<C, I>
where
    C: ChunkMap + ChunkIndexGetter<Index = I> + NoWaitSupport,
    I: Eq + Hash + Display,
{
    fn from(c: C) -> Self {
        Self {
            c,
            inflight_tracer: Mutex::new(HashMap::new()),
        }
    }
}

impl<C, I> ChunkMap for BlobChunkMap<C, I>
where
    C: ChunkMap + ChunkIndexGetter<Index = I> + NoWaitSupport,
    I: Eq + Hash + Display + Send,
{
    fn is_ready(&self, chunk: &dyn BlobChunkInfo, wait: bool) -> Result<bool> {
        let mut ready = self.c.is_ready(chunk, false)?;
        if ready {
            return Ok(true);
        }

        let index = C::get_index(chunk);
        let mut guard = self.inflight_tracer.lock().unwrap();
        trace!("chunk index {}, tracer scale {}", index, guard.len());

        if let Some(i) = guard.get(&index).cloned() {
            if wait {
                drop(guard);
                let result =
                    i.wait_for_inflight(Duration::from_millis(SINGLE_INFLIGHT_WAIT_TIMEOUT));
                if let Err(StorageError::Timeout) = result {
                    // Notice that lock of tracer is already dropped.
                    let mut t = self.inflight_tracer.lock().unwrap();
                    t.remove(&index);
                    i.notify();
                    warn!("Waiting for another backend IO expires. chunk index {}, compressed offset {}, tracer scale {}",
                          index, chunk.compress_offset(), t.len());
                };
                ready = self.c.is_ready(chunk, false)?;
            }
        } else {
            // Double check to close the window where prior slot was just removed after backend IO
            // returned.
            if self.c.is_ready(chunk, false)? {
                ready = true;
            } else {
                guard.insert(index, Arc::new(ChunkSlot::new()));
            }
        }

        Ok(ready)
    }

    fn set_ready(&self, chunk: &dyn BlobChunkInfo) -> Result<()> {
        self.c.set_ready(chunk).map(|_| {
            self.notify_ready(chunk);
        })
    }

    fn notify_ready(&self, chunk: &dyn BlobChunkInfo) {
        let index = C::get_index(chunk);
        let mut guard = self.inflight_tracer.lock().unwrap();
        if let Some(i) = guard.remove(&index) {
            i.done();
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;
    use std::thread;
    use std::time::Instant;

    use nydus_utils::digest::Algorithm::Blake3;
    use nydus_utils::digest::{Algorithm, RafsDigest};
    use vmm_sys_util::tempdir::TempDir;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::device::BlobChunkInfo;
    use crate::test::MockChunkInfo;

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

    impl BlobChunkInfo for Chunk {
        fn chunk_id(&self) -> &RafsDigest {
            &self.digest
        }

        fn id(&self) -> u32 {
            self.index
        }

        fn compress_offset(&self) -> u64 {
            unimplemented!();
        }

        fn compress_size(&self) -> u32 {
            unimplemented!();
        }

        fn uncompress_offset(&self) -> u64 {
            unimplemented!();
        }

        fn uncompress_size(&self) -> u32 {
            unimplemented!();
        }

        fn is_compressed(&self) -> bool {
            unimplemented!();
        }

        fn is_hole(&self) -> bool {
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

            let has_ready = indexed_chunk_map3.is_ready(chunk.as_ref(), false).unwrap();
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
                    .is_ready(chunks[idx as usize].as_ref(), false)
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
        let chunk_1: Arc<dyn BlobChunkInfo> = Arc::new({
            let mut c = MockChunkInfo::new();
            c.index = 1;
            c.block_id = RafsDigest::from_buf("hello world".as_bytes(), Blake3);
            c
        });
        let chunk_2: Arc<dyn BlobChunkInfo> = Arc::new({
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
        index_map.is_ready(chunk_1.as_ref(), false).unwrap();
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 1);
        index_map.is_ready(chunk_2.as_ref(), false).unwrap();
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 2);
        assert_eq!(index_map.is_ready(chunk_1.as_ref(), false).unwrap(), false);
        assert_eq!(index_map.is_ready(chunk_2.as_ref(), false).unwrap(), false);
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 2);

        index_map.set_ready(chunk_1.as_ref()).unwrap();
        assert_eq!(index_map.is_ready(chunk_1.as_ref(), false).unwrap(), true);
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 1);

        index_map.notify_ready(chunk_2.as_ref());
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 0);
        assert_eq!(index_map.is_ready(chunk_2.as_ref(), false).unwrap(), false);
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 1);
        index_map.notify_ready(chunk_2.as_ref());
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 0);
        index_map.set_ready(chunk_2.as_ref()).unwrap();
        assert_eq!(index_map.is_ready(chunk_2.as_ref(), false).unwrap(), true);
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 0);

        // digested ChunkMap
        let digest_map = Arc::new(BlobChunkMap::from(DigestedChunkMap::new()));
        digest_map.is_ready(chunk_1.as_ref(), false).unwrap();
        assert_eq!(digest_map.inflight_tracer.lock().unwrap().len(), 1);
        digest_map.is_ready(chunk_2.as_ref(), false).unwrap();
        assert_eq!(digest_map.inflight_tracer.lock().unwrap().len(), 2);
        assert_eq!(digest_map.is_ready(chunk_1.as_ref(), false).unwrap(), false);
        assert_eq!(digest_map.is_ready(chunk_2.as_ref(), false).unwrap(), false);
        digest_map.set_ready(chunk_1.as_ref()).unwrap();
        assert_eq!(digest_map.is_ready(chunk_1.as_ref(), false).unwrap(), true);
        digest_map.notify_ready(chunk_2.as_ref());
        assert_eq!(digest_map.is_ready(chunk_2.as_ref(), false).unwrap(), false);
        digest_map.notify_ready(chunk_2.as_ref());
        assert_eq!(digest_map.inflight_tracer.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_inflight_tracer_race() {
        let tmp_file = TempFile::new().unwrap();
        let map = Arc::new(BlobChunkMap::from(
            IndexedChunkMap::new(tmp_file.as_path().to_str().unwrap(), 10).unwrap(),
        ));

        let chunk_4: Arc<dyn BlobChunkInfo> = Arc::new({
            let mut c = MockChunkInfo::new();
            c.index = 4;
            c
        });

        assert_eq!(
            map.as_ref().is_ready(chunk_4.as_ref(), false).unwrap(),
            false
        );
        let map_cloned = map.clone();
        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 1);

        let chunk_4_cloned = chunk_4.clone();
        let t1 = thread::Builder::new()
            .spawn(move || {
                for _ in 0..4 {
                    let ready = map_cloned.is_ready(chunk_4_cloned.as_ref(), true).unwrap();
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
                        .is_ready(chunk_4_cloned_2.as_ref(), true)
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

        let chunk_4: Arc<dyn BlobChunkInfo> = Arc::new({
            let mut c = MockChunkInfo::new();
            c.index = 4;
            c
        });

        map.as_ref().is_ready(chunk_4.as_ref(), false).unwrap();
        let map_cloned = map.clone();

        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 1);

        let chunk_4_cloned = chunk_4.clone();
        let t1 = thread::Builder::new()
            .spawn(move || {
                for _ in 0..4 {
                    map_cloned.is_ready(chunk_4_cloned.as_ref(), true).unwrap();
                }
            })
            .unwrap();

        t1.join().unwrap();

        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 1);

        let ready = map.as_ref().is_ready(chunk_4.as_ref(), false).unwrap();
        assert_eq!(ready, false);
        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 1);

        map.notify_ready(chunk_4.as_ref());
        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 0);
    }
}
