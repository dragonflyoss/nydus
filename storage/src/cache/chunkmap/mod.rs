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

use std::any::Any;
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

/// Trait to query and manage chunk readiness state.
pub trait ChunkMap: Any + Send + Sync {
    /// Check whether the chunk is ready for use without waiting.
    fn is_ready(&self, chunk: &dyn BlobChunkInfo) -> Result<bool>;

    /// Check whether the chunk is ready for use.
    ///
    /// The function returns:
    /// - Err if timeout
    /// - Ok(true) if the the chunk is ready.
    /// - Ok(false) and also marks the chunk as pending, either set_ready() or clear_pending() must
    ///   be called to clear the pending state.
    fn check_ready_and_mark_pending(&self, _chunk: &dyn BlobChunkInfo) -> Result<bool> {
        panic!("no support of check_ready_and_mark_pending()");
    }

    /// Set chunk to ready state and clear pending state.
    fn set_ready_and_clear_pending(&self, chunk: &dyn BlobChunkInfo) -> Result<()>;

    /// Clear the pending(inflight) state of the chunk.
    fn clear_pending(&self, _chunk: &dyn BlobChunkInfo) {
        panic!("no support of clear_pending()");
    }

    /// Convert it to an `ChunkBitmap` object.
    fn as_bitmap(&self) -> Option<&dyn ChunkBitmap> {
        None
    }

    /// Check whether the chunk map implementation store chunk state persistently.
    fn is_persist(&self) -> bool {
        false
    }
}

/// Trait to track chunk readiness state using bitmap, indexed by chunk index.
///
/// Its interfaces are designed to support batch operations, to improve performance by avoid
/// frequently acquire/release locks.
pub trait ChunkBitmap: Send + Sync {
    /// Check whether all chunks are ready.
    fn is_bitmap_all_ready(&self) -> bool {
        false
    }

    /// Check whether the chunk is ready for use.
    fn is_bitmap_ready(&self, _start_index: u32, _count: u32) -> Result<bool> {
        Err(enosys!())
    }

    /// Check whether chunks in range [start_index, start_index + count) is ready or not.
    ///
    /// This function checks readiness of a range of chunks. If a chunk is both not ready and not
    /// pending(inflight), it will be marked as pending and returned. Following actions should be:
    /// - call set_bitmap_ready_and_clear_pending() to mark chunks as ready and clear pending state.
    /// - clear_bitmap_pending() to clear the pending state without marking chunk as ready.
    /// - wait_for_bitmap_ready() to wait for all chunks to clear pending state, including chunks
    ///   marked as pending by other threads.
    fn check_bitmap_ready_and_mark_pending(
        &self,
        _start_index: u32,
        _count: u32,
    ) -> Result<Option<Vec<u32>>> {
        Err(enosys!())
    }

    /// Mark all chunks as ready for use.
    fn set_bitmap_ready_and_clear_pending(&self, _start_index: u32, _count: u32) -> Result<()> {
        Err(enosys!())
    }

    /// Notify that the chunk is ready for use.
    fn clear_bitmap_pending(&self, _start_index: u32, _count: u32) {}

    /// Wait for all chunks to be ready until timeout.
    fn wait_for_bitmap_ready(&self, _start_index: u32, _count: u32) -> Result<bool> {
        Err(enosys!())
    }
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
    C: ChunkMap + ChunkIndexGetter<Index = I>,
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
    C: ChunkMap + ChunkIndexGetter<Index = I>,
    I: Eq + Hash + Display + Send + 'static,
{
    fn is_ready(&self, chunk: &dyn BlobChunkInfo) -> Result<bool> {
        self.c.is_ready(chunk)
    }

    fn check_ready_and_mark_pending(&self, chunk: &dyn BlobChunkInfo) -> Result<bool> {
        let mut ready = self.c.is_ready(chunk)?;
        if ready {
            return Ok(true);
        }

        let index = C::get_index(chunk);
        let mut guard = self.inflight_tracer.lock().unwrap();
        trace!("chunk index {}, tracer scale {}", index, guard.len());

        if let Some(i) = guard.get(&index).cloned() {
            drop(guard);
            let result = i.wait_for_inflight(Duration::from_millis(SINGLE_INFLIGHT_WAIT_TIMEOUT));
            if let Err(StorageError::Timeout) = result {
                /*
                // Notice that lock of tracer is already dropped.
                let mut t = self.inflight_tracer.lock().unwrap();
                t.remove(&index);
                i.notify();
                 */
                warn!(
                    "Waiting for backend IO expires. chunk index {}, compressed offset {}",
                    index,
                    chunk.compress_offset()
                );
                Err(eio!("timeout when read data from backend"))
            } else {
                self.check_ready_and_mark_pending(chunk)
            }
        } else {
            // Double check to close the window where prior slot was just removed after backend IO
            // returned.
            if self.c.is_ready(chunk)? {
                ready = true;
            } else {
                guard.insert(index, Arc::new(ChunkSlot::new()));
            }
            Ok(ready)
        }
    }

    fn set_ready_and_clear_pending(&self, chunk: &dyn BlobChunkInfo) -> Result<()> {
        let res = self.c.set_ready_and_clear_pending(chunk);
        self.clear_pending(chunk);
        res
    }

    fn clear_pending(&self, chunk: &dyn BlobChunkInfo) {
        let index = C::get_index(chunk);
        let mut guard = self.inflight_tracer.lock().unwrap();
        if let Some(i) = guard.remove(&index) {
            i.done();
        }
    }

    fn as_bitmap(&self) -> Option<&dyn ChunkBitmap> {
        let any = self as &dyn Any;
        if let Some(v) = any.downcast_ref::<BlobChunkMap<IndexedChunkMap, u32>>() {
            Some(v as &dyn ChunkBitmap)
        } else {
            None
        }
    }

    fn is_persist(&self) -> bool {
        self.c.is_persist()
    }
}

impl ChunkBitmap for BlobChunkMap<IndexedChunkMap, u32> {
    fn is_bitmap_all_ready(&self) -> bool {
        self.c.is_bitmap_all_ready()
    }

    fn is_bitmap_ready(&self, start_index: u32, count: u32) -> Result<bool> {
        self.c.is_bitmap_ready(start_index, count)
    }

    fn check_bitmap_ready_and_mark_pending(
        &self,
        start_index: u32,
        count: u32,
    ) -> Result<Option<Vec<u32>>> {
        let pending = match self
            .c
            .check_bitmap_ready_and_mark_pending(start_index, count)
        {
            Err(e) => return Err(e),
            Ok(None) => return Ok(None),
            Ok(Some(v)) => {
                if v.len() == 0 {
                    return Ok(None);
                }
                v
            }
        };

        let mut res = Vec::with_capacity(pending.len());
        let mut guard = self.inflight_tracer.lock().unwrap();
        for index in pending.iter() {
            if guard.get(index).is_none() {
                // Double check to close the window where prior slot was just removed after backend
                // IO returned.
                if !self.c.is_bitmap_ready(*index, 1)? {
                    guard.insert(*index, Arc::new(ChunkSlot::new()));
                    res.push(*index);
                }
            }
        }

        Ok(Some(res))
    }

    fn set_bitmap_ready_and_clear_pending(&self, start_index: u32, count: u32) -> Result<()> {
        let res = self
            .c
            .set_bitmap_ready_and_clear_pending(start_index, count);
        self.clear_bitmap_pending(start_index, count);
        res
    }

    fn clear_bitmap_pending(&self, start_index: u32, count: u32) {
        let count = std::cmp::min(count, u32::MAX - start_index);
        let end = start_index + count;
        let mut guard = self.inflight_tracer.lock().unwrap();

        for index in start_index..end {
            if let Some(i) = guard.remove(&index) {
                i.done();
            }
        }
    }

    fn wait_for_bitmap_ready(&self, start_index: u32, count: u32) -> Result<bool> {
        let count = std::cmp::min(count, u32::MAX - start_index);
        let end = start_index + count;
        if self.is_bitmap_ready(start_index, count)? {
            return Ok(true);
        }

        let mut guard = self.inflight_tracer.lock().unwrap();
        for index in start_index..end {
            if let Some(i) = guard.get(&index).cloned() {
                drop(guard);
                let result =
                    i.wait_for_inflight(Duration::from_millis(SINGLE_INFLIGHT_WAIT_TIMEOUT));
                if let Err(StorageError::Timeout) = result {
                    /*
                    // Notice that lock of tracer is already dropped.
                    let mut t = self.inflight_tracer.lock().unwrap();
                    t.remove(&index);
                    i.notify();
                     */
                    warn!("Waiting for backend IO expires. chunk index {}", index,);
                    break;
                };
                if !self.c.is_bitmap_ready(index, 1)? {
                    return Ok(false);
                }
                guard = self.inflight_tracer.lock().unwrap();
            }
        }

        self.is_bitmap_ready(start_index, count)
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

        fn blob_index(&self) -> u32 {
            0
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

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn test_chunk_map() {
        let dir = TempDir::new().unwrap();
        let blob_path = dir.as_path().join("blob-1");
        let blob_path = blob_path.as_os_str().to_str().unwrap().to_string();
        let chunk_count = 1000000;
        let skip_index = 77;

        let indexed_chunk_map1 = Arc::new(BlobChunkMap::from(
            IndexedChunkMap::new(&blob_path, chunk_count).unwrap(),
        ));
        let indexed_chunk_map2 = Arc::new(BlobChunkMap::from(
            IndexedChunkMap::new(&blob_path, chunk_count).unwrap(),
        ));
        let indexed_chunk_map3 = Arc::new(BlobChunkMap::from(
            IndexedChunkMap::new(&blob_path, chunk_count).unwrap(),
        ));

        let now = Instant::now();

        let h1 = thread::spawn(move || {
            for idx in 0..chunk_count {
                let chunk = Chunk::new(idx);
                if idx % skip_index != 0 {
                    indexed_chunk_map1
                        .set_ready_and_clear_pending(chunk.as_ref())
                        .unwrap();
                }
            }
        });

        let h2 = thread::spawn(move || {
            for idx in 0..chunk_count {
                let chunk = Chunk::new(idx);
                if idx % skip_index != 0 {
                    indexed_chunk_map2
                        .set_ready_and_clear_pending(chunk.as_ref())
                        .unwrap();
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

            let has_ready = indexed_chunk_map3
                .check_ready_and_mark_pending(chunk.as_ref())
                .unwrap();
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
            chunk_map
                .set_ready_and_clear_pending(chunks[idx as usize].as_ref())
                .unwrap();
        }
        for idx in 0..chunk_count {
            assert_eq!(
                chunk_map
                    .check_ready_and_mark_pending(chunks[idx as usize].as_ref())
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

        let indexed_chunk_map =
            BlobChunkMap::from(IndexedChunkMap::new(&blob_path, chunk_count).unwrap());
        let now = Instant::now();
        iterate(&chunks, &indexed_chunk_map as &dyn ChunkMap, chunk_count);
        let elapsed1 = now.elapsed().as_millis();

        let digested_chunk_map = BlobChunkMap::from(DigestedChunkMap::new());
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
        index_map
            .check_ready_and_mark_pending(chunk_1.as_ref())
            .unwrap();
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 1);
        index_map
            .check_ready_and_mark_pending(chunk_2.as_ref())
            .unwrap();
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 2);
        index_map
            .check_ready_and_mark_pending(chunk_1.as_ref())
            .unwrap_err();
        index_map
            .check_ready_and_mark_pending(chunk_2.as_ref())
            .unwrap_err();
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 2);

        index_map
            .set_ready_and_clear_pending(chunk_1.as_ref())
            .unwrap();
        assert_eq!(
            index_map
                .check_ready_and_mark_pending(chunk_1.as_ref())
                .unwrap(),
            true
        );
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 1);

        index_map.clear_pending(chunk_2.as_ref());
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 0);
        assert_eq!(
            index_map
                .check_ready_and_mark_pending(chunk_2.as_ref())
                .unwrap(),
            false
        );
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 1);
        index_map.clear_pending(chunk_2.as_ref());
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 0);
        index_map
            .set_ready_and_clear_pending(chunk_2.as_ref())
            .unwrap();
        assert_eq!(
            index_map
                .check_ready_and_mark_pending(chunk_2.as_ref())
                .unwrap(),
            true
        );
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 0);

        // digested ChunkMap
        let digest_map = Arc::new(BlobChunkMap::from(DigestedChunkMap::new()));
        digest_map
            .check_ready_and_mark_pending(chunk_1.as_ref())
            .unwrap();
        assert_eq!(digest_map.inflight_tracer.lock().unwrap().len(), 1);
        digest_map
            .check_ready_and_mark_pending(chunk_2.as_ref())
            .unwrap();
        assert_eq!(digest_map.inflight_tracer.lock().unwrap().len(), 2);
        digest_map
            .check_ready_and_mark_pending(chunk_1.as_ref())
            .unwrap_err();
        digest_map
            .check_ready_and_mark_pending(chunk_2.as_ref())
            .unwrap_err();
        digest_map
            .set_ready_and_clear_pending(chunk_1.as_ref())
            .unwrap();
        assert_eq!(
            digest_map
                .check_ready_and_mark_pending(chunk_1.as_ref())
                .unwrap(),
            true
        );
        digest_map.clear_pending(chunk_2.as_ref());
        assert_eq!(
            digest_map
                .check_ready_and_mark_pending(chunk_2.as_ref())
                .unwrap(),
            false
        );
        digest_map.clear_pending(chunk_2.as_ref());
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
            map.as_ref()
                .check_ready_and_mark_pending(chunk_4.as_ref())
                .unwrap(),
            false
        );
        let map_cloned = map.clone();
        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 1);

        let chunk_4_cloned = chunk_4.clone();
        let t1 = thread::Builder::new()
            .spawn(move || {
                for _ in 0..4 {
                    let ready = map_cloned
                        .check_ready_and_mark_pending(chunk_4_cloned.as_ref())
                        .unwrap();
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
                        .check_ready_and_mark_pending(chunk_4_cloned_2.as_ref())
                        .unwrap();
                    assert_eq!(ready, true);
                }
            })
            .unwrap();

        thread::sleep(Duration::from_secs(1));

        map.set_ready_and_clear_pending(chunk_4.as_ref()).unwrap();

        // Fuzz
        map.set_ready_and_clear_pending(chunk_4.as_ref()).unwrap();
        map.set_ready_and_clear_pending(chunk_4.as_ref()).unwrap();

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

        map.as_ref()
            .check_ready_and_mark_pending(chunk_4.as_ref())
            .unwrap();
        let map_cloned = map.clone();

        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 1);

        let chunk_4_cloned = chunk_4.clone();
        let t1 = thread::Builder::new()
            .spawn(move || {
                for _ in 0..4 {
                    map_cloned
                        .check_ready_and_mark_pending(chunk_4_cloned.as_ref())
                        .unwrap_err();
                }
            })
            .unwrap();

        t1.join().unwrap();

        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 1);

        map.as_ref()
            .check_ready_and_mark_pending(chunk_4.as_ref())
            .unwrap_err();
        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 1);

        map.clear_pending(chunk_4.as_ref());
        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_inflight_tracer_race_bitmap() {
        let tmp_file = TempFile::new().unwrap();
        let map = Arc::new(BlobChunkMap::from(
            IndexedChunkMap::new(tmp_file.as_path().to_str().unwrap(), 10).unwrap(),
        ));

        assert_eq!(map.is_bitmap_all_ready(), false);
        assert_eq!(map.is_bitmap_ready(0, 1).unwrap(), false);
        assert_eq!(map.is_bitmap_ready(9, 1).unwrap(), false);
        assert!(map.is_bitmap_ready(10, 1).is_err());
        assert_eq!(
            map.check_bitmap_ready_and_mark_pending(0, 2).unwrap(),
            Some(vec![0, 1])
        );
        map.set_bitmap_ready_and_clear_pending(0, 2).unwrap();
        assert_eq!(map.check_bitmap_ready_and_mark_pending(0, 2).unwrap(), None);
        map.wait_for_bitmap_ready(0, 2).unwrap();
        assert_eq!(
            map.check_bitmap_ready_and_mark_pending(1, 2).unwrap(),
            Some(vec![2])
        );
        map.set_bitmap_ready_and_clear_pending(2, 1).unwrap();
        map.set_bitmap_ready_and_clear_pending(3, 7).unwrap();
        assert_eq!(map.is_bitmap_ready(0, 1).unwrap(), true);
        assert_eq!(map.is_bitmap_ready(9, 1).unwrap(), true);
        assert_eq!(map.is_bitmap_all_ready(), true);
    }
}
