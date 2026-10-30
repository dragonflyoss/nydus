// Copyright 2021 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::io::Result;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::cache::state::{
    BlobRangeMap, ChunkIndexGetter, ChunkMap, IndexedChunkMap, PendingRange, RangeMap,
};
use crate::cache::SINGLE_INFLIGHT_WAIT_TIMEOUT;
use crate::device::BlobChunkInfo;
use crate::{StorageError, StorageResult};

#[derive(PartialEq, Copy, Clone)]
enum Status {
    Inflight,
    Complete,
}

struct Slot {
    state: Mutex<Status>,
    condvar: Condvar,
    completion_guarded: bool,
}

impl Slot {
    fn new() -> Self {
        Slot {
            state: Mutex::new(Status::Inflight),
            condvar: Condvar::new(),
            completion_guarded: false,
        }
    }

    fn notify(&self) {
        self.condvar.notify_all();
    }

    fn done(&self) {
        // Not expect poisoned lock here
        *self.state.lock().unwrap() = Status::Complete;
        self.notify();
    }

    fn wait_for_inflight(&self, timeout: Duration) -> StorageResult<Status> {
        let mut state = self.state.lock().unwrap();

        while *state == Status::Inflight {
            if self.completion_guarded {
                state = self.condvar.wait(state).unwrap();
                continue;
            }
            // Do not expect poisoned lock, so unwrap here.
            let (next, result) = self.condvar.wait_timeout(state, timeout).unwrap();
            state = next;
            if result.timed_out() {
                return Err(StorageError::Timeout);
            }
        }

        Ok(*state)
    }
}

/// Adapter structure to enable concurrent chunk readiness manipulating based on a base [ChunkMap]
/// object.
///
/// A base [ChunkMap], such as [IndexedChunkMap](../chunk_indexed/struct.IndexedChunkMap.html), only
/// tracks chunk readiness state, but doesn't support concurrent manipulating of the chunk readiness
/// state. The `BlobStateMap` structure acts as an adapter to enable concurrent chunk readiness
/// state manipulation.
pub struct BlobStateMap<C, I> {
    c: C,
    inflight_tracer: Mutex<HashMap<I, Arc<Slot>>>,
}

impl<C, I> From<C> for BlobStateMap<C, I>
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

impl<C, I> ChunkMap for BlobStateMap<C, I>
where
    C: ChunkMap + ChunkIndexGetter<Index = I>,
    I: Eq + Hash + Display + Send + 'static,
{
    fn is_ready(&self, chunk: &dyn BlobChunkInfo) -> Result<bool> {
        self.c.is_ready(chunk)
    }

    fn is_pending(&self, chunk: &dyn BlobChunkInfo) -> Result<bool> {
        let index = C::get_index(chunk);
        Ok(self.inflight_tracer.lock().unwrap().get(&index).is_some())
    }

    fn check_ready_and_mark_pending(&self, chunk: &dyn BlobChunkInfo) -> StorageResult<bool> {
        let mut ready = self.c.is_ready(chunk).map_err(StorageError::CacheIndex)?;

        if ready {
            return Ok(true);
        }

        let index = C::get_index(chunk);
        let mut guard = self.inflight_tracer.lock().unwrap();

        if let Some(i) = guard.get(&index).cloned() {
            drop(guard);
            let result = i.wait_for_inflight(Duration::from_millis(SINGLE_INFLIGHT_WAIT_TIMEOUT));
            if let Err(StorageError::Timeout) = result {
                warn!(
                    "Waiting for backend IO expires. chunk index {}, compressed offset {}",
                    index,
                    chunk.compressed_offset()
                );

                Err(StorageError::Timeout)
            } else {
                // Check if the chunk is ready in local cache again. It should be READY
                // since wait_for_inflight must return OK in this branch by one more check.
                self.check_ready_and_mark_pending(chunk)
            }
        } else {
            // Double check to close the window where prior slot was just removed after backend IO
            // returned.
            if self.c.is_ready(chunk).map_err(StorageError::CacheIndex)? {
                ready = true;
            } else {
                guard.insert(index, Arc::new(Slot::new()));
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

    fn is_persist(&self) -> bool {
        self.c.is_persist()
    }

    fn as_range_map(&self) -> Option<&dyn RangeMap<I = u32>> {
        let any = self as &dyn Any;

        any.downcast_ref::<BlobStateMap<IndexedChunkMap, u32>>()
            .map(|v| v as &dyn RangeMap<I = u32>)
    }
}

impl<C, I> BlobStateMap<C, I>
where
    C: RangeMap<I = I>,
    I: Copy + Eq + Hash + Send + From<u8>,
{
    fn claim_range(&self, start: I, count: I) -> Result<Option<PendingRange<'_, I>>> {
        let Some(pending) = self.c.check_range_ready_and_mark_pending(start, count)? else {
            return Ok(None);
        };

        let mut guard = self.inflight_tracer.lock().unwrap();
        let mut indices = Vec::with_capacity(pending.len());
        for index in pending.iter() {
            if !guard.contains_key(index) && !self.c.is_range_ready(*index, I::from(1))? {
                indices.push(*index);
            }
        }
        if indices.is_empty() {
            return Ok(Some(PendingRange::new(indices)));
        }
        let mut owned = Vec::with_capacity(indices.len());
        for index in &indices {
            let slot = Arc::new(Slot {
                completion_guarded: true,
                ..Slot::new()
            });
            guard.insert(*index, slot.clone());
            owned.push((*index, slot));
        }
        drop(guard);
        Ok(Some(PendingRange::with_cleanup(indices, move || {
            let mut guard = self.inflight_tracer.lock().unwrap();
            for (index, slot) in owned {
                if guard
                    .get(&index)
                    .is_some_and(|current| Arc::ptr_eq(current, &slot))
                {
                    guard.remove(&index);
                    slot.done();
                }
            }
        })))
    }
}

impl RangeMap for BlobStateMap<IndexedChunkMap, u32> {
    type I = u32;

    fn is_range_all_ready(&self) -> bool {
        self.c.is_range_all_ready()
    }

    fn is_range_ready(&self, start: Self::I, count: Self::I) -> Result<bool> {
        self.c.is_range_ready(start, count)
    }

    fn check_range_ready_and_mark_pending(
        &self,
        start: Self::I,
        count: Self::I,
    ) -> Result<Option<PendingRange<'_, Self::I>>> {
        self.claim_range(start, count)
    }

    fn set_range_ready_and_clear_pending(&self, start: Self::I, count: Self::I) -> Result<()> {
        let res = self.c.set_range_ready_and_clear_pending(start, count);
        self.clear_range_pending(start, count);
        res
    }

    fn clear_range_pending(&self, start: Self::I, count: Self::I) {
        let count = std::cmp::min(count, u32::MAX - start);
        let end = start + count;
        let mut guard = self.inflight_tracer.lock().unwrap();

        for index in start..end {
            if let Some(i) = guard.remove(&index) {
                i.done();
            }
        }
    }

    fn wait_for_range_ready(&self, start: Self::I, count: Self::I) -> Result<bool> {
        let count = std::cmp::min(count, u32::MAX - start);
        let end = start + count;
        if self.is_range_ready(start, count)? {
            return Ok(true);
        }

        let mut guard = self.inflight_tracer.lock().unwrap();
        for index in start..end {
            if let Some(i) = guard.get(&index).cloned() {
                drop(guard);
                let result =
                    i.wait_for_inflight(Duration::from_millis(SINGLE_INFLIGHT_WAIT_TIMEOUT));
                if let Err(StorageError::Timeout) = result {
                    warn!(
                        "Waiting for range backend IO expires. chunk index {}. range[{}, {}]",
                        index, start, count
                    );
                    break;
                };
                if !self.c.is_range_ready(index, 1)? {
                    return Ok(false);
                }
                guard = self.inflight_tracer.lock().unwrap();
            }
        }

        self.is_range_ready(start, count)
    }
}

impl RangeMap for BlobStateMap<BlobRangeMap, u64> {
    type I = u64;

    fn is_range_all_ready(&self) -> bool {
        self.c.is_range_all_ready()
    }

    fn is_range_ready(&self, start: Self::I, count: Self::I) -> Result<bool> {
        self.c.is_range_ready(start, count)
    }

    fn check_range_ready_and_mark_pending(
        &self,
        start: Self::I,
        count: Self::I,
    ) -> Result<Option<PendingRange<'_, Self::I>>> {
        self.claim_range(start, count)
    }

    fn set_range_ready_and_clear_pending(&self, start: Self::I, count: Self::I) -> Result<()> {
        let res = self.c.set_range_ready_and_clear_pending(start, count);
        self.clear_range_pending(start, count);
        res
    }

    fn clear_range_pending(&self, start: Self::I, count: Self::I) {
        let (start_index, end_index) = match self.c.get_range(start, count) {
            Ok(v) => v,
            Err(_) => {
                debug_assert!(false);
                return;
            }
        };

        let mut guard = self.inflight_tracer.lock().unwrap();
        for index in start_index..end_index {
            let idx = (index as u64) << self.c.shift;
            if let Some(i) = guard.remove(&idx) {
                i.done();
            }
        }
    }

    fn wait_for_range_ready(&self, start: Self::I, count: Self::I) -> Result<bool> {
        if self.c.is_range_ready(start, count)? {
            return Ok(true);
        }

        let (start_index, end_index) = self.c.get_range(start, count)?;
        let mut guard = self.inflight_tracer.lock().unwrap();
        for index in start_index..end_index {
            let idx = (index as u64) << self.c.shift;
            if let Some(i) = guard.get(&idx).cloned() {
                drop(guard);
                let result =
                    i.wait_for_inflight(Duration::from_millis(SINGLE_INFLIGHT_WAIT_TIMEOUT));
                if let Err(StorageError::Timeout) = result {
                    warn!(
                        "Waiting for range backend IO expires. chunk index {}. range[{}, {}]",
                        index, start, count
                    );
                    break;
                };
                if !self.c.is_range_ready(idx, 1)? {
                    return Ok(false);
                }
                guard = self.inflight_tracer.lock().unwrap();
            }
        }

        self.c.is_range_ready(start, count)
    }
}

impl BlobStateMap<BlobRangeMap, u64> {
    /// Create a new instance of `BlobStateMap` from a `BlobRangeMap` object.
    pub fn from_range_map(map: BlobRangeMap) -> Self {
        Self {
            c: map,
            inflight_tracer: Mutex::new(HashMap::new()),
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
    use crate::cache::state::DigestedChunkMap;
    use crate::device::BlobChunkInfo;
    use crate::test::MockChunkInfo;

    pub(crate) fn pending_slot_references(map: &dyn ChunkMap, index: u32) -> impl Fn() -> usize {
        let map = (map as &dyn Any)
            .downcast_ref::<BlobStateMap<IndexedChunkMap, u32>>()
            .unwrap();
        let slot = map
            .inflight_tracer
            .lock()
            .unwrap()
            .get(&index)
            .unwrap()
            .clone();
        move || Arc::strong_count(&slot)
    }

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

        fn compressed_offset(&self) -> u64 {
            unimplemented!();
        }

        fn compressed_size(&self) -> u32 {
            unimplemented!();
        }

        fn uncompressed_offset(&self) -> u64 {
            unimplemented!();
        }

        fn uncompressed_size(&self) -> u32 {
            unimplemented!();
        }

        fn is_batch(&self) -> bool {
            unimplemented!();
        }

        fn is_compressed(&self) -> bool {
            unimplemented!();
        }

        fn is_encrypted(&self) -> bool {
            false
        }

        fn has_crc32(&self) -> bool {
            unimplemented!();
        }

        fn crc32(&self) -> u32 {
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

        let indexed_chunk_map1 = Arc::new(BlobStateMap::from(
            IndexedChunkMap::new(&blob_path, chunk_count, true).unwrap(),
        ));
        let indexed_chunk_map2 = Arc::new(BlobStateMap::from(
            IndexedChunkMap::new(&blob_path, chunk_count, true).unwrap(),
        ));
        let indexed_chunk_map3 = Arc::new(BlobStateMap::from(
            IndexedChunkMap::new(&blob_path, chunk_count, true).unwrap(),
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
            assert!(chunk_map
                .check_ready_and_mark_pending(chunks[idx as usize].as_ref())
                .unwrap(),);
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
            BlobStateMap::from(IndexedChunkMap::new(&blob_path, chunk_count, true).unwrap());
        let now = Instant::now();
        iterate(&chunks, &indexed_chunk_map as &dyn ChunkMap, chunk_count);
        let elapsed1 = now.elapsed().as_millis();

        let digested_chunk_map = BlobStateMap::from(DigestedChunkMap::new());
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
        let index_map = Arc::new(BlobStateMap::from(
            IndexedChunkMap::new(tmp_file.as_path().to_str().unwrap(), 10, true).unwrap(),
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
        assert!(index_map
            .check_ready_and_mark_pending(chunk_1.as_ref())
            .unwrap(),);
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 1);

        index_map.clear_pending(chunk_2.as_ref());
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 0);
        assert!(!index_map
            .check_ready_and_mark_pending(chunk_2.as_ref())
            .unwrap(),);
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 1);
        index_map.clear_pending(chunk_2.as_ref());
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 0);
        index_map
            .set_ready_and_clear_pending(chunk_2.as_ref())
            .unwrap();
        assert!(index_map
            .check_ready_and_mark_pending(chunk_2.as_ref())
            .unwrap(),);
        assert_eq!(index_map.inflight_tracer.lock().unwrap().len(), 0);

        // digested ChunkMap
        let digest_map = Arc::new(BlobStateMap::from(DigestedChunkMap::new()));
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
        assert!(digest_map
            .check_ready_and_mark_pending(chunk_1.as_ref())
            .unwrap(),);
        digest_map.clear_pending(chunk_2.as_ref());
        assert!(!digest_map
            .check_ready_and_mark_pending(chunk_2.as_ref())
            .unwrap(),);
        digest_map.clear_pending(chunk_2.as_ref());
        assert_eq!(digest_map.inflight_tracer.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_inflight_tracer_race() {
        let tmp_file = TempFile::new().unwrap();
        let map = Arc::new(BlobStateMap::from(
            IndexedChunkMap::new(tmp_file.as_path().to_str().unwrap(), 10, true).unwrap(),
        ));

        let chunk_4: Arc<dyn BlobChunkInfo> = Arc::new({
            let mut c = MockChunkInfo::new();
            c.index = 4;
            c
        });

        assert!(!map
            .as_ref()
            .check_ready_and_mark_pending(chunk_4.as_ref())
            .unwrap(),);
        let map_cloned = map.clone();
        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 1);

        let chunk_4_cloned = chunk_4.clone();
        let t1 = thread::Builder::new()
            .spawn(move || {
                for _ in 0..4 {
                    let ready = map_cloned
                        .check_ready_and_mark_pending(chunk_4_cloned.as_ref())
                        .unwrap();
                    assert!(ready);
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
                    assert!(ready);
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
        let map = Arc::new(BlobStateMap::from(
            IndexedChunkMap::new(tmp_file.as_path().to_str().unwrap(), 10, true).unwrap(),
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

    fn check_range_owner_drop<C, I>(map: Arc<BlobStateMap<C, I>>, start: I, count: I)
    where
        C: Send + Sync + 'static,
        I: Copy + Eq + Hash + Send + Sync + 'static,
        BlobStateMap<C, I>: RangeMap<I = I>,
    {
        let pending = map
            .check_range_ready_and_mark_pending(start, count)
            .unwrap()
            .unwrap();
        let observer = map
            .check_range_ready_and_mark_pending(start, count)
            .unwrap()
            .unwrap();
        assert!(observer.is_empty());
        drop(observer);
        assert_eq!(map.inflight_tracer.lock().unwrap().len(), 1);

        let slot = map
            .inflight_tracer
            .lock()
            .unwrap()
            .get(&start)
            .unwrap()
            .clone();
        let (done, completed) = std::sync::mpsc::channel();
        let waiter = thread::spawn(move || {
            done.send(slot.wait_for_inflight(Duration::from_secs(1)))
                .unwrap();
        });
        drop(pending);
        assert!(
            completed
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap()
                == Status::Complete
        );
        waiter.join().unwrap();
        assert!(map.inflight_tracer.lock().unwrap().is_empty());
        assert!(!map.is_range_ready(start, count).unwrap());

        let original = map
            .check_range_ready_and_mark_pending(start, count)
            .unwrap()
            .unwrap();
        map.clear_range_pending(start, count);
        let successor = map
            .check_range_ready_and_mark_pending(start, count)
            .unwrap()
            .unwrap();
        let current = map
            .inflight_tracer
            .lock()
            .unwrap()
            .get(&start)
            .unwrap()
            .clone();
        drop(original);
        assert!(Arc::ptr_eq(
            map.inflight_tracer.lock().unwrap().get(&start).unwrap(),
            &current
        ));
        drop(successor);
        assert!(map.inflight_tracer.lock().unwrap().is_empty());
    }

    #[test]
    fn test_range_owner_drop() {
        let tmp_file = TempFile::new().unwrap();
        let path = tmp_file.as_path().to_str().unwrap();
        check_range_owner_drop(
            Arc::new(BlobStateMap::from(
                IndexedChunkMap::new(path, 2, true).unwrap(),
            )),
            0,
            1,
        );
        check_range_owner_drop(
            Arc::new(BlobStateMap::from_range_map(
                BlobRangeMap::new(path, 2, 12).unwrap(),
            )),
            0,
            4096,
        );
    }

    fn check_range_completion<C, I>(map: Arc<BlobStateMap<C, I>>, start: I, count: I)
    where
        C: Send + Sync + 'static,
        I: Copy + Eq + Hash + Send + Sync + 'static,
        BlobStateMap<C, I>: RangeMap<I = I>,
    {
        let pending = map
            .check_range_ready_and_mark_pending(start, count)
            .unwrap()
            .unwrap();
        let slot = map
            .inflight_tracer
            .lock()
            .unwrap()
            .get(&start)
            .unwrap()
            .clone();
        let owners = Arc::strong_count(&slot);
        let (done, completed) = std::sync::mpsc::channel();
        let waiting = map.clone();
        let waiter = thread::spawn(move || {
            let result = waiting.wait_for_range_ready(start, count);
            done.send(result).unwrap();
        });
        let started = Instant::now();
        while Arc::strong_count(&slot) == owners {
            assert!(started.elapsed() < Duration::from_secs(1));
            thread::yield_now();
        }
        let timeout = Duration::from_millis(SINGLE_INFLIGHT_WAIT_TIMEOUT + 200);
        let premature = completed.recv_timeout(timeout).ok();
        map.set_range_ready_and_clear_pending(start, count).unwrap();
        drop(pending);
        assert!(
            premature.is_none(),
            "active producer was reported as failed"
        );
        assert!(completed
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap());
        waiter.join().unwrap();
        assert!(map
            .check_range_ready_and_mark_pending(start, count)
            .unwrap()
            .is_none());
        assert!(map.inflight_tracer.lock().unwrap().is_empty());
    }

    #[test]
    fn test_range_waits_for_producer() {
        let tmp_file = TempFile::new().unwrap();
        let path = tmp_file.as_path().to_str().unwrap();
        check_range_completion(
            Arc::new(BlobStateMap::from(
                IndexedChunkMap::new(path, 2, true).unwrap(),
            )),
            0,
            1,
        );
        check_range_completion(
            Arc::new(BlobStateMap::from_range_map(
                BlobRangeMap::new(path, 2, 12).unwrap(),
            )),
            0,
            4096,
        );
    }

    #[test]
    fn test_chunk_reader_follows_range_producer() {
        for success in [true, false] {
            let tmp_file = TempFile::new().unwrap();
            let map = Arc::new(BlobStateMap::from(
                IndexedChunkMap::new(tmp_file.as_path().to_str().unwrap(), 1, false).unwrap(),
            ));
            let chunk = Arc::new(MockChunkInfo::default());
            let pending = map
                .check_range_ready_and_mark_pending(0, 1)
                .unwrap()
                .unwrap();
            let references = pending_slot_references(map.as_ref(), 0);
            let before = references();
            let waiting = map.clone();
            let waiting_chunk = chunk.clone();
            let (done, completed) = std::sync::mpsc::channel();
            let waiter = thread::spawn(move || {
                done.send(waiting.check_ready_and_mark_pending(waiting_chunk.as_ref()))
                    .unwrap();
            });
            let started = Instant::now();
            while references() == before {
                assert!(started.elapsed() < Duration::from_secs(1));
                thread::yield_now();
            }
            let premature = completed
                .recv_timeout(Duration::from_millis(SINGLE_INFLIGHT_WAIT_TIMEOUT + 200))
                .ok();
            if success {
                map.set_range_ready_and_clear_pending(0, 1).unwrap();
            }
            drop(pending);
            assert!(
                premature.is_none(),
                "chunk reader abandoned a range producer"
            );
            assert_eq!(
                completed
                    .recv_timeout(Duration::from_secs(1))
                    .unwrap()
                    .unwrap(),
                success
            );
            waiter.join().unwrap();
            if !success {
                assert!(map.is_pending(chunk.as_ref()).unwrap());
                map.clear_pending(chunk.as_ref());
            }
            assert!(map.inflight_tracer.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn test_range_completion_with_competing_waiters() {
        const WAITERS: usize = 4;
        const ROUNDS: u32 = 64;
        let tmp_file = TempFile::new().unwrap();
        let map = Arc::new(BlobStateMap::from(
            IndexedChunkMap::new(tmp_file.as_path().to_str().unwrap(), ROUNDS, false).unwrap(),
        ));
        for index in 0..ROUNDS {
            let pending = map
                .check_range_ready_and_mark_pending(index, 1)
                .unwrap()
                .unwrap();
            let references = pending_slot_references(map.as_ref(), index);
            let before = references();
            let mut waiters = Vec::new();
            let mut completions = Vec::new();
            for _ in 0..WAITERS {
                let waiting = map.clone();
                let (done, completed) = std::sync::mpsc::channel();
                waiters.push(thread::spawn(move || {
                    let observer = waiting
                        .check_range_ready_and_mark_pending(index, 1)
                        .unwrap()
                        .unwrap();
                    assert!(observer.is_empty());
                    drop(observer);
                    done.send(waiting.wait_for_range_ready(index, 1)).unwrap();
                }));
                completions.push(completed);
            }
            let started = Instant::now();
            while references() < before + WAITERS {
                assert!(started.elapsed() < Duration::from_secs(1));
                thread::yield_now();
            }
            let success = index % 2 == 0;
            if success {
                map.set_range_ready_and_clear_pending(index, 1).unwrap();
            }
            drop(pending);
            for completed in completions {
                assert_eq!(
                    completed
                        .recv_timeout(Duration::from_secs(1))
                        .unwrap()
                        .unwrap(),
                    success
                );
            }
            for waiter in waiters {
                waiter.join().unwrap();
            }
            assert!(map.inflight_tracer.lock().unwrap().is_empty());
            if !success {
                let retry = map
                    .check_range_ready_and_mark_pending(index, 1)
                    .unwrap()
                    .unwrap();
                assert_eq!(&*retry, &[index]);
            }
        }
    }

    #[test]
    fn test_inflight_tracer_race_range() {
        let tmp_file = TempFile::new().unwrap();
        let map = Arc::new(BlobStateMap::from(
            IndexedChunkMap::new(tmp_file.as_path().to_str().unwrap(), 10, true).unwrap(),
        ));

        assert!(!map.is_range_all_ready());
        assert!(!map.is_range_ready(0, 1).unwrap());
        assert!(!map.is_range_ready(9, 1).unwrap());
        assert!(map.is_range_ready(10, 1).is_err());
        let pending = map
            .check_range_ready_and_mark_pending(0, 2)
            .unwrap()
            .unwrap();
        assert_eq!(&*pending, &[0, 1]);
        map.set_range_ready_and_clear_pending(0, 2).unwrap();
        assert!(map
            .check_range_ready_and_mark_pending(0, 2)
            .unwrap()
            .is_none());
        map.wait_for_range_ready(0, 2).unwrap();
        let next = map
            .check_range_ready_and_mark_pending(1, 2)
            .unwrap()
            .unwrap();
        assert_eq!(&*next, &[2]);
        map.set_range_ready_and_clear_pending(2, 1).unwrap();
        map.set_range_ready_and_clear_pending(3, 7).unwrap();
        assert!(map.is_range_ready(0, 1).unwrap());
        assert!(map.is_range_ready(9, 1).unwrap());
        assert!(map.is_range_all_ready());
    }
}
