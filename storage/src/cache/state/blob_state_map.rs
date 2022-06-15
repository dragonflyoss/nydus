// Copyright 2021 Ant Group. All rights reserved.
// Copyright (C) 2021-2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::io::Result;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, MutexGuard, Notify};

use crate::cache::state::{BlobRangeMap, ChunkIndexGetter, ChunkMap, IndexedChunkMap, RangeMap};
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
    condvar: Notify,
}

impl Slot {
    fn new() -> Self {
        Slot {
            state: Mutex::new(Status::Inflight),
            condvar: Notify::new(),
        }
    }

    fn notify(&self) {
        self.condvar.notify_waiters();
    }

    async fn done(&self) {
        *self.lock().await = Status::Complete;
        self.notify();
    }

    async fn async_wait_for_inflight(&self, mut timeout: Duration) -> StorageResult<Status> {
        let mut state = self.lock().await;

        while *state == Status::Inflight {
            let notifier = self.condvar.notified();
            tokio::pin!(notifier);

            // Asynchronous version of condvar
            notifier.as_mut().enable();
            drop(state);
            let start = std::time::Instant::now();
            if tokio::time::timeout(timeout, notifier).await.is_err() {
                return Err(StorageError::Timeout);
            }
            let elapsed = start.elapsed();
            if elapsed < timeout {
                timeout -= elapsed;
            } else {
                timeout = Duration::from_millis(0);
            }
            state = self.lock().await;
        }

        Ok(*state)
    }

    async fn lock(&self) -> MutexGuard<'_, Status> {
        // Not expect poisoned lock here
        self.state.lock().await
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

#[async_trait::async_trait]
impl<C, I> ChunkMap for BlobStateMap<C, I>
where
    C: ChunkMap + ChunkIndexGetter<Index = I>,
    I: Eq + Hash + Display + Send + 'static,
{
    fn is_ready(&self, chunk: &dyn BlobChunkInfo) -> Result<bool> {
        self.c.is_ready(chunk)
    }

    async fn async_check_ready_and_mark_pending(
        &self,
        chunk: &dyn BlobChunkInfo,
    ) -> StorageResult<bool> {
        let mut ready = self.c.is_ready(chunk).map_err(StorageError::CacheIndex)?;

        if ready {
            return Ok(true);
        }

        let index = C::get_index(chunk);
        let mut guard = self.inflight_tracer.lock().await;
        trace!("chunk index {}, tracer scale {}", index, guard.len());

        let s = guard.get(&index).cloned();
        if let Some(i) = s {
            drop(guard);
            let result = i
                .async_wait_for_inflight(Duration::from_millis(SINGLE_INFLIGHT_WAIT_TIMEOUT))
                .await;
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

                Err(StorageError::Timeout)
            } else {
                self.async_check_ready_and_mark_pending(chunk).await
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

    async fn async_set_ready_and_clear_pending(&self, chunk: &dyn BlobChunkInfo) -> Result<()> {
        let res = self.c.async_set_ready_and_clear_pending(chunk).await;
        self.async_clear_pending(chunk).await;
        res
    }

    async fn async_clear_pending(&self, chunk: &dyn BlobChunkInfo) {
        let index = C::get_index(chunk);
        let mut guard = self.inflight_tracer.lock().await;
        let entry = guard.remove(&index);
        if let Some(i) = entry {
            i.done().await;
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

#[async_trait::async_trait]
impl RangeMap for BlobStateMap<IndexedChunkMap, u32> {
    type I = u32;

    fn is_range_all_ready(&self) -> bool {
        self.c.is_range_all_ready()
    }

    fn is_range_ready(&self, start: Self::I, count: Self::I) -> Result<bool> {
        self.c.is_range_ready(start, count)
    }

    async fn async_check_range_ready_and_mark_pending(
        &self,
        start: Self::I,
        count: Self::I,
    ) -> Result<Option<Vec<Self::I>>> {
        let pending = match self
            .c
            .async_check_range_ready_and_mark_pending(start, count)
            .await
        {
            Err(e) => return Err(e),
            Ok(None) => return Ok(None),
            Ok(Some(v)) => {
                if v.is_empty() {
                    return Ok(None);
                }
                v
            }
        };

        let mut res = Vec::with_capacity(pending.len());
        let mut guard = self.inflight_tracer.lock().await;
        for index in pending.iter() {
            if guard.get(index).is_none() {
                // Double check to close the window where prior slot was just removed after backend
                // IO returned.
                if !self.c.is_range_ready(*index, 1)? {
                    guard.insert(*index, Arc::new(Slot::new()));
                    res.push(*index);
                }
            }
        }

        Ok(Some(res))
    }

    async fn async_set_range_ready_and_clear_pending(
        &self,
        start: Self::I,
        count: Self::I,
    ) -> Result<()> {
        let res = self
            .c
            .async_set_range_ready_and_clear_pending(start, count)
            .await;
        self.async_clear_range_pending(start, count).await;
        res
    }

    async fn async_clear_range_pending(&self, start: Self::I, count: Self::I) {
        let count = std::cmp::min(count, u32::MAX - start);
        let end = start + count;
        let mut guard = self.inflight_tracer.lock().await;

        for index in start..end {
            if let Some(i) = guard.remove(&index) {
                i.done().await;
            }
        }
    }

    async fn async_wait_for_range_ready(&self, start: Self::I, count: Self::I) -> Result<bool> {
        let count = std::cmp::min(count, u32::MAX - start);
        let end = start + count;
        if self.is_range_ready(start, count)? {
            return Ok(true);
        }

        let mut guard = self.inflight_tracer.lock().await;
        for index in start..end {
            if let Some(i) = guard.get(&index).cloned() {
                drop(guard);
                let result = i
                    .async_wait_for_inflight(Duration::from_millis(SINGLE_INFLIGHT_WAIT_TIMEOUT))
                    .await;
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
                if !self.c.is_range_ready(index, 1)? {
                    return Ok(false);
                }
                guard = self.inflight_tracer.lock().await;
            }
        }

        self.is_range_ready(start, count)
    }
}

#[async_trait::async_trait]
impl RangeMap for BlobStateMap<BlobRangeMap, u64> {
    type I = u64;

    fn is_range_all_ready(&self) -> bool {
        self.c.is_range_all_ready()
    }

    fn is_range_ready(&self, start: Self::I, count: Self::I) -> Result<bool> {
        self.c.is_range_ready(start, count)
    }

    async fn async_check_range_ready_and_mark_pending(
        &self,
        start: Self::I,
        count: Self::I,
    ) -> Result<Option<Vec<Self::I>>> {
        let pending = match self
            .c
            .async_check_range_ready_and_mark_pending(start, count)
            .await
        {
            Err(e) => return Err(e),
            Ok(None) => return Ok(None),
            Ok(Some(v)) => {
                if v.is_empty() {
                    return Ok(None);
                }
                v
            }
        };

        let mut res = Vec::with_capacity(pending.len());
        let mut guard = self.inflight_tracer.lock().await;
        for index in pending.iter() {
            if guard.get(index).is_none() {
                // Double check to close the window where prior slot was just removed after backend
                // IO returned.
                if !self.c.is_range_ready(*index, 1)? {
                    guard.insert(*index, Arc::new(Slot::new()));
                    res.push(*index);
                }
            }
        }

        Ok(Some(res))
    }

    async fn async_set_range_ready_and_clear_pending(
        &self,
        start: Self::I,
        count: Self::I,
    ) -> Result<()> {
        let res = self
            .c
            .async_set_range_ready_and_clear_pending(start, count)
            .await;
        self.async_clear_range_pending(start, count).await;
        res
    }

    async fn async_clear_range_pending(&self, start: Self::I, count: Self::I) {
        let (start_index, end_index) = match self.c.get_range(start, count) {
            Ok(v) => v,
            Err(_) => {
                debug_assert!(false);
                return;
            }
        };

        let mut guard = self.inflight_tracer.lock().await;
        for index in start_index..end_index {
            let idx = (index as u64) << self.c.shift;
            if let Some(i) = guard.remove(&idx) {
                i.done().await;
            }
        }
    }

    async fn async_wait_for_range_ready(&self, start: Self::I, count: Self::I) -> Result<bool> {
        if self.c.is_range_ready(start, count)? {
            return Ok(true);
        }

        let (start_index, end_index) = self.c.get_range(start, count)?;
        let mut guard = self.inflight_tracer.lock().await;
        for index in start_index..end_index {
            let idx = (index as u64) << self.c.shift;
            if let Some(i) = guard.get(&idx).cloned() {
                drop(guard);
                let result = i
                    .async_wait_for_inflight(Duration::from_millis(SINGLE_INFLIGHT_WAIT_TIMEOUT))
                    .await;
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
                if !self.c.is_range_ready(idx, 1)? {
                    return Ok(false);
                }
                guard = self.inflight_tracer.lock().await;
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

    use nydus_utils::async_helper::with_runtime;
    use nydus_utils::digest::Algorithm::Blake3;
    use nydus_utils::digest::{Algorithm, RafsDigest};
    use vmm_sys_util::tempdir::TempDir;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::cache::state::DigestedChunkMap;
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

    #[tokio::test]
    async fn test_chunk_map() {
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
            with_runtime(|rt| {
                rt.block_on(async {
                    for idx in 0..chunk_count {
                        let chunk = Chunk::new(idx);
                        if idx % skip_index != 0 {
                            indexed_chunk_map1
                                .async_set_ready_and_clear_pending(chunk.as_ref())
                                .await
                                .unwrap();
                        }
                    }
                })
            });
        });

        let h2 = thread::spawn(move || {
            with_runtime(|rt| {
                rt.block_on(async {
                    for idx in 0..chunk_count {
                        let chunk = Chunk::new(idx);
                        if idx % skip_index != 0 {
                            indexed_chunk_map2
                                .async_set_ready_and_clear_pending(chunk.as_ref())
                                .await
                                .unwrap();
                        }
                    }
                })
            });
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
                .async_check_ready_and_mark_pending(chunk.as_ref())
                .await
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

    async fn iterate(chunks: &[Arc<Chunk>], chunk_map: &dyn ChunkMap, chunk_count: u32) {
        for idx in 0..chunk_count {
            chunk_map
                .async_set_ready_and_clear_pending(chunks[idx as usize].as_ref())
                .await
                .unwrap();
        }
        for idx in 0..chunk_count {
            assert!(chunk_map
                .async_check_ready_and_mark_pending(chunks[idx as usize].as_ref())
                .await
                .unwrap());
        }
    }

    #[tokio::test]
    async fn test_chunk_map_perf() {
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
        iterate(&chunks, &indexed_chunk_map as &dyn ChunkMap, chunk_count).await;
        let elapsed1 = now.elapsed().as_millis();

        let digested_chunk_map = BlobStateMap::from(DigestedChunkMap::new());
        let now = Instant::now();
        iterate(&chunks, &digested_chunk_map as &dyn ChunkMap, chunk_count).await;
        let elapsed2 = now.elapsed().as_millis();

        println!(
            "IndexedChunkMap vs DigestedChunkMap: {}ms vs {}ms",
            elapsed1, elapsed2
        );
    }

    #[tokio::test]
    async fn test_inflight_tracer() {
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
            .async_check_ready_and_mark_pending(chunk_1.as_ref())
            .await
            .unwrap();
        assert_eq!(index_map.inflight_tracer.lock().await.len(), 1);
        index_map
            .async_check_ready_and_mark_pending(chunk_2.as_ref())
            .await
            .unwrap();
        assert_eq!(index_map.inflight_tracer.lock().await.len(), 2);
        index_map
            .async_check_ready_and_mark_pending(chunk_1.as_ref())
            .await
            .unwrap_err();
        index_map
            .async_check_ready_and_mark_pending(chunk_2.as_ref())
            .await
            .unwrap_err();
        assert_eq!(index_map.inflight_tracer.lock().await.len(), 2);

        index_map
            .async_set_ready_and_clear_pending(chunk_1.as_ref())
            .await
            .unwrap();
        assert!(index_map
            .async_check_ready_and_mark_pending(chunk_1.as_ref())
            .await
            .unwrap(),);
        assert_eq!(index_map.inflight_tracer.lock().await.len(), 1);

        index_map.async_clear_pending(chunk_2.as_ref()).await;
        assert_eq!(index_map.inflight_tracer.lock().await.len(), 0);
        assert!(!index_map
            .async_check_ready_and_mark_pending(chunk_2.as_ref())
            .await
            .unwrap(),);
        assert_eq!(index_map.inflight_tracer.lock().await.len(), 1);
        index_map.async_clear_pending(chunk_2.as_ref()).await;
        assert_eq!(index_map.inflight_tracer.lock().await.len(), 0);
        index_map
            .async_set_ready_and_clear_pending(chunk_2.as_ref())
            .await
            .unwrap();
        assert!(index_map
            .async_check_ready_and_mark_pending(chunk_2.as_ref())
            .await
            .unwrap(),);
        assert_eq!(index_map.inflight_tracer.lock().await.len(), 0);

        // digested ChunkMap
        let digest_map = Arc::new(BlobStateMap::from(DigestedChunkMap::new()));
        digest_map
            .async_check_ready_and_mark_pending(chunk_1.as_ref())
            .await
            .unwrap();
        assert_eq!(digest_map.inflight_tracer.lock().await.len(), 1);
        digest_map
            .async_check_ready_and_mark_pending(chunk_2.as_ref())
            .await
            .unwrap();
        assert_eq!(digest_map.inflight_tracer.lock().await.len(), 2);
        digest_map
            .async_check_ready_and_mark_pending(chunk_1.as_ref())
            .await
            .unwrap_err();
        digest_map
            .async_check_ready_and_mark_pending(chunk_2.as_ref())
            .await
            .unwrap_err();
        digest_map
            .async_set_ready_and_clear_pending(chunk_1.as_ref())
            .await
            .unwrap();
        assert!(digest_map
            .async_check_ready_and_mark_pending(chunk_1.as_ref())
            .await
            .unwrap(),);
        digest_map.async_clear_pending(chunk_2.as_ref()).await;
        assert!(!digest_map
            .async_check_ready_and_mark_pending(chunk_2.as_ref())
            .await
            .unwrap(),);
        digest_map.async_clear_pending(chunk_2.as_ref()).await;
        assert_eq!(digest_map.inflight_tracer.lock().await.len(), 0);
    }

    #[tokio::test]
    async fn test_inflight_tracer_race() {
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
            .async_check_ready_and_mark_pending(chunk_4.as_ref())
            .await
            .unwrap(),);
        let map_cloned = map.clone();
        assert_eq!(map.inflight_tracer.lock().await.len(), 1);

        let chunk_4_cloned = chunk_4.clone();
        let t1 = thread::Builder::new()
            .spawn(move || {
                with_runtime(|rt| {
                    rt.block_on(async {
                        for _ in 0..4 {
                            let ready = map_cloned
                                .async_check_ready_and_mark_pending(chunk_4_cloned.as_ref())
                                .await
                                .unwrap();
                            assert!(ready);
                        }
                    })
                });
            })
            .unwrap();

        let map_cloned_2 = map.clone();
        let chunk_4_cloned_2 = chunk_4.clone();
        let t2 = thread::Builder::new()
            .spawn(move || {
                with_runtime(|rt| {
                    rt.block_on(async {
                        for _ in 0..2 {
                            let ready = map_cloned_2
                                .async_check_ready_and_mark_pending(chunk_4_cloned_2.as_ref())
                                .await
                                .unwrap();
                            assert!(ready);
                        }
                    })
                });
            })
            .unwrap();

        thread::sleep(Duration::from_secs(1));

        map.async_set_ready_and_clear_pending(chunk_4.as_ref())
            .await
            .unwrap();

        // Fuzz
        map.async_set_ready_and_clear_pending(chunk_4.as_ref())
            .await
            .unwrap();
        map.async_set_ready_and_clear_pending(chunk_4.as_ref())
            .await
            .unwrap();

        assert_eq!(map.inflight_tracer.lock().await.len(), 0);

        t1.join().unwrap();
        t2.join().unwrap();
    }

    #[tokio::test]
    /// Case description:
    ///     Never invoke `set_ready` method, thus to let each caller of `has_ready` reach
    ///     a point of timeout.
    /// Expect:
    ///     The chunk of index 4 is never marked as ready/downloaded.
    ///     Each caller of `has_ready` can escape from where it is blocked.
    ///     After timeout, no slot is left in inflight tracer.
    async fn test_inflight_tracer_timeout() {
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
            .async_check_ready_and_mark_pending(chunk_4.as_ref())
            .await
            .unwrap();
        let map_cloned = map.clone();

        assert_eq!(map.inflight_tracer.lock().await.len(), 1);

        let chunk_4_cloned = chunk_4.clone();
        let t1 = thread::Builder::new()
            .spawn(move || {
                with_runtime(|rt| {
                    rt.block_on(async {
                        for _ in 0..4 {
                            map_cloned
                                .async_check_ready_and_mark_pending(chunk_4_cloned.as_ref())
                                .await
                                .unwrap_err();
                        }
                    })
                });
            })
            .unwrap();

        t1.join().unwrap();

        assert_eq!(map.inflight_tracer.lock().await.len(), 1);

        map.as_ref()
            .async_check_ready_and_mark_pending(chunk_4.as_ref())
            .await
            .unwrap_err();
        assert_eq!(map.inflight_tracer.lock().await.len(), 1);

        map.async_clear_pending(chunk_4.as_ref()).await;
        assert_eq!(map.inflight_tracer.lock().await.len(), 0);
    }

    #[tokio::test]
    async fn test_inflight_tracer_race_range() {
        let tmp_file = TempFile::new().unwrap();
        let map = Arc::new(BlobStateMap::from(
            IndexedChunkMap::new(tmp_file.as_path().to_str().unwrap(), 10, true).unwrap(),
        ));

        assert!(!map.is_range_all_ready());
        assert!(!map.is_range_ready(0, 1).unwrap());
        assert!(!map.is_range_ready(9, 1).unwrap());
        assert!(map.is_range_ready(10, 1).is_err());
        assert_eq!(
            map.async_check_range_ready_and_mark_pending(0, 2)
                .await
                .unwrap(),
            Some(vec![0, 1])
        );
        map.async_set_range_ready_and_clear_pending(0, 2)
            .await
            .unwrap();
        assert_eq!(
            map.async_check_range_ready_and_mark_pending(0, 2)
                .await
                .unwrap(),
            None
        );
        map.async_wait_for_range_ready(0, 2).await.unwrap();
        assert_eq!(
            map.async_check_range_ready_and_mark_pending(1, 2)
                .await
                .unwrap(),
            Some(vec![2])
        );
        map.async_set_range_ready_and_clear_pending(2, 1)
            .await
            .unwrap();
        map.async_set_range_ready_and_clear_pending(3, 7)
            .await
            .unwrap();
        assert!(map.is_range_ready(0, 1).unwrap());
        assert!(map.is_range_ready(9, 1).unwrap());
        assert!(map.is_range_all_ready());
    }
}
