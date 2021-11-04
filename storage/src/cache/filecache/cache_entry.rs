// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Result, Seek, SeekFrom};
use std::mem::ManuallyDrop;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::slice;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use nix::sys::uio;
use nix::unistd::dup;
use nydus_utils::digest;
use nydus_utils::metrics::{BlobcacheMetrics, Metric};
use tokio::runtime::Runtime;
use vm_memory::VolatileSlice;

use crate::backend::BlobReader;
use crate::cache::filecache::FileCacheMgr;
use crate::cache::state::{BlobStateMap, ChunkMap, DigestedChunkMap, IndexedChunkMap};
use crate::cache::worker::{
    AsyncPrefetchConfig, AsyncRequestMessage, AsyncRequestState, AsyncWorkerMgr,
};
use crate::cache::{BlobCache, BlobIoMergeState};
use crate::device::{
    BlobChunkInfo, BlobFeatures, BlobInfo, BlobIoChunk, BlobIoDesc, BlobIoRange, BlobIoSegment,
    BlobIoTag, BlobIoVec, BlobObject, BlobPrefetchRequest,
};
use crate::meta::BlobMetaInfo;
use crate::utils::{alloc_buf, copyv, readv, MemSliceCursor};
use crate::{compress, StorageError, StorageResult, RAFS_DEFAULT_CHUNK_SIZE};

pub(crate) struct FileCacheEntry {
    blob_info: Arc<BlobInfo>,
    chunk_map: Arc<dyn ChunkMap>,
    file: Arc<File>,
    meta: Option<Arc<BlobMetaInfo>>,
    metrics: Arc<BlobcacheMetrics>,
    prefetch_state: Arc<AtomicU32>,
    reader: Arc<dyn BlobReader>,
    runtime: Arc<Runtime>,
    workers: Arc<AsyncWorkerMgr>,

    blob_size: u64,
    compressor: compress::Algorithm,
    digester: digest::Algorithm,
    // Whether `get_blob_object()` is supported.
    is_get_blob_object_supported: bool,
    // The compressed data instead of uncompressed data is cached if `compressed` is true.
    is_compressed: bool,
    // Whether direct chunkmap is used.
    is_direct_chunkmap: bool,
    // The blob is for an stargz image.
    is_stargz: bool,
    // Data from the file cache should be validated before use.
    need_validate: bool,
    prefetch_config: Arc<AsyncPrefetchConfig>,
}

impl FileCacheEntry {
    pub fn new(
        mgr: &FileCacheMgr,
        blob_info: Arc<BlobInfo>,
        prefetch_config: Arc<AsyncPrefetchConfig>,
        runtime: Arc<Runtime>,
        workers: Arc<AsyncWorkerMgr>,
    ) -> Result<Self> {
        let blob_file_path = format!("{}/{}", mgr.work_dir, blob_info.blob_id());
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(&blob_file_path)?;
        let (chunk_map, is_direct_chunkmap) =
            Self::create_chunk_map(mgr, &blob_info, &blob_file_path)?;
        let reader = mgr
            .backend
            .get_reader(blob_info.blob_id())
            .map_err(|_e| eio!("failed to get blob reader"))?;

        let blob_size = Self::get_blob_size(&reader, &blob_info)?;
        let compressor = blob_info.compressor();
        let digester = blob_info.digester();
        let is_stargz = blob_info.is_stargz();
        let is_compressed = mgr.is_compressed || is_stargz;
        let need_validate = (mgr.validate || !is_direct_chunkmap) && !is_stargz;
        let is_get_blob_object_supported = !mgr.is_compressed && is_direct_chunkmap && !is_stargz;

        let meta = if is_get_blob_object_supported && blob_info.meta_ci_is_valid() {
            Some(Arc::new(BlobMetaInfo::new(
                &blob_file_path,
                &blob_info,
                Some(&reader),
            )?))
        } else {
            None
        };

        Ok(FileCacheEntry {
            blob_info,
            chunk_map,
            file: Arc::new(file),
            meta,
            metrics: mgr.metrics.clone(),
            prefetch_state: Arc::new(AtomicU32::new(AsyncRequestState::Init as u32)),
            reader,
            runtime,
            workers,

            blob_size,
            compressor,
            digester,
            is_get_blob_object_supported,
            is_compressed,
            is_direct_chunkmap,
            is_stargz,
            need_validate,
            prefetch_config,
        })
    }

    fn create_chunk_map(
        mgr: &FileCacheMgr,
        blob_info: &BlobInfo,
        blob_file: &str,
    ) -> Result<(Arc<dyn ChunkMap>, bool)> {
        let mut direct_chunkmap = true;
        // The builder now records the number of chunks in the blob table, so we can
        // use IndexedChunkMap as a chunk map, but for the old Nydus bootstrap, we
        // need downgrade to use DigestedChunkMap as a compatible solution.
        let chunk_map: Arc<dyn ChunkMap> = if mgr.disable_indexed_map
            || blob_info.is_stargz()
            || blob_info.has_feature(BlobFeatures::V5_NO_EXT_BLOB_TABLE)
        {
            direct_chunkmap = false;
            Arc::new(BlobStateMap::from(DigestedChunkMap::new()))
        } else {
            Arc::new(BlobStateMap::from(IndexedChunkMap::new(
                blob_file,
                blob_info.chunk_count(),
            )?))
        };

        Ok((chunk_map, direct_chunkmap))
    }

    fn get_blob_size(reader: &Arc<dyn BlobReader>, blob_info: &BlobInfo) -> Result<u64> {
        // Stargz needs blob size information, so hacky!
        let size = if blob_info.is_stargz() {
            reader.blob_size().map_err(|e| einval!(e))?
        } else {
            0
        };

        Ok(size)
    }
}

impl BlobCache for FileCacheEntry {
    fn blob_id(&self) -> &str {
        self.blob_info.blob_id()
    }

    fn blob_size(&self) -> Result<u64> {
        Ok(self.blob_size)
    }

    fn compressor(&self) -> compress::Algorithm {
        self.compressor
    }

    fn digester(&self) -> digest::Algorithm {
        self.digester
    }

    fn is_stargz(&self) -> bool {
        self.is_stargz
    }

    fn need_validate(&self) -> bool {
        self.need_validate
    }

    fn reader(&self) -> &dyn BlobReader {
        &*self.reader
    }

    fn get_chunk_map(&self) -> &Arc<dyn ChunkMap> {
        &self.chunk_map
    }

    fn get_blob_object(&self) -> Option<&dyn BlobObject> {
        if self.is_get_blob_object_supported {
            Some(self)
        } else {
            None
        }
    }

    fn prefetch(
        &self,
        blob_cache: Arc<dyn BlobCache>,
        prefetches: &[BlobPrefetchRequest],
        bios: &[BlobIoDesc],
    ) -> StorageResult<usize> {
        self.metrics.prefetch_unmerged_chunks.add(bios.len());
        let mut bios = bios.to_vec();
        bios.sort_by_key(|entry| entry.chunkinfo.compress_offset());

        // Enable data prefetching
        self.prefetch_state
            .store(AsyncRequestState::Pending as u32, Ordering::Release);

        // Handle blob prefetch request first, it may help performance.
        for req in prefetches {
            let msg = AsyncRequestMessage::new_blob_prefetch(
                blob_cache.clone(),
                self.prefetch_state.clone(),
                req.offset as u64,
                req.len as u64,
            );
            let _ = self.workers.send(msg);
        }

        // Then handle fs prefetch
        let merging_size = self.prefetch_config.merging_size;
        BlobIoMergeState::merge_and_issue(&bios, merging_size, |req: BlobIoRange| {
            let msg = AsyncRequestMessage::new_fs_prefetch(
                blob_cache.clone(),
                self.prefetch_state.clone(),
                req,
            );
            let _ = self.workers.send(msg);
        });

        Ok(0)
    }

    fn stop_prefetch(&self) -> StorageResult<()> {
        self.prefetch_state
            .store(AsyncRequestState::Cancelled as u32, Ordering::Release);

        Ok(())
    }

    fn prefetch_range(&self, range: &BlobIoRange) -> Result<usize> {
        let mut pending = Vec::with_capacity(range.chunks.len());
        if !self.chunk_map.is_persist() {
            let mut d_size = 0;
            for c in range.chunks.iter() {
                d_size = std::cmp::max(d_size, c.uncompress_size() as usize);
            }
            let mut buf = alloc_buf(d_size);

            for c in range.chunks.iter() {
                if let Ok(true) = self.chunk_map.check_ready_and_mark_pending(c.as_base()) {
                    // The chunk is ready, so skip it.
                    continue;
                }

                // For digested chunk map, we must check whether the cached data is valid because
                // the digested chunk map cannot persist readiness state.
                let d_size = c.uncompress_size() as usize;
                match self.read_raw_chunk(c, &mut buf[0..d_size], true, None) {
                    Ok(_v) => {
                        // The cached data is valid, set the chunk as ready.
                        let _ = self
                            .chunk_map
                            .set_ready_and_clear_pending(c.as_base())
                            .map_err(|e| error!("Failed to set chunk ready: {:?}", e));
                    }
                    Err(_e) => {
                        // The cached data is invalid, queue the chunk for reading from backend.
                        pending.push(c.clone());
                    }
                }
            }
        } else {
            for c in range.chunks.iter() {
                if let Ok(true) = self.chunk_map.check_ready_and_mark_pending(c.as_base()) {
                    // The chunk is ready, so skip it.
                    continue;
                } else {
                    pending.push(c.clone());
                }
            }
        }

        let mut total_size = 0;
        let mut start = 0;
        while start < pending.len() {
            let mut end = start + 1;
            while end < pending.len() && pending[end].id() == pending[end - 1].id() + 1 {
                end += 1;
            }

            // Find a range with continuous chunk id
            let blob_offset = pending[start].compress_offset();
            let blob_end = pending[end].compress_offset() + pending[end].compress_size() as u64;
            let blob_size = (blob_end - blob_offset) as usize;
            match self.read_chunks(blob_offset, blob_size, &pending[start..end]) {
                Ok(v) => {
                    total_size += blob_size;
                    for idx in start..end {
                        let offset = if self.is_compressed {
                            pending[idx].compress_offset()
                        } else {
                            pending[idx].uncompress_offset()
                        };
                        match Self::persist_chunk(&self.file, offset, &v[idx - start]) {
                            Ok(_) => {
                                let _ = self.chunk_map.set_ready_and_clear_pending(&pending[idx]);
                            }
                            Err(_) => self.chunk_map.clear_pending(&pending[idx]),
                        }
                    }
                }
                Err(_e) => {
                    for chunk in pending.iter().take(end).skip(start) {
                        self.chunk_map.clear_pending(chunk);
                    }
                }
            }

            start = end;
        }

        Ok(total_size)
    }

    fn read(&self, iovec: &BlobIoVec, buffers: &[VolatileSlice]) -> Result<usize> {
        debug_assert!(iovec.validate());
        self.metrics.total.inc();
        self.workers.consume_prefetch_budget(buffers);

        if iovec.bi_vec.is_empty() {
            Ok(0)
        } else if iovec.bi_vec.len() == 1 {
            let mut state = FileIoMergeState::new();
            let mut cursor = MemSliceCursor::new(buffers);
            let req = BlobIoRange::new(&iovec.bi_vec[0], 1);

            self.dispatch_one_range(&req, &mut cursor, &mut state)
        } else {
            self.read_iter(&iovec.bi_vec, buffers)
        }
    }
}

impl AsRawFd for FileCacheEntry {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl BlobObject for FileCacheEntry {
    fn base_offset(&self) -> u64 {
        0
    }

    fn is_all_data_ready(&self) -> bool {
        if let Some(b) = self.chunk_map.as_range_map() {
            b.is_range_all_ready()
        } else {
            false
        }
    }

    fn fetch_range_compressed(&self, offset: u64, size: u64) -> Result<usize> {
        let meta = self.meta.as_ref().ok_or_else(|| einval!())?;
        let chunks = meta.get_chunks_compressed(offset, size)?;
        debug_assert!(!chunks.is_empty());

        self.do_fetch_chunks(&chunks)
    }

    fn fetch_range_uncompressed(&self, offset: u64, size: u64) -> Result<usize> {
        let meta = self.meta.as_ref().ok_or_else(|| einval!())?;

        // TODO: read amplify the range to naturally aligned 2M?
        let chunks = meta.get_chunks_uncompressed(offset, size)?;
        debug_assert!(!chunks.is_empty());

        self.do_fetch_chunks(&chunks)
    }

    fn fetch_chunks(&self, range: &BlobIoRange) -> Result<usize> {
        let chunks = &range.chunks;
        if chunks.is_empty() {
            return Ok(0);
        }

        for idx in 1..chunks.len() {
            if chunks[idx - 1].id() + 1 != chunks[idx].id() {
                return Err(einval!("chunks for fetch_chunks() must be continuous"));
            }
        }

        self.do_fetch_chunks(&chunks)
    }
}

impl FileCacheEntry {
    fn do_fetch_chunks(&self, chunks: &[BlobIoChunk]) -> Result<usize> {
        let bitmap = self.chunk_map.as_range_map().ok_or_else(|| einval!())?;
        let chunk_index = chunks[0].id();
        let count = chunks.len() as u32;

        // Get chunks not ready yet, also marking them as inflight.
        let pending = match bitmap.check_range_ready_and_mark_pending(chunk_index, count)? {
            None => return Ok(0),
            Some(v) => {
                if v.is_empty() {
                    return Ok(0);
                }
                v
            }
        };

        let mut total_size = 0;
        let mut start = 0;
        while start < pending.len() {
            let mut end = start + 1;
            while end < pending.len() && pending[end] == pending[end - 1] + 1 {
                end += 1;
            }

            let start_idx = (pending[start] - chunk_index) as usize;
            let end_idx = start_idx + (end - start) - 1;
            let blob_offset = chunks[start_idx].compress_offset();
            let blob_end =
                chunks[end_idx].compress_offset() + chunks[end_idx].compress_size() as u64;
            let blob_size = (blob_end - blob_offset) as usize;
            match self.read_chunks(blob_offset, blob_size, &chunks[start_idx..=end_idx]) {
                Ok(v) => {
                    total_size += blob_size;
                    trace!(
                        "range persist chunk start {} {} pending {} {}",
                        start,
                        end,
                        start_idx,
                        end_idx
                    );
                    for idx in start_idx..=end_idx {
                        let offset = if self.is_compressed {
                            chunks[idx].compress_offset()
                        } else {
                            chunks[idx].uncompress_offset()
                        };
                        trace!("persist_chunk idx {}", idx);
                        Self::persist_chunk(&self.file, offset, &v[idx - start_idx]).map_err(
                            |e| eio!(format!("do_fetch_chunk failed to persist {:?}", e)),
                        )?;
                    }

                    bitmap
                        .set_range_ready_and_clear_pending(pending[start], (end - start) as u32)?;
                }
                Err(e) => {
                    bitmap.clear_range_pending(pending[start], (end - start) as u32);
                    return Err(e);
                }
            }

            start = end;
        }

        if !bitmap.wait_for_range_ready(chunk_index, count)? {
            Err(eio!("failed to read data from storage backend"))
        } else {
            Ok(total_size)
        }
    }
}

impl FileCacheEntry {
    // There are some assumption applied to the `bios` passed to `read_iter()`.
    // - The blob address of chunks in `bios` are continuous.
    // - There is at most one user io request in the `bios`.
    // - The user io request may not aligned on chunk boundary.
    // - The user io request may partially consume data from the first and last chunk of user io
    //   request.
    // - Optionally there may be some prefetch/read amplify requests following the user io request.
    // - The optional prefetch/read amplify requests may be silently dropped.
    fn read_iter(&self, bios: &[BlobIoDesc], buffers: &[VolatileSlice]) -> Result<usize> {
        debug!("bios {:?}", bios);
        // Merge requests with continuous blob addresses.
        let requests = self
            .merge_requests_for_user(bios, RAFS_DEFAULT_CHUNK_SIZE as usize * 2)
            .ok_or_else(|| einval!("Empty bios list"))?;
        let mut state = FileIoMergeState::new();
        let mut cursor = MemSliceCursor::new(buffers);
        let mut total_read: usize = 0;

        for req in requests {
            total_read += self.dispatch_one_range(&req, &mut cursor, &mut state)?;
            state.reset();
        }

        Ok(total_read)
    }

    fn dispatch_one_range(
        &self,
        req: &BlobIoRange,
        cursor: &mut MemSliceCursor,
        state: &mut FileIoMergeState,
    ) -> Result<usize> {
        let mut total_read: usize = 0;

        debug!("dispatch a blob io range {:?}", req);
        for (i, chunk) in req.chunks.iter().enumerate() {
            let is_ready = self
                .chunk_map
                .check_ready_and_mark_pending(chunk.as_base())?;

            // Directly read data from the file cache into the user buffer iff:
            // - the chunk is ready in the file cache
            // - the data in the file cache is uncompressed.
            // - data validation is disabled
            if is_ready && !self.is_compressed && !self.need_validate {
                // Silently drop prefetch requests.
                if req.tags[i].is_user_io() {
                    state.push(
                        RegionType::CacheFast,
                        chunk.uncompress_offset(),
                        chunk.uncompress_size(),
                        req.tags[i].clone(),
                        None,
                    )?;
                }
            } else if self.is_stargz || !self.is_direct_chunkmap || is_ready {
                // Case to try loading data from cache
                // - chunk is ready but data validation is needed.
                // - direct chunk map is not used, so there may be data in the file cache but
                //   the readiness flag has been lost.
                // - special path for stargz blobs. An stargz blob is abstracted as a compressed
                //   file cache always need validation.
                if req.tags[i].is_user_io() {
                    state.push(
                        RegionType::CacheSlow,
                        chunk.uncompress_offset(),
                        chunk.uncompress_size(),
                        req.tags[i].clone(),
                        Some(req.chunks[i].clone()),
                    )?;
                } else if !is_ready {
                    // On slow path, don't try to handle internal(read amplification) IO.
                    self.chunk_map.clear_pending(chunk.as_base());
                }
            } else {
                let tag = if let BlobIoTag::User(ref s) = req.tags[i] {
                    BlobIoTag::User(s.clone())
                } else {
                    BlobIoTag::Internal(chunk.compress_offset())
                };
                // NOTE: Only this request region can steak more chunks from backend with user io.
                state.push(
                    RegionType::Backend,
                    chunk.compress_offset(),
                    chunk.compress_size(),
                    tag,
                    Some(chunk.clone()),
                )?;
            }
        }

        for r in &state.regions {
            use RegionType::*;

            total_read += match r.r#type {
                CacheFast => self.dispatch_cache_fast(cursor, r)?,
                CacheSlow => self.dispatch_cache_slow(cursor, r)?,
                Backend => self.dispatch_backend(cursor, r)?,
            }
        }

        Ok(total_read)
    }

    // Directly read data requested by user from the file cache into the user memory buffer.
    fn dispatch_cache_fast(&self, cursor: &mut MemSliceCursor, region: &Region) -> Result<usize> {
        let offset = region.blob_address + region.seg.offset as u64;
        let size = region.seg.len as usize;
        let iovec = cursor.consume(size);

        self.metrics.partial_hits.inc();
        readv(self.file.as_raw_fd(), &iovec, offset)
    }

    fn dispatch_cache_slow(&self, cursor: &mut MemSliceCursor, region: &Region) -> Result<usize> {
        let mut total_read = 0;

        for (i, c) in region.chunks.iter().enumerate() {
            let user_offset = if i == 0 { region.seg.offset } else { 0 };
            let size = std::cmp::min(
                c.uncompress_size() - user_offset,
                region.seg.len - total_read as u32,
            );
            total_read += self.read_single_chunk(c, user_offset, size, cursor)?;
        }

        Ok(total_read)
    }

    fn dispatch_backend(&self, mem_cursor: &mut MemSliceCursor, region: &Region) -> Result<usize> {
        if region.chunks.is_empty() {
            return Ok(0);
        } else if !region.has_user_io() {
            debug!("No user data");
            for c in &region.chunks {
                self.chunk_map.clear_pending(c.as_base());
            }
            return Ok(0);
        }

        let blob_size = region.blob_len as usize;
        debug!("total backend data {}KB", blob_size / 1024);
        let mut chunks = self.read_chunks(region.blob_address, blob_size, &region.chunks)?;
        assert_eq!(region.chunks.len(), chunks.len());

        let mut chunk_buffers = Vec::with_capacity(region.chunks.len());
        let mut buffer_holder = Vec::with_capacity(region.chunks.len());
        for (i, v) in chunks.drain(..).enumerate() {
            let d = Arc::new(DataBuffer::Allocated(v));
            if region.tags[i] {
                buffer_holder.push(d.clone());
            }
            self.delay_persist(region.chunks[i].clone(), d);
        }
        for d in buffer_holder.iter() {
            chunk_buffers.push(d.as_ref().slice());
        }

        let total_read = copyv(
            &chunk_buffers,
            mem_cursor.mem_slice,
            region.seg.offset as usize,
            region.seg.len as usize,
            mem_cursor.index,
            mem_cursor.offset,
        )
        .map(|(n, _)| n)
        .map_err(|e| {
            error!("failed to copy from chunk buf to buf: {:?}", e);
            eio!(e)
        })?;
        mem_cursor.move_cursor(total_read);

        Ok(total_read)
    }

    fn delay_persist(&self, chunk_info: BlobIoChunk, buffer: Arc<DataBuffer>) {
        let delayed_chunk_map = self.chunk_map.clone();
        let file = self.file.clone();
        let offset = if self.is_compressed {
            chunk_info.compress_offset()
        } else {
            chunk_info.uncompress_offset()
        };

        self.runtime.spawn(async move {
            match Self::persist_chunk(&file, offset, buffer.slice()) {
                Ok(_) => delayed_chunk_map
                    .set_ready_and_clear_pending(chunk_info.as_base())
                    .unwrap_or_else(|e| {
                        error!(
                            "Failed change caching state for chunk of offset {}, {:?}",
                            chunk_info.compress_offset(),
                            e
                        )
                    }),
                Err(e) => {
                    error!(
                        "Persist chunk of offset {} failed, {:?}",
                        chunk_info.compress_offset(),
                        e
                    );
                    delayed_chunk_map.clear_pending(chunk_info.as_base())
                }
            }
        });
    }

    /// Persist a single chunk into local blob cache file. We have to write to the cache
    /// file in unit of chunk size
    fn persist_chunk(file: &Arc<File>, offset: u64, buffer: &[u8]) -> Result<()> {
        let fd = file.as_raw_fd();

        let n = loop {
            let ret = uio::pwrite(fd, buffer, offset as i64).map_err(|_| last_error!());
            match ret {
                Ok(nr_write) => {
                    trace!("write {}(offset={}) bytes to cache file", nr_write, offset);
                    break nr_write;
                }
                Err(err) => {
                    // Retry if the IO is interrupted by signal.
                    if err.kind() != ErrorKind::Interrupted {
                        return Err(err);
                    }
                }
            }
        };

        if n != buffer.len() {
            Err(eio!("failed to write data to file cache"))
        } else {
            Ok(())
        }
    }

    fn read_single_chunk(
        &self,
        chunk: &BlobIoChunk,
        user_offset: u32,
        size: u32,
        mem_cursor: &mut MemSliceCursor,
    ) -> Result<usize> {
        debug!("single bio, blob offset {}", chunk.compress_offset());

        let is_ready = self.chunk_map.is_ready(chunk.as_base())?;
        let buffer_holder;
        let d_size = chunk.uncompress_size() as usize;
        let mut d = DataBuffer::Allocated(alloc_buf(d_size));

        // Try to read and validate data from cache if:
        // - it's an stargz image and the chunk is ready.
        // - chunk data validation is enabled.
        // - digested or dummy chunk map is used.
        let try_cache = is_ready || (!self.is_stargz && !self.is_direct_chunkmap);
        let buffer = if try_cache && self.read_file_cache(chunk, d.mut_slice()).is_ok() {
            self.metrics.whole_hits.inc();
            self.chunk_map
                .set_ready_and_clear_pending(chunk.as_base())?;
            trace!(
                "recover blob cache {} {} offset {} size {}",
                chunk.id(),
                d_size,
                user_offset,
                size,
            );
            &d
        } else if !self.is_compressed {
            self.read_raw_chunk(chunk, d.mut_slice(), false, None)?;
            buffer_holder = Arc::new(d.convert_to_owned_buffer());
            self.delay_persist(chunk.clone(), buffer_holder.clone());
            buffer_holder.as_ref()
        } else {
            let persist_compressed = |buffer: &[u8]| match Self::persist_chunk(
                &self.file,
                chunk.compress_offset(),
                buffer,
            ) {
                Ok(_) => {
                    self.chunk_map
                        .set_ready_and_clear_pending(chunk.as_base())
                        .unwrap_or_else(|e| error!("set ready failed, {}", e));
                }
                Err(e) => {
                    error!("Failed in writing compressed blob cache index, {}", e);
                    self.chunk_map.clear_pending(chunk.as_base())
                }
            };
            self.read_raw_chunk(chunk, d.mut_slice(), false, Some(&persist_compressed))?;
            &d
        };

        let dst_buffers = mem_cursor.inner_slice();
        let read_size = copyv(
            &[buffer.slice()],
            dst_buffers,
            user_offset as usize,
            size as usize,
            mem_cursor.index,
            mem_cursor.offset,
        )
        .map(|r| r.0)
        .map_err(|e| {
            error!("failed to copy from chunk buf to buf: {:?}", e);
            eother!(e)
        })?;
        mem_cursor.move_cursor(read_size);

        Ok(read_size)
    }

    fn read_file_cache(&self, chunk: &BlobIoChunk, buffer: &mut [u8]) -> Result<()> {
        let offset = if self.is_compressed {
            chunk.compress_offset()
        } else {
            chunk.uncompress_offset()
        };

        let mut d;
        let raw_buffer = if self.is_compressed && !self.is_stargz {
            // Need to put compressed data into a temporary buffer so as to perform decompression.
            //
            // gzip is special that it doesn't carry compress_size, instead, we make an IO stream
            // out of the file cache. So no need for an internal buffer here.
            let c_size = chunk.compress_size() as usize;
            d = alloc_buf(c_size);
            d.as_mut_slice()
        } else {
            // We have this unsafe assignment as it can directly store data into call's buffer.
            unsafe { slice::from_raw_parts_mut(buffer.as_mut_ptr(), buffer.len()) }
        };

        let mut raw_stream = None;
        if self.is_stargz {
            debug!("using blobcache file offset {} as data stream", offset,);
            // FIXME: In case of multiple threads duplicating the same fd, they still share the
            // same file offset.
            let fd = dup(self.file.as_raw_fd()).map_err(|_| last_error!())?;
            let mut f = unsafe { File::from_raw_fd(fd) };
            f.seek(SeekFrom::Start(offset)).map_err(|_| last_error!())?;
            raw_stream = Some(f)
        } else {
            debug!(
                "reading blob cache file offset {} size {}",
                offset,
                raw_buffer.len()
            );
            let nr_read = uio::pread(self.file.as_raw_fd(), raw_buffer, offset as i64)
                .map_err(|_| last_error!())?;
            if nr_read == 0 || nr_read != raw_buffer.len() {
                return Err(einval!());
            }
        }

        // Try to validate data just fetched from backend inside.
        self.process_raw_chunk(
            chunk,
            raw_buffer,
            raw_stream,
            buffer,
            self.is_compressed,
            false,
        )?;

        Ok(())
    }

    fn merge_requests_for_user(
        &self,
        bios: &[BlobIoDesc],
        merging_size: usize,
    ) -> Option<Vec<BlobIoRange>> {
        let mut requests: Vec<BlobIoRange> = Vec::with_capacity(bios.len());

        BlobIoMergeState::merge_and_issue(bios, merging_size, |mr: BlobIoRange| {
            requests.push(mr);
        });

        if requests.is_empty() {
            None
        } else {
            Some(requests)
        }
    }
}

/// An enum to reuse existing buffers for IO operations, and CoW on demand.
#[allow(dead_code)]
enum DataBuffer {
    Reuse(ManuallyDrop<Vec<u8>>),
    Allocated(Vec<u8>),
}

impl DataBuffer {
    fn slice(&self) -> &[u8] {
        match self {
            Self::Reuse(data) => data.as_slice(),
            Self::Allocated(data) => data.as_slice(),
        }
    }

    fn mut_slice(&mut self) -> &mut [u8] {
        match self {
            Self::Reuse(ref mut data) => data.as_mut_slice(),
            Self::Allocated(ref mut data) => data.as_mut_slice(),
        }
    }

    /// Make sure it owns the underlying memory buffer.
    fn convert_to_owned_buffer(self) -> Self {
        if let DataBuffer::Reuse(data) = self {
            DataBuffer::Allocated((*data).to_vec())
        } else {
            self
        }
    }

    #[allow(dead_code)]
    unsafe fn from_mut_slice(buf: &mut [u8]) -> Self {
        DataBuffer::Reuse(ManuallyDrop::new(Vec::from_raw_parts(
            buf.as_mut_ptr(),
            buf.len(),
            buf.len(),
        )))
    }
}

#[derive(PartialEq, Debug)]
enum RegionStatus {
    Init,
    Open,
    Committed,
}

#[derive(PartialEq, Copy, Clone)]
enum RegionType {
    // Fast path to read data from the cache directly, no decompression and validation needed.
    CacheFast,
    // Slow path to read data from the cache, due to decompression or validation.
    CacheSlow,
    // Need to read data from storage backend.
    Backend,
}

impl RegionType {
    fn joinable(&self, other: Self) -> bool {
        *self == other
    }
}

/// A continuous region in cache file or backend storage/blob, it may contains several chunks.
struct Region {
    r#type: RegionType,
    status: RegionStatus,
    // For debug and trace purpose implying how many chunks are concatenated
    count: u32,

    chunks: Vec<BlobIoChunk>,
    tags: Vec<bool>,

    // The range [blob_address, blob_address + blob_len) specifies data to be read from backend.
    blob_address: u64,
    blob_len: u32,
    // The range specifying data to return to user.
    seg: BlobIoSegment,
}

impl Region {
    fn new(region_type: RegionType) -> Self {
        Region {
            r#type: region_type,
            status: RegionStatus::Init,
            count: 0,
            chunks: Vec::with_capacity(8),
            tags: Vec::with_capacity(8),
            blob_address: 0,
            blob_len: 0,
            seg: Default::default(),
        }
    }

    fn append(
        &mut self,
        start: u64,
        len: u32,
        tag: BlobIoTag,
        chunk: Option<BlobIoChunk>,
    ) -> StorageResult<()> {
        debug_assert!(self.status != RegionStatus::Committed);

        if self.status == RegionStatus::Init {
            self.status = RegionStatus::Open;
            self.blob_address = start;
            self.blob_len = len;
            self.count = 1;
        } else {
            debug_assert!(self.status == RegionStatus::Open);
            if self.blob_address + self.blob_len as u64 != start
                || start.checked_add(len as u64).is_none()
            {
                return Err(StorageError::NotContinuous);
            }
            self.blob_len += len;
            self.count += 1;
        }

        // Maintain information for user triggered IO requests.
        if let BlobIoTag::User(ref s) = tag {
            if self.seg.is_empty() {
                self.seg = BlobIoSegment::new(s.offset, s.len);
            } else {
                self.seg.append(s.offset, s.len);
            }
        }

        if let Some(c) = chunk {
            self.chunks.push(c);
            self.tags.push(tag.is_user_io());
        }

        Ok(())
    }

    fn has_user_io(&self) -> bool {
        !self.seg.is_empty()
    }
}

struct FileIoMergeState {
    regions: Vec<Region>,
}

impl FileIoMergeState {
    fn new() -> Self {
        FileIoMergeState {
            regions: Vec::with_capacity(8),
        }
    }

    fn push(
        &mut self,
        region_type: RegionType,
        start: u64,
        len: u32,
        tag: BlobIoTag,
        chunk: Option<BlobIoChunk>,
    ) -> Result<()> {
        if self.regions.is_empty() || !self.joinable(region_type) {
            self.regions.push(Region::new(region_type));
        }

        let idx = self.regions.len() - 1;
        self.regions[idx]
            .append(start, len, tag, chunk)
            .map_err(|e| einval!(e))
    }

    fn reset(&mut self) {
        self.regions.truncate(0);
    }

    #[inline]
    fn joinable(&self, region_type: RegionType) -> bool {
        debug_assert!(!self.regions.is_empty());
        let idx = self.regions.len() - 1;

        self.regions[idx].r#type.joinable(region_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_buffer() {
        let mut buf1 = vec![0x1u8; 8];
        let buf2 = unsafe { DataBuffer::from_mut_slice(buf1.as_mut_slice()) };

        assert_eq!(buf2.slice()[1], 0x1);
        let mut buf2 = buf2.convert_to_owned_buffer();
        buf2.mut_slice()[1] = 0x2;
        assert_eq!(buf1[1], 0x1);
    }

    #[test]
    fn test_region_type() {
        assert!(RegionType::CacheFast.joinable(RegionType::CacheFast));
        assert!(RegionType::CacheSlow.joinable(RegionType::CacheSlow));
        assert!(RegionType::Backend.joinable(RegionType::Backend));

        assert!(!RegionType::CacheFast.joinable(RegionType::CacheSlow));
        assert!(!RegionType::CacheFast.joinable(RegionType::Backend));
        assert!(!RegionType::CacheSlow.joinable(RegionType::CacheFast));
        assert!(!RegionType::CacheSlow.joinable(RegionType::Backend));
        assert!(!RegionType::Backend.joinable(RegionType::CacheFast));
        assert!(!RegionType::Backend.joinable(RegionType::CacheSlow));
    }

    #[test]
    fn test_region_new() {
        let region = Region::new(RegionType::CacheFast);

        assert_eq!(region.status, RegionStatus::Init);
        assert!(!region.has_user_io());
        assert!(region.seg.is_empty());
        assert_eq!(region.chunks.len(), 0);
        assert_eq!(region.tags.len(), 0);
        assert_eq!(region.blob_address, 0);
        assert_eq!(region.blob_len, 0);
    }

    #[test]
    fn test_region_append() {
        let mut region = Region::new(RegionType::CacheFast);

        let tag = BlobIoTag::User(BlobIoSegment {
            offset: 0x1800,
            len: 0x1800,
        });
        region.append(0x1000, 0x2000, tag, None).unwrap();
        assert_eq!(region.status, RegionStatus::Open);
        assert_eq!(region.blob_address, 0x1000);
        assert_eq!(region.blob_len, 0x2000);
        assert_eq!(region.chunks.len(), 0);
        assert_eq!(region.tags.len(), 0);
        assert!(!region.seg.is_empty());
        assert!(region.has_user_io());

        let tag = BlobIoTag::User(BlobIoSegment {
            offset: 0x4000,
            len: 0x2000,
        });
        region.append(0x4000, 0x2000, tag, None).unwrap_err();
        assert_eq!(region.status, RegionStatus::Open);
        assert_eq!(region.blob_address, 0x1000);
        assert_eq!(region.blob_len, 0x2000);
        assert_eq!(region.seg.offset, 0x1800);
        assert_eq!(region.seg.len, 0x1800);
        assert_eq!(region.chunks.len(), 0);
        assert_eq!(region.tags.len(), 0);
        assert!(region.has_user_io());

        let tag = BlobIoTag::User(BlobIoSegment {
            offset: 0x3000,
            len: 0x2000,
        });
        region.append(0x3000, 0x2000, tag, None).unwrap();
        assert_eq!(region.status, RegionStatus::Open);
        assert_eq!(region.blob_address, 0x1000);
        assert_eq!(region.blob_len, 0x4000);
        assert_eq!(region.seg.offset, 0x1800);
        assert_eq!(region.seg.len, 0x3800);
        assert_eq!(region.chunks.len(), 0);
        assert_eq!(region.tags.len(), 0);
        assert!(!region.seg.is_empty());
        assert!(region.has_user_io());
    }

    #[test]
    fn test_file_io_merge_state() {
        let mut state = FileIoMergeState::new();
        assert_eq!(state.regions.len(), 0);

        let tag = BlobIoTag::User(BlobIoSegment {
            offset: 0x1800,
            len: 0x1800,
        });
        state
            .push(RegionType::CacheFast, 0x1000, 0x2000, tag, None)
            .unwrap();
        assert_eq!(state.regions.len(), 1);

        let tag = BlobIoTag::User(BlobIoSegment {
            offset: 0x3000,
            len: 0x2000,
        });
        state
            .push(RegionType::CacheFast, 0x3000, 0x2000, tag, None)
            .unwrap();
        assert_eq!(state.regions.len(), 1);

        let tag = BlobIoTag::User(BlobIoSegment {
            offset: 0x5000,
            len: 0x2000,
        });
        state
            .push(RegionType::CacheSlow, 0x5000, 0x2000, tag, None)
            .unwrap();
        assert_eq!(state.regions.len(), 2);
    }
}
