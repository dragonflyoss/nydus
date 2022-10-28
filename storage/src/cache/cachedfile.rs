// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Common cached file object for `FileCacheMgr` and `FsCacheMgr`.
//!
//! The `FileCacheEntry` manages local cached blob objects from remote backends to improve
//! performance. It may be used by both the userspace `FileCacheMgr` or the `FsCacheMgr` based
//! on the in-kernel fscache system.

use std::fs::File;
use std::io::{ErrorKind, Read, Result};
use std::mem::ManuallyDrop;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fuse_backend_rs::file_buf::FileVolatileSlice;
use nix::sys::uio;
use nydus_utils::compress::Decoder;
use nydus_utils::metrics::{BlobcacheMetrics, Metric};
use nydus_utils::{compress, digest, FileRangeReader};
use tokio::runtime::Runtime;

use crate::backend::BlobReader;
use crate::cache::state::ChunkMap;
use crate::cache::worker::{AsyncPrefetchConfig, AsyncPrefetchMessage, AsyncWorkerMgr};
use crate::cache::{BlobCache, BlobIoMergeState};
use crate::device::{
    BlobChunkInfo, BlobInfo, BlobIoDesc, BlobIoRange, BlobIoSegment, BlobIoTag, BlobIoVec,
    BlobObject, BlobPrefetchRequest,
};
use crate::meta::{BlobMetaChunk, BlobMetaInfo};
use crate::utils::{alloc_buf, copyv, readv, MemSliceCursor};
use crate::{StorageError, StorageResult, RAFS_DEFAULT_CHUNK_SIZE, RAFS_MERGING_SIZE_TO_GAP_SHIFT};

const DOWNLOAD_META_RETRY_COUNT: u32 = 20;
const DOWNLOAD_META_RETRY_DELAY: u64 = 500;

#[derive(Default, Clone)]
pub(crate) struct FileCacheMeta {
    has_error: Arc<AtomicBool>,
    meta: Arc<Mutex<Option<Arc<BlobMetaInfo>>>>,
}

impl FileCacheMeta {
    pub(crate) fn new(
        blob_file: String,
        blob_info: Arc<BlobInfo>,
        reader: Option<Arc<dyn BlobReader>>,
    ) -> Result<Self> {
        let meta = FileCacheMeta {
            has_error: Arc::new(AtomicBool::new(false)),
            meta: Arc::new(Mutex::new(None)),
        };
        let meta1 = meta.clone();

        std::thread::spawn(move || {
            let mut retry = 0;
            while retry < DOWNLOAD_META_RETRY_COUNT {
                match BlobMetaInfo::new(&blob_file, &blob_info, reader.as_ref()) {
                    Ok(m) => {
                        *meta1.meta.lock().unwrap() = Some(Arc::new(m));
                        return;
                    }
                    Err(e) => {
                        info!("temporarily failed to get blob.meta, {}", e);
                        std::thread::sleep(Duration::from_millis(DOWNLOAD_META_RETRY_DELAY));
                        retry += 1;
                    }
                }
            }
            warn!("failed to get blob.meta");
            meta1.has_error.store(true, Ordering::Release);
        });

        Ok(meta)
    }

    pub(crate) fn get_blob_meta(&self) -> Option<Arc<BlobMetaInfo>> {
        loop {
            let meta = self.meta.lock().unwrap();
            if meta.is_some() {
                return meta.clone();
            }
            drop(meta);
            if self.has_error.load(Ordering::Acquire) {
                return None;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

pub(crate) struct FileCacheEntry {
    pub(crate) blob_info: Arc<BlobInfo>,
    pub(crate) chunk_map: Arc<dyn ChunkMap>,
    pub(crate) file: Arc<File>,
    pub(crate) meta: Option<FileCacheMeta>,
    pub(crate) metrics: Arc<BlobcacheMetrics>,
    pub(crate) prefetch_state: Arc<AtomicU32>,
    pub(crate) reader: Arc<dyn BlobReader>,
    pub(crate) runtime: Arc<Runtime>,
    pub(crate) workers: Arc<AsyncWorkerMgr>,

    pub(crate) blob_compressed_size: u64,
    pub(crate) blob_uncompressed_size: u64,
    pub(crate) compressor: compress::Algorithm,
    pub(crate) digester: digest::Algorithm,
    // Whether `get_blob_object()` is supported.
    pub(crate) is_get_blob_object_supported: bool,
    // The compressed data instead of uncompressed data is cached if `compressed` is true.
    pub(crate) is_compressed: bool,
    // Whether direct chunkmap is used.
    pub(crate) is_direct_chunkmap: bool,
    // The blob is for an stargz image.
    pub(crate) is_legacy_stargz: bool,
    // True if direct IO is enabled for the `self.file`, supported for fscache only.
    pub(crate) dio_enabled: bool,
    // Data from the file cache should be validated before use.
    pub(crate) need_validate: bool,
    pub(crate) batch_size: u64,
    pub(crate) prefetch_config: Arc<AsyncPrefetchConfig>,
}

impl FileCacheEntry {
    pub(crate) fn get_blob_size(reader: &Arc<dyn BlobReader>, blob_info: &BlobInfo) -> Result<u64> {
        // Stargz needs blob size information, so hacky!
        let size = if blob_info.is_legacy_stargz() {
            reader.blob_size().map_err(|e| einval!(e))?
        } else {
            0
        };

        Ok(size)
    }

    fn delay_persist_chunk_data(
        &self,
        chunk: Arc<dyn BlobChunkInfo>,
        buffer: Arc<DataBuffer>,
        compressed: bool,
    ) {
        assert_eq!(self.is_compressed, compressed);
        let delayed_chunk_map = self.chunk_map.clone();
        let file = self.file.clone();
        let metrics = self.metrics.clone();

        metrics.buffered_backend_size.add(buffer.size() as u64);
        self.runtime.spawn_blocking(move || {
            metrics.buffered_backend_size.sub(buffer.size() as u64);
            let offset = if compressed {
                chunk.compressed_offset()
            } else {
                chunk.uncompressed_offset()
            };
            let res = Self::persist_cached_data(&file, offset, buffer.slice());
            Self::_update_chunk_pending_status(&delayed_chunk_map, chunk.as_ref(), res.is_ok());
        });
    }

    fn persist_chunk_data(&self, chunk: &dyn BlobChunkInfo, buf: &[u8]) {
        let offset = chunk.uncompressed_offset();
        let res = Self::persist_cached_data(&self.file, offset, buf);
        self.update_chunk_pending_status(chunk, res.is_ok());
    }

    fn persist_cached_data(file: &Arc<File>, offset: u64, buffer: &[u8]) -> Result<()> {
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

    fn update_chunk_pending_status(&self, chunk: &dyn BlobChunkInfo, success: bool) {
        Self::_update_chunk_pending_status(&self.chunk_map, chunk, success)
    }

    fn _update_chunk_pending_status(
        chunk_map: &Arc<dyn ChunkMap>,
        chunk: &dyn BlobChunkInfo,
        success: bool,
    ) {
        if success {
            if let Err(e) = chunk_map.set_ready_and_clear_pending(chunk) {
                error!(
                    "Failed change caching state for chunk of offset {}, {:?}",
                    chunk.compressed_offset(),
                    e
                )
            }
        } else {
            error!(
                "Failed to persist data for chunk at offset {}",
                chunk.compressed_offset()
            );
            chunk_map.clear_pending(chunk);
        }
    }
}

impl AsRawFd for FileCacheEntry {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl BlobCache for FileCacheEntry {
    fn blob_id(&self) -> &str {
        self.blob_info.blob_id()
    }

    fn blob_uncompressed_size(&self) -> Result<u64> {
        Ok(self.blob_uncompressed_size)
    }

    fn blob_compressed_size(&self) -> Result<u64> {
        Ok(self.blob_compressed_size)
    }

    fn compressor(&self) -> compress::Algorithm {
        self.compressor
    }

    fn digester(&self) -> digest::Algorithm {
        self.digester
    }

    fn is_legacy_stargz(&self) -> bool {
        self.is_legacy_stargz
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

    fn get_chunk_info(&self, chunk_index: u32) -> Option<Arc<dyn BlobChunkInfo>> {
        self.meta
            .as_ref()
            .and_then(|v| v.get_blob_meta())
            .map(|v| BlobMetaChunk::new(chunk_index as usize, &v.state))
    }

    fn get_blob_object(&self) -> Option<&dyn BlobObject> {
        if self.is_get_blob_object_supported {
            Some(self)
        } else {
            None
        }
    }

    fn start_prefetch(&self) -> StorageResult<()> {
        self.prefetch_state.fetch_add(1, Ordering::Release);
        Ok(())
    }

    fn stop_prefetch(&self) -> StorageResult<()> {
        loop {
            let val = self.prefetch_state.load(Ordering::Acquire);
            if val > 0
                && self
                    .prefetch_state
                    .compare_exchange(val, val - 1, Ordering::AcqRel, Ordering::Relaxed)
                    .is_err()
            {
                continue;
            }

            if val == 0 {
                warn!("storage: inaccurate prefetch status");
            }
            if val == 0 || val == 1 {
                self.workers
                    .flush_pending_prefetch_requests(self.blob_info.blob_id());
                return Ok(());
            }
        }
    }

    fn is_prefetch_active(&self) -> bool {
        self.prefetch_state.load(Ordering::Acquire) > 0
    }

    fn prefetch(
        &self,
        blob_cache: Arc<dyn BlobCache>,
        prefetches: &[BlobPrefetchRequest],
        bios: &[BlobIoDesc],
    ) -> StorageResult<usize> {
        let mut bios = bios.to_vec();
        bios.sort_by_key(|entry| entry.chunkinfo.compressed_offset());
        self.metrics.prefetch_unmerged_chunks.add(bios.len() as u64);

        // Handle blob prefetch request first, it may help performance.
        for req in prefetches {
            let msg = AsyncPrefetchMessage::new_blob_prefetch(
                blob_cache.clone(),
                req.offset as u64,
                req.len as u64,
            );
            let _ = self.workers.send_prefetch_message(msg);
        }

        // Then handle fs prefetch
        let max_comp_size = self.prefetch_config.merging_size;
        BlobIoMergeState::merge_and_issue(
            &bios,
            max_comp_size,
            max_comp_size as u64 >> RAFS_MERGING_SIZE_TO_GAP_SHIFT,
            |req: BlobIoRange| {
                let msg = AsyncPrefetchMessage::new_fs_prefetch(blob_cache.clone(), req);
                let _ = self.workers.send_prefetch_message(msg);
            },
        );

        Ok(0)
    }

    fn prefetch_range(&self, range: &BlobIoRange) -> Result<usize> {
        let mut pending = Vec::with_capacity(range.chunks.len());
        if !self.chunk_map.is_persist() {
            let mut d_size = 0;
            for c in range.chunks.iter() {
                d_size = std::cmp::max(d_size, c.uncompressed_size() as usize);
            }
            let mut buf = alloc_buf(d_size);

            for c in range.chunks.iter() {
                if let Ok(true) = self.chunk_map.check_ready_and_mark_pending(c.as_ref()) {
                    // The chunk is ready, so skip it.
                    continue;
                }

                // For digested chunk map, we must check whether the cached data is valid because
                // the digested chunk map cannot persist readiness state.
                let d_size = c.uncompressed_size() as usize;
                match self.read_file_cache(c.as_ref(), &mut buf[0..d_size]) {
                    // The cached data is valid, set the chunk as ready.
                    Ok(_v) => self.update_chunk_pending_status(c.as_ref(), true),
                    // The cached data is invalid, queue the chunk for reading from backend.
                    Err(_e) => pending.push(c.clone()),
                }
            }
        } else {
            for c in range.chunks.iter() {
                if let Ok(true) = self.chunk_map.check_ready_and_mark_pending(c.as_ref()) {
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
            // Be careful that `end` is inclusive.
            let mut end = start;

            // Figure out the range with continuous chunk ids.
            while end < pending.len() - 1 && pending[end + 1].id() == pending[end].id() + 1 {
                end += 1;
            }

            // Don't forget to clear its pending state whenever backend IO fails.
            let blob_offset = pending[start].compressed_offset();
            let blob_end = pending[end].compressed_offset() + pending[end].compressed_size() as u64;
            let blob_size = (blob_end - blob_offset) as usize;

            match self.read_chunks_from_backend(blob_offset, blob_size, &pending[start..=end], true)
            {
                Ok((v, c)) => {
                    total_size += blob_size;
                    if self.is_compressed {
                        let res = Self::persist_cached_data(&self.file, blob_offset, &c);
                        for c in pending.iter().take(end + 1).skip(start) {
                            self.update_chunk_pending_status(c.as_ref(), res.is_ok());
                        }
                    } else {
                        for idx in start..=end {
                            self.persist_chunk_data(pending[idx].as_ref(), &v[idx - start]);
                        }
                    }
                }
                Err(_e) => {
                    // Clear the pending flag for all chunks in processing.
                    for chunk in &mut pending[start..=end] {
                        self.update_chunk_pending_status(chunk.as_ref(), false);
                    }
                }
            }

            start = end + 1;
        }

        Ok(total_size)
    }

    fn read(&self, iovec: &mut BlobIoVec, buffers: &[FileVolatileSlice]) -> Result<usize> {
        self.metrics.total.inc();
        self.workers.consume_prefetch_budget(iovec.size());

        if iovec.is_empty() {
            Ok(0)
        } else if iovec.len() == 1 {
            let mut state = FileIoMergeState::new();
            let mut cursor = MemSliceCursor::new(buffers);
            let req = BlobIoRange::new(&iovec.bi_vec[0], 1);
            self.dispatch_one_range(&req, &mut cursor, &mut state)
        } else {
            self.read_iter(&mut iovec.bi_vec, buffers)
        }
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
        let meta = meta.get_blob_meta().ok_or_else(|| einval!())?;
        let chunks = meta.get_chunks_compressed(offset, size, self.batch_size)?;
        assert!(!chunks.is_empty());
        self.do_fetch_chunks(&chunks, true)
    }

    fn fetch_range_uncompressed(&self, offset: u64, size: u64) -> Result<usize> {
        let meta = self.meta.as_ref().ok_or_else(|| einval!())?;
        let meta = meta.get_blob_meta().ok_or_else(|| einval!())?;
        let chunks = meta.get_chunks_uncompressed(offset, size, self.batch_size * 2)?;
        assert!(!chunks.is_empty());
        self.do_fetch_chunks(&chunks, false)
    }

    fn prefetch_chunks(&self, range: &BlobIoRange) -> Result<usize> {
        let chunks = &range.chunks;
        if chunks.is_empty() {
            return Ok(0);
        }

        let mut ready_or_pending = matches!(
            self.chunk_map.is_ready_or_pending(chunks[0].as_ref()),
            Ok(true)
        );
        for idx in 1..chunks.len() {
            if chunks[idx - 1].id() + 1 != chunks[idx].id() {
                return Err(einval!("chunks for fetch_chunks() must be continuous"));
            }
            if ready_or_pending
                && !matches!(
                    self.chunk_map.is_ready_or_pending(chunks[idx].as_ref()),
                    Ok(true)
                )
            {
                ready_or_pending = false;
            }
        }
        // All chunks to be prefetched are already pending for downloading, no need to reissue.
        if ready_or_pending {
            return Ok(0);
        }

        if range.blob_size < self.prefetch_config.merging_size as u64 {
            let max_size = self.prefetch_config.merging_size as u64 - range.blob_size;
            if let Some(meta) = self.meta.as_ref() {
                if let Some(bm) = meta.get_blob_meta() {
                    if let Some(chunks) = bm.add_more_chunks(chunks, max_size) {
                        return self.do_fetch_chunks(&chunks, true);
                    }
                } else {
                    return Err(einval!("failed to get blob.meta"));
                }
            }
        }

        self.do_fetch_chunks(chunks, true)
    }
}

impl FileCacheEntry {
    fn do_fetch_chunks(&self, chunks: &[Arc<dyn BlobChunkInfo>], prefetch: bool) -> Result<usize> {
        if self.is_legacy_stargz() {
            // FIXME: for stargz, we need to implement fetching multiple chunks. here
            // is a heavy overhead workaround, needs to be optimized.
            for chunk in chunks {
                let mut buf = alloc_buf(chunk.uncompressed_size() as usize);
                self.read_chunk_from_backend(chunk.as_ref(), &mut buf, false)
                    .map_err(|e| {
                        eio!(format!(
                            "read_raw_chunk failed to read and decompress stargz chunk, {:?}",
                            e
                        ))
                    })?;
                if self.dio_enabled {
                    self.adjust_buffer_for_dio(&mut buf)
                }
                Self::persist_cached_data(&self.file, chunk.uncompressed_offset(), &buf).map_err(
                    |e| {
                        eio!(format!(
                            "do_fetch_chunk failed to persist stargz chunk, {:?}",
                            e
                        ))
                    },
                )?;
                self.chunk_map
                    .set_ready_and_clear_pending(chunk.as_ref())
                    .unwrap_or_else(|e| error!("set stargz chunk ready failed, {}", e));
            }
            return Ok(0);
        }

        debug_assert!(!chunks.is_empty());
        let bitmap = self
            .chunk_map
            .as_range_map()
            .ok_or_else(|| einval!("invalid chunk_map for do_fetch_chunks()"))?;
        let chunk_index = chunks[0].id();
        let count = chunks.len() as u32;

        // Get chunks not ready yet, also marking them as inflight.
        let pending = match bitmap.check_range_ready_and_mark_pending(chunk_index, count)? {
            None => return Ok(0),
            Some(v) => v,
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
            let blob_offset = chunks[start_idx].compressed_offset();
            let blob_end =
                chunks[end_idx].compressed_offset() + chunks[end_idx].compressed_size() as u64;
            let blob_size = (blob_end - blob_offset) as usize;

            match self.read_chunks_from_backend(
                blob_offset,
                blob_size,
                &chunks[start_idx..=end_idx],
                prefetch,
            ) {
                Ok((mut v, c)) => {
                    total_size += blob_size;
                    trace!(
                        "range persist chunk start {} {} pending {} {}",
                        start,
                        end,
                        start_idx,
                        end_idx
                    );
                    if self.is_compressed {
                        let res = Self::persist_cached_data(&self.file, blob_offset, &c);
                        for c in chunks.iter().take(end + 1).skip(start) {
                            self.update_chunk_pending_status(c.as_ref(), res.is_ok());
                        }
                    } else {
                        for idx in start_idx..=end_idx {
                            let buf = &mut v[idx - start_idx];
                            if self.dio_enabled {
                                self.adjust_buffer_for_dio(buf)
                            }
                            self.persist_chunk_data(chunks[idx].as_ref(), buf.as_ref());
                        }
                    }
                }
                Err(e) => {
                    bitmap.clear_range_pending(pending[start], (end - start) as u32);
                    return Err(e);
                }
            }

            start = end;
        }

        if !bitmap.wait_for_range_ready(chunk_index, count)? {
            if prefetch {
                return Err(eio!("failed to read data from storage backend"));
            }
            // if we are in ondemand path, retry for the timeout chunks
            for chunk in chunks {
                if self.chunk_map.is_ready(chunk.as_ref())? {
                    continue;
                }
                info!("retry for timeout chunk, {}", chunk.id());
                let mut buf = alloc_buf(chunk.uncompressed_size() as usize);
                self.read_chunk_from_backend(chunk.as_ref(), &mut buf, false)
                    .map_err(|e| eio!(format!("read_raw_chunk failed, {:?}", e)))?;
                if self.dio_enabled {
                    self.adjust_buffer_for_dio(&mut buf)
                }
                self.persist_chunk_data(chunk.as_ref(), &buf);
            }
            Ok(total_size)
        } else {
            Ok(total_size)
        }
    }

    fn adjust_buffer_for_dio(&self, buf: &mut Vec<u8>) {
        assert_eq!(buf.capacity() % 0x1000, 0);
        if buf.len() != buf.capacity() {
            // Padding with 0 for direct IO.
            buf.resize(buf.capacity(), 0);
        }
    }
}

impl FileCacheEntry {
    // There are some assumption applied to the `bios` passed to `read_iter()`.
    // - The blob address of chunks in `bios` are continuous.
    // - There is at most one user io request in the `bios`.
    // - The user io request may not be aligned on chunk boundary.
    // - The user io request may partially consume data from the first and last chunk of user io
    //   request.
    // - Optionally there may be some prefetch/read amplify requests following the user io request.
    // - The optional prefetch/read amplify requests may be silently dropped.
    fn read_iter(&self, bios: &mut [BlobIoDesc], buffers: &[FileVolatileSlice]) -> Result<usize> {
        // Merge requests with continuous blob addresses.
        let requests = self
            .merge_requests_for_user(bios, self.batch_size as usize)
            .ok_or_else(|| {
                for bio in bios.iter() {
                    self.update_chunk_pending_status(&bio.chunkinfo, false);
                }
                einval!("Empty bios list")
            })?;

        let mut state = FileIoMergeState::new();
        let mut cursor = MemSliceCursor::new(buffers);
        let mut total_read: usize = 0;
        for (idx, req) in requests.iter().enumerate() {
            total_read += self
                .dispatch_one_range(req, &mut cursor, &mut state)
                .map_err(|e| {
                    for req in requests.iter().skip(idx) {
                        for chunk in req.chunks.iter() {
                            self.update_chunk_pending_status(chunk.as_ref(), false);
                        }
                    }
                    e
                })?;
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

        trace!("dispatch single io range {:?}", req);
        for (i, chunk) in req.chunks.iter().enumerate() {
            let is_ready = match self.chunk_map.check_ready_and_mark_pending(chunk.as_ref()) {
                Ok(true) => true,
                Ok(false) => false,
                Err(StorageError::Timeout) => false, // Retry if waiting for inflight IO timeouts
                Err(e) => return Err(einval!(e)),
            };

            // Directly read data from the file cache into the user buffer iff:
            // - the chunk is ready in the file cache
            // - the data in the file cache is uncompressed.
            // - data validation is disabled
            if is_ready && !self.is_compressed && !self.need_validate() {
                // Internal IO should not be committed to local cache region, just
                // commit this region without pushing any chunk to avoid discontinuous
                // chunks in a region.
                if req.tags[i].is_user_io() {
                    state.push(
                        RegionType::CacheFast,
                        chunk.uncompressed_offset(),
                        chunk.uncompressed_size(),
                        req.tags[i].clone(),
                        None,
                    )?;
                } else {
                    state.commit()
                }
            } else if !self.is_direct_chunkmap || is_ready {
                // Case to try loading data from cache
                // - chunk is ready but data validation is needed.
                // - direct chunk map is not used, so there may be data in the file cache but
                //   the readiness flag has been lost.
                if req.tags[i].is_user_io() {
                    state.push(
                        RegionType::CacheSlow,
                        chunk.uncompressed_offset(),
                        chunk.uncompressed_size(),
                        req.tags[i].clone(),
                        Some(req.chunks[i].clone()),
                    )?;
                } else {
                    state.commit();
                    // On slow path, don't try to handle internal(read amplification) IO.
                    if !is_ready {
                        self.chunk_map.clear_pending(chunk.as_ref());
                    }
                }
            } else {
                let tag = if let BlobIoTag::User(ref s) = req.tags[i] {
                    BlobIoTag::User(s.clone())
                } else {
                    BlobIoTag::Internal
                };
                // NOTE: Only this request region can read more chunks from backend with user io.
                state.push(
                    RegionType::Backend,
                    chunk.compressed_offset(),
                    chunk.compressed_size(),
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
        let mut iovec = cursor.consume(size);

        self.metrics.partial_hits.inc();
        readv(self.file.as_raw_fd(), &mut iovec, offset)
    }

    // Try to read data from blob cache and validate it, fallback to storage backend.
    fn dispatch_cache_slow(&self, cursor: &mut MemSliceCursor, region: &Region) -> Result<usize> {
        let mut total_read = 0;

        for (i, c) in region.chunks.iter().enumerate() {
            let user_offset = if i == 0 { region.seg.offset } else { 0 };
            let size = std::cmp::min(
                c.uncompressed_size() - user_offset,
                region.seg.len - total_read as u32,
            );
            total_read += self.read_single_chunk(c.clone(), user_offset, size, cursor)?;
        }

        Ok(total_read)
    }

    fn dispatch_backend(&self, mem_cursor: &mut MemSliceCursor, region: &Region) -> Result<usize> {
        if region.chunks.is_empty() {
            return Ok(0);
        } else if !region.has_user_io() {
            debug!("No user data");
            for c in &region.chunks {
                self.chunk_map.clear_pending(c.as_ref());
            }
            return Ok(0);
        }

        let blob_size = region.blob_len as usize;
        debug!(
            "{} try to read {} bytes of {} chunks from backend",
            std::thread::current().name().unwrap_or_default(),
            blob_size,
            region.chunks.len()
        );

        let (mut chunks, c) =
            self.read_chunks_from_backend(region.blob_address, blob_size, &region.chunks, false)?;
        assert_eq!(region.chunks.len(), chunks.len());
        if self.is_compressed {
            let res = Self::persist_cached_data(&self.file, region.blob_address, &c);
            for chunk in region.chunks.iter() {
                self.update_chunk_pending_status(chunk.as_ref(), res.is_ok());
            }
            res?;
        }

        let mut chunk_buffers = Vec::with_capacity(region.chunks.len());
        let mut buffer_holder = Vec::with_capacity(region.chunks.len());
        for (i, v) in chunks.drain(..).enumerate() {
            let d = Arc::new(DataBuffer::Allocated(v));
            if region.tags[i] {
                buffer_holder.push(d.clone());
            }
            if !self.is_compressed {
                self.delay_persist_chunk_data(region.chunks[i].clone(), d, false);
            }
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

    fn read_single_chunk(
        &self,
        chunk: Arc<dyn BlobChunkInfo>,
        user_offset: u32,
        size: u32,
        mem_cursor: &mut MemSliceCursor,
    ) -> Result<usize> {
        trace!(
            "read_single_chunk {:x}:{:x}:{:x}/@{}",
            chunk.compressed_offset(),
            user_offset,
            size,
            chunk.blob_index()
        );

        let buffer_holder;
        let d_size = chunk.uncompressed_size() as usize;
        let mut d = DataBuffer::Allocated(alloc_buf(d_size));

        // Try to read and validate data from cache if:
        // - the chunk is marked as ready
        // - it's not in direct map mode and blob is not a legacy stargz. Legacy stargz has
        //   incorrect chunk hash value, so can't be used to validate data from cache.
        let buffer = if self.read_file_cache(chunk.as_ref(), d.mut_slice()).is_ok() {
            self.metrics.whole_hits.inc();
            self.chunk_map.set_ready_and_clear_pending(chunk.as_ref())?;
            trace!(
                "recover blob cache {} {} offset {} size {}",
                chunk.id(),
                d_size,
                user_offset,
                size,
            );
            &d
        } else {
            let c = self.read_chunk_from_backend(chunk.as_ref(), d.mut_slice(), false)?;
            if self.is_compressed {
                match c {
                    Some(v) => {
                        let buf = Arc::new(DataBuffer::Allocated(v));
                        self.delay_persist_chunk_data(chunk.clone(), buf, true);
                        &d
                    }
                    None => {
                        buffer_holder = Arc::new(d.convert_to_owned_buffer());
                        self.delay_persist_chunk_data(chunk.clone(), buffer_holder.clone(), true);
                        buffer_holder.as_ref()
                    }
                }
            } else {
                buffer_holder = Arc::new(d.convert_to_owned_buffer());
                self.delay_persist_chunk_data(chunk.clone(), buffer_holder.clone(), false);
                buffer_holder.as_ref()
            }
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

    fn read_file_cache(&self, chunk: &dyn BlobChunkInfo, buffer: &mut [u8]) -> Result<()> {
        if self.is_compressed {
            let offset = chunk.compressed_offset();
            let size = if self.is_legacy_stargz() {
                self.get_legacy_stargz_size(offset, chunk.uncompressed_size() as usize)? as u64
            } else {
                chunk.compressed_size() as u64
            };
            let mut reader = FileRangeReader::new(&self.file, offset, size);
            if self.compressor() == compress::Algorithm::Lz4Block {
                let mut buf = alloc_buf(size as usize);
                reader.read_exact(&mut buf)?;
                let size = compress::decompress(&buf, buffer, self.compressor)?;
                if size != buffer.len() {
                    return Err(einval!(
                        "data size decoded by lz4_block doesn't match expected"
                    ));
                }
            } else {
                let mut decoder = Decoder::new(reader, self.compressor())?;
                decoder.read_exact(buffer)?;
            }
        } else {
            let offset = chunk.uncompressed_offset();
            let size = chunk.uncompressed_size() as u64;
            FileRangeReader::new(&self.file, offset, size).read_exact(buffer)?;
        }
        self.validate_chunk_data(chunk, buffer, self.need_validate())?;
        Ok(())
    }

    fn merge_requests_for_user(
        &self,
        bios: &[BlobIoDesc],
        max_comp_size: usize,
    ) -> Option<Vec<BlobIoRange>> {
        let mut requests: Vec<BlobIoRange> = Vec::with_capacity(bios.len());

        BlobIoMergeState::merge_and_issue(
            bios,
            max_comp_size,
            max_comp_size as u64 >> RAFS_MERGING_SIZE_TO_GAP_SHIFT,
            |mr: BlobIoRange| {
                requests.push(mr);
            },
        );

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

    fn size(&self) -> usize {
        match self {
            Self::Reuse(_) => 0,
            Self::Allocated(data) => data.capacity(),
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

/// A continuous region in cache file or backend storage/blob, it may contain several chunks.
struct Region {
    r#type: RegionType,
    status: RegionStatus,
    // For debug and trace purpose implying how many chunks are concatenated
    count: u32,

    chunks: Vec<Arc<dyn BlobChunkInfo>>,
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
        chunk: Option<Arc<dyn BlobChunkInfo>>,
    ) -> StorageResult<()> {
        assert_ne!(self.status, RegionStatus::Committed);

        if self.status == RegionStatus::Init {
            self.status = RegionStatus::Open;
            self.blob_address = start;
            self.blob_len = len;
            self.count = 1;
        } else {
            assert_eq!(self.status, RegionStatus::Open);
            let end = self.blob_address + self.blob_len as u64;
            if end + RAFS_DEFAULT_CHUNK_SIZE < start || start.checked_add(len as u64).is_none() {
                return Err(StorageError::NotContinuous);
            }
            let sz = start + len as u64 - end;
            self.blob_len += sz as u32;
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
    // Whether last region can take in more io chunks. If not, a new region has to be
    // created for following chunks.
    last_region_joinable: bool,
}

impl FileIoMergeState {
    fn new() -> Self {
        FileIoMergeState {
            regions: Vec::with_capacity(8),
            last_region_joinable: true,
        }
    }

    fn push(
        &mut self,
        region_type: RegionType,
        start: u64,
        len: u32,
        tag: BlobIoTag,
        chunk: Option<Arc<dyn BlobChunkInfo>>,
    ) -> Result<()> {
        if self.regions.is_empty() || !self.joinable(region_type) {
            self.regions.push(Region::new(region_type));
            self.last_region_joinable = true;
        }

        let idx = self.regions.len() - 1;
        self.regions[idx]
            .append(start, len, tag, chunk)
            .map_err(|e| einval!(e))
    }

    // Committing current region ensures a new region will be created when more
    // chunks has to be added since `push` checks if newly pushed chunk is continuous
    // After committing, following `push` will create a new region.
    fn commit(&mut self) {
        self.last_region_joinable = false;
    }

    fn reset(&mut self) {
        self.regions.truncate(0);
        self.last_region_joinable = true;
    }

    #[inline]
    fn joinable(&self, region_type: RegionType) -> bool {
        assert!(!self.regions.is_empty());
        let idx = self.regions.len() - 1;

        self.regions[idx].r#type.joinable(region_type) && self.last_region_joinable
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
            offset: 0x0000,
            len: 0x2000,
        });
        region.append(0x100004000, 0x2000, tag, None).unwrap_err();
        assert_eq!(region.status, RegionStatus::Open);
        assert_eq!(region.blob_address, 0x1000);
        assert_eq!(region.blob_len, 0x2000);
        assert_eq!(region.seg.offset, 0x1800);
        assert_eq!(region.seg.len, 0x1800);
        assert_eq!(region.chunks.len(), 0);
        assert_eq!(region.tags.len(), 0);
        assert!(region.has_user_io());

        let tag = BlobIoTag::User(BlobIoSegment {
            offset: 0x0000,
            len: 0x2000,
        });
        region.append(0x4000, 0x2000, tag, None).unwrap();
        assert_eq!(region.status, RegionStatus::Open);
        assert_eq!(region.blob_address, 0x1000);
        assert_eq!(region.blob_len, 0x5000);
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
            offset: 0x0000,
            len: 0x2000,
        });
        state
            .push(RegionType::CacheFast, 0x3000, 0x2000, tag, None)
            .unwrap();
        assert_eq!(state.regions.len(), 1);

        let tag = BlobIoTag::User(BlobIoSegment {
            offset: 0x0000,
            len: 0x2000,
        });
        state
            .push(RegionType::CacheSlow, 0x5000, 0x2000, tag, None)
            .unwrap();
        assert_eq!(state.regions.len(), 2);
    }
}
