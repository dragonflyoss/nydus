// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Common cached file object for `FileCacheMgr` and `FsCacheMgr`.
//!
//! The `FileCacheEntry` manages local cached blob objects from remote backends to improve
//! performance. It may be used by both the userspace `FileCacheMgr` or the `FsCacheMgr` based
//! on the in-kernel fscache system.

use std::collections::HashSet;
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
use nydus_utils::crypt::{self, Cipher, CipherContext};
use nydus_utils::metrics::{BlobcacheMetrics, Metric};
use nydus_utils::{compress, digest, round_up_usize, DelayType, Delayer, FileRangeReader};
use tokio::runtime::Runtime;

use crate::backend::BlobReader;
use crate::cache::state::ChunkMap;
use crate::cache::worker::{AsyncPrefetchConfig, AsyncPrefetchMessage, AsyncWorkerMgr};
use crate::cache::{BlobCache, BlobIoMergeState};
use crate::device::{
    BlobChunkInfo, BlobInfo, BlobIoDesc, BlobIoRange, BlobIoSegment, BlobIoTag, BlobIoVec,
    BlobObject, BlobPrefetchRequest,
};
use crate::meta::{BlobCompressionContextInfo, BlobMetaChunk};
use crate::utils::{alloc_buf, copyv, readv, MemSliceCursor};
use crate::{StorageError, StorageResult, RAFS_BATCH_SIZE_TO_GAP_SHIFT, RAFS_DEFAULT_CHUNK_SIZE};

const DOWNLOAD_META_RETRY_COUNT: u32 = 5;
const DOWNLOAD_META_RETRY_DELAY: u64 = 400;
const ENCRYPTION_PAGE_SIZE: usize = 4096;

#[derive(Default, Clone)]
pub(crate) struct FileCacheMeta {
    has_error: Arc<AtomicBool>,
    meta: Arc<Mutex<Option<Arc<BlobCompressionContextInfo>>>>,
}

impl FileCacheMeta {
    pub(crate) fn new(
        blob_file: String,
        blob_info: Arc<BlobInfo>,
        reader: Option<Arc<dyn BlobReader>>,
        runtime: Option<Arc<Runtime>>,
        sync: bool,
        validation: bool,
    ) -> Result<Self> {
        if sync {
            match BlobCompressionContextInfo::new(
                &blob_file,
                &blob_info,
                reader.as_ref(),
                validation,
            ) {
                Ok(m) => Ok(FileCacheMeta {
                    has_error: Arc::new(AtomicBool::new(false)),
                    meta: Arc::new(Mutex::new(Some(Arc::new(m)))),
                }),
                Err(e) => Err(e),
            }
        } else {
            let meta = FileCacheMeta {
                has_error: Arc::new(AtomicBool::new(false)),
                meta: Arc::new(Mutex::new(None)),
            };
            let meta1 = meta.clone();

            if let Some(r) = runtime {
                r.as_ref().spawn_blocking(move || {
                    let mut retry = 0;
                    let mut delayer = Delayer::new(
                        DelayType::BackOff,
                        Duration::from_millis(DOWNLOAD_META_RETRY_DELAY),
                    );
                    while retry < DOWNLOAD_META_RETRY_COUNT {
                        match BlobCompressionContextInfo::new(
                            &blob_file,
                            &blob_info,
                            reader.as_ref(),
                            validation,
                        ) {
                            Ok(m) => {
                                *meta1.meta.lock().unwrap() = Some(Arc::new(m));
                                return;
                            }
                            Err(e) => {
                                info!("temporarily failed to get blob.meta, {}", e);
                                delayer.delay();
                                retry += 1;
                            }
                        }
                    }
                    warn!("failed to get blob.meta");
                    meta1.has_error.store(true, Ordering::Release);
                });
            } else {
                warn!("Want download blob meta asynchronously but no runtime.");
            }

            Ok(meta)
        }
    }

    pub(crate) fn get_blob_meta(&self) -> Option<Arc<BlobCompressionContextInfo>> {
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
    pub(crate) blob_id: String,
    pub(crate) blob_info: Arc<BlobInfo>,
    pub(crate) cache_cipher_object: Arc<Cipher>,
    pub(crate) cache_cipher_context: Arc<CipherContext>,
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
    // Whether `get_blob_object()` is supported.
    pub(crate) is_get_blob_object_supported: bool,
    // Cache raw data from backend instead of decompressed/decrypted plaintext.
    pub(crate) is_raw_data: bool,
    // The data in cache file is uncompressed and encrypted.
    pub(crate) is_cache_encrypted: bool,
    // Whether direct chunkmap is used.
    pub(crate) is_direct_chunkmap: bool,
    // The blob is for an stargz image.
    pub(crate) is_legacy_stargz: bool,
    // The blob is for an RAFS filesystem in `TARFS` mode.
    pub(crate) is_tarfs: bool,
    // The blob contains batch chunks.
    pub(crate) is_batch: bool,
    // The blob is based on ZRan decompression algorithm.
    pub(crate) is_zran: bool,
    // True if direct IO is enabled for the `self.file`, supported for fscache only.
    pub(crate) dio_enabled: bool,
    // Data from the file cache should be validated before use.
    pub(crate) need_validation: bool,
    pub(crate) batch_size: u64,
    pub(crate) prefetch_config: Arc<AsyncPrefetchConfig>,
}

impl FileCacheEntry {
    pub(crate) fn get_blob_size(reader: &Arc<dyn BlobReader>, blob_info: &BlobInfo) -> Result<u64> {
        // Stargz needs blob size information, so hacky!
        let size = if blob_info.is_legacy_stargz() {
            reader.blob_size().map_err(|e| einval!(e))?
        } else {
            blob_info.compressed_size()
        };

        Ok(size)
    }

    fn delay_persist_chunk_data(&self, chunk: Arc<dyn BlobChunkInfo>, buffer: Arc<DataBuffer>) {
        let delayed_chunk_map = self.chunk_map.clone();
        let file = self.file.clone();
        let metrics = self.metrics.clone();
        let is_raw_data = self.is_raw_data;
        let is_cache_encrypted = self.is_cache_encrypted;
        let cipher_object = self.cache_cipher_object.clone();
        let cipher_context = self.cache_cipher_context.clone();

        metrics.buffered_backend_size.add(buffer.size() as u64);
        self.runtime.spawn_blocking(move || {
            metrics.buffered_backend_size.sub(buffer.size() as u64);
            let mut t_buf;
            let buf = if !is_raw_data && is_cache_encrypted {
                let (key, iv) = cipher_context.generate_cipher_meta(&chunk.chunk_id().data);
                let buf = buffer.slice();
                t_buf = alloc_buf(round_up_usize(buf.len(), ENCRYPTION_PAGE_SIZE));

                let mut pos = 0;
                while pos < buf.len() {
                    let mut s_buf;
                    // Padding to buffer to 4096 bytes if needed.
                    let buf = if pos + ENCRYPTION_PAGE_SIZE > buf.len() {
                        s_buf = buf[pos..].to_vec();
                        s_buf.resize(ENCRYPTION_PAGE_SIZE, 0);
                        &s_buf
                    } else {
                        &buf[pos..pos + ENCRYPTION_PAGE_SIZE]
                    };

                    assert_eq!(buf.len(), ENCRYPTION_PAGE_SIZE);
                    match cipher_object.encrypt(key, Some(&iv), buf) {
                        Ok(buf2) => {
                            assert_eq!(buf2.len(), ENCRYPTION_PAGE_SIZE);
                            t_buf[pos..pos + ENCRYPTION_PAGE_SIZE].copy_from_slice(buf2.as_ref());
                            pos += ENCRYPTION_PAGE_SIZE;
                        }
                        Err(_) => {
                            Self::_update_chunk_pending_status(
                                &delayed_chunk_map,
                                chunk.as_ref(),
                                false,
                            );
                            return;
                        }
                    }
                }
                &t_buf
            } else {
                buffer.slice()
            };

            let offset = if is_raw_data {
                chunk.compressed_offset()
            } else {
                chunk.uncompressed_offset()
            };
            let res = Self::persist_cached_data(&file, offset, buf);
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

    fn prefetch_batch_size(&self) -> u64 {
        if self.prefetch_config.merging_size < 0x2_0000 {
            0x2_0000
        } else {
            self.prefetch_config.merging_size as u64
        }
    }

    fn ondemand_batch_size(&self) -> u64 {
        if self.batch_size < 0x2_0000 {
            0x2_0000
        } else {
            self.batch_size
        }
    }

    fn extend_pending_chunks(
        &self,
        chunks: &[Arc<dyn BlobChunkInfo>],
        batch_size: u64,
    ) -> Result<Option<Vec<Arc<dyn BlobChunkInfo>>>> {
        assert!(!chunks.is_empty());
        match self.get_blob_meta_info() {
            Err(e) => Err(e),
            Ok(None) => Ok(None),
            Ok(Some(bm)) => {
                let v = bm.add_more_chunks(chunks, batch_size)?;
                Ok(Some(self.strip_ready_chunks(bm, Some(chunks), v)))
            }
        }
    }

    fn strip_ready_chunks(
        &self,
        meta: Arc<BlobCompressionContextInfo>,
        old_chunks: Option<&[Arc<dyn BlobChunkInfo>]>,
        mut extended_chunks: Vec<Arc<dyn BlobChunkInfo>>,
    ) -> Vec<Arc<dyn BlobChunkInfo>> {
        if self.is_zran {
            let mut set = HashSet::new();
            for c in extended_chunks.iter() {
                if !matches!(self.chunk_map.is_ready(c.as_ref()), Ok(true)) {
                    set.insert(meta.get_zran_index(c.id()));
                }
            }

            let first = old_chunks.as_ref().map(|v| v[0].id()).unwrap_or(u32::MAX);
            let mut start = 0;
            while start < extended_chunks.len() - 1 {
                let id = extended_chunks[start].id();
                if id == first || set.contains(&meta.get_zran_index(id)) {
                    break;
                }
                start += 1;
            }

            let last = old_chunks
                .as_ref()
                .map(|v| v[v.len() - 1].id())
                .unwrap_or(u32::MAX);
            let mut end = extended_chunks.len() - 1;
            while end > start {
                let id = extended_chunks[end].id();
                if id == last || set.contains(&meta.get_zran_index(id)) {
                    break;
                }
                end -= 1;
            }

            assert!(end >= start, "start 0x{:x}, end 0x{:x}", start, end);
            if start == 0 && end == extended_chunks.len() - 1 {
                extended_chunks
            } else {
                extended_chunks[start..=end].to_vec()
            }
        } else {
            while !extended_chunks.is_empty() {
                let chunk = &extended_chunks[extended_chunks.len() - 1];
                if matches!(self.chunk_map.is_ready(chunk.as_ref()), Ok(true)) {
                    extended_chunks.pop();
                } else {
                    break;
                }
            }
            extended_chunks
        }
    }

    fn get_blob_range(&self, chunks: &[Arc<dyn BlobChunkInfo>]) -> Result<(u64, u64, usize)> {
        assert!(!chunks.is_empty());
        let (start, end) = if self.is_zran {
            let meta = self
                .get_blob_meta_info()?
                .ok_or_else(|| einval!("failed to get blob meta object"))?;
            let zran_index = meta.get_zran_index(chunks[0].id());
            let (ctx, _) = meta
                .get_zran_context(zran_index)
                .ok_or_else(|| einval!("failed to get ZRan context for chunk"))?;
            let blob_start = ctx.in_offset;
            let zran_index = meta.get_zran_index(chunks[chunks.len() - 1].id());
            let (ctx, _) = meta
                .get_zran_context(zran_index)
                .ok_or_else(|| einval!("failed to get ZRan context for chunk"))?;
            let blob_end = ctx.in_offset + ctx.in_len as u64;
            (blob_start, blob_end)
        } else if self.is_batch {
            let meta = self
                .get_blob_meta_info()?
                .ok_or_else(|| einval!("failed to get blob meta object"))?;

            let (c_offset, _) = meta.get_compressed_info(chunks[0].id())?;
            let blob_start = c_offset;

            let (c_offset, c_size) = meta.get_compressed_info(chunks[chunks.len() - 1].id())?;
            let blob_end = c_offset + c_size as u64;

            (blob_start, blob_end)
        } else {
            let last = chunks.len() - 1;
            (chunks[0].compressed_offset(), chunks[last].compressed_end())
        };

        let size = end - start;
        if end - start > u32::MAX as u64 {
            Err(einval!(
                "requested blob range is too bigger, larger than u32::MAX"
            ))
        } else {
            Ok((start, end, size as usize))
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
        &self.blob_id
    }

    fn blob_uncompressed_size(&self) -> Result<u64> {
        Ok(self.blob_uncompressed_size)
    }

    fn blob_compressed_size(&self) -> Result<u64> {
        Ok(self.blob_compressed_size)
    }

    fn blob_compressor(&self) -> compress::Algorithm {
        self.blob_info.compressor()
    }

    fn blob_cipher(&self) -> crypt::Algorithm {
        self.blob_info.cipher()
    }

    fn blob_cipher_object(&self) -> Arc<Cipher> {
        self.blob_info.cipher_object()
    }

    fn blob_cipher_context(&self) -> Option<CipherContext> {
        self.blob_info.cipher_context()
    }

    fn blob_digester(&self) -> digest::Algorithm {
        self.blob_info.digester()
    }

    fn is_legacy_stargz(&self) -> bool {
        self.is_legacy_stargz
    }

    fn is_batch(&self) -> bool {
        self.is_batch
    }

    fn is_zran(&self) -> bool {
        self.is_zran
    }

    fn need_validation(&self) -> bool {
        self.need_validation
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
                self.workers.flush_pending_prefetch_requests(&self.blob_id);
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
        let max_comp_size = self.prefetch_batch_size();
        let mut bios = bios.to_vec();
        bios.sort_unstable_by_key(|entry| entry.chunkinfo.compressed_offset());
        self.metrics.prefetch_unmerged_chunks.add(bios.len() as u64);
        BlobIoMergeState::merge_and_issue(
            &bios,
            max_comp_size,
            max_comp_size as u64 >> RAFS_BATCH_SIZE_TO_GAP_SHIFT,
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
            // Figure out the range with continuous chunk ids, be careful that `end` is inclusive.
            let mut end = start;
            while end < pending.len() - 1 && pending[end + 1].id() == pending[end].id() + 1 {
                end += 1;
            }

            let (blob_offset, _blob_end, blob_size) = self.get_blob_range(&pending[start..=end])?;
            match self.read_chunks_from_backend(blob_offset, blob_size, &pending[start..=end], true)
            {
                Ok(mut bufs) => {
                    total_size += blob_size;
                    if self.is_raw_data {
                        let res = Self::persist_cached_data(
                            &self.file,
                            blob_offset,
                            bufs.compressed_buf(),
                        );
                        for c in pending.iter().take(end + 1).skip(start) {
                            self.update_chunk_pending_status(c.as_ref(), res.is_ok());
                        }
                    } else {
                        for idx in start..=end {
                            let buf = match bufs.next() {
                                None => return Err(einval!("invalid chunk decompressed status")),
                                Some(Err(e)) => {
                                    for chunk in &mut pending[idx..=end] {
                                        self.update_chunk_pending_status(chunk.as_ref(), false);
                                    }
                                    return Err(e);
                                }
                                Some(Ok(v)) => v,
                            };
                            self.persist_chunk_data(pending[idx].as_ref(), &buf);
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

    fn get_blob_meta_info(&self) -> Result<Option<Arc<BlobCompressionContextInfo>>> {
        if let Some(meta) = self.meta.as_ref() {
            if let Some(bm) = meta.get_blob_meta() {
                Ok(Some(bm))
            } else {
                Err(einval!("failed to get blob meta object for cache file"))
            }
        } else {
            Ok(None)
        }
    }
}

impl BlobObject for FileCacheEntry {
    fn base_offset(&self) -> u64 {
        0
    }

    fn is_all_data_ready(&self) -> bool {
        // Assume data from tar file is always ready.
        if self.is_tarfs {
            true
        } else if let Some(b) = self.chunk_map.as_range_map() {
            b.is_range_all_ready()
        } else {
            false
        }
    }

    fn fetch_range_compressed(&self, offset: u64, size: u64, prefetch: bool) -> Result<()> {
        // Assume data from tar file is always ready.
        if self.is_tarfs {
            return Ok(());
        }

        let meta = self.meta.as_ref().ok_or_else(|| enoent!())?;
        let meta = meta.get_blob_meta().ok_or_else(|| einval!())?;
        let mut chunks =
            meta.get_chunks_compressed(offset, size, self.prefetch_batch_size(), prefetch)?;
        if !chunks.is_empty() {
            if let Some(meta) = self.get_blob_meta_info()? {
                chunks = self.strip_ready_chunks(meta, None, chunks);
            }
        } else {
            return Err(einval!(format!(
                "fetch_range_compressed offset 0x{:x}, size 0x{:x}",
                offset, size
            )));
        }
        if chunks.is_empty() {
            Ok(())
        } else {
            self.do_fetch_chunks(&chunks, true)
        }
    }

    fn fetch_range_uncompressed(&self, offset: u64, size: u64) -> Result<()> {
        // Assume data from tar file is always ready.
        if self.is_tarfs {
            return Ok(());
        }

        let meta = self.meta.as_ref().ok_or_else(|| einval!())?;
        let meta = meta.get_blob_meta().ok_or_else(|| einval!())?;
        let mut chunks = meta.get_chunks_uncompressed(offset, size, self.ondemand_batch_size())?;
        if let Some(meta) = self.get_blob_meta_info()? {
            chunks = self.strip_ready_chunks(meta, None, chunks);
        }
        if chunks.is_empty() {
            Ok(())
        } else {
            self.do_fetch_chunks(&chunks, false)
        }
    }

    fn prefetch_chunks(&self, range: &BlobIoRange) -> Result<()> {
        // Assume data from tar file is always ready.
        if self.is_tarfs {
            return Ok(());
        }

        let chunks_extended;
        let mut chunks = &range.chunks;
        if let Some(v) = self.extend_pending_chunks(chunks, self.prefetch_batch_size())? {
            chunks_extended = v;
            chunks = &chunks_extended;
        }

        let mut start = 0;
        while start < chunks.len() {
            // Figure out the range with continuous chunk ids, be careful that `end` is inclusive.
            let mut end = start;
            while end < chunks.len() - 1 && chunks[end + 1].id() == chunks[end].id() + 1 {
                end += 1;
            }
            self.do_fetch_chunks(&chunks[start..=end], true)?;
            start = end + 1;
        }

        Ok(())
    }
}

impl FileCacheEntry {
    fn do_fetch_chunks(&self, chunks: &[Arc<dyn BlobChunkInfo>], prefetch: bool) -> Result<()> {
        // Validate input parameters.
        assert!(!chunks.is_empty());

        // Get chunks not ready yet, also marking them as in-flight.
        let bitmap = self
            .chunk_map
            .as_range_map()
            .ok_or_else(|| einval!("invalid chunk_map for do_fetch_chunks()"))?;
        let chunk_index = chunks[0].id();
        let count = chunks.len() as u32;
        let pending = match bitmap.check_range_ready_and_mark_pending(chunk_index, count)? {
            None => return Ok(()),
            Some(v) => v,
        };

        let mut status = vec![false; count as usize];
        let (start_idx, end_idx) = {
            let mut start = u32::MAX;
            let mut end = 0;
            for chunk_id in pending.iter() {
                status[(*chunk_id - chunk_index) as usize] = true;
                start = std::cmp::min(*chunk_id - chunk_index, start);
                end = std::cmp::max(*chunk_id - chunk_index, end);
            }
            (start as usize, end as usize)
        };

        if start_idx <= end_idx {
            let start_chunk = &chunks[start_idx];
            let end_chunk = &chunks[end_idx];
            let (blob_offset, blob_end, blob_size) =
                self.get_blob_range(&chunks[start_idx..=end_idx])?;
            trace!(
                "fetch data range {:x}-{:x} for chunk {}-{} from blob {:x}",
                blob_offset,
                blob_end,
                start_chunk.id(),
                end_chunk.id(),
                chunks[0].blob_index()
            );

            match self.read_chunks_from_backend(
                blob_offset,
                blob_size,
                &chunks[start_idx..=end_idx],
                prefetch,
            ) {
                Ok(mut bufs) => {
                    if self.is_raw_data {
                        let res = Self::persist_cached_data(
                            &self.file,
                            blob_offset,
                            bufs.compressed_buf(),
                        );
                        for idx in start_idx..=end_idx {
                            if status[idx] {
                                self.update_chunk_pending_status(chunks[idx].as_ref(), res.is_ok());
                            }
                        }
                    } else {
                        for idx in start_idx..=end_idx {
                            let mut buf = match bufs.next() {
                                None => return Err(einval!("invalid chunk decompressed status")),
                                Some(Err(e)) => {
                                    for idx in idx..=end_idx {
                                        if status[idx] {
                                            bitmap.clear_range_pending(chunks[idx].id(), 1)
                                        }
                                    }
                                    return Err(e);
                                }
                                Some(Ok(v)) => v,
                            };

                            if status[idx] {
                                if self.dio_enabled {
                                    self.adjust_buffer_for_dio(&mut buf)
                                }
                                self.persist_chunk_data(chunks[idx].as_ref(), buf.as_ref());
                            }
                        }
                    }
                }
                Err(e) => {
                    for idx in 0..chunks.len() {
                        if status[idx] {
                            bitmap.clear_range_pending(chunks[idx].id(), 1)
                        }
                    }
                    return Err(e);
                }
            }
        }

        if !bitmap.wait_for_range_ready(chunk_index, count)? {
            if prefetch {
                return Err(eio!(format!(
                    "failed to prefetch data from storage backend for chunk {}/{}",
                    chunk_index, count
                )));
            }

            // if we are in on-demand path, retry for the timeout chunks
            for chunk in chunks {
                match self.chunk_map.check_ready_and_mark_pending(chunk.as_ref()) {
                    Err(e) => return Err(eio!(format!("do_fetch_chunks failed, {:?}", e))),
                    Ok(true) => {}
                    Ok(false) => {
                        info!("retry for timeout chunk, {}", chunk.id());
                        let mut buf = alloc_buf(chunk.uncompressed_size() as usize);
                        self.read_chunk_from_backend(chunk.as_ref(), &mut buf)
                            .map_err(|e| {
                                self.update_chunk_pending_status(chunk.as_ref(), false);
                                eio!(format!("read_raw_chunk failed, {:?}", e))
                            })?;
                        if self.dio_enabled {
                            self.adjust_buffer_for_dio(&mut buf)
                        }
                        self.persist_chunk_data(chunk.as_ref(), &buf);
                    }
                }
            }
        }

        Ok(())
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
            .merge_requests_for_user(bios, self.ondemand_batch_size())
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

            // Directly read chunk data from file cache into user buffer iff:
            // - the chunk is ready in the file cache
            // - data in the file cache is plaintext.
            // - data validation is disabled
            if is_ready && !self.is_raw_data && !self.is_cache_encrypted && !self.need_validation()
            {
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

                let (start, len) = if let Ok(Some(meta)) = self.get_blob_meta_info() {
                    meta.get_compressed_info(chunk.id())?
                } else {
                    (chunk.compressed_offset(), chunk.compressed_size())
                };

                // NOTE: Only this request region can read more chunks from backend with user io.
                state.push(RegionType::Backend, start, len, tag, Some(chunk.clone()))?;
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

    fn dispatch_backend(&self, mem_cursor: &mut MemSliceCursor, r: &Region) -> Result<usize> {
        let mut region = r;
        debug!(
            "{} try to read {} bytes of {} chunks from backend",
            std::thread::current().name().unwrap_or_default(),
            region.blob_len,
            region.chunks.len()
        );

        if region.chunks.is_empty() {
            return Ok(0);
        } else if !region.has_user_io() {
            debug!("No user data");
            for c in &region.chunks {
                self.chunk_map.clear_pending(c.as_ref());
            }
            return Ok(0);
        }
        if region.chunks.len() > 1 {
            for idx in 0..region.chunks.len() - 1 {
                let end = region.chunks[idx].compressed_offset()
                    + region.chunks[idx].compressed_size() as u64;
                let start = region.chunks[idx + 1].compressed_offset();
                assert!(end <= start);
                assert!(start - end <= self.ondemand_batch_size() >> RAFS_BATCH_SIZE_TO_GAP_SHIFT);
                assert!(region.chunks[idx].id() < region.chunks[idx + 1].id());
            }
        }

        // Try to extend requests.
        let mut region_hold;
        if let Some(v) = self.extend_pending_chunks(&region.chunks, self.ondemand_batch_size())? {
            if v.len() > r.chunks.len() {
                let mut tag_set = HashSet::new();
                for (idx, chunk) in region.chunks.iter().enumerate() {
                    if region.tags[idx] {
                        tag_set.insert(chunk.id());
                    }
                }

                region_hold = Region::with(self, region, v)?;
                for (idx, c) in region_hold.chunks.iter().enumerate() {
                    if tag_set.contains(&c.id()) {
                        region_hold.tags[idx] = true;
                    }
                }
                region = &region_hold;
                trace!(
                    "extended blob request from 0x{:x}/0x{:x} to 0x{:x}/0x{:x} with {} chunks",
                    r.blob_address,
                    r.blob_len,
                    region_hold.blob_address,
                    region_hold.blob_len,
                    region_hold.chunks.len(),
                );
            }
        }

        if self.is_zran() {
            let mut r = region.clone();
            let (blob_offset, _blob_end, blob_size) = self.get_blob_range(&r.chunks)?;
            r.blob_address = blob_offset;
            r.blob_len = blob_size as u32;
            region_hold = r;
            region = &region_hold;
        }

        let bufs = self
            .read_chunks_from_backend(
                region.blob_address,
                region.blob_len as usize,
                &region.chunks,
                false,
            )
            .map_err(|e| {
                for c in &region.chunks {
                    self.chunk_map.clear_pending(c.as_ref());
                }
                e
            })?;

        if self.is_raw_data {
            let res =
                Self::persist_cached_data(&self.file, region.blob_address, bufs.compressed_buf());
            for chunk in region.chunks.iter() {
                self.update_chunk_pending_status(chunk.as_ref(), res.is_ok());
            }
            res?;
        }

        let mut chunk_buffers = Vec::with_capacity(region.chunks.len());
        let mut buffer_holder = Vec::with_capacity(region.chunks.len());
        for (i, v) in bufs.enumerate() {
            let d = Arc::new(DataBuffer::Allocated(v?));
            if region.tags[i] {
                buffer_holder.push(d.clone());
            }
            if !self.is_raw_data {
                self.delay_persist_chunk_data(region.chunks[i].clone(), d);
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

    // Called with chunk in READY or PENDING state, exit with chunk set to READY or PENDING cleared.
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
        // - it's an stargz image and the chunk is ready.
        // - chunk data validation is enabled.
        // - digested or dummy chunk map is used.
        let is_ready = self.chunk_map.is_ready(chunk.as_ref())?;
        let try_cache = is_ready || !self.is_direct_chunkmap;
        let buffer = if try_cache && self.read_file_cache(chunk.as_ref(), d.mut_slice()).is_ok() {
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
            let c = self
                .read_chunk_from_backend(chunk.as_ref(), d.mut_slice())
                .map_err(|e| {
                    self.chunk_map.clear_pending(chunk.as_ref());
                    e
                })?;
            if self.is_raw_data {
                match c {
                    Some(v) => {
                        let buf = Arc::new(DataBuffer::Allocated(v));
                        self.delay_persist_chunk_data(chunk.clone(), buf);
                        &d
                    }
                    None => {
                        buffer_holder = Arc::new(d.convert_to_owned_buffer());
                        self.delay_persist_chunk_data(chunk.clone(), buffer_holder.clone());
                        buffer_holder.as_ref()
                    }
                }
            } else {
                buffer_holder = Arc::new(d.convert_to_owned_buffer());
                self.delay_persist_chunk_data(chunk.clone(), buffer_holder.clone());
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
        if self.is_raw_data {
            let offset = chunk.compressed_offset();
            let size = if self.is_legacy_stargz() {
                self.get_legacy_stargz_size(offset, chunk.uncompressed_size() as usize)? as u64
            } else {
                chunk.compressed_size() as u64
            };
            let mut reader = FileRangeReader::new(&self.file, offset, size);
            if !chunk.is_compressed() {
                reader.read_exact(buffer)?;
            } else if self.blob_compressor() == compress::Algorithm::Lz4Block {
                let mut buf = alloc_buf(size as usize);
                reader.read_exact(&mut buf)?;
                let size = compress::decompress(&buf, buffer, self.blob_compressor())?;
                if size != buffer.len() {
                    return Err(einval!(
                        "data size decoded by lz4_block doesn't match expected"
                    ));
                }
            } else {
                let mut decoder = Decoder::new(reader, self.blob_compressor())?;
                decoder.read_exact(buffer)?;
            }
        } else if self.is_cache_encrypted {
            let offset = chunk.uncompressed_offset();
            let size = chunk.uncompressed_size() as usize;
            let cipher_object = self.cache_cipher_object.clone();
            let cipher_context = self.cache_cipher_context.clone();
            let (key, iv) = cipher_context.generate_cipher_meta(&chunk.chunk_id().data);

            let align_size = round_up_usize(size, ENCRYPTION_PAGE_SIZE);
            let mut buf = alloc_buf(align_size);
            FileRangeReader::new(&self.file, offset, align_size as u64).read_exact(&mut buf)?;

            let mut pos = 0;
            while pos < buffer.len() {
                assert!(pos + ENCRYPTION_PAGE_SIZE <= buf.len());
                match cipher_object.decrypt(key, Some(&iv), &buf[pos..pos + ENCRYPTION_PAGE_SIZE]) {
                    Ok(buf2) => {
                        let len = std::cmp::min(buffer.len() - pos, ENCRYPTION_PAGE_SIZE);
                        buffer[pos..pos + len].copy_from_slice(&buf2[..len]);
                        pos += ENCRYPTION_PAGE_SIZE;
                    }
                    Err(_) => return Err(eother!("failed to decrypt data from cache file")),
                }
            }
        } else {
            let offset = chunk.uncompressed_offset();
            let size = chunk.uncompressed_size() as u64;
            FileRangeReader::new(&self.file, offset, size).read_exact(buffer)?;
        }
        self.validate_chunk_data(chunk, buffer, false)?;
        Ok(())
    }

    fn merge_requests_for_user(
        &self,
        bios: &[BlobIoDesc],
        max_comp_size: u64,
    ) -> Option<Vec<BlobIoRange>> {
        let mut requests: Vec<BlobIoRange> = Vec::with_capacity(bios.len());

        BlobIoMergeState::merge_and_issue(
            bios,
            max_comp_size,
            max_comp_size >> RAFS_BATCH_SIZE_TO_GAP_SHIFT,
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

#[derive(Clone, Copy, Debug, PartialEq)]
enum RegionStatus {
    Init,
    Open,
    Committed,
}

#[derive(Clone, Copy, Debug, PartialEq)]
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
#[derive(Clone)]
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

    fn with(
        ctx: &FileCacheEntry,
        region: &Region,
        chunks: Vec<Arc<dyn BlobChunkInfo>>,
    ) -> Result<Self> {
        assert!(!chunks.is_empty());
        let len = chunks.len();

        let meta = ctx
            .get_blob_meta_info()?
            .ok_or_else(|| einval!("failed to get blob meta object"))?;
        let (blob_address, blob_len) = if ctx.is_batch && meta.is_batch_chunk(chunks[0].id()) {
            // Assert all chunks are in the same batch.
            meta.get_compressed_info(chunks[0].id())?
        } else {
            let ba = chunks[0].compressed_offset();
            let last = &chunks[len - 1];
            let sz = last.compressed_offset() - ba;
            assert!(sz < u32::MAX as u64);

            (ba, sz as u32 + last.compressed_size())
        };

        Ok(Region {
            r#type: region.r#type,
            status: region.status,
            count: len as u32,
            chunks,
            tags: vec![false; len],
            blob_address,
            blob_len,
            seg: region.seg.clone(),
        })
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
