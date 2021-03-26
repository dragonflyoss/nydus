// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Result, Seek, SeekFrom};
use std::num::NonZeroU32;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex, RwLock,
};
use std::thread;

use nix::sys::uio;
use nix::unistd::dup;

use futures::executor::block_on;
use governor::{
    clock::QuantaClock, state::direct::NotKeyed, state::InMemoryState, Quota, RateLimiter,
};

use vm_memory::VolatileSlice;

use crate::storage::backend::BlobBackend;
use crate::storage::cache::RafsCache;
use crate::storage::cache::*;
use crate::storage::device::{BlobPrefetchControl, RafsBio};
use crate::storage::factory::CacheConfig;
use crate::storage::utils::{alloc_buf, copyv, readv};
use crate::storage::RAFS_DEFAULT_BLOCK_SIZE;

use nydus_utils::{
    digest::RafsDigest,
    einval, enoent, enosys, last_error,
    metrics::{BlobcacheMetrics, Metric},
};

#[derive(Clone, Eq, PartialEq)]
enum CacheStatus {
    Ready,
    NotReady,
}

struct BlobCacheEntry {
    status: CacheStatus,
    chunk: Arc<dyn RafsChunkInfo>,
    fd: RawFd,
}

impl BlobCacheEntry {
    fn new(chunk: Arc<dyn RafsChunkInfo>, fd: RawFd) -> BlobCacheEntry {
        BlobCacheEntry {
            status: CacheStatus::NotReady,
            chunk,
            fd,
        }
    }

    fn is_ready(&self) -> bool {
        self.status == CacheStatus::Ready
    }

    fn set_ready(&mut self) {
        self.status = CacheStatus::Ready
    }

    fn read_partial_chunk(
        &self,
        bufs: &[VolatileSlice],
        offset: u64,
        max_size: usize,
    ) -> Result<usize> {
        readv(self.fd, bufs, offset, max_size)
    }

    /// Persist a single chunk into local blob cache file. We have to write to the cache
    /// file in unit of chunk size
    fn cache(&mut self, buf: &[u8], offset: u64) -> Result<()> {
        loop {
            let ret = uio::pwrite(self.fd, buf, offset as i64).map_err(|_| last_error!());

            match ret {
                Ok(nr_write) => {
                    trace!("write {}(offset={}) bytes to cache file", nr_write, offset);
                    break;
                }
                Err(err) => {
                    // Retry if the IO is interrupted by signal.
                    if err.kind() != ErrorKind::Interrupted {
                        return Err(err);
                    }
                }
            }
        }

        self.set_ready();
        Ok(())
    }
}

#[derive(Default)]
struct BlobCacheState {
    chunk_map: HashMap<RafsDigest, Arc<Mutex<BlobCacheEntry>>>,
    file_map: HashMap<String, (File, u64)>,
    work_dir: String,
    backend_size_valid: bool,
}

impl BlobCacheState {
    fn get_blob_fd(
        &mut self,
        blob_id: &str,
        backend: &(dyn BlobBackend + Sync + Send),
        metrics: &Arc<BlobcacheMetrics>,
    ) -> Result<(RawFd, u64)> {
        if let Some((file, size)) = self.file_map.get(blob_id) {
            return Ok((file.as_raw_fd(), *size));
        }

        let blob_file_path = format!("{}/{}", self.work_dir, blob_id);
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(blob_file_path)?;
        let fd = file.as_raw_fd();

        let size = if self.backend_size_valid {
            backend.blob_size(blob_id).map_err(|e| einval!(e))?
        } else {
            0
        };

        self.file_map.insert(blob_id.to_string(), (file, size));
        metrics
            .underlying_files
            .lock()
            .unwrap()
            .insert(blob_id.to_string());

        Ok((fd, size))
    }

    fn get(&self, blk: &dyn RafsChunkInfo) -> Option<Arc<Mutex<BlobCacheEntry>>> {
        // Do not expect poisoned lock here.
        self.chunk_map.get(&blk.block_id()).cloned()
    }

    fn set(
        &mut self,
        blob_id: &str,
        cki: Arc<dyn RafsChunkInfo>,
        backend: &(dyn BlobBackend + Sync + Send),
        metrics: &Arc<BlobcacheMetrics>,
    ) -> Result<Arc<Mutex<BlobCacheEntry>>> {
        let block_id = *cki.block_id();
        // Double check if someone else has inserted the blob chunk concurrently.
        if let Some(entry) = self.chunk_map.get(&block_id) {
            Ok(entry.clone())
        } else {
            let (fd, _) = self.get_blob_fd(blob_id, backend, metrics)?;
            let entry = Arc::new(Mutex::new(BlobCacheEntry::new(cki, fd)));
            let r = self.chunk_map.insert(block_id, entry.clone());
            if r.is_some() {
                warn!("Entry(block_id={}) is inserted again", block_id);
            }
            metrics.entries_count.inc();
            Ok(entry)
        }
    }
}

pub struct BlobCache {
    cache: Arc<RwLock<BlobCacheState>>,
    validate: bool,
    pub backend: Arc<dyn BlobBackend + Sync + Send>,
    prefetch_worker: PrefetchWorker,
    is_compressed: bool,
    compressor: compress::Algorithm,
    digester: digest::Algorithm,
    // TODO: Directly using Governor RateLimiter makes code a little hard to read as
    // some concepts come from GCRA like "cells". GCRA is a sort of improved "Leaky Bucket"
    // firstly invented from ATM network technology. Wrap the limiter into Throttle!
    limiter: Option<Arc<RateLimiter<NotKeyed, InMemoryState, QuantaClock>>>,
    mr_sender: Arc<Mutex<Option<spmc::Sender<MergedBackendRequest>>>>,
    mr_receiver: Option<spmc::Receiver<MergedBackendRequest>>,
    prefetch_seq: AtomicU64,
    metrics: Arc<BlobcacheMetrics>,
}

impl BlobCache {
    fn entry_read(
        &self,
        blob_id: &str,
        entry: &Mutex<BlobCacheEntry>,
        bufs: &[VolatileSlice],
        offset: u64,
        size: usize,
    ) -> Result<usize> {
        let mut cache_entry = entry.lock().unwrap();
        let chunk = cache_entry.chunk.clone();
        let mut reuse = false;

        // Hit cache if cache ready
        if !self.is_compressed && !self.need_validate() && cache_entry.is_ready() {
            trace!(
                "hit blob cache {} {}",
                chunk.block_id().to_string(),
                chunk.compress_size()
            );
            self.metrics.partial_hits.inc();
            return cache_entry.read_partial_chunk(bufs, offset + chunk.decompress_offset(), size);
        }

        let d_size = chunk.decompress_size() as usize;
        let mut d;
        // one_chunk_buf is the decompressed data buffer
        let one_chunk_buf =
            if !self.is_compressed && bufs.len() == 1 && bufs[0].len() >= d_size && offset == 0 {
                // Optimize for the case where the first VolatileSlice covers the whole chunk.
                // Reuse the destination data buffer.
                reuse = true;
                unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), d_size) }
            } else {
                d = alloc_buf(d_size);
                d.as_mut_slice()
            };

        // Try to recover cache from blobcache first
        // For gzip, we can only trust ready blobcache because we cannot validate chunks due to
        // stargz format limitations (missing chunk level digest)
        if (self.compressor() != compress::Algorithm::GZip || cache_entry.is_ready())
            && self
                .read_blobcache_chunk(
                    cache_entry.fd,
                    chunk.as_ref(),
                    one_chunk_buf,
                    !cache_entry.is_ready() || self.need_validate(),
                )
                .is_ok()
        {
            self.metrics.whole_hits.inc();
            trace!(
                "recover blob cache {} {} reuse {} offset {} size {}",
                chunk.block_id(),
                d_size,
                reuse,
                offset,
                size,
            );
        } else {
            self.read_backend_chunk(blob_id, chunk.as_ref(), one_chunk_buf, |c1, c2| {
                let (chunk, c_offset) = if self.is_compressed {
                    (c1, cache_entry.chunk.compress_offset())
                } else {
                    (c2, cache_entry.chunk.decompress_offset())
                };
                // TODO: Try to make this as a following asynchronous step writing cache
                // This should be help to reduce read latency.
                cache_entry.cache(chunk, c_offset)
            })?;
        }

        if reuse {
            Ok(one_chunk_buf.len())
        } else {
            copyv(one_chunk_buf, bufs, offset, size).map_err(|e| {
                error!("failed to copy from chunk buf to buf: {:?}", e);
                e
            })
        }
    }

    fn read_blobcache_chunk(
        &self,
        fd: RawFd,
        cki: &dyn RafsChunkInfo,
        chunk: &mut [u8],
        need_validate: bool,
    ) -> Result<()> {
        let offset = if self.is_compressed {
            cki.compress_offset()
        } else {
            cki.decompress_offset()
        };

        let mut d;
        let raw_chunk = if self.is_compressed && self.compressor() != compress::Algorithm::GZip {
            // Need to put compressed data into a temporary buffer so as to perform decompression.
            //
            // gzip is special that it doesn't carry compress_size, instead, we make an IO stream out
            // of the blobcache file. So no need for an internal buffer here.
            let c_size = cki.compress_size() as usize;
            d = alloc_buf(c_size);
            d.as_mut_slice()
        } else {
            // We have this unsafe assignment as it can directly store data into call's buffer.
            unsafe { slice::from_raw_parts_mut(chunk.as_mut_ptr(), chunk.len()) }
        };

        let mut raw_stream = None;
        if self.compressor() != compress::Algorithm::GZip {
            debug!(
                "reading blobcache file fd {} offset {} size {}",
                fd,
                offset,
                raw_chunk.len()
            );
            let nr_read = uio::pread(fd, raw_chunk, offset as i64).map_err(|_| last_error!())?;
            if nr_read == 0 || nr_read != raw_chunk.len() {
                return Err(einval!());
            }
        } else {
            debug!(
                "using blobcache file fd {} offset {} as data stream",
                fd, offset,
            );
            // FIXME: In case of multiple threads duplicating the same fd, they still share the same file offset.
            let fd = dup(fd).map_err(|_| last_error!())?;
            let mut f = unsafe { File::from_raw_fd(fd) };
            f.seek(SeekFrom::Start(offset)).map_err(|_| last_error!())?;
            raw_stream = Some(f)
        }

        // Try to validate data just fetched from backend inside.
        self.process_raw_chunk(
            cki,
            raw_chunk,
            raw_stream,
            chunk,
            self.is_compressed,
            need_validate,
        )?;

        Ok(())
    }

    fn is_chunk_continuous(prior: &RafsBio, cur: &RafsBio) -> bool {
        let prior_cki = &prior.chunkinfo;
        let cur_cki = &cur.chunkinfo;
        let prior_end = prior_cki.compress_offset() + prior_cki.compress_size() as u64;
        let cur_offset = cur_cki.compress_offset();
        if prior_end == cur_offset && prior.blob_id == cur.blob_id {
            return true;
        }
        false
    }
    fn generate_merged_requests(
        &self,
        bios: &mut [RafsBio],
        tx: &mut spmc::Sender<MergedBackendRequest>,
        merging_size: usize,
        seq: u64,
    ) {
        let limiter = |merged_size: u32| {
            if let Some(ref limiter) = self.limiter {
                let cells = NonZeroU32::new(merged_size).unwrap();
                if let Err(e) = limiter
                    .check_n(cells)
                    .or_else(|_| block_on(limiter.until_n_ready(cells)))
                {
                    // `InsufficientCapacity` is the only possible error
                    // Have to give up to avoid dead-loop
                    error!("{}: give up rate-limiting", e);
                }
            }
        };

        bios.sort_by_key(|entry| entry.chunkinfo.compress_offset());
        let mut index: usize = 1;
        if bios.is_empty() {
            return;
        }
        let first_cki = &bios[0].chunkinfo;
        let mut mr = MergedBackendRequest::new(seq);
        mr.merge_begin(Arc::clone(first_cki), &bios[0].blob_id);

        if bios.len() == 1 {
            limiter(mr.blob_size);
            tx.send(mr).unwrap();
            return;
        }

        loop {
            let cki = &bios[index].chunkinfo;
            let prior_bio = &bios[index - 1];
            let cur_bio = &bios[index];
            // Even more chunks are continuous, still split them as per certain size.
            // So that to achieve an appropriate request size to backend.
            if Self::is_chunk_continuous(prior_bio, cur_bio) && mr.blob_size <= merging_size as u32
            {
                mr.merge_one_chunk(Arc::clone(&cki));
            } else {
                // New a MR if a non-continuous chunk is met.
                limiter(mr.blob_size);
                tx.send(mr.clone()).unwrap();
                mr.reset();
                mr.merge_begin(Arc::clone(&cki), &cur_bio.blob_id);
            }
            index += 1;
            if index >= bios.len() {
                limiter(mr.blob_size);
                tx.send(mr).unwrap();
                break;
            }
        }
    }
}

// TODO: This function is too long... :-(
fn kick_prefetch_workers(cache: &Arc<BlobCache>) {
    for num in 0..cache.prefetch_worker.threads_count {
        let blobcache = cache.clone();
        let rx = blobcache.mr_receiver.clone();
        // TODO: We now don't define prefetch policy. Prefetch works according to hints coming
        // from on-disk prefetch table or input arguments while nydusd starts. So better
        // we can have method to kill prefetch threads. But hopefully, we can add
        // another new prefetch policy triggering prefetch files belonging to the same
        // directory while one of them is read. We can easily get a continuous region on blob
        // that way.
        let _thread = thread::Builder::new()
            .name(format!("prefetch_thread_{}", num))
            .spawn(move || {
                blobcache
                    .metrics
                    .prefetch_workers
                    .fetch_add(1, Ordering::Relaxed);
                // Safe because channel must be established before prefetch workers
                'wait_mr: while let Ok(mr) = rx.as_ref().unwrap().recv() {
                    let blob_offset = mr.blob_offset;
                    let blob_size = mr.blob_size;
                    let continuous_chunks = &mr.chunks;
                    let blob_id = &mr.blob_id;
                    let mut issue_batch: bool;

                    trace!(
                        "Merged req id {} seq {} req offset {} size {}",
                        blob_id,
                        &mr.seq,
                        blob_offset,
                        blob_size
                    );

                    if blob_size == 0 {
                        continue;
                    }

                    if continuous_chunks.len() > 2 {
                        blobcache
                            .metrics
                            .prefetch_total_size
                            .add(blob_size as usize);
                        blobcache.metrics.prefetch_mr_count.inc();
                    }

                    blobcache
                        .metrics
                        .prefetch_data_amount
                        .add(blob_size as usize);

                    issue_batch = false;
                    // An immature trick here to detect if chunk already resides in
                    // blob cache file. Hopefully, we can have a more clever and agile
                    // way in the future. Principe is that if all chunks are Ready,
                    // abort this Merged Request. It might involve extra stress
                    // to local file system.
                    for c in continuous_chunks {
                        let d_size = c.decompress_size() as usize;
                        let entry = blobcache
                            .cache
                            .write()
                            .expect("Expect cache lock not poisoned")
                            .set(blob_id, c.clone(), blobcache.backend(), &blobcache.metrics);
                        if let Ok(entry) = entry {
                            let mut entry = entry.lock().unwrap();
                            if entry.is_ready() {
                                continue;
                            }
                            let fd = entry.fd;
                            let chunk = entry.chunk.clone();
                            // Always validate if chunk's hash is equal to `block_id` by which
                            // blobcache judges if the data is up-to-date.
                            if blobcache
                                .read_blobcache_chunk(
                                    fd,
                                    chunk.as_ref(),
                                    alloc_buf(d_size).as_mut_slice(),
                                    true,
                                )
                                .is_err()
                            {
                                // Aha, we have a not integrated chunk here. Issue the entire
                                // merged request from backend to boost.
                                issue_batch = true;
                                break;
                            } else {
                                entry.set_ready();
                            }
                        }
                    }

                    if !issue_batch {
                        continue 'wait_mr;
                    }

                    if let Ok(chunks) = blobcache.read_chunks(
                        blob_id,
                        blob_offset,
                        blob_size as usize,
                        &continuous_chunks,
                    ) {
                        for (i, c) in continuous_chunks.iter().enumerate() {
                            let mut cache_guard = blobcache
                                .cache
                                .write()
                                .expect("Expect cache lock not poisoned");

                            if let Ok(entry) = cache_guard
                                .set(blob_id, c.clone(), blobcache.backend(), &blobcache.metrics)
                                .map_err(|_| error!("Set cache index error!"))
                            {
                                let mut entry = entry.lock().unwrap();
                                if !entry.is_ready() {
                                    let offset = if blobcache.is_compressed {
                                        entry.chunk.compress_offset()
                                    } else {
                                        entry.chunk.decompress_offset()
                                    };
                                    if let Err(err) = entry.cache(chunks[i].as_slice(), offset) {
                                        error!("Failed to cache chunk: {}", err);
                                    }
                                }
                            }
                        }
                    }
                }
                blobcache
                    .metrics
                    .prefetch_workers
                    .fetch_sub(1, Ordering::Relaxed);
                info!("Prefetch thread exits.")
            });
    }
}

impl RafsCache for BlobCache {
    fn init(&self, blobs: &[BlobPrefetchControl]) -> Result<()> {
        // Backend may be capable to prefetch a range of blob bypass upper file system
        // to blobcache. This should be asynchronous, so filesystem read cache hit
        // should validate data integrity.
        for b in blobs {
            let _ = self.backend.prefetch_blob(&b.blob_id, b.offset, b.len);
        }
        Ok(())
    }

    fn backend(&self) -> &(dyn BlobBackend + Sync + Send) {
        self.backend.as_ref()
    }

    fn has(&self, cki: &dyn RafsChunkInfo) -> bool {
        // Doesn't expected poisoned lock here.
        self.cache
            .read()
            .unwrap()
            .chunk_map
            .contains_key(cki.block_id())
    }

    fn evict(&self, cki: &dyn RafsChunkInfo) -> Result<()> {
        // Doesn't expect poisoned lock here.
        self.cache.write().unwrap().chunk_map.remove(cki.block_id());
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        Err(enosys!())
    }

    fn read(&self, bio: &RafsBio, bufs: &[VolatileSlice], offset: u64) -> Result<usize> {
        let blob_id = &bio.blob_id;

        self.metrics.total.inc();

        let mut entry = self.cache.read().unwrap().get(bio.chunkinfo.as_ref());
        if entry.is_none() {
            let en = self.cache.write().unwrap().set(
                blob_id,
                bio.chunkinfo.clone(),
                self.backend(),
                &self.metrics,
            )?;
            entry = Some(en);
        };

        self.entry_read(blob_id, &entry.unwrap(), bufs, offset, bio.size)
    }

    fn write(&self, _blob_id: &str, _blk: &dyn RafsChunkInfo, _buf: &[u8]) -> Result<usize> {
        Err(enosys!())
    }

    fn blob_size(&self, blob_id: &str) -> Result<u64> {
        let (_, size) =
            self.cache
                .write()
                .unwrap()
                .get_blob_fd(blob_id, self.backend(), &self.metrics)?;
        Ok(size)
    }

    fn release(&self) {
        self.metrics.release().unwrap_or_else(|e| error!("{:?}", e));

        // TODO: Cache is responsible to release backend's resources
        self.backend().release()
    }
    fn prefetch(&self, bios: &mut [RafsBio]) -> StorageResult<usize> {
        let merging_size = self.prefetch_worker.merging_size;
        let seq = self.prefetch_seq.fetch_add(1, Ordering::Relaxed);

        self.metrics.prefetch_unmerged_chunks.add(bios.len());

        if let Some(mr_sender) = self.mr_sender.lock().unwrap().as_mut() {
            self.generate_merged_requests(bios, mr_sender, merging_size, seq);
        }

        Ok(0)
    }

    fn stop_prefetch(&self) -> StorageResult<()> {
        drop(self.mr_sender.lock().unwrap().take().unwrap());
        Ok(())
    }

    #[inline]
    fn digester(&self) -> digest::Algorithm {
        self.digester
    }

    #[inline]
    fn compressor(&self) -> compress::Algorithm {
        self.compressor
    }

    #[inline]
    fn need_validate(&self) -> bool {
        self.validate
    }
}

#[derive(Clone, Deserialize)]
struct BlobCacheConfig {
    #[serde(default = "default_work_dir")]
    work_dir: String,
}

fn default_work_dir() -> String {
    ".".to_string()
}

pub fn new(
    config: CacheConfig,
    backend: Arc<dyn BlobBackend + Sync + Send>,
    compressor: compress::Algorithm,
    digester: digest::Algorithm,
    id: &str,
) -> Result<Arc<BlobCache>> {
    let blob_config: BlobCacheConfig =
        serde_json::from_value(config.cache_config).map_err(|e| einval!(e))?;
    let work_dir = {
        let path = fs::metadata(&blob_config.work_dir)
            .or_else(|_| {
                fs::create_dir_all(&blob_config.work_dir)?;
                fs::metadata(&blob_config.work_dir)
            })
            .map_err(|e| {
                last_error!(format!(
                    "fail to stat blobcache work_dir {}: {}",
                    blob_config.work_dir, e
                ))
            })?;
        if path.is_dir() {
            Ok(blob_config.work_dir.as_str())
        } else {
            Err(enoent!(format!(
                "blobcache work_dir {} is not a directory",
                blob_config.work_dir
            )))
        }
    }?;

    // If the given value is less than blob chunk size, it exceeds burst size of the limiter ending
    // up with throttling all throughput.
    // TODO: We get the chunk size by a constant which is the default value and it's not
    // easy to get real value now. Perhaps we should have a configuration center?
    let tweaked_bw_limit = if config.prefetch_worker.bandwidth_rate != 0 {
        std::cmp::max(
            RAFS_DEFAULT_BLOCK_SIZE as u32,
            config.prefetch_worker.bandwidth_rate,
        )
    } else {
        0
    };

    let limiter = NonZeroU32::new(tweaked_bw_limit).map(|v| {
        info!("Prefetch bandwidth will be limited at {}Bytes/S", v);
        Arc::new(RateLimiter::direct(Quota::per_second(v)))
    });

    let mut enabled = false;
    let (tx, rx) = if config.prefetch_worker.enable {
        let (send, recv) = spmc::channel::<MergedBackendRequest>();
        enabled = true;
        (Some(send), Some(recv))
    } else {
        (None, None)
    };

    let cache = Arc::new(BlobCache {
        cache: Arc::new(RwLock::new(BlobCacheState {
            chunk_map: HashMap::new(),
            file_map: HashMap::new(),
            work_dir: work_dir.to_string(),
            backend_size_valid: compressor == compress::Algorithm::GZip,
        })),
        validate: config.cache_validate,
        is_compressed: config.cache_compressed,
        backend,
        prefetch_worker: config.prefetch_worker,
        compressor,
        digester,
        limiter,
        mr_sender: Arc::new(Mutex::new(tx)),
        mr_receiver: rx,
        prefetch_seq: AtomicU64::new(0),
        metrics: BlobcacheMetrics::new(id, work_dir),
    });

    cache
        .metrics
        .prefetch_policy
        .lock()
        .unwrap()
        .insert("hinted".to_string());

    if enabled {
        kick_prefetch_workers(&cache);
    }

    Ok(cache)
}

#[cfg(test)]
mod blob_cache_tests {
    use std::alloc::{alloc, Layout};
    use std::slice::from_raw_parts;
    use std::sync::Arc;

    use vm_memory::{VolatileMemory, VolatileSlice};
    use vmm_sys_util::tempdir::TempDir;

    use crate::impl_getter;
    use crate::storage::backend::{BackendResult, BlobBackend};
    use crate::storage::cache::blobcache;
    use crate::storage::cache::PrefetchWorker;
    use crate::storage::cache::RafsCache;
    use crate::storage::compress;
    use crate::storage::device::{RafsBio, RafsChunkFlags, RafsChunkInfo};
    use crate::storage::factory::CacheConfig;
    use crate::storage::RAFS_DEFAULT_BLOCK_SIZE;

    use nydus_utils::{
        digest::{self, RafsDigest},
        metrics::BackendMetrics,
    };

    struct MockBackend {
        metrics: Arc<BackendMetrics>,
    }

    impl BlobBackend for MockBackend {
        fn try_read(&self, _blob_id: &str, buf: &mut [u8], _offset: u64) -> BackendResult<usize> {
            let mut i = 0;
            while i < buf.len() {
                buf[i] = i as u8;
                i += 1;
            }
            Ok(i)
        }

        fn write(&self, _blob_id: &str, _buf: &[u8], _offset: u64) -> BackendResult<usize> {
            Ok(0)
        }

        fn blob_size(&self, _blob_id: &str) -> BackendResult<u64> {
            Ok(0)
        }

        fn release(&self) {}

        fn prefetch_blob(
            &self,
            _blob_id: &str,
            _blob_readahead_offset: u32,
            _blob_readahead_size: u32,
        ) -> BackendResult<()> {
            Ok(())
        }

        fn metrics(&self) -> &BackendMetrics {
            // Safe because nydusd must have backend attached with id, only image builder can no id
            // but use backend instance to upload blob.
            &self.metrics
        }
    }

    #[derive(Default, Clone)]
    struct MockChunkInfo {
        pub block_id: RafsDigest,
        pub blob_index: u32,
        pub flags: RafsChunkFlags,
        pub compress_size: u32,
        pub decompress_size: u32,
        pub compress_offset: u64,
        pub decompress_offset: u64,
        pub file_offset: u64,
        pub reserved: u64,
    }

    impl MockChunkInfo {
        fn new() -> Self {
            MockChunkInfo::default()
        }
    }

    impl RafsChunkInfo for MockChunkInfo {
        fn block_id(&self) -> &RafsDigest {
            &self.block_id
        }
        fn is_compressed(&self) -> bool {
            self.flags.contains(RafsChunkFlags::COMPRESSED)
        }
        fn is_hole(&self) -> bool {
            self.flags.contains(RafsChunkFlags::HOLECHUNK)
        }
        impl_getter!(blob_index, blob_index, u32);
        impl_getter!(compress_offset, compress_offset, u64);
        impl_getter!(compress_size, compress_size, u32);
        impl_getter!(decompress_offset, decompress_offset, u64);
        impl_getter!(decompress_size, decompress_size, u32);
        impl_getter!(file_offset, file_offset, u64);
        impl_getter!(flags, flags, RafsChunkFlags);
    }

    #[test]
    fn test_add() {
        // new blob cache
        let tmp_dir = TempDir::new().unwrap();
        let s = format!(
            r###"
        {{
            "work_dir": {:?}
        }}
        "###,
            tmp_dir.as_path().to_path_buf().join("cache"),
        );

        let cache_config = CacheConfig {
            cache_validate: true,
            cache_compressed: false,
            cache_type: String::from("blobcache"),
            cache_config: serde_json::from_str(&s).unwrap(),
            prefetch_worker: PrefetchWorker::default(),
        };
        let blob_cache = blobcache::new(
            cache_config,
            Arc::new(MockBackend {
                metrics: BackendMetrics::new("id", "mock"),
            }) as Arc<dyn BlobBackend + Send + Sync>,
            compress::Algorithm::LZ4Block,
            digest::Algorithm::Blake3,
            "id",
        )
        .unwrap();

        // generate backend data
        let mut expect = vec![1u8; 100];
        let blob_id = "blobcache";
        blob_cache
            .backend
            .read(blob_id, expect.as_mut(), 0)
            .unwrap();

        // generate chunk and bio
        let mut chunk = MockChunkInfo::new();
        chunk.block_id = RafsDigest::from_buf(&expect, digest::Algorithm::Blake3);
        chunk.file_offset = 0;
        chunk.compress_offset = 0;
        chunk.compress_size = 100;
        chunk.decompress_offset = 0;
        chunk.decompress_size = 100;
        let bio = RafsBio::new(
            Arc::new(chunk),
            blob_id.to_string(),
            50,
            50,
            RAFS_DEFAULT_BLOCK_SIZE as u32,
        );

        // read from cache
        let r1 = unsafe {
            let layout = Layout::from_size_align(50, 1).unwrap();
            let ptr = alloc(layout);
            let vs = VolatileSlice::new(ptr, 50);
            blob_cache.read(&bio, &[vs], 50).unwrap();
            let data = Vec::from(from_raw_parts(ptr, 50));
            // Don't dealloc as `data` already gets the ownership
            // dealloc(ptr, layout);
            data
        };

        let r2 = unsafe {
            let layout = Layout::from_size_align(50, 1).unwrap();
            let ptr = alloc(layout);
            let vs = VolatileSlice::new(ptr, 50);
            blob_cache.read(&bio, &[vs], 50).unwrap();
            let data = Vec::from(from_raw_parts(ptr, 50));
            // Don't dealloc as `data` already gets the ownership
            // dealloc(ptr, layout);
            data
        };

        assert_eq!(r1, &expect[50..]);
        assert_eq!(r2, &expect[50..]);
    }
}
