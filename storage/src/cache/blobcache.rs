// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Result, Seek, SeekFrom};
use std::num::NonZeroU32;
use std::ops::DerefMut;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::{
    atomic::{AtomicU32, AtomicU64, Ordering},
    Arc, Mutex, RwLock,
};
use std::thread::{self, JoinHandle};

use nix::sys::uio;
use nix::unistd::dup;

use futures::executor::block_on;
use governor::{
    clock::QuantaClock, state::direct::NotKeyed, state::InMemoryState, Quota, RateLimiter,
};

use vm_memory::VolatileSlice;

use crate::backend::BlobBackend;
use crate::cache::chunkmap::{digested::DigestedChunkMap, indexed::IndexedChunkMap, ChunkMap};
use crate::cache::RafsCache;
use crate::cache::*;
use crate::device::{BlobPrefetchControl, RafsBio, RafsBlobEntry};
use crate::factory::CacheConfig;
use crate::utils::{alloc_buf, copyv, readv};
use crate::RAFS_DEFAULT_BLOCK_SIZE;

use nydus_utils::{
    einval, enoent, enosys, last_error,
    metrics::{BlobcacheMetrics, Metric},
};

struct BlobCacheState {
    /// Index blob info by blob index, HashMap<blob_index, (blob_file, blob_size, Arc<ChunkMap>)>.
    blob_map: HashMap<u32, (File, u64, Arc<dyn ChunkMap + Sync + Send>)>,
    work_dir: String,
    backend_size_valid: bool,
    metrics: Arc<BlobcacheMetrics>,
    backend: Arc<dyn BlobBackend + Sync + Send>,
}

impl BlobCacheState {
    fn get(&self, blob: &RafsBlobEntry) -> Option<(RawFd, u64, Arc<dyn ChunkMap + Sync + Send>)> {
        self.blob_map
            .get(&blob.blob_index)
            .map(|(file, size, chunk_map)| (file.as_raw_fd(), *size, chunk_map.clone()))
    }

    fn set(
        &mut self,
        blob: &RafsBlobEntry,
    ) -> Result<(RawFd, u64, Arc<dyn ChunkMap + Sync + Send>)> {
        if let Some((fd, size, chunk_map)) = self.get(blob) {
            return Ok((fd, size, chunk_map));
        }

        let blob_file_path = format!("{}/{}", self.work_dir, blob.blob_id);
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(&blob_file_path)?;
        let fd = file.as_raw_fd();

        let size = if self.backend_size_valid {
            self.backend
                .blob_size(&blob.blob_id)
                .map_err(|e| einval!(e))?
        } else {
            0
        };

        // The builder now records the number of chunks in the blob table, so we can
        // use IndexedChunkMap as a chunk map, but for the old Nydus bootstrap, we
        // need downgrade to use DigestedChunkMap as a compatible solution.
        let chunk_map = if blob.with_extended_blob_table() {
            Arc::new(IndexedChunkMap::new(&blob_file_path, blob.chunk_count)?)
                as Arc<dyn ChunkMap + Sync + Send>
        } else {
            Arc::new(DigestedChunkMap::new()) as Arc<dyn ChunkMap + Sync + Send>
        };

        self.blob_map
            .insert(blob.blob_index, (file, size, chunk_map.clone()));

        self.metrics
            .underlying_files
            .lock()
            .unwrap()
            .insert(blob.blob_id.to_string());

        Ok((fd, size, chunk_map))
    }
}

struct PrefetchContext {
    pub enable: bool,
    pub threads_count: usize,
    pub merging_size: usize,
    // In unit of Bytes and Zero means no rate limit is set.
    pub bandwidth_rate: u32,
    pub workers: AtomicU32,
}

impl From<PrefetchWorker> for PrefetchContext {
    fn from(p: PrefetchWorker) -> Self {
        PrefetchContext {
            enable: p.enable,
            threads_count: p.threads_count,
            merging_size: p.merging_size,
            bandwidth_rate: p.bandwidth_rate,
            workers: AtomicU32::new(0),
        }
    }
}

impl PrefetchContext {
    fn is_working(&self) -> bool {
        self.enable && self.workers.load(Ordering::Relaxed) != 0
    }

    fn shrink_n(&self, n: u32) {
        self.workers.fetch_sub(n, Ordering::Relaxed);
    }

    fn grow_n(&self, n: u32) {
        self.workers.fetch_add(n, Ordering::Relaxed);
    }
}

pub struct BlobCache {
    cache: Arc<RwLock<BlobCacheState>>,
    validate: bool,
    pub backend: Arc<dyn BlobBackend + Sync + Send>,
    prefetch_ctx: PrefetchContext,
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
    prefetch_threads: Mutex<Vec<JoinHandle<()>>>,
}

impl BlobCache {
    fn entry_read(
        &self,
        blob: &RafsBlobEntry,
        chunk: &dyn RafsChunkInfo,
        bufs: &[VolatileSlice],
        offset: u64,
        size: usize,
    ) -> Result<(usize, bool)> {
        let cache_guard = self.cache.read().unwrap();
        let (fd, _, chunk_map) = match cache_guard.get(blob) {
            Some(entry) => entry,
            None => {
                drop(cache_guard);
                self.cache.write().unwrap().set(blob)?
            }
        };
        let has_ready = chunk_map.has_ready(chunk)?;
        let mut reuse = false;

        // Hit cache if cache ready
        if !self.is_compressed && !self.need_validate() && has_ready {
            trace!(
                "hit blob cache {} {}",
                chunk.block_id().to_string(),
                chunk.compress_size()
            );
            self.metrics.partial_hits.inc();
            let read_size =
                self.read_partial_chunk(fd, bufs, offset + chunk.decompress_offset(), size)?;
            return Ok((read_size, has_ready));
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
        if (self.compressor() != compress::Algorithm::GZip || has_ready)
            && self
                .read_blobcache_chunk(fd, chunk, one_chunk_buf, !has_ready || self.need_validate())
                .is_ok()
        {
            self.metrics.whole_hits.inc();
            chunk_map.set_ready(chunk)?;
            trace!(
                "recover blob cache {} {} reuse {} offset {} size {}",
                chunk.block_id(),
                d_size,
                reuse,
                offset,
                size,
            );
        } else {
            self.read_backend_chunk(blob, chunk, one_chunk_buf, |buf| {
                let offset = if self.is_compressed {
                    chunk.compress_offset()
                } else {
                    chunk.decompress_offset()
                };
                // TODO: Try to make this as a following asynchronous step writing cache
                // This should be help to reduce read latency.
                self.cache(fd, buf, offset)?;
                chunk_map.set_ready(chunk)?;
                Ok(())
            })?;
        }

        if reuse {
            Ok((one_chunk_buf.len(), has_ready))
        } else {
            let read_size = copyv(one_chunk_buf, bufs, offset, size).map_err(|e| {
                error!("failed to copy from chunk buf to buf: {:?}", e);
                e
            })?;
            Ok((read_size, has_ready))
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

    fn read_partial_chunk(
        &self,
        fd: RawFd,
        bufs: &[VolatileSlice],
        offset: u64,
        max_size: usize,
    ) -> Result<usize> {
        readv(fd, bufs, offset, max_size)
    }

    /// Persist a single chunk into local blob cache file. We have to write to the cache
    /// file in unit of chunk size
    fn cache(&self, fd: RawFd, buf: &[u8], offset: u64) -> Result<()> {
        loop {
            let ret = uio::pwrite(fd, buf, offset as i64).map_err(|_| last_error!());

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

        Ok(())
    }

    fn convert_to_merge_request(seq: u64, continuous_bios: &[&RafsBio]) -> MergedBackendRequest {
        let first = continuous_bios[0];
        let mut mr = MergedBackendRequest::new(seq, first.chunkinfo.clone(), first.blob.clone());

        for c in &continuous_bios[1..] {
            mr.merge_one_chunk(Arc::clone(&c.chunkinfo));
        }

        mr
    }

    fn is_chunk_continuous(prior: &RafsBio, cur: &RafsBio) -> bool {
        let prior_cki = &prior.chunkinfo;
        let cur_cki = &cur.chunkinfo;
        let prior_end = prior_cki.compress_offset() + prior_cki.compress_size() as u64;
        let cur_offset = cur_cki.compress_offset();
        if prior_end == cur_offset && prior.blob.blob_id == cur.blob.blob_id {
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
        if bios.is_empty() {
            return;
        }

        let mut continuous_bios = Vec::new();
        continuous_bios.push(&bios[0]);
        let mut accumulated_size = bios[0].chunkinfo.compress_size();

        let mut index = 1;

        for _ in &bios[1..] {
            let prior_bio = &bios[index - 1];
            let cur_bio = &bios[index];

            if Self::is_chunk_continuous(prior_bio, cur_bio)
                && accumulated_size <= merging_size as u32
            {
                continuous_bios.push(&cur_bio);
                accumulated_size += cur_bio.chunkinfo.compress_size();
            } else {
                // New a MR if a non-continuous chunk is met.
                if continuous_bios.is_empty() {
                    continue;
                }
                let mr = Self::convert_to_merge_request(seq, &continuous_bios);
                limiter(mr.blob_size);
                tx.send(mr).unwrap();
                continuous_bios.truncate(0);

                // current bio is not continuous with prior one,
                // so it is the first bio of next merged request.
                continuous_bios.push(&cur_bio);
                accumulated_size = cur_bio.chunkinfo.compress_size();
            }
            index += 1
        }

        // No more bio left, convert the collected bios to merged request and sent it.
        if !continuous_bios.is_empty() {
            let mr = Self::convert_to_merge_request(seq, &continuous_bios);
            limiter(mr.blob_size);
            tx.send(mr).unwrap();
        }
    }
}

// TODO: This function is too long... :-(
fn kick_prefetch_workers(cache: Arc<BlobCache>) {
    for num in 0..cache.prefetch_ctx.threads_count {
        let blobcache = cache.clone();
        let rx = blobcache.mr_receiver.clone();
        // TODO: We now don't define prefetch policy. Prefetch works according to hints coming
        // from on-disk prefetch table or input arguments while nydusd starts. So better
        // we can have method to kill prefetch threads. But hopefully, we can add
        // another new prefetch policy triggering prefetch files belonging to the same
        // directory while one of them is read. We can easily get a continuous region on blob
        // that way.
        thread::Builder::new()
            .name(format!("prefetch_thread_{}", num))
            .spawn(move || {
                blobcache.prefetch_ctx.grow_n(1);
                blobcache
                    .metrics
                    .prefetch_workers
                    .fetch_add(1, Ordering::Relaxed);
                // Safe because channel must be established before prefetch workers
                'wait_mr: while let Ok(mr) = rx.as_ref().unwrap().recv() {
                    let blob_offset = mr.blob_offset;
                    let blob_size = mr.blob_size;
                    let continuous_chunks = &mr.chunks;
                    let blob_id = &mr.blob_entry.blob_id;
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
                    let ee = blobcache
                        .cache
                        .read()
                        .expect("Expect cache lock not poisoned")
                        .get(&mr.blob_entry);

                    let (fd, _, chunk_map) = if let Some(be) = ee {
                        be
                    } else {
                        match blobcache
                            .cache
                            .write()
                            .expect("Expect cache lock not poisoned")
                            .set(&mr.blob_entry)
                        {
                            Err(err) => {
                                error!("{}", err);
                                continue;
                            }
                            Ok(be) => be,
                        }
                    };

                    for c in continuous_chunks {
                        if chunk_map.has_ready(c.as_ref()).unwrap_or_default() {
                            continue;
                        }

                        if !&mr.blob_entry.with_extended_blob_table() {
                            // Always validate if chunk's hash is equal to `block_id` by which
                            // blobcache judges if the data is up-to-date.
                            let d_size = c.decompress_size() as usize;
                            if blobcache
                                .read_blobcache_chunk(
                                    fd,
                                    c.as_ref(),
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
                                let _ = chunk_map
                                    .set_ready(c.as_ref())
                                    .map_err(|e| error!("Failed to set chunk ready: {:?}", e));
                            }
                        } else {
                            issue_batch = true;
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
                        // TODO: The locking granularity below is a little big. We
                        // don't have to hold blobcache mutex when writing files.
                        // But prefetch io is usually limited. So it is low priority.
                        let mut cache_guard = blobcache
                            .cache
                            .write()
                            .expect("Expect cache lock not poisoned");
                        if let Ok((fd, _, chunk_map)) = cache_guard
                            .set(&mr.blob_entry)
                            .map_err(|_| error!("Set cache index error!"))
                        {
                            for (i, c) in continuous_chunks.iter().enumerate() {
                                if !chunk_map.has_ready(c.as_ref()).unwrap_or_default() {
                                    let offset = if blobcache.is_compressed {
                                        c.compress_offset()
                                    } else {
                                        c.decompress_offset()
                                    };
                                    if let Err(err) =
                                        blobcache.cache(fd, chunks[i].as_slice(), offset)
                                    {
                                        error!("Failed to cache chunk: {}", err);
                                    } else {
                                        let _ = chunk_map.set_ready(c.as_ref()).map_err(|e| {
                                            error!("Failed to set chunk ready: {:?}", e)
                                        });
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
                blobcache.prefetch_ctx.shrink_n(1);
                info!("Prefetch thread exits.")
            })
            .map(|t| {
                cache
                    .prefetch_threads
                    .lock()
                    .expect("Not expect poisoned lock")
                    .push(t)
            })
            .unwrap_or_else(|e| error!("Create prefetch worker failed, {:?}", e));
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

    fn read(&self, bio: &RafsBio, bufs: &[VolatileSlice], offset: u64) -> Result<usize> {
        self.metrics.total.inc();

        // Try to get rid of effect from prefetch.
        if self.prefetch_ctx.is_working() {
            if let Some(ref limiter) = self.limiter {
                if let Some(v) = NonZeroU32::new(bufs.len() as u32) {
                    // Even fails in getting tokens, continue to read
                    limiter.check_n(v).unwrap_or(());
                }
            }
        }

        let (size, before_ready) =
            self.entry_read(&bio.blob, bio.chunkinfo.as_ref(), bufs, offset, bio.size)?;

        // The flag means the chunk is not ready before, but now ready,
        // so increase the entries_count metric.
        if !before_ready {
            self.metrics.entries_count.inc();
        }

        Ok(size)
    }

    fn write(&self, _blob_id: &str, _blk: &dyn RafsChunkInfo, _buf: &[u8]) -> Result<usize> {
        Err(enosys!())
    }

    fn blob_size(&self, blob: &RafsBlobEntry) -> Result<u64> {
        let cache_guard = self.cache.read().unwrap();
        let (_, size, _) = match cache_guard.get(blob) {
            Some(entry) => entry,
            None => {
                drop(cache_guard);
                self.cache.write().unwrap().set(blob)?
            }
        };
        Ok(size)
    }

    fn release(&self) {
        self.metrics.release().unwrap_or_else(|e| error!("{:?}", e));

        // TODO: Cache is responsible to release backend's resources
        self.backend().release()
    }
    fn prefetch(&self, bios: &mut [RafsBio]) -> StorageResult<usize> {
        let merging_size = self.prefetch_ctx.merging_size;
        let seq = self.prefetch_seq.fetch_add(1, Ordering::Relaxed);

        self.metrics.prefetch_unmerged_chunks.add(bios.len());

        if let Some(mr_sender) = self.mr_sender.lock().unwrap().as_mut() {
            self.generate_merged_requests(bios, mr_sender, merging_size, seq);
        }

        Ok(0)
    }

    fn stop_prefetch(&self) -> StorageResult<()> {
        if let Some(s) = self.mr_sender.lock().unwrap().take() {
            drop(s);
        }

        let mut guard = self
            .prefetch_threads
            .lock()
            .expect("Not expect poisoned lock");
        let threads = guard.deref_mut();

        while let Some(t) = threads.pop() {
            t.join()
                .unwrap_or_else(|e| error!("Thread might panic, {:?}", e));
        }

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

    let metrics = BlobcacheMetrics::new(id, work_dir);
    let cache = Arc::new(BlobCache {
        cache: Arc::new(RwLock::new(BlobCacheState {
            blob_map: HashMap::new(),
            work_dir: work_dir.to_string(),
            backend_size_valid: compressor == compress::Algorithm::GZip,
            metrics: metrics.clone(),
            backend: backend.clone(),
        })),
        validate: config.cache_validate,
        is_compressed: config.cache_compressed,
        backend,
        prefetch_ctx: config.prefetch_worker.into(),
        compressor,
        digester,
        limiter,
        mr_sender: Arc::new(Mutex::new(tx)),
        mr_receiver: rx,
        prefetch_seq: AtomicU64::new(0),
        metrics,
        prefetch_threads: Mutex::new(Vec::<_>::new()),
    });

    if enabled {
        kick_prefetch_workers(cache.clone());
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

    use crate::backend::{BackendResult, BlobBackend};
    use crate::cache::{blobcache, MergedBackendRequest, PrefetchWorker, RafsCache};
    use crate::compress;
    use crate::device::{RafsBio, RafsBlobEntry, RafsChunkFlags, RafsChunkInfo};
    use crate::factory::CacheConfig;
    use crate::impl_getter;
    use crate::RAFS_DEFAULT_BLOCK_SIZE;

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
        pub index: u32,
        pub reserved: u32,
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
        impl_getter!(index, index, u32);
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
            Arc::new(RafsBlobEntry {
                chunk_count: 0,
                readahead_offset: 0,
                readahead_size: 0,
                blob_id: blob_id.to_string(),
                blob_index: 0,
                blob_cache_size: 0,
            }),
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
            Vec::from(from_raw_parts(ptr, 50))
        };

        let r2 = unsafe {
            let layout = Layout::from_size_align(50, 1).unwrap();
            let ptr = alloc(layout);
            let vs = VolatileSlice::new(ptr, 50);
            blob_cache.read(&bio, &[vs], 50).unwrap();
            Vec::from(from_raw_parts(ptr, 50))
        };

        assert_eq!(r1, &expect[50..]);
        assert_eq!(r2, &expect[50..]);
    }

    #[test]
    fn test_merge_bio() {
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

        let merging_size: u64 = 128 * 1024 * 1024;

        let single_chunk = MockChunkInfo {
            compress_offset: 1000,
            compress_size: merging_size as u32 - 1,
            ..Default::default()
        };

        let bio = RafsBio::new(
            Arc::new(single_chunk.clone()),
            Arc::new(RafsBlobEntry {
                chunk_count: 0,
                readahead_offset: 0,
                readahead_size: 0,
                blob_id: "1".to_string(),
                blob_index: 0,
                blob_cache_size: 0,
            }),
            50,
            50,
            RAFS_DEFAULT_BLOCK_SIZE as u32,
        );

        let (mut send, recv) = spmc::channel::<MergedBackendRequest>();
        let mut bios = vec![bio];

        blob_cache.generate_merged_requests(&mut bios, &mut send, merging_size as usize, 1);
        let mr = recv.recv().unwrap();

        assert_eq!(mr.blob_offset, single_chunk.compress_offset());
        assert_eq!(mr.blob_size, single_chunk.compress_size());

        // ---
        let chunk1 = MockChunkInfo {
            compress_offset: 1000,
            compress_size: merging_size as u32 - 2000,
            ..Default::default()
        };

        let bio1 = RafsBio::new(
            Arc::new(chunk1.clone()),
            Arc::new(RafsBlobEntry {
                chunk_count: 0,
                readahead_offset: 0,
                readahead_size: 0,
                blob_id: "1".to_string(),
                blob_index: 0,
                blob_cache_size: 0,
            }),
            50,
            50,
            RAFS_DEFAULT_BLOCK_SIZE as u32,
        );

        let chunk2 = MockChunkInfo {
            compress_offset: 1000 + merging_size - 2000,
            compress_size: 200,
            ..Default::default()
        };

        let bio2 = RafsBio::new(
            Arc::new(chunk2.clone()),
            Arc::new(RafsBlobEntry {
                chunk_count: 0,
                readahead_offset: 0,
                readahead_size: 0,
                blob_id: "1".to_string(),
                blob_index: 0,
                blob_cache_size: 0,
            }),
            50,
            50,
            RAFS_DEFAULT_BLOCK_SIZE as u32,
        );

        let mut bios = vec![bio1, bio2];
        let (mut send, recv) = spmc::channel::<MergedBackendRequest>();
        blob_cache.generate_merged_requests(&mut bios, &mut send, merging_size as usize, 1);
        let mr = recv.recv().unwrap();

        assert_eq!(mr.blob_offset, chunk1.compress_offset());
        assert_eq!(
            mr.blob_size,
            chunk1.compress_size() + chunk2.compress_size()
        );

        // ---
        let chunk1 = MockChunkInfo {
            compress_offset: 1000,
            compress_size: merging_size as u32 - 2000,
            ..Default::default()
        };

        let bio1 = RafsBio::new(
            Arc::new(chunk1.clone()),
            Arc::new(RafsBlobEntry {
                chunk_count: 0,
                readahead_offset: 0,
                readahead_size: 0,
                blob_id: "1".to_string(),
                blob_index: 0,
                blob_cache_size: 0,
            }),
            50,
            50,
            RAFS_DEFAULT_BLOCK_SIZE as u32,
        );

        let chunk2 = MockChunkInfo {
            compress_offset: 1000 + merging_size - 2000 + 1,
            compress_size: 200,
            ..Default::default()
        };

        let bio2 = RafsBio::new(
            Arc::new(chunk2.clone()),
            Arc::new(RafsBlobEntry {
                chunk_count: 0,
                readahead_offset: 0,
                readahead_size: 0,
                blob_id: "1".to_string(),
                blob_index: 0,
                blob_cache_size: 0,
            }),
            50,
            50,
            RAFS_DEFAULT_BLOCK_SIZE as u32,
        );

        let mut bios = vec![bio1, bio2];
        let (mut send, recv) = spmc::channel::<MergedBackendRequest>();
        blob_cache.generate_merged_requests(&mut bios, &mut send, merging_size as usize, 1);

        let mr = recv.recv().unwrap();
        assert_eq!(mr.blob_offset, chunk1.compress_offset());
        assert_eq!(mr.blob_size, chunk1.compress_size());

        let mr = recv.recv().unwrap();
        assert_eq!(mr.blob_offset, chunk2.compress_offset());
        assert_eq!(mr.blob_size, chunk2.compress_size());

        // ---
        let chunk1 = MockChunkInfo {
            compress_offset: 1000,
            compress_size: merging_size as u32 - 2000,
            ..Default::default()
        };

        let bio1 = RafsBio::new(
            Arc::new(chunk1.clone()),
            Arc::new(RafsBlobEntry {
                chunk_count: 0,
                readahead_offset: 0,
                readahead_size: 0,
                blob_id: "1".to_string(),
                blob_index: 0,
                blob_cache_size: 0,
            }),
            50,
            50,
            RAFS_DEFAULT_BLOCK_SIZE as u32,
        );

        let chunk2 = MockChunkInfo {
            compress_offset: 1000 + merging_size - 2000,
            compress_size: 200,
            ..Default::default()
        };

        let bio2 = RafsBio::new(
            Arc::new(chunk2.clone()),
            Arc::new(RafsBlobEntry {
                chunk_count: 0,
                readahead_offset: 0,
                readahead_size: 0,
                blob_id: "2".to_string(),
                blob_index: 0,
                blob_cache_size: 0,
            }),
            50,
            50,
            RAFS_DEFAULT_BLOCK_SIZE as u32,
        );

        let mut bios = vec![bio1, bio2];
        let (mut send, recv) = spmc::channel::<MergedBackendRequest>();
        blob_cache.generate_merged_requests(&mut bios, &mut send, merging_size as usize, 1);

        let mr = recv.recv().unwrap();
        assert_eq!(mr.blob_offset, chunk1.compress_offset());
        assert_eq!(mr.blob_size, chunk1.compress_size());

        let mr = recv.recv().unwrap();
        assert_eq!(mr.blob_offset, chunk2.compress_offset());
        assert_eq!(mr.blob_size, chunk2.compress_size());

        // ---
        let chunk1 = MockChunkInfo {
            compress_offset: 1000,
            compress_size: merging_size as u32 - 2000,
            ..Default::default()
        };

        let bio1 = RafsBio::new(
            Arc::new(chunk1.clone()),
            Arc::new(RafsBlobEntry {
                chunk_count: 0,
                readahead_offset: 0,
                readahead_size: 0,
                blob_id: "1".to_string(),
                blob_index: 0,
                blob_cache_size: 0,
            }),
            50,
            50,
            RAFS_DEFAULT_BLOCK_SIZE as u32,
        );

        let chunk2 = MockChunkInfo {
            compress_offset: 1000 + merging_size - 2000,
            compress_size: 200,
            ..Default::default()
        };

        let bio2 = RafsBio::new(
            Arc::new(chunk2.clone()),
            Arc::new(RafsBlobEntry {
                chunk_count: 0,
                readahead_offset: 0,
                readahead_size: 0,
                blob_id: "1".to_string(),
                blob_index: 0,
                blob_cache_size: 0,
            }),
            50,
            50,
            RAFS_DEFAULT_BLOCK_SIZE as u32,
        );

        let chunk3 = MockChunkInfo {
            compress_offset: 1000 + merging_size - 2000,
            compress_size: 200,
            ..Default::default()
        };

        let bio3 = RafsBio::new(
            Arc::new(chunk3.clone()),
            Arc::new(RafsBlobEntry {
                chunk_count: 0,
                readahead_offset: 0,
                readahead_size: 0,
                blob_id: "2".to_string(),
                blob_index: 0,
                blob_cache_size: 0,
            }),
            50,
            50,
            RAFS_DEFAULT_BLOCK_SIZE as u32,
        );

        let mut bios = vec![bio1, bio2, bio3];
        let (mut send, recv) = spmc::channel::<MergedBackendRequest>();
        blob_cache.generate_merged_requests(&mut bios, &mut send, merging_size as usize, 1);

        let mr = recv.recv().unwrap();
        assert_eq!(mr.blob_offset, chunk1.compress_offset());
        assert_eq!(
            mr.blob_size,
            chunk1.compress_size() + chunk2.compress_size()
        );

        let mr = recv.recv().unwrap();
        assert_eq!(mr.blob_offset, chunk3.compress_offset());
        assert_eq!(mr.blob_size, chunk3.compress_size());
    }
}
