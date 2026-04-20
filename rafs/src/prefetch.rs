// Copyright 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Streaming blob prefetcher for Dragonfly proxy optimization.
//!
//! When a Dragonfly dfdaemon proxy is configured, this module sends rangeless
//! GET requests per blob, causing the proxy to download and cache entire blobs.
//! Chunks are matched from the stream by compressed offset and persisted to
//! the local file cache. This replaces N×1MB Range requests with a single
//! streaming connection per blob, reducing proxy task overhead from ~2600
//! per-chunk requests to ~10 per-blob streaming connections.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nydus_storage::backend::RequestSource;
use nydus_storage::cache::BlobCache;
use nydus_storage::device::{BlobChunkInfo, BlobInfo};

use crate::metadata::{RafsInodeExt, RafsSuper};

const DEFAULT_THREADS: usize = 5;
const DEFAULT_BANDWIDTH_RATE: u64 = 10 * 1024 * 1024; // 10 MB/s
const DEFAULT_MAX_RETRY: u64 = 10;
const STREAM_READ_SIZE: usize = 1024 * 1024; // 1MB per stream read

/// A blob and its chunks to prefetch, sorted by compressed offset.
struct BlobWork {
    info: Arc<BlobInfo>,
    /// Chunks sorted by compressed offset (via BTreeMap insertion).
    chunks: Vec<Arc<dyn BlobChunkInfo>>,
}

/// Progress tracking for the prefetcher.
pub struct PrefetchProgress {
    pub total_blobs: AtomicUsize,
    pub prefetched_blobs: AtomicUsize,
    pub total_chunks: AtomicUsize,
    pub prefetched_chunks: AtomicUsize,
    pub total_bytes: AtomicUsize,
    pub prefetched_bytes: AtomicUsize,
}

impl Default for PrefetchProgress {
    fn default() -> Self {
        Self {
            total_blobs: AtomicUsize::new(0),
            prefetched_blobs: AtomicUsize::new(0),
            total_chunks: AtomicUsize::new(0),
            prefetched_chunks: AtomicUsize::new(0),
            total_bytes: AtomicUsize::new(0),
            prefetched_bytes: AtomicUsize::new(0),
        }
    }
}

/// Token bucket rate limiter for bandwidth control.
struct RateLimiter {
    rate: u64,
    capacity: u64,
    available_tokens: u64,
    last_refill: Instant,
}

impl RateLimiter {
    fn new(rate: u64) -> Self {
        let capacity = rate.saturating_mul(2);
        Self {
            rate,
            capacity,
            available_tokens: capacity,
            last_refill: Instant::now(),
        }
    }

    /// Consume `bytes` tokens. Returns `Some(duration)` if the caller should
    /// sleep to stay within the rate limit, `None` if no wait is needed.
    fn consume(&mut self, bytes: usize) -> Option<Duration> {
        let bytes = bytes as u64;
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let tokens_to_add = (elapsed.as_secs_f64() * self.rate as f64) as u64;
        if tokens_to_add > 0 {
            self.available_tokens = self
                .available_tokens
                .saturating_add(tokens_to_add)
                .min(self.capacity);
            self.last_refill = now;
        }
        if self.available_tokens >= bytes {
            self.available_tokens -= bytes;
            return None;
        }
        let tokens_needed = bytes - self.available_tokens;
        let wait = Duration::from_secs_f64(tokens_needed as f64 / self.rate as f64);
        self.available_tokens = 0;
        Some(wait)
    }
}

struct State {
    stop_flag: AtomicBool,
    progress: PrefetchProgress,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
    thread_cv: Condvar,
    threads_count: usize,
    rate_limiter: Option<Arc<Mutex<RateLimiter>>>,
    max_retry_per_blob: u64,
}

/// Streaming blob prefetcher that downloads entire blobs via rangeless GET
/// requests and caches chunks from the stream.
pub struct BlobPrefetcher {
    sb: Arc<RafsSuper>,
    caches: Vec<Arc<dyn BlobCache>>,
    state: Arc<State>,
}

impl BlobPrefetcher {
    pub fn new(
        sb: Arc<RafsSuper>,
        caches: Vec<Arc<dyn BlobCache>>,
        threads_count: usize,
        bandwidth_rate: u64,
        max_retry: u64,
    ) -> Arc<Self> {
        let threads_count = if threads_count == 0 {
            DEFAULT_THREADS
        } else {
            threads_count
        };
        let max_retry = if max_retry == 0 {
            DEFAULT_MAX_RETRY
        } else {
            max_retry
        };
        let rate = if bandwidth_rate == 0 {
            DEFAULT_BANDWIDTH_RATE
        } else {
            bandwidth_rate
        };
        let rate_limiter = Some(Arc::new(Mutex::new(RateLimiter::new(rate))));

        Arc::new(Self {
            sb,
            caches,
            state: Arc::new(State {
                stop_flag: AtomicBool::new(false),
                progress: PrefetchProgress::default(),
                thread: Mutex::new(None),
                thread_cv: Condvar::new(),
                threads_count,
                rate_limiter,
                max_retry_per_blob: max_retry,
            }),
        })
    }

    /// Start the prefetcher in a background thread.
    pub fn start(self: &Arc<Self>) -> anyhow::Result<()> {
        let mut thread = self.state.thread.lock().unwrap();
        if thread.is_some() {
            anyhow::bail!("BlobPrefetcher already running");
        }
        self.state.stop_flag.store(false, Ordering::Release);

        let prefetcher = Arc::clone(self);
        let handle = thread::Builder::new()
            .name("blob-prefetcher".to_string())
            .spawn(move || {
                match prefetcher.build_blobs() {
                    Ok(blobs) => {
                        let total_chunks: usize = blobs.iter().map(|b| b.chunks.len()).sum();
                        info!(
                            "BlobPrefetcher: collected {} blobs with {} chunks",
                            blobs.len(),
                            total_chunks
                        );
                        prefetcher
                            .state
                            .progress
                            .total_blobs
                            .store(blobs.len(), Ordering::Relaxed);
                        prefetcher
                            .state
                            .progress
                            .total_chunks
                            .store(total_chunks, Ordering::Relaxed);

                        if let Err(e) = prefetcher.prefetch_all(blobs) {
                            error!("BlobPrefetcher: prefetch failed: {:?}", e);
                        }
                    }
                    Err(e) => error!("BlobPrefetcher: failed to build blobs: {:?}", e),
                }
                *prefetcher.state.thread.lock().unwrap() = None;
                prefetcher.state.thread_cv.notify_all();
                info!("BlobPrefetcher: thread completed");
            })?;

        *thread = Some(handle);
        Ok(())
    }

    /// Stop the prefetcher, waiting up to 5 seconds for the thread to finish.
    pub fn stop(&self) {
        info!("BlobPrefetcher: stopping");
        self.state.stop_flag.store(true, Ordering::Release);

        let timeout = Duration::from_secs(5);
        let deadline = Instant::now() + timeout;
        let mut thread = self.state.thread.lock().unwrap();
        while thread.is_some() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                warn!("BlobPrefetcher: timed out waiting, detaching thread");
                let _ = thread.take();
                break;
            }
            let (guard, _) = self
                .state
                .thread_cv
                .wait_timeout(thread, remaining)
                .unwrap();
            thread = guard;
        }
    }

    /// Get progress tracking data.
    pub fn progress(&self) -> &PrefetchProgress {
        &self.state.progress
    }

    /// Build blob work items by traversing the RAFS filesystem tree.
    ///
    /// Collects all chunks from all regular files, deduplicates them by chunk
    /// ID within each blob (via BTreeMap), and returns them sorted by
    /// compressed offset (BTreeMap's natural ordering).
    fn build_blobs(&self) -> anyhow::Result<Vec<BlobWork>> {
        // Map: blob_index → BTreeMap<chunk_id, chunk>
        let mut blob_map: BTreeMap<u32, BTreeMap<u64, Arc<dyn BlobChunkInfo>>> = BTreeMap::new();

        let root_ino = self.sb.superblock.root_ino();
        let root = self.sb.get_extended_inode(root_ino, false)?;
        let mut stack: Vec<Arc<dyn RafsInodeExt>> = vec![root];

        while let Some(inode) = stack.pop() {
            if inode.is_reg() {
                let chunk_count = inode.get_chunk_count();
                for idx in 0..chunk_count {
                    if let Ok(chunk) = inode.get_chunk_info(idx) {
                        let blob_index = chunk.blob_index();
                        // Use compressed_offset as key for dedup + natural sort order
                        blob_map
                            .entry(blob_index)
                            .or_default()
                            .insert(chunk.compressed_offset(), chunk);
                    }
                }
            } else if inode.is_dir() {
                let child_count = inode.get_child_count();
                for idx in 0..child_count {
                    if let Ok(child) = inode.get_child_by_index(idx) {
                        stack.push(child);
                    }
                }
            }
        }

        let blob_infos = self.sb.superblock.get_blob_infos();
        let mut blobs = Vec::new();
        for (blob_index, chunks_map) in blob_map {
            if (blob_index as usize) < blob_infos.len() {
                let chunks: Vec<Arc<dyn BlobChunkInfo>> = chunks_map.into_values().collect();
                blobs.push(BlobWork {
                    info: blob_infos[blob_index as usize].clone(),
                    chunks,
                });
            }
        }
        Ok(blobs)
    }

    /// Distribute blobs to worker threads and wait for completion.
    fn prefetch_all(&self, blobs: Vec<BlobWork>) -> anyhow::Result<()> {
        let blob_count = blobs.len();
        if blob_count == 0 {
            return Ok(());
        }
        let worker_count = self.state.threads_count.min(blob_count).max(1);

        let (tx, rx) = std::sync::mpsc::channel::<(BlobWork, Arc<dyn BlobCache>)>();
        let rx = Arc::new(Mutex::new(rx));

        let mut handles = Vec::new();
        for worker_id in 0..worker_count {
            let rx = Arc::clone(&rx);
            let state = Arc::clone(&self.state);
            let handle = thread::Builder::new()
                .name(format!("blob-pf-{}", worker_id))
                .spawn(move || {
                    loop {
                        let work = {
                            let rx = rx.lock().unwrap();
                            rx.recv().ok()
                        };
                        let Some((blob, cache)) = work else { break };

                        let blob_id = blob.info.blob_id().to_string();
                        let chunk_count = blob.chunks.len();
                        let mut retries = 0u64;

                        loop {
                            if state.stop_flag.load(Ordering::Acquire) {
                                break;
                            }

                            let mut chunk_status = vec![false; chunk_count];
                            match Self::prefetch_one_blob(&state, &blob, &cache, &mut chunk_status)
                            {
                                Ok(()) => {
                                    state
                                        .progress
                                        .prefetched_blobs
                                        .fetch_add(1, Ordering::Relaxed);
                                    break;
                                }
                                Err(e) => {
                                    retries += 1;
                                    if retries >= state.max_retry_per_blob {
                                        error!(
                                            "BlobPrefetcher: blob {} failed after {} retries: {:?}",
                                            blob_id, retries, e
                                        );
                                        break;
                                    }
                                    // Random backoff: 100ms * retry_count
                                    let backoff = Duration::from_millis(100 * retries);
                                    warn!(
                                        "BlobPrefetcher: blob {} retry {}/{}, backoff {:?}: {:?}",
                                        blob_id, retries, state.max_retry_per_blob, backoff, e
                                    );
                                    thread::sleep(backoff);
                                }
                            }
                        }
                    }
                })
                .map_err(|e| anyhow::anyhow!("failed to spawn worker thread: {}", e))?;

            handles.push(handle);
        }

        // Send blobs to workers with matching cache
        for blob in blobs {
            if self.state.stop_flag.load(Ordering::Acquire) {
                break;
            }
            let blob_index = blob.info.blob_index();
            if let Some(cache) = self.caches.get(blob_index as usize) {
                let _ = tx.send((blob, cache.clone()));
            }
        }
        drop(tx);

        for handle in handles {
            let _ = handle.join();
        }

        let progress = &self.state.progress;
        info!(
            "BlobPrefetcher: completed {}/{} blobs, {}/{} chunks, {} bytes",
            progress.prefetched_blobs.load(Ordering::Relaxed),
            progress.total_blobs.load(Ordering::Relaxed),
            progress.prefetched_chunks.load(Ordering::Relaxed),
            progress.total_chunks.load(Ordering::Relaxed),
            progress.prefetched_bytes.load(Ordering::Relaxed),
        );
        Ok(())
    }

    /// Prefetch a single blob: check cache status, get stream reader, stream and cache.
    fn prefetch_one_blob(
        state: &Arc<State>,
        blob: &BlobWork,
        cache: &Arc<dyn BlobCache>,
        chunk_status: &mut [bool],
    ) -> anyhow::Result<()> {
        let blob_id = blob.info.blob_id();
        let chunk_map = cache.get_chunk_map();

        // Find first uncached chunk
        let mut first_not_ready: Option<usize> = None;
        let mut start_offset: u64 = 0;

        for (idx, chunk) in blob.chunks.iter().enumerate() {
            if state.stop_flag.load(Ordering::Acquire) {
                return Ok(());
            }
            if chunk_status[idx] {
                continue;
            }

            if matches!(chunk_map.is_ready(chunk.as_ref()), Ok(true)) {
                chunk_status[idx] = true;
                continue;
            }

            if first_not_ready.is_none() {
                first_not_ready = Some(idx);
                start_offset = chunk.compressed_offset();
            }
        }

        if first_not_ready.is_none() {
            info!("BlobPrefetcher: blob {} fully cached, skipping", blob_id);
            return Ok(());
        }

        info!(
            "BlobPrefetcher: streaming blob {} from offset {}",
            blob_id, start_offset
        );

        // Get streaming reader from backend
        let reader = cache.reader();
        let stream_reader = reader
            .stream_read(start_offset, RequestSource::Prefetch)
            .map_err(|e| anyhow::anyhow!("stream_read failed for blob {}: {:?}", blob_id, e))?;

        Self::stream_and_cache(
            state,
            stream_reader,
            blob,
            cache,
            start_offset,
            chunk_status,
        )
    }

    /// Stream blob data and cache matched chunks.
    fn stream_and_cache(
        state: &Arc<State>,
        mut reader: Box<dyn Read + Send>,
        blob: &BlobWork,
        cache: &Arc<dyn BlobCache>,
        start_offset: u64,
        chunk_status: &mut [bool],
    ) -> anyhow::Result<()> {
        let blob_id = blob.info.blob_id();
        let last_chunk_end = blob
            .chunks
            .iter()
            .map(|c| c.compressed_offset() + c.compressed_size() as u64)
            .max()
            .unwrap_or(start_offset);

        let max_chunk_size = blob
            .chunks
            .iter()
            .map(|c| c.compressed_size() as usize)
            .max()
            .unwrap_or(STREAM_READ_SIZE);

        let mut accumulated: Vec<u8> = Vec::new();
        let mut acc_offset = start_offset;
        let mut scan_start: usize = 0;
        let mut chunks_cached = 0usize;

        loop {
            if state.stop_flag.load(Ordering::Acquire) {
                return Ok(());
            }

            // Read from stream
            let mut read_buf = vec![0u8; STREAM_READ_SIZE];
            let n = reader.read(&mut read_buf)?;
            if n == 0 {
                break;
            }

            // Rate limiting
            if let Some(ref limiter) = state.rate_limiter {
                if let Some(d) = limiter.lock().unwrap().consume(n) {
                    thread::sleep(d);
                }
            }

            accumulated.extend_from_slice(&read_buf[..n]);
            let acc_end = acc_offset + accumulated.len() as u64;

            // Match chunks against accumulated buffer
            let mut idx = scan_start;
            while idx < blob.chunks.len() {
                if chunk_status[idx] {
                    idx += 1;
                    continue;
                }

                let chunk = &blob.chunks[idx];
                let chunk_start = chunk.compressed_offset();
                let chunk_size = chunk.compressed_size() as usize;
                let chunk_end = chunk_start + chunk_size as u64;

                if chunk_start < acc_offset {
                    // Chunk before our buffer window, skip
                    scan_start = idx + 1;
                    idx += 1;
                    continue;
                }
                if chunk_end > acc_end {
                    // Not fully in buffer yet
                    break;
                }

                // Chunk is fully contained in accumulated buffer
                let buf_offset = (chunk_start - acc_offset) as usize;
                let chunk_data = &accumulated[buf_offset..buf_offset + chunk_size];

                match cache.cache_chunk_data(chunk.as_ref(), chunk_data) {
                    Ok(newly_cached) => {
                        chunk_status[idx] = true;
                        if newly_cached {
                            chunks_cached += 1;
                            state
                                .progress
                                .prefetched_chunks
                                .fetch_add(1, Ordering::Relaxed);
                            state
                                .progress
                                .prefetched_bytes
                                .fetch_add(chunk_size, Ordering::Relaxed);
                        }
                    }
                    Err(e) => {
                        warn!(
                            "BlobPrefetcher: failed to cache chunk {} of blob {}: {:?}",
                            chunk.id(),
                            blob_id,
                            e
                        );
                    }
                }
                idx += 1;
            }

            // Trim accumulated buffer — keep at least max_chunk_size to handle
            // chunks that span read boundaries.
            let trim_to = acc_end.saturating_sub(max_chunk_size as u64);
            if trim_to > acc_offset {
                let trim_bytes = (trim_to - acc_offset) as usize;
                if trim_bytes < accumulated.len() {
                    accumulated.drain(..trim_bytes);
                    acc_offset = trim_to;
                }
            }

            // Early exit conditions
            if chunk_status.iter().all(|&c| c) {
                break;
            }
            if acc_end >= last_chunk_end {
                break;
            }
        }

        info!(
            "BlobPrefetcher: streamed blob {}, cached {} chunks",
            blob_id, chunks_cached
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use fuse_backend_rs::file_buf::FileVolatileSlice;
    use nydus_storage::backend::{BackendContext, BackendResult, BlobReader};
    use nydus_storage::cache::state::ChunkMap;
    use nydus_storage::cache::BlobCache;
    use nydus_storage::device::{
        BlobChunkInfo, BlobInfo, BlobIoDesc, BlobIoVec, BlobPrefetchRequest,
    };
    use nydus_storage::{StorageError, StorageResult};
    use nydus_utils::crypt::{Cipher, CipherContext};
    use nydus_utils::metrics::BackendMetrics;
    use nydus_utils::{compress, crypt, digest};

    use crate::mock::MockChunkInfo;

    use super::*;

    // ── MockChunkMap ──────────────────────────────────────────────────────────

    struct MockChunkMap {
        ready: bool,
    }

    impl ChunkMap for MockChunkMap {
        fn is_ready(&self, _chunk: &dyn BlobChunkInfo) -> std::io::Result<bool> {
            Ok(self.ready)
        }
    }

    // ── MockBlobReader ────────────────────────────────────────────────────────

    struct MockBlobReader {
        stream_data: Vec<u8>,
        stream_call_count: Arc<AtomicUsize>,
        metrics: Arc<BackendMetrics>,
    }

    impl MockBlobReader {
        fn new(stream_data: Vec<u8>, stream_call_count: Arc<AtomicUsize>) -> Self {
            Self {
                stream_data,
                stream_call_count,
                metrics: BackendMetrics::new("mock", "prefetch-test"),
            }
        }
    }

    impl BlobReader for MockBlobReader {
        fn blob_size(&self) -> BackendResult<u64> {
            Ok(self.stream_data.len() as u64)
        }

        fn try_read(&self, _buf: &mut [u8], _offset: u64) -> BackendResult<usize> {
            Ok(0)
        }

        fn try_stream_read(
            &self,
            _offset: u64,
            _ctx: Option<&mut BackendContext>,
        ) -> BackendResult<Box<dyn Read + Send>> {
            self.stream_call_count.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(std::io::Cursor::new(self.stream_data.clone())))
        }

        fn metrics(&self) -> &BackendMetrics {
            &self.metrics
        }
    }

    // ── MockBlobCache ─────────────────────────────────────────────────────────

    struct MockBlobCache {
        chunk_map: Arc<dyn ChunkMap>,
        reader: Arc<MockBlobReader>,
        /// Whether `cache_chunk_data` returns `Ok(true)` (true) or `Err` (false).
        cache_succeeds: bool,
        cache_calls: Arc<AtomicUsize>,
    }

    impl BlobCache for MockBlobCache {
        fn blob_id(&self) -> &str {
            "mock-blob"
        }
        fn blob_uncompressed_size(&self) -> std::io::Result<u64> {
            Ok(0)
        }
        fn blob_compressed_size(&self) -> std::io::Result<u64> {
            Ok(0)
        }
        fn blob_compressor(&self) -> compress::Algorithm {
            compress::Algorithm::None
        }
        fn blob_cipher(&self) -> crypt::Algorithm {
            crypt::Algorithm::None
        }
        fn blob_cipher_object(&self) -> Arc<Cipher> {
            Arc::new(Cipher::default())
        }
        fn blob_cipher_context(&self) -> Option<CipherContext> {
            None
        }
        fn blob_digester(&self) -> digest::Algorithm {
            digest::Algorithm::Sha256
        }
        fn is_legacy_stargz(&self) -> bool {
            false
        }
        fn need_validation(&self) -> bool {
            false
        }
        fn reader(&self) -> &dyn BlobReader {
            self.reader.as_ref()
        }
        fn get_chunk_map(&self) -> &Arc<dyn ChunkMap> {
            &self.chunk_map
        }
        fn get_chunk_info(&self, _idx: u32) -> Option<Arc<dyn BlobChunkInfo>> {
            None
        }
        fn start_prefetch(&self) -> StorageResult<()> {
            Ok(())
        }
        fn stop_prefetch(&self) -> StorageResult<()> {
            Ok(())
        }
        fn is_prefetch_active(&self) -> bool {
            false
        }
        fn prefetch(
            &self,
            _blob_cache: Arc<dyn BlobCache>,
            _prefetches: &[BlobPrefetchRequest],
            _bios: &[BlobIoDesc],
        ) -> StorageResult<usize> {
            Err(StorageError::Unsupported)
        }
        fn read(
            &self,
            _iovec: &mut BlobIoVec,
            _bufs: &[FileVolatileSlice],
        ) -> std::io::Result<usize> {
            unimplemented!()
        }
        fn cache_chunk_data(
            &self,
            _chunk: &dyn BlobChunkInfo,
            _data: &[u8],
        ) -> std::io::Result<bool> {
            self.cache_calls.fetch_add(1, Ordering::Relaxed);
            if self.cache_succeeds {
                Ok(true)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "mock cache error",
                ))
            }
        }
    }

    // ── LimitedReader ─────────────────────────────────────────────────────────
    // Delivers at most `chunk_size` bytes per read(), forcing multi-read accumulation.

    struct LimitedReader {
        data: std::io::Cursor<Vec<u8>>,
        chunk_size: usize,
    }

    impl Read for LimitedReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let limit = self.chunk_size.min(buf.len());
            self.data.read(&mut buf[..limit])
        }
    }

    // SAFETY: used only in single-threaded tests.
    unsafe impl Send for LimitedReader {}

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_state(stop: bool) -> Arc<State> {
        Arc::new(State {
            stop_flag: AtomicBool::new(stop),
            progress: PrefetchProgress::default(),
            thread: Mutex::new(None),
            thread_cv: Condvar::new(),
            threads_count: 2,
            rate_limiter: None,
            max_retry_per_blob: 3,
        })
    }

    fn make_blob_work(chunks: Vec<Arc<dyn BlobChunkInfo>>) -> BlobWork {
        BlobWork {
            info: Arc::new(BlobInfo::default()),
            chunks,
        }
    }

    /// Build a `MockBlobCache` and return it along with call-count handles.
    ///
    /// * `ready` — what `is_ready()` returns for every chunk.
    /// * `stream_data` — data returned by `stream_read()`.
    /// * `cache_succeeds` — whether `cache_chunk_data` returns `Ok(true)` or `Err`.
    fn make_cache(
        ready: bool,
        stream_data: Vec<u8>,
        cache_succeeds: bool,
    ) -> (Arc<MockBlobCache>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let stream_calls = Arc::new(AtomicUsize::new(0));
        let cache_calls = Arc::new(AtomicUsize::new(0));
        let reader = Arc::new(MockBlobReader::new(stream_data, Arc::clone(&stream_calls)));
        let cache = Arc::new(MockBlobCache {
            chunk_map: Arc::new(MockChunkMap { ready }),
            reader,
            cache_succeeds,
            cache_calls: Arc::clone(&cache_calls),
        });
        (cache, stream_calls, cache_calls)
    }

    // ── RateLimiter ───────────────────────────────────────────────────────────

    #[test]
    fn test_rate_limiter_no_wait_under_capacity() {
        let mut limiter = RateLimiter::new(10 * 1024 * 1024); // 10 MB/s
        assert!(limiter.consume(1024).is_none());
    }

    #[test]
    fn test_rate_limiter_returns_wait_when_exhausted() {
        let mut limiter = RateLimiter::new(1024); // 1 KB/s, capacity = 2 KB
        assert!(limiter.consume(2048).is_none());
        let wait = limiter.consume(1024);
        assert!(wait.is_some());
        assert!(wait.unwrap() > Duration::from_millis(500));
    }

    #[test]
    fn test_rate_limiter_refills_over_time() {
        let mut limiter = RateLimiter::new(10_000); // 10 KB/s, capacity = 20 KB
        assert!(limiter.consume(20_000).is_none());
        std::thread::sleep(Duration::from_millis(200));
        // Should have refilled ~2 KB worth of tokens; just verify it doesn't panic.
        let _result = limiter.consume(1000);
    }

    #[test]
    fn test_rate_limiter_zero_bytes_never_waits() {
        let mut limiter = RateLimiter::new(1024);
        // Exhaust capacity first.
        limiter.consume(2048);
        // Consuming 0 bytes should never require a wait.
        assert!(limiter.consume(0).is_none());
    }

    #[test]
    fn test_rate_limiter_exact_capacity_no_wait() {
        let mut limiter = RateLimiter::new(1024); // capacity = 2048
        assert!(limiter.consume(2048).is_none());
        // Now exhausted: next byte requires a wait.
        assert!(limiter.consume(1).is_some());
    }

    #[test]
    fn test_rate_limiter_capacity_is_double_rate() {
        let rate = 4096u64;
        let limiter = RateLimiter::new(rate);
        assert_eq!(limiter.capacity, rate * 2);
        assert_eq!(limiter.available_tokens, rate * 2);
    }

    #[test]
    fn test_rate_limiter_wait_duration_accuracy() {
        let rate = 1000u64; // 1000 bytes/s
        let mut limiter = RateLimiter::new(rate);
        limiter.consume(2000); // drain capacity (2 × 1000)
                               // Requesting 500 more bytes should require ~500 ms wait.
        let wait = limiter.consume(500).expect("should wait");
        assert!(
            wait >= Duration::from_millis(400),
            "wait too short: {:?}",
            wait
        );
        assert!(
            wait <= Duration::from_millis(600),
            "wait too long: {:?}",
            wait
        );
    }

    // ── PrefetchProgress ─────────────────────────────────────────────────────

    #[test]
    fn test_progress_default_all_zero() {
        let p = PrefetchProgress::default();
        assert_eq!(p.total_blobs.load(Ordering::Relaxed), 0);
        assert_eq!(p.prefetched_blobs.load(Ordering::Relaxed), 0);
        assert_eq!(p.total_chunks.load(Ordering::Relaxed), 0);
        assert_eq!(p.prefetched_chunks.load(Ordering::Relaxed), 0);
        assert_eq!(p.total_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(p.prefetched_bytes.load(Ordering::Relaxed), 0);
    }

    // ── stream_and_cache ──────────────────────────────────────────────────────

    #[test]
    fn test_stream_empty_reader() {
        let state = make_state(false);
        let chunk = Arc::new(MockChunkInfo::mock(0, 0, 10, 0, 10));
        let blob = make_blob_work(vec![chunk]);
        let (cache, _, cache_calls) = make_cache(false, vec![], true);
        let mut status = vec![false; 1];
        let reader: Box<dyn Read + Send> = Box::new(std::io::Cursor::new(vec![]));

        BlobPrefetcher::stream_and_cache(
            &state,
            reader,
            &blob,
            &(cache as Arc<dyn BlobCache>),
            0,
            &mut status,
        )
        .unwrap();

        // EOF immediately — no chunks could be cached.
        assert_eq!(cache_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_stream_stop_flag_halts_immediately() {
        let state = make_state(true); // stop_flag = true from the start
        let chunk = Arc::new(MockChunkInfo::mock(0, 0, 10, 0, 10));
        let blob = make_blob_work(vec![chunk]);
        let (cache, _, cache_calls) = make_cache(false, vec![0u8; 100], true);
        let mut status = vec![false; 1];
        let reader: Box<dyn Read + Send> = Box::new(std::io::Cursor::new(vec![0u8; 100]));

        BlobPrefetcher::stream_and_cache(
            &state,
            reader,
            &blob,
            &(cache as Arc<dyn BlobCache>),
            0,
            &mut status,
        )
        .unwrap();

        assert_eq!(cache_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_stream_caches_chunk_and_updates_progress() {
        let state = make_state(false);
        let chunk_size = 20usize;
        let chunk = Arc::new(MockChunkInfo::mock(
            0,
            0,
            chunk_size as u32,
            0,
            chunk_size as u32,
        ));
        let blob = make_blob_work(vec![chunk]);
        let (cache, _, cache_calls) = make_cache(false, vec![], true);
        let cache_arc: Arc<dyn BlobCache> = cache;
        let mut status = vec![false; 1];
        let data: Vec<u8> = (0..chunk_size as u8).collect();
        let reader: Box<dyn Read + Send> = Box::new(std::io::Cursor::new(data));

        BlobPrefetcher::stream_and_cache(&state, reader, &blob, &cache_arc, 0, &mut status)
            .unwrap();

        assert_eq!(cache_calls.load(Ordering::Relaxed), 1);
        assert!(status[0]);
        assert_eq!(state.progress.prefetched_chunks.load(Ordering::Relaxed), 1);
        assert_eq!(
            state.progress.prefetched_bytes.load(Ordering::Relaxed),
            chunk_size
        );
    }

    #[test]
    fn test_stream_skips_chunk_already_in_status() {
        let state = make_state(false);
        let chunk_size = 20usize;
        let chunk = Arc::new(MockChunkInfo::mock(
            0,
            0,
            chunk_size as u32,
            0,
            chunk_size as u32,
        ));
        let blob = make_blob_work(vec![chunk]);
        let (cache, _, cache_calls) = make_cache(false, vec![], true);
        let cache_arc: Arc<dyn BlobCache> = cache;
        let mut status = vec![true; 1]; // already marked done
        let data: Vec<u8> = vec![0u8; chunk_size];
        let reader: Box<dyn Read + Send> = Box::new(std::io::Cursor::new(data));

        BlobPrefetcher::stream_and_cache(&state, reader, &blob, &cache_arc, 0, &mut status)
            .unwrap();

        assert_eq!(cache_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_stream_chunk_before_window_skipped_inside_window_cached() {
        // chunk_before lives at offset 0, but the stream starts at offset 50,
        // so acc_offset = 50 > chunk_before.start → it should be skipped.
        // chunk_inside starts at offset 50 and should be cached.
        let state = make_state(false);
        let chunk_before = Arc::new(MockChunkInfo::mock(0, 0, 10, 0, 10));
        let chunk_size = 20usize;
        let chunk_inside = Arc::new(MockChunkInfo::mock(
            0,
            50,
            chunk_size as u32,
            0,
            chunk_size as u32,
        ));
        let blob = make_blob_work(vec![chunk_before, chunk_inside]);
        let (cache, _, cache_calls) = make_cache(false, vec![], true);
        let cache_arc: Arc<dyn BlobCache> = cache;
        let mut status = vec![false; 2];
        // Reader delivers the 20 bytes that correspond to chunk_inside.
        let data: Vec<u8> = vec![0xABu8; chunk_size];
        let reader: Box<dyn Read + Send> = Box::new(std::io::Cursor::new(data));

        BlobPrefetcher::stream_and_cache(&state, reader, &blob, &cache_arc, 50, &mut status)
            .unwrap();

        assert_eq!(
            cache_calls.load(Ordering::Relaxed),
            1,
            "only the inside-window chunk should be cached"
        );
        assert!(!status[0], "before-window chunk must not be marked done");
        assert!(status[1], "inside-window chunk must be marked done");
    }

    #[test]
    fn test_stream_cache_error_does_not_propagate() {
        // When cache_chunk_data returns Err, the function logs a warning but
        // continues and ultimately returns Ok(()).
        let state = make_state(false);
        let chunk_size = 10usize;
        let chunk = Arc::new(MockChunkInfo::mock(
            0,
            0,
            chunk_size as u32,
            0,
            chunk_size as u32,
        ));
        let blob = make_blob_work(vec![chunk]);
        let (cache, _, cache_calls) = make_cache(false, vec![], false); // cache_succeeds = false
        let cache_arc: Arc<dyn BlobCache> = cache;
        let mut status = vec![false; 1];
        let data = vec![0u8; chunk_size];
        let reader: Box<dyn Read + Send> = Box::new(std::io::Cursor::new(data));

        let result =
            BlobPrefetcher::stream_and_cache(&state, reader, &blob, &cache_arc, 0, &mut status);

        assert!(result.is_ok(), "cache error must not be returned as Err");
        assert!(
            !status[0],
            "chunk must not be marked done when caching failed"
        );
        assert_eq!(cache_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_stream_cross_read_boundary() {
        // Two sequential chunks; the reader delivers only 5 bytes per call, so
        // each chunk spans multiple read() calls, exercising the buffer
        // accumulation and trimming logic.
        let state = make_state(false);
        let chunk_size = 8usize;
        // chunk0: compressed bytes [0, 8), chunk1: [8, 16).
        let chunk0 = Arc::new(MockChunkInfo::mock(
            0,
            0,
            chunk_size as u32,
            0,
            chunk_size as u32,
        ));
        let chunk1 = Arc::new(MockChunkInfo::mock(
            0,
            8,
            chunk_size as u32,
            0,
            chunk_size as u32,
        ));
        let blob = make_blob_work(vec![chunk0, chunk1]);
        let (cache, _, cache_calls) = make_cache(false, vec![], true);
        let cache_arc: Arc<dyn BlobCache> = cache;
        let mut status = vec![false; 2];
        let data: Vec<u8> = (0u8..16).collect();
        let reader: Box<dyn Read + Send> = Box::new(LimitedReader {
            data: std::io::Cursor::new(data),
            chunk_size: 5, // forces multiple read() calls per chunk
        });

        BlobPrefetcher::stream_and_cache(&state, reader, &blob, &cache_arc, 0, &mut status)
            .unwrap();

        assert_eq!(cache_calls.load(Ordering::Relaxed), 2);
        assert!(status[0]);
        assert!(status[1]);
        assert_eq!(state.progress.prefetched_chunks.load(Ordering::Relaxed), 2);
        assert_eq!(state.progress.prefetched_bytes.load(Ordering::Relaxed), 16);
    }

    // ── prefetch_one_blob ────────────────────────────────────────────────────

    #[test]
    fn test_prefetch_one_blob_all_chunks_ready() {
        // When every chunk is already cached (is_ready = true), no stream_read
        // call should be made.
        let state = make_state(false);
        let chunk = Arc::new(MockChunkInfo::mock(0, 0, 10, 0, 10));
        let blob = make_blob_work(vec![chunk]);
        let (cache, stream_calls, _) = make_cache(true, vec![], true); // ready = true
        let cache_arc: Arc<dyn BlobCache> = cache;
        let mut status = vec![false; 1];

        BlobPrefetcher::prefetch_one_blob(&state, &blob, &cache_arc, &mut status).unwrap();

        assert_eq!(stream_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_prefetch_one_blob_stop_flag_skips_stream() {
        // A set stop flag causes the chunk scan loop to return early before
        // streaming begins.
        let state = make_state(true); // stop immediately
        let chunk = Arc::new(MockChunkInfo::mock(0, 0, 10, 0, 10));
        let blob = make_blob_work(vec![chunk]);
        let (cache, stream_calls, _) = make_cache(false, vec![], true);
        let cache_arc: Arc<dyn BlobCache> = cache;
        let mut status = vec![false; 1];

        BlobPrefetcher::prefetch_one_blob(&state, &blob, &cache_arc, &mut status).unwrap();

        assert_eq!(stream_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_prefetch_one_blob_streams_when_uncached() {
        // A pre-cached first chunk (chunk_status[0] = true) and an uncached
        // second chunk: stream_read should be called once and start at the
        // second chunk's compressed offset (10).
        let state = make_state(false);
        let chunk0 = Arc::new(MockChunkInfo::mock(0, 0, 10, 0, 10));
        let chunk_size = 20usize;
        let chunk1 = Arc::new(MockChunkInfo::mock(
            0,
            10,
            chunk_size as u32,
            0,
            chunk_size as u32,
        ));
        let blob = make_blob_work(vec![chunk0, chunk1]);
        // is_ready = false for all; chunk0 is skipped via chunk_status = true.
        let (cache, stream_calls, _) = make_cache(false, vec![0u8; chunk_size], true);
        let cache_arc: Arc<dyn BlobCache> = cache;
        // Pre-mark chunk0 as done so the first-uncached search starts at chunk1.
        let mut status = vec![true, false];

        BlobPrefetcher::prefetch_one_blob(&state, &blob, &cache_arc, &mut status).unwrap();

        assert_eq!(
            stream_calls.load(Ordering::Relaxed),
            1,
            "stream_read should be called exactly once"
        );
    }

    #[test]
    fn test_prefetch_one_blob_no_chunks() {
        // Empty blob: should return Ok(()) immediately without streaming.
        let state = make_state(false);
        let blob = make_blob_work(vec![]);
        let (cache, stream_calls, _) = make_cache(false, vec![], true);
        let cache_arc: Arc<dyn BlobCache> = cache;
        let mut status: Vec<bool> = vec![];

        BlobPrefetcher::prefetch_one_blob(&state, &blob, &cache_arc, &mut status).unwrap();

        assert_eq!(stream_calls.load(Ordering::Relaxed), 0);
    }

    // ── BlobPrefetcher::new defaults ──────────────────────────────────────────

    #[test]
    fn test_blob_prefetcher_new_zero_inputs_use_defaults() {
        use crate::metadata::RafsSuper;
        let sb = Arc::new(RafsSuper::default());
        // Passing 0 for all tunable parameters must fall back to the built-in defaults.
        let p = BlobPrefetcher::new(sb, vec![], 0, 0, 0);
        assert_eq!(p.state.threads_count, DEFAULT_THREADS);
        assert_eq!(p.state.max_retry_per_blob, DEFAULT_MAX_RETRY);
        // Rate limiter capacity = 2 × rate; with default rate that is 2 × DEFAULT_BANDWIDTH_RATE.
        let limiter = p
            .state
            .rate_limiter
            .as_ref()
            .expect("rate limiter should be set")
            .lock()
            .unwrap();
        assert_eq!(limiter.rate, DEFAULT_BANDWIDTH_RATE);
        assert_eq!(limiter.capacity, DEFAULT_BANDWIDTH_RATE * 2);
    }

    #[test]
    fn test_blob_prefetcher_new_nonzero_inputs_preserved() {
        use crate::metadata::RafsSuper;
        let sb = Arc::new(RafsSuper::default());
        let threads = 3usize;
        let rate = 5 * 1024 * 1024u64; // 5 MB/s
        let retry = 7u64;
        let p = BlobPrefetcher::new(sb, vec![], threads, rate, retry);
        assert_eq!(p.state.threads_count, threads);
        assert_eq!(p.state.max_retry_per_blob, retry);
        let limiter = p
            .state
            .rate_limiter
            .as_ref()
            .expect("rate limiter should be set")
            .lock()
            .unwrap();
        assert_eq!(limiter.rate, rate);
    }

    #[test]
    fn test_blob_prefetcher_progress_returns_state_ref() {
        use crate::metadata::RafsSuper;
        let sb = Arc::new(RafsSuper::default());
        let p = BlobPrefetcher::new(sb, vec![], 1, 1024, 1);
        // progress() must expose the live counters; increment one and verify.
        p.state.progress.total_blobs.store(42, Ordering::Relaxed);
        assert_eq!(p.progress().total_blobs.load(Ordering::Relaxed), 42);
    }
}
