// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021-2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::io::{Error, ErrorKind, Result};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use fuse_backend_rs::transport::FileVolatileSlice;
use governor::clock::QuantaClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use nydus_utils::metrics::{BlobcacheMetrics, Metric};
use tokio::runtime::Runtime;
use tokio::sync::Notify;

use crate::cache::{BlobCache, BlobIoRange, BlobPrefetchConfig};
use crate::RAFS_MAX_CHUNK_SIZE;

/// Configuration information for asynchronous workers.
pub(crate) struct AsyncPrefetchConfig {
    /// Whether or not to enable prefetch.
    pub enable: bool,
    /// Number of working threads.
    pub threads_count: usize,
    /// Window size to merge/amplify requests.
    pub merging_size: usize,
    /// Network bandwidth for prefetch, in unit of Bytes and Zero means no rate limit is set.
    pub bandwidth_rate: u32,
}

impl From<BlobPrefetchConfig> for AsyncPrefetchConfig {
    fn from(p: BlobPrefetchConfig) -> Self {
        AsyncPrefetchConfig {
            enable: p.enable,
            threads_count: p.threads_count,
            merging_size: p.merging_size,
            bandwidth_rate: p.bandwidth_rate,
        }
    }
}

/// Status of an asynchronous prefetch requests.
#[repr(u32)]
pub(crate) enum AsyncPrefetchState {
    /// Initializations state.
    Init,
    /// The asynchronous service request is pending for executing, worker should not touching state
    /// after executing the request.
    Active,
    /// The asynchronous service request has been cancelled.
    Cancelled,
}

/// Asynchronous service request message.
pub(crate) enum AsyncPrefetchMessage {
    /// Asynchronous blob layer prefetch request with (offset, size) of blob on storage backend.
    BlobPrefetch(Arc<AtomicU32>, Arc<dyn BlobCache>, u64, u64),
    /// Asynchronous file-system layer prefetch request.
    FsPrefetch(Arc<AtomicU32>, Arc<dyn BlobCache>, BlobIoRange),
    #[cfg_attr(not(test), allow(unused))]
    /// Ping for test.
    Ping,
    #[cfg_attr(not(test), allow(unused))]
    RateLimiter(u64),
}

impl AsyncPrefetchMessage {
    /// Create a new asynchronous filesystem prefetch request message.
    pub fn new_fs_prefetch(
        req_state: Arc<AtomicU32>,
        blob_cache: Arc<dyn BlobCache>,
        req: BlobIoRange,
    ) -> Self {
        AsyncPrefetchMessage::FsPrefetch(req_state, blob_cache, req)
    }

    /// Create a new asynchronous blob prefetch request message.
    pub fn new_blob_prefetch(
        req_state: Arc<AtomicU32>,
        blob_cache: Arc<dyn BlobCache>,
        offset: u64,
        size: u64,
    ) -> Self {
        AsyncPrefetchMessage::BlobPrefetch(req_state, blob_cache, offset, size)
    }
}

// Async implementation of Multi-Producer-Multi-Consumer channel.
struct Channel<T> {
    closed: AtomicBool,
    notifier: Notify,
    requests: Mutex<VecDeque<T>>,
}

impl<T> Channel<T> {
    fn new() -> Self {
        Channel {
            closed: AtomicBool::new(false),
            notifier: Notify::new(),
            requests: Mutex::new(VecDeque::new()),
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notifier.notify_waiters();
    }

    fn send(&self, msg: T) -> std::result::Result<(), T> {
        if self.closed.load(Ordering::Acquire) {
            Err(msg)
        } else {
            self.requests.lock().unwrap().push_back(msg);
            self.notifier.notify_one();
            Ok(())
        }
    }

    fn try_recv(&self) -> Option<T> {
        self.requests.lock().unwrap().pop_front()
    }

    async fn recv(&self) -> Result<T> {
        let future = self.notifier.notified();
        tokio::pin!(future);

        loop {
            /*
            // TODO: enable this after https://github.com/tokio-rs/tokio/issues/4745 has been fixed
            // Make sure that no wakeup is lost if we get `None` from `try_recv`.
            future.as_mut().enable();
             */

            if let Some(msg) = self.try_recv() {
                return Ok(msg);
            } else if self.closed.load(Ordering::Acquire) {
                return Err(Error::new(ErrorKind::BrokenPipe, "channel has been closed"));
            }

            // Wait for a call to `notify_one`.
            //
            // This uses `.as_mut()` to avoid consuming the future,
            // which lets us call `Pin::set` below.
            future.as_mut().await;

            // Reset the future in case another call to `try_recv` got the message before us.
            future.set(self.notifier.notified());
        }
    }
}

pub(crate) struct AsyncWorkerMgr {
    metrics: Arc<BlobcacheMetrics>,
    ping_requests: AtomicU32,
    workers: AtomicU32,

    prefetch_channel: Arc<Channel<AsyncPrefetchMessage>>,
    prefetch_config: Arc<AsyncPrefetchConfig>,
    prefetch_delayed: AtomicU64,
    prefetch_inflight: AtomicU32,
    prefetch_limiter: Option<Arc<RateLimiter<NotKeyed, InMemoryState, QuantaClock>>>,
}

impl AsyncWorkerMgr {
    /// Create a new instance of `AsyncWorkerMgr`.
    pub fn new(
        metrics: Arc<BlobcacheMetrics>,
        prefetch_config: Arc<AsyncPrefetchConfig>,
    ) -> Result<Self> {
        // If the given value is less than maximum blob chunk size, it exceeds burst size of the
        // limiter ending up with throttling all throughput, so ensure bandwidth is bigger than
        // the maximum chunk size.
        let tweaked_bw_limit = if prefetch_config.bandwidth_rate != 0 {
            std::cmp::max(RAFS_MAX_CHUNK_SIZE as u32, prefetch_config.bandwidth_rate)
        } else {
            0
        };
        let prefetch_limiter = NonZeroU32::new(tweaked_bw_limit).map(|v| {
            info!(
                "stroage: prefetch bandwidth will be limited at {}Bytes/S",
                v
            );
            Arc::new(RateLimiter::direct(Quota::per_second(v)))
        });

        Ok(AsyncWorkerMgr {
            metrics,
            ping_requests: AtomicU32::new(0),
            workers: AtomicU32::new(0),

            prefetch_channel: Arc::new(Channel::new()),
            prefetch_config,
            prefetch_delayed: AtomicU64::new(0),
            prefetch_inflight: AtomicU32::new(0),
            prefetch_limiter,
        })
    }

    /// Create working threads and start the event loop.
    pub fn start(mgr: Arc<AsyncWorkerMgr>) -> Result<()> {
        if mgr.prefetch_config.enable {
            Self::start_prefetch_workers(mgr.clone())?;
        }

        Ok(())
    }

    /// Stop all working threads.
    pub fn stop(&self) {
        self.prefetch_channel.close();

        while self.workers.load(Ordering::Relaxed) > 0 {
            self.prefetch_channel.notifier.notify_waiters();
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Send an asynchronous service request message to the workers.
    pub fn send_prefetch_message(
        &self,
        msg: AsyncPrefetchMessage,
    ) -> std::result::Result<(), AsyncPrefetchMessage> {
        if !self.prefetch_config.enable {
            Err(msg)
        } else {
            self.prefetch_inflight.fetch_add(1, Ordering::Relaxed);
            self.prefetch_channel.send(msg)
        }
    }

    /// Consume network bandwidth budget for prefetching.
    pub fn consume_prefetch_budget(&self, buffers: &[FileVolatileSlice]) {
        if self.prefetch_inflight.load(Ordering::Relaxed) > 0 {
            let size = buffers.iter().fold(0, |v, i| v + i.len());
            if let Some(v) = NonZeroU32::new(std::cmp::min(size, u32::MAX as usize) as u32) {
                // Try to consume budget but ignore result.
                if let Some(limiter) = self.prefetch_limiter.as_ref() {
                    let _ = limiter.check_n(v);
                }
            }
        }
    }

    fn start_prefetch_workers(mgr: Arc<AsyncWorkerMgr>) -> Result<()> {
        // Hold the request queue to barrier all working threads.
        let guard = mgr.prefetch_channel.requests.lock().unwrap();
        for num in 0..mgr.prefetch_config.threads_count {
            let mgr2 = mgr.clone();
            let res = thread::Builder::new()
                .name(format!("nydus_storage_worker_{}", num))
                .spawn(move || {
                    mgr2.grow_n(1);
                    mgr2.metrics
                        .prefetch_workers
                        .fetch_add(1, Ordering::Relaxed);

                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("storage: failed to create tokio runtime for current thread");
                    rt.block_on(Self::handle_prefetch_requests(mgr2.clone(), &rt));

                    mgr2.metrics
                        .prefetch_workers
                        .fetch_sub(1, Ordering::Relaxed);
                    mgr2.shrink_n(1);
                    info!("storage: worker thread {} exits.", num)
                });

            if let Err(e) = res {
                error!("storage: failed to create worker thread, {:?}", e);
                mgr.prefetch_channel.close();
                drop(guard);
                mgr.stop();
                return Err(e);
            }
        }

        Ok(())
    }

    async fn handle_prefetch_requests(mgr: Arc<AsyncWorkerMgr>, rt: &Runtime) {
        while let Ok(msg) = mgr.prefetch_channel.recv().await {
            mgr.handle_prefetch_rate_limit(&msg).await;

            match msg {
                AsyncPrefetchMessage::BlobPrefetch(state, blob_cache, offset, size) => {
                    if state.load(Ordering::Acquire) == AsyncPrefetchState::Active as u32 {
                        let _ = rt.spawn(Self::handle_blob_prefetch_request(
                            mgr.clone(),
                            blob_cache,
                            offset,
                            size,
                        ));
                    }
                }
                AsyncPrefetchMessage::FsPrefetch(state, blob_cache, req) => {
                    if state.load(Ordering::Acquire) == AsyncPrefetchState::Active as u32 {
                        let _ = rt.spawn(Self::handle_fs_prefetch_request(
                            mgr.clone(),
                            blob_cache,
                            req,
                        ));
                    }
                }
                AsyncPrefetchMessage::Ping => {
                    let _ = mgr.ping_requests.fetch_add(1, Ordering::Relaxed);
                }
                AsyncPrefetchMessage::RateLimiter(_size) => {}
            }

            mgr.prefetch_inflight.fetch_sub(1, Ordering::Relaxed);
        }
    }

    async fn handle_prefetch_rate_limit(&self, msg: &AsyncPrefetchMessage) {
        // Allocate network bandwidth budget
        if let Some(limiter) = &self.prefetch_limiter {
            let size = match msg {
                AsyncPrefetchMessage::BlobPrefetch(state, _blob_cache, _offset, size) => {
                    if state.load(Ordering::Acquire) == AsyncPrefetchState::Active as u32 {
                        *size
                    } else {
                        0
                    }
                }
                AsyncPrefetchMessage::FsPrefetch(state, _blob_cache, req) => {
                    if state.load(Ordering::Acquire) == AsyncPrefetchState::Active as u32 {
                        req.blob_size
                    } else {
                        0
                    }
                }
                AsyncPrefetchMessage::Ping => 0,
                AsyncPrefetchMessage::RateLimiter(size) => *size,
            };

            if size > 0 {
                let size = std::cmp::min(size, u32::MAX as u64) as u32;
                // Safe to unwrap because we have checked that size is not zero.
                let cells = NonZeroU32::new(size).unwrap();
                if limiter.check_n(cells).is_err() {
                    self.prefetch_delayed.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = limiter.until_n_ready(cells).await {
                        // `InsufficientCapacity` is the only possible error
                        // Have to give up to avoid dead-loop
                        error!("{}: give up rate-limiting", e);
                    }
                }
            }
        }
    }

    async fn handle_blob_prefetch_request(
        _mgr: Arc<AsyncWorkerMgr>,
        cache: Arc<dyn BlobCache>,
        offset: u64,
        size: u64,
    ) -> Result<()> {
        trace!(
            "storage: prefetch blob {} offset {} size {}",
            cache.blob_id(),
            offset,
            size
        );
        if size == 0 {
            return Ok(());
        }

        if let Some(obj) = cache.get_blob_object() {
            if let Err(e) = obj.fetch_range_compressed(offset, size) {
                warn!(
                    "storage: failed to prefetch data from blob {}, offset {}, size {}, {}",
                    cache.blob_id(),
                    offset,
                    size,
                    e
                );
            }
        } else {
            let _ = cache.reader().prefetch_blob_data_range(offset, size);
        }

        Ok(())
    }

    async fn handle_fs_prefetch_request(
        mgr: Arc<AsyncWorkerMgr>,
        cache: Arc<dyn BlobCache>,
        req: BlobIoRange,
    ) -> Result<()> {
        let blob_offset = req.blob_offset;
        let blob_size = req.blob_size;
        trace!(
            "storage: prefetch fs data from blob {} offset {} size {}",
            cache.blob_id(),
            blob_offset,
            blob_size
        );
        if blob_size == 0 {
            return Ok(());
        }

        // Record how much prefetch data is requested from storage backend.
        // So the average backend merged request size will be prefetch_data_amount/prefetch_mr_count.
        // We can measure merging possibility by this.
        mgr.metrics.prefetch_mr_count.inc();
        mgr.metrics.prefetch_data_amount.add(blob_size);

        if let Some(obj) = cache.get_blob_object() {
            obj.fetch_chunks(&req)?;
        } else {
            cache.prefetch_range(&req)?;
        }

        Ok(())
    }

    fn shrink_n(&self, n: u32) {
        self.workers.fetch_sub(n, Ordering::Relaxed);
    }

    fn grow_n(&self, n: u32) {
        self.workers.fetch_add(n, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmm_sys_util::tempdir::TempDir;

    #[test]
    fn test_worker_mgr_new() {
        let tmpdir = TempDir::new().unwrap();
        let metrics = BlobcacheMetrics::new("test1", tmpdir.as_path().to_str().unwrap());
        let config = Arc::new(AsyncPrefetchConfig {
            enable: true,
            threads_count: 2,
            merging_size: 0x100000,
            bandwidth_rate: 0x100000,
        });

        let mgr = Arc::new(AsyncWorkerMgr::new(metrics, config).unwrap());
        AsyncWorkerMgr::start(mgr.clone()).unwrap();
        assert_eq!(mgr.ping_requests.load(Ordering::Acquire), 0);
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::Ping)
            .is_ok());
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::Ping)
            .is_ok());
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::Ping)
            .is_ok());
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::Ping)
            .is_ok());
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::Ping)
            .is_ok());
        thread::sleep(Duration::from_secs(1));
        assert_eq!(mgr.ping_requests.load(Ordering::Acquire), 5);
        assert_eq!(mgr.workers.load(Ordering::Acquire), 2);
        mgr.stop();
        assert_eq!(mgr.workers.load(Ordering::Acquire), 0);
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::Ping)
            .is_err());
    }

    #[test]
    fn test_worker_mgr_rate_limiter() {
        let tmpdir = TempDir::new().unwrap();
        let metrics = BlobcacheMetrics::new("test1", tmpdir.as_path().to_str().unwrap());
        let config = Arc::new(AsyncPrefetchConfig {
            enable: true,
            threads_count: 4,
            merging_size: 0x100000,
            bandwidth_rate: 0x100000,
        });

        let mgr = Arc::new(AsyncWorkerMgr::new(metrics, config).unwrap());
        AsyncWorkerMgr::start(mgr.clone()).unwrap();

        assert_eq!(mgr.prefetch_delayed.load(Ordering::Acquire), 0);
        assert_eq!(mgr.prefetch_inflight.load(Ordering::Acquire), 0);

        thread::sleep(Duration::from_secs(1));
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::RateLimiter(1))
            .is_ok());
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::RateLimiter(1))
            .is_ok());
        thread::sleep(Duration::from_secs(1));
        assert_eq!(mgr.prefetch_delayed.load(Ordering::Acquire), 0);
        assert_eq!(mgr.prefetch_inflight.load(Ordering::Acquire), 0);

        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::RateLimiter(0x100001))
            .is_ok());
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::RateLimiter(u64::MAX))
            .is_ok());
        thread::sleep(Duration::from_secs(4));
        assert_eq!(mgr.prefetch_delayed.load(Ordering::Acquire), 2);
        assert_eq!(mgr.prefetch_inflight.load(Ordering::Acquire), 0);

        mgr.stop();
        assert_eq!(mgr.workers.load(Ordering::Acquire), 0);
    }
}
