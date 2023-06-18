// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021-2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Once};
use std::thread;
use std::time::{Duration, SystemTime};

use nydus_api::PrefetchConfigV2;
use nydus_utils::async_helper::with_runtime;
use nydus_utils::metrics::{BlobcacheMetrics, Metric};
use nydus_utils::mpmc::Channel;
use tokio::runtime::Runtime;
use tokio::sync::Semaphore;

use crate::cache::{BlobCache, BlobIoRange};
use crate::factory::ASYNC_RUNTIME;

/// Configuration information for asynchronous workers.
pub(crate) struct AsyncPrefetchConfig {
    /// Whether or not to enable prefetch.
    pub enable: bool,
    /// Number of working threads.
    pub threads_count: usize,
    /// Window size to merge/amplify requests.
    pub merging_size: usize,
    /// Network bandwidth for prefetch, in unit of Bytes and Zero means no rate limit is set.
    #[allow(unused)]
    pub bandwidth_rate: u32,
}

impl From<&PrefetchConfigV2> for AsyncPrefetchConfig {
    fn from(p: &PrefetchConfigV2) -> Self {
        AsyncPrefetchConfig {
            enable: p.enable,
            threads_count: p.threads,
            merging_size: p.batch_size,
            bandwidth_rate: p.bandwidth_limit,
        }
    }
}

/// Asynchronous service request message.
pub(crate) enum AsyncPrefetchMessage {
    /// Asynchronous blob layer prefetch request with (offset, size) of blob on storage backend.
    BlobPrefetch(Arc<dyn BlobCache>, u64, u64, SystemTime),
    /// Asynchronous file-system layer prefetch request.
    FsPrefetch(Arc<dyn BlobCache>, BlobIoRange, SystemTime),
    #[cfg_attr(not(test), allow(unused))]
    /// Ping for test.
    Ping,
    #[allow(unused)]
    RateLimiter(u64),
}

impl AsyncPrefetchMessage {
    /// Create a new asynchronous filesystem prefetch request message.
    pub fn new_fs_prefetch(blob_cache: Arc<dyn BlobCache>, req: BlobIoRange) -> Self {
        AsyncPrefetchMessage::FsPrefetch(blob_cache, req, SystemTime::now())
    }

    /// Create a new asynchronous blob prefetch request message.
    pub fn new_blob_prefetch(blob_cache: Arc<dyn BlobCache>, offset: u64, size: u64) -> Self {
        AsyncPrefetchMessage::BlobPrefetch(blob_cache, offset, size, SystemTime::now())
    }
}

/// An asynchronous task manager for data prefetching
pub(crate) struct AsyncWorkerMgr {
    metrics: Arc<BlobcacheMetrics>,
    ping_requests: AtomicU32,
    workers: AtomicU32,
    active: AtomicBool,
    begin_timing_once: Once,

    // Limit the total retry times to avoid unnecessary resource consumption.
    retry_times: AtomicI32,

    prefetch_sema: Arc<Semaphore>,
    prefetch_channel: Arc<Channel<AsyncPrefetchMessage>>,
    prefetch_config: Arc<AsyncPrefetchConfig>,
    #[allow(unused)]
    prefetch_delayed: AtomicU64,
    prefetch_inflight: AtomicU32,
    prefetch_consumed: AtomicUsize,
    #[cfg(feature = "prefetch-rate-limit")]
    prefetch_limiter: Option<Arc<leaky_bucket::RateLimiter>>,
}

impl AsyncWorkerMgr {
    /// Create a new instance of `AsyncWorkerMgr`.
    pub fn new(
        metrics: Arc<BlobcacheMetrics>,
        prefetch_config: Arc<AsyncPrefetchConfig>,
    ) -> Result<Self> {
        #[cfg(feature = "prefetch-rate-limit")]
        let prefetch_limiter = match prefetch_config.bandwidth_rate {
            0 => None,
            v => {
                // If the given value is less than maximum blob chunk size, it exceeds burst size of the
                // limiter ending up with throttling all throughput, so ensure bandwidth is bigger than
                // the maximum chunk size.
                let limit = std::cmp::max(crate::RAFS_MAX_CHUNK_SIZE as usize, v as usize);
                let limiter = leaky_bucket::RateLimiter::builder()
                    .initial(limit)
                    .refill(limit / 10)
                    .interval(Duration::from_millis(100))
                    .build();
                Some(Arc::new(limiter))
            }
        };

        Ok(AsyncWorkerMgr {
            metrics,
            ping_requests: AtomicU32::new(0),
            workers: AtomicU32::new(0),
            active: AtomicBool::new(false),
            begin_timing_once: Once::new(),

            retry_times: AtomicI32::new(32),

            prefetch_sema: Arc::new(Semaphore::new(0)),
            prefetch_channel: Arc::new(Channel::new()),
            prefetch_config,
            prefetch_delayed: AtomicU64::new(0),
            prefetch_inflight: AtomicU32::new(0),
            prefetch_consumed: AtomicUsize::new(0),
            #[cfg(feature = "prefetch-rate-limit")]
            prefetch_limiter,
        })
    }

    /// Create working threads and start the event loop.
    pub fn start(mgr: Arc<AsyncWorkerMgr>) -> Result<()> {
        if mgr.prefetch_config.enable {
            Self::start_prefetch_workers(mgr)?;
        }

        Ok(())
    }

    /// Stop all working threads.
    pub fn stop(&self) {
        if self
            .active
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        self.prefetch_channel.close();

        while self.workers.load(Ordering::Relaxed) > 0 {
            self.prefetch_channel.notify_waiters();
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

    /// Flush pending prefetch requests associated with `blob_id`.
    pub fn flush_pending_prefetch_requests(&self, blob_id: &str) {
        self.prefetch_channel
            .flush_pending_prefetch_requests(|t| match t {
                AsyncPrefetchMessage::BlobPrefetch(blob, _, _, _) => {
                    blob_id == blob.blob_id() && !blob.is_prefetch_active()
                }
                AsyncPrefetchMessage::FsPrefetch(blob, _, _) => {
                    blob_id == blob.blob_id() && !blob.is_prefetch_active()
                }
                _ => false,
            });
    }

    /// Consume network bandwidth budget for prefetching.
    pub fn consume_prefetch_budget(&self, size: u64) {
        if self.prefetch_inflight.load(Ordering::Relaxed) > 0 {
            self.prefetch_consumed
                .fetch_add(size as usize, Ordering::AcqRel);
        }
    }

    fn start_prefetch_workers(mgr: Arc<AsyncWorkerMgr>) -> Result<()> {
        // Hold the request queue to barrier all working threads.
        let guard = mgr.prefetch_channel.lock_channel();
        for num in 0..mgr.prefetch_config.threads_count {
            let mgr2 = mgr.clone();
            let res = thread::Builder::new()
                .name(format!("nydus_storage_worker_{}", num))
                .spawn(move || {
                    mgr2.grow_n(1);
                    mgr2.metrics
                        .prefetch_workers
                        .fetch_add(1, Ordering::Relaxed);

                    with_runtime(|rt| {
                        rt.block_on(Self::handle_prefetch_requests(mgr2.clone(), rt));
                    });

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
        mgr.active.store(true, Ordering::Release);
        Ok(())
    }

    async fn handle_prefetch_requests(mgr: Arc<AsyncWorkerMgr>, rt: &Runtime) {
        mgr.begin_timing_once.call_once(|| {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap();

            mgr.metrics.prefetch_begin_time_secs.set(now.as_secs());
            mgr.metrics
                .prefetch_begin_time_millis
                .set(now.subsec_millis() as u64);
        });

        // Max 1 active requests per thread.
        mgr.prefetch_sema.add_permits(1);

        while let Ok(msg) = mgr.prefetch_channel.recv().await {
            mgr.handle_prefetch_rate_limit(&msg).await;
            let mgr2 = mgr.clone();

            match msg {
                AsyncPrefetchMessage::BlobPrefetch(blob_cache, offset, size, begin_time) => {
                    let token = Semaphore::acquire_owned(mgr2.prefetch_sema.clone())
                        .await
                        .unwrap();
                    if blob_cache.is_prefetch_active() {
                        rt.spawn_blocking(move || {
                            let _ = Self::handle_blob_prefetch_request(
                                mgr2.clone(),
                                blob_cache,
                                offset,
                                size,
                                begin_time,
                            );
                            drop(token);
                        });
                    }
                }
                AsyncPrefetchMessage::FsPrefetch(blob_cache, req, begin_time) => {
                    let token = Semaphore::acquire_owned(mgr2.prefetch_sema.clone())
                        .await
                        .unwrap();

                    if blob_cache.is_prefetch_active() {
                        rt.spawn_blocking(move || {
                            let _ = Self::handle_fs_prefetch_request(
                                mgr2.clone(),
                                blob_cache,
                                req,
                                begin_time,
                            );
                            drop(token)
                        });
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

    async fn handle_prefetch_rate_limit(&self, _msg: &AsyncPrefetchMessage) {
        #[cfg(feature = "prefetch-rate-limit")]
        // Allocate network bandwidth budget
        if let Some(limiter) = &self.prefetch_limiter {
            let size = match _msg {
                AsyncPrefetchMessage::BlobPrefetch(blob_cache, _offset, size, _) => {
                    if blob_cache.is_prefetch_active() {
                        *size
                    } else {
                        0
                    }
                }
                AsyncPrefetchMessage::FsPrefetch(blob_cache, req, _) => {
                    if blob_cache.is_prefetch_active() {
                        req.blob_size
                    } else {
                        0
                    }
                }
                AsyncPrefetchMessage::Ping => 0,
                AsyncPrefetchMessage::RateLimiter(size) => *size,
            };

            if size > 0 {
                let size = (self.prefetch_consumed.swap(0, Ordering::AcqRel))
                    .saturating_add(size as usize);
                let max = limiter.max();
                let size = std::cmp::min(size, max.saturating_add(max));
                let cap = limiter.balance();
                if cap < size {
                    self.prefetch_delayed.fetch_add(1, Ordering::Relaxed);
                }
                limiter.acquire(size).await;
            }
        }
    }

    fn handle_blob_prefetch_request(
        mgr: Arc<AsyncWorkerMgr>,
        cache: Arc<dyn BlobCache>,
        offset: u64,
        size: u64,
        begin_time: SystemTime,
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

        // Record how much prefetch data is requested from storage backend.
        // So the average backend merged request size will be prefetch_data_amount/prefetch_requests_count.
        // We can measure merging possibility by this.
        let metrics = mgr.metrics.clone();
        metrics.prefetch_requests_count.inc();
        metrics.prefetch_data_amount.add(size);

        if let Some(obj) = cache.get_blob_object() {
            if let Err(_e) = obj.fetch_range_compressed(offset, size, true) {
                if mgr.retry_times.load(Ordering::Relaxed) > 0 {
                    mgr.retry_times.fetch_sub(1, Ordering::Relaxed);
                    ASYNC_RUNTIME.spawn(async move {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        let msg =
                            AsyncPrefetchMessage::new_blob_prefetch(cache.clone(), offset, size);
                        let _ = mgr.send_prefetch_message(msg);
                    });
                }
            }
        } else {
            warn!("prefetch blob range is not supported");
        }

        metrics.calculate_prefetch_metrics(begin_time);

        Ok(())
    }

    // TODO: Nydus plans to switch backend storage IO stack to full asynchronous mode.
    // But we can't make `handle_fs_prefetch_request` as async due to the fact that
    // tokio doesn't allow dropping runtime in a non-blocking context. Otherwise, prefetch
    // threads always panic in debug program profile. We can achieve the goal when
    // backend/registry also switches to async IO.
    fn handle_fs_prefetch_request(
        mgr: Arc<AsyncWorkerMgr>,
        cache: Arc<dyn BlobCache>,
        req: BlobIoRange,
        begin_time: SystemTime,
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
        // So the average backend merged request size will be prefetch_data_amount/prefetch_requests_count.
        // We can measure merging possibility by this.
        mgr.metrics.prefetch_requests_count.inc();
        mgr.metrics.prefetch_data_amount.add(blob_size);

        if let Some(obj) = cache.get_blob_object() {
            obj.prefetch_chunks(&req)?;
        } else {
            cache.prefetch_range(&req)?;
        }

        mgr.metrics.calculate_prefetch_metrics(begin_time);

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

    #[cfg(feature = "prefetch-rate-limit")]
    #[test]
    fn test_worker_mgr_rate_limiter() {
        let tmpdir = TempDir::new().unwrap();
        let metrics = BlobcacheMetrics::new("test1", tmpdir.as_path().to_str().unwrap());
        let config = Arc::new(AsyncPrefetchConfig {
            enable: true,
            threads_count: 4,
            merging_size: 0x1000000,
            bandwidth_rate: 0x1000000,
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
            .send_prefetch_message(AsyncPrefetchMessage::RateLimiter(0x1000000))
            .is_ok());
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::RateLimiter(0x1000000))
            .is_ok());
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::RateLimiter(u64::MAX))
            .is_ok());
        assert_eq!(mgr.prefetch_inflight.load(Ordering::Acquire), 3);
        thread::sleep(Duration::from_secs(1));
        assert!(mgr.prefetch_inflight.load(Ordering::Acquire) <= 2);
        assert!(mgr.prefetch_inflight.load(Ordering::Acquire) >= 1);
        thread::sleep(Duration::from_secs(3));
        assert!(mgr.prefetch_inflight.load(Ordering::Acquire) >= 1);
        assert!(mgr.prefetch_delayed.load(Ordering::Acquire) >= 1);

        mgr.stop();
        assert_eq!(mgr.workers.load(Ordering::Acquire), 0);
    }
}
