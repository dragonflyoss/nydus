// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021-2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::ops::Deref;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::thread;
use std::time::{Duration, SystemTime};

use leaky_bucket::RateLimiter;
use nydus_api::PrefetchConfigV2;
use nydus_utils::async_helper::with_runtime;
use nydus_utils::metrics::{BlobcacheMetrics, Metric};
use nydus_utils::mpmc::Channel;
use tokio::runtime::Runtime;
use tokio::sync::Semaphore;

use crate::cache::{BlobCache, BlobIoRange};
use crate::factory::ASYNC_RUNTIME;
use crate::RAFS_MAX_CHUNK_SIZE;

static ASYNC_WORKER_MGR: Mutex<Option<Arc<AsyncWorkerMgr>>> = Mutex::new(None);

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
    BlobPrefetch(Arc<PrefetchMgr>, Arc<dyn BlobCache>, u64, u64, SystemTime),
    /// Asynchronous file-system layer prefetch request.
    FsPrefetch(
        Arc<PrefetchMgr>,
        Arc<dyn BlobCache>,
        BlobIoRange,
        SystemTime,
    ),
    #[cfg_attr(not(test), allow(unused))]
    /// Ping for test.
    Ping,
    #[cfg_attr(not(test), allow(unused))]
    RateLimiter(u64),
}

impl AsyncPrefetchMessage {
    /// Create a new asynchronous filesystem prefetch request message.
    pub fn new_fs_prefetch(
        mgr: Arc<PrefetchMgr>,
        blob_cache: Arc<dyn BlobCache>,
        req: BlobIoRange,
    ) -> Self {
        AsyncPrefetchMessage::FsPrefetch(mgr, blob_cache, req, SystemTime::now())
    }

    /// Create a new asynchronous blob prefetch request message.
    pub fn new_blob_prefetch(
        mgr: Arc<PrefetchMgr>,
        blob_cache: Arc<dyn BlobCache>,
        offset: u64,
        size: u64,
    ) -> Self {
        AsyncPrefetchMessage::BlobPrefetch(mgr, blob_cache, offset, size, SystemTime::now())
    }
}

struct AsyncWorkerMgr {
    workers: AtomicU32,
    ping_requests: AtomicU32,

    prefetch_config: Arc<AsyncPrefetchConfig>,
    prefetch_delayed: AtomicU64,
    prefetch_inflight: AtomicU32,
    prefetch_sema: Arc<Semaphore>,
    prefetch_channel: Arc<Channel<AsyncPrefetchMessage>>,
    prefetch_consumed: AtomicUsize,
    prefetch_limiter: Option<Arc<RateLimiter>>,
}

impl AsyncWorkerMgr {
    fn new(prefetch_config: Arc<AsyncPrefetchConfig>) -> Self {
        let prefetch_limiter = match prefetch_config.bandwidth_rate {
            0 => None,
            v => {
                // If the given value is less than maximum blob chunk size, it exceeds burst size of the
                // limiter ending up with throttling all throughput, so ensure bandwidth is bigger than
                // the maximum chunk size.
                let limit = std::cmp::max(RAFS_MAX_CHUNK_SIZE as usize * 2, v as usize);
                let limiter = RateLimiter::builder()
                    .initial(limit)
                    .refill(limit / 10)
                    .interval(Duration::from_millis(100))
                    .build();
                Some(Arc::new(limiter))
            }
        };

        AsyncWorkerMgr {
            workers: AtomicU32::new(0),
            ping_requests: AtomicU32::new(0),

            prefetch_sema: Arc::new(Semaphore::new(0)),
            prefetch_channel: Arc::new(Channel::new()),
            prefetch_config,
            prefetch_delayed: AtomicU64::new(0),
            prefetch_inflight: AtomicU32::new(0),
            prefetch_consumed: AtomicUsize::new(0),
            prefetch_limiter,
        }
    }

    fn start(self: Arc<Self>) -> Result<()> {
        // Hold the request queue to barrier all working threads.
        let guard = self.prefetch_channel.lock_channel();
        for num in 0..self.prefetch_config.threads_count {
            let mgr2 = self.clone();
            let res = thread::Builder::new()
                .name(format!("nydus_storage_worker_{}", num))
                .spawn(move || {
                    mgr2.grow_n(1);
                    with_runtime(|rt| {
                        rt.block_on(Self::handle_prefetch_requests(mgr2.clone(), rt));
                    });
                    mgr2.shrink_n(1);
                    info!("storage: worker thread {} exits.", num)
                });

            if let Err(e) = res {
                error!("storage: failed to create worker thread, {:?}", e);
                self.prefetch_channel.close();
                drop(guard);
                self.stop();
                return Err(e);
            }
        }
        Ok(())
    }

    /// Stop all working threads.
    fn stop(&self) {
        self.prefetch_channel.close();

        while self.workers.load(Ordering::Relaxed) > 0 {
            self.prefetch_channel.notify_waiters();
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn send_prefetch_message(
        &self,
        msg: AsyncPrefetchMessage,
    ) -> std::result::Result<(), AsyncPrefetchMessage> {
        self.prefetch_inflight.fetch_add(1, Ordering::Relaxed);
        self.prefetch_channel.send(msg)
    }

    fn flush_pending_prefetch_requests(&self, blob_id: &str) {
        self.prefetch_channel
            .flush_pending_prefetch_requests(|t| match t {
                AsyncPrefetchMessage::BlobPrefetch(_, blob, _, _, _) => {
                    blob_id == blob.blob_id() && !blob.is_prefetch_active()
                }
                AsyncPrefetchMessage::FsPrefetch(_, blob, _, _) => {
                    blob_id == blob.blob_id() && !blob.is_prefetch_active()
                }
                _ => false,
            });
    }

    fn consume_prefetch_budget(&self, size: u32) {
        if self.prefetch_inflight.load(Ordering::Relaxed) > 0 {
            self.prefetch_consumed
                .fetch_add(size as usize, Ordering::AcqRel);
        }
    }

    async fn handle_prefetch_requests(self: Arc<Self>, rt: &Runtime) {
        // Max 1 active requests per thread.
        self.prefetch_sema.add_permits(1);

        while let Ok(msg) = self.prefetch_channel.recv().await {
            self.handle_prefetch_rate_limit(&msg).await;

            match msg {
                AsyncPrefetchMessage::BlobPrefetch(mgr, blob_cache, offset, size, begin_time) => {
                    let token = Semaphore::acquire_owned(self.prefetch_sema.clone())
                        .await
                        .unwrap();
                    if blob_cache.is_prefetch_active() {
                        rt.spawn_blocking(move || {
                            let _ = Self::handle_blob_prefetch_request(
                                mgr, blob_cache, offset, size, begin_time,
                            );
                            drop(token);
                        });
                    }
                }
                AsyncPrefetchMessage::FsPrefetch(mgr, blob_cache, req, begin_time) => {
                    let token = Semaphore::acquire_owned(self.prefetch_sema.clone())
                        .await
                        .unwrap();

                    if blob_cache.is_prefetch_active() {
                        rt.spawn_blocking(move || {
                            let _ =
                                Self::handle_fs_prefetch_request(mgr, blob_cache, req, begin_time);
                            drop(token)
                        });
                    }
                }
                AsyncPrefetchMessage::Ping => {
                    let _ = self.ping_requests.fetch_add(1, Ordering::Relaxed);
                }
                AsyncPrefetchMessage::RateLimiter(_size) => {}
            }

            self.prefetch_inflight.fetch_sub(1, Ordering::Relaxed);
        }
    }

    async fn handle_prefetch_rate_limit(&self, msg: &AsyncPrefetchMessage) {
        // Allocate network bandwidth budget
        if let Some(limiter) = &self.prefetch_limiter {
            let size = match msg {
                AsyncPrefetchMessage::BlobPrefetch(_, blob_cache, _offset, size, _) => {
                    if blob_cache.is_prefetch_active() {
                        *size
                    } else {
                        0
                    }
                }
                AsyncPrefetchMessage::FsPrefetch(_, blob_cache, req, _) => {
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
        mgr: Arc<PrefetchMgr>,
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

        if let Some(obj) = cache.get_blob_object() {
            if let Err(e) = obj.fetch_range_compressed(offset, size, true) {
                if mgr.retry_times.load(Ordering::Relaxed) > 0 {
                    mgr.retry_times.fetch_sub(1, Ordering::Relaxed);
                    ASYNC_RUNTIME.spawn(async move {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        let msg = AsyncPrefetchMessage::new_blob_prefetch(
                            mgr.clone(),
                            cache.clone(),
                            offset,
                            size,
                        );
                        let _ = mgr.send_prefetch_message(msg);
                    });
                    Ok(())
                } else {
                    warn!("storage: failed to prefetch data from blob {}, offset {}, size {}, {}, will try resend",
                          cache.blob_id(), offset, size, e);
                    Err(e)
                }
            } else {
                // Record how much prefetch data is requested from storage backend.
                // So the average backend merged request size will be prefetch_data_amount/prefetch_requests_count.
                // We can measure merging possibility by this.
                mgr.metrics.prefetch_requests_count.inc();
                mgr.metrics.prefetch_data_amount.add(size);
                mgr.metrics.calculate_prefetch_metrics(begin_time);
                Ok(())
            }
        } else {
            Err(eother!("prefetch blob range is not supported"))
        }
    }

    // TODO: Nydus plans to switch backend storage IO stack to full asynchronous mode.
    // But we can't make `handle_fs_prefetch_request` as async due to the fact that
    // tokio doesn't allow dropping runtime in a non-blocking context. Otherwise, prefetch
    // threads always panic in debug program profile. We can achieve the goal when
    // backend/registry also switches to async IO.
    fn handle_fs_prefetch_request(
        mgr: Arc<PrefetchMgr>,
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

        if let Some(obj) = cache.get_blob_object() {
            obj.prefetch_chunks(&req)?;
        } else {
            cache.prefetch_range(&req)?;
        }

        // Record how much prefetch data is requested from storage backend.
        // So the average backend merged request size will be prefetch_data_amount/prefetch_requests_count.
        // We can measure merging possibility by this.
        mgr.metrics.prefetch_requests_count.inc();
        mgr.metrics.prefetch_data_amount.add(blob_size);
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

/// An asynchronous task manager for data prefetching
pub(crate) struct PrefetchMgr {
    enabled: bool,
    metrics: Arc<BlobcacheMetrics>,
    begin_timing_once: Once,
    retry_times: AtomicI32,
    worker_mgr: Arc<AsyncWorkerMgr>,
}

impl PrefetchMgr {
    /// Create a new instance of `AsyncWorkerMgr`.
    pub fn new(
        metrics: Arc<BlobcacheMetrics>,
        prefetch_config: Arc<AsyncPrefetchConfig>,
    ) -> Result<Self> {
        let enabled = prefetch_config.enable;
        let mut guard = ASYNC_WORKER_MGR.lock().unwrap();
        let worker_mgr = match guard.deref() {
            Some(v) => v.clone(),
            None => {
                let mgr = Arc::new(AsyncWorkerMgr::new(prefetch_config));
                mgr.clone().start()?;
                *guard = Some(mgr.clone());
                mgr
            }
        };

        Ok(PrefetchMgr {
            enabled,
            metrics,
            begin_timing_once: Once::new(),
            retry_times: AtomicI32::new(32),
            worker_mgr,
        })
    }

    /// Create working threads and start the event loop.
    pub fn setup(&self) -> Result<()> {
        self.begin_timing_once.call_once(|| {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap();
            self.metrics.prefetch_begin_time_secs.set(now.as_secs());
            self.metrics
                .prefetch_begin_time_millis
                .set(now.subsec_millis() as u64);
            self.metrics.prefetch_workers.store(
                self.worker_mgr.workers.load(Ordering::Relaxed) as usize,
                Ordering::Relaxed,
            );
        });

        Ok(())
    }

    /// Send an asynchronous service request message to the workers.
    pub fn send_prefetch_message(
        &self,
        msg: AsyncPrefetchMessage,
    ) -> std::result::Result<(), AsyncPrefetchMessage> {
        if self.enabled {
            self.worker_mgr.send_prefetch_message(msg)
        } else {
            Ok(())
        }
    }

    /// Flush pending prefetch requests associated with `blob_id`.
    pub fn flush_pending_prefetch_requests(&self, blob_id: &str) {
        if self.enabled {
            self.worker_mgr.flush_pending_prefetch_requests(blob_id);
        }
    }

    /// Consume network bandwidth budget for prefetching.
    pub fn consume_prefetch_budget(&self, size: u32) {
        self.worker_mgr.consume_prefetch_budget(size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmm_sys_util::tempdir::TempDir;

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

        let mgr = Arc::new(PrefetchMgr::new(metrics, config).unwrap());
        mgr.setup().unwrap();
        thread::sleep(Duration::from_secs(1));
        assert_eq!(mgr.worker_mgr.workers.load(Ordering::Acquire), 4);

        assert_eq!(mgr.worker_mgr.ping_requests.load(Ordering::Acquire), 0);
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
        assert_eq!(mgr.worker_mgr.ping_requests.load(Ordering::Acquire), 5);

        assert_eq!(mgr.worker_mgr.prefetch_delayed.load(Ordering::Acquire), 0);
        assert_eq!(mgr.worker_mgr.prefetch_inflight.load(Ordering::Acquire), 0);
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::RateLimiter(1))
            .is_ok());
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::RateLimiter(1))
            .is_ok());
        thread::sleep(Duration::from_secs(1));
        assert_eq!(mgr.worker_mgr.prefetch_delayed.load(Ordering::Acquire), 0);
        assert_eq!(mgr.worker_mgr.prefetch_inflight.load(Ordering::Acquire), 0);

        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::RateLimiter(0x300_0000))
            .is_ok());
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::RateLimiter(0x100_0000))
            .is_ok());
        assert!(mgr
            .send_prefetch_message(AsyncPrefetchMessage::RateLimiter(u64::MAX))
            .is_ok());
        assert!(mgr.worker_mgr.prefetch_inflight.load(Ordering::Acquire) >= 2);
        thread::sleep(Duration::from_secs(2));
        assert!(mgr.worker_mgr.prefetch_inflight.load(Ordering::Acquire) <= 2);
        assert!(mgr.worker_mgr.prefetch_inflight.load(Ordering::Acquire) >= 1);
        thread::sleep(Duration::from_secs(3));
        assert!(mgr.worker_mgr.prefetch_inflight.load(Ordering::Acquire) >= 1);
        assert!(mgr.worker_mgr.prefetch_delayed.load(Ordering::Acquire) >= 1);

        assert_eq!(mgr.worker_mgr.workers.load(Ordering::Acquire), 4);
        mgr.worker_mgr.stop();
        assert_eq!(mgr.worker_mgr.workers.load(Ordering::Acquire), 0);
    }
}
