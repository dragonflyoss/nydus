// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use futures::executor::block_on;
use governor::clock::QuantaClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use nydus_utils::metrics::{BlobcacheMetrics, Metric};
use spmc::{channel, Receiver, Sender};

use crate::cache::{BlobCache, BlobIoRange, BlobPrefetchConfig};
use crate::RAFS_MAX_CHUNK_SIZE;
use fuse_backend_rs::transport::FileVolatileSlice;

/// Configuration information for asynchronous workers.
pub(crate) struct AsyncPrefetchConfig {
    /// Whether or not to eneable prefetch.
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

/// Status of an asynchronous service request message.
#[repr(u32)]
pub(crate) enum AsyncRequestState {
    /// Initializations state.
    Init,
    /// The asynchronous service request is pending for executing, worker should not touching state
    /// after executing the request.
    Pending,
    /// The asynchronous service request has been cancelled.
    #[allow(dead_code)]
    Cancelled,
    /*
    /// The caller is waiting for the worker to execute the request and set state to `Finished`.
    WaitingForAck,
    /// The asynchronous service request has been executed.
    Finished,
     */
}

/// Asynchronous service request message.
#[allow(dead_code)]
pub(crate) enum AsyncRequestMessage {
    /// Notify the working threads to exit.
    Exit,
    /// Ping for test.
    Ping,
    /// Asynchronous file-system layer prefetch request.
    FsPrefetch(Arc<AtomicU32>, Arc<dyn BlobCache>, BlobIoRange),
    /// Asynchronous blob layer prefetch request with (offset, size) of blob on storage backend.
    BlobPrefetch(Arc<AtomicU32>, Arc<dyn BlobCache>, u64, u64),
}

impl AsyncRequestMessage {
    /// Create a new asynchronous filesystem prefetch request message.
    pub fn new_fs_prefetch(
        blob_cache: Arc<dyn BlobCache>,
        req_state: Arc<AtomicU32>,
        req: BlobIoRange,
    ) -> Self {
        AsyncRequestMessage::FsPrefetch(req_state, blob_cache, req)
    }

    /// Create a new asynchronous blob prefetch request message.
    pub fn new_blob_prefetch(
        blob_cache: Arc<dyn BlobCache>,
        req_state: Arc<AtomicU32>,
        offset: u64,
        size: u64,
    ) -> Self {
        AsyncRequestMessage::BlobPrefetch(req_state, blob_cache, offset, size)
    }
}

pub(crate) struct AsyncWorkerMgr {
    metrics: Arc<BlobcacheMetrics>,
    receiver: Receiver<AsyncRequestMessage>,
    sender: Mutex<Sender<AsyncRequestMessage>>,
    workers: AtomicU32,
    busy_workers: AtomicU32,
    pings: AtomicU32,
    exiting: AtomicBool,

    prefetch_config: Arc<AsyncPrefetchConfig>,
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
            info!("Prefetch bandwidth will be limited at {}Bytes/S", v);
            Arc::new(RateLimiter::direct(Quota::per_second(v)))
        });
        let (sender, receiver) = channel::<AsyncRequestMessage>();

        Ok(AsyncWorkerMgr {
            metrics,
            receiver,
            sender: Mutex::new(sender),
            workers: AtomicU32::new(0),
            busy_workers: AtomicU32::new(0),
            pings: AtomicU32::new(0),
            exiting: AtomicBool::new(false),

            prefetch_config,
            prefetch_limiter,
        })
    }

    /// Create working threads and start the event loop.
    pub fn start(mgr: Arc<AsyncWorkerMgr>) -> Result<()> {
        // Hold the sender to barrier all working threads.
        let guard = mgr.sender.lock().unwrap();
        let threads = mgr.prefetch_config.threads_count;

        for num in 0..threads {
            let mgr2 = mgr.clone();
            let rx = mgr.receiver.clone();
            let res = thread::Builder::new()
                .name(format!("blob_async_thread_{}", num))
                .spawn(move || {
                    mgr2.grow_n(1);
                    mgr2.metrics
                        .prefetch_workers
                        .fetch_add(1, Ordering::Relaxed);
                    mgr2.run(rx);
                    mgr2.metrics
                        .prefetch_workers
                        .fetch_sub(1, Ordering::Relaxed);
                    mgr2.shrink_n(1);
                    info!("Prefetch thread exits.")
                });

            if let Err(e) = res {
                error!("Create prefetch worker failed, {:?}", e);
                drop(guard);
                mgr.stop();
                return Err(e);
            }
        }

        Ok(())
    }

    /// Stop all working threads.
    pub fn stop(&self) {
        //self.exiting.store(true, Ordering::Release);
        while self.send(AsyncRequestMessage::Exit).is_ok()
            && self.workers.load(Ordering::Relaxed) > 0
        {
            thread::sleep(Duration::from_millis(1));
        }
    }

    /// Send an asynchronous service request message to the workers.
    pub fn send(&self, msg: AsyncRequestMessage) -> Result<()> {
        match &msg {
            AsyncRequestMessage::FsPrefetch(_, _, req) => {
                if let Some(ref limiter) = self.prefetch_limiter {
                    let size = std::cmp::min(req.blob_size, u32::MAX as u64) as u32;
                    let cells = match NonZeroU32::new(size) {
                        Some(v) => v,
                        None => return Ok(()),
                    };
                    if let Err(e) = limiter
                        .check_n(cells)
                        .or_else(|_| block_on(limiter.until_n_ready(cells)))
                    {
                        // `InsufficientCapacity` is the only possible error
                        // Have to give up to avoid dead-loop
                        error!("{}: give up rate-limiting", e);
                    }
                }
            }
            AsyncRequestMessage::BlobPrefetch(_, _, _, size) => {
                if let Some(ref limiter) = self.prefetch_limiter {
                    let size = std::cmp::min(*size, u32::MAX as u64) as u32;
                    let cells = match NonZeroU32::new(size) {
                        Some(v) => v,
                        None => return Ok(()),
                    };
                    if let Err(e) = limiter
                        .check_n(cells)
                        .or_else(|_| block_on(limiter.until_n_ready(cells)))
                    {
                        // `InsufficientCapacity` is the only possible error
                        // Have to give up to avoid dead-loop
                        error!("{}: give up rate-limiting", e);
                    }
                }
            }
            _ => {}
        }

        let mut sender = self.sender.lock().unwrap();
        sender.send(msg).map_err(|e| {
            warn!("no more receiver for channel, {}", e);
            eio!()
        })
    }

    /// Consume network bandwidth budget for prefetching.
    pub fn consume_prefetch_budget(&self, buffers: &[FileVolatileSlice]) {
        if self.busy_workers.load(Ordering::Relaxed) > 0 {
            let size = buffers.iter().fold(0, |v, i| v + i.len());
            if let Some(v) = NonZeroU32::new(std::cmp::min(size, u32::MAX as usize) as u32) {
                // Try to consume budget but ignore result.
                if let Some(limiter) = self.prefetch_limiter.as_ref() {
                    let _ = limiter.check_n(v);
                }
            }
        }
    }

    fn run(&self, rx: Receiver<AsyncRequestMessage>) {
        while let Ok(msg) = rx.recv() {
            match msg {
                AsyncRequestMessage::FsPrefetch(state, blob_cache, req) => {
                    self.busy_workers.fetch_add(1, Ordering::Relaxed);
                    if state.load(Ordering::Acquire) == AsyncRequestState::Pending as u32 {
                        let _ = self.handle_fs_prefetch_request(&blob_cache, &req);
                    }
                    self.busy_workers.fetch_sub(1, Ordering::Relaxed);
                }
                AsyncRequestMessage::BlobPrefetch(state, blob_cache, offset, size) => {
                    self.busy_workers.fetch_add(1, Ordering::Relaxed);
                    if state.load(Ordering::Acquire) == AsyncRequestState::Pending as u32 {
                        let _ = self.handle_blob_prefetch_request(&blob_cache, offset, size);
                    }
                    self.busy_workers.fetch_sub(1, Ordering::Relaxed);
                }
                AsyncRequestMessage::Ping => {
                    let _ = self.pings.fetch_add(1, Ordering::Relaxed);
                }
                AsyncRequestMessage::Exit => return,
            }

            if self.exiting.load(Ordering::Relaxed) {
                return;
            }
        }
    }

    fn handle_blob_prefetch_request(
        &self,
        cache: &Arc<dyn BlobCache>,
        offset: u64,
        size: u64,
    ) -> Result<()> {
        trace!(
            "Prefetch blob {} offset {} size {}",
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
                    "Failed to prefetch data from blob {}, offset {}, size {}, {}",
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

    fn handle_fs_prefetch_request(
        &self,
        cache: &Arc<dyn BlobCache>,
        req: &BlobIoRange,
    ) -> Result<()> {
        let blob_offset = req.blob_offset;
        let blob_size = req.blob_size;
        trace!(
            "prefetch fs data from blob {} offset {} size {}",
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
        self.metrics.prefetch_mr_count.inc();
        self.metrics.prefetch_data_amount.add(blob_size);

        if let Some(obj) = cache.get_blob_object() {
            obj.fetch_chunks(req)?;
        } else {
            cache.prefetch_range(req)?;
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
        assert_eq!(mgr.pings.load(Ordering::Relaxed), 0);
        mgr.send(AsyncRequestMessage::Ping).unwrap();
        mgr.send(AsyncRequestMessage::Ping).unwrap();
        mgr.send(AsyncRequestMessage::Ping).unwrap();
        thread::sleep(Duration::from_secs(1));
        assert_eq!(mgr.workers.load(Ordering::Relaxed), 2);
        assert_eq!(mgr.pings.load(Ordering::Relaxed), 3);
        mgr.stop();
        assert_eq!(mgr.workers.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_worker_mgr_rate_limiter() {
        // TODO
    }
}
