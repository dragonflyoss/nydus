// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use crate::cache::filecache::FileCacheMgr;
use crate::cache::BlobPrefetchConfig;

/// Struct to maintain prefetch configuration and state.
///
/// The `PrefetchContext` structure receives prefetch configuration from `BlobPrefetchConfig`
/// an
pub(crate) struct PrefetchContext {
    pub enable: bool,
    pub threads_count: usize,
    pub merging_size: usize,
    pub bandwidth_rate: u32, // In unit of Bytes and Zero means no rate limit is set.
    pub workers: AtomicU32,
    pub prefetch_threads: Mutex<Vec<JoinHandle<()>>>,
    /*
    // TODO: Directly using Governor RateLimiter makes code a little hard to read as
    // some concepts come from GCRA like "cells". GCRA is a sort of improved "Leaky Bucket"
    // firstly invented from ATM network technology. Wrap the limiter into Throttle!
    limiter: Option<Arc<RateLimiter<NotKeyed, InMemoryState, QuantaClock>>>,
    mr_sender: Arc<Mutex<Option<spmc::Sender<MergedBackendRequest>>>>,
    mr_receiver: Option<spmc::Receiver<MergedBackendRequest>>,
    runtime: Arc<Runtime>,
    */
}

impl From<BlobPrefetchConfig> for PrefetchContext {
    fn from(p: BlobPrefetchConfig) -> Self {
        PrefetchContext {
            enable: p.enable,
            threads_count: p.threads_count,
            merging_size: p.merging_size,
            bandwidth_rate: p.bandwidth_rate,
            workers: AtomicU32::new(0),
            prefetch_threads: Mutex::new(Vec::<_>::new()),
        }
    }
}

impl PrefetchContext {
    /// Create working threads and start to prefetch blob data from storage backend.
    pub fn create_working_threads(&self, mgr: Arc<FileCacheMgr>) -> Result<()> {
        for num in 0..self.threads_count {
            let mgr2 = mgr.clone();
            //let rx = blobcache.mr_receiver.clone();

            // TODO: We now don't define prefetch policy. Prefetch works according to hints coming
            // from on-disk prefetch table or input arguments while nydusd starts. So better
            // we can have method to kill prefetch threads. But hopefully, we can add
            // another new prefetch policy triggering prefetch files belonging to the same
            // directory while one of them is read. We can easily get a continuous region on blob
            // that way.
            thread::Builder::new()
                .name(format!("prefetch_thread_{}", num))
                .spawn(move || {
                    mgr2.prefetch_ctx.grow_n(1);
                    mgr2.metrics
                        .prefetch_workers
                        .fetch_add(1, Ordering::Relaxed);
                    // TODO: barrier here
                    //mgr2.prefetch_ctx.prefetch_blob_data();
                    mgr2.metrics
                        .prefetch_workers
                        .fetch_sub(1, Ordering::Relaxed);
                    mgr2.prefetch_ctx.shrink_n(1);
                    info!("Prefetch thread exits.")
                })
                .map(|t| {
                    self.prefetch_threads
                        .lock()
                        .expect("Not expect poisoned lock")
                        .push(t)
                })
                .unwrap_or_else(|e| error!("Create prefetch worker failed, {:?}", e));
        }

        Ok(())
    }

    pub fn is_working(&self) -> bool {
        self.enable && self.workers.load(Ordering::Relaxed) != 0
    }

    fn shrink_n(&self, n: u32) {
        self.workers.fetch_sub(n, Ordering::Relaxed);
    }

    fn grow_n(&self, n: u32) {
        self.workers.fetch_add(n, Ordering::Relaxed);
    }
}

/*
// TODO: This function is too long... :-(
fn kick_prefetch_workers(cache: Arc<BlobCache>) {
                // Safe because channel must be established before prefetch workers
                'wait_mr: while let Ok(mr) = rx.as_ref().unwrap().recv() {
                    let blob_offset = mr.blob_offset;
                    let blob_size = mr.blob_size;
                    let continuous_chunks = &mr.chunks;
                    let blob_id = &mr.blob_entry.blob_id;
                    let mut issue_batch: bool;

                    trace!(
                        "Merged req id {} req offset {} size {}",
                        blob_id,
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
                        if chunk_map.is_ready(c.as_base(), false).unwrap_or_default() {
                            continue;
                        }

                        if !&mr.blob_entry.with_v5_extended_blob_table() {
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
                                    .set_ready(c.as_base())
                                    .map_err(|e| error!("Failed to set chunk ready: {:?}", e));
                            }
                        } else {
                            issue_batch = true;
                        }
                    }

                    if !issue_batch {
                        for c in continuous_chunks {
                            chunk_map.notify_ready(c.as_base());
                        }
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
                                if !chunk_map.is_ready_nowait(c.as_base()).unwrap_or_default() {
                                    // Write multiple chunks once
                                    match BlobCache::persist_chunk(
                                        blobcache.is_compressed,
                                        fd,
                                        c.as_ref(),
                                        chunks[i].as_slice(),
                                    ) {
                                        Err(e) => {
                                            error!("Failed to cache chunk: {}", e);
                                            chunk_map.notify_ready(c.as_base())
                                        }
                                        Ok(_) => {
                                            chunk_map.set_ready(c.as_base()).unwrap_or_else(|e| {
                                                error!("Failed to set chunk ready: {:?}", e)
                                            })
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        // Before issue a merged backend request, we already mark
                        // them as `OnTrip` inflight.
                        for c in continuous_chunks.iter().map(|i| i.as_ref()) {
                            chunk_map.notify_ready(c.as_base());
                        }
                    }
                }
}
*/

/*
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

    limiter,
    mr_sender: Arc::new(Mutex::new(tx)),
    mr_receiver: rx,
    runtime: Arc::new(Runtime::new().unwrap()),
*/

/*
if enabled {
    kick_prefetch_workers(cache.clone());
}
 */
