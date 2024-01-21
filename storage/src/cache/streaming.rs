use crate::cache::BlobCache;
use crate::device::BlobRange;
use nydus_utils::async_helper::with_runtime;
use nydus_utils::mpmc::Channel;
use std::collections::BTreeMap;
use std::io::Result;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use tokio::runtime::Runtime;

use super::worker::AsyncPrefetchConfig;

/// Asynchronous service request message.
pub enum StreamingPrefetchMessage {
    /// Asynchronous blob layer prefetch request with (offset, size) of blob on storage backend.
    BlobPrefetch(Arc<dyn BlobCache>, u64, u64),
}

impl StreamingPrefetchMessage {
    /// Create a new asynchronous blob prefetch request message.
    pub fn new_blob_prefetch(blob_cache: Arc<dyn BlobCache>, offset: u64, size: u64) -> Self {
        StreamingPrefetchMessage::BlobPrefetch(blob_cache, offset, size)
    }
}

// 最大负债4MB
static MAX_DEBT: u64 = 0x400000;
// 小任务判断标准：<1MB
#[allow(unused)]
static MIN_TASK_SIZE: u64 = 0x100000;

// 最小任务阈值: 512KB
static MIN_SUBMITTALBE_TASK_SIZE: u64 = 0x80000;

// 最大合并阈值：512KB
// 两个不连续的任务，如果中间间隔小于MAX_MERGE_GAP，那么可以合并
static MAX_MERGE_GAP: u64 = 0x80000;

struct PrefetchBuffer {
    // 用于计算预取任务的
    // 最后更新的任务（大概率是最新的任务）的end_offset
    // 允许指向0或者已经被remove的任务
    last_modified: u64,
    // 正在等待用于计算的任务队列
    buf: BTreeMap<u64, BlobRange>,
    // 目前为止总共计算了多少预取数据
    total_processed: u64,
    blobs: Vec<Arc<dyn BlobCache>>,
}
pub(crate) struct StreamPrefetchMgr {
    workers: AtomicU32,
    threads_count: u32,
    active: AtomicBool,
    waiting: Mutex<PrefetchBuffer>,
    // 保存任务的队列
    new_channel: Arc<Channel<StreamingPrefetchMessage>>,
    // 保存小任务的队列
    new_channel_small: Arc<Channel<StreamingPrefetchMessage>>,
}

impl StreamPrefetchMgr {
    pub fn new(prefetch_config: Arc<AsyncPrefetchConfig>) -> Self {
        Self {
            threads_count: prefetch_config.threads_count as u32,
            workers: AtomicU32::new(0),
            active: AtomicBool::new(false),
            waiting: Mutex::new(PrefetchBuffer {
                last_modified: 0,
                buf: BTreeMap::new(),
                total_processed: 0,
                blobs: Vec::new(),
            }),
            new_channel: Arc::new(Channel::new()),
            new_channel_small: Arc::new(Channel::new()),
        }
    }

    /// Create working threads and start the event loop.
    pub fn start(mgr: Arc<Self>) -> Result<()> {
        Self::start_prefetch_workers(mgr)?;

        Ok(())
    }

    pub fn init_blobs(&self, blobs: Vec<Arc<dyn BlobCache>>) {
        let mut waiting = self.waiting.lock().unwrap();
        waiting.blobs = blobs;
    }

    // 尝试将需要提交的range提交
    fn submit_ranges(&self, waiting: &mut PrefetchBuffer) -> Result<()> {
        // 从后往前遍历，找到第一个不超过阈值的任务
        let mut not_exceeded_offset = u64::MAX;
        for end_offset in waiting.buf.keys() {
            if waiting.total_processed - end_offset < MAX_DEBT {
                not_exceeded_offset = *end_offset;
                break;
            }
        }

        // 弹出需要被提交的任务
        let to_keep = waiting.buf.split_off(&not_exceeded_offset);
        let to_submit = std::mem::take(&mut waiting.buf);
        waiting.buf = to_keep;

        // 提交任务
        for (end_offset, r) in to_submit {
            // 将太小的任务放回
            if r.end - r.offset < MIN_SUBMITTALBE_TASK_SIZE {
                waiting.buf.insert(end_offset, r);
            } else {
                self.send_msg(&r, &waiting.blobs)?;
            }
        }
        Ok(())
    }

    pub fn add_prefetch_range(&self, r_new: BlobRange) -> Result<()> {
        let mut waiting = self.waiting.lock().unwrap();

        //1. 尝试merge到现有任务中
        // 先判断last_modified，允许last_modified指向不存在的key
        let mut merged = false;

        let last_modified = waiting.buf.get_key_value(&waiting.last_modified);
        for (end_offset, r_old) in last_modified.into_iter().chain(waiting.buf.iter()) {
            if let Some((added_size, r_merged)) = r_old.try_merge(&r_new, MAX_MERGE_GAP) {
                merged = true;

                // remove old and add merged
                let end_offset = *end_offset;
                waiting.buf.remove(&end_offset);
                // 在原先的end_processed基础上增加
                let new_end_offset = end_offset + added_size;
                waiting.buf.insert(new_end_offset, r_merged);
                waiting.last_modified = new_end_offset;
                waiting.total_processed += added_size;

                break;
            }
        }

        // 3. 检查旧任务是否需要提交
        self.submit_ranges(&mut waiting)?;

        // 2.append为新任务
        if !merged {
            let r_new_size = r_new.end - r_new.offset;
            waiting.total_processed += r_new_size;
            waiting.last_modified = waiting.total_processed;

            let p = waiting.total_processed;
            waiting.buf.insert(p, r_new);
        }

        Ok(())
    }

    #[inline]
    fn send_msg(&self, r: &BlobRange, blobs: &[Arc<dyn BlobCache>]) -> Result<()> {
        let msg = StreamingPrefetchMessage::new_blob_prefetch(
            blobs[r.blob_idx as usize].clone(),
            r.offset,
            r.end - r.offset,
        );
        let channel = if r.end - r.offset < MIN_TASK_SIZE {
            &self.new_channel_small
        } else {
            &self.new_channel
        };
        debug!(
            "CMDebug: send_msg, offset: {}, size: {}",
            r.offset,
            r.end - r.offset
        );
        channel.send(msg).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "Send prefetch message failed")
        })
    }

    // 清空等待队列，提交全部任务
    pub fn flush_waiting_queue(&self) -> Result<()> {
        let mut waiting = self.waiting.lock().unwrap();
        let mut buf = std::mem::take(&mut waiting.buf);

        for r in buf.values() {
            self.send_msg(r, &waiting.blobs)?;
        }
        buf.clear();

        Ok(())
    }

    fn start_prefetch_workers(mgr: Arc<Self>) -> Result<()> {
        for num in 0..mgr.threads_count + 1 {
            let mgr2 = mgr.clone();
            let res = thread::Builder::new()
                .name(format!("nydus_storage_worker_{}", num))
                .spawn(move || {
                    mgr2.grow_n(1);
                    debug!("CMDebug: start_prefetch_workers, {}", num);

                    with_runtime(|rt| {
                        if num == 0 {
                            rt.block_on(Self::handle_prefetch_requests_small(mgr2.clone(), rt));
                        } else {
                            rt.block_on(Self::handle_prefetch_requests(mgr2.clone(), rt));
                        }
                    });

                    mgr2.shrink_n(1);
                    info!("storage: worker thread {} exits.", num)
                });

            if let Err(e) = res {
                error!("storage: failed to create worker thread, {:?}", e);
                return Err(e);
            }
        }
        mgr.active.store(true, Ordering::Release);
        Ok(())
    }

    async fn handle_prefetch_requests(mgr: Arc<Self>, rt: &Runtime) {
        loop {
            let msg;
            tokio::select! {
                Ok(m) = mgr.new_channel.recv() => msg = m,
                Ok(m) = mgr.new_channel_small.recv() => msg = m,
                else => break,
            }
            match msg {
                StreamingPrefetchMessage::BlobPrefetch(blob_cache, offset, size) => {
                    rt.spawn_blocking(move || {
                        let _ = Self::handle_blob_prefetch_request(blob_cache, offset, size);
                    });
                }
            }
        }
    }

    // 专门处理小blob
    async fn handle_prefetch_requests_small(mgr: Arc<Self>, rt: &Runtime) {
        while let Ok(msg) = mgr.new_channel_small.recv().await {
            match msg {
                StreamingPrefetchMessage::BlobPrefetch(blob_cache, offset, size) => {
                    rt.spawn_blocking(move || {
                        let _ = Self::handle_blob_prefetch_request(blob_cache, offset, size);
                    });
                }
            }
        }
    }

    fn handle_blob_prefetch_request(
        cache: Arc<dyn BlobCache>,
        offset: u64,
        size: u64,
    ) -> Result<()> {
        debug!(
            "CMDebug: storage: prefetch blob {} offset {} size {}",
            cache.blob_id(),
            offset,
            size
        );
        if size == 0 {
            return Ok(());
        }

        cache.fetch_range_compressed_stream(offset, size, true)?;

        Ok(())
    }

    fn shrink_n(&self, n: u32) {
        self.workers.fetch_sub(n, Ordering::Relaxed);
    }
    fn grow_n(&self, n: u32) {
        self.workers.fetch_add(n, Ordering::Relaxed);
    }
}
