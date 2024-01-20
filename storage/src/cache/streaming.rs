use crate::cache::BlobCache;
use crate::device::BlobRange;
use indexmap::IndexMap;
use nydus_utils::async_helper::with_runtime;
use nydus_utils::mpmc::Channel;
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

struct PrefetchBuffer {
    // 用于计算预取任务的
    // 最后更新的任务（大概率是最新的任务）的start_offset
    last_modified: u64,
    // 正在等待用于计算的任务队列
    buf: IndexMap<u64, BlobRange>,
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
                buf: IndexMap::new(),
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

    // 要求append是合法的，这里不检查合法性
    fn extend_range(
        &self,
        start_processed: u64,
        r_new: BlobRange,
        waiting: &mut PrefetchBuffer,
    ) -> Result<()> {
        let r = waiting.buf.get_mut(&start_processed).unwrap();
        let r_new_size = r_new.end - r_new.offset;
        // TODO:判断数据债是否超过阈值
        // 全局已处理的数据量-任务发起前全局已处理的数据量 > 任务目前的长度 + MAX_DEPT
        // 而且，任务不能太小
        if waiting.total_processed - start_processed > r.end - r.offset + MAX_DEBT
            && r.end - r.offset < MIN_SUBMITTALBE_TASK_SIZE
        {
            // 数据债是否超过阈值，所以要提交该任务
            if let Some(r) = waiting.buf.remove(&start_processed) {
                // 将该任务弹出并加入到任务队列
                self.send_msg(r, &waiting.blobs)?;
                // 将新任务添加到末尾
                waiting.buf.insert(waiting.total_processed, r_new);
                waiting.last_modified = waiting.total_processed;
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "append_range: waiting_queue remove failed",
                ));
            }
        } else {
            // 数据债未超阈值，
            r.end = r_new.end;
        }

        // 为两种情况均更新current_offset
        waiting.total_processed += r_new_size;
        Ok(())
    }

    pub fn add_prefetch_range(&self, r_new: BlobRange) -> Result<()> {
        let mut waiting = self.waiting.lock().unwrap();

        // 这里处理了self.last_modified初始值问题，if==false
        if let Some(r_recent) = waiting.buf.get(&waiting.last_modified) {
            // TODO:完善这里对于is_countinous的判断
            if r_recent.blob_idx == r_new.blob_idx && r_recent.end == r_new.offset {
                self.extend_range(waiting.last_modified, r_new, &mut waiting)?;
                return Ok(());
            }
        }
        //针对非连续的任务，需要判断任务列表了
        //1. 尝试extend到现有任务中
        for (start_offset, r) in waiting.buf.iter() {
            if r.blob_idx == r_new.blob_idx && r.end == r_new.offset {
                self.extend_range(*start_offset, r_new, &mut waiting)?;
                return Ok(());
            }
        }
        // 2.append为新任务
        let r_new_size = r_new.end - r_new.offset;
        let p = waiting.total_processed;
        waiting.buf.insert(p, r_new);
        waiting.last_modified = waiting.total_processed;
        waiting.total_processed += r_new_size;
        Ok(())
    }

    #[inline]
    fn send_msg(&self, r: BlobRange, blobs: &[Arc<dyn BlobCache>]) -> Result<()> {
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

    pub fn flush_waiting_queue(&self) -> Result<()> {
        let mut waiting = self.waiting.lock().unwrap();
        let mut buf = std::mem::take(&mut waiting.buf);

        for (_, r) in buf.drain(..) {
            self.send_msg(r, &waiting.blobs)?;
        }

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
