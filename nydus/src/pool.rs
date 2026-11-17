use nydus_error::{Context, Result};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use tracing::warn;

/// The pre-warmed thread pool that serves fetches.
///
/// `max` worker threads are created once and live for the daemon's lifetime, consuming
/// work from an mpsc channel. `execute` never blocks: when all workers are busy, work
/// queues in memory, bounded by the kernel's outstanding requests.
pub struct FetchPool {
    /// The sending half of the work queue.
    tx: mpsc::Sender<Box<dyn FnOnce() + Send + 'static>>,
}

/// Implements the fetch thread pool.
impl FetchPool {
    /// Creates a pool of `max` worker threads.
    pub fn new(max: usize) -> Result<Self> {
        let (tx, rx) = mpsc::channel::<Box<dyn FnOnce() + Send + 'static>>();
        let rx = Arc::new(Mutex::new(rx));
        for _ in 0..max {
            let rx = rx.clone();
            thread::Builder::new()
                .name("nydus_fetch".to_string())
                .spawn(move || loop {
                    let received = rx.lock().unwrap().recv();
                    let Ok(work) = received else {
                        return;
                    };
                    work();
                })
                .context("failed to spawn fetch worker")?;
        }
        Ok(FetchPool { tx })
    }

    /// Queues `f` for a worker thread without blocking; the channel is unbounded.
    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        if self.tx.send(Box::new(f)).is_err() {
            warn!("fetch pool has no worker thread left; dropping a job");
        }
    }
}
