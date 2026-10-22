//! The blob-level prefetch after a mount: warms the local caches with the
//! priority blobs the image declares, and optionally every remaining blob,
//! so on-demand reads hit the cache instead of the backend.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tracing::{info, warn};

use nydus_config::{PrefetchConfig, PrefetchScope};

use crate::cache::BlobCaches;

/// The blob prefetch order: the `priority` blobs stream first, sequentially
/// and in declared order; the `rest` follow through the worker pool when
/// the scope is [`PrefetchScope::All`].
pub struct PrefetchPlan {
    /// The blob indexes to warm first, in declared order.
    pub priority: Vec<u16>,

    /// The remaining blob indexes, in ascending order.
    pub rest: Vec<u16>,
}

/// The driver of the blob-level prefetch after a nydus filesystem is
/// mounted.
///
/// ```text
/// run()
///   1. resolve scope `auto` from the priority blobs' metadata: `ondemand`
///      when one of them is an ondemand (redirect) blob, otherwise `all`
///   2. prefetch the priority blobs sequentially, the ondemand blobs first:
///      under `ondemand` nothing else, under `all` the other priority blobs
///      follow in declared order
///   3. under `all`, prefetch the remaining blobs through a worker pool;
///      otherwise only open every blob's cache in the background, alongside
///      step 2, so the backend bandwidth stays on the access-ordered hot set
///      while no later read pays the blob meta round trips
/// ```
///
/// A blob whose prefetch fails is logged and skipped; the backend itself
/// sends a prefetch read it could not serve once more, hours later.
pub struct BlobPrefetcher {
    /// The blob caches of the image.
    caches: Arc<BlobCaches>,

    /// The blob indexes to warm first, in declared order.
    priority: Vec<u16>,

    /// The remaining blob indexes, in ascending order.
    rest: Vec<u16>,

    /// The worker count: the blobs prefetched concurrently, and the batches
    /// of one priority blob fetched concurrently.
    workers: usize,

    /// The scope of the prefetch, `auto` resolved when it runs.
    scope: PrefetchScope,

    /// The timeout of prefetching one blob, zero for no bound.
    timeout: Duration,

    /// The cooperative stop flag: once raised, no new prefetch work starts.
    stop: Arc<AtomicBool>,
}

/// Implements the blob prefetcher.
impl BlobPrefetcher {
    /// Creates the prefetcher of `caches` following `plan`, with the
    /// concurrency, scope and timeout of the `prefetch` configuration
    /// section.
    pub fn new(caches: Arc<BlobCaches>, plan: PrefetchPlan, prefetch: &PrefetchConfig) -> Self {
        Self {
            caches,
            priority: plan.priority,
            rest: plan.rest,
            workers: prefetch.concurrent_blob_count.max(1),
            scope: prefetch.scope,
            timeout: prefetch.request_timeout,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Returns the stop flag. Storing `true` makes the prefetcher start no
    /// new work, so a detached prefetch thread winds down on unmount.
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }

    /// Returns whether the stop flag is raised.
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Spawns a background thread driving the whole prefetch workflow, whose
    /// handle the caller may detach.
    pub fn spawn(self) -> io::Result<JoinHandle<()>> {
        thread::Builder::new()
            .name("nydus_prefetch".to_string())
            .spawn(move || self.run())
    }

    /// Drives the whole prefetch workflow on the calling thread: the
    /// ondemand priority blobs first, then, only when the scope resolves to
    /// [`PrefetchScope::All`], the other priority blobs in declared order
    /// and the remaining blobs through a worker pool. Per-blob failures are
    /// logged and skipped.
    pub fn run(self) {
        if self.scope == PrefetchScope::None {
            return;
        }

        // Under `ondemand` the other blobs are not pulled, but every cache
        // is opened in the background, blob meta fetched and sparse files
        // created, so nothing pays those round trips serially later: neither
        // the ondemand checks below nor the block-device frontends, which
        // probe many blobs right after the device appears. `auto` needs the
        // same checks to pick its scope, so it starts the openers too. They
        // run alongside the priority prefetch and are joined once it is done.
        let openers = if self.scope != PrefetchScope::All {
            self.spawn_blob_openers()
        } else {
            Vec::new()
        };

        // Which priority blobs are ondemand blobs: needed to resolve `auto`,
        // to pick the blobs `ondemand` pulls and to order the priority blobs
        // under `all`. A blob whose meta cannot be read is treated as a
        // plain blob and logged.
        let ondemand: Vec<bool> = self
            .priority
            .iter()
            .map(|&blob_index| match self.caches.is_ondemand(blob_index) {
                Ok(ondemand) => ondemand,
                Err(err) => {
                    warn!("failed to inspect priority blob {}: {}", blob_index, err);
                    false
                }
            })
            .collect();
        let scope = match self.scope {
            PrefetchScope::Auto => {
                let resolved = if ondemand.contains(&true) {
                    PrefetchScope::Ondemand
                } else {
                    PrefetchScope::All
                };
                info!("prefetch scope auto resolved to {:?}", resolved);
                resolved
            }
            scope => scope,
        };
        if self.stopped() {
            return;
        }

        // The priority blobs, sequentially. The ondemand blobs go first, they
        // stream the recorded working set into the source blobs' caches so
        // the whole-blob pulls that follow skip the chunk groups already
        // filled; under `ondemand` they are the only blobs pulled, under
        // `all` the other priority blobs follow in declared order.
        let priority_with_flag = || self.priority.iter().copied().zip(ondemand.iter().copied());
        let mut priority: Vec<u16> = priority_with_flag()
            .filter(|&(_, ondemand)| ondemand)
            .map(|(index, _)| index)
            .collect();
        if scope == PrefetchScope::All {
            priority.extend(
                priority_with_flag()
                    .filter(|&(_, ondemand)| !ondemand)
                    .map(|(index, _)| index),
            );
        }
        for blob_index in priority {
            if self.stopped() {
                return;
            }

            let metrics = &self.caches.metrics().storage;
            match self
                .caches
                .prefetch_blob(blob_index, self.workers, self.timeout)
            {
                Ok(()) => {
                    metrics.collect_prefetch_task_finished_metrics();
                    info!("prefetched priority blob {}", blob_index)
                }
                Err(err) => {
                    metrics.collect_prefetch_task_failure_metrics();
                    warn!("failed to prefetch priority blob {}: {}", blob_index, err)
                }
            }
        }

        for handle in openers {
            if handle.join().is_err() {
                warn!("blob open worker panicked");
            }
        }

        // The remaining blobs, through the worker pool, under `all` alone.
        if scope != PrefetchScope::All || self.rest.is_empty() {
            return;
        }

        let worker_count = self.workers.min(self.rest.len());
        let queue = Arc::new(Mutex::new(self.rest));
        let timeout = self.timeout;
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let caches = self.caches.clone();
            let queue = queue.clone();
            let stop = self.stop.clone();
            let handle = thread::Builder::new()
                .name("nydus_prefetch_worker".to_string())
                .spawn(move || loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }

                    let Some(blob_index) = queue.lock().unwrap().pop() else {
                        break;
                    };
                    let metrics = &caches.metrics().storage;
                    match caches.prefetch_blob(blob_index, 1, timeout) {
                        Ok(()) => {
                            metrics.collect_prefetch_task_finished_metrics();
                            info!("prefetched blob {}", blob_index)
                        }
                        Err(err) => {
                            metrics.collect_prefetch_task_failure_metrics();
                            warn!("failed to prefetch blob {}: {}", blob_index, err)
                        }
                    }
                });
            match handle {
                Ok(handle) => handles.push(handle),
                Err(err) => warn!("failed to spawn prefetch worker: {}", err),
            }
        }

        for handle in handles {
            if handle.join().is_err() {
                warn!("prefetch worker panicked");
            }
        }
    }

    /// Opens every blob's cache on a small worker pool, the priority blobs
    /// first, so the blob meta round trips overlap each other and the
    /// priority prefetch instead of being paid one blob at a time by the
    /// ondemand checks, an optimized image lists every blob in its prefetch
    /// xattr, or by the first reads. Returns the workers' handles.
    fn spawn_blob_openers(&self) -> Vec<JoinHandle<()>> {
        // Popped from the back, so reversed to hand out the priority blobs
        // first.
        let mut queue: Vec<u16> = self.priority.iter().chain(&self.rest).copied().collect();
        queue.reverse();
        let worker_count = self.workers.min(queue.len());
        let queue = Arc::new(Mutex::new(queue));
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let caches = self.caches.clone();
            let queue = queue.clone();
            let stop = self.stop.clone();
            let handle = thread::Builder::new()
                .name("nydus_blob_open".to_string())
                .spawn(move || loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }

                    let Some(blob_index) = queue.lock().unwrap().pop() else {
                        break;
                    };
                    if let Err(err) = caches.prefetch_cache(blob_index) {
                        warn!("failed to open blob {} cache: {}", blob_index, err);
                    }
                });
            match handle {
                Ok(handle) => handles.push(handle),
                Err(err) => warn!("failed to spawn blob open worker: {}", err),
            }
        }

        handles
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_backend::{Backend, Local};
    use nydus_config::StorageConfig;
    use nydus_format::blob::BlobMetadata;
    use nydus_format::utils::SHA256_DIGEST_SIZE;
    use nydus_telemetry::metrics::Metrics;
    use nydus_test_utils::blob::FullBlob;
    use nydus_test_utils::metadata::{single_chunk_group, single_chunk_group_ondemand};
    use std::path::Path;
    use std::sync::atomic::AtomicUsize;
    use tempfile::tempdir;

    struct FlakyBackend {
        inner: Local,
        failures: usize,
        error: fn() -> io::Error,
        attempts: AtomicUsize,
    }

    impl FlakyBackend {
        fn new(dir: &Path, failures: usize, error: fn() -> io::Error) -> Arc<Self> {
            Arc::new(Self {
                inner: Local::new(dir.to_path_buf(), Arc::new(Metrics::new())),
                failures,
                error,
                attempts: AtomicUsize::new(0),
            })
        }

        fn attempts(&self) -> usize {
            self.attempts.load(Ordering::SeqCst)
        }
    }

    impl Backend for FlakyBackend {
        fn metrics(&self) -> &Arc<Metrics> {
            self.inner.metrics()
        }

        fn read_blob_metadata(
            &self,
            blob_id: &[u8; SHA256_DIGEST_SIZE],
        ) -> io::Result<BlobMetadata> {
            self.inner.read_blob_metadata(blob_id)
        }

        fn read_range_into(
            &self,
            blob_id: &[u8; SHA256_DIGEST_SIZE],
            offset: u64,
            buf: &mut [u8],
        ) -> io::Result<()> {
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
            if attempt < self.failures {
                return Err((self.error)());
            }
            self.inner.read_range_into(blob_id, offset, buf)
        }
    }

    struct RecordingBackend {
        inner: Local,
        reads: Mutex<Vec<[u8; SHA256_DIGEST_SIZE]>>,
    }

    impl Backend for RecordingBackend {
        fn metrics(&self) -> &Arc<Metrics> {
            self.inner.metrics()
        }

        fn read_blob_metadata(
            &self,
            blob_id: &[u8; SHA256_DIGEST_SIZE],
        ) -> io::Result<BlobMetadata> {
            self.inner.read_blob_metadata(blob_id)
        }

        fn read_range_into(
            &self,
            blob_id: &[u8; SHA256_DIGEST_SIZE],
            offset: u64,
            buf: &mut [u8],
        ) -> io::Result<()> {
            self.reads.lock().unwrap().push(*blob_id);
            self.inner.read_range_into(blob_id, offset, buf)
        }
    }

    fn prefetch_config(scope: PrefetchScope, concurrent_blob_count: usize) -> PrefetchConfig {
        PrefetchConfig {
            concurrent_blob_count,
            request_timeout: Duration::ZERO,
            scope,
            ..PrefetchConfig::default()
        }
    }

    fn test_payload() -> (Vec<u8>, BlobMetadata) {
        let payload = vec![0xabu8; 4096];
        let blob_metadata = single_chunk_group(&payload);
        (payload, blob_metadata)
    }

    fn prefetcher_over(
        backend: Arc<FlakyBackend>,
        backend_dir: &Path,
        cache_dir: &Path,
        payload: &[u8],
        blob_metadata: &BlobMetadata,
    ) -> BlobPrefetcher {
        let full_blob_id = FullBlob::new(payload)
            .with_blob_metadata(blob_metadata)
            .with_blob_metadata_file()
            .save_in(backend_dir);
        let caches = Arc::new(
            BlobCaches::new(
                [(0u16, full_blob_id)],
                backend,
                &StorageConfig {
                    dir: Some(cache_dir.to_path_buf()),
                    ..StorageConfig::default()
                },
                None,
            )
            .unwrap(),
        );
        BlobPrefetcher::new(
            caches,
            PrefetchPlan {
                priority: vec![0],
                rest: Vec::new(),
            },
            &prefetch_config(PrefetchScope::All, 1),
        )
    }

    fn plain_and_ondemand_blobs(
        backend_dir: &Path,
        cache_dir: &Path,
    ) -> (
        Arc<RecordingBackend>,
        Arc<BlobCaches>,
        [[u8; SHA256_DIGEST_SIZE]; 2],
    ) {
        let (payload, plain_blob_metadata) = test_payload();
        let plain_id = FullBlob::new(&payload)
            .with_blob_metadata(&plain_blob_metadata)
            .with_blob_metadata_file()
            .save_in(backend_dir);
        let ondemand_blob_metadata = single_chunk_group_ondemand(&payload, 1);
        assert!(ondemand_blob_metadata.is_ondemand());
        let ondemand_id = FullBlob::new(&payload)
            .with_blob_metadata(&ondemand_blob_metadata)
            .with_blob_metadata_file()
            .save_in(backend_dir);
        let backend = Arc::new(RecordingBackend {
            inner: Local::new(backend_dir.to_path_buf(), Arc::new(Metrics::new())),
            reads: Mutex::new(Vec::new()),
        });
        let caches = Arc::new(
            BlobCaches::new(
                [(1u16, plain_id), (2u16, ondemand_id)],
                backend.clone(),
                &StorageConfig {
                    dir: Some(cache_dir.to_path_buf()),
                    ..StorageConfig::default()
                },
                None,
            )
            .unwrap(),
        );
        (backend, caches, [plain_id, ondemand_id])
    }

    fn blobs_read(scope: PrefetchScope, plan: PrefetchPlan) -> Vec<u16> {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let (backend, caches, ids) = plain_and_ondemand_blobs(backend_dir.path(), cache_dir.path());
        BlobPrefetcher::new(caches, plan, &prefetch_config(scope, 2)).run();
        let mut order = Vec::new();
        for read in backend.reads.lock().unwrap().iter() {
            let index = if *read == ids[0] { 1 } else { 2 };
            if !order.contains(&index) {
                order.push(index);
            }
        }
        order
    }

    #[test]
    fn a_failed_prefetch_is_skipped_after_one_attempt() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let (payload, blob_metadata) = test_payload();
        let backend = FlakyBackend::new(backend_dir.path(), usize::MAX, || {
            io::Error::other("ordinary failure")
        });
        let prefetcher = prefetcher_over(
            backend.clone(),
            backend_dir.path(),
            cache_dir.path(),
            &payload,
            &blob_metadata,
        );
        prefetcher.run();

        assert_eq!(backend.attempts(), 1);
        let failures: f64 = backend
            .metrics()
            .registry()
            .gather()
            .iter()
            .filter(|family| family.get_name() == "nydus_storage_prefetch_task_failure_total")
            .flat_map(|family| family.get_metric())
            .map(|metric| metric.get_counter().get_value())
            .sum();
        assert_eq!(failures, 1.0);
    }

    #[test]
    fn a_raised_stop_flag_skips_the_prefetch() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let (payload, blob_metadata) = test_payload();
        let backend = FlakyBackend::new(backend_dir.path(), usize::MAX, || {
            io::Error::other("ordinary failure")
        });
        let prefetcher = prefetcher_over(
            backend.clone(),
            backend_dir.path(),
            cache_dir.path(),
            &payload,
            &blob_metadata,
        );
        prefetcher.stop_flag().store(true, Ordering::SeqCst);

        prefetcher.run();

        assert_eq!(backend.attempts(), 0);
    }

    #[test]
    fn scope_none_pulls_nothing_even_with_an_ondemand_blob() {
        let plan = PrefetchPlan {
            priority: vec![2, 1],
            rest: Vec::new(),
        };
        assert!(blobs_read(PrefetchScope::None, plan).is_empty());
    }

    #[test]
    fn scope_ondemand_streams_only_the_ondemand_blob() {
        let plan = PrefetchPlan {
            priority: vec![2, 1],
            rest: Vec::new(),
        };
        assert_eq!(blobs_read(PrefetchScope::Ondemand, plan), vec![2]);
        let plan = PrefetchPlan {
            priority: vec![1],
            rest: vec![2],
        };
        assert!(blobs_read(PrefetchScope::Ondemand, plan).is_empty());
    }

    #[test]
    fn scope_all_streams_the_ondemand_blob_before_the_others() {
        let plan = PrefetchPlan {
            priority: vec![1, 2],
            rest: Vec::new(),
        };
        let read = blobs_read(PrefetchScope::All, plan);
        assert_eq!(read.first(), Some(&2), "reads: {read:?}");
    }

    #[test]
    fn scope_auto_picks_ondemand_with_an_ondemand_blob_and_all_without() {
        let plan = PrefetchPlan {
            priority: vec![2, 1],
            rest: Vec::new(),
        };
        assert_eq!(blobs_read(PrefetchScope::Auto, plan), vec![2]);
        let plan = PrefetchPlan {
            priority: vec![1],
            rest: Vec::new(),
        };
        assert_eq!(blobs_read(PrefetchScope::Auto, plan), vec![1]);
    }
}
