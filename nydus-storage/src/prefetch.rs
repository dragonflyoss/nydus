//! Post-mount blob prefetch: warms the local caches with the priority blobs
//! declared in the image (and optionally every remaining blob) so on-demand
//! reads hit the cache instead of the backend.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tracing::{info, warn};

use nydus_backend::ReadKind;
use nydus_config::PrefetchScope;
use nydus_telemetry::metrics::{
    collect_prefetch_task_failure_metrics, collect_prefetch_task_started_metrics,
};

use crate::cache::BlobCaches;

/// Drives blob-level prefetch after a nydus filesystem is mounted.
///
/// Workflow:
/// 1. Resolve [`PrefetchScope::Auto`] from the priority blobs' metadata:
///    [`PrefetchScope::Ondemand`] when one of them is an "ondemand" (REDIRECT)
///    blob, otherwise [`PrefetchScope::All`].
/// 2. Prefetch the blobs declared in the root `trusted.nydus.prefetch.blobs`
///    xattr sequentially (single thread): the ondemand blobs first; under
///    `ondemand` nothing else, under `all` the other priority blobs follow in
///    declared order.
/// 3. When the scope is [`PrefetchScope::All`], prefetch the remaining blobs
///    concurrently with a worker pool; otherwise only open every blob's cache
///    (blob meta, sparse files) in the background, alongside step 2, so the
///    backend bandwidth stays focused on the access-ordered hot set (e.g. an
///    optimized image's "ondemand" blob) while no later read pays the
///    metadata round trips.
///
/// A blob whose prefetch fails is logged and skipped; the backend itself
/// retries a read it could not serve once, hours later.
pub struct BlobPrefetcher {
    caches: Arc<BlobCaches>,
    priority: Vec<u16>,
    rest: Vec<u16>,
    threads: usize,
    scope: PrefetchScope,
    /// Per-blob prefetch timeout; `0s` disables the bound.
    timeout: Duration,
    /// Cooperative stop flag: once raised, no new prefetch work is started.
    stop: Arc<AtomicBool>,
}

/// The blob prefetch order: `priority` blobs stream first, sequentially and
/// in declared order; `rest` follows through the worker pool when the scope
/// is [`PrefetchScope::All`].
pub struct PrefetchPlan {
    /// Blob indexes to warm first, in declared order.
    pub priority: Vec<u16>,
    /// The remaining blob indexes, in ascending order.
    pub rest: Vec<u16>,
}

impl BlobPrefetcher {
    /// `plan` is typically the result of `ErofsReader::prefetch_plan`, and
    /// `blobs` the matching cache set (`ErofsReader::blob_caches`).
    pub fn new(
        caches: Arc<BlobCaches>,
        plan: PrefetchPlan,
        threads: usize,
        scope: PrefetchScope,
        timeout: Duration,
    ) -> Self {
        Self {
            caches,
            priority: plan.priority,
            rest: plan.rest,
            threads: threads.max(1),
            scope,
            timeout,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A handle to this prefetcher's stop flag. Storing `true` makes the
    /// prefetcher stop starting new work, so a detached prefetch thread can
    /// be wound down on unmount.
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Open every blob's cache on a small worker pool, priority blobs first,
    /// so the blob meta round trips overlap each other and the priority
    /// prefetch instead of being paid one blob at a time — by the phase 1
    /// `is_redirect` checks (an optimized image lists every blob in its
    /// prefetch xattr) or by the first reads. Returns the workers' handles.
    fn spawn_blob_openers(&self) -> Vec<JoinHandle<()>> {
        // Popped from the back, so reverse to hand out the priority blobs first.
        let mut queue: Vec<u16> = self.priority.iter().chain(&self.rest).copied().collect();
        queue.reverse();
        let worker_count = self.threads.min(queue.len());
        let queue = Arc::new(Mutex::new(queue));
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let blobs = self.caches.clone();
            let queue = queue.clone();
            let stop = self.stop.clone();
            let handle = thread::Builder::new()
                .name("nydus_blob_open".to_string())
                .spawn(move || loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let blob_index = queue.lock().unwrap().pop();
                    match blob_index {
                        Some(blob_index) => {
                            if let Err(err) = blobs.cache(blob_index, ReadKind::Prefetch) {
                                warn!("failed to open blob {} cache: {}", blob_index, err);
                            }
                        }
                        None => break,
                    }
                });
            match handle {
                Ok(handle) => handles.push(handle),
                Err(err) => warn!("failed to spawn blob open worker: {}", err),
            }
        }
        handles
    }

    /// Spawn a background thread that drives the whole prefetch workflow. The
    /// returned handle may be detached by the caller.
    pub fn spawn(self) -> io::Result<JoinHandle<()>> {
        thread::Builder::new()
            .name("nydus_prefetch".to_string())
            .spawn(move || self.run())
    }

    /// Drive the whole prefetch workflow synchronously on the calling thread:
    /// ondemand priority blobs first, then (only when the scope resolves to
    /// [`PrefetchScope::All`]) the other priority blobs in declared order and
    /// the remaining blobs through a worker pool. Per-blob failures are
    /// logged and skipped.
    pub fn run(mut self) {
        if self.scope == PrefetchScope::None {
            return;
        }

        // Under the "ondemand" scope the non-ondemand blobs are not pulled, but
        // every cache is opened in the background (blob meta fetched and
        // validated, sparse files created) so nothing pays those round trips
        // serially later: neither the ondemand checks below nor block-device
        // frontends, which probe many blobs right after the device appears.
        // "auto" needs the same checks to pick its scope, so it starts the
        // openers too. The openers run alongside the priority prefetch and
        // are joined once it is done.
        let openers = if self.scope != PrefetchScope::All {
            self.spawn_blob_openers()
        } else {
            Vec::new()
        };

        // Which priority blobs are ondemand (REDIRECT) blobs: needed to resolve
        // `auto`, to pick the blobs `ondemand` pulls and to order phase 1 under
        // `all`. A blob whose meta cannot be read is treated as a plain blob
        // and logged.
        let ondemand: Vec<bool> = self
            .priority
            .iter()
            .map(|&blob_index| match self.caches.is_redirect(blob_index) {
                Ok(redirect) => redirect,
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

        // Phase 1: priority blobs, sequential. Ondemand blobs go first (they
        // stream the recorded working set into the source blobs' caches, so
        // whole-blob pulls that follow skip the groups already filled); under
        // "ondemand" they are the only blobs pulled, under "all" the other
        // priority blobs follow in declared order.
        let priority_with_flag = || self.priority.iter().copied().zip(ondemand.iter().copied());
        let mut phase1: Vec<u16> = priority_with_flag()
            .filter(|&(_, redirect)| redirect)
            .map(|(index, _)| index)
            .collect();
        if scope == PrefetchScope::All {
            phase1.extend(
                priority_with_flag()
                    .filter(|&(_, redirect)| !redirect)
                    .map(|(index, _)| index),
            );
        }
        for blob_index in phase1 {
            if self.stopped() {
                return;
            }
            collect_prefetch_task_started_metrics();
            match self
                .caches
                .prefetch_blob(blob_index, self.threads, self.timeout)
            {
                Ok(()) => info!("prefetched priority blob {}", blob_index),
                Err(err) => {
                    collect_prefetch_task_failure_metrics();
                    warn!("failed to prefetch priority blob {}: {}", blob_index, err)
                }
            }
        }

        for handle in openers {
            let _ = handle.join();
        }

        // Phase 2: remaining blobs, concurrent worker pool. Skipped unless the
        // scope resolved to "all".
        if scope == PrefetchScope::All && !self.rest.is_empty() {
            let worker_count = self.threads.min(self.rest.len());
            let queue = Arc::new(Mutex::new(std::mem::take(&mut self.rest)));
            let timeout = self.timeout;
            let mut handles = Vec::with_capacity(worker_count);
            for _ in 0..worker_count {
                let blobs = self.caches.clone();
                let queue = queue.clone();
                let stop = self.stop.clone();
                let handle = thread::Builder::new()
                    .name("nydus_prefetch_worker".to_string())
                    .spawn(move || loop {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        let blob_index = {
                            let mut guard = queue.lock().unwrap();
                            guard.pop()
                        };
                        let Some(blob_index) = blob_index else {
                            break;
                        };
                        collect_prefetch_task_started_metrics();
                        match blobs.prefetch_blob(blob_index, 1, timeout) {
                            Ok(()) => info!("prefetched blob {}", blob_index),
                            Err(err) => {
                                collect_prefetch_task_failure_metrics();
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
                let _ = handle.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::atomic::AtomicUsize;

    use nydus_backend::{Backend, Local};
    use nydus_format::blob::BlobMetadata;
    use nydus_format::utils::SHA256_DIGEST_SIZE;
    use nydus_test_utils::blob::FullBlob;
    use nydus_test_utils::metadata::{single_chunk_group, single_chunk_group_redirect};
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
                inner: Local::new(dir.to_path_buf()),
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
        fn kind(&self) -> nydus_backend::BackendKind {
            self.inner.kind()
        }

        fn protocol(&self) -> Option<nydus_backend::Protocol> {
            self.inner.protocol()
        }

        fn read_blob_metadata(
            &self,
            blob_id: &[u8; SHA256_DIGEST_SIZE],
            kind: ReadKind,
        ) -> io::Result<BlobMetadata> {
            self.inner.read_blob_metadata(blob_id, kind)
        }

        fn read_range_into(
            &self,
            blob_id: &[u8; SHA256_DIGEST_SIZE],
            offset: u64,
            dst: &mut [u8],
            kind: ReadKind,
        ) -> io::Result<()> {
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
            if attempt < self.failures {
                return Err((self.error)());
            }
            self.inner.read_range_into(blob_id, offset, dst, kind)
        }
    }

    fn prefetcher_over(
        backend: Arc<FlakyBackend>,
        backend_dir: &Path,
        cache_dir: &Path,
        payload: &[u8],
        meta: &BlobMetadata,
    ) -> BlobPrefetcher {
        let full_blob_id = FullBlob::new(payload)
            .with_blob_metadata(meta)
            .with_blob_metadata_file()
            .save_in(backend_dir);
        let caches = Arc::new(
            BlobCaches::new([(0u16, full_blob_id)], backend, Some(cache_dir), None).unwrap(),
        );
        BlobPrefetcher::new(
            caches,
            PrefetchPlan {
                priority: vec![0],
                rest: Vec::new(),
            },
            1,
            PrefetchScope::All,
            Duration::ZERO,
        )
    }

    fn test_payload() -> (Vec<u8>, BlobMetadata) {
        let payload = vec![0xabu8; 4096];
        let meta = single_chunk_group(&payload);
        (payload, meta)
    }

    #[test]
    fn failed_prefetch_is_skipped_after_one_attempt() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let (payload, meta) = test_payload();
        let backend = FlakyBackend::new(backend_dir.path(), usize::MAX, || {
            io::Error::other("ordinary failure")
        });
        let prefetcher = prefetcher_over(
            backend.clone(),
            backend_dir.path(),
            cache_dir.path(),
            &payload,
            &meta,
        );
        let failures = || {
            nydus_telemetry::metrics::PREFETCH_TASK_FAILURE_COUNT
                .with_label_values(&[])
                .get()
        };
        let failures_before = failures();

        prefetcher.run();

        assert_eq!(backend.attempts(), 1);
        assert!(failures() > failures_before);
    }

    #[test]
    fn raised_stop_flag_skips_the_prefetch() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let (payload, meta) = test_payload();
        let backend = FlakyBackend::new(backend_dir.path(), usize::MAX, || {
            io::Error::other("ordinary failure")
        });
        let prefetcher = prefetcher_over(
            backend.clone(),
            backend_dir.path(),
            cache_dir.path(),
            &payload,
            &meta,
        );
        prefetcher.stop_flag().store(true, Ordering::SeqCst);

        prefetcher.run();

        assert_eq!(backend.attempts(), 0);
    }

    struct RecordingBackend {
        inner: Local,
        reads: Mutex<Vec<[u8; SHA256_DIGEST_SIZE]>>,
    }

    impl Backend for RecordingBackend {
        fn kind(&self) -> nydus_backend::BackendKind {
            self.inner.kind()
        }

        fn protocol(&self) -> Option<nydus_backend::Protocol> {
            self.inner.protocol()
        }

        fn read_blob_metadata(
            &self,
            blob_id: &[u8; SHA256_DIGEST_SIZE],
            kind: ReadKind,
        ) -> io::Result<BlobMetadata> {
            self.inner.read_blob_metadata(blob_id, kind)
        }

        fn read_range_into(
            &self,
            blob_id: &[u8; SHA256_DIGEST_SIZE],
            offset: u64,
            dst: &mut [u8],
            kind: ReadKind,
        ) -> io::Result<()> {
            self.reads.lock().unwrap().push(*blob_id);
            self.inner.read_range_into(blob_id, offset, dst, kind)
        }
    }

    fn plain_and_redirect_blobs(
        backend_dir: &Path,
        cache_dir: &Path,
    ) -> (
        Arc<RecordingBackend>,
        Arc<BlobCaches>,
        [[u8; SHA256_DIGEST_SIZE]; 2],
    ) {
        let (payload, plain_meta) = test_payload();
        let plain_id = FullBlob::new(&payload)
            .with_blob_metadata(&plain_meta)
            .with_blob_metadata_file()
            .save_in(backend_dir);
        let redirect_meta = single_chunk_group_redirect(&payload, 1);
        assert!(redirect_meta.is_redirect());
        let redirect_id = FullBlob::new(&payload)
            .with_blob_metadata(&redirect_meta)
            .with_blob_metadata_file()
            .save_in(backend_dir);
        let backend = Arc::new(RecordingBackend {
            inner: Local::new(backend_dir.to_path_buf()),
            reads: Mutex::new(Vec::new()),
        });
        let caches = Arc::new(
            BlobCaches::new(
                [(1u16, plain_id), (2u16, redirect_id)],
                backend.clone(),
                Some(cache_dir),
                None,
            )
            .unwrap(),
        );
        (backend, caches, [plain_id, redirect_id])
    }

    fn blobs_read(scope: PrefetchScope, plan: PrefetchPlan) -> Vec<u16> {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let (backend, caches, ids) = plain_and_redirect_blobs(backend_dir.path(), cache_dir.path());
        BlobPrefetcher::new(caches, plan, 2, scope, Duration::ZERO).run();
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
