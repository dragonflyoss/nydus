//! Post-mount blob prefetch: warms the local caches with the priority blobs
//! declared in the image (and optionally every remaining blob) so on-demand
//! reads hit the cache instead of the backend.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tracing::{info, warn};

use nydus_config::PrefetchScope;
use nydus_telemetry::metrics::{
    collect_prefetch_task_failure_metrics, collect_prefetch_task_started_metrics,
};

/// The blob store a prefetch fills: one cache per blob of the image, kept by
/// the storage layer, which streams a blob's chunk groups from the backend.
pub trait Store: Send + Sync {
    /// Opens the cache of blob `blob_index`: its blob metadata fetched and
    /// validated, its sparse file created, no data prefetched.
    fn open(&self, blob_index: u16) -> io::Result<()>;

    /// Returns whether blob `blob_index` is an "ondemand" (REDIRECT) blob,
    /// opening its cache.
    fn is_redirect(&self, blob_index: u16) -> io::Result<bool>;

    /// Prefetches every chunk group of blob `blob_index` with up to `workers`
    /// concurrent batch fetches, a non-zero `timeout` bounding the whole
    /// blob.
    fn prefetch_blob(&self, blob_index: u16, workers: usize, timeout: Duration) -> io::Result<()>;
}

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
    store: Arc<dyn Store>,
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
    /// `store` the matching cache set (`ErofsReader::blob_caches`).
    pub fn new(
        store: Arc<dyn Store>,
        plan: PrefetchPlan,
        threads: usize,
        scope: PrefetchScope,
        timeout: Duration,
    ) -> Self {
        Self {
            store,
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
            let store = self.store.clone();
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
                            if let Err(err) = store.open(blob_index) {
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
            .map(|&blob_index| match self.store.is_redirect(blob_index) {
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
                .store
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
                let store = self.store.clone();
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
                        match store.prefetch_blob(blob_index, 1, timeout) {
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

    use std::sync::atomic::AtomicUsize;

    struct ScriptedStore {
        redirects: Vec<u16>,
        fail: bool,
        attempts: AtomicUsize,
        prefetched: Mutex<Vec<u16>>,
    }

    impl ScriptedStore {
        fn new(redirects: &[u16], fail: bool) -> Arc<Self> {
            Arc::new(Self {
                redirects: redirects.to_vec(),
                fail,
                attempts: AtomicUsize::new(0),
                prefetched: Mutex::new(Vec::new()),
            })
        }

        fn attempts(&self) -> usize {
            self.attempts.load(Ordering::SeqCst)
        }

        fn prefetched(&self) -> Vec<u16> {
            self.prefetched.lock().unwrap().clone()
        }
    }

    impl Store for ScriptedStore {
        fn open(&self, _blob_index: u16) -> io::Result<()> {
            Ok(())
        }

        fn is_redirect(&self, blob_index: u16) -> io::Result<bool> {
            Ok(self.redirects.contains(&blob_index))
        }

        fn prefetch_blob(
            &self,
            blob_index: u16,
            _workers: usize,
            _timeout: Duration,
        ) -> io::Result<()> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(io::Error::other("failure"));
            }
            self.prefetched.lock().unwrap().push(blob_index);
            Ok(())
        }
    }

    fn prefetcher(
        store: Arc<ScriptedStore>,
        scope: PrefetchScope,
        plan: PrefetchPlan,
    ) -> BlobPrefetcher {
        BlobPrefetcher::new(store, plan, 1, scope, Duration::ZERO)
    }

    fn single_blob_plan() -> PrefetchPlan {
        PrefetchPlan {
            priority: vec![0],
            rest: Vec::new(),
        }
    }

    #[test]
    fn failed_prefetch_is_skipped_after_one_attempt() {
        let store = ScriptedStore::new(&[], true);
        let failures = || {
            nydus_telemetry::metrics::PREFETCH_TASK_FAILURE_COUNT
                .with_label_values(&[])
                .get()
        };
        let failures_before = failures();

        prefetcher(store.clone(), PrefetchScope::All, single_blob_plan()).run();

        assert_eq!(store.attempts(), 1);
        assert!(store.prefetched().is_empty());
        assert!(failures() > failures_before);
    }

    #[test]
    fn raised_stop_flag_skips_the_prefetch() {
        let store = ScriptedStore::new(&[], false);
        let prefetcher = prefetcher(store.clone(), PrefetchScope::All, single_blob_plan());
        prefetcher.stop_flag().store(true, Ordering::SeqCst);

        prefetcher.run();

        assert_eq!(store.attempts(), 0);
    }

    #[test]
    fn scope_selects_the_blobs_to_pull_and_their_order() {
        let test_cases = vec![
            (PrefetchScope::None, vec![2, 1], vec![], vec![]),
            (PrefetchScope::Ondemand, vec![2, 1], vec![], vec![2]),
            (PrefetchScope::Ondemand, vec![1], vec![2], vec![]),
            (PrefetchScope::All, vec![1, 2], vec![], vec![2, 1]),
            (PrefetchScope::All, vec![1], vec![2, 3], vec![1, 3, 2]),
            (PrefetchScope::Auto, vec![2, 1], vec![], vec![2]),
            (PrefetchScope::Auto, vec![1], vec![], vec![1]),
        ];

        for (scope, priority, rest, expected) in test_cases {
            let store = ScriptedStore::new(&[2], false);
            let plan = PrefetchPlan {
                priority: priority.clone(),
                rest: rest.clone(),
            };
            prefetcher(store.clone(), scope, plan).run();

            assert_eq!(
                store.prefetched(),
                expected,
                "scope={scope:?} priority={priority:?} rest={rest:?}"
            );
        }
    }
}
