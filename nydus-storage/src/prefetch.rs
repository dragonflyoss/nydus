//! Post-mount blob prefetch: warms the local caches with the priority blobs
//! declared in the image (and optionally every remaining blob) so on-demand
//! reads hit the cache instead of the backend.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tracing::{info, warn};

use nydus_backend::is_backend_throttled;
use nydus_config::PrefetchScope;
use nydus_telemetry::metrics::{inc_prefetch_reschedule, inc_prefetch_reschedule_run};

use crate::cache::BlobCaches;

/// How often the reschedule wait re-checks the stop flag while sleeping
/// towards the next deadline.
const RESCHEDULE_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Drives blob-level prefetch after a nydus filesystem is mounted.
///
/// Workflow:
/// 1. Prefetch the blobs declared in the root `trusted.nydus.prefetch.blobs`
///    xattr sequentially, in the declared priority order (single thread).
/// 2. When the scope is [`PrefetchScope::All`], prefetch the remaining blobs
///    concurrently with a worker pool; otherwise stop after the priority blobs so the
///    backend bandwidth stays focused on the access-ordered hot set (e.g. an
///    optimized image's "ondemand" redirect blob).
/// 3. Blobs whose prefetch the backend throttled (Dragonfly `429`, detected
///    via [`is_backend_throttled`]) are rescheduled after a random delay in
///    the configured window and re-attempted until they stop being throttled
///    or the [stop flag](Self::stop_flag) is raised. Other failures are
///    logged and skipped.
pub struct BlobPrefetcher {
    caches: Arc<BlobCaches>,
    priority: Vec<u16>,
    rest: Vec<u16>,
    threads: usize,
    scope: PrefetchScope,
    /// Per-blob prefetch timeout; `0s` disables the bound.
    timeout: Duration,
    /// The `[min, max]` window for the random delay before a throttled blob
    /// prefetch is re-attempted.
    retry_delay_min: Duration,
    retry_delay_max: Duration,
    /// Cooperative stop flag: once raised, no new prefetch work is started
    /// and the reschedule loop exits.
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
    /// `retry_delay_min ..= retry_delay_max` is the window for the random
    /// delay before a throttled blob prefetch is re-attempted.
    pub fn new(
        caches: Arc<BlobCaches>,
        plan: PrefetchPlan,
        threads: usize,
        scope: PrefetchScope,
        timeout: Duration,
        retry_delay_min: Duration,
        retry_delay_max: Duration,
    ) -> Self {
        Self {
            caches,
            priority: plan.priority,
            rest: plan.rest,
            threads: threads.max(1),
            scope,
            timeout,
            retry_delay_min,
            retry_delay_max: retry_delay_max.max(retry_delay_min),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A handle to this prefetcher's stop flag. Storing `true` makes the
    /// prefetcher stop starting new work and exit its reschedule loop, so a
    /// detached prefetch thread can be wound down on unmount.
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Spawn a background thread that drives the whole prefetch workflow. The
    /// returned handle may be detached by the caller.
    pub fn spawn(self) -> io::Result<JoinHandle<()>> {
        thread::Builder::new()
            .name("nydus_prefetch".to_string())
            .spawn(move || self.run())
    }

    /// Drive the whole prefetch workflow synchronously on the calling thread:
    /// priority blobs sequentially in declared order, then (only when the scope
    /// is [`PrefetchScope::All`]) the remaining blobs through a worker pool,
    /// then delayed retries of throttled blobs. Per-blob failures other than
    /// backend throttling are logged and skipped.
    pub fn run(mut self) {
        if self.scope == PrefetchScope::None {
            return;
        }

        // Blobs the backend throttled, awaiting a delayed retry.
        let mut throttled: Vec<u16> = Vec::new();

        // Phase 1: priority blobs, sequential, in declared order. Under the
        // default "ondemand" scope only the redirect blob is warmed (it
        // streams the access-ordered hot set into the source caches);
        // non-redirect priority blobs are skipped so the backend bandwidth is
        // not spent pulling whole source blobs.
        for blob_index in &self.priority {
            let blob_index = *blob_index;
            if self.stopped() {
                return;
            }
            if self.scope != PrefetchScope::All {
                match self.caches.is_redirect(blob_index) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(err) => {
                        warn!("failed to inspect priority blob {}: {}", blob_index, err);
                        continue;
                    }
                }
            }
            match self
                .caches
                .prefetch_blob(blob_index, self.threads, self.timeout)
            {
                Ok(()) => info!("prefetched priority blob {}", blob_index),
                Err(err) if is_backend_throttled(&err) => {
                    inc_prefetch_reschedule();
                    warn!(
                        "backend throttled prefetch of priority blob {}, rescheduling: {}",
                        blob_index, err
                    );
                    throttled.push(blob_index);
                }
                Err(err) => warn!("failed to prefetch priority blob {}: {}", blob_index, err),
            }
        }

        // Phase 2: remaining blobs, concurrent worker pool. Skipped unless the
        // scope is "all".
        if self.scope == PrefetchScope::All && !self.rest.is_empty() {
            let worker_count = self.threads.min(self.rest.len());
            let queue = Arc::new(Mutex::new(std::mem::take(&mut self.rest)));
            let throttled_shared = Arc::new(Mutex::new(Vec::new()));
            let timeout = self.timeout;
            let mut handles = Vec::with_capacity(worker_count);
            for _ in 0..worker_count {
                let blobs = self.caches.clone();
                let queue = queue.clone();
                let throttled_shared = throttled_shared.clone();
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
                        match blob_index {
                            Some(blob_index) => match blobs.prefetch_blob(blob_index, 1, timeout) {
                                Ok(()) => info!("prefetched blob {}", blob_index),
                                Err(err) if is_backend_throttled(&err) => {
                                    inc_prefetch_reschedule();
                                    warn!(
                                        "backend throttled prefetch of blob {}, rescheduling: {}",
                                        blob_index, err
                                    );
                                    throttled_shared.lock().unwrap().push(blob_index);
                                }
                                Err(err) => {
                                    warn!("failed to prefetch blob {}: {}", blob_index, err)
                                }
                            },
                            None => break,
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
            throttled.append(&mut throttled_shared.lock().unwrap());
        }

        // Phase 3: delayed retries of throttled blobs. Each blob gets a fresh
        // random deadline inside the retry window; retries that get throttled
        // again are rescheduled, other failures are dropped. The cross-process
        // prefetch flock and group-map skip logic inside `prefetch_blob` make
        // a rescheduled prefetch behind another node's progress nearly free.
        let mut queue: Vec<(Instant, u16)> = throttled
            .into_iter()
            .map(|blob_index| (Instant::now() + self.retry_delay(), blob_index))
            .collect();
        while !queue.is_empty() {
            queue.sort_by_key(|(deadline, _)| *deadline);
            let (deadline, blob_index) = queue.remove(0);
            while Instant::now() < deadline {
                if self.stopped() {
                    return;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                thread::sleep(remaining.min(RESCHEDULE_POLL_INTERVAL));
            }
            if self.stopped() {
                return;
            }
            inc_prefetch_reschedule_run();
            match self
                .caches
                .prefetch_blob(blob_index, self.threads, self.timeout)
            {
                Ok(()) => info!("prefetched rescheduled blob {}", blob_index),
                Err(err) if is_backend_throttled(&err) => {
                    inc_prefetch_reschedule();
                    warn!(
                        "backend throttled rescheduled prefetch of blob {}, rescheduling again: {}",
                        blob_index, err
                    );
                    queue.push((Instant::now() + self.retry_delay(), blob_index));
                }
                Err(err) => warn!(
                    "failed to prefetch rescheduled blob {}, giving up: {}",
                    blob_index, err
                ),
            }
        }
    }

    /// A random delay inside the configured retry window, seeded from OS
    /// entropy via `RandomState` so no `rand` dependency is needed.
    fn retry_delay(&self) -> Duration {
        let span = self.retry_delay_max.saturating_sub(self.retry_delay_min);
        if span.is_zero() {
            return self.retry_delay_min;
        }
        use std::hash::{BuildHasher, Hasher};
        let seed = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish();
        // The default window (6h span) is far below `u64::MAX` nanoseconds
        // (~584 years); clamp anyway so pathological configs cannot overflow.
        let span_nanos = u64::try_from(span.as_nanos()).unwrap_or(u64::MAX);
        self.retry_delay_min + Duration::from_nanos(seed % span_nanos.saturating_add(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::atomic::AtomicUsize;

    use nydus_backend::{throttled_error, BlobBackend, Local, ReadContext};
    use nydus_format::blob::{
        BlobMetadata, BlobMetadataBlockGroup, BlobMetadataChunk, BlobMetadataCompressor,
    };
    use nydus_format::utils::{write_minimal_full_blob, SHA256_DIGEST_SIZE};
    use tempfile::tempdir;

    /// Wraps a local backend and fails the first `failures` data reads with
    /// the given error builder, then delegates, counting every read attempt.
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

    impl BlobBackend for FlakyBackend {
        fn blob_metadata(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<BlobMetadata> {
            self.inner.blob_metadata(blob_id)
        }

        fn read_range_into(
            &self,
            blob_id: &[u8; SHA256_DIGEST_SIZE],
            offset: u64,
            dst: &mut [u8],
            ctx: ReadContext,
        ) -> io::Result<()> {
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
            if attempt < self.failures {
                return Err((self.error)());
            }
            self.inner.read_range_into(blob_id, offset, dst, ctx)
        }
    }

    /// A single-blob prefetcher over a `FlakyBackend`, with a tight retry
    /// window so tests run in milliseconds.
    fn prefetcher_over(
        backend: Arc<FlakyBackend>,
        backend_dir: &Path,
        cache_dir: &Path,
        payload: &[u8],
        meta: &BlobMetadata,
    ) -> BlobPrefetcher {
        let full_blob_id = write_minimal_full_blob(backend_dir, payload, meta, true);
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
            Duration::from_millis(30),
            Duration::from_millis(60),
        )
    }

    fn test_payload() -> (Vec<u8>, BlobMetadata) {
        let payload = vec![0xabu8; 4096];
        let meta = BlobMetadata::new(
            BlobMetadataCompressor::None,
            1,
            vec![BlobMetadataChunk::new(*blake3::hash(&payload).as_bytes(), 0, 1).unwrap()],
            vec![BlobMetadataBlockGroup::new(0, 1, 0, 4096, crc32c::crc32c(&payload)).unwrap()],
        )
        .unwrap();
        (payload, meta)
    }

    #[test]
    fn throttled_prefetch_is_rescheduled_and_retried() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let (payload, meta) = test_payload();
        // The first data read is throttled; the delayed retry succeeds.
        let backend = FlakyBackend::new(backend_dir.path(), 1, || {
            throttled_error("proxy answered 429")
        });
        let prefetcher = prefetcher_over(
            backend.clone(),
            backend_dir.path(),
            cache_dir.path(),
            &payload,
            &meta,
        );

        let reschedules_before = nydus_telemetry::metrics::prefetch_reschedule_total();
        let runs_before = nydus_telemetry::metrics::prefetch_reschedule_run_total();
        let start = Instant::now();
        prefetcher.run();

        // One throttled attempt plus the successful delayed retry.
        assert!(backend.attempts() >= 2, "attempts={}", backend.attempts());
        // The retry waited out (at least) the minimum delay.
        assert!(start.elapsed() >= Duration::from_millis(30));
        assert!(nydus_telemetry::metrics::prefetch_reschedule_total() > reschedules_before);
        assert!(nydus_telemetry::metrics::prefetch_reschedule_run_total() > runs_before);
    }

    #[test]
    fn non_throttled_failure_is_not_rescheduled() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let (payload, meta) = test_payload();
        // Always fail with an ordinary error: log-and-skip, no reschedule.
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

        let start = Instant::now();
        prefetcher.run();

        // No delayed retry: exactly the initial attempt, and no retry-window
        // sleep.
        assert_eq!(backend.attempts(), 1);
        assert!(start.elapsed() < Duration::from_millis(30));
    }

    #[test]
    fn raised_stop_flag_prevents_rescheduled_retries() {
        let backend_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let (payload, meta) = test_payload();
        let backend = FlakyBackend::new(backend_dir.path(), usize::MAX, || {
            throttled_error("proxy answered 429")
        });
        let prefetcher = prefetcher_over(
            backend.clone(),
            backend_dir.path(),
            cache_dir.path(),
            &payload,
            &meta,
        );

        // Raise the stop flag before running: the initial pass is skipped
        // entirely and run() returns without sleeping towards a retry.
        prefetcher.stop_flag().store(true, Ordering::SeqCst);
        let start = Instant::now();
        prefetcher.run();

        assert_eq!(backend.attempts(), 0);
        assert!(start.elapsed() < Duration::from_millis(30));
    }
}
