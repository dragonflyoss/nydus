//! One-shot image preheat: downloads every blob of an image into the local
//! cache without mounting the image, and reports how far it got through a
//! state file.
//!
//! ```text
//! open every blob's cache ──▶ download every blob ──▶ succeeded
//!        │ fails                    │ first blob fails
//!        └──────────────────────────┴───────────────▶ failed
//!
//! state file: replaced on every step, every STATE_INTERVAL in between, and
//! once with the final state
//! ```
//!
//! The download is the blob prefetch of a mount with `prefetch.scope: all`,
//! so the processes sharing the cache directory see every chunk group the
//! moment it is ready and no blob is fetched by two of them at once.

use nydus_backend::ReadKind;
use nydus_config::PrefetchScope;
use nydus_core::ErofsReader;
use nydus_error::{Context, Error, Result};
use nydus_format::utils::SHA256_DIGEST_SIZE;
use nydus_storage::cache::BlobCaches;
use nydus_storage::prefetch::{BlobPrefetcher, PrefetchPlan};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::mem;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};
use tracing::{debug, error, info};

/// The interval the state file is replaced at while blobs download.
const STATE_INTERVAL: Duration = Duration::from_secs(5);

/// The longest description of a failure in bytes, the limit the kubelet puts
/// on the termination message of a container, refer to
/// https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/api/core/v1/types.go.
const MAX_DESCRIPTION_SIZE: usize = 4096;

/// The state of a preheat.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum State {
    /// The blobs are being downloaded.
    Running,

    /// Every blob is in the cache.
    Succeeded,

    /// The preheat ended before every blob was in the cache.
    Failed,
}

/// The status of a blob of the image.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct BlobStatus {
    /// The digest of the blob, as the registry names it.
    digest: String,

    /// The uncompressed size of the blob in bytes.
    content_length: u64,

    /// The uncompressed bytes of the blob the cache holds.
    finished_content_length: u64,

    /// Whether the blob is downloaded completely.
    is_finished: bool,
}

/// Implements the status of a blob.
impl BlobStatus {
    /// Creates the status of the blob of `digest` before its download.
    fn new(digest: String) -> Self {
        Self {
            digest,
            content_length: 0,
            finished_content_length: 0,
            is_finished: false,
        }
    }
}

/// The status of a preheat, the document of the state file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Status {
    /// The state of the preheat.
    state: State,

    /// The blobs of the image: the priority blobs in declared order, then
    /// the rest by index.
    blobs: Vec<BlobStatus>,

    /// The reason of the failure, empty unless the preheat failed. It never
    /// holds a credential.
    description: String,

    /// The time the status was written.
    #[serde(with = "humantime_serde")]
    updated_at: SystemTime,
}

/// Implements the status.
impl Status {
    /// Creates the status of a preheat that starts with `blobs`.
    fn new(blobs: Vec<BlobStatus>) -> Self {
        Self {
            state: State::Running,
            blobs,
            description: String::new(),
            updated_at: SystemTime::now(),
        }
    }

    /// Returns the number of blobs downloaded completely.
    fn finished_blob_count(&self) -> usize {
        self.blobs.iter().filter(|blob| blob.is_finished).count()
    }

    /// Returns the uncompressed size of all the blobs in bytes.
    fn total_content_length(&self) -> u64 {
        self.blobs.iter().map(|blob| blob.content_length).sum()
    }

    /// Marks the preheat failed over `reason`, which is kept without the
    /// query of any URL and within [`MAX_DESCRIPTION_SIZE`].
    fn fail(&mut self, reason: impl fmt::Display) {
        let mut description = without_url_queries(&reason.to_string());
        let mut size = description.len().min(MAX_DESCRIPTION_SIZE);
        while !description.is_char_boundary(size) {
            size -= 1;
        }
        description.truncate(size);

        self.state = State::Failed;
        self.description = description;
    }

    /// Writes the status to `path` through a file next to it, so a reader
    /// finds the previous document or this one, never a part of one. Stamps
    /// `updated_at` first.
    fn write(&mut self, path: &Path) -> Result<()> {
        self.updated_at = SystemTime::now();
        let mut temp_path = path.as_os_str().to_owned();
        temp_path.push(".tmp");
        fs::write(&temp_path, serde_json::to_vec(self)?)
            .and_then(|()| fs::rename(&temp_path, path))
            .with_context(|| format!("failed to write state file {}", path.display()))
    }
}

/// Returns `message` without the query of any URL in it. The registry
/// redirects a blob read to a signed link, whose query authorizes the read
/// and which the HTTP client names in its errors.
fn without_url_queries(message: &str) -> String {
    let mut result = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(scheme_end) = rest.find("://") {
        // A URL ends at the first character an error message closes it
        // with, less the punctuation of the sentence around it.
        let url_end = rest[scheme_end..]
            .find(|c: char| c.is_whitespace() || matches!(c, ')' | '"' | '\'' | '>' | ','))
            .map_or(rest.len(), |offset| scheme_end + offset);
        let url_end = rest[..url_end].trim_end_matches([':', ';', '.']).len();
        let query_start = rest[scheme_end..url_end]
            .find('?')
            .map_or(url_end, |offset| scheme_end + offset);
        result.push_str(&rest[..query_start]);
        rest = &rest[url_end..];
    }
    result.push_str(rest);
    result
}

/// Returns `err` and every cause beneath it as one line, as
/// [`Error::report`] prints an error, so the description of a failed read
/// carries what the transport hit and not only that its retries ran out.
fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut line = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        line.push_str(": ");
        line.push_str(&cause.to_string());
        source = cause.source();
    }
    line
}

/// Writes the state file of a preheat that failed over `err` before it
/// could start: an invalid config, a bootstrap that cannot be read or a
/// backend that cannot be built.
pub fn write_failure(state_file: &Path, err: &Error) {
    let mut status = Status::new(Vec::new());
    status.fail(err.report());
    if let Err(err) = status.write(state_file) {
        error!("{}", err.report());
    }
}

/// The event the preheat thread reports while it runs.
enum Event {
    /// The cache of every blob is open, so the sizes are known.
    Opened,

    /// The blob at the index is downloaded completely.
    Finished(u16),

    /// The blob at the index failed over the reason.
    Failed(u16, String),
}

/// Sends `event` to the thread following the preheat, which is gone once the
/// preheat failed.
fn send(tx: &Sender<Event>, event: Event) {
    if tx.send(event).is_err() {
        debug!("preheat ended, dropped an event");
    }
}

/// The preheat of one image.
pub struct Preheat {
    /// The caches of the blobs of the image.
    caches: Arc<BlobCaches>,

    /// The prefetch plan of the image: the priority blobs, then the rest.
    plan: PrefetchPlan,

    /// The ids of the blobs by index, the digests the status names them by.
    blob_ids: HashMap<u16, [u8; SHA256_DIGEST_SIZE]>,

    /// The number of blobs downloaded at once.
    concurrent_blob_count: usize,

    /// The timeout of downloading one whole blob.
    timeout: Duration,

    /// The file the status is written to.
    state_file: PathBuf,

    /// The interval between two writes of the state file, [`STATE_INTERVAL`]
    /// outside tests.
    state_interval: Duration,
}

/// Implements the preheat.
impl Preheat {
    /// Creates the preheat of the image `reader` opened, downloading
    /// `concurrent_blob_count` blobs at once, each within `timeout`, and
    /// writing its status to `state_file`.
    pub fn new(
        reader: &ErofsReader,
        concurrent_blob_count: usize,
        timeout: Duration,
        state_file: &Path,
    ) -> Result<Self> {
        let blob_ids = reader
            .blob_infos()?
            .iter()
            .map(|info| (info.blob_index, info.blob_id))
            .collect();

        Ok(Self {
            caches: reader.blob_caches(),
            plan: reader.prefetch_plan(),
            blob_ids,
            concurrent_blob_count,
            timeout,
            state_file: state_file.to_path_buf(),
            state_interval: STATE_INTERVAL,
        })
    }

    /// Downloads every blob of the image into the cache and returns once all
    /// of them are complete, or with the first one that fails: the blobs not
    /// started yet are skipped, and the ones in flight end with the process.
    /// What a failed preheat downloaded stays in the cache, so the next one
    /// fetches only the rest.
    pub fn run(mut self) -> Result<()> {
        let plan = PrefetchPlan {
            priority: mem::take(&mut self.plan.priority),
            rest: mem::take(&mut self.plan.rest),
        };
        let blob_indexes: Vec<u16> = plan.priority.iter().chain(&plan.rest).copied().collect();
        let mut status = Status::new(
            blob_indexes
                .iter()
                .map(|blob_index| BlobStatus::new(self.digest(*blob_index).unwrap_or_default()))
                .collect(),
        );
        status.write(&self.state_file)?;

        // Download the blobs as a mount with `prefetch.scope: all` does. The
        // observer raises the stop flag on the first failure, so no further
        // blob is started.
        let (tx, rx) = mpsc::channel();
        let prefetcher = BlobPrefetcher::new(
            self.caches.clone(),
            plan,
            self.concurrent_blob_count,
            PrefetchScope::All,
            self.timeout,
        );
        let stop = prefetcher.stop_flag();
        let observer_tx = tx.clone();
        let prefetcher = prefetcher.with_observer(move |blob_index, result| {
            let event = match result {
                Ok(()) => Event::Finished(blob_index),
                Err(err) => {
                    stop.store(true, Ordering::Relaxed);
                    Event::Failed(blob_index, error_chain(err))
                }
            };
            send(&observer_tx, event);
        });

        // Open the cache of every blob first, so the sizes are known before
        // the download starts and a blob the backend refuses fails the
        // preheat before any data is fetched. The blob metadata an open
        // fetches is small next to the blob, so the blobs are opened one
        // after the other.
        let caches = self.caches.clone();
        let opened_blob_indexes = blob_indexes.clone();
        thread::Builder::new()
            .name("nydus_preheat".to_string())
            .spawn(move || {
                for blob_index in opened_blob_indexes {
                    if let Err(err) = caches.cache(blob_index, ReadKind::Prefetch) {
                        return send(&tx, Event::Failed(blob_index, error_chain(&err)));
                    }
                }
                send(&tx, Event::Opened);
                prefetcher.run();
            })
            .context("failed to spawn the preheat thread")?;

        // Follow the download until the thread ends, which drops the last
        // sender and closes the channel.
        let mut opened = false;
        loop {
            let event = rx.recv_timeout(self.state_interval);
            if matches!(event, Ok(Event::Opened)) {
                opened = true;
            }
            if opened {
                self.measure(&blob_indexes, &mut status);
            }

            match event {
                Ok(Event::Finished(blob_index)) => {
                    if let Some(position) =
                        blob_indexes.iter().position(|index| *index == blob_index)
                    {
                        status.blobs[position].is_finished = true;
                    }
                }
                Ok(Event::Failed(blob_index, reason)) => {
                    let reason = format!("{}: {reason}", self.blob_name(blob_index));
                    return Err(Error::Backend(self.fail(status, reason)));
                }
                Ok(Event::Opened) | Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            status.write(&self.state_file)?;
        }

        // A download that ended without the result of every blob lost a
        // worker, which is no success.
        let (finished, count) = (status.finished_blob_count(), status.blobs.len());
        if finished != count {
            let reason = format!("preheat ended with {finished} of {count} blobs downloaded");
            return Err(Error::Runtime(self.fail(status, reason)));
        }

        status.state = State::Succeeded;
        status.write(&self.state_file)?;
        info!(
            "preheated {count} blobs, {} bytes",
            status.total_content_length()
        );
        Ok(())
    }

    /// Reads how much of every blob the cache holds into `status`. A raw
    /// device and an ondemand blob have no size of their own and count as 0.
    fn measure(&self, blob_indexes: &[u16], status: &mut Status) {
        for (blob_index, blob) in blob_indexes.iter().zip(&mut status.blobs) {
            let cached_bytes = self
                .caches
                .cache(*blob_index, ReadKind::Prefetch)
                .ok()
                .and_then(|cache| cache.cached_bytes());
            if let Some((cached, total)) = cached_bytes {
                blob.content_length = total;
                blob.finished_content_length = cached;
            }
        }
    }

    /// Returns the digest of the blob at `blob_index`, as the registry names
    /// the blob.
    fn digest(&self, blob_index: u16) -> Option<String> {
        self.blob_ids
            .get(&blob_index)
            .map(|blob_id| format!("sha256:{}", hex::encode(blob_id)))
    }

    /// Names the blob at `blob_index` by its digest.
    fn blob_name(&self, blob_index: u16) -> String {
        match self.digest(blob_index) {
            Some(digest) => format!("blob {digest}"),
            None => format!("blob {blob_index}"),
        }
    }

    /// Ends the preheat over `reason`: writes the failed status and returns
    /// its description.
    fn fail(&self, mut status: Status, reason: impl fmt::Display) -> String {
        status.fail(reason);
        if let Err(err) = status.write(&self.state_file) {
            error!("{}", err.report());
        }

        status.description
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::*;
    use nydus_format::blob::BlobMetadataCompressor;
    use nydus_storage::cache::CacheOptions;
    use nydus_test_utils::fault::{Fault, FaultBackend, FaultRule};
    use nydus_test_utils::metadata::from_chunk_groups;
    use std::io;
    use std::time::Instant;
    use tempfile::tempdir;

    const BLOB_IDS: [[u8; SHA256_DIGEST_SIZE]; 2] =
        [[1; SHA256_DIGEST_SIZE], [2; SHA256_DIGEST_SIZE]];

    const TOTAL_CONTENT_LENGTH: u64 = 4 * 4096;

    fn backend() -> Arc<FaultBackend> {
        let groups = vec![vec![vec![0x5a; 4096]], vec![vec![0xa5; 4096]]];
        let (data, blob_metadata) =
            from_chunk_groups(BlobMetadataCompressor::Zstd, 4096, &groups, None);
        Arc::new(
            FaultBackend::in_memory()
                .with_blob(BLOB_IDS[0], data.clone(), &blob_metadata)
                .with_blob(BLOB_IDS[1], data, &blob_metadata),
        )
    }

    fn preheat(backend: Arc<FaultBackend>, cache_dir: &Path, state_file: &Path) -> Preheat {
        let blob_ids = HashMap::from([(1, BLOB_IDS[0]), (2, BLOB_IDS[1])]);
        let caches = BlobCaches::new(
            blob_ids.clone(),
            backend,
            Some(cache_dir),
            None,
            CacheOptions::default(),
        )
        .unwrap();
        Preheat {
            caches: Arc::new(caches),
            plan: PrefetchPlan {
                priority: Vec::new(),
                rest: vec![1, 2],
            },
            blob_ids,
            concurrent_blob_count: 1,
            timeout: Duration::from_secs(5),
            state_file: state_file.to_path_buf(),
            state_interval: Duration::from_millis(10),
        }
    }

    fn read_status(state_file: &Path) -> Option<Status> {
        match fs::read(state_file) {
            Ok(content) => Some(serde_json::from_slice(&content).unwrap()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => panic!("{err}"),
        }
    }

    fn wait_for_status(state_file: &Path, condition: impl Fn(&Status) -> bool) -> Status {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = read_status(state_file).filter(&condition) {
                return status;
            }

            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn run_downloads_every_blob_and_reports_success() {
        let dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let state_file = dir.path().join("state.json");
        let backend = backend();

        preheat(backend.clone(), cache_dir.path(), &state_file)
            .run()
            .unwrap();

        let status = read_status(&state_file).unwrap();
        assert_eq!(
            status,
            Status {
                state: State::Succeeded,
                blobs: BLOB_IDS
                    .iter()
                    .map(|blob_id| BlobStatus {
                        digest: format!("sha256:{}", hex::encode(blob_id)),
                        content_length: TOTAL_CONTENT_LENGTH / 2,
                        finished_content_length: TOTAL_CONTENT_LENGTH / 2,
                        is_finished: true,
                    })
                    .collect(),
                description: String::new(),
                updated_at: status.updated_at,
            }
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        assert!(!backend.reads().is_empty());
    }

    #[test]
    fn run_reads_nothing_when_the_blobs_are_cached() {
        let dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let state_file = dir.path().join("state.json");
        preheat(backend(), cache_dir.path(), &state_file)
            .run()
            .unwrap();
        let backend = backend();
        backend.inject(FaultRule::read(Fault::Error(io::ErrorKind::Other)));

        preheat(backend.clone(), cache_dir.path(), &state_file)
            .run()
            .unwrap();

        let status = read_status(&state_file).unwrap();
        assert_eq!(status.state, State::Succeeded);
        assert_eq!(status.finished_blob_count(), 2);
        assert_eq!(status.total_content_length(), TOTAL_CONTENT_LENGTH);
        assert!(status
            .blobs
            .iter()
            .all(|blob| blob.finished_content_length == blob.content_length));
        assert!(backend.reads().is_empty());
    }

    #[test]
    fn run_stops_at_the_first_blob_that_fails() {
        let test_cases: Vec<(FaultRule, fn(&Status, &FaultBackend))> = vec![
            (
                FaultRule::read(Fault::Error(io::ErrorKind::Other)).on_blob(BLOB_IDS[1]),
                |status, backend| {
                    assert!(status
                        .description
                        .starts_with(&format!("blob sha256:{}: ", hex::encode(BLOB_IDS[1]))));
                    assert_eq!(status.total_content_length(), TOTAL_CONTENT_LENGTH);
                    assert!(backend
                        .reads()
                        .iter()
                        .all(|read| read.blob_id == BLOB_IDS[1]));
                },
            ),
            (
                FaultRule::metadata(Fault::Error(io::ErrorKind::Other)).on_blob(BLOB_IDS[0]),
                |status, backend| {
                    assert!(status
                        .description
                        .starts_with(&format!("blob sha256:{}: ", hex::encode(BLOB_IDS[0]))));
                    assert_eq!(status.total_content_length(), 0);
                    assert!(backend.reads().is_empty());
                },
            ),
        ];

        for (rule, assert_fn) in test_cases {
            let dir = tempdir().unwrap();
            let cache_dir = tempdir().unwrap();
            let state_file = dir.path().join("state.json");
            let backend = backend();
            backend.inject(rule);

            let err = preheat(backend.clone(), cache_dir.path(), &state_file)
                .run()
                .unwrap_err();

            let status = read_status(&state_file).unwrap();
            assert!(matches!(err, Error::Backend(_)));
            assert_eq!(err.to_string(), status.description);
            assert_eq!(status.state, State::Failed);
            assert!(status
                .blobs
                .iter()
                .all(|blob| blob.finished_content_length == 0));
            assert_eq!(
                status
                    .blobs
                    .iter()
                    .map(|blob| (blob.digest.as_str(), blob.is_finished))
                    .collect::<Vec<_>>(),
                vec![
                    (
                        format!("sha256:{}", hex::encode(BLOB_IDS[0])).as_str(),
                        false
                    ),
                    (
                        format!("sha256:{}", hex::encode(BLOB_IDS[1])).as_str(),
                        false
                    ),
                ]
            );
            assert!(status.description.contains("injected backend fault"));
            assert_fn(&status, &backend);
        }
    }

    #[test]
    fn run_replaces_the_state_file_while_it_waits_for_the_backend() {
        let delay = Fault::Delay(Duration::from_millis(200));
        let test_cases = vec![
            (FaultRule::metadata(delay.clone()).times(1), 0),
            (FaultRule::read(delay).times(1), TOTAL_CONTENT_LENGTH),
        ];

        for (rule, content_length) in test_cases {
            let dir = tempdir().unwrap();
            let cache_dir = tempdir().unwrap();
            let state_file = dir.path().join("state.json");
            let backend = backend();
            backend.inject(rule);
            let preheat = preheat(backend, cache_dir.path(), &state_file);
            let handle = thread::spawn(move || preheat.run());

            let waiting = wait_for_status(&state_file, |status| {
                status.state == State::Running && status.total_content_length() == content_length
            });
            let replaced =
                wait_for_status(&state_file, |status| status.updated_at > waiting.updated_at);
            handle.join().unwrap().unwrap();

            assert_eq!(replaced.state, State::Running);
            assert_eq!(replaced.total_content_length(), content_length);
            assert_eq!(replaced.finished_blob_count(), 0);
            assert_eq!(read_status(&state_file).unwrap().state, State::Succeeded);
        }
    }

    #[test]
    fn write_replaces_the_state_file_with_one_json_document() {
        let test_cases = vec![
            (State::Running, "running"),
            (State::Succeeded, "succeeded"),
            (State::Failed, "failed"),
        ];

        let dir = tempdir().unwrap();
        let state_file = dir.path().join("state.json");
        for (state, expected) in test_cases {
            let mut status = Status::new(vec![BlobStatus::new("sha256:aa".to_string())]);
            status.state = state;
            status.blobs[0].content_length = 8192;
            status.blobs[0].finished_content_length = 4096;
            status.blobs[0].is_finished = true;
            status.write(&state_file).unwrap();

            let document: serde_json::Value =
                serde_json::from_slice(&fs::read(&state_file).unwrap()).unwrap();
            let updated_at = document["updated_at"].as_str().unwrap();
            assert_eq!(
                document,
                serde_json::json!({
                    "state": expected,
                    "blobs": [{
                        "digest": "sha256:aa",
                        "content_length": 8192,
                        "finished_content_length": 4096,
                        "is_finished": true,
                    }],
                    "description": "",
                    "updated_at": updated_at,
                })
            );
            assert_eq!(
                humantime_serde::re::humantime::parse_rfc3339(updated_at).unwrap(),
                status.updated_at
            );
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }

    #[test]
    fn fail_keeps_the_description_free_of_url_queries_and_bounded() {
        let test_cases = vec![
            (
                "error sending request for url (https://cdn.example/blob?sig=secret&exp=1)"
                    .to_string(),
                "error sending request for url (https://cdn.example/blob)".to_string(),
            ),
            (
                r#"unexpected status 401: {"realm":"https://auth.example/token?service=a"}"#
                    .to_string(),
                r#"unexpected status 401: {"realm":"https://auth.example/token"}"#.to_string(),
            ),
            (
                "a://b?c d://e?f, g".to_string(),
                "a://b d://e, g".to_string(),
            ),
            ("no link, a?b".to_string(), "no link, a?b".to_string()),
            (
                "é".repeat(MAX_DESCRIPTION_SIZE),
                "é".repeat(MAX_DESCRIPTION_SIZE / 2),
            ),
            (
                format!("a{}", "é".repeat(MAX_DESCRIPTION_SIZE)),
                format!("a{}", "é".repeat(MAX_DESCRIPTION_SIZE / 2 - 1)),
            ),
        ];

        for (reason, expected) in test_cases {
            let mut status = Status::new(vec![BlobStatus::new("sha256:aa".to_string())]);
            status.fail(reason);
            assert_eq!(status.state, State::Failed);
            assert_eq!(status.description, expected);
        }
    }

    #[test]
    fn error_chain_joins_an_error_and_its_causes() {
        let test_cases = vec![
            (io::Error::other("refused"), "refused"),
            (
                io::Error::other(
                    Error::InvalidConfig("refused".to_string()).context("retries ran out"),
                ),
                "retries ran out: refused",
            ),
        ];

        for (err, expected) in test_cases {
            assert_eq!(error_chain(&err), expected);
        }
    }

    #[test]
    fn write_failure_reports_a_preheat_that_never_started() {
        let dir = tempdir().unwrap();
        let state_file = dir.path().join("state.json");
        let err = Error::InvalidConfig("backend is missing".to_string())
            .context("failed to load https://config.example/nydus?token=secret");

        write_failure(&state_file, &err);

        let status = read_status(&state_file).unwrap();
        assert_eq!(
            status,
            Status {
                state: State::Failed,
                blobs: Vec::new(),
                description: "failed to load https://config.example/nydus: backend is missing"
                    .to_string(),
                updated_at: status.updated_at,
            }
        );
    }
}
