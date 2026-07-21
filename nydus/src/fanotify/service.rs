//! Fanotify pre-content group setup and an event coordinator (epoll + thread pool).
//!
//! The coordinator runs one event loop and never runs the synchronous accessor
//! fetch inline. Each event dispatches its fetch to a thread pool; the task
//! reports every result back through a completion channel. Concurrency is
//! bounded by the pool size (--fetch-concurrency).
//!
//! The lifecycle, parser, permission ownership, admission, and completion
//! logic here is kernel-independent except the fanotify syscalls themselves.
//! Verified end-to-end on Linux 6.15+ with a registry backend.

use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::mpsc::{self, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::{anyhow, Context, Result};
use tracing::{debug, warn};

use crate::BlobID;

use super::core::{
    align_fetch_range, decide, fd_identity, Decision, DenyReason, FanotifyCore, FetchError,
    Response,
};
use super::event::{EventIter, PreContentEvent};
use super::response::{FdResponseWriter, PendingPermission, ResponseWriter};

const FAN_CLOEXEC: u32 = 0x0000_0001;
const FAN_NONBLOCK: u32 = 0x0000_0002;
const FAN_CLASS_PRE_CONTENT: u32 = 0x0000_0008;
const FAN_MARK_ADD: u32 = 0x0000_0001;
const FAN_PRE_ACCESS: u64 = 0x0010_0000;

// 256 KiB holds ~5400 minimum-size events per read(2)
// (24-byte fanotify_event_metadata + 24-byte RANGE record).
const EVENT_BUFFER_SIZE: usize = 256 * 1024;

/// A live fanotify pre-content group marking every external-device cache file.
pub struct FanotifyService {
    fan: OwnedFd,
    core: Arc<FanotifyCore>,
}

/// The terminal outcome of one fetch job.
enum CompletionResult {
    Fetch(Result<(), FetchError>),
    Panicked,
}

/// The result of one job, correlated back to its event by `job_id`.
struct Completion {
    job_id: u64,
    result: CompletionResult,
}

/// Coalescing key: identical (blob, aligned offset, aligned length) reads share
/// one fetch job and are all answered by its single completion.
type FetchKey = (BlobID, u64, u64);

/// One in-flight fetch job and every permission event waiting on it. Concurrent
/// reads of the same range (common at container start: many tasks page in the
/// same library) coalesce into a single backend fetch instead of one per reader.
struct PendingEvent {
    key: FetchKey,
    waiters: Vec<PendingPermission>,
}

/// Sends a fetch result back to the event loop and wakes it.
///
/// Workers hold this via `Arc`; the coordinator polls `wake`. Without the wake,
/// completions would only be noticed on the next fanotify event or an idle
/// timeout — a single-stream cold read would then stall until the timer fired.
/// One `eventfd` write per completion removes that latency.
struct CompletionSink {
    tx: mpsc::Sender<Completion>,
    wake: OwnedFd,
}

impl CompletionSink {
    fn complete(&self, job_id: u64, result: CompletionResult) {
        let _ = self.tx.send(Completion { job_id, result });
        // eventfd counter semantics: writes accumulate into the counter and a
        // single read drains them, so a completion can never be missed even if
        // it lands between the coordinator's read and its drain.
        let one: u64 = 1;
        let _ = unsafe {
            libc::write(
                self.wake.as_raw_fd(),
                &one as *const u64 as *const libc::c_void,
                std::mem::size_of::<u64>(),
            )
        };
    }
}

/// What the service should do with a fetch completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompletionAction {
    Decide,
    Late,
    Unknown,
}

struct PendingEntry {
    decided: bool,
}

/// Table of in-flight permission events, unbounded by design.
struct PendingTable {
    entries: HashMap<u64, PendingEntry>,
    next_job_id: u64,
}

impl PendingTable {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            next_job_id: 0,
        }
    }

    fn admit(&mut self) -> u64 {
        let job_id = self.next_job_id;
        self.next_job_id = self.next_job_id.wrapping_add(1);
        self.entries.insert(job_id, PendingEntry { decided: false });
        job_id
    }

    fn on_completion(&mut self, job_id: u64) -> CompletionAction {
        match self.entries.get(&job_id) {
            Some(entry) => {
                let decided = entry.decided;
                self.entries.remove(&job_id);
                if decided {
                    CompletionAction::Late
                } else {
                    CompletionAction::Decide
                }
            }
            None => CompletionAction::Unknown,
        }
    }

    fn take_undecided(&mut self) -> Vec<u64> {
        let undecided: Vec<u64> = self
            .entries
            .iter()
            .filter(|(_, entry)| !entry.decided)
            .map(|(job_id, _)| *job_id)
            .collect();
        for job_id in &undecided {
            if let Some(entry) = self.entries.get_mut(job_id) {
                entry.decided = true;
            }
        }
        undecided
    }
}

// ---- epoll helpers ----

const EPOLLIN: u32 = libc::EPOLLIN as u32;
const EPOLL_CLOEXEC: i32 = libc::EPOLL_CLOEXEC;

fn epoll_create() -> io::Result<OwnedFd> {
    let fd = unsafe { libc::epoll_create1(EPOLL_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn epoll_add(epfd: RawFd, fd: RawFd, events: u32, data: u64) -> io::Result<()> {
    let mut ev = libc::epoll_event { events, u64: data };
    let ret = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Non-blocking, close-on-exec eventfd used to wake the coordinator from a
/// blocking `epoll_wait` when a fetch completes.
fn create_eventfd() -> io::Result<OwnedFd> {
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

// ---- thread pool ----

/// Pre-warmed thread pool. `max` worker threads are created once and
/// live for the daemon's lifetime, consuming work from an mpsc channel.
/// `execute` never blocks — when all workers are busy, work queues in
/// memory (bounded by the fanotify event rate, ~16K items max per 64MB file).
pub struct FetchPool {
    tx: mpsc::Sender<Box<dyn FnOnce() + Send + 'static>>,
}

impl FetchPool {
    pub fn new(max: usize) -> Result<Self> {
        let (tx, rx) = mpsc::channel::<Box<dyn FnOnce() + Send + 'static>>();
        let rx = Arc::new(Mutex::new(rx));
        for _ in 0..max {
            let rx = Arc::clone(&rx);
            thread::Builder::new()
                .name("nydus_fanotify_fetch".to_string())
                .spawn(move || loop {
                    let work: Box<dyn FnOnce() + Send> = {
                        let guard = rx.lock().unwrap();
                        match guard.recv() {
                            Ok(w) => w,
                            Err(_) => return,
                        }
                    };
                    work();
                })
                .with_context(|| format!("failed to spawn fetch worker"))?;
        }
        Ok(FetchPool { tx })
    }

    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        // Non-blocking: the mpsc channel is unbounded and send never
        // blocks. If the channel is disconnected (pool dropped) the send
        // fails silently.
        let _ = self.tx.send(Box::new(f));
    }
}

// ---- service ----

impl FanotifyService {
    /// Create the group and marks while retaining an unregistered `OwnedFd`.
    pub fn setup(core: Arc<FanotifyCore>) -> Result<Self> {
        if core.devices().is_empty() {
            anyhow::bail!("image has no blob devices to serve");
        }

        let fan_fd = unsafe {
            libc::fanotify_init(
                FAN_CLOEXEC | FAN_NONBLOCK | FAN_CLASS_PRE_CONTENT,
                (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
            )
        };
        if fan_fd < 0 {
            return Err(std::io::Error::last_os_error()).context(
                "fanotify_init failed (needs CAP_SYS_ADMIN and kernel FAN_CLASS_PRE_CONTENT)",
            );
        }
        let fan = unsafe { OwnedFd::from_raw_fd(fan_fd) };

        for device in core.devices() {
            if core
                .range_ready(&device.id, 0, device.cache_size)
                .unwrap_or(false)
            {
                debug!(
                    "fanotify: skip marking fully-ready blob {} (slot {})",
                    device.id, device.index
                );
                continue;
            }
            let path = CString::new(device.cache_path.as_os_str().as_bytes())
                .context("blob device path contains an interior NUL byte")?;
            let ret = unsafe {
                libc::fanotify_mark(
                    fan.as_raw_fd(),
                    FAN_MARK_ADD,
                    FAN_PRE_ACCESS,
                    libc::AT_FDCWD,
                    path.as_ptr(),
                )
            };
            if ret < 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "fanotify_mark(FAN_PRE_ACCESS) failed for {}",
                        device.cache_path.display()
                    )
                });
            }
            debug!(
                "fanotify: marked device slot {} at {}",
                device.index,
                device.cache_path.display()
            );
        }

        Ok(Self { fan, core })
    }

    /// Run the event loop synchronously on the calling thread and return the
    /// group fd in **every** case — clean stop or fatal error — paired with the
    /// outcome, so the caller can always unmount before dropping the fd.
    /// Dropping the fd triggers `fanotify_release`, which fail-opens any
    /// residual permission events; unmounting first ensures those ALLOWs land on
    /// a filesystem no reader can reach. Returning the fd on the error path too
    /// is what keeps that invariant across fatal exits (overflow, parse error).
    ///
    /// `stop_fd` is the read end of a self-pipe: the signal thread writes to it
    /// to wake this loop for shutdown.
    pub fn run(
        self,
        stop_fd: OwnedFd,
        ready: mpsc::Sender<()>,
        pool: Arc<FetchPool>,
    ) -> (Arc<OwnedFd>, Result<()>) {
        let fan_fd = Arc::new(self.fan);
        let outcome = serve(&fan_fd, &self.core, stop_fd, ready, pool);
        (fan_fd, outcome)
    }
}

/// Body of [`FanotifyService::run`], factored out so `fan_fd` stays owned by
/// `run` and is handed back to the caller even when this returns an error.
fn serve(
    fan_fd: &Arc<OwnedFd>,
    core: &Arc<FanotifyCore>,
    stop_fd: OwnedFd,
    ready: mpsc::Sender<()>,
    pool: Arc<FetchPool>,
) -> Result<()> {
    let fan_raw = fan_fd.as_raw_fd();
    let epfd = epoll_create().context("epoll_create1")?;

    let writer: Arc<dyn ResponseWriter> = Arc::new(FdResponseWriter::new(fan_fd.clone()));

    // Register fanotify fd for readability.
    epoll_add(epfd.as_raw_fd(), fan_raw, EPOLLIN, fan_raw as u64).context("epoll add fan_fd")?;

    // Register stop pipe for readability.
    let stop_raw = stop_fd.as_raw_fd();
    epoll_add(epfd.as_raw_fd(), stop_raw, EPOLLIN, stop_raw as u64)
        .context("epoll add stop pipe")?;

    let (completion_tx, completion_rx) = mpsc::channel();
    let wake = create_eventfd().context("create completion eventfd")?;
    let wake_raw = wake.as_raw_fd();
    epoll_add(epfd.as_raw_fd(), wake_raw, EPOLLIN, wake_raw as u64)
        .context("epoll add completion eventfd")?;
    let sink = Arc::new(CompletionSink {
        tx: completion_tx,
        wake,
    });

    ready
        .send(())
        .map_err(|_| anyhow!("fanotify readiness receiver was dropped"))?;

    let mut pending_events = HashMap::new();
    let mut pending_table = PendingTable::new();
    coordinate(
        epfd.as_raw_fd(),
        fan_raw,
        core,
        &writer,
        &pool,
        &sink,
        &completion_rx,
        stop_raw,
        wake_raw,
        &mut pending_events,
        &mut pending_table,
    )
}

// ---- event loop ----

#[allow(clippy::too_many_arguments)]
fn coordinate(
    epfd: RawFd,
    fan_fd: RawFd,
    core: &Arc<FanotifyCore>,
    writer: &Arc<dyn ResponseWriter>,
    pool: &FetchPool,
    sink: &Arc<CompletionSink>,
    completion_rx: &mpsc::Receiver<Completion>,
    stop_fd: RawFd,
    wake_fd: RawFd,
    pending_events: &mut HashMap<u64, PendingEvent>,
    pending_table: &mut PendingTable,
) -> Result<()> {
    // Reverse index (FetchKey -> job_id) for coalescing concurrent identical reads.
    let mut in_flight: HashMap<FetchKey, u64> = HashMap::new();

    let outcome = event_loop(
        epfd,
        fan_fd,
        core,
        writer,
        pool,
        sink,
        completion_rx,
        stop_fd,
        wake_fd,
        pending_events,
        pending_table,
        &mut in_flight,
    );

    // Unblock every reader regardless of why the loop exited. This must run on
    // the fatal path too: `run` returns the fd to the caller, which then
    // unmounts and drops it — and a still-blocked reader would wedge that
    // unmount, after which the fail-open fd drop would corrupt a live mount.
    shutdown_cleanup(
        fan_fd,
        writer,
        completion_rx,
        pending_events,
        pending_table,
        &mut in_flight,
    );
    outcome
}

/// The epoll loop. Returns `Ok(())` when the stop signal arrives, `Err` on any
/// fatal condition. Never runs teardown itself — [`coordinate`] does that after,
/// so clean and fatal exits share one cleanup path.
#[allow(clippy::too_many_arguments)]
fn event_loop(
    epfd: RawFd,
    fan_fd: RawFd,
    core: &Arc<FanotifyCore>,
    writer: &Arc<dyn ResponseWriter>,
    pool: &FetchPool,
    sink: &Arc<CompletionSink>,
    completion_rx: &mpsc::Receiver<Completion>,
    stop_fd: RawFd,
    wake_fd: RawFd,
    pending_events: &mut HashMap<u64, PendingEvent>,
    pending_table: &mut PendingTable,
    in_flight: &mut HashMap<FetchKey, u64>,
) -> Result<()> {
    let mut buffer = vec![0u8; EVENT_BUFFER_SIZE];
    let mut events = vec![
        libc::epoll_event { events: 0, u64: 0 },
        libc::epoll_event { events: 0, u64: 0 },
        libc::epoll_event { events: 0, u64: 0 },
    ];

    loop {
        // Block until a fanotify event, a completion wakeup (eventfd), or the
        // stop signal. A completing fetch writes the eventfd, so there is no
        // idle poll timer and no wake latency.
        let nfds = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 3, -1) };
        if nfds < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err).context("epoll_wait");
        }

        for ev in events.iter().take(nfds as usize) {
            let fd = ev.u64 as RawFd;

            if fd == stop_fd {
                debug!("fanotify: stop signal received; entering shutdown");
                return Ok(());
            }

            if fd == wake_fd {
                // Reset the eventfd counter; the completions are drained after
                // the fd loop. Reading before draining avoids a lost wakeup.
                let mut drain_buf = [0u8; 8];
                let _ =
                    unsafe { libc::read(wake_fd, drain_buf.as_mut_ptr() as *mut libc::c_void, 8) };
            }

            if fd == fan_fd && ev.events & EPOLLIN != 0 {
                match read_events(fan_fd, &mut buffer) {
                    Ok(0) => {} // EAGAIN: no events
                    Ok(n) => admit_batch(
                        core,
                        writer,
                        pool,
                        sink,
                        &buffer[..n],
                        pending_events,
                        pending_table,
                        in_flight,
                    )?,
                    Err(err) => return Err(err).context("failed to read fanotify events"),
                }
            }
        }

        // Drain completions (non-blocking).
        drain_completions(completion_rx, pending_events, pending_table, in_flight)?;
    }
}

/// Best-effort teardown: deny every outstanding permission event and drain the
/// kernel queue so no reader stays blocked. Runs after the loop exits for any
/// reason; failures are logged, not propagated, because the caller still needs
/// to unmount and the fetch group's fail-open will cover any true residue.
fn shutdown_cleanup(
    fan_fd: RawFd,
    writer: &Arc<dyn ResponseWriter>,
    completion_rx: &mpsc::Receiver<Completion>,
    pending_events: &mut HashMap<u64, PendingEvent>,
    pending_table: &mut PendingTable,
    in_flight: &mut HashMap<FetchKey, u64>,
) {
    if let Err(err) = deny_undecided(pending_events, pending_table, in_flight) {
        warn!("fanotify: denying outstanding events during shutdown failed: {err:#}");
    }
    // In-flight fetches may still be completing; answer them so their readers
    // unblock too.
    if let Err(err) = drain_completions(completion_rx, pending_events, pending_table, in_flight) {
        warn!("fanotify: draining completions during shutdown failed: {err:#}");
    }
    if let Err(err) = drain_kernel_queue(fan_fd, writer) {
        warn!("fanotify: draining kernel queue during shutdown failed: {err:#}");
    }
}

fn drain_completions(
    rx: &mpsc::Receiver<Completion>,
    pending_events: &mut HashMap<u64, PendingEvent>,
    pending_table: &mut PendingTable,
    in_flight: &mut HashMap<FetchKey, u64>,
) -> Result<()> {
    loop {
        match rx.try_recv() {
            Ok(completion) => {
                handle_completion(completion, pending_events, pending_table, in_flight)?
            }
            Err(TryRecvError::Empty) => return Ok(()),
            Err(TryRecvError::Disconnected) => {
                return Err(anyhow!("fanotify completion channel closed unexpectedly"))
            }
        }
    }
}

// ---- batch admission ----

#[allow(clippy::too_many_arguments)]
fn admit_batch(
    core: &Arc<FanotifyCore>,
    writer: &Arc<dyn ResponseWriter>,
    pool: &FetchPool,
    sink: &Arc<CompletionSink>,
    bytes: &[u8],
    pending_events: &mut HashMap<u64, PendingEvent>,
    pending_table: &mut PendingTable,
    in_flight: &mut HashMap<FetchKey, u64>,
) -> Result<()> {
    for parsed in EventIter::new(bytes) {
        let event = match parsed {
            Ok(event) if event.is_overflow() => {
                return Err(anyhow!("fanotify queue overflow; stopping fail-closed"));
            }
            Ok(event) => event,
            Err(err) => {
                // Deny the offending event's fd when the metadata was intact
                // enough to extract it, so that one reader unblocks either way.
                if let Some(fd) = err.event_fd() {
                    if let Ok(owned) = owned_event_fd(fd) {
                        let mut permission = PendingPermission::new(owned, writer.clone());
                        respond(&mut permission, Response::Deny)?;
                    }
                }
                if err.is_recoverable() {
                    // The event's length was validated, so the next event's
                    // boundary is known: deny just this unusable event and keep
                    // serving the batch. One malformed event no longer takes the
                    // whole daemon down and strands every other blocked reader.
                    warn!(
                        "fanotify: denying and skipping unusable event at offset {}: {:?}",
                        err.offset, err.kind
                    );
                    continue;
                }
                // Structural corruption: the remaining bytes cannot be trusted
                // as event boundaries, so stop fail-closed.
                warn!(
                    "fanotify: batch corruption at offset {}: {:?}; stopping fail-closed",
                    err.offset, err.kind
                );
                return Err(anyhow!(
                    "fanotify batch parse error at offset {}: {:?}; stopping fail-closed",
                    err.offset,
                    err.kind
                ));
            }
        };

        admit_event(
            core,
            writer,
            pool,
            sink,
            event,
            pending_events,
            pending_table,
            in_flight,
        )?;
    }
    Ok(())
}

// ---- single-event admission ----

#[allow(clippy::too_many_arguments)]
fn admit_event(
    core: &Arc<FanotifyCore>,
    writer: &Arc<dyn ResponseWriter>,
    pool: &FetchPool,
    sink: &Arc<CompletionSink>,
    event: PreContentEvent,
    pending_events: &mut HashMap<u64, PendingEvent>,
    pending_table: &mut PendingTable,
    in_flight: &mut HashMap<FetchKey, u64>,
) -> Result<()> {
    let mut permission = PendingPermission::new(owned_event_fd(event.fd)?, writer.clone());
    let range = match decide(&event) {
        Decision::Fill(range) => range,
        Decision::Deny(reason) => {
            warn!("fanotify: immediate deny: {reason:?}");
            respond(&mut permission, Response::Deny)?;
            return Ok(());
        }
    };

    let (dev, ino) = match fd_identity(permission.event_fd()) {
        Ok(identity) => identity,
        Err(err) => {
            warn!("fanotify: fstat event fd failed: {err:#}");
            respond(&mut permission, Response::Deny)?;
            return Ok(());
        }
    };
    let Some(device) = core.device_for(dev, ino) else {
        warn!(
            "fanotify: {:?}: unknown event fd",
            DenyReason::UnknownDevice
        );
        respond(&mut permission, Response::Deny)?;
        return Ok(());
    };
    if device.is_redirect {
        warn!(
            "fanotify: {:?}: redirect slot {} received a data read",
            DenyReason::RedirectRead,
            device.index
        );
        respond(&mut permission, Response::Deny)?;
        return Ok(());
    }

    let (offset, count) = match align_fetch_range(range.offset, range.count, device.cache_size) {
        Ok(range) => range,
        Err(err) => {
            warn!("fanotify: {:?}: {err:?}", DenyReason::InvalidRange);
            respond(&mut permission, Response::Deny)?;
            return Ok(());
        }
    };
    match core.range_ready(&device.id, offset, count) {
        Ok(true) => {
            debug!(
                "fanotify: range [{}, +{}) already ready for blob {}; allowing immediately",
                offset, count, device.id
            );
            respond(&mut permission, Response::Allow)?;
            return Ok(());
        }
        Ok(false) => {}
        Err(err) => {
            warn!("fanotify: ready-range lookup failed: {err:#}");
            respond(&mut permission, Response::Deny)?;
            return Ok(());
        }
    }

    // Coalesce: if an identical (blob, offset, count) fetch is already in
    // flight, attach this reader to it rather than dispatch a duplicate. Safe
    // because completions are processed only between batches, never mid-batch,
    // so any job found in `in_flight` here is still pending.
    let key: FetchKey = (device.id, offset, count);
    if let Some(&job_id) = in_flight.get(&key) {
        match pending_events.get_mut(&job_id) {
            Some(entry) => {
                entry.waiters.push(permission);
                debug!(
                    "fanotify: coalesced read into job {}: blob {} range [{}, +{})",
                    job_id, device.id, offset, count
                );
                return Ok(());
            }
            None => return Err(anyhow!("in-flight key maps to missing job {job_id}")),
        }
    }

    let job_id = pending_table.admit();

    let id = device.id;
    let cache_size = device.cache_size;
    let core = Arc::clone(core);
    let sink = Arc::clone(sink);
    pool.execute(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.fetch(&id, cache_size, offset, count)
        }));
        let result = match result {
            Ok(fetch_result) => CompletionResult::Fetch(fetch_result),
            Err(_) => CompletionResult::Panicked,
        };
        sink.complete(job_id, result);
    });

    let previous = pending_events.insert(
        job_id,
        PendingEvent {
            key,
            waiters: vec![permission],
        },
    );
    if previous.is_some() {
        return Err(anyhow!("duplicate fanotify job id {job_id}"));
    }
    in_flight.insert(key, job_id);
    debug!(
        "fanotify: job {} dispatched: blob {} range [{}, +{})",
        job_id, device.id, offset, count
    );
    Ok(())
}

// ---- completion ----

fn handle_completion(
    completion: Completion,
    pending_events: &mut HashMap<u64, PendingEvent>,
    pending_table: &mut PendingTable,
    in_flight: &mut HashMap<FetchKey, u64>,
) -> Result<()> {
    match pending_table.on_completion(completion.job_id) {
        CompletionAction::Decide => {
            let mut event = pending_events.remove(&completion.job_id).ok_or_else(|| {
                anyhow!("completion has no permission event: {}", completion.job_id)
            })?;
            in_flight.remove(&event.key);
            let decision = match completion.result {
                CompletionResult::Fetch(Ok(())) => {
                    debug!(
                        "fanotify: job {} fetch succeeded; allowing",
                        completion.job_id
                    );
                    Response::Allow
                }
                CompletionResult::Fetch(Err(FetchError::Backend(err))) => {
                    warn!("fanotify fetch backend failure: {err:#}");
                    Response::Deny
                }
                CompletionResult::Panicked => {
                    warn!("fanotify fetch worker panicked");
                    Response::Deny
                }
            };
            // Every reader coalesced onto this range gets the same answer.
            for permission in &mut event.waiters {
                respond(permission, decision)?;
            }
            Ok(())
        }
        CompletionAction::Late => {
            debug!(
                "fanotify: late completion for job {}; response already denied",
                completion.job_id
            );
            Ok(())
        }
        CompletionAction::Unknown => Err(anyhow!(
            "unknown or duplicate fanotify completion for job {}",
            completion.job_id
        )),
    }
}

// ---- shutdown ----

fn deny_undecided(
    pending_events: &mut HashMap<u64, PendingEvent>,
    pending_table: &mut PendingTable,
    in_flight: &mut HashMap<FetchKey, u64>,
) -> Result<()> {
    for job_id in pending_table.take_undecided() {
        if let Some(mut event) = pending_events.remove(&job_id) {
            in_flight.remove(&event.key);
            // Deny every reader coalesced onto this job. The kernel's fail-open
            // on group close covers any residue past a fatal respond error.
            for permission in &mut event.waiters {
                respond(permission, Response::Deny)?;
            }
        }
    }
    Ok(())
}

/// Deny-drain every event currently queued on the fanotify fd. For the caller
/// of [`FanotifyService::run`] to use between unmount retries during shutdown,
/// after the event loop has exited: a reader that faults in that window must
/// get a deny (`EPERM`) instead of blocking forever and wedging the unmount.
pub fn deny_queued_events(fan_fd: &Arc<OwnedFd>) -> Result<()> {
    let writer: Arc<dyn ResponseWriter> = Arc::new(FdResponseWriter::new(fan_fd.clone()));
    drain_kernel_queue(fan_fd.as_raw_fd(), &writer)
}

fn drain_kernel_queue(fan_fd: RawFd, writer: &Arc<dyn ResponseWriter>) -> Result<()> {
    let mut buffer = vec![0u8; EVENT_BUFFER_SIZE];
    loop {
        match read_events(fan_fd, &mut buffer) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                for parsed in EventIter::new(&buffer[..n]) {
                    match parsed {
                        Ok(event) if event.is_overflow() => {
                            return Err(anyhow!("fanotify queue overflow during shutdown drain"));
                        }
                        Ok(event) => {
                            let fd = owned_event_fd(event.fd)?;
                            let mut permission = PendingPermission::new(fd, writer.clone());
                            permission.decide(Response::Deny)?;
                            while !permission.try_submit()? {
                                thread::yield_now();
                            }
                        }
                        Err(err) => {
                            if let Some(fd) = err.event_fd() {
                                if let Ok(owned) = owned_event_fd(fd) {
                                    let mut permission =
                                        PendingPermission::new(owned, writer.clone());
                                    permission.decide(Response::Deny)?;
                                    while !permission.try_submit()? {
                                        thread::yield_now();
                                    }
                                }
                            }
                            return Err(anyhow!(
                                "fanotify parse error during shutdown drain at offset {}: {:?}",
                                err.offset,
                                err.kind
                            ));
                        }
                    }
                }
            }
            Err(err) => {
                return Err(err).context("failed to read fanotify events during shutdown drain");
            }
        }
    }
}

// ---- response helpers ----

fn respond(permission: &mut PendingPermission, response: Response) -> Result<()> {
    permission.decide(response)?;
    while !permission.try_submit()? {
        thread::yield_now();
    }
    Ok(())
}

fn owned_event_fd(fd: RawFd) -> Result<OwnedFd> {
    if fd < 0 {
        return Err(anyhow!("invalid fanotify event fd {fd}"));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn read_events(fan_fd: RawFd, buffer: &mut [u8]) -> std::io::Result<usize> {
    loop {
        let read = unsafe {
            libc::read(
                fan_fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
            )
        };
        if read >= 0 {
            return Ok(read as usize);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if err.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(0);
        }
        return Err(err);
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Mutex;

    use super::*;

    /// Records every (fd, decision) written, and reports each write as the
    /// full-size success `PendingPermission` expects.
    #[derive(Default)]
    struct RecordWriter {
        calls: Mutex<Vec<(RawFd, Response)>>,
    }

    impl ResponseWriter for RecordWriter {
        fn write_response(&self, event_fd: RawFd, decision: Response) -> io::Result<usize> {
            self.calls.lock().unwrap().push((event_fd, decision));
            // size_of::<fanotify_response>() = i32 + u32 = 8; a full write.
            Ok(8)
        }
    }

    fn eventfd() -> OwnedFd {
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        assert!(fd >= 0, "eventfd: {}", io::Error::last_os_error());
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    fn perm(writer: &Arc<dyn ResponseWriter>) -> PendingPermission {
        PendingPermission::new(eventfd(), writer.clone())
    }

    fn key() -> FetchKey {
        (BlobID::from_str(&format!("{:064x}", 7)).unwrap(), 0, 4096)
    }

    /// Two readers coalesced onto one job both receive the fetch's decision.
    #[test]
    fn completion_answers_all_coalesced_waiters() {
        let rec: Arc<RecordWriter> = Arc::new(RecordWriter::default());
        let w: Arc<dyn ResponseWriter> = rec.clone();
        let mut pending_events = HashMap::new();
        let mut table = PendingTable::new();
        let mut in_flight = HashMap::new();

        let job = table.admit();
        pending_events.insert(
            job,
            PendingEvent {
                key: key(),
                waiters: vec![perm(&w), perm(&w)],
            },
        );
        in_flight.insert(key(), job);

        handle_completion(
            Completion {
                job_id: job,
                result: CompletionResult::Fetch(Ok(())),
            },
            &mut pending_events,
            &mut table,
            &mut in_flight,
        )
        .unwrap();

        let calls = rec.calls.lock().unwrap();
        assert_eq!(calls.len(), 2, "both waiters answered");
        assert!(calls.iter().all(|(_, d)| *d == Response::Allow));
        assert!(pending_events.is_empty());
        assert!(in_flight.is_empty(), "coalescing index cleared");
    }

    /// A backend failure denies every coalesced reader, not just the leader.
    #[test]
    fn completion_backend_failure_denies_all_waiters() {
        let rec: Arc<RecordWriter> = Arc::new(RecordWriter::default());
        let w: Arc<dyn ResponseWriter> = rec.clone();
        let mut pending_events = HashMap::new();
        let mut table = PendingTable::new();
        let mut in_flight = HashMap::new();

        let job = table.admit();
        pending_events.insert(
            job,
            PendingEvent {
                key: key(),
                waiters: vec![perm(&w), perm(&w), perm(&w)],
            },
        );
        in_flight.insert(key(), job);

        handle_completion(
            Completion {
                job_id: job,
                result: CompletionResult::Fetch(Err(FetchError::Backend(anyhow!("boom")))),
            },
            &mut pending_events,
            &mut table,
            &mut in_flight,
        )
        .unwrap();

        let calls = rec.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert!(calls.iter().all(|(_, d)| *d == Response::Deny));
    }

    /// Shutdown denies every coalesced reader and clears both indexes.
    #[test]
    fn shutdown_denies_all_coalesced_waiters() {
        let rec: Arc<RecordWriter> = Arc::new(RecordWriter::default());
        let w: Arc<dyn ResponseWriter> = rec.clone();
        let mut pending_events = HashMap::new();
        let mut table = PendingTable::new();
        let mut in_flight = HashMap::new();

        let job = table.admit();
        pending_events.insert(
            job,
            PendingEvent {
                key: key(),
                waiters: vec![perm(&w), perm(&w)],
            },
        );
        in_flight.insert(key(), job);

        deny_undecided(&mut pending_events, &mut table, &mut in_flight).unwrap();

        let calls = rec.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert!(calls.iter().all(|(_, d)| *d == Response::Deny));
        assert!(pending_events.is_empty());
        assert!(in_flight.is_empty());
    }

    /// A fetch that completes after shutdown already denied the event is a
    /// no-op: the reader is answered exactly once (the shutdown deny).
    #[test]
    fn late_completion_after_shutdown_is_noop() {
        let rec: Arc<RecordWriter> = Arc::new(RecordWriter::default());
        let w: Arc<dyn ResponseWriter> = rec.clone();
        let mut pending_events = HashMap::new();
        let mut table = PendingTable::new();
        let mut in_flight = HashMap::new();

        let job = table.admit();
        pending_events.insert(
            job,
            PendingEvent {
                key: key(),
                waiters: vec![perm(&w)],
            },
        );
        in_flight.insert(key(), job);

        deny_undecided(&mut pending_events, &mut table, &mut in_flight).unwrap();
        // Fetch finishes late; the pending table still holds the job as decided.
        handle_completion(
            Completion {
                job_id: job,
                result: CompletionResult::Fetch(Ok(())),
            },
            &mut pending_events,
            &mut table,
            &mut in_flight,
        )
        .unwrap();

        let calls = rec.calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "answered once, by the shutdown deny");
        assert_eq!(calls[0].1, Response::Deny);
    }
}
