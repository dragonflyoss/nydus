use nydus_error::{Context, Error, Result};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::fs::File;
use std::io::{self, IoSlice, Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use super::proto::{
    encode_reply, Request, NBD_CMD_WRITE, NBD_EINVAL, NBD_EIO, NBD_OK, NBD_REQUEST_HEADER_SIZE,
};
use super::{netlink, NbdCore};
use crate::continuity::ownership::SessionOwner;
use crate::continuity::wire::MAX_TRANSFER_FDS;
use crate::pool::FetchPool;

/// The largest read a request may ask for.
const MAX_READ_LEN: usize = 4 * 1024 * 1024;

/// The most connections of one session: a hot upgrade passes them all in one transfer.
const MAX_CONNECTIONS: usize = MAX_TRANSFER_FDS;

/// How often a waiting loop checks its condition again.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// How long a repair waits after a failed attachment before trying again.
const REPAIR_RETRY: Duration = Duration::from_secs(5);

/// How long a release waits for the parked workers to exit.
const RELEASE_TIMEOUT: Duration = Duration::from_secs(5);

/// The kernel session settings, persisted and inherited instead of reconstructed from restart flags.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NbdOptions {
    /// The number of kernel connections, one worker each.
    pub connections: usize,

    /// The seconds the kernel waits for one reply before retrying the request.
    pub timeout_secs: u64,

    /// The seconds new I/O waits for a replacement connection when none is alive.
    pub dead_conn_timeout_secs: u64,
}

/// Implements the kernel session settings.
impl NbdOptions {
    /// Checks that the settings fit the netlink attributes.
    pub(crate) fn validate(&self) -> Result<()> {
        if self.connections == 0 || self.connections > MAX_CONNECTIONS {
            return Err(Error::InvalidParameter(format!(
                "NBD connection count {} must be between 1 and {MAX_CONNECTIONS}",
                self.connections
            )));
        }
        if self.timeout_secs == 0 || self.timeout_secs > u32::MAX.into() {
            return Err(Error::InvalidParameter(format!(
                "invalid NBD request timeout {}",
                self.timeout_secs
            )));
        }
        if self.dead_conn_timeout_secs > u32::MAX.into() {
            return Err(Error::InvalidParameter(format!(
                "NBD dead-connection timeout {} must be at most {} seconds",
                self.dead_conn_timeout_secs,
                u32::MAX
            )));
        }
        Ok(())
    }
}

/// The lifecycle of a worker pool.
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum Mode {
    /// The workers serve requests.
    Running,

    /// The workers hold their connections without reading them, for a handoff.
    Paused,

    /// The workers exit and leave their connections open for the daemon that took them over.
    Detached,

    /// The workers exit and close their connections.
    Stopped,
}

/// The state shared by the workers of one pool and the session control.
pub(crate) struct NbdService {
    /// The current [Mode] of the pool.
    mode: AtomicU8,

    /// The eventfd that interrupts every worker waiting for a request.
    wake: File,

    /// The number of workers that have not exited.
    live: AtomicUsize,

    /// Whether the kernel explicitly requested session disconnect.
    disconnect_requested: AtomicBool,

    /// The lifetime ownership, held until the workers of a released pool have exited.
    pub(crate) owner: Mutex<Option<SessionOwner>>,

    /// A duplicate of the connection of every worker a pause parked.
    parked: Mutex<Vec<OwnedFd>>,

    /// The condition signalled when the pool leaves [Mode::Paused].
    resumed: Condvar,
}

/// Implements the shared worker state.
impl NbdService {
    /// Returns whether the pool is in `mode`.
    fn is(&self, mode: Mode) -> bool {
        self.mode.load(Ordering::SeqCst) == mode as u8
    }

    /// Moves the pool to `mode` and wakes every worker, whether it waits for a request or
    /// is parked.
    fn enter(&self, mode: Mode) -> Result<()> {
        // Change the mode under the lock a parking worker holds, so that it cannot miss the
        // change.
        let mut parked = self.parked.lock().unwrap();
        self.mode.store(mode as u8, Ordering::SeqCst);
        self.resumed.notify_all();
        if !matches!(mode, Mode::Paused) {
            parked.clear();
        }
        if !matches!(mode, Mode::Running) {
            return (&self.wake)
                .write_all(&1u64.to_ne_bytes())
                .context("failed to wake NBD workers");
        }

        // Rearm the wakeup, so that the resumed workers wait for requests again.
        match (&self.wake).read(&mut [0; 8]) {
            Err(err) if err.kind() != io::ErrorKind::WouldBlock => {
                Err(err).context("failed to rearm the NBD worker wakeup")
            }
            _ => Ok(()),
        }
    }

    /// Parks every worker once the reads it dispatched are answered, and returns a
    /// duplicate of each parked connection.
    ///
    /// The kernel keeps queueing requests on a parked connection, so neither a request nor
    /// a reply is lost: whoever reads the connection next continues both streams. The
    /// caller resumes the pool when this fails.
    pub(crate) fn pause(&self, timeout: Duration) -> Result<Vec<OwnedFd>> {
        self.enter(Mode::Paused)?;
        let deadline = Instant::now() + timeout;
        loop {
            let mut parked = self.parked.lock().unwrap();
            if parked.len() == self.live.load(Ordering::SeqCst) {
                return Ok(std::mem::take(&mut *parked));
            }
            drop(parked);
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "NBD reads in flight did not finish in time to pause the connections",
                )
                .into());
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// Lets the parked workers serve again.
    pub(crate) fn resume(&self) -> Result<()> {
        self.enter(Mode::Running)
    }

    /// Leaves the parked connections to the successor that took them over, then gives up
    /// lifetime ownership.
    pub(crate) fn release(&self) -> Result<()> {
        self.enter(Mode::Detached)?;
        let deadline = Instant::now() + RELEASE_TIMEOUT;
        while self.live.load(Ordering::SeqCst) != 0 {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "NBD workers did not exit after handing their connections over",
                )
                .into());
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        self.owner.lock().unwrap().take();
        Ok(())
    }
}

/// The worker pool of one kernel session.
///
/// Dropping it closes only this process's connections, never the device.
pub(crate) struct NbdSession {
    /// The state shared with the workers and the session control.
    pub(crate) service: Arc<NbdService>,

    /// The `/dev/nbd<N>` index.
    pub(crate) index: u32,

    /// The connection count and timeouts of the kernel session.
    options: NbdOptions,

    /// The backend identity registered with the kernel.
    backend: String,

    /// The image the workers read from.
    core: Arc<NbdCore>,

    /// The threads that serve the reads of every connection concurrently.
    pool: Arc<FetchPool>,

    /// The worker threads not joined yet.
    workers: Vec<JoinHandle<Result<()>>>,

    /// The repair attachment whose netlink call has not been settled yet.
    attachment: Option<Attachment>,

    /// When the next repair may start.
    retry_at: Instant,
}

/// A repair attachment whose RECONFIGURE runs off the serve loop.
///
/// The kernel call cannot be cancelled, so a call blocked in the kernel only delays the
/// repair; the serve loop keeps answering signals and releases meanwhile.
struct Attachment {
    /// The netlink call, which hands back the kernel ends once the kernel answered.
    call: JoinHandle<(Vec<OwnedFd>, Result<()>)>,

    /// The user ends of the offered connections.
    users: Vec<Arc<UnixStream>>,

    /// When the call started.
    started: Instant,

    /// Whether a slow call was reported.
    reported: bool,
}

/// Implements the worker pool.
impl NbdSession {
    /// Creates a pool without connections, whose reads run on `pool`.
    pub(crate) fn new(
        core: Arc<NbdCore>,
        pool: Arc<FetchPool>,
        index: u32,
        options: NbdOptions,
        backend: String,
    ) -> Result<Self> {
        // SAFETY: eventfd accepts integer arguments and the returned fd is checked.
        let wake = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if wake < 0 {
            return Err(io::Error::last_os_error()).context("failed to create NBD worker wakeup");
        }

        // SAFETY: eventfd returned a fresh descriptor owned by this state.
        let wake = unsafe { File::from_raw_fd(wake) };
        Ok(Self {
            service: Arc::new(NbdService {
                mode: AtomicU8::new(Mode::Running as u8),
                wake,
                live: AtomicUsize::new(0),
                disconnect_requested: AtomicBool::new(false),
                owner: Mutex::new(None),
                parked: Mutex::new(Vec::new()),
                resumed: Condvar::new(),
            }),
            index,
            options,
            backend,
            core,
            pool,
            workers: Vec::new(),
            attachment: None,
            retry_at: Instant::now(),
        })
    }

    /// Starts `count` workers on fresh socket pairs, returning each kernel end with its user end.
    pub(crate) fn start(&mut self, count: usize) -> Result<Vec<(OwnedFd, Arc<UnixStream>)>> {
        (0..count)
            .map(|_| {
                let (kernel, user) =
                    UnixStream::pair().context("failed to create NBD socket pair")?;
                let user = Arc::new(user);
                self.workers.push(NbdWorker::spawn(
                    &self.core,
                    &self.pool,
                    &self.service,
                    user.clone(),
                )?);
                Ok((kernel.into(), user))
            })
            .collect()
    }

    /// Takes over the connections a predecessor parked, holding them parked until the pool
    /// resumes.
    pub(crate) fn adopt(&mut self, sockets: Vec<OwnedFd>) -> Result<()> {
        self.service.enter(Mode::Paused)?;
        for socket in sockets {
            self.workers.push(NbdWorker::spawn(
                &self.core,
                &self.pool,
                &self.service,
                Arc::new(socket.into()),
            )?);
        }
        Ok(())
    }

    /// Creates the kernel session over fresh connections.
    ///
    /// The workers start first, because the kernel may use a connection before CONNECT returns.
    pub(crate) fn connect(&mut self, size: u64) -> Result<()> {
        let connections = self.start(self.options.connections)?;
        let kernels: Vec<_> = connections
            .iter()
            .map(|(kernel, _)| kernel.as_fd())
            .collect();
        netlink::connect_device(self.index, size, &self.options, &self.backend, &kernels)
    }

    /// Attaches up to `count` fresh connections to dead kernel slots, returning how many the
    /// kernel kept.
    ///
    /// The kernel silently ignores a socket when no slot is dead. Dropping our copy of the
    /// kernel end then closes the connection, which tells the two outcomes apart.
    pub(crate) fn attach(&mut self, count: usize) -> Result<usize> {
        let (kernels, users): (Vec<_>, Vec<_>) = self.start(count)?.into_iter().unzip();

        // Check the mode only now that the workers count as live, so that a concurrent
        // handoff either stops the attachment here or parks the workers it started.
        if self.service.is(Mode::Running) {
            reconfigure(self.index, &self.options, &self.backend, &kernels)?;
        }
        kept(kernels, &users)
    }

    /// Joins the workers that exited and reattaches the connections the kernel closed.
    ///
    /// The kernel closes a connection when a request times out, and a retired kernel
    /// receiver can also close the connection that replaced it: Linux `recv_work` marks its
    /// slot dead again on exit without checking which socket the slot now holds. No process
    /// can observe that receiver, so every loss is repaired instead of assuming it exited.
    /// A replacement the kernel ignores because its slot is not dead yet is retried by the
    /// next call.
    ///
    /// The RECONFIGURE runs on its own thread, because netlink runs the command inside the
    /// sending call and the kernel can block it on a lock no deadline interrupts. A failed
    /// attachment only defers the next one: the remaining connections keep
    /// serving, so only a worker failure is an error.
    pub(crate) fn repair(&mut self) -> Result<()> {
        if self.workers.iter().any(JoinHandle::is_finished) {
            let (exited, serving): (Vec<_>, Vec<_>) = std::mem::take(&mut self.workers)
                .into_iter()
                .partition(JoinHandle::is_finished);
            self.workers = serving;
            Self::join(exited)?;
        }

        if let Some(attachment) = self.attachment.as_mut().filter(|a| !a.call.is_finished()) {
            if !attachment.reported && attachment.started.elapsed() >= netlink::NETLINK_TIMEOUT {
                attachment.reported = true;
                warn!(
                    "nbd: NBD_CMD_RECONFIGURE has not returned after {:?}; serving on the remaining connections",
                    netlink::NETLINK_TIMEOUT
                );
            }
            return Ok(());
        }
        if let Some(attachment) = self.attachment.take() {
            self.settle(attachment)?;
        }

        let live = self.service.live.load(Ordering::SeqCst);
        let missing = self.options.connections.saturating_sub(live);
        if missing == 0
            || !self.service.is(Mode::Running)
            || self.disconnect_requested()
            || Instant::now() < self.retry_at
        {
            return Ok(());
        }
        let (kernels, users): (Vec<_>, Vec<_>) = match self.start(missing) {
            Ok(connections) => connections.into_iter().unzip(),
            Err(err) => {
                self.defer(missing, err);
                return Ok(());
            }
        };

        // As in `attach`, a handoff that began after the workers started stops the attachment;
        // dropping the kernel ends closes their connections.
        if !self.service.is(Mode::Running) {
            return Ok(());
        }
        let (index, options, backend) = (self.index, self.options.clone(), self.backend.clone());
        let call = std::thread::Builder::new()
            .name("nydus_nbd_attach".into())
            .spawn(move || {
                let called = reconfigure(index, &options, &backend, &kernels);
                (kernels, called)
            })
            .context("failed to spawn NBD attachment");
        match call {
            Ok(call) => {
                self.attachment = Some(Attachment {
                    call,
                    users,
                    started: Instant::now(),
                    reported: false,
                })
            }
            Err(err) => self.defer(users.len(), err),
        }
        Ok(())
    }

    /// Counts the connections a finished repair attachment kept, deferring a retry after a failure.
    fn settle(&mut self, attachment: Attachment) -> Result<()> {
        let (kernels, called) = attachment.call.join().unwrap_or_else(|_| {
            (
                Vec::new(),
                Err(Error::Runtime("NBD attachment panicked".into())),
            )
        });
        let kept = kept(kernels, &attachment.users)?;
        if kept != 0 {
            info!("nbd: reattached {} connections the kernel closed", kept);
        }
        if let Err(err) = called {
            self.defer(attachment.users.len(), err);
        }
        Ok(())
    }

    /// Defers the next repair after failing to attach `count` connections.
    fn defer(&mut self, count: usize, err: Error) {
        self.retry_at = Instant::now() + REPAIR_RETRY;
        warn!(
            "nbd: failed to reattach {} lost connections, retrying in {:?}: {}",
            count,
            REPAIR_RETRY,
            err.report()
        );
    }

    /// Waits for `workers` and returns the first failure.
    fn join(workers: impl IntoIterator<Item = JoinHandle<Result<()>>>) -> Result<()> {
        let mut failure = None;
        for thread in workers {
            let result = thread
                .join()
                .map_err(|_| Error::Runtime("NBD worker panicked".into()))
                .and_then(|result| result);
            if let Err(err) = result {
                if failure.is_none() {
                    failure = Some(err);
                } else {
                    warn!("additional NBD worker failure: {}", err.report());
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }

    /// Stops the workers, closing their connections, and waits for them.
    pub(crate) fn cancel(&mut self) -> Result<()> {
        let stopped = self.service.enter(Mode::Stopped);
        combine(stopped, Self::join(self.workers.drain(..)))
    }

    /// Stops the workers without closing connections another daemon still holds, and waits
    /// for them.
    pub(crate) fn detach(&mut self) -> Result<()> {
        let detached = self.service.enter(Mode::Detached);
        combine(detached, Self::join(self.workers.drain(..)))
    }

    /// Returns whether the kernel requested disconnect.
    pub(crate) fn disconnect_requested(&self) -> bool {
        self.service.disconnect_requested.load(Ordering::Acquire)
    }

    /// Returns whether a release handed every connection over.
    pub(crate) fn is_released(&self) -> bool {
        self.service.is(Mode::Detached) && self.service.live.load(Ordering::SeqCst) == 0
    }
}

/// Implements stopping the workers on drop.
impl Drop for NbdSession {
    /// Stops the workers when the pool is dropped before it was joined.
    fn drop(&mut self) {
        if !self.workers.is_empty() {
            if let Err(err) = self.cancel() {
                warn!("failed to stop NBD workers: {}", err.report());
            }
        }
    }
}

/// Offers the kernel ends of fresh connections to the dead slots of the session.
///
/// Unit tests fail it as a kernel without the session would, so they never configure the
/// host's NBD.
fn reconfigure(index: u32, options: &NbdOptions, backend: &str, kernels: &[OwnedFd]) -> Result<()> {
    if cfg!(test) {
        return Err(Error::Runtime(
            "unit tests do not send NBD_CMD_RECONFIGURE".into(),
        ));
    }
    let sockets: Vec<_> = kernels.iter().map(AsFd::as_fd).collect();
    netlink::reconfigure_device(index, options, backend, &sockets)
}

/// Closes our copy of each kernel end and returns how many connections the kernel kept.
///
/// The kernel silently ignores a socket when no slot is dead, so a connection the kernel
/// did not keep closes with our copy.
fn kept(kernels: Vec<OwnedFd>, users: &[Arc<UnixStream>]) -> Result<usize> {
    drop(kernels);
    let mut kept = 0;
    for user in users {
        kept += usize::from(!peer_closed(user)?);
    }
    Ok(kept)
}

/// Combines two results, keeping the first error and attaching the second to it.
pub(crate) fn combine(first: Result<()>, second: Result<()>) -> Result<()> {
    match (first, second) {
        (Err(first), Err(second)) => {
            Err(first.context(format!("cleanup also failed: {}", second.report())))
        }
        (Err(err), _) | (_, Err(err)) => Err(err),
        _ => Ok(()),
    }
}

/// The worker serving one kernel connection.
struct NbdWorker {
    /// The state shared with the pool.
    service: Arc<NbdService>,

    /// The image requests are served from.
    core: Arc<NbdCore>,

    /// The user end of the connection.
    socket: Arc<UnixStream>,

    /// The threads that serve this connection's reads.
    pool: Arc<FetchPool>,

    /// The replies of the requests this worker read.
    replies: Arc<Replies>,
}

/// Implements the per-connection worker.
impl NbdWorker {
    /// Spawns a worker that serves `socket`.
    fn spawn(
        core: &Arc<NbdCore>,
        pool: &Arc<FetchPool>,
        service: &Arc<NbdService>,
        socket: Arc<UnixStream>,
    ) -> Result<JoinHandle<Result<()>>> {
        service.live.fetch_add(1, Ordering::SeqCst);
        let worker = Self {
            service: service.clone(),
            core: core.clone(),
            pool: pool.clone(),
            replies: Arc::new(Replies::new(socket.clone())),
            socket,
        };
        std::thread::Builder::new()
            .name("nydus_nbd_worker".into())
            .spawn(move || worker.run())
            .context("failed to spawn NBD worker")
    }

    /// Serves the connection until it closes or the pool stops.
    fn run(mut self) -> Result<()> {
        match self.run_loop() {
            Err(err) if Self::connection_closed(&err) => {
                debug!("nbd: connection closed: {}", err.report());
                Ok(())
            }
            result => result,
        }
    }

    /// Returns whether the error is a transport loss, which retires one connection, not the
    /// other workers or the kernel session.
    fn connection_closed(err: &Error) -> bool {
        err.io_error().is_some_and(|err| {
            matches!(
                err.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::NotConnected
            )
        })
    }

    /// Serves requests until the pool stops or the kernel disconnects, parking while the
    /// pool is paused.
    fn run_loop(&mut self) -> Result<()> {
        let mut header = [0; NBD_REQUEST_HEADER_SIZE];
        loop {
            if wait_for_request(&self.socket, &self.service.wake)? {
                if !self.park()? {
                    return Ok(());
                }
            } else if !self.serve_one(&mut header)? {
                return Ok(());
            }
        }
    }

    /// Holds the connection without reading it while the pool is paused; returns whether
    /// to serve again.
    ///
    /// The worker stops between two requests and waits for the reads it dispatched, so the
    /// request and reply streams are whole when another daemon continues them.
    fn park(&self) -> Result<bool> {
        while self.service.is(Mode::Paused) {
            if !self.replies.idle_within(POLL_INTERVAL) {
                continue;
            }
            if peer_closed(&self.socket)? {
                return Ok(false);
            }
            let socket = self
                .socket
                .try_clone()
                .context("failed to duplicate an NBD connection")?;
            let mut parked = self.service.parked.lock().unwrap();
            if self.service.is(Mode::Paused) {
                parked.push(socket.into());
            }
            while self.service.is(Mode::Paused) {
                parked = self.service.resumed.wait(parked).unwrap();
            }
        }
        Ok(self.service.is(Mode::Running))
    }

    /// Reads and dispatches one request; returns `false` on a disconnect request.
    ///
    /// Reads run on the pool, so a slow backend fetch does not hold up the requests
    /// queued behind it on this connection.
    fn serve_one(&mut self, header: &mut [u8; NBD_REQUEST_HEADER_SIZE]) -> Result<bool> {
        self.socket
            .as_ref()
            .read_exact(header)
            .context("failed to read NBD request")?;
        let request = Request::parse(header)
            .map_err(|err| Error::Protocol(format!("invalid NBD request: {err:?}")))?;
        if request.is_disc() {
            self.service
                .disconnect_requested
                .store(true, Ordering::Release);
            return Ok(false);
        }
        if request.ty == NBD_CMD_WRITE {
            return Err(Error::Protocol(
                "write request on read-only NBD device".into(),
            ));
        }
        self.replies.begin();
        let length = usize::try_from(request.len).unwrap_or(usize::MAX);
        if !request.is_read() {
            warn!("nbd: unsupported request type {}", request.ty);
            self.replies.send(request.handle, NBD_EINVAL, &[]);
        } else if length > MAX_READ_LEN || !request.is_block_aligned() {
            warn!(
                "nbd: invalid read offset {} length {}",
                request.offset, request.len
            );
            self.replies.send(request.handle, NBD_EINVAL, &[]);
        } else {
            let core = self.core.clone();
            let replies = self.replies.clone();
            self.pool
                .execute(move || read_and_reply(&core, &replies, &request, length));
        }
        Ok(true)
    }
}

/// Implements the worker exit accounting.
impl Drop for NbdWorker {
    /// Closes the connection and records the worker exit.
    fn drop(&mut self) {
        // Shut the socket down unless the daemon that took it over continues it: reads still
        // in flight keep it open, but the kernel retires the slot only once the reply stream
        // ends.
        if !self.service.is(Mode::Detached) {
            if let Err(err) = self.socket.shutdown(std::net::Shutdown::Both) {
                if err.kind() != io::ErrorKind::NotConnected {
                    warn!(
                        "nbd: failed to close an exited worker's connection: {}",
                        err
                    );
                }
            }
        }
        self.service.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serves one validated read on a pool thread and replies to it.
fn read_and_reply(core: &NbdCore, replies: &Replies, request: &Request, length: usize) {
    thread_local! {
        /// The reply buffer each pool thread reuses.
        static BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    }
    BUF.with_borrow_mut(|buf| {
        if buf.len() < length {
            buf.resize(length, 0);
        }
        match core.read_at(request.offset, &mut buf[..length]) {
            Ok(()) => replies.send(request.handle, NBD_OK, &buf[..length]),
            Err(err) => {
                warn!(
                    "nbd: read [{:#x}, +{}) failed: {}",
                    request.offset,
                    request.len,
                    err.report()
                );
                replies.send(request.handle, NBD_EIO, &[]);
            }
        }
    });
}

/// The replies of one connection, shared by its worker and the reads it dispatched.
struct Replies {
    /// The user end of the connection.
    socket: Arc<UnixStream>,

    /// The lock that serializes reply frames; the kernel matches out-of-order replies by
    /// handle.
    writer: Mutex<()>,

    /// The requests read but not yet answered.
    pending: Mutex<usize>,

    /// The condition signalled whenever a request is answered.
    answered: Condvar,
}

/// Implements the connection replies.
impl Replies {
    /// Creates the replies of a connection.
    fn new(socket: Arc<UnixStream>) -> Self {
        Self {
            socket,
            writer: Mutex::new(()),
            pending: Mutex::new(0),
            answered: Condvar::new(),
        }
    }

    /// Counts a request that will be answered.
    fn begin(&self) {
        *self.pending.lock().unwrap() += 1;
    }

    /// Writes the reply of a request.
    ///
    /// A reply that cannot be written closes the connection: the kernel then retries the
    /// requests it had sent on it.
    fn send(&self, handle: u64, code: u32, payload: &[u8]) {
        let _frame = self.writer.lock().unwrap();
        let written = writev_all(
            &mut self.socket.as_ref(),
            &encode_reply(code, handle),
            payload,
        );
        if let Err(err) = written {
            // Shut the connection down before the lock lets another reply follow the
            // partial frame, which desyncs the stream. This also stops the worker's intake.
            debug!("nbd: failed to write a reply: {}", err);
            if let Err(err) = self.socket.shutdown(std::net::Shutdown::Both) {
                debug!("nbd: failed to close a connection after its reply: {}", err);
            }
        }
        *self.pending.lock().unwrap() -= 1;
        self.answered.notify_all();
    }

    /// Returns whether every request is answered, waiting at most `timeout`.
    fn idle_within(&self, timeout: Duration) -> bool {
        let pending = self.pending.lock().unwrap();
        let (pending, _) = self
            .answered
            .wait_timeout_while(pending, timeout, |pending| *pending != 0)
            .unwrap();
        *pending == 0
    }
}

/// Writes the reply header and payload with vectored writes until both are sent.
fn writev_all(writer: &mut impl Write, mut header: &[u8], mut payload: &[u8]) -> io::Result<()> {
    while !header.is_empty() || !payload.is_empty() {
        match writer.write_vectored(&[IoSlice::new(header), IoSlice::new(payload)]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => {
                let head = written.min(header.len());
                header = &header[head..];
                payload = &payload[written - head..];
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// Waits until a request arrives or the pool wakes the worker, returning whether it was woken.
fn wait_for_request(socket: &UnixStream, wake: &File) -> io::Result<bool> {
    let mut fds = [
        libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: wake.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: fds is an initialized array of two live borrowed descriptors.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } >= 0 {
            return Ok(fds[1].revents != 0);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Returns the ready events of the socket without blocking.
fn poll_socket(socket: &UnixStream, events: i16) -> io::Result<i16> {
    let mut fd = libc::pollfd {
        fd: socket.as_raw_fd(),
        events,
        revents: 0,
    };
    loop {
        // SAFETY: fd is initialized and borrows a live socket for this poll.
        if unsafe { libc::poll(&mut fd, 1, 0) } >= 0 {
            return Ok(fd.revents);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Returns whether the connection is closed in both directions, by the kernel end or by a
/// local shutdown of both; shutting down only the read side does not count.
fn peer_closed(socket: &UnixStream) -> io::Result<bool> {
    Ok(poll_socket(socket, 0)? & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::nbd::proto::{NBD_CMD_DISC, NBD_CMD_READ, NBD_REPLY_HEADER_SIZE, NBD_REQUEST_MAGIC};

    pub(crate) fn test_pool() -> Arc<FetchPool> {
        Arc::new(FetchPool::new(4).unwrap())
    }

    pub(crate) fn test_session(root: &std::path::Path, pool: Arc<FetchPool>) -> NbdSession {
        let options = NbdOptions {
            connections: 2,
            timeout_secs: 15,
            dead_conn_timeout_secs: 60,
        };
        NbdSession::new(
            empty_core(root),
            pool,
            u32::MAX,
            options,
            "nydus:test".into(),
        )
        .unwrap()
    }

    pub(crate) fn empty_core(root: &std::path::Path) -> Arc<NbdCore> {
        use crate::build::{build_image, BuildImageOptions};
        use nydus_format::blob::BlobMetadataCompressor;
        use nydus_format::erofs::EROFS_BLOCK_SIZE;

        let source = root.join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("file"), vec![1; EROFS_BLOCK_SIZE as usize]).unwrap();
        let options = BuildImageOptions::new(
            source,
            EROFS_BLOCK_SIZE,
            BlobMetadataCompressor::None,
            Default::default(),
            true,
        )
        .unwrap();
        let mut blob = Vec::new();
        let image = build_image(&options, &mut blob).unwrap();
        std::fs::write(root.join(hex::encode(image.full_blob_digest)), blob).unwrap();
        let bootstrap = root.join("bootstrap");
        std::fs::write(&bootstrap, image.standalone_bootstrap.unwrap()).unwrap();
        let config = serde_yaml::from_str::<nydus_config::Config>(&format!(
            "backend:\n  type: local\n  config:\n    dir: {}\nstorage:\n  dir: {}\nprefetch:\n  scope: none\n",
            root.display(), root.join("cache").display(),
        )).unwrap();
        Arc::new(NbdCore::new(&bootstrap, config).unwrap())
    }

    fn kernel_ends(session: &mut NbdSession, count: usize) -> Vec<UnixStream> {
        let connections = session.start(count).unwrap();
        connections
            .into_iter()
            .map(|(kernel, _)| {
                let kernel = UnixStream::from(kernel);
                kernel
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                kernel
            })
            .collect()
    }

    fn request(ty: u32, handle: u64) -> Vec<u8> {
        request_at(ty, handle, 0, 4096)
    }

    fn request_at(ty: u32, handle: u64, offset: u64, len: u32) -> Vec<u8> {
        let mut request = Vec::new();
        request.extend(NBD_REQUEST_MAGIC.to_be_bytes());
        request.extend(ty.to_be_bytes());
        request.extend(handle.to_be_bytes());
        request.extend(offset.to_be_bytes());
        request.extend(len.to_be_bytes());
        request
    }

    fn read_reply(kernel: &mut UnixStream) -> u64 {
        let mut reply = vec![0; NBD_REPLY_HEADER_SIZE + 4096];
        kernel.read_exact(&mut reply).unwrap();
        assert_eq!(reply[..8], encode_reply(NBD_OK, 0)[..8]);
        u64::from_be_bytes(reply[8..16].try_into().unwrap())
    }

    fn wait_for_live(session: &NbdSession, live: usize) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while session.service.live.load(Ordering::SeqCst) != live {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn later_requests_are_read_before_earlier_reads_are_answered() {
        let dir = tempfile::tempdir().unwrap();
        let pool = Arc::new(FetchPool::new(1).unwrap());
        let (release, busy) = std::sync::mpsc::channel::<()>();
        pool.execute(move || busy.recv().unwrap());
        let mut session = test_session(dir.path(), pool);
        let (kernel, user) = session.start(1).unwrap().remove(0);
        let mut kernel = UnixStream::from(kernel);
        kernel.write_all(&request(NBD_CMD_READ, 7)).unwrap();
        kernel.write_all(&request(NBD_CMD_READ, 8)).unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        while unread(&user) {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        kernel.set_nonblocking(true).unwrap();
        assert_eq!(
            kernel.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        kernel.set_nonblocking(false).unwrap();
        kernel
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        release.send(()).unwrap();
        let mut handles = [read_reply(&mut kernel), read_reply(&mut kernel)];
        handles.sort();
        assert_eq!(handles, [7, 8]);
        session.cancel().unwrap();
    }

    #[test]
    fn invalid_requests_get_an_errno_and_keep_the_stream_in_sync() {
        let dir = tempfile::tempdir().unwrap();
        let mut session = test_session(dir.path(), test_pool());
        let bootstrap = std::fs::read(dir.path().join("bootstrap")).unwrap();
        let device_size = session.core.device_size();
        let mut kernel = kernel_ends(&mut session, 1).remove(0);
        let test_cases = vec![
            (NBD_CMD_READ, 1, 4096, NBD_EINVAL),
            (NBD_CMD_READ, 0, 4095, NBD_EINVAL),
            (NBD_CMD_READ, 0, 4 * 1024 * 1024 + 4096, NBD_EINVAL),
            (NBD_CMD_READ, device_size, 4096, NBD_EIO),
            (NBD_CMD_READ, u64::MAX - 4095, 4096, NBD_EIO),
            (3, 0, 0, NBD_EINVAL),
        ];

        for (ty, offset, len, errno) in test_cases {
            kernel.write_all(&request_at(ty, 7, offset, len)).unwrap();
            let mut reply = [0; NBD_REPLY_HEADER_SIZE];
            kernel.read_exact(&mut reply).unwrap();
            assert_eq!(reply, encode_reply(errno, 7), "{ty} {offset} {len}");

            kernel.write_all(&request(NBD_CMD_READ, 8)).unwrap();
            let mut reply = [0; NBD_REPLY_HEADER_SIZE + 4096];
            kernel.read_exact(&mut reply).unwrap();
            assert_eq!(reply[..NBD_REPLY_HEADER_SIZE], encode_reply(NBD_OK, 8));
            assert_eq!(reply[NBD_REPLY_HEADER_SIZE..], bootstrap[..4096]);
        }
        session.cancel().unwrap();
    }

    #[test]
    fn malformed_requests_close_the_connection_without_a_reply() {
        let dir = tempfile::tempdir().unwrap();
        let mut session = test_session(dir.path(), test_pool());
        let mut bad_magic = request(NBD_CMD_READ, 7);
        bad_magic[0] ^= 1;
        let test_cases = vec![
            bad_magic,
            request(NBD_CMD_WRITE, 7),
            request(NBD_CMD_READ, 7)[..13].to_vec(),
        ];

        for bytes in test_cases {
            let mut kernel = kernel_ends(&mut session, 1).remove(0);
            kernel.write_all(&bytes).unwrap();
            kernel.shutdown(std::net::Shutdown::Write).unwrap();
            assert_eq!(kernel.read(&mut [0]).unwrap(), 0, "{bytes:?}");
        }
    }

    #[test]
    fn connection_loss_keeps_other_workers_serving() {
        let test_cases = vec![false, true];

        for pending_reply in test_cases {
            let dir = tempfile::tempdir().unwrap();
            let mut session = test_session(dir.path(), test_pool());
            let mut kernels = kernel_ends(&mut session, 2);
            let mut healthy = kernels.remove(1);
            let mut closed = kernels.remove(0);
            if pending_reply {
                closed.shutdown(std::net::Shutdown::Read).unwrap();
                closed.write_all(&request(NBD_CMD_READ, 7)).unwrap();
            }
            drop(closed);
            wait_for_live(&session, 1);
            assert!(!session.disconnect_requested());
            assert!(!session.is_released());
            healthy.write_all(&request(NBD_CMD_READ, 8)).unwrap();
            assert_eq!(read_reply(&mut healthy), 8);
            session.cancel().unwrap();
        }
    }

    #[test]
    fn kernel_disconnect_is_distinct_from_connection_loss() {
        let dir = tempfile::tempdir().unwrap();
        let mut session = test_session(dir.path(), test_pool());
        let mut kernel = kernel_ends(&mut session, 1).remove(0);
        kernel.write_all(&request(NBD_CMD_DISC, 0)).unwrap();
        assert_eq!(kernel.read(&mut [0]).unwrap(), 0);
        assert!(session.disconnect_requested());
        session.cancel().unwrap();
    }

    #[test]
    fn a_failed_reattachment_is_retried_later_instead_of_failing_the_pool() {
        let dir = tempfile::tempdir().unwrap();
        let mut session = test_session(dir.path(), test_pool());
        let _kernel = kernel_ends(&mut session, 1);

        session.repair().unwrap();
        let deadline = Instant::now() + netlink::NETLINK_TIMEOUT + Duration::from_secs(1);
        while !session.attachment.as_ref().unwrap().call.is_finished() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        session.repair().unwrap();
        assert!(session.attachment.is_none());
        assert!(session.retry_at > Instant::now());
        wait_for_live(&session, 1);

        session.repair().unwrap();
        assert!(session.attachment.is_none());
        assert_eq!(session.service.live.load(Ordering::SeqCst), 1);

        session.retry_at = Instant::now();
        session.repair().unwrap();
        assert!(session.attachment.is_some());
        session.cancel().unwrap();
    }

    #[test]
    fn protocol_failure_is_not_treated_as_connection_loss() {
        let dir = tempfile::tempdir().unwrap();
        let mut session = test_session(dir.path(), test_pool());
        let mut kernel = kernel_ends(&mut session, 1).remove(0);
        kernel.write_all(&[0; NBD_REQUEST_HEADER_SIZE]).unwrap();
        wait_for_live(&session, 0);
        assert!(session.cancel().is_err());
    }

    fn unread(socket: &UnixStream) -> bool {
        poll_socket(socket, libc::POLLIN).unwrap() & libc::POLLIN != 0
    }

    fn assert_unanswered(kernel: &UnixStream) {
        kernel.set_nonblocking(true).unwrap();
        assert_eq!(
            (&*kernel).read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        kernel.set_nonblocking(false).unwrap();
    }

    #[test]
    fn a_paused_connection_is_continued_by_the_session_that_adopts_it() {
        let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
        let base = dirs[0].path().join("owner");
        let mut predecessor = test_session(dirs[0].path(), test_pool());
        *predecessor.service.owner.lock().unwrap() =
            Some(SessionOwner::acquire(&base, true).unwrap());
        let mut kernel = kernel_ends(&mut predecessor, 1).remove(0);
        kernel.write_all(&request(NBD_CMD_READ, 7)).unwrap();
        assert_eq!(read_reply(&mut kernel), 7);

        let sockets = predecessor.service.pause(Duration::from_secs(2)).unwrap();
        assert_eq!(sockets.len(), 1);
        kernel.write_all(&request(NBD_CMD_READ, 8)).unwrap();

        let mut successor = test_session(dirs[1].path(), test_pool());
        successor.adopt(sockets).unwrap();
        predecessor.service.release().unwrap();
        assert!(predecessor.is_released());
        assert!(SessionOwner::acquire(&base, false).is_ok());
        assert_unanswered(&kernel);

        successor.service.resume().unwrap();
        assert_eq!(read_reply(&mut kernel), 8);
        kernel.write_all(&request(NBD_CMD_READ, 9)).unwrap();
        assert_eq!(read_reply(&mut kernel), 9);
        successor.cancel().unwrap();
        predecessor.cancel().unwrap();
    }

    #[test]
    fn a_pause_waits_for_reads_in_flight_and_serving_resumes_when_it_fails() {
        let dir = tempfile::tempdir().unwrap();
        let pool = Arc::new(FetchPool::new(1).unwrap());
        let (unblock, busy) = std::sync::mpsc::channel::<()>();
        pool.execute(move || busy.recv().unwrap());
        let mut session = test_session(dir.path(), pool);
        let (kernel, user) = session.start(1).unwrap().remove(0);
        let mut kernel = UnixStream::from(kernel);
        kernel
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        kernel.write_all(&request(NBD_CMD_READ, 7)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while unread(&user) {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }

        let paused = session.service.pause(Duration::from_millis(50));
        assert_eq!(
            paused.unwrap_err().io_error().unwrap().kind(),
            io::ErrorKind::TimedOut
        );
        session.service.resume().unwrap();
        unblock.send(()).unwrap();
        assert_eq!(read_reply(&mut kernel), 7);
        kernel.write_all(&request(NBD_CMD_READ, 8)).unwrap();
        assert_eq!(read_reply(&mut kernel), 8);
        session.cancel().unwrap();
    }

    #[test]
    fn detaching_an_adopted_session_leaves_the_connection_to_the_resumed_predecessor() {
        let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
        let mut predecessor = test_session(dirs[0].path(), test_pool());
        let mut kernel = kernel_ends(&mut predecessor, 1).remove(0);
        let sockets = predecessor.service.pause(Duration::from_secs(2)).unwrap();

        let mut successor = test_session(dirs[1].path(), test_pool());
        successor.adopt(sockets).unwrap();
        successor.detach().unwrap();
        predecessor.service.resume().unwrap();
        kernel.write_all(&request(NBD_CMD_READ, 7)).unwrap();
        assert_eq!(read_reply(&mut kernel), 7);
        predecessor.cancel().unwrap();
    }

    #[test]
    fn unaccepted_socket_is_detected_after_dropping_the_kernel_endpoint() {
        let (user, kernel) = UnixStream::pair().unwrap();
        assert!(!peer_closed(&user).unwrap());
        drop(kernel);
        assert!(peer_closed(&user).unwrap());
    }

    #[test]
    fn vectored_replies_survive_partial_writes() {
        struct Short(Vec<u8>);
        impl Write for Short {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let n = bytes.len().min(2);
                self.0.extend_from_slice(&bytes[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut writer = Short(Vec::new());
        writev_all(&mut writer, b"header", b"payload").unwrap();
        assert_eq!(writer.0, b"headerpayload");
    }
}
