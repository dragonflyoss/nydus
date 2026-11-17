use nydus_error::{Context, Error, Result};
use std::fs::File;
use std::io::{self, IoSlice, Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use tracing::{debug, info, warn};

use super::proto::{
    encode_reply, Request, NBD_CMD_WRITE, NBD_EINVAL, NBD_EIO, NBD_OK, NBD_REQUEST_HEADER_SIZE,
};
use super::{mount_nbd, netlink, NbdCore};
use crate::mount::unmount;
use crate::signal;

/// The largest read a request may ask for.
const MAX_READ_LEN: usize = 4 * 1024 * 1024;

/// The most connections whose socket list fits one netlink attribute.
const MAX_CONNECTIONS: usize = (u16::MAX as usize - 4) / 12;

/// How often a waiting loop checks its condition again.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// The kernel session settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NbdOptions {
    /// The number of kernel connections, one worker each.
    pub connections: usize,

    /// The seconds the kernel waits for one reply before retrying the request.
    pub timeout_secs: u64,
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
        Ok(())
    }
}

/// The state shared by one pool and its workers.
pub(crate) struct NbdService {
    /// The eventfd that interrupts every worker waiting for a request.
    wake: File,

    /// The number of workers that have not exited.
    live: AtomicUsize,

    /// Whether the kernel explicitly requested session disconnect.
    disconnect_requested: AtomicBool,
}

/// Implements the shared worker state.
impl NbdService {
    /// Stops every worker by waking it while it waits for a request.
    fn stop(&self) -> Result<()> {
        (&self.wake)
            .write_all(&1u64.to_ne_bytes())
            .context("failed to wake NBD workers")
    }
}

/// The worker pool of one kernel session.
///
/// Dropping it closes only this process's connections, never the device.
pub(crate) struct NbdSession {
    /// The state shared with the workers.
    pub(crate) service: Arc<NbdService>,

    /// The `/dev/nbd<N>` index.
    pub(crate) index: u32,

    /// The connection count and timeouts of the kernel session.
    options: NbdOptions,

    /// The image the workers read from.
    core: Arc<NbdCore>,

    /// The worker threads not joined yet.
    workers: Vec<JoinHandle<Result<()>>>,
}

/// Implements the worker pool.
impl NbdSession {
    /// Creates a pool without connections.
    pub(crate) fn new(core: Arc<NbdCore>, index: u32, options: NbdOptions) -> Result<Self> {
        // SAFETY: eventfd accepts integer arguments and the returned fd is checked.
        let wake = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if wake < 0 {
            return Err(io::Error::last_os_error()).context("failed to create NBD worker wakeup");
        }

        // SAFETY: eventfd returned a fresh descriptor owned by this state.
        let wake = unsafe { File::from_raw_fd(wake) };
        Ok(Self {
            service: Arc::new(NbdService {
                wake,
                live: AtomicUsize::new(0),
                disconnect_requested: AtomicBool::new(false),
            }),
            index,
            options,
            core,
            workers: Vec::new(),
        })
    }

    /// Starts `count` workers on fresh socket pairs, returning each kernel end with its user end.
    pub(crate) fn start(&mut self, count: usize) -> Result<Vec<(OwnedFd, Arc<UnixStream>)>> {
        (0..count)
            .map(|_| {
                let (kernel, user) =
                    UnixStream::pair().context("failed to create NBD socket pair")?;
                let user = Arc::new(user);
                self.workers
                    .push(NbdWorker::spawn(&self.core, &self.service, user.clone())?);
                Ok((kernel.into(), user))
            })
            .collect()
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
        netlink::connect_device(self.index, size, &self.options, &kernels)
    }

    /// Joins the workers that exited, failing once a worker failed or no connection is left.
    ///
    /// The kernel closes a connection when a request times out. That retires only its
    /// worker: the kernel retries the request on the remaining connections.
    fn reap(&mut self) -> Result<()> {
        let (exited, serving): (Vec<_>, Vec<_>) = std::mem::take(&mut self.workers)
            .into_iter()
            .partition(JoinHandle::is_finished);
        self.workers = serving;
        Self::join(exited)?;

        if self.service.live.load(Ordering::SeqCst) == 0 {
            return Err(Error::Runtime(
                "the kernel closed every NBD connection".into(),
            ));
        }
        Ok(())
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

    /// Stops the workers and waits for them.
    pub(crate) fn cancel(&mut self) -> Result<()> {
        let stopped = self.service.stop();
        combine(stopped, Self::join(self.workers.drain(..)))
    }

    /// Returns whether the kernel requested disconnect.
    pub(crate) fn disconnect_requested(&self) -> bool {
        self.service.disconnect_requested.load(Ordering::Acquire)
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

/// Attaches a fresh netlink session on `device`, optionally mounts it as EROFS
/// and serves it until a termination signal or a worker failure.
pub fn serve(
    core: Arc<NbdCore>,
    device: &str,
    mountpoint: Option<&Path>,
    options: &NbdOptions,
    signals: signal::Signals,
) -> Result<()> {
    let index = device_index(device)?;
    let mut session = NbdSession::new(core.clone(), index, options.clone())?;
    session.connect(core.device_size())?;
    info!(
        "nydus nbd service attached to {} ({} connections)",
        device, options.connections
    );
    let stop = Arc::new(AtomicBool::new(false));
    let requested = stop.clone();
    let signal = match signal::spawn_signal_thread("nbd", signals, move || {
        requested.store(true, Ordering::Release);
    }) {
        Ok(signal) => signal,
        Err(err) => return combine(Err(err), teardown(&mut session, None)),
    };
    let mounted: Result<Option<&Path>> = mountpoint
        .map(|path| {
            mount_nbd(device, path, "erofs")?;
            info!("mounted {} at {}", device, path.display());
            Ok(path)
        })
        .transpose();
    let served = match mounted {
        Ok(mounted) => loop {
            // Reap before reading the disconnect flag: a worker sets it before it exits,
            // so the connections a kernel disconnect closes never hide the request.
            let reaped = session.reap();
            if stop.load(Ordering::Acquire) || session.disconnect_requested() {
                break teardown(&mut session, mounted);
            }
            if let Err(err) = reaped {
                break combine(Err(err), teardown(&mut session, mounted));
            }
            std::thread::sleep(POLL_INTERVAL);
        },
        Err(err) => combine(Err(err), teardown(&mut session, None)),
    };
    combine(served, signal.shutdown())
}

/// Unmounts while workers still serve, then disconnects and stops any remaining workers.
fn teardown(session: &mut NbdSession, mountpoint: Option<&Path>) -> Result<()> {
    let unmounted = mountpoint.map_or(Ok(()), |path| unmount(path, || {}));
    let disconnected = netlink::disconnect_device(session.index);
    combine(combine(unmounted, disconnected), session.cancel())
}

/// Returns the `/dev/nbd<N>` index of a device path, resolving aliases.
fn device_index(device: &str) -> Result<u32> {
    let device = std::fs::canonicalize(device)
        .with_context(|| format!("failed to resolve NBD device {device}"))?;
    device
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("nbd"))
        .filter(|index| !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|index| index.parse::<u32>().ok())
        .ok_or_else(|| {
            Error::InvalidParameter(format!(
                "NBD device {} must name /dev/nbd<N>",
                device.display()
            ))
        })
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

    /// The read buffer reused across requests.
    buf: Vec<u8>,
}

/// Implements the per-connection worker.
impl NbdWorker {
    /// Spawns a worker that serves `socket`.
    fn spawn(
        core: &Arc<NbdCore>,
        service: &Arc<NbdService>,
        socket: Arc<UnixStream>,
    ) -> Result<JoinHandle<Result<()>>> {
        service.live.fetch_add(1, Ordering::SeqCst);
        let worker = Self {
            service: service.clone(),
            core: core.clone(),
            socket,
            buf: Vec::new(),
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

    /// Serves requests until the pool stops or the kernel disconnects.
    fn run_loop(&mut self) -> Result<()> {
        let mut header = [0; NBD_REQUEST_HEADER_SIZE];
        loop {
            if wait_for_request(&self.socket, &self.service.wake)? {
                return Ok(());
            }
            if !self.serve_one(&mut header)? {
                return Ok(());
            }
        }
    }

    /// Reads and answers one request; returns `false` on a disconnect request.
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
        let length = usize::try_from(request.len).unwrap_or(usize::MAX);
        let mut code = NBD_OK;
        let mut payload: &[u8] = &[];
        if !request.is_read() {
            warn!("nbd: unsupported request type {}", request.ty);
            code = NBD_EINVAL;
        } else if length > MAX_READ_LEN || !request.is_block_aligned() {
            warn!(
                "nbd: invalid read offset {} length {}",
                request.offset, request.len
            );
            code = NBD_EINVAL;
        } else {
            if self.buf.len() < length {
                self.buf.resize(length, 0);
            }
            match self.core.read_at(request.offset, &mut self.buf[..length]) {
                Ok(()) => payload = &self.buf[..length],
                Err(err) => {
                    warn!(
                        "nbd: read [{:#x}, +{}) failed: {}",
                        request.offset,
                        request.len,
                        err.report()
                    );
                    code = NBD_EIO;
                }
            }
        }
        writev_all(
            &mut self.socket.as_ref(),
            &encode_reply(code, request.handle),
            payload,
        )
        .context("failed to write NBD reply")?;
        Ok(true)
    }
}

/// Implements the worker exit accounting.
impl Drop for NbdWorker {
    /// Closes the connection and records the worker exit.
    fn drop(&mut self) {
        // Shut the socket down, because the kernel retires the slot only once the reply
        // stream ends.
        if let Err(err) = self.socket.shutdown(std::net::Shutdown::Both) {
            if err.kind() != io::ErrorKind::NotConnected {
                warn!(
                    "nbd: failed to close an exited worker's connection: {}",
                    err
                );
            }
        }
        self.service.live.fetch_sub(1, Ordering::SeqCst);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nbd::proto::{NBD_CMD_DISC, NBD_CMD_READ, NBD_REPLY_HEADER_SIZE, NBD_REQUEST_MAGIC};
    use std::time::Instant;

    fn test_session(root: &std::path::Path) -> NbdSession {
        let options = NbdOptions {
            connections: 2,
            timeout_secs: 15,
        };
        NbdSession::new(empty_core(root), u32::MAX, options).unwrap()
    }

    fn empty_core(root: &std::path::Path) -> Arc<NbdCore> {
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
    fn invalid_requests_get_an_errno_and_keep_the_stream_in_sync() {
        let dir = tempfile::tempdir().unwrap();
        let mut session = test_session(dir.path());
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
        let mut session = test_session(dir.path());
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
            let mut session = test_session(dir.path());
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
            healthy.write_all(&request(NBD_CMD_READ, 8)).unwrap();
            assert_eq!(read_reply(&mut healthy), 8);
            session.cancel().unwrap();
        }
    }

    #[test]
    fn kernel_disconnect_is_distinct_from_connection_loss() {
        let dir = tempfile::tempdir().unwrap();
        let mut session = test_session(dir.path());
        let mut kernel = kernel_ends(&mut session, 1).remove(0);
        kernel.write_all(&request(NBD_CMD_DISC, 0)).unwrap();
        assert_eq!(kernel.read(&mut [0]).unwrap(), 0);
        assert!(session.disconnect_requested());
        session.cancel().unwrap();
    }

    #[test]
    fn protocol_failure_is_not_treated_as_connection_loss() {
        let dir = tempfile::tempdir().unwrap();
        let mut session = test_session(dir.path());
        let mut kernel = kernel_ends(&mut session, 1).remove(0);
        kernel.write_all(&[0; NBD_REQUEST_HEADER_SIZE]).unwrap();
        wait_for_live(&session, 0);
        assert!(session.cancel().is_err());
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
