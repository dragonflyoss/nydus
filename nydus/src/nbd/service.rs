//! NBD kernel device setup and request-handling worker.
//!
//! [`NbdService`] owns the `/dev/nbdX` descriptor and drives the ioctl
//! handshake (block size/count, timeout, flags; attach a socket; `NBD_DO_IT`).
//! Each [`NbdWorker`] runs the request loop on the user end of its own socket
//! pair: read a 28-byte header, ask [`NbdCore`] to fill the range, write back
//! the 16-byte reply plus data. Wire-protocol framing lives in
//! [`super::proto`]; this module deals only with the kernel interface and the
//! socket I/O loop.

use std::fs::{File, OpenOptions};
use std::io::{IoSlice, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nydus_error::{Context, Error, Result};
use tracing::{debug, warn};

use super::core::NbdCore;
use super::proto::{
    encode_reply, ParseError, Request, NBD_BLOCK_SIZE, NBD_CMD_WRITE, NBD_EINVAL, NBD_EIO, NBD_OK,
    NBD_REQUEST_HEADER_SIZE,
};

// The NBD ioctls are `_IO(0xab, nr)` — no direction bits, no size field — so
// the encoded request is simply `(0xab << 8) | nr`. We hardcode the magic
// rather than depending on a `nix` macro (the crate deliberately avoids a nix
// dependency).

/// `ioctl(fd, NBD_SET_SOCK, sock)` — attach the kernel end of the socket pair.
const NBD_SET_SOCK: u32 = 0xab << 8;
/// `ioctl(fd, NBD_SET_BLOCK_SIZE, bytes)`.
const NBD_SET_BLOCK_SIZE: u32 = (0xab << 8) | 1;
/// `ioctl(fd, NBD_DO_IT)` — block until the session ends.
const NBD_DO_IT: u32 = (0xab << 8) | 3;
/// `ioctl(fd, NBD_CLEAR_SOCK)` — detach the socket, stop the session.
const NBD_CLEAR_SOCK: u32 = (0xab << 8) | 4;
/// `ioctl(fd, NBD_SET_BLOCKS, count)`.
const NBD_SET_BLOCKS: u32 = (0xab << 8) | 7;
/// `ioctl(fd, NBD_SET_TIMEOUT, seconds)`.
const NBD_SET_TIMEOUT: u32 = (0xab << 8) | 9;
/// `ioctl(fd, NBD_SET_FLAGS, flags)`.
const NBD_SET_FLAGS: u32 = (0xab << 8) | 10;

/// `ioctl(fd, BLKGETSIZE64, &u64)` — read the device capacity in bytes.
/// `_IOR(0x12, 114, size_t)` on 64-bit Linux, hardcoded like the NBD codes.
const BLKGETSIZE64: u32 = 0x8008_1272;

const NBD_FLAG_HAS_FLAGS: u32 = 0x1;
const NBD_FLAG_READ_ONLY: u32 = 0x2;
const NBD_FLAG_CAN_MULTI_CONN: u32 = 0x100;

/// Interval between `BLKGETSIZE64` polls in [`NbdService::wait_for_capacity`];
/// the capacity commit lands microseconds after `NBD_DO_IT` enters the kernel.
const CAPACITY_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Upper bound on a single `NBD_CMD_READ` length, rejecting a pathological
/// `len` (up to 4 GiB in a `u32`) before it drives a huge allocation. The
/// block layer's default `max_sectors` keeps real requests far below this;
/// raising `/sys/block/nbdX/queue/max_sectors_kb` past 4096 would need this
/// cap raised too.
const MAX_READ_LEN: usize = 4 * 1024 * 1024;

/// A raw `ioctl` carrying a single `unsigned long` argument.
///
/// NBD ioctls ignore the direction/size encoding of the request code, so the
/// argument is passed by value regardless of pointer width.
fn nbd_ioctl(fd: RawFd, request: u32, arg: u64) -> std::io::Result<i32> {
    // SAFETY: `fd` is a live `/dev/nbdX` descriptor and `request` is one of
    // the NBD _IO codes above.
    let ret = unsafe { libc::ioctl(fd, request as libc::c_ulong, arg as libc::c_ulong) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Read the block device's current capacity in bytes via `BLKGETSIZE64`.
fn query_block_device_size(fd: RawFd) -> std::io::Result<u64> {
    let mut size: u64 = 0;
    // SAFETY: `fd` is a live block-device descriptor and BLKGETSIZE64 writes
    // a single u64 through the pointer.
    let ret = unsafe { libc::ioctl(fd, BLKGETSIZE64 as libc::c_ulong, &mut size as *mut u64) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(size)
    }
}

/// Write every byte of `a` then `b` to `w`, looping on partial writes. Each
/// `write_vectored` call (a real `writev` on `UnixStream`) merges the two
/// remaining suffixes, so a header+data reply is one syscall instead of two.
/// Hand-rolled because `Write::write_all_vectored` is still unstable (#70436).
fn writev_all<W: Write>(w: &mut W, a: &mut &[u8], b: &mut &[u8]) -> std::io::Result<()> {
    while !a.is_empty() || !b.is_empty() {
        let iovs = [IoSlice::new(a), IoSlice::new(b)];
        let n = w.write_vectored(&iovs)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "writev returned 0 before all bytes were written",
            ));
        }
        let mut left = n;
        if !a.is_empty() {
            if left >= a.len() {
                left -= a.len();
                *a = &[];
            } else {
                let cur: &[u8] = a;
                *a = &cur[left..];
                left = 0;
            }
        }
        if left > 0 && !b.is_empty() {
            if left >= b.len() {
                *b = &[];
            } else {
                let cur: &[u8] = b;
                *b = &cur[left..];
            }
        }
    }
    Ok(())
}

/// Owns the `/dev/nbdX` descriptor and drives the NBD ioctl handshake.
///
/// Split from [`NbdWorker`] so setup errors surface before any thread is
/// spawned, and so `stop()` can tear down the kernel session (clear-sock) from
/// the control thread while the worker drains.
pub struct NbdService {
    core: Arc<NbdCore>,
    nbd_dev: File,
    active: Arc<AtomicBool>,
}

impl NbdService {
    /// Open the NBD device and initialize it (block size, block count,
    /// timeout, flags) from the flattened image geometry. The device is
    /// mounted read-only by [`super::mount::mount_nbd`]; the daemon never
    /// writes the NBD device itself. `timeout_secs` is handed to
    /// `NBD_SET_TIMEOUT`: how long the kernel waits for one reply before
    /// failing the request and tearing the session down, so it must exceed
    /// the worst-case cold fetch from the backend.
    pub fn new(core: Arc<NbdCore>, nbd_path: &str, timeout_secs: u64) -> Result<Self> {
        let nbd_dev = OpenOptions::new()
            .read(true)
            .write(true)
            .open(nbd_path)
            .with_context(|| format!("failed to open nbd device: {nbd_path}"))?;
        let fd = nbd_dev.as_raw_fd();

        // A nonzero capacity means another client is already serving this
        // device; the NBD_CLEAR_SOCK below would shut that session's sockets
        // down and kill it, so refuse instead of hijacking.
        let size = query_block_device_size(fd)
            .context("failed to query nbd device size (BLKGETSIZE64)")?;
        if size != 0 {
            return Err(Error::InvalidParameter(format!(
                "NBD device {nbd_path} is busy (reports {size} bytes); \
                 pick a free device or detach the other client first"
            )));
        }

        // Clear any previous session so a fresh socket/flags set applies.
        let _ = nbd_ioctl(fd, NBD_CLEAR_SOCK, 0);
        nbd_ioctl(fd, NBD_SET_BLOCK_SIZE, NBD_BLOCK_SIZE)
            .context("failed to set nbd block size (NBD_SET_BLOCK_SIZE)")?;
        nbd_ioctl(fd, NBD_SET_BLOCKS, core.block_count())
            .context("failed to set nbd device blocks (NBD_SET_BLOCKS)")?;
        nbd_ioctl(fd, NBD_SET_TIMEOUT, timeout_secs)
            .context("failed to set nbd timeout (NBD_SET_TIMEOUT)")?;
        nbd_ioctl(
            fd,
            NBD_SET_FLAGS,
            (NBD_FLAG_HAS_FLAGS | NBD_FLAG_READ_ONLY | NBD_FLAG_CAN_MULTI_CONN) as u64,
        )
        .context("failed to set nbd flags (NBD_SET_FLAGS)")?;

        Ok(Self {
            core,
            nbd_dev,
            active: Arc::new(AtomicBool::new(true)),
        })
    }

    /// Create the socket pair, hand the kernel end to the driver, and return a
    /// worker owning the user end. `NBD_DO_IT` must be called separately
    /// ([`Self::run`]); it blocks until the session ends.
    pub fn create_worker(&self) -> Result<NbdWorker> {
        let (sock_kern, sock_user) =
            UnixStream::pair().context("failed to create nbd socket pair")?;
        nbd_ioctl(
            self.nbd_dev.as_raw_fd(),
            NBD_SET_SOCK,
            sock_kern.as_raw_fd() as u64,
        )
        .context("failed to set nbd socket (NBD_SET_SOCK)")?;
        Ok(NbdWorker {
            core: self.core.clone(),
            active: self.active.clone(),
            // Keep the kernel end open until NBD_DO_IT returns.
            _sock_kern: sock_kern,
            sock_user,
            buf: Vec::new(),
        })
    }

    /// Block on `NBD_DO_IT` until the session ends; both `stop()` and a clean
    /// client disconnect unblock it. Afterwards clear the sock to release the
    /// kernel reference and mark the service inactive so the workers drain.
    pub fn run(&self) {
        let fd = self.nbd_dev.as_raw_fd();
        // An error is expected on a clean shutdown: `stop()` clears the sock
        // first, so DO_IT may return EBADR/EINVAL.
        if let Err(err) = nbd_ioctl(fd, NBD_DO_IT, 0) {
            debug!("NBD_DO_IT returned {err} (clearing socket)");
        }
        self.active.store(false, Ordering::Release);
        let _ = nbd_ioctl(fd, NBD_CLEAR_SOCK, 0);
    }

    /// Block until the device reports a capacity of `bytes`, or `timeout`
    /// elapses.
    ///
    /// Kernels since ~6.13 commit the queue geometry and capacity inside
    /// `NBD_DO_IT` (older ones did it at `NBD_SET_SOCK`), so until the
    /// event-loop thread has entered the kernel the device stays zero-sized
    /// and mounting fails with EINVAL. Polling `BLKGETSIZE64` is the
    /// canonical readiness check — `nbd-client` does the same — and must run
    /// while [`Self::run`] is in flight on another thread.
    pub fn wait_for_capacity(&self, bytes: u64, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let fd = self.nbd_dev.as_raw_fd();
        loop {
            let size = query_block_device_size(fd)
                .context("failed to query nbd device size (BLKGETSIZE64)")?;
            if size == bytes {
                debug!("nbd device capacity committed: {size} bytes");
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error::Runtime(format!(
                    "timed out after {timeout:?} waiting for the nbd device to \
                     report {bytes} bytes (got {size}); NBD_DO_IT may not be running"
                )));
            }
            std::thread::sleep(CAPACITY_POLL_INTERVAL);
        }
    }

    /// Stop the session from the control thread: clearing the sock unblocks
    /// `run()` (and thus `NBD_DO_IT`) and the flag lets the worker exit.
    pub fn stop(&self) {
        self.active.store(false, Ordering::Release);
        let _ = nbd_ioctl(self.nbd_dev.as_raw_fd(), NBD_CLEAR_SOCK, 0);
    }
}

/// Runs the request loop on the user end of the NBD socket pair.
///
/// One worker per `/dev/nbdX` is enough for correctness (the kernel serializes
/// the reply stream); spawn more and hand each its own `create_worker()` socket
/// pair to parallelize backend fetches, matching the old RAFS NBD behavior.
pub struct NbdWorker {
    core: Arc<NbdCore>,
    active: Arc<AtomicBool>,
    _sock_kern: UnixStream,
    sock_user: UnixStream,
    /// Reuse buffer for `NBD_CMD_READ` replies: grows to the largest request
    /// seen and stays, so the steady-state read path pays no malloc/memset.
    buf: Vec<u8>,
}

impl NbdWorker {
    /// Read request headers and write replies until the session ends: on
    /// `NbdService::stop` the kernel shuts the socket pair down, which
    /// unblocks the `read_exact` here.
    pub fn run(mut self) {
        let mut header = [0u8; NBD_REQUEST_HEADER_SIZE];

        while self.active.load(Ordering::Acquire) {
            if let Err(err) = self.sock_user.read_exact(&mut header) {
                if self.active.load(Ordering::Acquire) {
                    warn!("nbd: failed to read request header: {err}");
                }
                break;
            }
            match self.handle_request(&header) {
                Ok(true) => {}
                Ok(false) => break,
                Err(err) => {
                    warn!("nbd: failed to handle request: {}", err.report());
                    break;
                }
            }
        }
    }

    /// Parse one 28-byte request, fetch + read the data, and write the reply.
    /// Returns `Ok(false)` when the session should end (disconnect command or
    /// a desynced stream).
    fn handle_request(&mut self, header: &[u8]) -> Result<bool> {
        let req = match Request::parse(header) {
            Ok(req) => req,
            Err(ParseError::ShortBuffer) => {
                // Should never happen: the loop always feeds a full header.
                warn!("nbd: short request header");
                return Ok(true);
            }
            Err(ParseError::BadMagic { got }) => {
                // The stream is no longer aligned to request-header
                // boundaries and there is no way to resync; a reply would
                // carry a fabricated handle the kernel cannot match, killing
                // the connection from its side anyway. Drop the session.
                warn!("nbd: invalid request magic 0x{got:08x} (dropping connection)");
                return Ok(false);
            }
        };

        // Disconnect: no reply, the loop exits.
        if req.is_disc() {
            return Ok(false);
        }

        let mut code = NBD_OK;
        let mut wrote_data = false;

        if req.is_read() {
            if req.len as usize > MAX_READ_LEN {
                warn!(
                    "nbd: read length {} exceeds cap {}, rejecting",
                    req.len, MAX_READ_LEN
                );
                code = NBD_EINVAL;
            } else if !req.is_block_aligned() {
                warn!(
                    "nbd: unaligned read offset 0x{:x} len {} (block size {})",
                    req.offset, req.len, NBD_BLOCK_SIZE
                );
                code = NBD_EINVAL;
            } else {
                // Reuse the worker-local buffer; the zero-fill runs only when
                // it grows past its high-water mark.
                let len = req.len as usize;
                if self.buf.len() < len {
                    self.buf.resize(len, 0);
                }
                // Split the borrows so `self.core` and `self.buf` stay disjoint.
                let core = &self.core;
                let buf = &mut self.buf[..len];
                match core.read_at(req.offset, buf) {
                    Ok(()) => wrote_data = true,
                    Err(err) => {
                        warn!(
                            "nbd: read [{:#x}, +{}) failed: {}",
                            req.offset,
                            req.len,
                            err.report()
                        );
                        code = NBD_EIO;
                    }
                }
            }
        } else if req.ty == NBD_CMD_WRITE {
            // The read-only flag stops writes at the block layer, so this
            // never fires for the kernel; a write from a misbehaving peer
            // carries a payload we never consume, desyncing the stream, so
            // drop the session instead of replying.
            warn!("nbd: write request on read-only device, dropping connection");
            return Ok(false);
        } else {
            // Read-only device: flush/trim/etc are not supported.
            warn!("nbd: unsupported request type {}", req.ty);
            code = NBD_EINVAL;
        }

        let reply = encode_reply(code, req.handle);
        if wrote_data {
            // One writev for header + payload; the buffer may be longer than
            // this request (high-water reuse), so slice to `req.len`.
            let mut header: &[u8] = &reply;
            let mut data: &[u8] = &self.buf[..req.len as usize];
            writev_all(&mut self.sock_user, &mut header, &mut data)
                .context("failed to write nbd reply")?;
        } else {
            self.sock_user
                .write_all(&reply)
                .context("failed to write nbd reply header")?;
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_codes_match_linux_nbd_header() {
        // _IO(0xab, nr) = (0xab << 8) | nr — verify the constants we hardcoded.
        assert_eq!(NBD_SET_SOCK, 0xab << 8);
        assert_eq!(NBD_SET_BLOCK_SIZE, (0xab << 8) | 1);
        assert_eq!(NBD_DO_IT, (0xab << 8) | 3);
        assert_eq!(NBD_CLEAR_SOCK, (0xab << 8) | 4);
        assert_eq!(NBD_SET_BLOCKS, (0xab << 8) | 7);
        assert_eq!(NBD_SET_TIMEOUT, (0xab << 8) | 9);
        assert_eq!(NBD_SET_FLAGS, (0xab << 8) | 10);
    }
}
