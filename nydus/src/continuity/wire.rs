//! Bounded length-prefixed JSON framing and descriptor passing over Unix sockets.

use std::io::{Read, Write};
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use nydus_error::{Context, Error, Result};
use serde::{de::DeserializeOwned, Serialize};

const MAX_FRAME_BYTES: u32 = 4 * 1024 * 1024;

/// The one-byte payload that carries an `SCM_RIGHTS` record.
const FD_TAG: u8 = b'F';

/// The most descriptors one transfer may carry; frontends validate the exact layout.
const MAX_TRANSFER_FDS: usize = 16;

/// The absolute expiry shared by every step of one protocol transaction.
#[derive(Clone, Copy)]
pub(crate) struct ProtocolDeadline {
    expires_at: Instant,
    transaction: &'static str,
}

impl ProtocolDeadline {
    pub(crate) fn after(timeout: Duration, transaction: &'static str) -> Self {
        Self {
            expires_at: Instant::now() + timeout,
            transaction,
        }
    }

    pub(crate) fn remaining(self) -> std::io::Result<Duration> {
        self.expires_at
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("{} deadline expired", self.transaction),
                )
            })
    }
}

/// Connects to the Unix socket at `path`, retrying a full backlog until `deadline`.
pub(crate) fn connect_until(
    path: &Path,
    deadline: ProtocolDeadline,
) -> std::io::Result<UnixStream> {
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: sockaddr_un is a C structure whose fields accept zero initialization.
    let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid Unix socket pathname",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
        *target = *byte as libc::c_char;
    }
    let address_len =
        (mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as libc::socklen_t;

    loop {
        deadline.remaining()?;
        // SAFETY: socket takes only integer arguments; the returned descriptor is checked.
        let fd = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: socket returned a fresh owned Unix stream descriptor.
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        // SAFETY: address is initialized and address_len stays within sockaddr_un.
        let result = unsafe {
            libc::connect(
                stream.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                address_len,
            )
        };
        if result == 0 {
            deadline.remaining()?;
            stream.set_nonblocking(false)?;
            return Ok(stream);
        }
        let error = std::io::Error::last_os_error();
        drop(stream);
        match error.kind() {
            // Linux AF_UNIX returns EAGAIN for a full backlog without queuing a
            // connection. Retry instead of polling it as an in-progress connect.
            std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(deadline.remaining()?.min(Duration::from_millis(5)));
            }
            std::io::ErrorKind::Interrupted => {}
            _ => return Err(error),
        }
    }
}

/// A stream whose every read and write is bounded by one transaction deadline.
pub(crate) struct DeadlineStream<'a> {
    pub(crate) stream: &'a mut UnixStream,
    pub(crate) deadline: ProtocolDeadline,
}

impl Read for DeadlineStream<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream
            .set_read_timeout(Some(self.deadline.remaining()?))?;
        self.stream.read(bytes)
    }
}

impl Write for DeadlineStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream
            .set_write_timeout(Some(self.deadline.remaining()?))?;
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream
            .set_write_timeout(Some(self.deadline.remaining()?))?;
        self.stream.flush()
    }
}

pub(crate) fn write_raw_frame_until(
    stream: &mut UnixStream,
    deadline: ProtocolDeadline,
    payload: &[u8],
) -> Result<()> {
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES as usize {
        return Err(Error::Protocol(format!(
            "invalid control frame length {}",
            payload.len()
        )));
    }
    let mut stream = DeadlineStream { stream, deadline };
    stream.write_all(&(payload.len() as u32).to_le_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

pub(crate) fn write_frame_until<T: Serialize>(
    stream: &mut UnixStream,
    deadline: ProtocolDeadline,
    value: &T,
) -> Result<()> {
    let payload = serde_json::to_vec(value)?;
    write_raw_frame_until(stream, deadline, &payload)
}

/// Reads one JSON frame, or `None` when the peer closed before a frame started.
pub(crate) fn read_frame_until<T: DeserializeOwned>(
    stream: &mut UnixStream,
    deadline: ProtocolDeadline,
) -> Result<Option<T>> {
    read_frame(&mut DeadlineStream { stream, deadline })
}

fn read_raw_frame_until(
    stream: &mut UnixStream,
    deadline: ProtocolDeadline,
) -> Result<Option<Vec<u8>>> {
    let mut stream = DeadlineStream { stream, deadline };
    read_raw_frame(&mut stream)
}

/// Reads one JSON frame, consuming bytes already buffered by an HTTP upgrade first.
pub(crate) fn read_buffered_frame_until<T: DeserializeOwned>(
    stream: &mut UnixStream,
    buffered: &mut std::io::Cursor<Vec<u8>>,
    deadline: ProtocolDeadline,
) -> Result<Option<T>> {
    deadline.remaining()?;
    read_frame(&mut buffered.chain(DeadlineStream { stream, deadline }))
}

fn read_frame<T: DeserializeOwned>(stream: &mut impl Read) -> Result<Option<T>> {
    read_raw_frame(stream)?
        .map(|payload| {
            serde_json::from_slice(&payload)
                .map_err(|err| Error::Protocol(format!("malformed control frame JSON: {err}")))
        })
        .transpose()
}

/// Reads one length-prefixed frame; EOF before the first byte is `None`.
fn read_raw_frame(stream: &mut impl Read) -> Result<Option<Vec<u8>>> {
    let mut length = [0u8; 4];
    loop {
        match stream.read(&mut length[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err.into()),
        }
    }
    stream
        .read_exact(&mut length[1..])
        .context("truncated control frame length")?;
    let length = u32::from_le_bytes(length);
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(Error::Protocol(format!(
            "invalid control frame length {length}"
        )));
    }
    let mut payload = vec![0u8; length as usize];
    stream
        .read_exact(&mut payload)
        .context("truncated control frame payload")?;
    Ok(Some(payload))
}

/// Sends `fds` in one `SCM_RIGHTS` record tagged with [`FD_TAG`].
fn send_fds_until(
    stream: &UnixStream,
    fds: &[BorrowedFd<'_>],
    deadline: ProtocolDeadline,
) -> std::io::Result<()> {
    if fds.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "at least one descriptor is required",
        ));
    }
    let raw_fds: Vec<RawFd> = fds.iter().map(AsRawFd::as_raw_fd).collect();
    let rights_bytes = raw_fds
        .len()
        .checked_mul(mem::size_of::<RawFd>())
        .and_then(|size| u32::try_from(size).ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many descriptors to transfer",
            )
        })?;
    let payload = [FD_TAG];
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    // SAFETY: rights_bytes is a checked descriptor-array size.
    let control_bytes = unsafe { libc::CMSG_SPACE(rights_bytes) as usize };
    let word_bytes = mem::size_of::<usize>();
    let mut control = vec![0usize; control_bytes.div_ceil(word_bytes)];
    // SAFETY: zero initializes the unused pointers and lengths in msghdr.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control_bytes;
    // SAFETY: control is aligned and sized for this SCM_RIGHTS header and descriptor array.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(rights_bytes) as usize;
        std::ptr::copy_nonoverlapping(
            raw_fds.as_ptr(),
            libc::CMSG_DATA(header).cast::<RawFd>(),
            raw_fds.len(),
        );
    }
    loop {
        stream.set_write_timeout(Some(deadline.remaining()?))?;
        // SAFETY: message borrows live payload, iovec, and ancillary buffers for this call.
        let result = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, 0) };
        if result == payload.len() as isize {
            return Ok(());
        }
        if result >= 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(err);
        }
    }
}

/// Receives one to [`MAX_TRANSFER_FDS`] descriptors from one tagged `SCM_RIGHTS` record,
/// closing every received descriptor when the record is rejected.
fn recv_fds_until(
    stream: &UnixStream,
    deadline: ProtocolDeadline,
) -> std::io::Result<Vec<OwnedFd>> {
    // One extra slot distinguishes an oversized record from a full one.
    let rights_bytes = ((MAX_TRANSFER_FDS + 1) * mem::size_of::<RawFd>()) as u32;
    let mut payload = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // SAFETY: rights_bytes is a checked descriptor-array size.
    let control_bytes = unsafe { libc::CMSG_SPACE(rights_bytes) as usize };
    let word_bytes = mem::size_of::<usize>();
    let mut control = vec![0usize; control_bytes.div_ceil(word_bytes)];
    // SAFETY: zero initializes the unused pointers and lengths in msghdr.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control_bytes;
    let received = loop {
        stream.set_read_timeout(Some(deadline.remaining()?))?;
        // SAFETY: all writable message buffers are live and sized for their declared lengths.
        let result =
            unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
        if result >= 0 {
            break result;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(err);
        }
    };
    let mut received_fds = Vec::new();
    let mut invalid_control = false;
    let mut rights_messages = 0;
    // SAFETY: validate each kernel-provided header's bounds before reading it; adopt each
    // received descriptor once so every validation failure closes the accumulated descriptors.
    unsafe {
        let control_start = message.msg_control as usize;
        let control_end = control_start.saturating_add(message.msg_controllen);
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            let base_len = libc::CMSG_LEN(0) as usize;
            let header_start = header as usize;
            if header_start < control_start
                || header_start.saturating_add(base_len) > control_end
                || (*header).cmsg_len < base_len
                || (*header).cmsg_len > control_end.saturating_sub(header_start)
            {
                invalid_control = true;
                break;
            }
            let data_len = (*header).cmsg_len - base_len;
            if (*header).cmsg_level != libc::SOL_SOCKET
                || (*header).cmsg_type != libc::SCM_RIGHTS
                || data_len % mem::size_of::<RawFd>() != 0
            {
                invalid_control = true;
            } else {
                rights_messages += 1;
                let count = data_len / mem::size_of::<RawFd>();
                let data = libc::CMSG_DATA(header).cast::<RawFd>();
                for index in 0..count {
                    received_fds.push(OwnedFd::from_raw_fd(std::ptr::read_unaligned(
                        data.add(index),
                    )));
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if received == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
    }
    let invalid = if received != payload.len() as isize {
        Some("descriptor transfer data was truncated")
    } else if payload[0] != FD_TAG {
        Some("descriptor transfer tag is invalid")
    } else if message.msg_flags & libc::MSG_TRUNC != 0 {
        Some("descriptor transfer data was truncated")
    } else if message.msg_flags & libc::MSG_CTRUNC != 0 {
        Some("descriptor transfer ancillary data was truncated")
    } else if invalid_control {
        Some("descriptor transfer contains an invalid ancillary record")
    } else if rights_messages != 1 {
        Some("descriptor transfer must contain exactly one SCM_RIGHTS record")
    } else if received_fds.is_empty() || received_fds.len() > MAX_TRANSFER_FDS {
        Some("descriptor transfer has an invalid descriptor count")
    } else {
        None
    };
    if let Some(reason) = invalid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{reason}: received {} descriptors, at most {MAX_TRANSFER_FDS} allowed",
                received_fds.len()
            ),
        ));
    }
    Ok(received_fds)
}

/// Opaque metadata and owned descriptors in frontend-defined wire order.
pub struct Transfer {
    pub metadata: Vec<u8>,
    pub fds: Vec<OwnedFd>,
}

impl Transfer {
    pub(crate) fn send(&self, stream: &mut UnixStream, deadline: ProtocolDeadline) -> Result<()> {
        write_raw_frame_until(stream, deadline, &self.metadata)
            .context("failed to send session transfer metadata")?;
        let fds: Vec<_> = self.fds.iter().map(AsFd::as_fd).collect();
        send_fds_until(stream, &fds, deadline)
            .context("failed to send session transfer descriptors")
    }

    pub(crate) fn receive(stream: &mut UnixStream, deadline: ProtocolDeadline) -> Result<Self> {
        let metadata = read_raw_frame_until(stream, deadline)?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "session transfer closed before metadata",
            )
        })?;
        let fds = recv_fds_until(stream, deadline)
            .context("failed to receive session transfer descriptors")?;
        Ok(Self { metadata, fds })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::continuity::test_support::{assert_cloexec, assert_peer_closed, test_deadline};
    use std::io::{Read, Seek, SeekFrom, Write};

    #[test]
    fn http_read_ahead_is_preserved_across_control_frames() {
        for prefix_len in [1, 4, 7, 21] {
            let (mut sender, mut receiver) = UnixStream::pair().unwrap();
            write_frame_until(&mut sender, test_deadline(), &"info").unwrap();
            write_frame_until(&mut sender, test_deadline(), &"ready").unwrap();
            let mut prefix = vec![0; prefix_len];
            receiver.read_exact(&mut prefix).unwrap();
            let mut buffered = std::io::Cursor::new(prefix);
            for expected in ["info", "ready"] {
                assert_eq!(
                    read_buffered_frame_until::<String>(
                        &mut receiver,
                        &mut buffered,
                        test_deadline(),
                    )
                    .unwrap()
                    .as_deref(),
                    Some(expected)
                );
            }
        }
    }

    fn read_request(frame: &[u8]) -> Result<Option<String>> {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender.write_all(frame).unwrap();
        drop(sender);
        read_frame_until(&mut receiver, test_deadline())
    }

    fn read_file(fd: OwnedFd) -> String {
        let mut file = std::fs::File::from(fd);
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        content
    }

    #[test]
    fn transfer_preserves_metadata_descriptor_order_and_close_on_exec() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let mut first = tempfile::tempfile().unwrap();
        let mut second = tempfile::tempfile().unwrap();
        first.write_all(b"first").unwrap();
        second.write_all(b"second").unwrap();
        let transfer = Transfer {
            metadata: br#"{"opaque":true}"#.to_vec(),
            fds: vec![first.into(), second.into()],
        };
        transfer.send(&mut sender, test_deadline()).unwrap();
        let received = Transfer::receive(&mut receiver, test_deadline()).unwrap();
        assert_eq!(received.metadata, transfer.metadata);
        assert_cloexec(received.fds.iter().map(AsFd::as_fd));
        let mut received = received.fds.into_iter();
        assert_eq!(read_file(received.next().unwrap()), "first");
        assert_eq!(read_file(received.next().unwrap()), "second");
    }

    #[test]
    fn truncated_transport_is_distinct_from_malformed_protocol() {
        assert!(read_request(&[]).unwrap().is_none());

        for frame in [vec![1], vec![1, 0, 0], vec![2, 0, 0, 0, b'{']] {
            let error = read_request(&frame).unwrap_err();
            assert_eq!(
                error.io_error().unwrap().kind(),
                std::io::ErrorKind::UnexpectedEof
            );
        }

        let unknown_field = br#"{"type":"info","unexpected":true}"#;
        let mut unknown_frame = (unknown_field.len() as u32).to_le_bytes().to_vec();
        unknown_frame.extend_from_slice(unknown_field);

        for frame in [[&1u32.to_le_bytes()[..], b"{"].concat(), unknown_frame] {
            let error = read_request(&frame).unwrap_err();
            assert!(
                matches!(error, Error::Protocol(_)),
                "invalid frame returned {error:?}"
            );
        }
    }

    #[test]
    fn transaction_deadline_is_not_reset_by_partial_frame_progress() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let payload = serde_json::to_vec(&"trickled frame").unwrap();
        let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(&payload);
        let sender = std::thread::spawn(move || {
            for byte in frame {
                std::thread::sleep(std::time::Duration::from_millis(10));
                if writer.write_all(&[byte]).is_err() {
                    break;
                }
            }
        });

        let started = std::time::Instant::now();
        let deadline = ProtocolDeadline::after(
            std::time::Duration::from_millis(30),
            "test protocol transaction",
        );
        let error = read_frame_until::<String>(&mut reader, deadline).unwrap_err();
        assert!(
            started.elapsed() < std::time::Duration::from_millis(100),
            "trickled frame exceeded its transaction deadline: {error:?}"
        );
        sender.join().unwrap();
    }

    #[test]
    fn additional_ancillary_records_are_rejected_without_leaking_fds() {
        let (left, right) = UnixStream::pair().unwrap();
        let enable: libc::c_int = 1;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    right.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    (&enable as *const libc::c_int).cast(),
                    mem::size_of_val(&enable) as libc::socklen_t,
                )
            },
            0
        );
        let (sentinel, peer) = UnixStream::pair().unwrap();
        let other = tempfile::tempfile().unwrap();
        send_fds_until(&left, &[sentinel.as_fd(), other.as_fd()], test_deadline()).unwrap();
        drop(sentinel);
        drop(other);

        let error = recv_fds_until(&right, test_deadline()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_peer_closed(peer);
    }

    #[test]
    fn invalid_fd_counts_and_truncation_close_received_descriptors() {
        let (mut left, right) = UnixStream::pair().unwrap();
        left.write_all(&[FD_TAG]).unwrap();
        let error = recv_fds_until(&right, test_deadline()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

        for sent_count in [MAX_TRANSFER_FDS + 1, 64] {
            let (left, right) = UnixStream::pair().unwrap();
            let (sentinel, peer) = UnixStream::pair().unwrap();
            let files: Vec<_> = (1..sent_count)
                .map(|_| tempfile::tempfile().unwrap())
                .collect();
            let mut fds = vec![sentinel.as_fd()];
            fds.extend(files.iter().map(AsFd::as_fd));

            send_fds_until(&left, &fds, test_deadline()).unwrap();
            drop(fds);
            drop(files);
            drop(sentinel);

            let error = recv_fds_until(&right, test_deadline()).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
            assert_peer_closed(peer);
        }
    }
}
