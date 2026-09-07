use std::io::{Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use nydus_error::{Error, Result};
use serde::{Deserialize, Serialize};

const MAX_FRAME_BYTES: u32 = 4 * 1024 * 1024;
const FD_TAG: u8 = b'F';

#[derive(Clone, Copy)]
pub(super) struct ProtocolDeadline {
    expires_at: Instant,
    transaction: &'static str,
}

impl ProtocolDeadline {
    pub(super) fn after(timeout: Duration, transaction: &'static str) -> Self {
        Self {
            expires_at: Instant::now() + timeout,
            transaction,
        }
    }

    pub(super) fn remaining(self) -> std::io::Result<Duration> {
        let remaining = self
            .expires_at
            .checked_duration_since(Instant::now())
            .unwrap_or_default();
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("{} deadline expired", self.transaction),
            ));
        }
        Ok(remaining)
    }
}

struct DeadlineStream<'a> {
    stream: &'a mut UnixStream,
    deadline: ProtocolDeadline,
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

pub(super) fn write_raw_frame_until(
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

pub(super) fn write_frame_until<T: Serialize>(
    stream: &mut UnixStream,
    deadline: ProtocolDeadline,
    value: &T,
) -> Result<()> {
    let payload = serde_json::to_vec(value)?;
    write_raw_frame_until(stream, deadline, &payload)
}

pub(super) fn read_frame_until<T: for<'de> Deserialize<'de>>(
    stream: &mut UnixStream,
    deadline: ProtocolDeadline,
) -> Result<Option<T>> {
    let Some(payload) = read_raw_frame_until(stream, deadline)? else {
        return Ok(None);
    };
    serde_json::from_slice(&payload)
        .map(Some)
        .map_err(|err| Error::Protocol(format!("malformed control frame JSON: {err}")))
}

pub(super) fn read_raw_frame_until(
    stream: &mut UnixStream,
    deadline: ProtocolDeadline,
) -> Result<Option<Vec<u8>>> {
    let mut stream = DeadlineStream { stream, deadline };
    let mut length = [0u8; 4];
    loop {
        match stream.read(&mut length[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err.into()),
        }
    }
    read_frame_exact(&mut stream, &mut length[1..], "length")?;
    let length = u32::from_le_bytes(length);
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(Error::Protocol(format!(
            "invalid control frame length {length}"
        )));
    }
    let mut payload = vec![0u8; length as usize];
    read_frame_exact(&mut stream, &mut payload, "payload")?;
    Ok(Some(payload))
}

fn read_frame_exact(stream: &mut impl Read, bytes: &mut [u8], part: &str) -> Result<()> {
    stream.read_exact(bytes).map_err(|err| {
        if err.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::Protocol(format!("truncated control frame {part}"))
        } else {
            err.into()
        }
    })
}

pub(super) fn send_fds_until(
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
    let control_bytes = unsafe { libc::CMSG_SPACE(rights_bytes) as usize };
    let word_bytes = mem::size_of::<usize>();
    let mut control = vec![0usize; control_bytes.div_ceil(word_bytes)];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control_bytes;
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

pub(super) fn recv_fds_exact_until(
    stream: &UnixStream,
    expected: usize,
    deadline: ProtocolDeadline,
) -> std::io::Result<Vec<OwnedFd>> {
    if expected == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "at least one descriptor is required",
        ));
    }
    let capacity = expected.checked_add(1).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "too many descriptors requested",
        )
    })?;
    let rights_bytes = capacity
        .checked_mul(mem::size_of::<RawFd>())
        .and_then(|size| u32::try_from(size).ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many descriptors requested",
            )
        })?;
    let mut payload = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let control_bytes = unsafe { libc::CMSG_SPACE(rights_bytes) as usize };
    let word_bytes = mem::size_of::<usize>();
    let mut control = vec![0usize; control_bytes.div_ceil(word_bytes)];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control_bytes;
    let received = loop {
        stream.set_read_timeout(Some(deadline.remaining()?))?;
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
    } else if received_fds.len() != expected {
        Some("descriptor transfer has the wrong descriptor count")
    } else {
        None
    };
    if let Some(reason) = invalid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{reason}: received {} descriptors, expected {expected}",
                received_fds.len()
            ),
        ));
    }
    Ok(received_fds)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::AsFd;

    use super::*;
    use crate::fuse::upgrade::handoff::{InstanceInfo, Request};
    use crate::fuse::upgrade::test_support::{assert_cloexec, assert_peer_closed, test_deadline};

    fn read_request(frame: &[u8]) -> Result<Option<Request>> {
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
    fn frames_and_fds_round_trip_atomically_with_close_on_exec() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        write_frame_until(
            &mut sender,
            test_deadline(),
            &Request::HandoffBegin {
                peer: InstanceInfo::new("/mnt", &[0; 32]),
            },
        )
        .unwrap();
        assert!(matches!(
            read_frame_until::<Request>(&mut receiver, test_deadline())
                .unwrap()
                .unwrap(),
            Request::HandoffBegin { .. }
        ));

        let (left, right) = UnixStream::pair().unwrap();
        let mut first = tempfile::tempfile().unwrap();
        let mut second = tempfile::tempfile().unwrap();
        first.write_all(b"first").unwrap();
        second.write_all(b"second").unwrap();
        send_fds_until(&left, &[first.as_fd(), second.as_fd()], test_deadline()).unwrap();

        let received = recv_fds_exact_until(&right, 2, test_deadline()).unwrap();
        assert_cloexec(received.iter().map(AsFd::as_fd));
        let mut received = received.into_iter();
        assert_eq!(read_file(received.next().unwrap()), "first");
        assert_eq!(read_file(received.next().unwrap()), "second");
    }

    #[test]
    fn partial_and_malformed_frames_are_protocol_errors() {
        assert!(read_request(&[]).unwrap().is_none());

        let unknown_field = br#"{"type":"info","unexpected":true}"#;
        let mut unknown_frame = (unknown_field.len() as u32).to_le_bytes().to_vec();
        unknown_frame.extend_from_slice(unknown_field);

        for frame in [
            vec![1],                                  // truncated length
            vec![1, 0, 0],                            // truncated length
            vec![2, 0, 0, 0, b'{'],                   // truncated payload
            [&1u32.to_le_bytes()[..], b"{"].concat(), // malformed JSON
            unknown_frame,                            // unknown request field
        ] {
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
        let payload = serde_json::to_vec(&Request::Info {}).unwrap();
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
        let error = read_frame_until::<Request>(&mut reader, deadline).unwrap_err();
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

        let error = recv_fds_exact_until(&right, 2, test_deadline()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_peer_closed(peer);
    }

    #[test]
    fn invalid_fd_counts_and_truncation_close_received_descriptors() {
        let (mut left, right) = UnixStream::pair().unwrap();
        left.write_all(&[FD_TAG]).unwrap();
        let error = recv_fds_exact_until(&right, 2, test_deadline()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

        for sent_count in [1, 3, 64] {
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

            let error = recv_fds_exact_until(&right, 2, test_deadline()).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
            assert_peer_closed(peer);
        }
    }
}
