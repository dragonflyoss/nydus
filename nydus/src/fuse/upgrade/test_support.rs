//! Shared unit-test fixtures for the continuity modules.

use std::io::Read;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use super::wire::ProtocolDeadline;

pub(super) fn test_deadline() -> ProtocolDeadline {
    ProtocolDeadline::after(Duration::from_secs(5), "continuity unit test")
}

/// Proves a descriptor received over `SCM_RIGHTS` was closed: the caller
/// keeps the sentinel socketpair's other half and observes EOF once the
/// receiving side drops its copy.
pub(super) fn assert_peer_closed(mut peer: UnixStream) {
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut byte = [0u8; 1];
    assert_eq!(
        peer.read(&mut byte).unwrap(),
        0,
        "expected the received descriptor to be closed"
    );
}

pub(super) fn assert_cloexec<'a>(fds: impl IntoIterator<Item = BorrowedFd<'a>>) {
    for fd in fds {
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags, -1);
        assert_ne!(
            flags & libc::FD_CLOEXEC,
            0,
            "descriptors received over SCM_RIGHTS must be close-on-exec"
        );
    }
}
