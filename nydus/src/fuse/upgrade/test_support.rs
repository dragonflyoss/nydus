//! Shared unit-test fixtures for the continuity modules.

use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use uuid::Uuid;

use super::handoff::SessionRuntimeHandle;
use super::transfer::{FuseFailoverSession, FuseInitState, SessionProtection};
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

struct EmptyFilesystem;

impl fuser::Filesystem for EmptyFilesystem {}

pub(super) fn fuse_init_state() -> FuseInitState {
    FuseInitState {
        proto_major: 7,
        proto_minor: 31,
        negotiated_init_flags: 0,
        kernel_init_flags: 0,
    }
}

/// A [`SessionRuntimeHandle`] over a parked fuser session whose `/dev/fuse` end is
/// a socketpair half: the handoff machinery only duplicates and streams the
/// fd, never inspects its contents, so a socketpair can stand in for the
/// kernel connection. Pass a `session_id` for a Failover-Protected Session,
/// `None` for a Standalone one.
///
/// The returned kernel-side stream must stay alive for the caller's whole
/// test: once resumed, the worker loop reads from the daemon fd immediately,
/// and a dropped peer would deliver EOF and kill the worker. `spawn_paused`
/// synchronously waits for every worker to register and park before
/// returning, unlike `spawn`, which races the caller against worker startup;
/// callers that need a live serving predecessor resume explicitly.
pub(super) fn parked_runtime_handle(
    session_id: Option<Uuid>,
) -> (SessionRuntimeHandle, fuser::BackgroundSession, UnixStream) {
    let (daemon, kernel) = UnixStream::pair().unwrap();
    let session = fuser::Session::from_initialized_fd(
        EmptyFilesystem,
        OwnedFd::from(daemon),
        fuser::SessionACL::All,
        fuser::Config::default(),
        fuser::Version(7, 31),
        fuser::InitFlags::empty(),
        fuser::InitFlags::empty(),
    )
    .unwrap();
    let fuse_fd = session.as_fd().try_clone_to_owned().unwrap();
    let background = session.spawn_paused(Duration::from_secs(5)).unwrap();
    let protection = match session_id {
        Some(session_id) => SessionProtection::Failover(FuseFailoverSession {
            session_id,
            journal: fuser::InflightJournal::create().unwrap(),
        }),
        None => SessionProtection::Standalone,
    };
    let handle = SessionRuntimeHandle::new(
        background.pauser(),
        fuse_fd,
        fuse_init_state(),
        background.mount_disarmer(),
        protection,
    );
    (handle, background, kernel)
}
