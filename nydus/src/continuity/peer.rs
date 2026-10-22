use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// Authenticates the effective uid before returning the peer pid.
pub(crate) fn authenticate_peer(stream: &UnixStream) -> io::Result<u32> {
    let mut credentials = MaybeUninit::<libc::ucred>::zeroed();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: credentials and length provide correctly sized writable storage.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SO_PEERCRED response length",
        ));
    }
    // SAFETY: getsockopt succeeded and returned a complete ucred.
    let credentials = unsafe { credentials.assume_init() };
    // SAFETY: geteuid takes no pointers and cannot fail.
    if credentials.uid != unsafe { libc::geteuid() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "control peer has a different effective uid",
        ));
    }
    u32::try_from(credentials.pid).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "control peer has an invalid pid",
        )
    })
}

/// Tracks exit and signals through a pidfd, never through a reusable numeric pid.
pub(crate) enum PeerProcess {
    Exited,
    Tracked(OwnedFd),
    Untracked,
}

impl PeerProcess {
    pub(crate) fn observe(pid: u32) -> Self {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return Self::Untracked;
        };
        // SAFETY: pidfd_open takes a checked pid and zero flags.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd >= 0 {
            // SAFETY: pidfd_open returned a fresh owned descriptor.
            return Self::Tracked(unsafe { OwnedFd::from_raw_fd(fd as i32) });
        }
        if io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            Self::Exited
        } else {
            Self::Untracked
        }
    }

    pub(crate) fn confirm_exited(&self, timeout: Duration) -> bool {
        let Self::Tracked(pidfd) = self else {
            return matches!(self, Self::Exited);
        };
        let started = Instant::now();
        loop {
            let remaining = timeout.saturating_sub(started.elapsed());
            let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
            let mut poll = libc::pollfd {
                fd: pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll points to one initialized entry containing a borrowed live pidfd.
            let result = unsafe { libc::poll(&mut poll, 1, timeout_ms) };
            if result > 0 {
                return poll.revents & libc::POLLIN != 0;
            }
            if result == 0 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return false;
            }
        }
    }

    pub(crate) fn can_terminate(&self) -> bool {
        let Self::Tracked(pidfd) = self else {
            return matches!(self, Self::Exited);
        };
        // SAFETY: the owned pidfd identifies the peer; a null siginfo requests default delivery.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                0,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }

    pub(crate) fn terminate_and_confirm(&self, timeout: Duration) -> io::Result<bool> {
        let Self::Tracked(pidfd) = self else {
            return Ok(matches!(self, Self::Exited));
        };
        if self.confirm_exited(Duration::ZERO) {
            return Ok(true);
        }
        // SAFETY: the owned pidfd cannot be recycled to target another process.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        Ok(self.confirm_exited(timeout))
    }
}
