//! Entering a network namespace on the runtime's threads: the `setns` the
//! thread start hook makes, the probe that validates a descriptor before the
//! runtime is built, and the inode identity `setns` compares namespaces by.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

/// `(st_dev, st_ino)` of the namespace inode behind `fd`.
pub(super) fn identity(fd: &OwnedFd) -> io::Result<(u64, u64)> {
    // SAFETY: fstat writes only into the zeroed stat buffer we hand it and the
    // descriptor is owned (open) for the duration of the call.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd.as_raw_fd(), &mut st) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // Field widths differ across targets; widen them uniformly.
    #[allow(clippy::unnecessary_cast)]
    Ok((st.st_dev as u64, st.st_ino as u64))
}

/// Verify that `netns` can be entered, on a scratch thread whose namespace
/// change dies with it.
pub(super) fn probe(netns: &OwnedFd) -> io::Result<()> {
    let fd = netns.as_raw_fd();
    std::thread::scope(|scope| {
        scope
            .spawn(move || enter(fd))
            .join()
            .map_err(|_| io::Error::other("netns probe thread panicked"))?
    })
    .map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("cannot enter the configured netns for the backend runtime: {err}"),
        )
    })
}

/// Move the calling thread into the network namespace behind `fd`.
#[cfg(target_os = "linux")]
pub(super) fn enter(fd: RawFd) -> io::Result<()> {
    // SAFETY: setns only takes the descriptor and a flag; the descriptor is
    // owned by the process-wide RuntimeOptions and stays open for the life of
    // the process, so it cannot have been reused for anything else.
    let rc = unsafe { libc::setns(fd, libc::CLONE_NEWNET) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn enter(_fd: RawFd) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "network namespaces are only supported on linux",
    ))
}

/// The identity of the calling thread's network namespace.
#[cfg(all(test, target_os = "linux"))]
pub(super) fn current() -> (u64, u64) {
    let ns = std::fs::File::open("/proc/thread-self/ns/net").unwrap();
    identity(&OwnedFd::from(ns)).unwrap()
}

/// A network namespace of our own, distinguishable from the one the test
/// process runs in. Needs the same privilege as `setns`, so a
/// `PermissionDenied` here means the test cannot run in this environment.
#[cfg(all(test, target_os = "linux"))]
pub(super) fn fresh() -> io::Result<OwnedFd> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                // SAFETY: unshare only affects this scratch thread, which
                // exits right after; the descriptor keeps the namespace.
                if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                std::fs::File::open("/proc/thread-self/ns/net").map(OwnedFd::from)
            })
            .join()
            .unwrap()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_rejects_a_non_namespace_descriptor() {
        let file = tempfile::tempfile().unwrap();
        let err = probe(&OwnedFd::from(file)).unwrap_err();
        assert!(err.to_string().contains("netns"), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_fresh_namespace_differs_from_the_current_one() {
        let netns = match fresh() {
            Ok(netns) => netns,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipped: cannot create a netns ({err})");
                return;
            }
            Err(err) => panic!("unshare(CLONE_NEWNET): {err}"),
        };
        assert_ne!(identity(&netns).unwrap(), current());
        probe(&netns).unwrap();
    }
}
