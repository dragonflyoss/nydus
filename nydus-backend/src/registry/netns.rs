//! A Linux network namespace the runtime's threads enter before they do any
//! work, so sockets and DNS queries never depend on the caller's namespace.

use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;

/// The identity of a network namespace: the device and inode of its
/// `/proc/<pid>/ns/net` file, which is what `setns` compares namespaces by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetnsId {
    dev: u64,
    ino: u64,
}

impl fmt::Display for NetnsId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dev {} ino {}", self.dev, self.ino)
    }
}

/// A network namespace held open by a descriptor on its `/proc/<pid>/ns/net`
/// file. Two values are equal when they name the same namespace, however
/// they were opened.
#[derive(Debug)]
pub struct Netns {
    fd: OwnedFd,
    id: NetnsId,
}

impl PartialEq for Netns {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Netns {}

impl Netns {
    /// Wrap an open namespace descriptor, recording its identity. Entering
    /// it is not checked here, see [`probe`](Self::probe).
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        let metadata = File::from(fd.try_clone()?).metadata()?;
        Ok(Self {
            fd,
            id: NetnsId {
                dev: metadata.dev(),
                ino: metadata.ino(),
            },
        })
    }

    /// The namespace's identity.
    pub fn id(&self) -> NetnsId {
        self.id
    }

    /// Move the calling thread into the namespace.
    #[cfg(target_os = "linux")]
    pub fn enter(&self) -> io::Result<()> {
        // SAFETY: setns only takes the descriptor and a flag, and the
        // descriptor is owned by `self`, so it is open for the whole call.
        let rc = unsafe { libc::setns(self.fd.as_raw_fd(), libc::CLONE_NEWNET) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Move the calling thread into the namespace.
    #[cfg(not(target_os = "linux"))]
    pub fn enter(&self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "network namespaces are only supported on linux",
        ))
    }

    /// Verify the namespace can be entered, on a scratch thread whose
    /// namespace change dies with it, so an unusable descriptor or a missing
    /// privilege fails here rather than inside a runtime thread.
    pub fn probe(&self) -> io::Result<()> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| self.enter())
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
}

#[cfg(all(test, target_os = "linux"))]
impl Netns {
    /// The calling thread's network namespace.
    pub(super) fn current() -> io::Result<Self> {
        Self::new(File::open("/proc/thread-self/ns/net")?.into())
    }

    /// A network namespace of our own, distinguishable from the one the test
    /// process runs in. Needs the same privilege as `setns`, so a
    /// `PermissionDenied` here means the test cannot run in this environment.
    pub(super) fn unshared() -> io::Result<Self> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    // SAFETY: unshare only affects this scratch thread, which
                    // exits right after; the descriptor keeps the namespace.
                    if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Self::current()
                })
                .join()
                .unwrap()
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn new_records_the_identity_of_the_descriptor() {
        let first = Netns::current().unwrap();
        let second = Netns::current().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.id(), second.id());
    }

    #[test]
    fn probe_rejects_a_non_namespace_descriptor() {
        let netns = Netns::new(OwnedFd::from(tempfile::tempfile().unwrap())).unwrap();
        let err = netns.probe().unwrap_err();
        assert!(err.to_string().contains("netns"), "{err}");
    }

    #[test]
    fn an_unshared_namespace_differs_and_can_be_entered() {
        let netns = match Netns::unshared() {
            Ok(netns) => netns,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipped: cannot create a netns ({err})");
                return;
            }
            Err(err) => panic!("unshare(CLONE_NEWNET): {err}"),
        };
        assert_ne!(netns, Netns::current().unwrap());
        netns.probe().unwrap();
    }
}
