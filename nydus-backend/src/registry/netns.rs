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
    /// The device the namespace file lives on.
    dev: u64,

    /// The inode of the namespace file.
    ino: u64,
}

/// Implements the display of a namespace identity.
impl fmt::Display for NetnsId {
    /// Formats the identity as its device and inode.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dev {} ino {}", self.dev, self.ino)
    }
}

/// A network namespace held open by a descriptor on its `/proc/<pid>/ns/net`
/// file. Two values are equal when they name the same namespace, however
/// they were opened.
#[derive(Debug)]
pub struct Netns {
    /// The open namespace file, kept for as long as threads may enter it.
    fd: OwnedFd,

    /// The identity read from `fd` when the value was created.
    id: NetnsId,
}

/// Implements equality by namespace identity, however the descriptors were
/// opened.
impl PartialEq for Netns {
    /// Returns whether both values name the same namespace.
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

/// Implements [Eq] for the namespace.
impl Eq for Netns {}

/// Implements the network namespace.
impl Netns {
    /// Creates a namespace from an open descriptor on its `ns/net` file,
    /// recording its identity.
    ///
    /// Entering it is not checked here, see [`probe`](Self::probe).
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

    /// Returns the namespace's identity.
    pub fn id(&self) -> NetnsId {
        self.id
    }

    /// Moves the calling thread into the namespace.
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

    /// Moves the calling thread into the namespace.
    #[cfg(not(target_os = "linux"))]
    pub fn enter(&self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "network namespaces are only supported on linux",
        ))
    }

    /// Verifies the namespace can be entered.
    ///
    /// The check runs on a scratch thread whose namespace change dies with
    /// it, so an unusable descriptor or a missing privilege fails here rather
    /// than inside a runtime thread.
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
mod tests {
    use super::*;

    #[test]
    fn probe_rejects_a_non_namespace_descriptor() {
        let netns = Netns::new(OwnedFd::from(tempfile::tempfile().unwrap())).unwrap();
        let err = netns.probe().unwrap_err();
        assert!(err.to_string().contains("netns"), "{err}");
    }
}
