use std::io;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

use serde::{Deserialize, Serialize};

use nydus_format::utils::hex_string;

pub(in crate::fuse::upgrade) fn authenticate_peer(stream: &UnixStream) -> io::Result<u32> {
    let mut credentials = MaybeUninit::<libc::ucred>::zeroed();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
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
    let credentials = unsafe { credentials.assume_init() };
    if credentials.uid != unsafe { libc::geteuid() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "fuse control peer has a different effective uid",
        ));
    }
    u32::try_from(credentials.pid).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "fuse control peer has an invalid pid",
        )
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::fuse::upgrade) struct InstanceInfo {
    pub(in crate::fuse::upgrade) pid: u32,
    pub(in crate::fuse::upgrade) version: String,
    pub(in crate::fuse::upgrade) mountpoint: String,
    pub(in crate::fuse::upgrade) image_digest: String,
}

impl InstanceInfo {
    pub(in crate::fuse::upgrade) fn new(mountpoint: &str, image_digest: &[u8]) -> Self {
        Self {
            pid: std::process::id(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            mountpoint: mountpoint.to_string(),
            image_digest: hex_string(image_digest),
        }
    }

    pub(super) fn check(&self, peer: &Self) -> std::result::Result<(), String> {
        if peer.mountpoint != self.mountpoint {
            return Err(format!(
                "mountpoint mismatch: peer owns {}, expected {}",
                peer.mountpoint, self.mountpoint
            ));
        }
        if peer.image_digest != self.image_digest {
            return Err(format!(
                "image content mismatch: peer {}, expected {}",
                peer.image_digest, self.image_digest
            ));
        }
        Ok(())
    }

    pub(super) fn check_pid(&self, authenticated_pid: u32) -> std::result::Result<(), String> {
        if self.pid != authenticated_pid {
            return Err(format!(
                "peer pid mismatch: declared {}, authenticated {}",
                self.pid, authenticated_pid
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_check_rejects_a_mismatched_session() {
        let current = InstanceInfo::new("/mnt", &[1; 32]);

        let replacement_mount = InstanceInfo::new("/other", &[1; 32]);
        assert!(current.check(&replacement_mount).is_err());

        let replacement_digest = InstanceInfo::new("/mnt", &[2; 32]);
        assert!(current.check(&replacement_digest).is_err());
    }

    #[test]
    fn declared_pid_must_match_the_authenticated_peer() {
        // The uid branch in `authenticate_peer` cannot be reached in-process:
        // both ends of a socketpair share this process's euid. What is worth
        // pinning is that a peer cannot pass off a pid it does not own.
        let mut declared = InstanceInfo::new("/mnt", &[1; 32]);
        assert!(declared.check_pid(declared.pid).is_ok());
        declared.pid = declared.pid.saturating_add(1);
        assert!(declared.check_pid(std::process::id()).is_err());
    }
}
