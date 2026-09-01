use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use nydus_error::{Context, Error, Result};

const CONTROL_DIR: &str = "/run/nydus/ctl";

fn slug(mountpoint: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(mountpoint.as_bytes());
    format!("fuse-{}", nydus_format::utils::hex_string(&digest[..8]))
}

fn control_socket_path(mountpoint: &str) -> PathBuf {
    Path::new(CONTROL_DIR).join(format!("{}.sock", slug(mountpoint)))
}

pub(super) struct StartupLock {
    _file: std::fs::File,
}

impl StartupLock {
    fn acquire(mountpoint: &str) -> Result<Self> {
        Self::acquire_in(Path::new(CONTROL_DIR), mountpoint)
    }

    pub(super) fn acquire_in(dir: &Path, mountpoint: &str) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!("{}.lock", slug(mountpoint)));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let err = std::io::Error::last_os_error();
            if err
                .raw_os_error()
                .is_some_and(|code| code == libc::EAGAIN || code == libc::EWOULDBLOCK)
            {
                return Err(Error::Runtime(format!(
                    "another process is deciding ownership of fuse mountpoint {mountpoint}"
                )));
            }
            return Err(err).with_context(|| format!("failed to lock {}", path.display()));
        }
        Ok(Self { _file: file })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_is_instance_scoped() {
        let dir = tempfile::tempdir().unwrap();
        let _held = StartupLock::acquire_in(dir.path(), "/mnt/a").unwrap();
        assert!(StartupLock::acquire_in(dir.path(), "/mnt/a").is_err());
        // Scoped, not global: a second mountpoint in the same control
        // directory must still be able to start. A lock name that stopped
        // deriving from the mountpoint would pass the assertion above and
        // deadlock every other instance on the host.
        assert!(StartupLock::acquire_in(dir.path(), "/mnt/b").is_ok());
    }
}
