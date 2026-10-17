use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Instant;

use nydus_error::{Context, Error, Result};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

use super::{lock_exclusive, CONTROL_RESPONSE_TIMEOUT};

const MAX_RECORD_BYTES: u64 = 64 * 1024;

/// Derives a stable coordination key from the frontend and native resource, never the image or API path.
pub fn state_base(frontend: &str, resource: &str) -> Result<PathBuf> {
    if frontend.is_empty()
        || !frontend
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(Error::InvalidParameter(
            "invalid continuity frontend name".into(),
        ));
    }
    // SAFETY: geteuid takes no pointers and cannot fail.
    let directory = PathBuf::from(format!("/tmp/nydus-{frontend}-{}", unsafe {
        libc::geteuid()
    }));
    Ok(directory.join(format!("{:x}", Sha256::digest(resource.as_bytes()))))
}

fn state_path(base: &Path, suffix: &str) -> PathBuf {
    let mut path = base.as_os_str().to_owned();
    path.push(suffix);
    path.into()
}

/// Keeps the startup inode locked through discovery and optional API publication.
pub(crate) fn lock_startup(base: &Path) -> Result<File> {
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(state_path(base, ".lock"))?;
    lock_exclusive(&file).with_context(|| {
        format!(
            "another process may be deciding ownership through {}",
            base.display()
        )
    })?;
    Ok(file)
}

pub(crate) fn prepare_state_directory(directory: &Path) -> Result<()> {
    match std::fs::DirBuilder::new().mode(0o700).create(directory) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "failed to create ownership directory {}",
                    directory.display()
                )
            })
        }
    }
    let metadata = std::fs::symlink_metadata(directory)?;
    // SAFETY: geteuid takes no pointers and cannot fail.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(Error::InvalidParameter(format!(
            "ownership directory {} must be a non-symlink directory owned by the effective uid with no group or other access",
            directory.display()
        )));
    }
    Ok(())
}

/// Lifetime ownership, held by workers and teardown independently of endpoint liveness.
/// Frontends own the record format and decide what it must prove.
pub struct SessionOwner {
    file: File,
}

impl SessionOwner {
    pub(crate) fn acquire(base: &Path, create: bool) -> Result<Self> {
        let path = state_path(base, ".owner");
        let mut options = File::options();
        options
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW);
        let file = options
            .create(create)
            .open(&path)
            .with_context(|| format!("cannot open session ownership record {}", path.display()))?;
        if !file.metadata()?.is_file() {
            return Err(Error::Runtime(
                "session ownership record is not a file".into(),
            ));
        }
        lock_exclusive(&file).context(
            "cannot acquire session ownership; an existing reader or teardown may still be active",
        )?;
        Ok(Self { file })
    }

    pub(crate) fn wait_for_release(base: &Path, create: bool) -> Result<Self> {
        let deadline = Instant::now() + CONTROL_RESPONSE_TIMEOUT;
        loop {
            match Self::acquire(base, create) {
                Ok(owner) => return Ok(owner),
                Err(err)
                    if err
                        .io_error()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::WouldBlock)
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(10))
                }
                Err(err) => return Err(err),
            }
        }
    }

    /// Waits without a deadline once a handoff is irreversible; only cancellation stops it.
    pub(crate) fn wait_for_predecessor_release(
        base: &Path,
        check_cancelled: impl Fn() -> Result<()>,
    ) -> Result<Self> {
        let mut warned = Instant::now();
        loop {
            match Self::acquire(base, false) {
                Ok(owner) => return Ok(owner),
                Err(err)
                    if err
                        .io_error()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::WouldBlock) =>
                {
                    check_cancelled()?;
                    if warned.elapsed() >= CONTROL_RESPONSE_TIMEOUT {
                        warn!("predecessor still holds session ownership after release; waiting");
                        warned = Instant::now();
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10))
                }
                Err(err) => return Err(err),
            }
        }
    }

    /// Reads the record without the lifetime lock. Callers must hold the startup lock,
    /// which excludes fresh startup, the only writer.
    pub(crate) fn peek<T: DeserializeOwned>(base: &Path) -> Result<T> {
        let path = state_path(base, ".owner");
        let file = File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .with_context(|| format!("cannot open session ownership record {}", path.display()))?;
        if !file.metadata()?.is_file() {
            return Err(Error::Runtime(
                "session ownership record is not a file".into(),
            ));
        }
        read_record(&file)
    }

    pub(crate) fn write<T: Serialize>(&mut self, record: &T) -> Result<()> {
        let bytes = serde_json::to_vec(record)?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(Error::InvalidParameter(
                "session ownership record is too large".into(),
            ));
        }
        self.file.seek(SeekFrom::Start(0))?;
        self.file.set_len(0)?;
        self.file.write_all(&bytes)?;
        self.file.sync_data()?;
        Ok(())
    }

    pub(crate) fn read_optional<T: DeserializeOwned>(&mut self) -> Result<Option<T>> {
        if self.file.metadata()?.len() == 0 {
            Ok(None)
        } else {
            self.read().map(Some)
        }
    }

    pub(crate) fn read<T: DeserializeOwned>(&mut self) -> Result<T> {
        self.file.seek(SeekFrom::Start(0))?;
        read_record(&self.file)
    }
}

fn read_record<T: DeserializeOwned>(file: &File) -> Result<T> {
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(Error::Protocol(
            "session ownership record is too large".into(),
        ));
    }
    serde_json::from_slice(&bytes)
        .context("missing or invalid session ownership record; recovery is not authorized")
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt};

    use super::*;

    #[test]
    fn coordination_keys_separate_frontends_without_changing_fuse_paths() {
        let fuse = state_base("fuse", "/mnt/image").unwrap();
        let hash = format!("{:x}", Sha256::digest(b"/mnt/image"));
        assert_eq!(
            fuse,
            PathBuf::from(format!("/tmp/nydus-fuse-{}/{hash}", unsafe {
                libc::geteuid()
            }))
        );
        assert_ne!(fuse, state_base("nbd", "/mnt/image").unwrap());
        assert_ne!(fuse, state_base("fuse", "/mnt/other").unwrap());
        assert!(state_base("../other", "device").is_err());
    }

    #[test]
    fn locks_preserve_their_inodes_and_lifetime_exclusion() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("session");
        let startup = lock_startup(&base).unwrap();
        let owner = SessionOwner::acquire(&base, true).unwrap();
        let inode = std::fs::metadata(state_path(&base, ".lock")).unwrap().ino();
        assert!(lock_startup(&base).is_err());
        assert!(SessionOwner::acquire(&base, false).is_err());
        drop(startup);
        let _startup = lock_startup(&base).unwrap();
        assert_eq!(
            std::fs::metadata(state_path(&base, ".lock")).unwrap().ino(),
            inode
        );
        assert!(SessionOwner::acquire(&base, false).is_err());
        drop(owner);
        assert!(SessionOwner::acquire(&base, false).is_ok());
    }

    #[test]
    fn state_paths_reject_symlinks_and_unsafe_existing_directories() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        prepare_state_directory(&state).unwrap();
        let before = std::fs::metadata(&state).unwrap();
        prepare_state_directory(&state).unwrap();
        assert_eq!(std::fs::metadata(&state).unwrap().ino(), before.ino());
        assert_eq!(before.mode() & 0o077, 0);
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(prepare_state_directory(&state).is_err());
        assert_eq!(std::fs::metadata(&state).unwrap().mode() & 0o777, 0o750);
        let alias = dir.path().join("alias");
        symlink(&state, &alias).unwrap();
        assert!(prepare_state_directory(&alias).is_err());
        let base = dir.path().join("session");
        symlink(&state, state_path(&base, ".owner")).unwrap();
        assert!(SessionOwner::acquire(&base, true).is_err());
    }
}
