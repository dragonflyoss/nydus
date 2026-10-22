//! Mount helpers shared by the fanotify and NBD mount lifecycles.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

use nydus_error::{Context, Error, Result};
use tracing::{debug, info};

/// Watches the identity of an owned mount, including lazy external unmounts.
pub struct MountWatcher {
    stop: std::sync::mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
    detached: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl MountWatcher {
    pub fn start(mountpoint: &Path, on_unmount: impl FnOnce() + Send + 'static) -> Result<Self> {
        let path = std::fs::canonicalize(mountpoint).context("resolve owned mountpoint")?;
        let escaped = path
            .to_string_lossy()
            .replace('\\', "\\134")
            .replace(' ', "\\040")
            .replace('\t', "\\011")
            .replace('\n', "\\012");
        let mount_id = move || -> std::io::Result<Option<String>> {
            let info = std::fs::read_to_string("/proc/self/mountinfo")?;
            Ok(info
                .lines()
                .filter_map(|line| {
                    let fields: Vec<_> = line.split_whitespace().take(5).collect();
                    (fields.len() == 5 && fields[4] == escaped).then(|| fields[0].to_string())
                })
                .next_back())
        };
        let original =
            mount_id()?.ok_or_else(|| Error::Runtime("owned mount disappeared".into()))?;
        let (stop, rx) = std::sync::mpsc::channel();
        let detached = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let lost = detached.clone();
        let thread = std::thread::Builder::new()
            .name("nydus_mount_watch".into())
            .spawn(move || loop {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                }
                match mount_id() {
                    Ok(Some(current)) if current == original => continue,
                    Ok(_) => {
                        // Lazy unmount removes the path before the last
                        // open file stops using this mount. Keep serving
                        // those descriptors until they are closed.
                        match MountWatcher::mount_has_open_files(&original) {
                            Ok(true) => continue,
                            Ok(false) => {}
                            Err(err) => {
                                tracing::warn!("cannot inspect detached mount references: {err}");
                                continue;
                            }
                        }
                    }
                    Err(err) => tracing::error!("cannot inspect owned mount: {err}"),
                }
                lost.store(true, std::sync::atomic::Ordering::Release);
                on_unmount();
                return;
            })
            .context("spawn mount watcher")?;
        Ok(Self {
            stop,
            thread: Some(thread),
            detached,
        })
    }

    fn mount_has_open_files(id: &str) -> std::io::Result<bool> {
        Self::mount_has_open_files_at(Path::new("/proc"), id)
    }

    fn mount_has_open_files_at(proc_root: &Path, id: &str) -> std::io::Result<bool> {
        let mount_namespace = std::fs::read_link(proc_root.join("self/ns/mnt"))?;
        for entry in std::fs::read_dir(proc_root)? {
            let entry = entry?;
            if !entry
                .file_name()
                .as_encoded_bytes()
                .iter()
                .all(u8::is_ascii_digit)
            {
                continue;
            }
            let namespace = match std::fs::read_link(entry.path().join("ns/mnt")) {
                Ok(namespace) => namespace,
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    continue
                }
                Err(err) => return Err(err),
            };
            if namespace != mount_namespace {
                continue;
            }
            let descriptors = match std::fs::read_dir(entry.path().join("fdinfo")) {
                Ok(entries) => entries,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err),
            };
            for descriptor in descriptors {
                let text = match std::fs::read_to_string(descriptor?.path()) {
                    Ok(text) => text,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(err) => return Err(err),
                };
                if text.lines().any(|line| {
                    line.strip_prefix("mnt_id:")
                        .is_some_and(|value| value.trim() == id)
                }) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    pub fn detached(&self) -> bool {
        self.detached.load(std::sync::atomic::Ordering::Acquire)
    }
}

impl Drop for MountWatcher {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if self
            .thread
            .take()
            .is_some_and(|thread| thread.join().is_err())
        {
            tracing::error!("mount watcher panicked");
        }
    }
}

/// Shutdown unmount retry window: EBUSY is expected while readers still hold
/// files open, so keep trying for a bounded window (10 s) before giving up.
const UNMOUNT_RETRY_ATTEMPTS: u32 = 40;
const UNMOUNT_RETRY_DELAY: Duration = Duration::from_millis(250);

/// NUL-check a path before handing it to a `mount(2)`-family syscall.
pub fn path_cstring(path: &Path, kind: &str) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|err| {
        Error::InvalidParameter(format!("{kind} path contains an interior NUL byte: {err}"))
    })
}

/// Unmount whatever is mounted at `mountpoint`: a plain `umount2(., 0)`
/// without any retry — [`unmount`] owns the EBUSY retry policy.
pub fn umount2(mountpoint: &Path) -> Result<()> {
    let target = path_cstring(mountpoint, "mountpoint")?;
    let ret = unsafe { libc::umount2(target.as_ptr(), 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to unmount: {}", mountpoint.display()));
    }
    Ok(())
}

/// True when an unmount error means "nothing is mounted there" (EINVAL: not a
/// mount point; ENOENT: the path is gone), so unmounting is a no-op success.
fn is_not_mounted(err: &Error) -> bool {
    matches!(
        err.io_error().and_then(|io| io.raw_os_error()),
        Some(libc::EINVAL) | Some(libc::ENOENT)
    )
}

/// True when an unmount error means the mount is still in use (EBUSY): the
/// only transient failure, so the only one worth another attempt.
fn is_busy(err: &Error) -> bool {
    matches!(
        err.io_error().and_then(|io| io.raw_os_error()),
        Some(libc::EBUSY)
    )
}

/// Unmount `mountpoint` during a daemon shutdown. EBUSY (readers still hold
/// files open) is retried for a bounded window; any other error fails fast.
/// `on_retry` runs after a failed attempt, before the next one (e.g. fanotify
/// deny-drains newly queued events). Returns the final error when unmounting
/// gives up, so each daemon logs its own consequences.
pub fn unmount(mountpoint: &Path, mut on_retry: impl FnMut()) -> Result<()> {
    for attempt in 1..=UNMOUNT_RETRY_ATTEMPTS {
        match umount2(mountpoint) {
            Ok(()) => {
                info!("unmounted {}", mountpoint.display());
                return Ok(());
            }
            // Nothing mounted (e.g. the signal arrived before the mount
            // happened): retrying would only stall the shutdown for the
            // whole retry window.
            Err(err) if is_not_mounted(&err) => {
                debug!(
                    "nothing mounted at {}: {}",
                    mountpoint.display(),
                    err.report()
                );
                return Ok(());
            }
            Err(err) if is_busy(&err) && attempt < UNMOUNT_RETRY_ATTEMPTS => {
                debug!(
                    "unmount attempt {attempt} failed: {} (retrying)",
                    err.report()
                );
                on_retry();
                std::thread::sleep(UNMOUNT_RETRY_DELAY);
            }
            Err(err) => {
                return Err(err.context(format!(
                    "gave up at unmount attempt {attempt}/{UNMOUNT_RETRY_ATTEMPTS}"
                )))
            }
        }
    }
    unreachable!("the final unmount attempt always returns")
}

#[cfg(test)]
mod tests {
    use super::MountWatcher;
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    fn write_process(proc_root: &Path, pid: &str, namespace: &str, fdinfo: &str) {
        let process = proc_root.join(pid);
        fs::create_dir_all(process.join("ns")).unwrap();
        fs::create_dir_all(process.join("fdinfo")).unwrap();
        std::os::unix::fs::symlink(namespace, process.join("ns/mnt")).unwrap();
        fs::write(process.join("fdinfo/0"), fdinfo).unwrap();
    }

    #[test]
    fn detects_open_files_in_the_same_mount_namespace() {
        let proc_root = tempdir().unwrap();
        fs::create_dir_all(proc_root.path().join("self/ns")).unwrap();
        std::os::unix::fs::symlink("mnt:[1]", proc_root.path().join("self/ns/mnt")).unwrap();
        write_process(proc_root.path(), "123", "mnt:[1]", "pos:\t0\nmnt_id:\t42\n");
        write_process(proc_root.path(), "not-a-pid", "mnt:[1]", "mnt_id:\t42\n");

        assert!(MountWatcher::mount_has_open_files_at(proc_root.path(), "42").unwrap());
        assert!(!MountWatcher::mount_has_open_files_at(proc_root.path(), "43").unwrap());
    }

    #[test]
    fn ignores_open_files_from_other_mount_namespaces() {
        let proc_root = tempdir().unwrap();
        fs::create_dir_all(proc_root.path().join("self/ns")).unwrap();
        std::os::unix::fs::symlink("mnt:[1]", proc_root.path().join("self/ns/mnt")).unwrap();
        write_process(proc_root.path(), "123", "mnt:[2]", "mnt_id:\t42\n");

        assert!(!MountWatcher::mount_has_open_files_at(proc_root.path(), "42").unwrap());
    }

    #[test]
    fn watcher_stays_attached_while_its_mount_is_present() {
        let watcher = MountWatcher::start(Path::new("/"), || {}).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(250));
        assert!(!watcher.detached());
        drop(watcher);
    }

    #[test]
    fn watcher_rejects_a_directory_that_is_not_a_mountpoint() {
        let mountpoint = tempdir().unwrap();

        assert!(MountWatcher::start(mountpoint.path(), || {}).is_err());
    }
}
