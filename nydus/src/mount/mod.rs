//! Mount helpers shared by the fanotify and NBD mount lifecycles.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

use nydus_error::{Context, Error, Result};
use tracing::{debug, info};

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
            .with_context(|| format!("failed to unmount {}", mountpoint.display()));
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
                    "unmount attempt {attempt} failed: {}; retrying",
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
