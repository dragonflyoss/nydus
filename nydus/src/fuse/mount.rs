//! FUSE mount teardown and mount-table helpers.

use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::Path;

use tracing::{info, warn};

use super::service::SessionOrigin;
pub(super) use crate::mount::table::mount_entry_of;

/// Polls only for connection failure; queued requests must not trigger teardown.
pub(super) fn connection_dead(fd: BorrowedFd<'_>) -> bool {
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: 0,
        revents: 0,
    };
    // SAFETY: polling one fd owned by the caller for the duration of the call.
    let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
    ret > 0 && pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
}

/// Unmounts only while this process owns the recorded device at `mountpoint`.
/// A handoff preserves the device, so release must be checked separately.
/// Adopted sessions have no fuser mount guard and unmount by path; fresh sessions
/// use their guard. Detached, replaced, or unidentifiable mounts are left alone.
pub(super) fn finish_session(
    session: fuser::BackgroundSession,
    mountpoint: &Path,
    origin: SessionOrigin,
    released: bool,
    mount_dev: Option<&str>,
) -> std::io::Result<()> {
    let owned_mount_present = match mount_dev_of(mountpoint) {
        Ok(current) => mount_dev.is_some() && current.as_deref() == mount_dev,
        Err(err) => {
            warn!(
                "cannot identify mount {}; refusing to unmount: {}",
                mountpoint.display(),
                err
            );
            false
        }
    };

    if !released && owned_mount_present {
        info!("unmounting {}", mountpoint.display());
        if origin == SessionOrigin::Adopted {
            let unmount_result = fuser::unmount_path(mountpoint);
            session.pauser().exit();
            let join_result = session.join();
            return unmount_result.and(join_result);
        }
        // A lazy unmount can leave client-held fds alive; stop workers before joining.
        session.pauser().exit();
        return session.umount_and_join();
    }

    // Joining must neither unmount another owner nor wait on a detached live connection.
    if let Err(err) = session.finish_handoff() {
        warn!("background fuse session join returned an error during teardown: {err}");
    }
    Ok(())
}

/// Returns the top mount's `major:minor` device without accessing the target.
pub(super) fn mount_dev_of(target: &Path) -> std::io::Result<Option<String>> {
    Ok(mount_entry_of(target)?.map(|(dev, _fstype)| dev))
}

pub(super) fn is_fuse_fstype(fstype: &str) -> bool {
    fstype == "fuse" || fstype.starts_with("fuse.")
}
