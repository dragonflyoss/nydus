//! FUSE mount teardown and mount-table helpers.

use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::Path;

use tracing::{info, warn};

use super::service::SessionOrigin;

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

/// Decodes mountinfo octal escapes as bytes to preserve UTF-8 paths.
fn unescape_mountinfo(field: &str) -> String {
    let mut out = Vec::with_capacity(field.len());
    let mut chars = field.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        let octal: String = chars.clone().take(3).collect();
        match u8::from_str_radix(&octal, 8) {
            Ok(byte) if octal.len() == 3 => {
                out.push(byte);
                for _ in 0..3 {
                    chars.next();
                }
            }
            _ => out.push(b'\\'),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Returns the top mount's `major:minor` device without accessing the target.
pub(super) fn mount_dev_of(target: &Path) -> std::io::Result<Option<String>> {
    Ok(mount_entry_of(target)?.map(|(dev, _fstype)| dev))
}

/// Reads device identity and filesystem type from the same mount-table snapshot.
/// Never stats the target: a crashed FUSE reader can leave path lookups blocked.
pub(super) fn mount_entry_of(target: &Path) -> std::io::Result<Option<(String, String)>> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")?;
    Ok(mount_entry_from(&mountinfo, target))
}

pub(super) fn is_fuse_fstype(fstype: &str) -> bool {
    fstype == "fuse" || fstype.starts_with("fuse.")
}

fn mount_entry_from(mountinfo: &str, target: &Path) -> Option<(String, String)> {
    let target = target.as_os_str().to_string_lossy();
    // Later entries shadow earlier ones when mounts are stacked.
    mountinfo.lines().rev().find_map(|line| {
        let (head, tail) = line.split_once(" - ")?;
        let mut fields = head.split_whitespace();
        let device = fields.nth(2)?;
        let point = fields.nth(1)?;
        if unescape_mountinfo(point) != target {
            return None;
        }
        Some((
            device.to_string(),
            tail.split_whitespace().next()?.to_string(),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_entry_identifies_the_top_mount_at_a_reused_path() {
        for (mountinfo, target, expected) in [
            ("", "/mnt", None),
            ("41 1 0:41 / /other rw - fuse old rw", "/mnt", None),
            (
                "41 1 0:41 / /mnt rw - fuse old rw\n42 1 0:42 / /mnt rw - tmpfs new rw",
                "/mnt",
                Some(("0:42", "tmpfs")),
            ),
            (
                "41 1 0:41 / /mnt\\040\\303\\274 rw shared:1 - fuse.nydus image rw\nmalformed",
                "/mnt ü",
                Some(("0:41", "fuse.nydus")),
            ),
        ] {
            assert_eq!(
                mount_entry_from(mountinfo, Path::new(target)),
                expected.map(|(device, kind)| (device.into(), kind.into()))
            );
        }
    }
}
