//! FUSE mount teardown and mount-table helpers.

use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::Path;

use tracing::{info, warn};

use super::upgrade::SessionOrigin;

/// True once the FUSE kernel connection behind `fd` has ended: the kernel
/// raises `POLLERR` on every fd of a dead connection (unmounted, aborted).
/// A live connection reports at most `POLLIN` (queued requests), which is not
/// requested here. Non-blocking (zero timeout).
pub(crate) fn connection_dead(fd: BorrowedFd<'_>) -> bool {
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: 0,
        revents: 0,
    };
    // SAFETY: polling one fd owned by the caller for the duration of the call.
    let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
    ret > 0 && pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
}

/// Tears the session down using the service's explicit ownership state plus
/// the mount's recorded identity.
///
/// * `handed_off` — the connection now belongs to a successor process. The
///   mount device at the path never changed (the fd, and with it the
///   connection, moved across processes), so no inspection of the mountpoint
///   can tell whose mount it is; only the lifecycle can. Never unmount:
///   join the workers (released by cutover's exit, they return at their
///   request boundary without touching the connection) and leave.
/// * [`SessionOrigin::Adopted`] — this process owns the kernel mount
///   but holds no fuser `Mount` object (the predecessor leaked its own), so a
///   clean shutdown unmounts by path, explicitly exits the workers, then joins
///   them. Explicit exit is required after a lazy detach because client-held
///   file descriptors can otherwise keep the connection alive.
/// * [`SessionOrigin::Fresh`] — the fuser session owns the mount;
///   unmount through it.
///
/// Unmounting by path is authorized by identity, not by heuristics:
/// `mount_dev` is the `major:minor` this session recorded when it started
/// serving, and it must match the device currently mounted at the path. The
/// device is stable across an fd handoff (which `handed_off` covers) and
/// across a connection abort (a dead mount keeps its entry, so it is still
/// cleaned up), while an external `MNT_DETACH` (no entry) or an unrelated
/// filesystem later mounted at the same path (different device) both fail
/// the comparison and fall through to disarm/exit/join.
pub(super) fn finish_session(
    session: fuser::BackgroundSession,
    mountpoint: &Path,
    origin: SessionOrigin,
    handed_off: bool,
    mount_dev: Option<&str>,
) -> std::io::Result<()> {
    // If mountinfo is unreadable, do not unmount what cannot be identified.
    let owned_mount_present = mount_dev
        .is_some_and(|dev| mount_dev_of(mountpoint).ok().flatten().as_deref() == Some(dev));

    if !handed_off && owned_mount_present {
        info!("unmounting {}", mountpoint.display());
        if origin == SessionOrigin::Adopted {
            fuser::unmount_path(mountpoint)?;
            session.pauser().exit();
            return session.join();
        }
        // Exit the workers before unmounting: `umount_and_join` joins
        // unboundedly after a successful unmount request, and the connection
        // can outlive that request (a lazy unmount helper, client-held fds),
        // which would block the join forever. Exited workers return at their
        // request boundary; the kernel completes the unmount without them.
        session.pauser().exit();
        return session.umount_and_join();
    }

    // Handed off, or the mount at the path is no longer the one this session
    // recorded (detached, replaced, or unidentifiable): never unmount by
    // path. Disarm the mount teardown (a no-op after a handoff cutover
    // already disarmed it) so the drop inside join never unmounts, release
    // workers that a still-live detached connection would otherwise keep
    // blocked, then join them.
    session.mount_disarmer().disarm();
    session.pauser().exit();
    if let Err(err) = session.join() {
        warn!("background fuse session join returned an error during teardown: {err}");
    }
    Ok(())
}

/// mountinfo escapes space, tab, newline and backslash as octal sequences.
/// Unescaped octal sequences are raw bytes (e.g. one per UTF-8 continuation
/// byte for non-ASCII paths), so they are collected as bytes and decoded as
/// UTF-8 at the end.
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

/// The filesystem type currently mounted on top at `target`, or `None`.
/// The path is matched as given rather than canonicalized because stat-ing a
/// dead FUSE mountpoint fails with `ENOTCONN`.
pub fn mount_fstype_of(target: &Path) -> std::io::Result<Option<String>> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")?;
    Ok(mount_entry_from(&mountinfo, target).map(|(_dev, fstype)| fstype))
}

/// The `major:minor` device of the mount on top at `target`, or `None`. The
/// device identifies one mount across process generations: it never changes
/// when the `/dev/fuse` fd moves to a successor, and a different filesystem
/// later mounted at the same path always reports a different device.
pub(super) fn mount_dev_of(target: &Path) -> std::io::Result<Option<String>> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")?;
    Ok(mount_entry_from(&mountinfo, target).map(|(dev, _fstype)| dev))
}

/// True when `fstype` names a FUSE filesystem (`fuse`, `fuse.nydus`, ...).
pub fn is_fuse_fstype(fstype: &str) -> bool {
    fstype == "fuse" || fstype.starts_with("fuse.")
}

fn mount_entry_from(mountinfo: &str, target: &Path) -> Option<(String, String)> {
    let target = target.as_os_str().to_string_lossy();
    let mut found = None;
    for line in mountinfo.lines() {
        // <id> <parent> <dev> <root> <mountpoint> <opts> [optional...] - <fstype> <src> <sopts>
        // Paths escape spaces as octal, so a literal " - " only ever appears
        // as the optional-fields terminator.
        let Some((head, tail)) = line.split_once(" - ") else {
            continue;
        };
        let mut fields = head.split(' ');
        let (Some(_id), Some(_parent), Some(device), Some(_root), Some(point)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        if unescape_mountinfo(point) != target {
            continue;
        }
        // Later entries shadow earlier ones when mounts are stacked.
        let Some(fstype) = tail.split(' ').next() else {
            continue;
        };
        found = Some((device.to_string(), fstype.to_string()));
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescape_mountinfo_decodes_octal_sequences() {
        assert_eq!(unescape_mountinfo(r"/mnt/a\040b"), "/mnt/a b");
        assert_eq!(unescape_mountinfo("/mnt/plain"), "/mnt/plain");
        assert_eq!(unescape_mountinfo(r"/mnt/trailing\04"), r"/mnt/trailing\04");
        // Non-ASCII paths are escaped one octal sequence per UTF-8 byte.
        assert_eq!(unescape_mountinfo(r"/mnt/\303\274"), "/mnt/ü");
    }

    #[test]
    fn mount_fstype_of_parses_the_fstype_field() {
        assert!(mount_fstype_of(Path::new("/")).unwrap().is_some());
        assert_eq!(
            mount_fstype_of(Path::new("/definitely/not/a/mountpoint")).unwrap(),
            None
        );
    }

    #[test]
    fn mount_entry_identifies_the_top_mount_at_a_reused_path() {
        let mountinfo = "\
41 1 0:41 / /mnt rw - fuse old rw\n\
42 1 0:42 / /mnt rw - fuse new rw\n";
        assert_eq!(
            mount_entry_from(mountinfo, Path::new("/mnt")),
            Some(("0:42".to_string(), "fuse".to_string()))
        );
    }
}
