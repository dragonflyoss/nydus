use std::fs;
use std::path::Path;
use std::time::Duration;

use tracing::{error, info};

/// Returns the `major:minor` that /proc/self/mountinfo reports for
/// `mountpoint`, or `None` when nothing is mounted there.
///
/// Read from mountinfo rather than stat() so that it stays answerable while the
/// session is being torn down, and deliberately not the mount ID: the kernel
/// recycles those as soon as a mount is destroyed, so a successor at the same
/// path routinely inherits the ID its predecessor had.
pub(crate) fn mount_dev_of(mountpoint: &Path) -> std::io::Result<Option<String>> {
    let target = match fs::canonicalize(mountpoint) {
        Ok(path) => path,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };

    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    let mut found = None;
    for line in mountinfo.lines() {
        let mut fields = line.split(' ');
        let (Some(_id), Some(_parent), Some(dev), Some(_root), Some(point)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        if unescape_mountinfo(point) != target.as_os_str().to_string_lossy() {
            continue;
        }
        // Later entries shadow earlier ones when mounts are stacked.
        found = Some(dev.to_string());
    }

    Ok(found)
}

/// mountinfo escapes space, tab, newline and backslash as octal sequences.
fn unescape_mountinfo(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut chars = field.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let octal: String = chars.clone().take(3).collect();
        match u8::from_str_radix(&octal, 8) {
            Ok(byte) if octal.len() == 3 => {
                out.push(byte as char);
                for _ in 0..3 {
                    chars.next();
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// Tears the session down, unmounting only while the mount at `mountpoint` is
/// still the one we created.
///
/// fuser unmounts by path: both `BackgroundSession::umount_and_join` and the
/// `Mount` destructor reach `umount(2)` on the mountpoint string, which as root
/// succeeds against whatever happens to be mounted there. Once our own mount is
/// gone that would detach the next daemon's mount, and the victim then dies
/// reporting "Unmount failed: Invalid argument".
///
/// A live session is the authoritative signal that the mount is still ours,
/// because the kernel tears our channel down as soon as the mount goes away.
/// The device number additionally covers a lazy unmount, which detaches the
/// path while leaving the connection open. When neither holds we leak the
/// session rather than dropping it; the process is exiting and there is nothing
/// left to release.
pub(crate) fn finish_session(
    session: fuser::BackgroundSession,
    mountpoint: &Path,
    our_dev: Option<String>,
) -> std::io::Result<()> {
    let session_alive = !session.guard.is_finished();
    let same_dev = match mount_dev_of(mountpoint) {
        Ok(current) => current.is_some() && current == our_dev,
        Err(err) => {
            error!(
                "failed to inspect mountpoint {} before unmount: {:?}",
                mountpoint.display(),
                err
            );
            false
        }
    };

    if session_alive && same_dev {
        info!("unmounting {}", mountpoint.display());
        return session.umount_and_join();
    }

    for _ in 0..100 {
        if session.guard.is_finished() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    std::mem::forget(session);
    Ok(())
}
