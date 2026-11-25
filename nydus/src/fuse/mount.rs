//! FUSE mount teardown and mount-table helpers.

use std::fs::File;
use std::io::Read;
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
    let owned_mount_present = match MountTable::read() {
        Ok(table) => {
            let current = table.entry_of(mountpoint).map(|entry| entry.device);
            mount_dev.is_some() && current.as_deref() == mount_dev
        }
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

/// One reading of `/proc/self/mountinfo`. Mounts are identified from it and
/// never by a stat of their path: a crashed FUSE reader can leave path lookups
/// blocked.
pub(super) struct MountTable(String);

/// The mount on top of a path.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct MountEntry {
    /// The `major:minor` device.
    pub(super) device: String,
    /// The filesystem type.
    fstype: String,
}

/// Implements the mount entry.
impl MountEntry {
    /// Returns whether the mount is a FUSE filesystem.
    pub(super) fn is_fuse(&self) -> bool {
        self.fstype == "fuse" || self.fstype.starts_with("fuse.")
    }
}

/// Implements the mount table.
impl MountTable {
    /// The readings of a table that keeps changing before the last one is used.
    const MAX_READ_ATTEMPTS: usize = 32;

    /// Reads the mount table, again while it changed during the reading.
    pub(super) fn read() -> std::io::Result<Self> {
        Self::settled(Self::read_once)
    }

    /// Repeats `read` while it reports that the table changed under it. A
    /// table that never settles yields its last reading.
    fn settled(mut read: impl FnMut() -> std::io::Result<(String, bool)>) -> std::io::Result<Self> {
        let mut attempts = 1;
        loop {
            let (mountinfo, changed) = read()?;
            if !changed || attempts == Self::MAX_READ_ATTEMPTS {
                return Ok(Self(mountinfo));
            }
            attempts += 1;
        }
    }

    /// Reads the mount table and reports whether it changed meanwhile: the
    /// file then polls as changed. Before 5.8 the kernel resumes a partial
    /// read by entry index, so an unmount in between skips an entry.
    fn read_once() -> std::io::Result<(String, bool)> {
        let mut file = File::open("/proc/self/mountinfo")?;
        let mut mountinfo = String::new();
        file.read_to_string(&mut mountinfo)?;
        let mut pfd = libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLPRI,
            revents: 0,
        };
        // SAFETY: polling one fd owned by `file` for the duration of the call.
        let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
        let changed = ret < 0 || pfd.revents & (libc::POLLERR | libc::POLLPRI) != 0;
        Ok((mountinfo, changed))
    }

    /// The mount on top of `target`: later entries shadow earlier ones when
    /// mounts are stacked.
    pub(super) fn entry_of(&self, target: &Path) -> Option<MountEntry> {
        let target = target.as_os_str().to_string_lossy();
        self.0.lines().rev().find_map(|line| {
            let (head, tail) = line.split_once(" - ")?;
            let mut fields = head.split_whitespace();
            let device = fields.nth(2)?;
            let point = fields.nth(1)?;
            if Self::unescape(point) != target {
                return None;
            }
            Some(MountEntry {
                device: device.to_string(),
                fstype: tail.split_whitespace().next()?.to_string(),
            })
        })
    }

    /// Decodes the octal escapes of a field as bytes to preserve UTF-8 paths.
    fn unescape(field: &str) -> String {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_table_that_changed_while_it_was_read_is_read_again() {
        for (changes, expected_reads) in
            [(0, 1), (2, 3), (usize::MAX, MountTable::MAX_READ_ATTEMPTS)]
        {
            let mut reads = 0;
            let table = MountTable::settled(|| {
                reads += 1;
                Ok((reads.to_string(), reads <= changes))
            })
            .unwrap();
            assert_eq!(
                (table.0, reads),
                (expected_reads.to_string(), expected_reads)
            );
        }

        let table = MountTable::read().unwrap();
        assert!(!table.entry_of(Path::new("/proc")).unwrap().is_fuse());
    }

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
            let entry = MountTable(mountinfo.into()).entry_of(Path::new(target));
            assert_eq!(
                entry.as_ref().map(MountEntry::is_fuse),
                expected.map(|(_, fstype)| fstype != "tmpfs")
            );
            assert_eq!(
                entry.map(|entry| (entry.device, entry.fstype)),
                expected.map(|(device, fstype)| (device.into(), fstype.into()))
            );
        }
    }
}
