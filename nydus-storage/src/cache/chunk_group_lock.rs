//! Cross-process singleflight for cold group fetches.
//!
//! Several nydus instances on one node share a cache directory, and on a cold
//! start they tend to want the same groups at the same moment. Without any
//! coordination each of them fetches, decodes and writes the same bytes: the
//! result is correct, because the writes are identical and the readiness bits
//! are idempotent, but the backend sees the traffic multiplied by the number
//! of instances.
//!
//! Byte `N` of a per-blob lock file stands for group `N`, so a whole blob
//! needs one descriptor however many groups it has, and a fetch window of
//! consecutive groups is one range lock. The locks are open file description
//! locks, which the kernel drops when the descriptor closes — including when
//! the process dies — so a fetcher that crashes mid-flight never wedges its
//! peers.

use std::fs::{File, OpenOptions};
use std::io;
use std::ops::Range;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use tracing::warn;

/// Per-blob fetch rights, one byte per group.
///
/// This only coordinates *between* processes. Within a process the caller must
/// already have elected a single fetcher for the group, because an OFD lock is
/// owned by the descriptor: two threads locking the same byte through the same
/// descriptor would both succeed and neither would wait.
pub struct ChunkGroupLocks {
    path: PathBuf,
    /// Opened on first contention. A warm cache never fetches, so it never
    /// needs the descriptor. `None` means locking is unavailable here and
    /// callers fall back to fetching without coordination.
    file: OnceLock<Option<File>>,
    unavailable: AtomicBool,
}

impl ChunkGroupLocks {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            file: OnceLock::new(),
            unavailable: AtomicBool::new(false),
        }
    }

    fn file(&self) -> Option<&File> {
        self.file
            .get_or_init(|| {
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(&self.path)
                    .inspect_err(|err| {
                        warn!(
                            "failed to open group lock file {}: {err}; \
                             fetching without cross-process coordination",
                            self.path.display()
                        );
                    })
                    .ok()
            })
            .as_ref()
    }

    /// Claim the right to fetch the consecutive `groups`, waiting for any
    /// holder of a group among them.
    ///
    /// The whole window is claimed, not just the group that missed: two
    /// processes missing different groups of one cell plan the same window,
    /// and a claim on their own group alone would let both fetch it.
    ///
    /// Contention is polled for at most two seconds before this call falls
    /// back to an uncoordinated fetch. Later calls still try to acquire the
    /// lock; only unsupported locking permanently disables coordination.
    ///
    /// Returns `None` on timeout or when the filesystem cannot provide the lock; callers
    /// then fetch uncoordinated, exactly as they did before this existed,
    /// because a missing optimisation must never fail a read.
    ///
    /// Callers must re-check readiness afterwards: the holder publishes the
    /// groups just before releasing, so the usual outcome of waiting is that
    /// no backend request is needed at all.
    pub fn acquire(&self, groups: Range<usize>) -> Option<GroupLockGuard<'_>> {
        if self.unavailable.load(Ordering::Relaxed) {
            return None;
        }
        let file = self.file()?;
        let start = std::time::Instant::now();
        let result = loop {
            match set_lock(
                file,
                &groups,
                libc::F_WRLCK as libc::c_short,
                libc::F_OFD_SETLK,
            ) {
                Err(err)
                    if matches!(err.raw_os_error(), Some(libc::EAGAIN | libc::EACCES))
                        && start.elapsed() < std::time::Duration::from_secs(2) =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                result => break result,
            }
        };
        match result {
            Ok(()) => Some(GroupLockGuard { file, groups }),
            Err(err) => {
                if matches!(
                    err.raw_os_error(),
                    Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP)
                ) {
                    self.unavailable.store(true, Ordering::Relaxed);
                }
                warn!(
                    "failed to lock groups {groups:?} in {}: {err}; \
                     fetching without cross-process coordination",
                    self.path.display()
                );
                None
            }
        }
    }
}

/// Releases the groups' fetch right when dropped.
pub struct GroupLockGuard<'a> {
    file: &'a File,
    groups: Range<usize>,
}

impl Drop for GroupLockGuard<'_> {
    fn drop(&mut self) {
        let _ = set_lock(
            self.file,
            &self.groups,
            libc::F_UNLCK as libc::c_short,
            libc::F_OFD_SETLK,
        );
    }
}

/// Apply `l_type` to the bytes standing for `groups`.
fn set_lock(
    file: &File,
    groups: &Range<usize>,
    l_type: libc::c_short,
    cmd: libc::c_int,
) -> io::Result<()> {
    // OFD locks require l_pid to be zero, which the zeroed struct provides.
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = l_type;
    lock.l_whence = libc::SEEK_SET as libc::c_short;
    lock.l_start = groups.start as libc::off_t;
    lock.l_len = groups.len().max(1) as libc::off_t;

    if unsafe { libc::fcntl(file.as_raw_fd(), cmd, &lock) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    use tempfile::tempdir;

    #[test]
    fn distinct_groups_do_not_contend() {
        let dir = tempdir().unwrap();
        let locks = ChunkGroupLocks::new(dir.path().join("blob.flight.lock"));

        let first = locks.acquire(0..1).expect("group 0 lock");
        let second = locks.acquire(1..2).expect("group 1 lock");
        drop(first);
        drop(second);
    }

    #[test]
    fn a_group_can_be_reclaimed_after_release() {
        let dir = tempdir().unwrap();
        let locks = ChunkGroupLocks::new(dir.path().join("blob.flight.lock"));

        drop(locks.acquire(7..8).expect("first claim"));
        drop(locks.acquire(7..8).expect("second claim after release"));
    }

    #[test]
    fn contention_timeout_does_not_disable_later_acquisitions() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.flight.lock");
        let peer = ChunkGroupLocks::new(path.clone());
        let locks = ChunkGroupLocks::new(path);
        let claim = peer.acquire(3..4).expect("peer claims group 3");

        let started = Instant::now();
        assert!(locks.acquire(3..4).is_none());
        assert!(started.elapsed() >= Duration::from_secs(2));
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(locks.acquire(4..5).expect("uncontended groups still lock"));

        drop(claim);
        let reclaimed = locks.acquire(3..4).expect("claim after contention clears");
        assert!(
            matches!(
                set_lock(
                    peer.file().unwrap(),
                    &(3..4),
                    libc::F_WRLCK as libc::c_short,
                    libc::F_OFD_SETLK,
                )
                .unwrap_err()
                .raw_os_error(),
                Some(libc::EAGAIN | libc::EACCES)
            ),
            "the recovered claim must exclude a peer"
        );
        drop(reclaimed);
        drop(
            peer.acquire(3..4)
                .expect("recovered claim releases normally"),
        );
    }

    #[test]
    fn a_window_conflicts_with_any_group_inside_it() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.flight.lock");

        let peer = ChunkGroupLocks::new(path.clone());
        let claim = peer.acquire(2..4).expect("peer claims groups 2..4");

        let (claimed_tx, claimed) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let locks = ChunkGroupLocks::new(path);
            drop(
                locks
                    .acquire(3..4)
                    .expect("waiter eventually claims group 3"),
            );
            claimed_tx.send(()).unwrap();
        });

        assert!(
            claimed.recv_timeout(Duration::from_millis(200)).is_err(),
            "a group inside the peer's window must wait for the window"
        );
        drop(claim);
        claimed
            .recv_timeout(Duration::from_secs(5))
            .expect("releasing the window must hand the group over");
        waiter.join().unwrap();
    }

    #[test]
    fn an_unusable_lock_path_degrades_instead_of_failing() {
        let dir = tempdir().unwrap();
        // A directory cannot be opened for writing, standing in for a
        // filesystem that cannot host the lock file.
        let path = dir.path().join("not-a-file");
        std::fs::create_dir(&path).unwrap();

        let locks = ChunkGroupLocks::new(path);
        assert!(locks.acquire(0..1).is_none());
    }

    #[test]
    fn a_waiter_blocks_until_the_peer_releases() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.flight.lock");

        // Separate `ChunkGroupLocks` means a separate descriptor, which is what
        // makes these conflict the way two processes would. Sharing one
        // descriptor would not: an OFD lock is owned by the description, so
        // re-locking through it always succeeds.
        let peer = ChunkGroupLocks::new(path.clone());
        let claim = peer.acquire(3..4).expect("peer claims group 3");

        let (waiting_tx, waiting) = mpsc::channel();
        let (claimed_tx, claimed) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let locks = ChunkGroupLocks::new(path);
            waiting_tx.send(()).unwrap();
            let guard = locks.acquire(3..4).expect("waiter eventually claims it");
            claimed_tx.send(()).unwrap();
            drop(guard);
        });

        waiting.recv().unwrap();
        assert!(
            claimed.recv_timeout(Duration::from_millis(200)).is_err(),
            "the waiter must block while the peer holds the group"
        );

        let released = Instant::now();
        drop(claim);
        claimed
            .recv_timeout(Duration::from_secs(5))
            .expect("releasing must hand the group over");
        assert!(
            released.elapsed() < Duration::from_secs(1),
            "the handover should follow the release promptly"
        );
        waiter.join().unwrap();
    }

    #[test]
    fn a_dead_peers_claim_is_released_by_the_kernel() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.flight.lock");

        let us = ChunkGroupLocks::new(path.clone());
        {
            // Dropping `ChunkGroupLocks` closes the descriptor, which is what the
            // kernel does for a process that dies mid-fetch. Leaking the guard
            // makes sure only the close can have released the claim.
            let peer = ChunkGroupLocks::new(path);
            std::mem::forget(peer.acquire(5..6).expect("peer claims group 5"));
        }
        // This would block forever if the close had not released the claim.
        drop(
            us.acquire(5..6)
                .expect("the claim must not outlive its descriptor"),
        );
    }
}
