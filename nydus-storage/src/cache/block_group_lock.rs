//! Cross-process singleflight for cold block group fetches.
//!
//! Several nydus instances on one node share a cache directory, and on a cold
//! start they tend to want the same block groups at the same moment. Without any
//! coordination each of them fetches, decodes and writes the same bytes: the
//! result is correct, because the writes are identical and the readiness bits
//! are idempotent, but the backend sees the traffic multiplied by the number
//! of instances.
//!
//! Byte `N` of a per-blob lock file stands for block group `N`, so a whole blob
//! needs one descriptor however many block groups it has. The locks are open file
//! description locks, which the kernel drops when the descriptor closes —
//! including when the process dies — so a fetcher that crashes mid-flight
//! never wedges its peers.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::OnceLock;

use tracing::warn;

/// Per-blob fetch rights, one byte per block group.
///
/// This only coordinates *between* processes. Within a process the caller must
/// already have elected a single fetcher for the block group, because an OFD lock is
/// owned by the descriptor: two threads locking the same byte through the same
/// descriptor would both succeed and neither would wait.
pub struct BlockGroupLocks {
    path: PathBuf,
    /// Opened on first contention. A warm cache never fetches, so it never
    /// needs the descriptor. `None` means locking is unavailable here and
    /// callers fall back to fetching without coordination.
    file: OnceLock<Option<File>>,
}

impl BlockGroupLocks {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            file: OnceLock::new(),
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
                            "failed to open block_group lock file {}: {err}; \
                             fetching without cross-process coordination",
                            self.path.display()
                        );
                    })
                    .ok()
            })
            .as_ref()
    }

    /// Claim the right to fetch `block_group_index`, waiting for the current holder.
    ///
    /// The wait blocks in the kernel, which hands the block group over the moment
    /// the holder releases it — no polling, no wasted wakeups, and no interval
    /// to oversleep. What bounds the wait is the holder rather than the
    /// waiter: every backend read carries a timeout so a claim is always
    /// released, and a claim whose process dies is released by the kernel.
    /// Waiters therefore block for as long as the fetch they are waiting for,
    /// which is what they would have spent fetching it themselves anyway.
    ///
    /// **A claim must not be held across an operation that cannot time out**,
    /// because what queues up behind it are reader threads.
    ///
    /// The wait is interruptible, so a shutdown signal still breaks it.
    ///
    /// Returns `None` when the filesystem cannot provide the lock; callers
    /// then fetch uncoordinated, exactly as they did before this existed,
    /// because a missing optimisation must never fail a read.
    ///
    /// Callers must re-check readiness afterwards: the holder publishes the
    /// block group just before releasing, so the usual outcome of waiting is that no
    /// backend request is needed at all.
    pub fn acquire(&self, block_group_index: usize) -> Option<BlockGroupLockGuard<'_>> {
        let file = self.file()?;
        match set_lock(
            file,
            block_group_index,
            libc::F_WRLCK as libc::c_short,
            libc::F_OFD_SETLKW,
        ) {
            Ok(()) => Some(BlockGroupLockGuard {
                file,
                block_group_index,
            }),
            Err(err) => {
                warn!(
                    "failed to lock block_group {block_group_index} in {}: {err}; \
                     fetching without cross-process coordination",
                    self.path.display()
                );
                None
            }
        }
    }
}

/// Releases the block group's fetch right when dropped.
pub struct BlockGroupLockGuard<'a> {
    file: &'a File,
    block_group_index: usize,
}

impl Drop for BlockGroupLockGuard<'_> {
    fn drop(&mut self) {
        let _ = set_lock(
            self.file,
            self.block_group_index,
            libc::F_UNLCK as libc::c_short,
            libc::F_OFD_SETLK,
        );
    }
}

/// Apply `l_type` to the single byte standing for `block_group_index`.
fn set_lock(
    file: &File,
    block_group_index: usize,
    l_type: libc::c_short,
    cmd: libc::c_int,
) -> io::Result<()> {
    // OFD locks require l_pid to be zero, which the zeroed struct provides.
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = l_type;
    lock.l_whence = libc::SEEK_SET as libc::c_short;
    lock.l_start = block_group_index as libc::off_t;
    lock.l_len = 1;

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
    fn distinct_block_groups_do_not_contend() {
        let dir = tempdir().unwrap();
        let locks = BlockGroupLocks::new(dir.path().join("blob.flight.lock"));

        let first = locks.acquire(0).expect("block_group 0 lock");
        let second = locks.acquire(1).expect("block_group 1 lock");
        drop(first);
        drop(second);
    }

    #[test]
    fn a_block_group_can_be_reclaimed_after_release() {
        let dir = tempdir().unwrap();
        let locks = BlockGroupLocks::new(dir.path().join("blob.flight.lock"));

        drop(locks.acquire(7).expect("first claim"));
        drop(locks.acquire(7).expect("second claim after release"));
    }

    #[test]
    fn an_unusable_lock_path_degrades_instead_of_failing() {
        let dir = tempdir().unwrap();
        // A directory cannot be opened for writing, standing in for a
        // filesystem that cannot host the lock file.
        let path = dir.path().join("not-a-file");
        std::fs::create_dir(&path).unwrap();

        let locks = BlockGroupLocks::new(path);
        assert!(locks.acquire(0).is_none());
    }

    #[test]
    fn a_waiter_blocks_until_the_peer_releases() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.flight.lock");

        // Separate `BlockGroupLocks` means a separate descriptor, which is what
        // makes these conflict the way two processes would. Sharing one
        // descriptor would not: an OFD lock is owned by the description, so
        // re-locking through it always succeeds.
        let peer = BlockGroupLocks::new(path.clone());
        let claim = peer.acquire(3).expect("peer claims block_group 3");

        let (waiting_tx, waiting) = mpsc::channel();
        let (claimed_tx, claimed) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let locks = BlockGroupLocks::new(path);
            waiting_tx.send(()).unwrap();
            let guard = locks.acquire(3).expect("waiter eventually claims it");
            claimed_tx.send(()).unwrap();
            drop(guard);
        });

        waiting.recv().unwrap();
        assert!(
            claimed.recv_timeout(Duration::from_millis(200)).is_err(),
            "the waiter must block while the peer holds the block group"
        );

        let released = Instant::now();
        drop(claim);
        claimed
            .recv_timeout(Duration::from_secs(5))
            .expect("releasing must hand the block_group over");
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

        let us = BlockGroupLocks::new(path.clone());
        {
            // Dropping `BlockGroupLocks` closes the descriptor, which is what the
            // kernel does for a process that dies mid-fetch. Leaking the guard
            // makes sure only the close can have released the claim.
            let peer = BlockGroupLocks::new(path);
            std::mem::forget(peer.acquire(5).expect("peer claims block_group 5"));
        }
        // This would block forever if the close had not released the claim.
        drop(
            us.acquire(5)
                .expect("the claim must not outlive its descriptor"),
        );
    }
}
