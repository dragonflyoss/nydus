//! The per-blob chunk group sidecar shared across the processes using one
//! cache directory: the ready bit of every chunk group, and the claim of
//! its fetch.
//!
//! Several nydus instances on one node share a cache directory, and on a
//! cold start they want the same chunk groups at the same moment. Without
//! coordination each fetches, decodes and writes the same bytes: the result
//! is correct, since the writes are identical and the ready bits idempotent,
//! but the backend sees the traffic multiplied by the number of instances.
//! So byte `N` of the map file also stands for the fetch of chunk group `N`:
//! a fetch window of consecutive chunk groups is one range lock on it, an
//! open file description lock the kernel drops when the descriptor closes,
//! when the process dies included, so a fetcher that crashes mid-flight
//! never wedges its peers.

use std::fs::{File, OpenOptions};
use std::io;
use std::ops::Range;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use memmap2::MmapRaw;
use tracing::warn;

use nydus_format::erofs::EROFS_BLOCK_SIZE;

/// The guard holding `flock(LOCK_EX)` on a file, which serializes the
/// resets of a map across processes; independent of the byte range claims,
/// which are `fcntl` locks.
struct FileLock<'a> {
    /// The locked file.
    file: &'a File,
}

/// Implements the file lock.
impl<'a> FileLock<'a> {
    /// Takes the exclusive lock of `file`, waiting for its holder.
    fn exclusive(file: &'a File) -> io::Result<Self> {
        // SAFETY: flock has no memory preconditions; the descriptor is open
        // for the lifetime of the borrowed file.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { file })
    }
}

/// Implements the release of the file lock.
impl Drop for FileLock<'_> {
    fn drop(&mut self) {
        // SAFETY: flock has no memory preconditions; the descriptor is still
        // open since the file outlives the guard.
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// The persistent readiness bitmap of a blob's chunk groups, shared across
/// processes.
///
/// The on-disk layout is a 4096-byte header followed by one bit per chunk
/// group:
///
/// ```text
/// offset  size  field
///      0     8  magic                   b"NDGRPMAP"
///      8     4  feature_compat          unknown bits are ignored
///     12     4  feature_incompat        unknown bits reject the file
///     16     4  chunk_group_count
///     20     4  ready_count             advisory, atomically updated
///     24     4  state                   bit 0 ALL_READY, atomically updated
///     28  4068  reserved                writers zero it, readers ignore it
///   4096     -  bitmap                  one bit per chunk group
/// ```
///
/// Bytes past the bitmap are ignored, so a newer writer may append data
/// announced by a compat feature bit. The feature words follow the blob meta
/// and footer prefix; this local, rebuildable state has no crc32 and no
/// version.
///
/// The whole file is mapped `MAP_SHARED` and the bits are accessed with
/// atomic operations, so every process and thread that opens the same file
/// observes the others' [`set_ready`](Self::set_ready) through the shared
/// page cache, which is what lets concurrent nydus instances on one node
/// share one warmed cache. The kernel's writeback of the dirty pages keeps
/// the bits across reboots.
///
/// The header carries an `ALL_READY` state bit, set the moment the last
/// chunk group turns ready and visible across processes too, so
/// [`is_all_ready`](Self::is_all_ready) is one atomic load: the fast path
/// the per-event handlers of uffd, fanotify and FUSE take to skip per-group
/// bookkeeping once a blob is fully cached.
///
/// The file doubles as the lock file of the fetch claims,
/// [`claim`](Self::claim): the bytes locked and the bytes the map stores
/// are unrelated, so no second sidecar is needed.
pub(super) struct ChunkGroupMap {
    /// The shared mapping of the whole file.
    map: MmapRaw,

    /// The number of chunk groups the bitmap covers.
    chunk_group_count: usize,

    /// The backing file, kept open for the lifetime of the mapping and the
    /// descriptor the fetch claims are taken through.
    file: File,
}

/// Implements the chunk group map.
impl ChunkGroupMap {
    /// The on-disk magic, 8 raw ASCII bytes (`NDGRPMAP`, Nydus GRouP MAP)
    /// written as-is so a hexdump of the file starts with the readable string.
    const MAGIC: [u8; 8] = *b"NDGRPMAP";

    /// The header size, one block-sized page so the bitmap starts on a page
    /// boundary; the unused tail of the header is reserved for future fields.
    const HEADER_SIZE: usize = EROFS_BLOCK_SIZE as usize;

    /// The byte offset of the `feature_incompat` word in the header.
    const FEATURE_INCOMPAT_OFFSET: usize = 12;

    /// The byte offset of the `chunk_group_count` field in the header.
    const CHUNK_GROUP_COUNT_OFFSET: usize = 16;

    /// The byte offset of the `ready_count` field in the header, updated
    /// atomically through the shared mapping.
    const READY_COUNT_OFFSET: usize = 20;

    /// The byte offset of the `state` field in the header, updated atomically
    /// through the shared mapping.
    const STATE_OFFSET: usize = 24;

    /// The `state` bit saying every chunk group of the blob is ready. Sticky:
    /// ready bits are never cleared, so once set it stays set for the lifetime
    /// of the file.
    const STATE_ALL_READY: u32 = 1;

    /// Opens the map at `path` for `chunk_group_count` chunk groups,
    /// creating it when absent.
    ///
    /// Racing creators run the same idempotent sequence: size the file, then
    /// write the identical header bytes. A file sized but not yet headed by
    /// another creator maps as all zeros and is healed by writing the header
    /// once more; its mutable fields cannot have been touched, no process
    /// updates them before a successful open. Anything else that fails the
    /// magic is a corrupt or foreign file.
    pub(super) fn open(path: &Path, chunk_group_count: usize) -> io::Result<Self> {
        let expected_len = (Self::HEADER_SIZE + chunk_group_count.div_ceil(8)) as u64;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let file_len = file.metadata()?.len();
        if file_len == 0 {
            file.set_len(expected_len)?;
        } else if file_len < expected_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "chunk group map {} is truncated: expected at least {}, got {}",
                    path.display(),
                    expected_len,
                    file_len
                ),
            ));
        }

        let map = MmapRaw::map_raw(&file)?;
        if map.len() < expected_len as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("chunk group map {} mapping size mismatch", path.display()),
            ));
        }

        let chunk_group_map = Self {
            map,
            chunk_group_count,
            file,
        };

        // SAFETY: the mapping is at least `expected_len` bytes long, which
        // includes the whole header, and stays mapped while `map` lives.
        let header =
            unsafe { std::slice::from_raw_parts(chunk_group_map.map.as_ptr(), Self::HEADER_SIZE) };
        if header[..Self::MAGIC.len()] != Self::MAGIC {
            if !header.iter().all(|byte| *byte == 0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid chunk group map magic: {}", path.display()),
                ));
            }

            chunk_group_map.write_header()?;
        } else {
            let incompat = chunk_group_map
                .header_u32(Self::FEATURE_INCOMPAT_OFFSET)
                .load(Ordering::Relaxed);
            if incompat != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "chunk group map {} has unsupported incompat features {incompat:#x}",
                        path.display()
                    ),
                ));
            }

            let existing = chunk_group_map
                .header_u32(Self::CHUNK_GROUP_COUNT_OFFSET)
                .load(Ordering::Relaxed) as usize;
            if existing != chunk_group_count {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "chunk group map {} chunk group count mismatch: expected {}, got {}",
                        path.display(),
                        chunk_group_count,
                        existing
                    ),
                ));
            }
        }

        // Reconcile the ALL_READY flag from the authoritative bitmap: this
        // heals the counter skew left by a process that died between setting
        // the last bit and bumping the ready count, and marks fully warmed
        // blobs, empty ones included, at open so readers start on the fast
        // path at once.
        if !chunk_group_map.is_all_ready() && chunk_group_map.scan_all_ready() {
            chunk_group_map.mark_all_ready();
        }

        Ok(chunk_group_map)
    }

    /// Returns the atomic view of the bitmap byte holding the ready bit of
    /// `index`.
    fn bit_byte(&self, index: usize) -> &AtomicU8 {
        let offset = Self::HEADER_SIZE + index / 8;
        // SAFETY: `offset` is within the mapping, whose length `open`
        // checked against `chunk_group_count`, and `AtomicU8` has the layout
        // and alignment of `u8`.
        unsafe { &*(self.map.as_ptr().add(offset) as *const AtomicU8) }
    }

    /// Returns the atomic view of the `u32` header field at `offset`.
    fn header_u32(&self, offset: usize) -> &AtomicU32 {
        debug_assert!(offset % 4 == 0 && offset + 4 <= Self::HEADER_SIZE);
        // SAFETY: the mapping is page aligned and at least one header page
        // long, and `offset` is a 4-byte aligned position inside the header,
        // satisfying the alignment and size of `AtomicU32`.
        unsafe { &*(self.map.as_ptr().add(offset) as *const AtomicU32) }
    }

    /// Writes the header of a fresh map: the magic and the chunk group
    /// count, every other field zero.
    fn write_header(&self) -> io::Result<()> {
        let mut header = [0u8; Self::HEADER_SIZE];
        header[..Self::MAGIC.len()].copy_from_slice(&Self::MAGIC);
        header[Self::CHUNK_GROUP_COUNT_OFFSET..Self::CHUNK_GROUP_COUNT_OFFSET + 4]
            .copy_from_slice(&(self.chunk_group_count as u32).to_le_bytes());
        self.file.write_all_at(&header, 0)
    }

    /// Clears every ready bit and the counters derived from them, in place.
    ///
    /// Used when the cache data file these bits describe has gone away: each
    /// set bit would otherwise claim bytes that are no longer there, and
    /// reads would return the holes of a fresh sparse file. Resetting in
    /// place rather than replacing the file keeps the processes mapping it
    /// together: they observe the reset, whereas a new inode would leave a
    /// survivor waiting for chunk groups that, in its map, never turn ready.
    pub(super) fn reset(&self) -> io::Result<()> {
        let _guard = FileLock::exclusive(&self.file)?;
        for index in (0..self.chunk_group_count).step_by(8) {
            self.bit_byte(index).store(0, Ordering::Release);
        }

        self.header_u32(Self::READY_COUNT_OFFSET)
            .store(0, Ordering::Release);
        self.header_u32(Self::STATE_OFFSET)
            .fetch_and(!Self::STATE_ALL_READY, Ordering::AcqRel);
        Ok(())
    }

    /// Returns whether chunk group `index` is ready.
    pub(super) fn is_ready(&self, index: usize) -> io::Result<bool> {
        self.validate_index(index)?;
        let mask = 1u8 << (index % 8);
        Ok(self.bit_byte(index).load(Ordering::Acquire) & mask != 0)
    }

    /// Marks chunk group `index` ready, latching the `ALL_READY` flag when it
    /// is the last one.
    pub(super) fn set_ready(&self, index: usize) -> io::Result<()> {
        self.validate_index(index)?;
        let mask = 1u8 << (index % 8);
        let previous = self.bit_byte(index).fetch_or(mask, Ordering::AcqRel);
        if previous & mask != 0 {
            return Ok(());
        }

        // This call made the 0 to 1 transition, which exactly one process
        // does per chunk group, so it owns bumping the shared ready count.
        let count = self
            .header_u32(Self::READY_COUNT_OFFSET)
            .fetch_add(1, Ordering::AcqRel)
            + 1;
        if count as usize >= self.chunk_group_count {
            self.mark_all_ready();
        }

        Ok(())
    }

    /// Returns whether every chunk group of the blob is ready, one atomic
    /// load of the sticky `ALL_READY` flag.
    pub(super) fn is_all_ready(&self) -> bool {
        self.header_u32(Self::STATE_OFFSET).load(Ordering::Acquire) & Self::STATE_ALL_READY != 0
    }

    /// Returns whether every chunk group of the blob is ready, scanning the
    /// shared bitmap when the `ALL_READY` flag is not set yet and latching
    /// the flag when the scan proves completion, which also heals the ready
    /// count a crashed writer left short.
    pub(super) fn latch_all_ready(&self) -> bool {
        if self.is_all_ready() {
            return true;
        }

        if self.scan_all_ready() {
            self.mark_all_ready();
            return true;
        }

        false
    }

    /// Claims the fetch of the consecutive `chunk_groups`, waiting for the
    /// holder of any chunk group among them.
    ///
    /// This coordinates between processes only. Within a process the caller
    /// has already elected a single fetcher per chunk group, because an OFD
    /// lock is owned by the descriptor: two threads locking the same byte
    /// through one descriptor both succeed and neither waits.
    ///
    /// The whole window is claimed, not just the chunk group that missed:
    /// two processes missing different chunk groups of one cell plan the
    /// same window, and a claim on their own chunk group alone would let
    /// both fetch it.
    ///
    /// The wait blocks in the kernel, which hands the chunk groups over the
    /// moment the holder releases them. What bounds the wait is the holder:
    /// every backend read carries a timeout so a claim is always released,
    /// and the kernel releases the claim of a process that dies. A claim
    /// must not be held across an operation that cannot time out, because
    /// what queues up behind it are reader threads. The wait is
    /// interruptible, so a shutdown signal still breaks it.
    ///
    /// Returns `None` when the filesystem cannot provide the lock; the caller
    /// then fetches uncoordinated, since a missing optimisation must never
    /// fail a read. Callers re-check readiness afterwards: the holder
    /// publishes the chunk groups just before releasing, so the usual
    /// outcome of waiting is that no backend request is needed at all.
    pub(super) fn claim(&self, chunk_groups: Range<usize>) -> Option<ChunkGroupClaim<'_>> {
        match ChunkGroupClaim::acquire(&self.file, chunk_groups.clone()) {
            Ok(claim) => Some(claim),
            Err(err) => {
                warn!(
                    "failed to claim chunk groups {:?}: {}; fetching without cross-process coordination",
                    chunk_groups, err
                );
                None
            }
        }
    }

    /// Returns whether every bit of the bitmap is set, the partial last byte
    /// masked.
    fn scan_all_ready(&self) -> bool {
        for index in (0..self.chunk_group_count).step_by(8) {
            let bits = self.bit_byte(index).load(Ordering::Acquire);
            let remaining = self.chunk_group_count - index;
            let mask = if remaining >= 8 {
                0xFF
            } else {
                (1u8 << remaining) - 1
            };
            if bits & mask != mask {
                return false;
            }
        }

        true
    }

    /// Latches the `ALL_READY` flag and sets the ready count to the total.
    ///
    /// Every bit is set at this point, so no concurrent 0 to 1 increment can
    /// race with the store; the store corrects a count a crashed writer left
    /// short.
    fn mark_all_ready(&self) {
        self.header_u32(Self::READY_COUNT_OFFSET)
            .store(self.chunk_group_count as u32, Ordering::Release);
        self.header_u32(Self::STATE_OFFSET)
            .fetch_or(Self::STATE_ALL_READY, Ordering::AcqRel);
    }

    /// Returns the number of chunk groups marked ready, the advisory shared
    /// counter, exact once `ALL_READY` is latched.
    #[cfg(test)]
    fn ready_count(&self) -> usize {
        self.header_u32(Self::READY_COUNT_OFFSET)
            .load(Ordering::Acquire) as usize
    }

    /// Fails with [`io::ErrorKind::InvalidInput`] when `index` is past the
    /// blob's chunk groups.
    fn validate_index(&self, index: usize) -> io::Result<()> {
        if index >= self.chunk_group_count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "chunk group index {index} out of range {}",
                    self.chunk_group_count
                ),
            ));
        }

        Ok(())
    }
}

/// The claim of a fetch, releasing its chunk groups when dropped.
pub(super) struct ChunkGroupClaim<'a> {
    /// The map file the claim is taken on.
    file: &'a File,

    /// The claimed chunk groups.
    chunk_groups: Range<usize>,
}

/// Implements the claim.
impl<'a> ChunkGroupClaim<'a> {
    /// Takes the write lock on the bytes of `file` standing for
    /// `chunk_groups`, waiting for their holder.
    fn acquire(file: &'a File, chunk_groups: Range<usize>) -> io::Result<Self> {
        Self::set_lock(
            file,
            &chunk_groups,
            libc::F_WRLCK as libc::c_short,
            libc::F_OFD_SETLKW,
        )?;
        Ok(Self { file, chunk_groups })
    }

    /// Applies the lock type `l_type` with `cmd` to the bytes of `file`
    /// standing for `chunk_groups`.
    fn set_lock(
        file: &File,
        chunk_groups: &Range<usize>,
        l_type: libc::c_short,
        cmd: libc::c_int,
    ) -> io::Result<()> {
        // SAFETY: `flock` is a plain C struct for which all zeros is a valid
        // value, and OFD locks require the zero `l_pid` it provides.
        let mut lock: libc::flock = unsafe { std::mem::zeroed() };
        lock.l_type = l_type;
        lock.l_whence = libc::SEEK_SET as libc::c_short;
        lock.l_start = chunk_groups.start as libc::off_t;
        lock.l_len = chunk_groups.len().max(1) as libc::off_t;

        // SAFETY: `lock` is a fully initialized struct that outlives the
        // call, and the descriptor is open for the lifetime of the borrowed
        // file.
        if unsafe { libc::fcntl(file.as_raw_fd(), cmd, &lock) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
}

/// Implements the release of the claim.
impl Drop for ChunkGroupClaim<'_> {
    fn drop(&mut self) {
        if let Err(err) = Self::set_lock(
            self.file,
            &self.chunk_groups,
            libc::F_UNLCK as libc::c_short,
            libc::F_OFD_SETLK,
        ) {
            warn!(
                "failed to release chunk groups {:?}: {}",
                self.chunk_groups, err
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    use tempfile::tempdir;

    #[test]
    fn set_ready_persists_across_reopens() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");

        let map = ChunkGroupMap::open(&path, 10).unwrap();
        assert!(!map.is_ready(3).unwrap());
        map.set_ready(3).unwrap();
        map.set_ready(9).unwrap();
        assert!(map.is_ready(3).unwrap());
        assert!(map.is_ready(9).unwrap());

        let reopened = ChunkGroupMap::open(&path, 10).unwrap();
        assert!(reopened.is_ready(3).unwrap());
        assert!(reopened.is_ready(9).unwrap());
        assert!(!reopened.is_ready(2).unwrap());
    }

    #[test]
    fn set_ready_is_visible_through_another_handle() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");

        let writer = ChunkGroupMap::open(&path, 20).unwrap();
        let observer = ChunkGroupMap::open(&path, 20).unwrap();
        assert!(!observer.is_ready(7).unwrap());
        writer.set_ready(7).unwrap();
        assert!(observer.is_ready(7).unwrap());
        assert!(!observer.latch_all_ready());

        for index in 0..20 {
            writer.set_ready(index).unwrap();
        }
        assert!(observer.latch_all_ready());
    }

    #[test]
    fn open_rejects_a_chunk_group_count_mismatch() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");

        ChunkGroupMap::open(&path, 10).unwrap();
        assert!(ChunkGroupMap::open(&path, 11).is_err());
    }

    #[test]
    fn open_heals_a_sized_file_without_a_header() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");
        let chunk_group_count = 10usize;
        let expected_len = (ChunkGroupMap::HEADER_SIZE + chunk_group_count.div_ceil(8)) as u64;
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        file.set_len(expected_len).unwrap();
        drop(file);

        let map = ChunkGroupMap::open(&path, chunk_group_count).unwrap();
        map.set_ready(4).unwrap();
        assert!(map.is_ready(4).unwrap());

        let reopened = ChunkGroupMap::open(&path, chunk_group_count).unwrap();
        assert!(reopened.is_ready(4).unwrap());
    }

    #[test]
    fn open_rejects_a_corrupt_magic_and_a_truncated_file() {
        let dir = tempdir().unwrap();
        let expected_len = ChunkGroupMap::HEADER_SIZE + 10usize.div_ceil(8);

        let garbage = dir.path().join("garbage.group.map");
        std::fs::write(&garbage, vec![0xABu8; expected_len]).unwrap();
        assert!(ChunkGroupMap::open(&garbage, 10).is_err());

        let truncated = dir.path().join("truncated.group.map");
        std::fs::write(&truncated, vec![0u8; expected_len - 1]).unwrap();
        assert!(ChunkGroupMap::open(&truncated, 10).is_err());
    }

    #[test]
    fn open_ignores_bytes_past_the_bitmap() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");
        ChunkGroupMap::open(&path, 10)
            .unwrap()
            .set_ready(3)
            .unwrap();

        let file = OpenOptions::new().write(true).open(&path).unwrap();
        let len = file.metadata().unwrap().len();
        file.write_all_at(&[0x5a; 4096], len).unwrap();
        let reopened = ChunkGroupMap::open(&path, 10).unwrap();
        assert!(reopened.is_ready(3).unwrap());
        assert!(!reopened.is_ready(4).unwrap());
    }

    #[test]
    fn set_ready_latches_all_ready_on_the_last_bit() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");

        let writer = ChunkGroupMap::open(&path, 9).unwrap();
        let observer = ChunkGroupMap::open(&path, 9).unwrap();
        assert!(!writer.is_all_ready());

        for index in 0..8 {
            writer.set_ready(index).unwrap();
            assert!(!writer.is_all_ready(), "flag latched early at {index}");
        }
        writer.set_ready(8).unwrap();

        assert!(writer.is_all_ready());
        assert!(observer.is_all_ready());
        assert!(observer.latch_all_ready());

        let reopened = ChunkGroupMap::open(&path, 9).unwrap();
        assert!(reopened.is_all_ready());
    }

    #[test]
    fn open_heals_the_ready_count_from_a_full_bitmap() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");
        let chunk_group_count = 10usize;
        drop(ChunkGroupMap::open(&path, chunk_group_count).unwrap());
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.write_all_at(&[0xFF, 0x03], ChunkGroupMap::HEADER_SIZE as u64)
            .unwrap();
        drop(file);

        let map = ChunkGroupMap::open(&path, chunk_group_count).unwrap();
        assert!(map.is_all_ready());
        assert!(map.latch_all_ready());
        assert_eq!(map.ready_count(), chunk_group_count);
    }

    #[test]
    fn an_empty_blob_is_all_ready() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");

        let map = ChunkGroupMap::open(&path, 0).unwrap();
        assert!(map.is_all_ready());
        assert!(map.latch_all_ready());
    }

    #[test]
    fn the_header_carries_the_features_and_the_state() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");
        let map = ChunkGroupMap::open(&path, 3).unwrap();
        for index in 0..3 {
            map.set_ready(index).unwrap();
        }
        drop(map);

        let bytes = std::fs::read(&path).unwrap();
        let field = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        assert_eq!(&bytes[..8], b"NDGRPMAP");
        assert_eq!((field(8), field(12)), (0, 0));
        assert_eq!((field(16), field(20), field(24)), (3, 3, 1));

        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.write_all_at(&1u32.to_le_bytes(), 8).unwrap();
        assert!(ChunkGroupMap::open(&path, 3).unwrap().is_all_ready());
        file.write_all_at(&1u32.to_le_bytes(), 12).unwrap();
        let err = ChunkGroupMap::open(&path, 3).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn bits_stay_within_their_byte_and_indexes_are_range_checked() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");

        let map = ChunkGroupMap::open(&path, 9).unwrap();
        for index in [0usize, 7, 8] {
            assert!(!map.is_ready(index).unwrap());
            map.set_ready(index).unwrap();
            assert!(map.is_ready(index).unwrap());
        }
        for index in [1usize, 6] {
            assert!(!map.is_ready(index).unwrap(), "neighbor bit {index} leaked");
        }
        assert!(!map.latch_all_ready());
        for index in 0..9 {
            map.set_ready(index).unwrap();
        }
        assert!(map.latch_all_ready());

        assert_eq!(
            map.is_ready(9).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            map.set_ready(9).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn concurrent_setters_lose_no_updates() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");
        let chunk_group_count = 4096usize;

        let even = ChunkGroupMap::open(&path, chunk_group_count).unwrap();
        let odd = ChunkGroupMap::open(&path, chunk_group_count).unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for index in (0..chunk_group_count).step_by(2) {
                    even.set_ready(index).unwrap();
                }
            });
            scope.spawn(|| {
                for index in (1..chunk_group_count).step_by(2) {
                    odd.set_ready(index).unwrap();
                }
            });
        });

        let verify = ChunkGroupMap::open(&path, chunk_group_count).unwrap();
        for index in 0..chunk_group_count {
            assert!(verify.is_ready(index).unwrap(), "lost update at {index}");
        }
        assert!(verify.latch_all_ready());
    }

    #[test]
    fn a_million_chunk_groups_stay_in_memory_fast() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");
        let chunk_group_count = 1_000_000usize;

        let start = std::time::Instant::now();
        let map = ChunkGroupMap::open(&path, chunk_group_count).unwrap();
        for index in 0..chunk_group_count {
            map.set_ready(index).unwrap();
        }
        for index in 0..chunk_group_count {
            assert!(map.is_ready(index).unwrap());
        }
        assert!(map.latch_all_ready());
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "chunk group map operations too slow: {elapsed:?}"
        );
    }

    #[test]
    fn reset_clears_the_bits_and_the_counters() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");

        let map = ChunkGroupMap::open(&path, 10).unwrap();
        for index in 0..10 {
            map.set_ready(index).unwrap();
        }
        assert!(map.is_all_ready());

        map.reset().unwrap();
        assert!(!map.is_all_ready());
        assert_eq!(map.ready_count(), 0);
        for index in 0..10 {
            assert!(!map.is_ready(index).unwrap());
        }
    }

    #[test]
    fn distinct_chunk_groups_do_not_contend() {
        let dir = tempdir().unwrap();
        let map = ChunkGroupMap::open(&dir.path().join("blob.group.map"), 8).unwrap();

        let first = map.claim(0..1).unwrap();
        let second = map.claim(1..2).unwrap();
        drop(first);
        drop(second);
    }

    #[test]
    fn a_chunk_group_can_be_reclaimed_after_release() {
        let dir = tempdir().unwrap();
        let map = ChunkGroupMap::open(&dir.path().join("blob.group.map"), 8).unwrap();

        drop(map.claim(7..8).unwrap());
        drop(map.claim(7..8).unwrap());
    }

    #[test]
    fn a_window_conflicts_with_any_chunk_group_inside_it() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");

        let peer = ChunkGroupMap::open(&path, 8).unwrap();
        let claim = peer.claim(2..4).unwrap();

        let (claimed_tx, claimed_rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let map = ChunkGroupMap::open(&path, 8).unwrap();
            drop(map.claim(3..4).unwrap());
            claimed_tx.send(()).unwrap();
        });

        assert!(claimed_rx.recv_timeout(Duration::from_millis(200)).is_err());
        drop(claim);
        claimed_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        waiter.join().unwrap();
    }

    #[test]
    fn a_waiter_blocks_until_the_peer_releases() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");

        let peer = ChunkGroupMap::open(&path, 8).unwrap();
        let claim = peer.claim(3..4).unwrap();

        let (waiting_tx, waiting_rx) = mpsc::channel();
        let (claimed_tx, claimed_rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let map = ChunkGroupMap::open(&path, 8).unwrap();
            waiting_tx.send(()).unwrap();
            let claim = map.claim(3..4).unwrap();
            claimed_tx.send(()).unwrap();
            drop(claim);
        });

        waiting_rx.recv().unwrap();
        assert!(claimed_rx.recv_timeout(Duration::from_millis(200)).is_err());

        let released = Instant::now();
        drop(claim);
        claimed_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(released.elapsed() < Duration::from_secs(1));
        waiter.join().unwrap();
    }

    #[test]
    fn a_dead_peers_claim_is_released_by_the_kernel() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");

        let map = ChunkGroupMap::open(&path, 8).unwrap();
        {
            let peer = ChunkGroupMap::open(&path, 8).unwrap();
            std::mem::forget(peer.claim(5..6).unwrap());
        }
        drop(map.claim(5..6).unwrap());
    }
}
