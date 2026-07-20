use std::fs::{File, OpenOptions};
use std::io;
use std::ops::Range;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use memmap2::MmapRaw;

/// On-disk magic: 8 raw ASCII bytes ("LPGRPMAP" = LePton GRouP MAP), written
/// as-is so a hexdump of the file starts with the readable string. Same magic
/// style as the blob meta header (`LPBLMETA`); the format version is a
/// separate field instead of being baked into the magic.
const GROUPMAP_MAGIC: [u8; 8] = *b"LPGRPMAP";
/// On-disk format generation, informational only: readers do not gate on it.
/// A groupmap is local mutable state — its `flags` word carries runtime state
/// bits (not format features), and unknown state bits are simply ignored.
const GROUPMAP_VERSION: u32 = 1;
/// Fixed header size: one block-sized page, matching the blob meta header
/// (`BLOB_META_HEADER_SIZE`) for a uniform sidecar format family. The bitmap
/// starts on a page boundary and the unused header tail is reserved for
/// future fields.
const GROUPMAP_HEADER_SIZE: usize = crate::metadata::EROFS_BLOCK_SIZE as usize;

/// Byte offsets of the header fields after magic and version. `flags` and
/// `ready_count` are mutable at runtime, updated atomically through the
/// shared mapping (unlike magic/version/group count, which are written once
/// at creation). The `magic + version + flags` prefix matches the blob meta
/// header layout.
const GROUPMAP_FLAGS_OFFSET: usize = 12;
const GROUPMAP_GROUP_COUNT_OFFSET: usize = 16;
const GROUPMAP_READY_COUNT_OFFSET: usize = 20;
/// `flags` bit: every group of this blob is ready. Sticky — ready bits are
/// never cleared, so once set it stays set for the lifetime of the file.
const GROUPMAP_FLAG_ALL_READY: u32 = 1;

/// Persistent per-blob group readiness bitmap, shared across processes.
///
/// The on-disk layout is a 4096-byte header (magic, version, flags, group
/// count, ready count) followed by one bit per group. The whole file is
/// mapped `MAP_SHARED` and the bits are accessed with atomic operations, so
/// every process (or thread) that opens the same groupmap file observes
/// `set_ready` updates from all the others through the shared page cache —
/// this is what lets concurrent nydus instances on one node share a single
/// warmed cache. Persistence across reboots is provided by regular kernel
/// writeback of the dirty pages.
///
/// The header additionally carries an `ALL_READY` flag: the moment the last
/// group turns ready, the flag is set (also visible cross-process), and
/// `is_all_ready` becomes a single atomic load. On-demand services (uffd,
/// fanotify, FUSE) use it as a fast path to skip per-group readiness
/// bookkeeping entirely once a blob is fully cached.
pub struct GroupMap {
    map: MmapRaw,
    group_count: usize,
    // Keep the backing file open for the lifetime of the mapping.
    _file: File,
}

impl GroupMap {
    pub fn open(path: &Path, group_count: usize) -> io::Result<Self> {
        let bytes_len = group_count.div_ceil(8);
        let expected_len = (GROUPMAP_HEADER_SIZE + bytes_len) as u64;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let file_len = file.metadata()?.len();
        if file_len == 0 {
            // First creation. Racing creators run the same idempotent
            // sequence: size the file, then write the identical header bytes.
            file.set_len(expected_len)?;
            file.write_all_at(&header_bytes(group_count), 0)?;
        } else if file_len != expected_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "groupmap {} size mismatch: expected {}, got {}",
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
                format!("groupmap {} mapping size mismatch", path.display()),
            ));
        }

        // There is a race window between a concurrent creator's `set_len` and
        // its header write, during which we may map an all-zero header. That
        // window is detected here and healed by (re)writing the identical
        // header bytes; anything else is a corrupt or foreign file. The
        // mutable fields (flags, ready count) cannot have been touched in
        // that window: no process can update them before a successful open.
        let header = unsafe { std::slice::from_raw_parts(map.as_ptr(), GROUPMAP_HEADER_SIZE) };
        if header[..GROUPMAP_MAGIC.len()] != GROUPMAP_MAGIC {
            if header.iter().all(|byte| *byte == 0) {
                file.write_all_at(&header_bytes(group_count), 0)?;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid groupmap magic: {}", path.display()),
                ));
            }
        } else {
            // `version` (offset 8) is informational and not gated on, matching
            // the other sidecar formats.
            let existing = u32::from_le_bytes(
                header[GROUPMAP_GROUP_COUNT_OFFSET..GROUPMAP_GROUP_COUNT_OFFSET + 4]
                    .try_into()
                    .unwrap(),
            ) as usize;
            if existing != group_count {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "groupmap {} group count mismatch: expected {}, got {}",
                        path.display(),
                        group_count,
                        existing
                    ),
                ));
            }
        }

        let groupmap = Self {
            map,
            group_count,
            _file: file,
        };
        // Reconcile the ALL_READY flag from the authoritative bitmap. This
        // heals the rare counter skew left by a process that died between
        // setting the last bit and bumping the ready count, and marks
        // fully-warmed blobs (including empty ones) at open time so readers
        // start on the fast path immediately.
        if !groupmap.is_all_ready() && groupmap.scan_all_ready() {
            groupmap.mark_all_ready();
        }
        Ok(groupmap)
    }

    /// Atomic view of the byte holding the ready bit for `index`.
    fn bit_byte(&self, index: usize) -> &AtomicU8 {
        let offset = GROUPMAP_HEADER_SIZE + index / 8;
        // Safety: `offset` is within the mapping (checked against the file
        // size derived from `group_count` in `open`), and `AtomicU8` has the
        // same layout as `u8` with no alignment requirement beyond 1.
        unsafe { &*(self.map.as_ptr().add(offset) as *const AtomicU8) }
    }

    /// Atomic view of a mutable u32 header field at `offset`.
    fn header_u32(&self, offset: usize) -> &AtomicU32 {
        debug_assert!(offset % 4 == 0 && offset + 4 <= GROUPMAP_HEADER_SIZE);
        // Safety: the mapping is page aligned and at least one header page
        // long, and `offset` is a 4-byte-aligned position inside the header,
        // satisfying AtomicU32's alignment and size requirements.
        unsafe { &*(self.map.as_ptr().add(offset) as *const AtomicU32) }
    }

    pub fn is_ready(&self, index: usize) -> io::Result<bool> {
        ensure_index(index, self.group_count)?;
        let mask = 1u8 << (index % 8);
        Ok(self.bit_byte(index).load(Ordering::Acquire) & mask != 0)
    }

    pub fn ready_ranges(&self, first: usize, last: usize) -> io::Result<Vec<Range<usize>>> {
        ensure_range(first, last, self.group_count)?;

        // Fast path: a fully-ready blob needs no bit scanning at all.
        if self.is_all_ready() {
            // A Vec holding one Range value is exactly what callers expect.
            #[allow(clippy::single_range_in_vec_init)]
            return Ok(vec![first..last + 1]);
        }

        let mut ranges = Vec::new();
        let mut start = None;
        for index in first..=last {
            match (start, self.is_ready(index)?) {
                (None, true) => start = Some(index),
                (Some(range_start), false) => {
                    ranges.push(range_start..index);
                    start = None;
                }
                _ => {}
            }
        }
        if let Some(range_start) = start {
            ranges.push(range_start..last + 1);
        }
        Ok(ranges)
    }

    pub fn set_ready(&self, index: usize) -> io::Result<()> {
        ensure_index(index, self.group_count)?;
        let mask = 1u8 << (index % 8);
        let previous = self.bit_byte(index).fetch_or(mask, Ordering::AcqRel);
        if previous & mask == 0 {
            // This call made the 0→1 transition (exactly one process does,
            // per group), so it owns bumping the shared ready count. When the
            // count reaches the total, latch the sticky ALL_READY flag.
            let count = self
                .header_u32(GROUPMAP_READY_COUNT_OFFSET)
                .fetch_add(1, Ordering::AcqRel)
                + 1;
            if count as usize >= self.group_count {
                self.mark_all_ready();
            }
        }
        Ok(())
    }

    /// O(1) fast-path check: true when the sticky ALL_READY header flag is
    /// set, i.e. every group of this blob has been decoded into the cache.
    /// A single atomic load on the shared mapping — no bitmap scan — so
    /// per-fault handlers (uffd, fanotify, FUSE reads) can consult it on
    /// every event at effectively zero cost.
    pub fn is_all_ready(&self) -> bool {
        self.header_u32(GROUPMAP_FLAGS_OFFSET)
            .load(Ordering::Acquire)
            & GROUPMAP_FLAG_ALL_READY
            != 0
    }

    /// True when every group is marked ready. Checks the sticky header flag
    /// first; otherwise scans the shared bitmap and latches the flag when the
    /// scan proves completion (also healing any ready-count skew left by a
    /// crashed writer). The answer reflects updates from other processes.
    pub fn all_ready(&self) -> bool {
        if self.is_all_ready() {
            return true;
        }
        if self.scan_all_ready() {
            self.mark_all_ready();
            return true;
        }
        false
    }

    /// Authoritative scan of the bitmap (masking the partial final byte).
    fn scan_all_ready(&self) -> bool {
        for index in (0..self.group_count).step_by(8) {
            let bits = self.bit_byte(index).load(Ordering::Acquire);
            let remaining = self.group_count - index;
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

    fn mark_all_ready(&self) {
        // Keep the advisory ready counter honest as well: when the flag is
        // latched from a bitmap scan (heal path), the counter may still be
        // short from a crashed writer. Every bit is set at this point, so no
        // concurrent 0→1 increment can race with this store.
        self.header_u32(GROUPMAP_READY_COUNT_OFFSET)
            .store(self.group_count as u32, Ordering::Release);
        self.header_u32(GROUPMAP_FLAGS_OFFSET)
            .fetch_or(GROUPMAP_FLAG_ALL_READY, Ordering::AcqRel);
    }

    /// Number of groups currently marked ready (advisory shared counter,
    /// exact once ALL_READY is latched).
    pub fn ready_count(&self) -> usize {
        self.header_u32(GROUPMAP_READY_COUNT_OFFSET)
            .load(Ordering::Acquire) as usize
    }
}

fn header_bytes(group_count: usize) -> [u8; GROUPMAP_HEADER_SIZE] {
    let mut header = [0u8; GROUPMAP_HEADER_SIZE];
    header[..8].copy_from_slice(&GROUPMAP_MAGIC);
    header[8..12].copy_from_slice(&GROUPMAP_VERSION.to_le_bytes());
    // flags (12..16) and ready count (20..24) start at zero; the remaining
    // header tail is reserved and stays zero.
    header[GROUPMAP_GROUP_COUNT_OFFSET..GROUPMAP_GROUP_COUNT_OFFSET + 4]
        .copy_from_slice(&(group_count as u32).to_le_bytes());
    header
}

fn ensure_index(index: usize, group_count: usize) -> io::Result<()> {
    if index >= group_count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("group index {index} out of range {group_count}"),
        ));
    }
    Ok(())
}

fn ensure_range(first: usize, last: usize, group_count: usize) -> io::Result<()> {
    ensure_index(first, group_count)?;
    ensure_index(last, group_count)?;
    if first > last {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid group range",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn groupmap_persists_ready_bits() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");

        let map = GroupMap::open(&path, 10).unwrap();
        assert!(!map.is_ready(3).unwrap());
        map.set_ready(3).unwrap();
        map.set_ready(9).unwrap();
        assert!(map.is_ready(3).unwrap());
        assert!(map.is_ready(9).unwrap());

        let reopened = GroupMap::open(&path, 10).unwrap();
        assert!(reopened.is_ready(3).unwrap());
        assert!(reopened.is_ready(9).unwrap());
        assert!(!reopened.is_ready(2).unwrap());
    }

    #[test]
    fn groupmap_updates_are_visible_across_handles() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");

        // Two live handles on the same file model two concurrent processes:
        // bits set through one must be observed by the other without reopen.
        let writer = GroupMap::open(&path, 20).unwrap();
        let observer = GroupMap::open(&path, 20).unwrap();
        assert!(!observer.is_ready(7).unwrap());
        writer.set_ready(7).unwrap();
        assert!(observer.is_ready(7).unwrap());
        assert!(!observer.all_ready());

        for index in 0..20 {
            writer.set_ready(index).unwrap();
        }
        assert!(observer.all_ready());
    }

    #[test]
    fn groupmap_reports_merged_ready_ranges() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");
        let map = GroupMap::open(&path, 10).unwrap();
        for index in [1, 2, 4, 7, 8, 9] {
            map.set_ready(index).unwrap();
        }

        assert_eq!(map.ready_ranges(0, 9).unwrap(), vec![1..3, 4..5, 7..10]);
        assert_eq!(map.ready_ranges(7, 9).unwrap(), vec![7..10]);
        assert_eq!(map.ready_ranges(0, 8).unwrap(), vec![1..3, 4..5, 7..9]);
        assert_eq!(map.ready_ranges(8, 9).unwrap(), vec![8..10]);
    }

    #[test]
    fn groupmap_rejects_count_mismatch() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");

        GroupMap::open(&path, 10).unwrap();
        assert!(GroupMap::open(&path, 11).is_err());
    }

    #[test]
    fn groupmap_heals_all_zero_header_race() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");

        // Model the concurrent-creation race window: another process ran
        // `set_len` but has not written the header yet, so we map a fully
        // sized, all-zero file. Open must heal the header and proceed.
        let group_count = 10usize;
        let expected_len = (GROUPMAP_HEADER_SIZE + group_count.div_ceil(8)) as u64;
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        file.set_len(expected_len).unwrap();
        drop(file);

        let map = GroupMap::open(&path, group_count).unwrap();
        map.set_ready(4).unwrap();
        assert!(map.is_ready(4).unwrap());

        // The healed header persists: a reopen validates magic/count normally.
        let reopened = GroupMap::open(&path, group_count).unwrap();
        assert!(reopened.is_ready(4).unwrap());
    }

    #[test]
    fn groupmap_rejects_corrupt_magic_and_size() {
        let dir = tempdir().unwrap();

        // Correctly sized file with non-zero garbage: not a race window,
        // must be rejected instead of silently reinitialized.
        let garbage = dir.path().join("garbage.group.map");
        let expected_len = GROUPMAP_HEADER_SIZE + 10usize.div_ceil(8);
        std::fs::write(&garbage, vec![0xABu8; expected_len]).unwrap();
        assert!(GroupMap::open(&garbage, 10).is_err());

        // Existing file whose size does not match the expected layout.
        let truncated = dir.path().join("truncated.group.map");
        std::fs::write(&truncated, vec![0u8; expected_len - 1]).unwrap();
        assert!(GroupMap::open(&truncated, 10).is_err());
    }

    #[test]
    fn groupmap_latches_all_ready_flag_on_last_bit() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");

        let writer = GroupMap::open(&path, 9).unwrap();
        let observer = GroupMap::open(&path, 9).unwrap();
        assert!(!writer.is_all_ready());

        for index in 0..8 {
            writer.set_ready(index).unwrap();
            assert!(!writer.is_all_ready(), "flag latched early at {index}");
        }
        writer.set_ready(8).unwrap();

        // The sticky flag is a single shared header field: both the setter and
        // a concurrent observer see it without any bitmap scan or reopen.
        assert!(writer.is_all_ready());
        assert!(observer.is_all_ready());
        assert!(observer.all_ready());

        // ready_ranges collapses to the whole span on the fast path.
        assert_eq!(observer.ready_ranges(0, 8).unwrap(), vec![0..9]);

        // And the flag persists on disk.
        let reopened = GroupMap::open(&path, 9).unwrap();
        assert!(reopened.is_all_ready());
    }

    #[test]
    fn groupmap_heals_ready_count_skew_from_bitmap() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");

        // Model a writer that died between setting bits and bumping the ready
        // count: craft a file whose bitmap is fully set but whose flags and
        // ready count are still zero.
        let group_count = 10usize;
        {
            let map = GroupMap::open(&path, group_count).unwrap();
            drop(map);
        }
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.write_all_at(&[0xFF, 0x03], GROUPMAP_HEADER_SIZE as u64)
            .unwrap();
        drop(file);

        // Open reconciles the flag from the authoritative bitmap.
        let map = GroupMap::open(&path, group_count).unwrap();
        assert!(map.is_all_ready());
        assert!(map.all_ready());
        // The heal path also corrects the advisory ready counter.
        assert_eq!(map.ready_count(), group_count);
    }

    #[test]
    fn groupmap_empty_blob_is_all_ready() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");

        let map = GroupMap::open(&path, 0).unwrap();
        assert!(map.is_all_ready());
        assert!(map.all_ready());
    }

    #[test]
    fn groupmap_bit_boundaries_and_range_checks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");

        // 9 groups spill into a second bitmap byte; exercise both byte
        // boundaries and the partial final byte in all_ready().
        let map = GroupMap::open(&path, 9).unwrap();
        for index in [0usize, 7, 8] {
            assert!(!map.is_ready(index).unwrap());
            map.set_ready(index).unwrap();
            assert!(map.is_ready(index).unwrap());
        }
        for index in [1usize, 6] {
            assert!(!map.is_ready(index).unwrap(), "neighbor bit {index} leaked");
        }
        assert!(!map.all_ready());
        for index in 0..9 {
            map.set_ready(index).unwrap();
        }
        assert!(map.all_ready());

        // Out-of-range indexes are rejected, not silently wrapped.
        assert_eq!(
            map.is_ready(9).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            map.set_ready(9).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn groupmap_concurrent_setters_lose_no_updates() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");
        let group_count = 4096usize;

        // Two handles (modeling two processes) hammer interleaved indexes so
        // nearly every fetch_or contends on a byte shared with the other
        // writer. Any non-atomic read-modify-write would lose bits here.
        let even = GroupMap::open(&path, group_count).unwrap();
        let odd = GroupMap::open(&path, group_count).unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for index in (0..group_count).step_by(2) {
                    even.set_ready(index).unwrap();
                }
            });
            scope.spawn(|| {
                for index in (1..group_count).step_by(2) {
                    odd.set_ready(index).unwrap();
                }
            });
        });

        let verify = GroupMap::open(&path, group_count).unwrap();
        for index in 0..group_count {
            assert!(verify.is_ready(index).unwrap(), "lost update at {index}");
        }
        assert!(verify.all_ready());
    }

    #[test]
    fn groupmap_scales_to_large_group_counts() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.group.map");
        // 1M groups ≈ a 4TiB blob at the default 4MiB group size — far above
        // anything real. The old implementation issued a write syscall per
        // set_ready; the mmap version must stay in-memory fast.
        let group_count = 1_000_000usize;

        let start = std::time::Instant::now();
        let map = GroupMap::open(&path, group_count).unwrap();
        for index in 0..group_count {
            map.set_ready(index).unwrap();
        }
        for index in 0..group_count {
            assert!(map.is_ready(index).unwrap());
        }
        assert!(map.all_ready());
        let elapsed = start.elapsed();
        // Generous bound (debug builds included): catches only pathological
        // regressions such as reintroducing per-bit file I/O.
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "groupmap operations too slow: {elapsed:?}"
        );
    }
}
