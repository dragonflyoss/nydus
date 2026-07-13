use std::fs::{File, OpenOptions};
use std::io;
use std::ops::Range;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};

use memmap2::MmapRaw;

const GROUPMAP_MAGIC: [u8; 8] = *b"LPGM0001";
const GROUPMAP_VERSION: u32 = 1;
const GROUPMAP_HEADER_SIZE: usize = 16;

/// Persistent per-blob group readiness bitmap, shared across processes.
///
/// The on-disk layout is a 16-byte header (magic, version, group count)
/// followed by one bit per group. The whole file is mapped `MAP_SHARED` and
/// the bits are accessed with atomic operations, so every process (or thread)
/// that opens the same groupmap file observes `set_ready` updates from all
/// the others through the shared page cache — this is what lets concurrent
/// nydus instances on one node share a single warmed cache. Persistence
/// across reboots is provided by regular kernel writeback of the dirty pages.
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
        // header bytes; anything else is a corrupt or foreign file.
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
            let version = u32::from_le_bytes(header[8..12].try_into().unwrap());
            if version != GROUPMAP_VERSION {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported groupmap version {version}: {}", path.display()),
                ));
            }
            let existing = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
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

        Ok(Self {
            map,
            group_count,
            _file: file,
        })
    }

    /// Atomic view of the byte holding the ready bit for `index`.
    fn bit_byte(&self, index: usize) -> &AtomicU8 {
        let offset = GROUPMAP_HEADER_SIZE + index / 8;
        // Safety: `offset` is within the mapping (checked against the file
        // size derived from `group_count` in `open`), and `AtomicU8` has the
        // same layout as `u8` with no alignment requirement beyond 1.
        unsafe { &*(self.map.as_ptr().add(offset) as *const AtomicU8) }
    }

    pub fn is_ready(&self, index: usize) -> io::Result<bool> {
        ensure_index(index, self.group_count)?;
        let mask = 1u8 << (index % 8);
        Ok(self.bit_byte(index).load(Ordering::Acquire) & mask != 0)
    }

    pub fn ready_ranges(&self, first: usize, last: usize) -> io::Result<Vec<Range<usize>>> {
        ensure_range(first, last, self.group_count)?;

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
        self.bit_byte(index).fetch_or(mask, Ordering::AcqRel);
        Ok(())
    }

    /// True when every group is marked ready. Scans the shared bitmap, so the
    /// answer reflects updates from other processes as well.
    pub fn all_ready(&self) -> bool {
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
}

fn header_bytes(group_count: usize) -> [u8; GROUPMAP_HEADER_SIZE] {
    let mut header = [0u8; GROUPMAP_HEADER_SIZE];
    header[..8].copy_from_slice(&GROUPMAP_MAGIC);
    header[8..12].copy_from_slice(&GROUPMAP_VERSION.to_le_bytes());
    header[12..16].copy_from_slice(&(group_count as u32).to_le_bytes());
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
        let path = dir.path().join("blob.groupmap");

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
        let path = dir.path().join("blob.groupmap");

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
        let path = dir.path().join("blob.groupmap");
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
        let path = dir.path().join("blob.groupmap");

        GroupMap::open(&path, 10).unwrap();
        assert!(GroupMap::open(&path, 11).is_err());
    }

    #[test]
    fn groupmap_heals_all_zero_header_race() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.groupmap");

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
        let garbage = dir.path().join("garbage.groupmap");
        let expected_len = GROUPMAP_HEADER_SIZE + 10usize.div_ceil(8);
        std::fs::write(&garbage, vec![0xABu8; expected_len]).unwrap();
        assert!(GroupMap::open(&garbage, 10).is_err());

        // Existing file whose size does not match the expected layout.
        let truncated = dir.path().join("truncated.groupmap");
        std::fs::write(&truncated, vec![0u8; expected_len - 1]).unwrap();
        assert!(GroupMap::open(&truncated, 10).is_err());
    }

    #[test]
    fn groupmap_bit_boundaries_and_range_checks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.groupmap");

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
        let path = dir.path().join("blob.groupmap");
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
        let path = dir.path().join("blob.groupmap");
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
