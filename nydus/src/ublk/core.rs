//! Flattened block-device view of a nydus image.
//!
//! [`UblkCore`] turns [`NydusCore`]'s flattened device view into a plain
//! `read_at(offset, buf)` interface: the bootstrap is exposed at the beginning
//! of the address space, each blob at the `mapped_blkaddr` recorded in the
//! bootstrap device table, and the gaps in between as zeroes. That is exactly
//! the layout the kernel EROFS driver expects from a single block device, so
//! the resulting device can be mounted with `mount -t erofs /dev/ublkbN`.

use std::collections::HashMap;
use std::io;
use std::os::fd::RawFd;
use std::path::Path;
use std::sync::RwLock;

use anyhow::{Context, Result};

use nydus_core::config::Config;
use nydus_core::core::{FdRange, NydusCore};
use nydus_core::metadata::EROFS_BLOCK_SIZE;
use nydus_core::utils::{align_up, pread_exact};

/// Logical block size exposed by the ublk device. Matching the EROFS block size
/// keeps every incoming request aligned to a whole number of EROFS blocks.
pub const UBLK_LOGICAL_BLOCK_SIZE: u64 = EROFS_BLOCK_SIZE as u64;

/// Read-only block device backed by a nydus image.
pub struct UblkCore {
    core: NydusCore,
    zero_fd: RawFd,
    device_size: u64,
    maps: FileMaps,
}

impl UblkCore {
    /// Open `bootstrap` with the storage `config` and expose it as a flattened
    /// read-only block device. All blobs referenced by the bootstrap device
    /// table are prepared up front, and background prefetch follows
    /// `config.prefetch`.
    pub fn new(bootstrap: &Path, config: Config) -> Result<Self> {
        let core = NydusCore::new(bootstrap, config)
            .context("failed to open nydus image for the ublk device")?;
        let zero_fd = core.zero_fd();
        // Round the device size up to a whole block: the kernel always reads in
        // block units, and the tail block of the last blob may be partial.
        let device_size = align_up(core.flat_size(), UBLK_LOGICAL_BLOCK_SIZE)
            .context("flattened device size overflow")?;
        // Preparing a blob downloads and validates its meta and sizes its cache
        // file, which takes seconds for a large image. Left to the first block
        // read it stalls whoever gets there first — typically `mount`, which
        // then appears to hang long after the device was announced as ready.
        core.blobs
            .flat_layout()
            .context("failed to prepare the blobs backing the device")?;

        Ok(Self {
            core,
            zero_fd,
            device_size,
            maps: FileMaps::default(),
        })
    }

    /// Size of the block device in bytes, always a multiple of
    /// [`UBLK_LOGICAL_BLOCK_SIZE`].
    pub fn device_size(&self) -> u64 {
        self.device_size
    }

    /// Borrow the underlying core, e.g. to snapshot metrics.
    pub fn core(&self) -> &NydusCore {
        &self.core
    }

    /// Read `buf.len()` bytes at `offset` of the flattened device.
    ///
    /// Ranges past the end of the image, gaps between blobs and holes in a
    /// partially fetched blob all read as zeroes, mirroring what a real block
    /// device with sparse backing would return. Missing blob data is fetched
    /// from the backend on demand before the copy.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        if offset >= self.device_size {
            buf.fill(0);
            return Ok(());
        }

        let len = (buf.len() as u64).min(self.device_size - offset);
        let ranges = self
            .core
            .fetch_flat_ranges(offset, len)
            .map_err(|err| io::Error::other(format!("{err:#}")))?;

        copy_ranges(&ranges, offset, self.zero_fd, buf, &self.maps)
    }
}

/// Copy `ranges` into `buf`, where `buf` starts at flattened device `offset`.
///
/// `fetch_flat_ranges` returns ranges ordered by `source_offset`, but it may
/// stop short of the requested length (e.g. past `flat_size`). Any byte not
/// covered by a range — before, between or after them — reads as zero, which is
/// what a block device with sparse backing returns.
fn copy_ranges(
    ranges: &[FdRange],
    offset: u64,
    zero_fd: RawFd,
    buf: &mut [u8],
    maps: &FileMaps,
) -> io::Result<()> {
    let mut cursor = 0usize;
    for range in ranges {
        // Where this range lands in `buf`, clipping the part that starts before
        // the requested offset.
        let (start, clipped) = if range.source_offset >= offset {
            ((range.source_offset - offset) as usize, 0u64)
        } else {
            let behind = offset - range.source_offset;
            if behind >= range.len {
                continue;
            }
            (0usize, behind)
        };
        if start >= buf.len() {
            continue;
        }
        if start > cursor {
            buf[cursor..start].fill(0);
            cursor = start;
        }
        let end = (start + (range.len - clipped) as usize).min(buf.len());
        if end <= cursor {
            continue;
        }

        let dst = &mut buf[cursor..end];
        let src_offset = range.offset + clipped + (cursor - start) as u64;
        if range.fd == zero_fd {
            dst.fill(0);
        } else if !maps.copy(range.fd, src_offset, dst) {
            pread_exact(range.fd, dst, src_offset)?;
        }
        cursor = end;
    }

    if cursor < buf.len() {
        buf[cursor..].fill(0);
    }
    Ok(())
}

/// Read-only shared mappings of the files backing the flattened device.
///
/// Serving a block request with `pread` costs a syscall plus a
/// `copy_to_user` of the whole payload; copying out of a `MAP_SHARED`
/// mapping of the same page cache costs about half as much, which matters
/// because a queue thread is CPU bound at high IOPS.
///
/// The backing files never shrink — the bootstrap is opened read-only and
/// each blob cache file is sized to the blob's dense address space when it is
/// prepared — so a mapping stays valid for the life of the device and cannot
/// fault with `SIGBUS`. A range that reaches past a mapping (a file that grew
/// after it was mapped) simply falls back to `pread`.
#[derive(Default)]
struct FileMaps {
    maps: RwLock<HashMap<RawFd, Mapping>>,
}

/// A single `mmap`ed file. `addr` is kept as a `usize` so the map stays
/// `Send`/`Sync`: the mapping is read-only and shared by all queue threads.
struct Mapping {
    addr: usize,
    len: usize,
}

impl FileMaps {
    /// Copy `dst.len()` bytes at `offset` of `fd` out of its mapping, mapping
    /// the file on first use. Returns false when the copy could not be served
    /// from a mapping and the caller must fall back to `pread`.
    fn copy(&self, fd: RawFd, offset: u64, dst: &mut [u8]) -> bool {
        if let Ok(maps) = self.maps.read() {
            if let Some(map) = maps.get(&fd) {
                return map.copy(offset, dst);
            }
        }

        let Some(map) = Mapping::new(fd) else {
            return false;
        };
        let Ok(mut maps) = self.maps.write() else {
            return false;
        };
        // A racing thread may have mapped the same fd already; keep the
        // existing mapping and drop ours.
        maps.entry(fd).or_insert(map).copy(offset, dst)
    }
}

impl Mapping {
    fn new(fd: RawFd) -> Option<Self> {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            return None;
        }
        let len = usize::try_from(stat.st_size).ok().filter(|len| *len > 0)?;
        // SAFETY: `fd` is a readable regular file owned by the core and
        // kept open for the whole life of the device.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return None;
        }
        Some(Self {
            addr: addr as usize,
            len,
        })
    }

    fn copy(&self, offset: u64, dst: &mut [u8]) -> bool {
        let Ok(offset) = usize::try_from(offset) else {
            return false;
        };
        let Some(end) = offset.checked_add(dst.len()) else {
            return false;
        };
        if end > self.len {
            return false;
        }
        // SAFETY: `[offset, end)` is inside the mapping, which stays alive and
        // read-only until this `Mapping` is dropped.
        unsafe {
            std::ptr::copy_nonoverlapping(
                (self.addr as *const u8).add(offset),
                dst.as_mut_ptr(),
                dst.len(),
            );
        }
        true
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: `addr`/`len` come from a successful `mmap` and are unmapped
        // exactly once.
        unsafe { libc::munmap(self.addr as *mut libc::c_void, self.len) };
    }
}

/// Read `buf.len()` bytes at `offset` from `fd`, zero-filling the tail on EOF.
///
/// Blob cache files are sparse and sized to the blob's dense block address
/// space, but a short read can still happen when the core resolved a range
/// that extends past the current file size; treat it the same way a block
/// device treats an unwritten sector.

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    const ZERO_FD: RawFd = -1;

    /// A temp file holding `data`, kept alive for the fd's lifetime.
    fn temp_file(data: &[u8]) -> std::fs::File {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(data).unwrap();
        file
    }

    fn range(fd: RawFd, offset: u64, len: u64, source_offset: u64) -> FdRange {
        FdRange {
            fd,
            offset,
            len,
            source_offset,
        }
    }

    #[test]
    fn copies_contiguous_ranges_from_multiple_files() {
        let meta = temp_file(b"BOOTSTRAP");
        let blob = temp_file(b"__BLOBDATA");

        // Flattened layout: bootstrap at 0..4, blob at 4..12 (from byte 2 of
        // the blob file, i.e. skipping its "__" prefix).
        let ranges = [
            range(meta.as_raw_fd(), 0, 4, 0),
            range(blob.as_raw_fd(), 2, 8, 4),
        ];

        let mut buf = [0xffu8; 12];
        copy_ranges(&ranges, 0, ZERO_FD, &mut buf, &FileMaps::default()).unwrap();
        assert_eq!(&buf, b"BOOTBLOBDATA");
    }

    #[test]
    fn zero_fills_gaps_and_the_tail() {
        let blob = temp_file(b"DATA");

        // A hole at 0..4, blob data at 4..8, nothing beyond.
        let ranges = [range(ZERO_FD, 0, 4, 0), range(blob.as_raw_fd(), 0, 4, 4)];

        let mut buf = [0xffu8; 12];
        copy_ranges(&ranges, 0, ZERO_FD, &mut buf, &FileMaps::default()).unwrap();
        assert_eq!(&buf, b"\0\0\0\0DATA\0\0\0\0");
    }

    #[test]
    fn zero_fills_ranges_missing_from_the_middle() {
        let head = temp_file(b"HEAD");
        let tail = temp_file(b"TAIL");

        // 4..8 is not covered by any range and must read back as zeroes.
        let ranges = [
            range(head.as_raw_fd(), 0, 4, 0),
            range(tail.as_raw_fd(), 0, 4, 8),
        ];

        let mut buf = [0xffu8; 12];
        copy_ranges(&ranges, 0, ZERO_FD, &mut buf, &FileMaps::default()).unwrap();
        assert_eq!(&buf, b"HEAD\0\0\0\0TAIL");
    }

    #[test]
    fn honours_a_non_zero_request_offset() {
        let blob = temp_file(b"0123456789");

        // Reading 4 bytes at flattened offset 4, served by a range that starts
        // at flattened offset 2: the first two bytes of the range are skipped.
        let ranges = [range(blob.as_raw_fd(), 0, 8, 2)];

        let mut buf = [0xffu8; 4];
        copy_ranges(&ranges, 4, ZERO_FD, &mut buf, &FileMaps::default()).unwrap();
        assert_eq!(&buf, b"2345");
    }

    #[test]
    fn truncates_ranges_that_overshoot_the_buffer() {
        let blob = temp_file(b"0123456789");
        let ranges = [range(blob.as_raw_fd(), 0, 10, 0)];

        let mut buf = [0xffu8; 4];
        copy_ranges(&ranges, 0, ZERO_FD, &mut buf, &FileMaps::default()).unwrap();
        assert_eq!(&buf, b"0123");
    }

    #[test]
    fn zero_fills_when_no_range_is_returned() {
        let mut buf = [0xffu8; 8];
        copy_ranges(&[], 0, ZERO_FD, &mut buf, &FileMaps::default()).unwrap();
        assert_eq!(&buf, &[0u8; 8]);
    }
}
