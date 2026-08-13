//! Extent primitives: [`Extent`] maps one span of a source
//! view (flattened device or file) to its backing file location, shared by the crate-root
//! [`NydusCore`](crate::NydusCore) flat-device view and the per-file
//! [`Node`](crate::entry::Node) API.

use std::collections::HashMap;
use std::io;
use std::os::fd::RawFd;
use std::sync::RwLock;

use crate::reader::ErofsReader;
use nydus_error::{Context, Error, Result};
use nydus_format::utils::pread_exact;

/// One resolved extent: maps `[source_offset, source_offset + len)` of the
/// source view to its mmap-ready backing location `(fd, offset)`, in the
/// fiemap `logical -> physical` sense.
///
/// `fd` is always a real file descriptor. Zero-filled ranges use the
/// core-owned `/dev/zero` fd with `offset == 0`; callers can compare
/// against [`NydusCore::zero_fd`](crate::NydusCore::zero_fd) to recognize
/// those ranges for optimized copy-mode handling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Extent {
    /// Raw fd backing this range. The fd is owned by the core/cache and
    /// must not be closed by the caller.
    pub fd: RawFd,
    /// Byte offset within `fd`. For zero-filled ranges this is always `0`.
    pub offset: u64,
    /// Length in bytes.
    pub len: u64,
    /// Offset in the source view: flattened-device offset for
    /// [`NydusCore`](crate::NydusCore) ranges, file-relative offset for
    /// [`Node`](crate::entry::Node) ranges.
    pub source_offset: u64,
}

impl Extent {
    pub(crate) fn new(fd: RawFd, offset: u64, len: u64, source_offset: u64) -> Self {
        Self {
            fd,
            offset,
            len,
            source_offset,
        }
    }
}

/// How a range resolution treats missing data: `Fetch` pulls it into the
/// cache, `Probe` only reports readiness. Shared by the flat-device and
/// per-file resolution paths and by transports (e.g. uffd).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveMode {
    Fetch,
    Probe,
}

/// A blob-relative range to resolve into [`Extent`]s.
#[derive(Clone, Copy)]
pub(crate) struct BlobRangeSpec {
    pub(crate) index: u16,
    pub(crate) offset: u64,
    pub(crate) len: u64,
    pub(crate) source_offset: u64,
}

/// Clamp `[offset, offset + len)` to `limit` and return the exclusive end,
/// or `None` when the clamped range is empty (zero length, or entirely past
/// `limit`). Errors only when `offset + len` overflows.
pub(crate) fn clamped_range_end(offset: u64, len: u64, limit: u64) -> Result<Option<u64>> {
    if len == 0 {
        return Ok(None);
    }
    let end = offset
        .checked_add(len)
        .ok_or_else(|| Error::Overflow("range offset + length overflow".to_string()))?
        .min(limit);
    if offset >= end {
        return Ok(None);
    }
    Ok(Some(end))
}

pub(crate) fn mapped_range_offset(mapped_offset: u64, size: u64, offset: u64) -> Option<u64> {
    let end = mapped_offset.checked_add(size)?;
    if offset >= mapped_offset && offset < end {
        Some(offset - mapped_offset)
    } else {
        None
    }
}

/// Accumulates the [`Extent`]s of one resolution pass.
///
/// Owns the state the resolution loops share — the output vector, the
/// `/dev/zero` fd used for hole handling and merge detection, and the reader
/// whose blob caches blob-relative spans resolve against.
pub(crate) struct ExtentResolver<'a> {
    reader: &'a ErofsReader,
    zero_fd: RawFd,
    ranges: Vec<Extent>,
}

impl<'a> ExtentResolver<'a> {
    pub(crate) fn new(reader: &'a ErofsReader, zero_fd: RawFd) -> Self {
        Self {
            reader,
            zero_fd,
            ranges: Vec::new(),
        }
    }

    /// Append `range`, merging it into the previous range when both are backed
    /// by the same fd and contiguous (adjacent zero-fd ranges also merge).
    pub(crate) fn push(&mut self, range: Extent) {
        if range.len == 0 {
            return;
        }
        if let Some(last) = self.ranges.last_mut() {
            let source_contiguous = last.source_offset + last.len == range.source_offset;
            let file_contiguous = last.offset + last.len == range.offset;
            let both_zero = last.fd == self.zero_fd
                && range.fd == self.zero_fd
                && last.offset == 0
                && range.offset == 0;
            if last.fd == range.fd && source_contiguous && (file_contiguous || both_zero) {
                last.len += range.len;
                return;
            }
        }
        self.ranges.push(range);
    }

    /// Resolve `spec` against its blob cache and append the results: fetch
    /// missing data first in [`ResolveMode::Fetch`], append only cache-ready
    /// intervals in [`ResolveMode::Probe`].
    pub(crate) fn push_blob(&mut self, spec: BlobRangeSpec, mode: ResolveMode) -> Result<()> {
        let cache = self
            .reader
            .blob_cache(spec.index)
            .with_context(|| format!("failed to open blob {}", spec.index))?;
        let fd = cache
            .cache_fd()
            .with_context(|| format!("failed to get cache fd for blob {}", spec.index))?;

        match mode {
            ResolveMode::Fetch => {
                cache.ensure_range(spec.offset, spec.len).with_context(|| {
                    format!(
                        "failed to fetch blob {} range [{}, +{})",
                        spec.index, spec.offset, spec.len
                    )
                })?;
                self.push(Extent::new(fd, spec.offset, spec.len, spec.source_offset));
            }
            ResolveMode::Probe => {
                for ready in cache.ready_ranges(spec.offset, spec.len)? {
                    self.push(Extent::new(
                        fd,
                        ready.start,
                        ready.end - ready.start,
                        spec.source_offset + (ready.start - spec.offset),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Consume the resolver and return the accumulated ranges.
    pub(crate) fn finish(self) -> Vec<Extent> {
        self.ranges
    }
}

/// Lazily-built cache of read-only shared mappings of the files backing the
/// flattened device, keyed by fd. A file is mapped on first use; a copy that
/// cannot be served from a mapping falls back to `pread`.
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
pub struct MmapCache {
    maps: RwLock<HashMap<RawFd, Mapping>>,
}

/// A single `mmap`ed file. `addr` is kept as a `usize` so the map stays
/// `Send`/`Sync`: the mapping is read-only and shared by all queue threads.
struct Mapping {
    addr: usize,
    len: usize,
}

impl MmapCache {
    /// Copy `ranges` into `buf`, where `buf` starts at flattened device `offset`.
    ///
    /// `fetch_flat_ranges` returns ranges ordered by `source_offset`, but it may
    /// stop short of the requested length (e.g. past `flat_size`). Any byte not
    /// covered by a range — before, between or after them — reads as zero, which is
    /// what a block device with sparse backing returns.
    pub fn copy_ranges(
        &self,
        ranges: &[Extent],
        offset: u64,
        zero_fd: RawFd,
        buf: &mut [u8],
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
            } else if !self.copy(range.fd, src_offset, dst) {
                pread_exact(range.fd, dst, src_offset)?;
            }
            cursor = end;
        }

        if cursor < buf.len() {
            buf[cursor..].fill(0);
        }
        Ok(())
    }

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

    fn range(fd: RawFd, offset: u64, len: u64, source_offset: u64) -> Extent {
        Extent {
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
        MmapCache::default()
            .copy_ranges(&ranges, 0, ZERO_FD, &mut buf)
            .unwrap();
        assert_eq!(&buf, b"BOOTBLOBDATA");
    }

    #[test]
    fn zero_fills_gaps_and_the_tail() {
        let blob = temp_file(b"DATA");

        // A hole at 0..4, blob data at 4..8, nothing beyond.
        let ranges = [range(ZERO_FD, 0, 4, 0), range(blob.as_raw_fd(), 0, 4, 4)];

        let mut buf = [0xffu8; 12];
        MmapCache::default()
            .copy_ranges(&ranges, 0, ZERO_FD, &mut buf)
            .unwrap();
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
        MmapCache::default()
            .copy_ranges(&ranges, 0, ZERO_FD, &mut buf)
            .unwrap();
        assert_eq!(&buf, b"HEAD\0\0\0\0TAIL");
    }

    #[test]
    fn honours_a_non_zero_request_offset() {
        let blob = temp_file(b"0123456789");

        // Reading 4 bytes at flattened offset 4, served by a range that starts
        // at flattened offset 2: the first two bytes of the range are skipped.
        let ranges = [range(blob.as_raw_fd(), 0, 8, 2)];

        let mut buf = [0xffu8; 4];
        MmapCache::default()
            .copy_ranges(&ranges, 4, ZERO_FD, &mut buf)
            .unwrap();
        assert_eq!(&buf, b"2345");
    }

    #[test]
    fn truncates_ranges_that_overshoot_the_buffer() {
        let blob = temp_file(b"0123456789");
        let ranges = [range(blob.as_raw_fd(), 0, 10, 0)];

        let mut buf = [0xffu8; 4];
        MmapCache::default()
            .copy_ranges(&ranges, 0, ZERO_FD, &mut buf)
            .unwrap();
        assert_eq!(&buf, b"0123");
    }

    #[test]
    fn zero_fills_when_no_range_is_returned() {
        let mut buf = [0xffu8; 8];
        MmapCache::default()
            .copy_ranges(&[], 0, ZERO_FD, &mut buf)
            .unwrap();
        assert_eq!(&buf, &[0u8; 8]);
    }
}
