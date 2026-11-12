use std::io;
use std::os::fd::RawFd;
use std::path::Path;
use std::sync::Arc;

use nydus_config::Config;
use nydus_core::{Extent, NydusCore, ResolveMode};
use nydus_error::{Context, Error, Result};
use nydus_format::erofs::EROFS_BLOCK_SIZE;
use nydus_format::utils::align_up_u64;

use super::proto::{DeviceRange, FaultPolicy, VmaRegion};

pub const UFFD_BLOCK_SIZE: u64 = EROFS_BLOCK_SIZE as u64;
pub const UFFD_TOTAL_SIZE_ALIGNMENT: u64 = 2 * 1024 * 1024;

#[cfg(target_env = "musl")]
type IoctlRequest = i32;
#[cfg(not(target_env = "musl"))]
type IoctlRequest = u64;

pub(crate) const UFFD_EVENT_PAGEFAULT: u8 = 0x12;
pub(crate) const UFFDIO_WAKE: IoctlRequest = 0x8010aa02u32 as IoctlRequest;
pub(crate) const UFFDIO_COPY: IoctlRequest = 0xc028aa03u32 as IoctlRequest;
pub(crate) const UFFDIO_ZEROPAGE: IoctlRequest = 0xc020aa04u32 as IoctlRequest;

/// The times a fill is tried again while the address space changes under it,
/// and the wait between two tries.
const FILL_BUSY_RETRIES: u32 = 1000;
const FILL_BUSY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(1);

#[repr(C)]
struct UffdioRange {
    start: u64,
    len: u64,
}

#[repr(C)]
pub(crate) struct UffdMsg {
    pub event: u8,
    _reserved1: [u8; 3],
    _reserved2: u32,
    pub pagefault: UffdPagefault,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct UffdPagefault {
    pub flags: u64,
    pub address: u64,
    pub feat: u64,
}

#[repr(C)]
struct UffdioCopy {
    dst: u64,
    src: u64,
    len: u64,
    mode: u64,
    copy: i64,
}

#[repr(C)]
struct UffdioZeropage {
    range_start: u64,
    range_len: u64,
    mode: u64,
    zeropage: i64,
}

pub struct UffdCore {
    core: Arc<NydusCore>,
    device_size: u64,
}

impl UffdCore {
    pub fn new(bootstrap: &Path, config: Config) -> Result<Self> {
        let core = Arc::new(NydusCore::new(bootstrap, config, None)?);
        let device_size = align_up_u64(core.flat_size(), UFFD_TOTAL_SIZE_ALIGNMENT)
            .ok_or_else(|| Error::Overflow("alignment overflow".to_string()))?;

        Ok(Self { core, device_size })
    }

    pub fn device_size(&self) -> u64 {
        self.device_size
    }

    pub fn block_size(&self) -> u32 {
        UFFD_BLOCK_SIZE as u32
    }

    pub(crate) fn resolve_page_fault(
        &self,
        uffd_fd: RawFd,
        regions: &[VmaRegion],
        policy: FaultPolicy,
        msg: &UffdMsg,
    ) -> Result<Vec<Extent>> {
        let Some((region, range)) = resolve_fault_range(regions, msg)? else {
            return Ok(Vec::new());
        };
        let ranges = self.fetch_ranges(range.offset, range.len)?;

        match policy {
            FaultPolicy::Zerocopy => Ok(ranges),
            FaultPolicy::Copy => {
                for range in ranges {
                    let addr = region.virt_addr + (range.source_offset - region.offset);
                    if range.fd == self.core.zero_fd() {
                        uffdio_zeropage(uffd_fd, addr, range.len)?;
                    } else {
                        uffdio_copy_from_fd(uffd_fd, addr, range.fd, range.offset, range.len)?;
                    }
                }
                Ok(Vec::new())
            }
        }
    }

    pub fn prefault_ranges(&self, regions: &[VmaRegion]) -> Result<Vec<Extent>> {
        let mut ranges = Vec::new();
        for region in regions {
            let start = region.offset;
            let end = region
                .offset
                .saturating_add(region.size)
                .min(self.device_size);
            if end <= start {
                continue;
            }
            ranges.extend(self.resolve_ranges(start, end - start, ResolveMode::Probe)?);
        }
        Ok(ranges)
    }

    pub fn fetch_ranges(&self, device_offset: u64, len: u64) -> Result<Vec<Extent>> {
        self.resolve_ranges(device_offset, len, ResolveMode::Fetch)
    }

    pub fn probe_ranges(&self) -> Result<Vec<Extent>> {
        self.resolve_ranges(0, self.device_size, ResolveMode::Probe)
    }

    fn resolve_ranges(
        &self,
        device_offset: u64,
        len: u64,
        mode: ResolveMode,
    ) -> Result<Vec<Extent>> {
        ensure_device_range(self.device_size, device_offset, len)?;
        let end = device_offset
            .checked_add(len)
            .ok_or_else(|| Error::Overflow("device range overflow".to_string()))?;
        let mut ranges = Vec::new();

        let flat_end = end.min(self.core.flat_size());
        if device_offset < flat_end {
            let flat_ranges = match mode {
                ResolveMode::Fetch => self
                    .core
                    .fetch_flat_ranges(device_offset, flat_end - device_offset)?,
                ResolveMode::Probe => self
                    .core
                    .probe_flat_ranges(device_offset, flat_end - device_offset)?,
            };
            ranges.extend(flat_ranges);
        }

        let tail_start = device_offset.max(self.core.flat_size());
        if tail_start < end {
            ranges.push(Extent {
                fd: self.core.zero_fd(),
                offset: 0,
                len: end - tail_start,
                source_offset: tail_start,
            });
        }

        Ok(ranges)
    }
}

pub(crate) fn read_uffd_msg(uffd_fd: RawFd) -> io::Result<Option<UffdMsg>> {
    let mut msg = std::mem::MaybeUninit::<UffdMsg>::uninit();
    let n = unsafe {
        libc::read(
            uffd_fd,
            msg.as_mut_ptr() as *mut libc::c_void,
            std::mem::size_of::<UffdMsg>(),
        )
    };
    if n < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        return Err(err);
    }
    if n == 0 {
        return Ok(None);
    }
    if n as usize != std::mem::size_of::<UffdMsg>() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short uffd read",
        ));
    }
    Ok(Some(unsafe { msg.assume_init() }))
}

fn resolve_fault_range<'a>(
    regions: &'a [VmaRegion],
    msg: &UffdMsg,
) -> Result<Option<(&'a VmaRegion, DeviceRange)>> {
    if msg.event != UFFD_EVENT_PAGEFAULT {
        return Ok(None);
    }
    let fault_addr = msg.pagefault.address;
    let Some(region) = regions.iter().find(|region| {
        fault_addr >= region.virt_addr && fault_addr < region.virt_addr.saturating_add(region.size)
    }) else {
        return Ok(None);
    };

    let fault_size = region.fault_size.max(UFFD_BLOCK_SIZE);
    let fault_region_offset = fault_addr - region.virt_addr;
    let aligned_region_offset = (fault_region_offset / fault_size) * fault_size;
    let start = region
        .offset
        .checked_add(aligned_region_offset)
        .ok_or_else(|| Error::Overflow("uffd fault device offset overflow".to_string()))?;
    let region_end = region
        .offset
        .checked_add(region.size)
        .ok_or_else(|| Error::Overflow("uffd region end overflow".to_string()))?;
    let end = start.saturating_add(fault_size).min(region_end);
    if end <= start {
        return Ok(None);
    }

    Ok(Some((
        region,
        DeviceRange {
            offset: start,
            len: end - start,
        },
    )))
}

fn ensure_device_range(device_size: u64, offset: u64, len: u64) -> Result<()> {
    if len == 0 {
        return Err(Error::InvalidParameter(
            "device range length must be non-zero".to_string(),
        ));
    }
    if offset % UFFD_BLOCK_SIZE != 0 || len % UFFD_BLOCK_SIZE != 0 {
        return Err(Error::InvalidParameter(format!(
            "device range must be 4 KiB aligned: offset={offset} len={len}"
        )));
    }
    let end = offset
        .checked_add(len)
        .ok_or_else(|| Error::Overflow("device range overflow".to_string()))?;
    if end > device_size {
        return Err(Error::InvalidParameter(format!(
            "device range [{offset}, {end}) exceeds device size {device_size}"
        )));
    }
    Ok(())
}

fn uffdio_copy_from_fd(
    uffd_fd: RawFd,
    dst: u64,
    source_fd: RawFd,
    offset: u64,
    len: u64,
) -> Result<()> {
    let mut buf = vec![0u8; usize::try_from(len).map_err(|err| Error::Overflow(err.to_string()))?];
    let source_offset = libc::off_t::try_from(offset).map_err(|err| {
        Error::Overflow(format!(
            "uffd backing file offset exceeds the platform off_t range: {err}"
        ))
    })?;
    let read = unsafe {
        libc::pread(
            source_fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            source_offset,
        )
    };
    if read < 0 {
        return Err(io::Error::last_os_error()).context("failed to read file for UFFDIO_COPY");
    }
    if read as usize != buf.len() {
        return Err(Error::Runtime(format!(
            "short read from uffd backing file: expected {}, got {}",
            buf.len(),
            read
        )));
    }

    let source = buf.as_ptr() as u64;
    fill_missing_pages(uffd_fd, dst, len, |start, len| {
        let mut arg = UffdioCopy {
            dst: start,
            src: source + (start - dst),
            len,
            mode: 0,
            copy: 0,
        };
        // SAFETY: the argument outlives the call, and its source range lies
        // within `buf`, which is alive and at least `len` bytes from there.
        let ret = unsafe { libc::ioctl(uffd_fd, UFFDIO_COPY as IoctlRequest, &mut arg) };
        (ret, arg.copy)
    })
    .context("failed to copy pages into faulting range (UFFDIO_COPY)")
}

fn uffdio_zeropage(uffd_fd: RawFd, start: u64, len: u64) -> Result<()> {
    fill_missing_pages(uffd_fd, start, len, |start, len| {
        let mut arg = UffdioZeropage {
            range_start: start,
            range_len: len,
            mode: 0,
            zeropage: 0,
        };
        // SAFETY: the argument outlives the call.
        let ret = unsafe { libc::ioctl(uffd_fd, UFFDIO_ZEROPAGE as IoctlRequest, &mut arg) };
        (ret, arg.zeropage)
    })
    .context("failed to zero-fill faulting range (UFFDIO_ZEROPAGE)")
}

/// Fills the missing pages of `[start, start + len)` through `fill`, which
/// runs one `UFFDIO_COPY` or `UFFDIO_ZEROPAGE` over the range it is given and
/// returns the result of the ioctl with the bytes the kernel reports filled.
///
/// The kernel stops at the first page that is already there, one of a block
/// filled earlier and reclaimed in part since: it fails with `EEXIST` when
/// that is the first page of the request, and with `EAGAIN` and the bytes
/// filled when it comes later. The page holds what the fill would have put
/// there, so it is skipped, waking whoever still waits on it, and the fill
/// goes on behind it. `EAGAIN` without progress means the address space is
/// changing under the fill, which is tried again for a while.
fn fill_missing_pages(
    uffd_fd: RawFd,
    start: u64,
    len: u64,
    mut fill: impl FnMut(u64, u64) -> (libc::c_int, i64),
) -> io::Result<()> {
    let mut filled = 0;
    let mut busy_retries = 0;
    while filled < len {
        let (ret, progress) = fill(start + filled, len - filled);
        if ret == 0 {
            break;
        }

        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EAGAIN) if progress > 0 => filled += progress as u64,
            Some(libc::EEXIST) => {
                let mut range = UffdioRange {
                    start: start + filled,
                    len: UFFD_BLOCK_SIZE,
                };
                // SAFETY: the argument outlives the call. A failed wake
                // leaves nobody worse off than not trying.
                unsafe { libc::ioctl(uffd_fd, UFFDIO_WAKE as IoctlRequest, &mut range) };
                filled += UFFD_BLOCK_SIZE;
            }
            Some(libc::EAGAIN) if busy_retries < FILL_BUSY_RETRIES => {
                busy_retries += 1;
                std::thread::sleep(FILL_BUSY_INTERVAL);
            }
            _ => return Err(err),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    const PAGE: usize = UFFD_BLOCK_SIZE as usize;
    const UFFD_USER_MODE_ONLY: libc::c_int = 1;
    const UFFDIO_API: IoctlRequest = 0xc018aa3fu32 as IoctlRequest;
    const UFFDIO_REGISTER: IoctlRequest = 0xc020aa00u32 as IoctlRequest;

    /// `pages` of fresh memory whose missing pages a userfaultfd handles.
    struct Region {
        uffd: OwnedFd,
        addr: *mut u8,
        len: usize,
    }

    impl Region {
        /// Returns `None` where the kernel or its policy refuses a
        /// userfaultfd.
        fn new(pages: usize) -> Option<Self> {
            let open = |flags: libc::c_int| unsafe {
                libc::syscall(libc::SYS_userfaultfd, libc::O_CLOEXEC | flags) as libc::c_int
            };
            let mut fd = open(UFFD_USER_MODE_ONLY);
            if fd < 0 {
                fd = open(0);
            }
            if fd < 0 {
                return None;
            }
            let uffd = unsafe { OwnedFd::from_raw_fd(fd) };
            let mut api = [0xaau64, 0, 0];
            if unsafe { libc::ioctl(fd, UFFDIO_API as IoctlRequest, &mut api) } != 0 {
                return None;
            }

            let len = pages * PAGE;
            let addr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(addr, libc::MAP_FAILED);
            let mut register = [addr as u64, len as u64, 1, 0];
            assert_eq!(
                unsafe { libc::ioctl(fd, UFFDIO_REGISTER as IoctlRequest, &mut register) },
                0
            );
            Some(Self {
                uffd,
                addr: addr.cast(),
                len,
            })
        }

        fn page(&self, index: usize) -> u64 {
            self.addr as u64 + (index * PAGE) as u64
        }

        /// Returns which pages are there, without touching the missing ones.
        fn present(&self) -> Vec<bool> {
            let mut pages = vec![0u8; self.len / PAGE];
            assert_eq!(
                unsafe { libc::mincore(self.addr.cast(), self.len, pages.as_mut_ptr()) },
                0
            );
            pages.iter().map(|page| page & 1 == 1).collect()
        }

        fn bytes(&self) -> &[u8] {
            unsafe { std::slice::from_raw_parts(self.addr, self.len) }
        }
    }

    impl Drop for Region {
        fn drop(&mut self) {
            unsafe { libc::munmap(self.addr.cast(), self.len) };
        }
    }

    #[test]
    fn fills_skip_the_pages_that_are_already_there() {
        let mut file = tempfile::tempfile().unwrap();
        let content: Vec<u8> = (0..4u8).flat_map(|page| [page + 1; PAGE]).collect();
        file.write_all(&content).unwrap();
        let test_cases = vec![
            vec![0],
            vec![1],
            vec![3],
            vec![0, 2],
            vec![0, 1, 2, 3],
            vec![],
        ];

        for there in test_cases {
            let Some(copied) = Region::new(4) else {
                return;
            };
            let zeroed = Region::new(4).unwrap();
            for &index in &there {
                let offset = (index * PAGE) as u64;
                let uffd = copied.uffd.as_raw_fd();
                uffdio_copy_from_fd(uffd, copied.page(index), file.as_raw_fd(), offset, 4096)
                    .unwrap();
                uffdio_zeropage(zeroed.uffd.as_raw_fd(), zeroed.page(index), 4096).unwrap();
            }

            let len = content.len() as u64;
            uffdio_copy_from_fd(
                copied.uffd.as_raw_fd(),
                copied.page(0),
                file.as_raw_fd(),
                0,
                len,
            )
            .unwrap();
            uffdio_zeropage(zeroed.uffd.as_raw_fd(), zeroed.page(0), len).unwrap();

            assert_eq!(copied.present(), vec![true; 4], "{there:?}");
            assert_eq!(zeroed.present(), vec![true; 4], "{there:?}");
            assert_eq!(copied.bytes(), content, "{there:?}");
            assert!(zeroed.bytes().iter().all(|byte| *byte == 0), "{there:?}");
        }
    }

    #[test]
    fn fills_fail_on_a_range_the_userfaultfd_does_not_handle() {
        let Some(region) = Region::new(1) else {
            return;
        };
        let outside = region.page(0) + (16 * PAGE) as u64;
        assert!(uffdio_zeropage(region.uffd.as_raw_fd(), outside, 4096).is_err());
    }
}
