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
pub(crate) const UFFDIO_COPY: IoctlRequest = 0xc028aa03u32 as IoctlRequest;
pub(crate) const UFFDIO_ZEROPAGE: IoctlRequest = 0xc020aa04u32 as IoctlRequest;

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
        let core = Arc::new(NydusCore::new(bootstrap, config)?);
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

    let mut arg = UffdioCopy {
        dst,
        src: buf.as_ptr() as u64,
        len,
        mode: 0,
        copy: 0,
    };
    let ret = unsafe { libc::ioctl(uffd_fd, UFFDIO_COPY as IoctlRequest, &mut arg) };
    if ret < 0 {
        return Err(io::Error::last_os_error())
            .context("failed to copy pages into faulting range (UFFDIO_COPY)");
    }
    Ok(())
}

fn uffdio_zeropage(uffd_fd: RawFd, start: u64, len: u64) -> Result<()> {
    if len == 0 {
        return Ok(());
    }
    let mut arg = UffdioZeropage {
        range_start: start,
        range_len: len,
        mode: 0,
        zeropage: 0,
    };
    let ret = unsafe { libc::ioctl(uffd_fd, UFFDIO_ZEROPAGE as IoctlRequest, &mut arg) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EEXIST) {
            return Ok(());
        }
        return Err(err).context("failed to zero-fill faulting range (UFFDIO_ZEROPAGE)");
    }
    Ok(())
}
