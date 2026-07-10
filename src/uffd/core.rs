use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};

use crate::{BlobID, Config, LeptonAccessor};

pub use super::proto::ResolvedRange;
use super::proto::{DeviceRange, FaultPolicy, VmaRegion};

pub const UFFD_BLOCK_SIZE: u64 = 4096;
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

#[derive(Clone, Debug)]
pub struct UffdOptions {
    pub bootstrap: PathBuf,
    pub config: Config,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DevicePartKind {
    Bootstrap,
    Blob { blob_id: BlobID },
}

#[derive(Debug)]
struct DevicePart {
    kind: DevicePartKind,
    device_offset: u64,
    len: u64,
    file: Arc<File>,
}

impl DevicePart {
    fn end(&self) -> u64 {
        self.device_offset + self.len
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Segment {
    Data {
        part_index: usize,
        file_offset: u64,
        device_offset: u64,
        len: u64,
    },
    Hole {
        device_offset: u64,
        len: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResolveMode {
    Fetch,
    Probe,
}

pub struct UffdCore {
    accessor: Arc<LeptonAccessor>,
    parts: Vec<DevicePart>,
    total_size: u64,
    zero_file: Arc<File>,
}

impl UffdCore {
    pub fn new(options: UffdOptions) -> Result<Self> {
        let bootstrap_file = Arc::new(
            OpenOptions::new()
                .read(true)
                .open(&options.bootstrap)
                .with_context(|| {
                    format!("failed to open bootstrap {}", options.bootstrap.display())
                })?,
        );
        let bootstrap_len = bootstrap_file
            .metadata()
            .context("failed to stat bootstrap")?
            .len();
        let accessor = Arc::new(
            LeptonAccessor::new(&options.bootstrap, options.config)
                .context("failed to create lepton accessor")?,
        );
        let zero_file = Arc::new(
            OpenOptions::new()
                .read(true)
                .open("/dev/zero")
                .context("failed to open /dev/zero")?,
        );

        let mut parts = vec![DevicePart {
            kind: DevicePartKind::Bootstrap,
            device_offset: 0,
            len: bootstrap_len,
            file: bootstrap_file,
        }];
        for blob in accessor.blob.entries()? {
            if blob.is_redirect {
                continue;
            }
            let file = Arc::new(
                OpenOptions::new()
                    .read(true)
                    .open(&blob.cache_path)
                    .with_context(|| {
                        format!("failed to open cache file {}", blob.cache_path.display())
                    })?,
            );
            let device_offset = blob.mapped_offset;
            parts.push(DevicePart {
                kind: DevicePartKind::Blob { blob_id: blob.id },
                device_offset,
                len: blob.cache_size,
                file,
            });
        }

        let (parts, total_size) = finalize_device_layout(parts)?;

        Ok(Self {
            accessor,
            parts,
            total_size,
            zero_file,
        })
    }

    pub fn total_size(&self) -> u64 {
        self.total_size
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
    ) -> Result<Vec<ResolvedRange>> {
        let Some((region, range)) = fault_device_range(regions, msg)? else {
            return Ok(Vec::new());
        };
        let ranges = self.fetch_ranges(range.offset, range.len)?;

        match policy {
            FaultPolicy::Zerocopy => Ok(ranges),
            FaultPolicy::Copy => {
                for range in ranges {
                    let addr = region.base_host_virt_addr + (range.device_offset - region.offset);
                    if range.fd == self.zero_file.as_raw_fd() {
                        uffdio_zeropage(uffd_fd, addr, range.len)?;
                    } else {
                        uffdio_copy_from_fd(uffd_fd, addr, range.fd, range.file_offset, range.len)?;
                    }
                }
                Ok(Vec::new())
            }
        }
    }

    pub fn prefault_ranges(&self, regions: &[VmaRegion]) -> Result<Vec<ResolvedRange>> {
        let mut ranges = Vec::new();
        for region in regions {
            let start = region.offset;
            let end = region
                .offset
                .saturating_add(region.size)
                .min(self.total_size);
            if end <= start {
                continue;
            }
            ranges.extend(self.resolve_ranges(start, end - start, ResolveMode::Probe)?);
        }
        Ok(ranges)
    }

    pub fn fetch_ranges(&self, device_offset: u64, len: u64) -> Result<Vec<ResolvedRange>> {
        self.resolve_ranges(device_offset, len, ResolveMode::Fetch)
    }

    pub fn probe_ranges(&self) -> Result<Vec<ResolvedRange>> {
        self.resolve_ranges(0, self.total_size, ResolveMode::Probe)
    }

    fn resolve_ranges(
        &self,
        device_offset: u64,
        len: u64,
        mode: ResolveMode,
    ) -> Result<Vec<ResolvedRange>> {
        validate_device_range(self.total_size, device_offset, len)?;
        let mut ranges = Vec::new();
        for segment in split_range(&self.parts, self.total_size, device_offset, len)? {
            match segment {
                Segment::Hole { device_offset, len } => self.push_range(
                    &mut ranges,
                    ResolvedRange {
                        fd: self.zero_file.as_raw_fd(),
                        file_offset: 0,
                        len,
                        device_offset,
                    },
                ),
                Segment::Data {
                    part_index,
                    file_offset,
                    device_offset,
                    len,
                } => {
                    let part = &self.parts[part_index];
                    match part.kind {
                        DevicePartKind::Bootstrap => self.push_range(
                            &mut ranges,
                            ResolvedRange {
                                fd: part.file.as_raw_fd(),
                                file_offset,
                                len,
                                device_offset,
                            },
                        ),
                        DevicePartKind::Blob { blob_id } => match mode {
                            ResolveMode::Fetch => {
                                self.accessor
                                    .blob
                                    .fetch(
                                        &blob_id,
                                        align_down(file_offset),
                                        align_len(file_offset, len)?,
                                    )
                                    .context("failed to fetch lepton blob range")?;
                                self.push_range(
                                    &mut ranges,
                                    ResolvedRange {
                                        fd: part.file.as_raw_fd(),
                                        file_offset,
                                        len,
                                        device_offset,
                                    },
                                );
                            }
                            ResolveMode::Probe => {
                                for ready in
                                    self.accessor
                                        .blob
                                        .ready_ranges(&blob_id, file_offset, len)?
                                {
                                    self.push_range(
                                        &mut ranges,
                                        ResolvedRange {
                                            fd: part.file.as_raw_fd(),
                                            file_offset: ready.start,
                                            len: ready.end - ready.start,
                                            device_offset: part.device_offset + ready.start,
                                        },
                                    );
                                }
                            }
                        },
                    }
                }
            }
        }
        Ok(ranges)
    }

    fn push_range(&self, ranges: &mut Vec<ResolvedRange>, range: ResolvedRange) {
        if let Some(last) = ranges.last_mut() {
            let device_contiguous = last.device_offset + last.len == range.device_offset;
            let file_contiguous = last.file_offset + last.len == range.file_offset;
            let both_zero = last.fd == self.zero_file.as_raw_fd()
                && range.fd == self.zero_file.as_raw_fd()
                && last.file_offset == 0
                && range.file_offset == 0;
            if last.fd == range.fd && device_contiguous && (file_contiguous || both_zero) {
                last.len += range.len;
                return;
            }
        }
        ranges.push(range);
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

fn finalize_device_layout(mut parts: Vec<DevicePart>) -> Result<(Vec<DevicePart>, u64)> {
    let mut total_size = 0;
    for part in &parts {
        total_size = total_size.max(
            part.device_offset
                .checked_add(part.len)
                .ok_or_else(|| anyhow!("lepton device part range overflow"))?,
        );
    }

    parts.sort_by_key(|part| part.device_offset);
    for pair in parts.windows(2) {
        let previous = &pair[0];
        let next = &pair[1];
        if previous.end() > next.device_offset {
            bail!(
                "overlapping lepton device parts: {:?} [{:#x}, {:#x}) and {:?} [{:#x}, {:#x})",
                previous.kind,
                previous.device_offset,
                previous.end(),
                next.kind,
                next.device_offset,
                next.end()
            );
        }
    }

    Ok((parts, align_up(total_size, UFFD_TOTAL_SIZE_ALIGNMENT)?))
}

fn fault_device_range<'a>(
    regions: &'a [VmaRegion],
    msg: &UffdMsg,
) -> Result<Option<(&'a VmaRegion, DeviceRange)>> {
    if msg.event != UFFD_EVENT_PAGEFAULT {
        return Ok(None);
    }
    let fault_addr = msg.pagefault.address;
    let Some(region) = regions.iter().find(|region| {
        fault_addr >= region.base_host_virt_addr
            && fault_addr < region.base_host_virt_addr.saturating_add(region.size)
    }) else {
        return Ok(None);
    };

    let page_size = region.page_size.max(UFFD_BLOCK_SIZE);
    let fault_region_offset = fault_addr - region.base_host_virt_addr;
    let aligned_region_offset = (fault_region_offset / page_size) * page_size;
    let start = region
        .offset
        .checked_add(aligned_region_offset)
        .ok_or_else(|| anyhow!("UFFD fault device offset overflow"))?;
    let region_end = region
        .offset
        .checked_add(region.size)
        .ok_or_else(|| anyhow!("UFFD region end overflow"))?;
    let end = start.saturating_add(page_size).min(region_end);
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

fn validate_device_range(total_size: u64, offset: u64, len: u64) -> Result<()> {
    if len == 0 {
        bail!("device range length must be non-zero");
    }
    if offset % UFFD_BLOCK_SIZE != 0 || len % UFFD_BLOCK_SIZE != 0 {
        bail!("device range must be 4 KiB aligned: offset={offset} len={len}");
    }
    let end = offset
        .checked_add(len)
        .ok_or_else(|| anyhow!("device range overflow"))?;
    if end > total_size {
        bail!("device range [{offset}, {end}) exceeds device size {total_size}");
    }
    Ok(())
}

fn split_range(
    parts: &[DevicePart],
    total_size: u64,
    offset: u64,
    len: u64,
) -> Result<Vec<Segment>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let end = offset
        .checked_add(len)
        .ok_or_else(|| anyhow!("range overflow"))?;
    let mut pos = offset;
    let mut segments = Vec::new();

    while pos < end {
        let part_index = parts
            .iter()
            .position(|part| pos >= part.device_offset && pos < part.end());
        if let Some(part_index) = part_index {
            let part = &parts[part_index];
            let seg_end = end.min(part.end());
            segments.push(Segment::Data {
                part_index,
                file_offset: pos - part.device_offset,
                device_offset: pos,
                len: seg_end - pos,
            });
            pos = seg_end;
        } else {
            let next_part = parts
                .iter()
                .filter(|part| part.device_offset > pos)
                .map(|part| part.device_offset)
                .min()
                .unwrap_or(total_size);
            let hole_end = end.min(next_part).min(total_size);
            if hole_end <= pos {
                break;
            }
            segments.push(Segment::Hole {
                device_offset: pos,
                len: hole_end - pos,
            });
            pos = hole_end;
        }
    }

    if pos < end {
        segments.push(Segment::Hole {
            device_offset: pos,
            len: end - pos,
        });
    }
    Ok(segments)
}

fn uffdio_copy_from_fd(
    uffd_fd: RawFd,
    dst: u64,
    source_fd: RawFd,
    offset: u64,
    len: u64,
) -> Result<()> {
    let mut buf = vec![0u8; usize::try_from(len)?];
    let source_offset = libc::off_t::try_from(offset)
        .context("UFFD backing file offset exceeds the platform off_t range")?;
    let read = unsafe {
        libc::pread(
            source_fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            source_offset,
        )
    };
    if read < 0 {
        bail!(
            "failed to read file for UFFDIO_COPY: {}",
            io::Error::last_os_error()
        );
    }
    if read as usize != buf.len() {
        bail!(
            "short read from UFFD backing file: expected {}, got {}",
            buf.len(),
            read
        );
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
        bail!("UFFDIO_COPY failed: {}", io::Error::last_os_error());
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
        bail!("UFFDIO_ZEROPAGE failed: {err}");
    }
    Ok(())
}

fn align_up(value: u64, alignment: u64) -> Result<u64> {
    Ok(value
        .checked_add(alignment - 1)
        .ok_or_else(|| anyhow!("alignment overflow"))?
        & !(alignment - 1))
}

fn align_down(value: u64) -> u64 {
    value & !(UFFD_BLOCK_SIZE - 1)
}

fn align_len(offset: u64, len: u64) -> Result<u64> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| anyhow!("range overflow"))?;
    Ok(align_up(end, UFFD_BLOCK_SIZE)? - align_down(offset))
}
