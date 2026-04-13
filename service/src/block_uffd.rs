// Copyright (C) 2026 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0)

//! Export a RAFSv6 image as a block device through userfaultfd (uffd) protocol.
//!
//! The UffdService provides a way to handle page faults for a RAFSv6 image via
//! userfaultfd. Clients connect to the unix socket and send:
//! - uffd file descriptor (via SCM_RIGHTS)
//! - VMA (Virtual Memory Area) information about the memory region to monitor
//!
//! When a page fault occurs, the service responds with blob fds and range metadata
//! (len, blob_offset, block_offset) so the client can mmap the data directly (zero-copy).
//!
//! This module provides two integration modes:
//!
//! **Daemon mode** (`UffdService` / `UffdDaemon`): A standalone Unix-domain-socket
//! server. Clients connect, send a uffd fd + VMA regions via SCM_RIGHTS, and the
//! server resolves page faults asynchronously over the socket.
//!
//! **Builtin mode** (`UffdCore`): An embeddable library. The consumer creates the
//! userfaultfd, mmaps the region, and calls `UffdCore::handle_page_fault` directly
//! in-process — no socket, no protocol overhead.
//!
//! Protocol (JSON + fd format, Firecracker compatible):
//! - [Handshake] JSON HandshakeRequest + SCM_RIGHTS (uffd fds)
//! - [Page Fault Response] JSON PageFaultResponse + SCM_RIGHTS (blob fds)
//! - [Stat Request] JSON StatRequest
//! - [Stat Response] JSON StatResponse

use std::any::Any;
use std::io::{Error, Result};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use flume;
use mio::Waker;
use nydus_api::{BlobCacheEntry, BuildTimeInfo};
use nydus_storage::utils::alloc_buf;
use sendfd::{RecvWithFd, SendWithFd};
use tokio::io::unix::AsyncFd;
use tokio::sync::broadcast::Sender;
use tokio::task::spawn_blocking;

use crate::blob_cache::{generate_blob_key, BlobCacheMgr};
use crate::block_device::BlockDevice;
use crate::daemon::{
    DaemonState, DaemonStateMachineContext, DaemonStateMachineInput, DaemonStateMachineSubscriber,
    NydusDaemon,
};
use crate::{Error as NydusError, Result as NydusResult};

use super::uffd_proto::*;

// ---------------------------------------------------------------------------
// UFFD kernel ABI constants
// ---------------------------------------------------------------------------

/// UFFD event type for page fault (from linux/userfaultfd.h).
pub const UFFD_EVENT_PAGEFAULT: u8 = 0x12;

/// Maximum number of ranges (and fds) per message.
const MAX_RANGES_PER_MSG: usize = 16;

/// Maximum receive buffer size for socket messages.
const RECV_BUF_SIZE: usize = 4096;

// UFFDIO ioctl definitions (from linux/userfaultfd.h).
pub(crate) const UFFDIO_COPY: libc::Ioctl = 0xc028aa03u32 as libc::Ioctl;
pub(crate) const UFFDIO_ZEROPAGE: libc::Ioctl = 0xc020aa04u32 as libc::Ioctl;
#[allow(dead_code)]
pub(crate) const UFFDIO_WAKE: libc::Ioctl = 0x8010aa02u32 as libc::Ioctl;

// ---------------------------------------------------------------------------
// Kernel ABI structs
// ---------------------------------------------------------------------------

/// Kernel uffd_msg struct layout (from linux/userfaultfd.h).
#[repr(C)]
pub struct UffdMsg {
    pub event: u8,
    _reserved1: [u8; 3],
    _reserved2: u32,
    /// Union field for UFFD_EVENT_PAGEFAULT
    pub pagefault: UffdPagefault,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UffdPagefault {
    pub flags: u64,
    pub address: u64,
    pub feat: u64,
}

#[repr(C)]
pub(crate) struct UffdioCopy {
    dst: u64,
    src: u64,
    len: u64,
    mode: u64,
    copy: i64,
}

#[repr(C)]
pub(crate) struct UffdioZeropage {
    range_start: u64,
    range_len: u64,
    mode: u64,
    zeropage: i64,
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Result of resolving a zerocopy page fault.
/// Data ranges must be delivered by the caller (socket for daemon, mmap for builtin).
/// Holes have already been zeroed via UFFDIO_ZEROPAGE.
#[derive(Debug)]
pub struct ZerocopyResult {
    /// (blob_fd, blob_offset, len, block_offset)
    pub ranges: Vec<(RawFd, u64, usize, u64)>,
}

/// Result of handling a single uffd page fault event.
#[derive(Debug)]
pub enum PageFaultResult {
    /// Zerocopy: data ranges need delivery by the caller.
    Zerocopy(ZerocopyResult),
    /// Copy: UFFDIO_COPY already performed.
    Copy,
    /// Not a page-fault event, or address not in any VMA region.
    Noop,
}

// ---------------------------------------------------------------------------
// Low-level UFFDIO functions
// ---------------------------------------------------------------------------

/// Read a `uffd_msg` from a non-blocking uffd fd.
/// Returns `Ok(None)` if no event is available (WouldBlock).
/// Returns `Ok(Some(msg))` on successful read.
pub fn read_uffd_msg(uffd_fd: RawFd) -> Result<Option<UffdMsg>> {
    let mut msg = std::mem::MaybeUninit::<UffdMsg>::uninit();
    let n = unsafe {
        libc::read(
            uffd_fd,
            msg.as_mut_ptr() as *mut libc::c_void,
            std::mem::size_of::<UffdMsg>(),
        )
    };

    if n < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        return Err(eother!(format!("uffd read failed: {}", err)));
    }
    if (n as usize) < std::mem::size_of::<UffdMsg>() {
        return Err(eother!(format!("uffd short read: {n} bytes")));
    }

    Ok(Some(unsafe { msg.assume_init() }))
}

/// Perform UFFDIO_ZEROPAGE ioctl asynchronously.
pub async fn uffdio_zeropage(uffd_fd: RawFd, start_addr: u64, len: u64) -> Result<()> {
    spawn_blocking(move || {
        let mut ioctl_arg = UffdioZeropage {
            range_start: start_addr,
            range_len: len,
            mode: 0,
            zeropage: 0,
        };
        let ret = unsafe { libc::ioctl(uffd_fd, UFFDIO_ZEROPAGE, &mut ioctl_arg) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EEXIST) {
                return Ok(());
            }
            return Err(eother!(format!("UFFDIO_ZEROPAGE failed: {}", err)));
        }
        Ok(())
    })
    .await
    .map_err(|e| eother!(format!("join error: {e}")))?
}

/// Perform UFFDIO_COPY ioctl asynchronously.
/// `buf` holds the source data; ownership is transferred to ensure the buffer
/// lives until the ioctl completes inside `spawn_blocking`.
pub async fn uffdio_copy(uffd_fd: RawFd, dst: u64, buf: Vec<u8>, len: u64) -> Result<()> {
    spawn_blocking(move || {
        let src = buf.as_ptr() as u64;
        let mut ioctl_arg = UffdioCopy {
            dst,
            src,
            len,
            mode: 0,
            copy: 0,
        };
        let ret = unsafe { libc::ioctl(uffd_fd, UFFDIO_COPY, &mut ioctl_arg) };
        if ret < 0 {
            return Err(eother!(format!(
                "UFFDIO_COPY failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    })
    .await
    .map_err(|e| eother!(format!("join error: {e}")))?
}

/// Perform UFFDIO_WAKE ioctl asynchronously.
#[allow(dead_code)]
pub async fn uffdio_wake(uffd_fd: RawFd, start_addr: u64, len: u64) -> Result<()> {
    spawn_blocking(move || {
        #[repr(C)]
        struct UffdioRange {
            start: u64,
            len: u64,
        }
        let mut range = UffdioRange {
            start: start_addr,
            len,
        };
        let ret = unsafe { libc::ioctl(uffd_fd, UFFDIO_WAKE, &mut range) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EEXIST) {
                return Ok(());
            }
            return Err(eother!(format!("UFFDIO_WAKE failed: {}", err)));
        }
        Ok(())
    })
    .await
    .map_err(|e| eother!(format!("join error: {e}")))?
}

// ---------------------------------------------------------------------------
// UffdCore — page fault resolution engine
// ---------------------------------------------------------------------------

/// Core UFFD page fault resolution engine.
///
/// Holds a `BlockDevice` reference and provides methods to resolve page faults.
/// Must be used within a tokio_uring runtime (BlockDevice is !Send).
pub struct UffdCore {
    device: Arc<BlockDevice>,
    device_size: u64,
    block_size: u64,
}

impl UffdCore {
    pub fn new(device: Arc<BlockDevice>) -> Self {
        let device_size = device.blocks_to_size(device.blocks());
        let block_size = device.block_size();
        UffdCore {
            device,
            device_size,
            block_size,
        }
    }

    /// Access the underlying BlockDevice.
    pub fn device(&self) -> &Arc<BlockDevice> {
        &self.device
    }

    /// Handle a single uffd page fault event.
    ///
    /// - Copy policy: performs UFFDIO_COPY directly.
    /// - Zerocopy policy: zeroes holes via UFFDIO_ZEROPAGE, returns data ranges
    ///   for the caller to deliver.
    /// - Beyond-device regions: zeroed via UFFDIO_ZEROPAGE.
    pub async fn handle_page_fault(
        &self,
        msg: &UffdMsg,
        vma_regions: &[VmaRegion],
        policy: FaultPolicy,
        uffd_fd: RawFd,
    ) -> Result<PageFaultResult> {
        if msg.event != UFFD_EVENT_PAGEFAULT {
            warn!("uffd_core: unexpected uffd event: {}", msg.event);
            return Ok(PageFaultResult::Noop);
        }

        let fault_addr = msg.pagefault.address;
        debug!(
            "uffd_core: page fault at 0x{:x}, policy {:?}",
            fault_addr, policy
        );

        let vma_region = match vma_regions.iter().find(|v| {
            fault_addr >= v.base_host_virt_addr
                && fault_addr < v.base_host_virt_addr + v.size as u64
        }) {
            Some(v) => v,
            None => {
                warn!("uffd_core: fault addr 0x{:x} not in any VMA", fault_addr);
                return Ok(PageFaultResult::Noop);
            }
        };

        let fetch_size = vma_region.page_size as u64;
        let fault_block_offset = vma_region.offset + (fault_addr - vma_region.base_host_virt_addr);
        let region_offset_end = vma_region.offset + vma_region.size as u64;
        let aligned_start = (fault_block_offset / fetch_size) * fetch_size;
        let fetch_start = std::cmp::max(aligned_start, vma_region.offset);
        let fetch_end = std::cmp::min(fetch_start + fetch_size, region_offset_end);

        // Handle range beyond device bounds with UFFDIO_ZEROPAGE.
        if fetch_end > self.device_size {
            let zero_start = std::cmp::max(fetch_start, self.device_size);
            let zero_len = fetch_end - zero_start;
            let zero_addr = vma_region.base_host_virt_addr + (zero_start - vma_region.offset);
            uffdio_zeropage(uffd_fd, zero_addr, zero_len).await?;
        }

        match policy {
            FaultPolicy::Zerocopy => {
                let mut all_ranges: Vec<(RawFd, u64, usize, u64)> = Vec::new();

                if fetch_start < self.device_size {
                    let data_end = std::cmp::min(fetch_end, self.device_size);
                    let data_len = data_end - fetch_start;
                    let result = self
                        .resolve_zerocopy_ranges(fetch_start, data_len, vma_region, uffd_fd)
                        .await?;
                    all_ranges.extend(result.ranges);
                }

                Ok(PageFaultResult::Zerocopy(ZerocopyResult {
                    ranges: all_ranges,
                }))
            }
            FaultPolicy::Copy => {
                if fetch_start < self.device_size {
                    let data_end = std::cmp::min(fetch_end, self.device_size);
                    let data_len = data_end - fetch_start;
                    let data_addr =
                        vma_region.base_host_virt_addr + (fetch_start - vma_region.offset);
                    self.resolve_copy(fetch_start, data_len, data_addr, uffd_fd)
                        .await?;
                }

                Ok(PageFaultResult::Copy)
            }
        }
    }

    /// Resolve zerocopy ranges for a sub-range within device bounds.
    pub async fn resolve_zerocopy_ranges(
        &self,
        block_offset: u64,
        len: u64,
        vma_region: &VmaRegion,
        uffd_fd: RawFd,
    ) -> Result<ZerocopyResult> {
        let start_block = (block_offset / self.block_size) as u32;
        let num_blocks = len.div_ceil(self.block_size) as u32;
        let ranges = self
            .device
            .fetch_ranges(start_block, num_blocks, false)
            .await?;

        if ranges.is_empty() {
            let target_addr = vma_region.base_host_virt_addr + (block_offset - vma_region.offset);
            uffdio_zeropage(uffd_fd, target_addr, len).await?;
            return Ok(ZerocopyResult { ranges: Vec::new() });
        }

        let mut current_offset = block_offset;
        let end_offset = block_offset + len;
        let mut data_ranges: Vec<(RawFd, u64, usize, u64)> = Vec::new();

        for (blob_fd, blob_offset, blob_len, range_offset) in ranges {
            if range_offset > current_offset {
                let hole_len = range_offset - current_offset;
                let target_addr =
                    vma_region.base_host_virt_addr + (current_offset - vma_region.offset);
                uffdio_zeropage(uffd_fd, target_addr, hole_len).await?;
            }

            if blob_len > 0 && range_offset < end_offset {
                let actual_len =
                    std::cmp::min(range_offset + blob_len as u64, end_offset) - range_offset;
                data_ranges.push((blob_fd, blob_offset, actual_len as usize, range_offset));
                current_offset = range_offset + actual_len;
            }
        }

        if current_offset < end_offset {
            let hole_len = end_offset - current_offset;
            let target_addr = vma_region.base_host_virt_addr + (current_offset - vma_region.offset);
            uffdio_zeropage(uffd_fd, target_addr, hole_len).await?;
        }

        Ok(ZerocopyResult {
            ranges: data_ranges,
        })
    }

    /// Resolve a range using copy mode: async_read + UFFDIO_COPY.
    pub async fn resolve_copy(
        &self,
        block_offset: u64,
        len: u64,
        target_addr: u64,
        uffd_fd: RawFd,
    ) -> Result<()> {
        let start_block = (block_offset / self.block_size) as u32;
        let num_blocks = len.div_ceil(self.block_size) as u32;

        let read_len = num_blocks as usize * self.block_size as usize;
        let buf = alloc_buf(read_len);
        let (res, buf) = self.device.async_read(start_block, num_blocks, buf).await;
        let bytes_read = res.map_err(|e| eother!(format!("async_read failed: {}", e)))?;
        if bytes_read != read_len {
            return Err(eother!(format!(
                "read {} bytes, expected {}",
                bytes_read, read_len
            )));
        }

        uffdio_copy(uffd_fd, target_addr, buf, len).await
    }

    /// Probe already-cached ranges for prefaulting (probe_only=true).
    pub async fn prefault_ranges(
        &self,
        vma_regions: &[VmaRegion],
    ) -> Result<Vec<(RawFd, u64, usize, u64)>> {
        let mut all_ranges: Vec<(RawFd, u64, usize, u64)> = Vec::new();

        for vma_region in vma_regions.iter() {
            let region_start = vma_region.offset;
            let region_end = vma_region.offset + vma_region.size as u64;
            if region_start >= self.device_size {
                continue;
            }

            let effective_end = std::cmp::min(region_end, self.device_size);
            let start_block = (region_start / self.block_size) as u32;
            let num_blocks = (effective_end - region_start).div_ceil(self.block_size) as u32;

            let ranges = match self
                .device
                .fetch_ranges(start_block, num_blocks, true)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    warn!("uffd_core: pre-fault fetch_ranges failed: {}", e);
                    continue;
                }
            };

            for (blob_fd, blob_offset, blob_len, block_offset) in ranges {
                if blob_len == 0 {
                    continue;
                }
                all_ranges.push((blob_fd, blob_offset, blob_len, block_offset));
            }
        }

        Ok(all_ranges)
    }
}

/// Connection state after handshake.
struct ConnState {
    vma_regions: Vec<VmaRegion>,
    policy: FaultPolicy,
    uffd_async: AsyncFd<OwnedFd>,
}

/// A worker to handle uffd connections in asynchronous mode.
struct UffdWorker {
    active: Arc<AtomicBool>,
    active_conns: Arc<Mutex<Vec<RawFd>>>,
    blob_id: String,
    cache_mgr: Arc<BlobCacheMgr>,
    conn_receiver: flume::Receiver<StdUnixStream>,
    sender: Arc<Sender<u32>>,
    name: String,
}

// BlockDevice uses tokio-uring (single-threaded) and is not Send+Sync,
// but Arc is needed for sharing across async tasks within the same thread.
#[allow(clippy::arc_with_non_send_sync)]
impl UffdWorker {
    async fn run(self) {
        info!("block_uffd: worker {} start", self.name);

        let device =
            match BlockDevice::new_with_cache_manager(self.blob_id.clone(), self.cache_mgr.clone())
            {
                Ok(v) => Arc::new(v),
                Err(e) => {
                    error!(
                        "block_uffd: worker {} failed to create block device: {}",
                        self.name, e
                    );
                    return;
                }
            };

        let mut receiver = self.sender.subscribe();
        loop {
            if !self.active.load(Ordering::Acquire) {
                break;
            }
            tokio::select! {
                Ok(stream) = self.conn_receiver.recv_async() => {
                    stream.set_nonblocking(true).expect("failed to set nonblocking");
                    let active = self.active.clone();
                    let active_conns = self.active_conns.clone();
                    let device = device.clone();
                    let sender = self.sender.clone();
                    tokio_uring::spawn(async move {
                        if let Err(e) = Self::handle_conn(active, active_conns, device, stream, sender).await {
                            warn!("block_uffd: connection handler exited with error: {e}");
                        }
                    });
                }
                _ = receiver.recv() => break,
            }
        }

        info!("block_uffd: worker {} exit!", self.name);
    }

    /// Run the event loop to handle uffd requests in asynchronous mode.
    async fn handle_conn(
        active: Arc<AtomicBool>,
        active_conns: Arc<Mutex<Vec<RawFd>>>,
        device: Arc<BlockDevice>,
        stream: StdUnixStream,
        sender: Arc<Sender<u32>>,
    ) -> Result<()> {
        let fd = stream.as_raw_fd();
        info!("block_uffd: conn {} start!", fd);

        // Register fd so stop() can shutdown this socket.
        active_conns.lock().unwrap().push(fd);

        let sock_async = AsyncFd::new(stream)
            .map_err(|e| eother!(format!("Failed to create AsyncFd for sock: {}", e)))?;

        let mut receiver = sender.subscribe();
        let device_size = device.blocks_to_size(device.blocks());
        let block_size = device.block_size();
        let core = UffdCore::new(device);
        let mut conn_state: Option<ConnState> = None;
        while active.load(Ordering::Acquire) {
            tokio::select! {
                res = sock_async.readable() => {
                    let mut guard = res.map_err(|e| eother!(format!("sock readable: {e}")))?;
                    let msg = Self::try_recv_from_sock(guard.get_inner());
                    guard.clear_ready();
                    match msg {
                        Ok(None) => continue,
                        Err(e) => {
                            warn!("block_uffd: sock recv error: {e}");
                            break;
                        }
                        Ok(Some((json_val, fds, msg_type))) => {
                            Self::dispatch_message(
                                msg_type, json_val, &fds,
                                &sock_async, &core, &mut conn_state,
                                device_size, block_size,
                            ).await?;
                        }
                    }
                }

                res = async {
                    if let Some(ref state) = conn_state {
                        state.uffd_async.readable().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    let mut guard = res.map_err(|e| eother!(format!("uffd readable: {e}")))?;
                    let state = conn_state.as_ref().unwrap();
                    if let Err(e) = Self::handle_uffd_event(state, &core, &sock_async).await {
                        warn!("block_uffd: failed to handle page fault: {e}");
                    }
                    guard.clear_ready();
                }

                _ = receiver.recv() => {
                    info!("block_uffd: conn receive exit signal");
                    break;
                }
            }
        }

        // Unregister fd.
        active_conns.lock().unwrap().retain(|&f| f != fd);
        info!("block_uffd: conn {} exit!", fd);

        Ok(())
    }

    /// Dispatch a received message by type.
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_message(
        msg_type: MessageType,
        json_val: serde_json::Value,
        fds: &[RawFd],
        sock_async: &AsyncFd<StdUnixStream>,
        core: &UffdCore,
        conn_state: &mut Option<ConnState>,
        device_size: u64,
        block_size: u64,
    ) -> Result<()> {
        match msg_type {
            MessageType::Handshake => {
                if conn_state.is_some() {
                    warn!("block_uffd: received handshake but already handshaked");
                    return Ok(());
                }
                *conn_state = Some(Self::handle_handshake(json_val, fds, sock_async, core)?);
            }
            MessageType::Stat => {
                Self::handle_stat_request(sock_async, device_size, block_size).await?;
            }
            other => {
                warn!("block_uffd: unexpected message type: {other:?}");
            }
        }
        Ok(())
    }

    /// Handle handshake request from client. Returns ConnState on success.
    /// Also accepts Firecracker-compatible bare array of regions.
    fn handle_handshake(
        json_val: serde_json::Value,
        fds: &[RawFd],
        sock_async: &AsyncFd<StdUnixStream>,
        core: &UffdCore,
    ) -> Result<ConnState> {
        let request: HandshakeRequest = if json_val.is_array() {
            // Firecracker-compatible: bare array of regions, all defaults
            let regions: Vec<VmaRegion> = serde_json::from_value(json_val)
                .map_err(|e| eother!(format!("Invalid region array: {}", e)))?;
            HandshakeRequest {
                r#type: MessageType::Handshake,
                regions,
                policy: FaultPolicy::default(),
                enable_prefault: false,
            }
        } else {
            serde_json::from_value(json_val)
                .map_err(|e| eother!(format!("Invalid HandshakeRequest: {}", e)))?
        };

        info!(
            "block_uffd: handshake successful, {} regions, {} uffd fds, policy {:?}, enable_prefault={}",
            request.regions.len(), fds.len(), request.policy, request.enable_prefault
        );

        let fd = fds
            .first()
            .copied()
            .ok_or_else(|| eother!("No uffd fd received during handshake"))?;

        // Close extra fds beyond the first one
        for &extra_fd in &fds[1..] {
            unsafe { libc::close(extra_fd) };
        }

        // Set uffd fd to non-blocking mode
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
        if flags < 0 {
            unsafe { libc::close(fd) };
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }

        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let uffd_async = AsyncFd::new(owned_fd)
            .map_err(|e| eother!(format!("Failed to create AsyncFd for uffd: {}", e)))?;
        let state = ConnState {
            vma_regions: request.regions.clone(),
            policy: request.policy,
            uffd_async,
        };

        // Spawn pre-fault task if enabled and policy is zerocopy
        if request.enable_prefault && request.policy == FaultPolicy::Zerocopy {
            let stream_prefault = sock_async
                .get_ref()
                .try_clone()
                .map_err(|e| eother!(format!("Failed to clone stream for prefault: {}", e)))?;
            stream_prefault
                .set_nonblocking(true)
                .expect("failed to set nonblocking");

            let device_prefault = core.device().clone();
            let regions_prefault = request.regions;
            tokio_uring::spawn(async move {
                if let Err(e) =
                    Self::do_prefault(device_prefault, stream_prefault, regions_prefault).await
                {
                    warn!("block_uffd: pre-fault task error: {}", e);
                }
            });
        }

        Ok(state)
    }

    /// Handle stat request from client.
    async fn handle_stat_request(
        sock_async: &AsyncFd<StdUnixStream>,
        device_size: u64,
        block_size: u64,
    ) -> Result<()> {
        let response = StatResponse::new(device_size, block_size as u32, 0, UFFD_PROTOCOL_VERSION);
        let json_data = serde_json::to_vec(&response)
            .map_err(|e| eother!(format!("Failed to serialize StatResponse: {}", e)))?;
        Self::async_send_with_fd(sock_async, &json_data, &[]).await
    }

    /// Handle uffd page fault event.
    async fn handle_uffd_event(
        state: &ConnState,
        core: &UffdCore,
        sock_async: &AsyncFd<StdUnixStream>,
    ) -> Result<()> {
        let uffd_fd = state.uffd_async.get_ref().as_raw_fd();
        let msg = match read_uffd_msg(uffd_fd)? {
            Some(m) => m,
            None => return Ok(()),
        };

        let result = core
            .handle_page_fault(&msg, &state.vma_regions, state.policy, uffd_fd)
            .await?;

        match result {
            PageFaultResult::Zerocopy(zr) => {
                for chunk in zr.ranges.chunks(MAX_RANGES_PER_MSG) {
                    Self::send_batch_response(sock_async, chunk).await?;
                }
            }
            PageFaultResult::Copy | PageFaultResult::Noop => {}
        }

        Ok(())
    }

    fn close_fds(fds: &[i32]) {
        for &fd in fds {
            unsafe {
                libc::close(fd);
            }
        }
    }

    /// Try to receive a message from sock (non-blocking).
    /// Returns parsed JSON Value, received fds, and inferred message type.
    fn try_recv_from_sock(
        sock: &StdUnixStream,
    ) -> Result<Option<(serde_json::Value, Vec<RawFd>, MessageType)>> {
        let mut data_buf = [0u8; RECV_BUF_SIZE];
        let mut fds = [0i32; MAX_RANGES_PER_MSG];
        match sock.recv_with_fd(&mut data_buf, &mut fds) {
            Ok((bytes_read, fd_count)) => {
                if bytes_read == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "client disconnected",
                    ));
                }

                let received_fds = &fds[..fd_count];
                let json_str = match std::str::from_utf8(&data_buf[..bytes_read]) {
                    Ok(s) => s,
                    Err(e) => {
                        Self::close_fds(received_fds);
                        return Err(eother!(format!("Invalid UTF-8: {}", e)));
                    }
                };
                let json_val: serde_json::Value = match serde_json::from_str(json_str) {
                    Ok(v) => v,
                    Err(e) => {
                        Self::close_fds(received_fds);
                        return Err(eother!(format!("Invalid JSON: {}", e)));
                    }
                };
                let msg_type = json_val
                    .get("type")
                    .and_then(|v| v.as_u64())
                    .and_then(|v| serde_json::from_value(serde_json::Value::Number(v.into())).ok())
                    .unwrap_or(MessageType::Handshake);
                let fd_vec = received_fds.to_vec();
                Ok(Some((json_val, fd_vec, msg_type)))
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(None);
                }
                Err(eother!(format!("recv_with_fd failed: {}", e)))
            }
        }
    }

    /// Send data with fd asynchronously using tokio's try_io pattern.
    /// This avoids spawn_blocking by using the async socket's readiness notification.
    async fn async_send_with_fd(
        sock: &AsyncFd<StdUnixStream>,
        data: &[u8],
        fds: &[RawFd],
    ) -> Result<()> {
        loop {
            match sock.get_ref().send_with_fd(data, fds) {
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Wait for socket to become writable
                    let mut guard = sock
                        .writable()
                        .await
                        .map_err(|e| eother!(format!("socket writable failed: {}", e)))?;
                    guard.clear_ready();
                }
                Err(e) => return Err(eother!(format!("send_with_fd failed: {}", e))),
            }
        }
    }

    /// Send a batch of page fault responses with blob fds to client. Zerocopy only
    async fn send_batch_response(
        stream: &AsyncFd<StdUnixStream>,
        batch: &[(RawFd, u64, usize, u64)],
    ) -> Result<()> {
        let response = PageFaultResponse {
            r#type: MessageType::PageFault,
            ranges: batch
                .iter()
                .map(|(_, blob_offset, len, block_offset)| BlobRange {
                    len: *len,
                    blob_offset: *blob_offset,
                    block_offset: *block_offset,
                })
                .collect(),
        };
        let json_data = serde_json::to_vec(&response)
            .map_err(|e| eother!(format!("Failed to serialize PageFaultResponse: {}", e)))?;

        let fds: Vec<RawFd> = batch.iter().map(|(fd, _, _, _)| *fd).collect();
        Self::async_send_with_fd(stream, &json_data, &fds).await
    }

    /// Pre-fault: probe ready ranges and send them to client proactively.
    async fn do_prefault(
        device: Arc<BlockDevice>,
        stream: StdUnixStream,
        vma_regions: Vec<VmaRegion>,
    ) -> Result<()> {
        let stream = AsyncFd::new(stream)
            .map_err(|e| eother!(format!("Failed to create AsyncFd for pre-fault: {}", e)))?;
        let core = UffdCore::new(device);
        let ranges = core.prefault_ranges(&vma_regions).await?;
        for chunk in ranges.chunks(MAX_RANGES_PER_MSG) {
            Self::send_batch_response(&stream, chunk).await?;
        }
        Ok(())
    }
}

/// Uffd server to expose RAFSv6 images as block devices via userfaultfd.
pub struct UffdService {
    active: Arc<AtomicBool>,
    blob_id: String,
    cache_mgr: Arc<BlobCacheMgr>,
    uds_path: String,
    sender: Arc<Sender<u32>>,
    active_conns: Arc<Mutex<Vec<RawFd>>>,
    worker_senders: Mutex<Vec<flume::Sender<StdUnixStream>>>,
    worker_threads: Mutex<Vec<JoinHandle<Result<()>>>>,
}

impl UffdService {
    /// Create a new instance of [UffdService] to expose a RAFSv6 image as a block device.
    ///
    /// It accepts unix sockets from `uds_path` and receives uffd fd and VMA info
    /// from clients to monitor for page faults.
    pub fn new(device: Arc<BlockDevice>, uds_path: String) -> Result<Self> {
        let (sender, _receiver) = tokio::sync::broadcast::channel(4);

        Ok(UffdService {
            active: Arc::new(AtomicBool::new(true)),
            blob_id: device.meta_blob_id().to_string(),
            cache_mgr: device.cache_mgr().clone(),
            uds_path,
            sender: Arc::new(sender),
            active_conns: Arc::new(Mutex::new(Vec::new())),
            worker_threads: Mutex::new(Vec::new()),
            worker_senders: Mutex::new(Vec::new()),
        })
    }

    /// Create a [UffdWorker] to run the event loop to handle uffd connections.
    pub fn create_worker(&self, waker: Arc<Waker>) -> Result<()> {
        let (tx, rx) = flume::unbounded::<StdUnixStream>();
        let worker_index = self.worker_threads.lock().unwrap().len();
        let name = format!("block_uffd_worker_{}", worker_index);
        let worker = UffdWorker {
            active: self.active.clone(),
            active_conns: self.active_conns.clone(),
            blob_id: self.blob_id.clone(),
            cache_mgr: self.cache_mgr.clone(),
            conn_receiver: rx,
            sender: self.sender.clone(),
            name: name.clone(),
        };

        let thread: std::thread::JoinHandle<Result<()>> = std::thread::Builder::new()
            .name(name)
            .spawn(move || {
                tokio_uring::start(async move {
                    worker.run().await;
                    // Notify the daemon controller that one working thread has exited.
                    if let Err(err) = waker.wake() {
                        error!("block: fail to exit daemon, error: {:?}", err);
                    }
                });
                Ok(())
            })
            .map_err(crate::Error::ThreadSpawn)?;
        self.worker_senders.lock().unwrap().push(tx);
        self.worker_threads.lock().unwrap().push(thread);

        Ok(())
    }

    /// Run the event loop to handle incoming uffd connection requests.
    pub fn run(&self) -> Result<()> {
        info!("block_uffd: service start!");

        let _ = std::fs::remove_file(&self.uds_path);
        let listener = UnixListener::bind(&self.uds_path)?;
        listener.set_nonblocking(true)?;

        let mut curr_worker = 0;
        let worker_num = self.worker_threads.lock().unwrap().len();
        while self.active.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    if !self.active.load(Ordering::Acquire) {
                        info!("block_uffd: shutting down, drop the accepted stream");
                        break;
                    }

                    let senders = self.worker_senders.lock().unwrap();
                    let _ = senders[curr_worker].send(stream);
                    curr_worker = (curr_worker + 1) % worker_num;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
                Err(e) => {
                    warn!("block_uffd: accept error: {e}");
                }
            }
        }

        self.active.store(false, Ordering::Release);
        let _ = self.sender.send(1);
        loop {
            let handle = self.worker_threads.lock().unwrap().pop();
            if let Some(handle) = handle {
                handle
                    .join()
                    .map_err(|e| {
                        let e = *e
                            .downcast::<Error>()
                            .unwrap_or_else(|e| Box::new(eother!(e)));
                        crate::Error::WaitDaemon(e)
                    })?
                    .map_err(crate::Error::WaitDaemon)?;
            } else {
                // No more handles to wait
                break;
            }
        }

        info!("block_uffd: service exit!");

        Ok(())
    }

    /// Deactivate the uffd session, send exit notification to workers,
    /// shutdown all active client sockets, and send dummy connect to
    /// wake up the accept loop.
    pub fn stop(&self) {
        self.active.store(false, Ordering::Release);
        let _ = self.sender.send(0);
        // Shutdown all active client sockets so handle_conn tasks exit.
        let conns = self.active_conns.lock().unwrap();
        for &fd in conns.iter() {
            unsafe {
                libc::shutdown(fd, libc::SHUT_RDWR);
            }
        }
        drop(conns);
        // wake up blocking accept()
        let _ = std::os::unix::net::UnixStream::connect(&self.uds_path);
    }

    pub fn get_blob_cache_mgr(&self) -> Option<Arc<BlobCacheMgr>> {
        Some(self.cache_mgr.clone())
    }

    pub fn save(&self) -> crate::Result<()> {
        info!("block_uffd: stateless, no need to save");
        Ok(())
    }

    pub fn restore(&self) -> crate::Result<()> {
        info!("block_uffd: stateless, no need to restore");
        Ok(())
    }
}

/// A [NydusDaemon] implementation to expose RAFS v6 images as block devices through uffd.
pub struct UffdDaemon {
    service: Arc<UffdService>,

    bti: BuildTimeInfo,
    id: Option<String>,
    supervisor: Option<String>,

    nr_threads: u32,
    service_threads: Mutex<Vec<JoinHandle<Result<()>>>>,
    request_sender: Arc<Mutex<std::sync::mpsc::Sender<DaemonStateMachineInput>>>,
    result_receiver: Mutex<std::sync::mpsc::Receiver<NydusResult<()>>>,
    state: AtomicI32,
    state_machine_thread: Mutex<Option<JoinHandle<Result<()>>>>,
    waker: Arc<Waker>,
}

impl UffdDaemon {
    #[allow(clippy::too_many_arguments)]
    fn new(
        service: Arc<UffdService>,
        threads: u32,
        trigger: std::sync::mpsc::Sender<DaemonStateMachineInput>,
        receiver: std::sync::mpsc::Receiver<NydusResult<()>>,
        waker: Arc<Waker>,
        bti: BuildTimeInfo,
        id: Option<String>,
        supervisor: Option<String>,
    ) -> Result<Self> {
        Ok(UffdDaemon {
            service,

            bti,
            id,
            supervisor,

            nr_threads: threads,
            service_threads: Mutex::new(Vec::new()),
            state: AtomicI32::new(DaemonState::INIT as i32),
            request_sender: Arc::new(Mutex::new(trigger)),
            result_receiver: Mutex::new(receiver),
            state_machine_thread: Mutex::new(None),
            waker,
        })
    }
}

impl DaemonStateMachineSubscriber for UffdDaemon {
    fn on_event(&self, event: DaemonStateMachineInput) -> NydusResult<()> {
        self.request_sender
            .lock()
            .expect("uffd: failed to lock request sender!")
            .send(event)
            .map_err(NydusError::ChannelSend)?;

        self.result_receiver
            .lock()
            .expect("uffd: failed to lock result receiver!")
            .recv()
            .map_err(NydusError::ChannelReceive)?
    }
}

impl NydusDaemon for UffdDaemon {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn id(&self) -> Option<String> {
        self.id.clone()
    }

    fn version(&self) -> BuildTimeInfo {
        self.bti.clone()
    }

    fn get_state(&self) -> DaemonState {
        self.state.load(Ordering::Relaxed).into()
    }

    fn set_state(&self, state: DaemonState) {
        self.state.store(state as i32, Ordering::Relaxed);
    }

    fn start(&self) -> NydusResult<()> {
        info!("start uffd service with {} worker threads", self.nr_threads);
        for _ in 0..self.nr_threads {
            self.service.create_worker(self.waker.clone())?;
        }

        let service = self.service.clone();
        let waker = self.waker.clone();
        let thread = std::thread::spawn(move || {
            if let Err(e) = service.run() {
                error!("uffd: failed to run uffd control loop, {}", e);
            }
            // Notify the daemon controller that server thread has exited.
            if let Err(err) = waker.wake() {
                error!("uffd: fail to exit daemon, error: {:?}", err);
            }
            Ok(())
        });
        self.service_threads.lock().unwrap().push(thread);

        Ok(())
    }

    fn umount(&self) -> NydusResult<()> {
        Ok(())
    }

    fn stop(&self) {
        self.service.stop();
    }

    fn wait(&self) -> NydusResult<()> {
        self.wait_state_machine()?;
        self.wait_service()
    }

    fn wait_service(&self) -> NydusResult<()> {
        loop {
            let handle = self.service_threads.lock().unwrap().pop();
            if let Some(handle) = handle {
                handle
                    .join()
                    .map_err(|e| {
                        let e = *e
                            .downcast::<Error>()
                            .unwrap_or_else(|e| Box::new(eother!(e)));
                        NydusError::WaitDaemon(e)
                    })?
                    .map_err(NydusError::WaitDaemon)?;
            } else {
                // No more handles to wait
                break;
            }
        }

        Ok(())
    }

    fn wait_state_machine(&self) -> NydusResult<()> {
        let mut guard = self.state_machine_thread.lock().unwrap();
        if let Some(handler) = guard.take() {
            let result = handler.join().map_err(|e| {
                let e = *e
                    .downcast::<Error>()
                    .unwrap_or_else(|e| Box::new(eother!(e)));
                NydusError::WaitDaemon(e)
            })?;
            result.map_err(NydusError::WaitDaemon)
        } else {
            Ok(())
        }
    }

    fn supervisor(&self) -> Option<String> {
        self.supervisor.clone()
    }

    fn save(&self) -> NydusResult<()> {
        self.service.save()
    }

    fn restore(&self) -> NydusResult<()> {
        self.service.restore()
    }

    fn get_blob_cache_mgr(&self) -> Option<Arc<BlobCacheMgr>> {
        self.service.get_blob_cache_mgr()
    }
}

/// Create and start a [UffdDaemon] instance to expose a RAFS v6 image as a block device through uffd.
#[allow(clippy::too_many_arguments, clippy::arc_with_non_send_sync)]
pub fn create_uffd_daemon(
    sock: String,
    threads: u32,
    blob_entry: BlobCacheEntry,
    bti: BuildTimeInfo,
    id: Option<String>,
    supervisor: Option<String>,
    waker: Arc<Waker>,
) -> Result<Arc<dyn NydusDaemon>> {
    let blob_id = generate_blob_key(&blob_entry.domain_id, &blob_entry.blob_id);
    let cache_mgr = Arc::new(BlobCacheMgr::new());
    cache_mgr.add_blob_entry(&blob_entry)?;
    let block_device = BlockDevice::new_with_cache_manager(blob_id.clone(), cache_mgr.clone())?;
    let service = Arc::new(UffdService::new(Arc::new(block_device), sock)?);

    let (trigger, events_rx) = std::sync::mpsc::channel::<DaemonStateMachineInput>();
    let (result_sender, result_receiver) = std::sync::mpsc::channel::<NydusResult<()>>();
    let daemon = UffdDaemon::new(
        service,
        threads,
        trigger,
        result_receiver,
        waker,
        bti,
        id,
        supervisor,
    )?;
    let daemon = Arc::new(daemon);
    let machine = DaemonStateMachineContext::new(daemon.clone(), events_rx, result_sender);
    let machine_thread = machine.kick_state_machine()?;
    *daemon.state_machine_thread.lock().unwrap() = Some(machine_thread);
    daemon
        .on_event(DaemonStateMachineInput::Mount)
        .map_err(|e| eother!(e))?;
    daemon
        .on_event(DaemonStateMachineInput::Start)
        .map_err(|e| eother!(e))?;

    Ok(daemon)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob_cache::{generate_blob_key, BlobCacheMgr};
    use nydus_api::BlobCacheEntry;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::path::PathBuf;
    use std::time::Duration;
    use vmm_sys_util::tempdir::TempDir;

    // ---- UFFD test helpers ----

    fn setup_uffd_region(size: usize) -> Result<(i32, u64, usize)> {
        let uffd_fd = create_userfaultfd_for_test()?;
        let align = 2 * 1024 * 1024; // 2MB
        let mmap_size = size.div_ceil(align) * align;
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mmap_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            unsafe { libc::close(uffd_fd) };
            return Err(std::io::Error::last_os_error());
        }
        if let Err(e) = uffd_register_for_test(uffd_fd, addr as u64, mmap_size as u64) {
            unsafe {
                libc::munmap(addr, mmap_size);
                libc::close(uffd_fd);
            }
            return Err(e);
        }
        Ok((uffd_fd, addr as u64, mmap_size))
    }

    fn cleanup_uffd_region(uffd_fd: i32, addr: u64, size: usize) {
        unsafe {
            libc::munmap(addr as *mut _, size);
            libc::close(uffd_fd);
        }
    }

    fn create_userfaultfd_for_test() -> Result<i32> {
        let fd = unsafe { libc::syscall(libc::SYS_userfaultfd, libc::O_CLOEXEC | libc::O_NONBLOCK) }
            as i32;
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        #[repr(C)]
        struct UffdioApi {
            api: u64,
            features: u64,
            ioctls: u64,
        }
        let mut api = UffdioApi {
            api: 0xaa,
            features: 0,
            ioctls: 0,
        };
        const UFFDIO_API_IOCTL: libc::Ioctl = 0xc018aa3fu32 as libc::Ioctl;
        let ret = unsafe { libc::ioctl(fd, UFFDIO_API_IOCTL, &mut api) };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(std::io::Error::last_os_error());
        }
        Ok(fd)
    }

    fn uffd_register_for_test(fd: i32, addr: u64, len: u64) -> Result<()> {
        #[repr(C)]
        struct UffdioRegister {
            range_start: u64,
            range_len: u64,
            mode: u64,
            ioctls: u64,
        }
        const UFFDIO_REGISTER_IOCTL: libc::Ioctl = 0xc020aa00u32 as libc::Ioctl;
        const UFFDIO_REGISTER_MODE_MISSING: u64 = 1;
        let mut reg = UffdioRegister {
            range_start: addr,
            range_len: len,
            mode: UFFDIO_REGISTER_MODE_MISSING,
            ioctls: 0,
        };
        let ret = unsafe { libc::ioctl(fd, UFFDIO_REGISTER_IOCTL, &mut reg) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn create_block_device(tmpdir: PathBuf) -> Result<Arc<BlockDevice>> {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/blobs/be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef");
        let mut dest_path = tmpdir.clone();
        dest_path.push("be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef");
        std::fs::copy(&source_path, &dest_path).unwrap();

        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/bootstrap/rafs-v6-2.2.boot");
        let config = r#"
        {
            "type": "bootstrap",
            "id": "rafs-v6",
            "domain_id": "domain2",
            "config_v2": {
                "version": 2,
                "id": "factory1",
                "backend": {
                    "type": "localfs",
                    "localfs": {
                        "dir": "/tmp/nydus"
                    }
                },
                "cache": {
                    "type": "filecache",
                    "filecache": {
                        "work_dir": "/tmp/nydus"
                    }
                },
                "metadata_path": "RAFS_V6"
            }
          }"#;
        let content = config
            .replace("/tmp/nydus", tmpdir.as_path().to_str().unwrap())
            .replace("RAFS_V6", &source_path.display().to_string());
        let mut entry: BlobCacheEntry = serde_json::from_str(&content).unwrap();
        assert!(entry.prepare_configuration_info());

        let mgr = BlobCacheMgr::new();
        mgr.add_blob_entry(&entry).unwrap();
        let blob_id = generate_blob_key(&entry.domain_id, &entry.blob_id);
        assert!(mgr.get_config(&blob_id).is_some());

        // Check existence of data blob referenced by the bootstrap.
        let key = generate_blob_key(
            &entry.domain_id,
            "be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef",
        );
        assert!(mgr.get_config(&key).is_some());

        let mgr = Arc::new(mgr);
        let device = BlockDevice::new_with_cache_manager(blob_id.clone(), mgr).unwrap();

        Ok(Arc::new(device))
    }

    #[test]
    fn test_uffd_daemon_lifecycle() {
        let tmpdir = TempDir::new().unwrap();
        let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
        let sock_path = format!("{}/test_daemon.sock", tmpdir.as_path().display());
        let service = Arc::new(UffdService::new(device, sock_path.clone()).unwrap());

        let (trigger, events_rx) = std::sync::mpsc::channel::<DaemonStateMachineInput>();
        let (result_sender, result_receiver) = std::sync::mpsc::channel::<NydusResult<()>>();
        let poll = mio::Poll::new().unwrap();
        let waker = Arc::new(Waker::new(poll.registry(), mio::Token(0)).unwrap());

        let daemon = UffdDaemon::new(
            service,
            2,
            trigger,
            result_receiver,
            waker,
            BuildTimeInfo {
                package_ver: String::new(),
                git_commit: String::new(),
                build_time: String::new(),
                profile: String::new(),
                rustc: String::new(),
            },
            None,
            None,
        )
        .unwrap();
        let daemon = Arc::new(daemon);

        // Start state machine thread
        let machine = DaemonStateMachineContext::new(daemon.clone(), events_rx, result_sender);
        let machine_thread = machine.kick_state_machine().unwrap();
        *daemon.state_machine_thread.lock().unwrap() = Some(machine_thread);

        // Drive through Mount -> Start
        // Wait for state machine thread to be ready
        for _ in 0..100 {
            if daemon.get_state() != DaemonState::INIT {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        daemon.on_event(DaemonStateMachineInput::Mount).unwrap();
        daemon.on_event(DaemonStateMachineInput::Start).unwrap();
        assert_eq!(daemon.get_state(), DaemonState::RUNNING);

        // Verify interface methods
        assert!(daemon.id().is_none());
        assert!(daemon.supervisor().is_none());
        assert!(daemon.save().is_ok());
        assert!(daemon.restore().is_ok());
        assert!(daemon.get_blob_cache_mgr().is_some());

        // Graceful shutdown
        daemon.on_event(DaemonStateMachineInput::Stop).unwrap();
        assert_eq!(daemon.get_state(), DaemonState::READY);
        daemon.on_event(DaemonStateMachineInput::Stop).unwrap();
        assert_eq!(daemon.get_state(), DaemonState::STOPPED);

        // Also test create_uffd_daemon convenience function
        let tmpdir2 = TempDir::new().unwrap();
        let entry = create_test_blob_entry(tmpdir2.as_path().to_path_buf());
        let sock_path2 = format!("{}/test_daemon2.sock", tmpdir2.as_path().display());
        let poll2 = mio::Poll::new().unwrap();
        let waker2 = Arc::new(Waker::new(poll2.registry(), mio::Token(0)).unwrap());

        let daemon2 = create_uffd_daemon(
            sock_path2,
            1,
            entry,
            BuildTimeInfo {
                package_ver: "test".to_string(),
                git_commit: "test".to_string(),
                build_time: "test".to_string(),
                profile: "test".to_string(),
                rustc: "test".to_string(),
            },
            None,
            None,
            waker2,
        )
        .expect("create_uffd_daemon failed");
        assert_eq!(daemon2.get_state(), DaemonState::RUNNING);

        let _ = daemon2.on_event(DaemonStateMachineInput::Stop);
    }

    // --- UffdService basic tests ---

    #[test]
    fn test_uffd_service_stop_flag() {
        let tmpdir = TempDir::new().unwrap();
        let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
        let sock_path = format!("{}/test.sock", tmpdir.as_path().display());
        let service = UffdService::new(device, sock_path).unwrap();

        assert!(service.active.load(Ordering::Acquire));
        service.stop();
        assert!(!service.active.load(Ordering::Acquire));
    }

    #[test]
    fn test_uffd_service_save_restore() {
        let tmpdir = TempDir::new().unwrap();
        let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
        let sock_path = format!("{}/test.sock", tmpdir.as_path().display());
        let service = UffdService::new(device, sock_path).unwrap();

        // save and restore are no-ops for stateless service
        assert!(service.save().is_ok());
        assert!(service.restore().is_ok());
    }

    #[test]
    fn test_uffd_service_get_blob_cache_mgr() {
        let tmpdir = TempDir::new().unwrap();
        let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
        let sock_path = format!("{}/test.sock", tmpdir.as_path().display());
        let service = UffdService::new(device, sock_path).unwrap();

        assert!(service.get_blob_cache_mgr().is_some());
    }

    // --- close_fds test ---

    #[test]
    fn test_close_fds_empty() {
        // Closing an empty list should not panic
        UffdWorker::close_fds(&[]);
    }

    #[test]
    fn test_close_fds_invalid_fd() {
        // Closing invalid fds should not panic (close returns EBADF but we ignore it)
        UffdWorker::close_fds(&[-1, -2]);
    }

    // --- try_recv_from_sock tests ---

    #[test]
    fn test_try_recv_from_sock_eof() {
        // Create a pair of unix stream sockets, close the sender side
        let (sock1, sock2) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(sock2); // close the peer

        let result = UffdWorker::try_recv_from_sock(&sock1);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_try_recv_from_sock_would_block() {
        // Create a pair and set non-blocking, read without writing -> WouldBlock -> Ok(None)
        let (sock1, _sock2) = std::os::unix::net::UnixStream::pair().unwrap();
        sock1.set_nonblocking(true).unwrap();

        let result = UffdWorker::try_recv_from_sock(&sock1);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_try_recv_from_sock_valid_handshake() {
        let (sock1, sock2) = std::os::unix::net::UnixStream::pair().unwrap();

        let request = HandshakeRequest {
            r#type: MessageType::Handshake,
            regions: vec![VmaRegion::new(0x1000, 0x2000, 0, 2 * 1024 * 1024)],
            policy: FaultPolicy::Zerocopy,
            enable_prefault: false,
        };
        let json_data = serde_json::to_vec(&request).unwrap();
        sock2.send_with_fd(&json_data, &[]).unwrap();

        let result = UffdWorker::try_recv_from_sock(&sock1);
        assert!(result.is_ok());
        let (json_val, fds, msg_type) = result.unwrap().unwrap();
        assert_eq!(msg_type, MessageType::Handshake);
        assert!(fds.is_empty());
        assert!(json_val.is_object());
        assert!(json_val.get("regions").unwrap().is_array());
    }

    #[test]
    fn test_try_recv_from_sock_stat_request() {
        let (sock1, sock2) = std::os::unix::net::UnixStream::pair().unwrap();

        let request = StatRequest::new();
        let json_data = serde_json::to_vec(&request).unwrap();
        sock2.send_with_fd(&json_data, &[]).unwrap();

        let result = UffdWorker::try_recv_from_sock(&sock1);
        assert!(result.is_ok());
        let (_, _, msg_type) = result.unwrap().unwrap();
        assert_eq!(msg_type, MessageType::Stat);
    }

    #[test]
    fn test_try_recv_from_sock_invalid_utf8() {
        let (sock1, sock2) = std::os::unix::net::UnixStream::pair().unwrap();

        // Send invalid UTF-8 bytes
        let invalid_data: &[u8] = &[0xff, 0xfe, 0xfd];
        sock2.send_with_fd(invalid_data, &[]).unwrap();

        let result = UffdWorker::try_recv_from_sock(&sock1);
        assert!(result.is_err());
    }

    #[test]
    fn test_try_recv_from_sock_invalid_json() {
        let (sock1, sock2) = std::os::unix::net::UnixStream::pair().unwrap();

        // Send valid UTF-8 but invalid JSON
        let bad_json = b"not valid json {{{";
        sock2.send_with_fd(bad_json, &[]).unwrap();

        let result = UffdWorker::try_recv_from_sock(&sock1);
        assert!(result.is_err());
    }

    // --- handle_handshake Firecracker compatibility test ---

    #[test]
    fn test_handle_handshake_firecracker_format() {
        let (sock1, sock2) = std::os::unix::net::UnixStream::pair().unwrap();

        // Send Firecracker-compatible bare array format
        let regions = vec![VmaRegion::new(0x1000, 0x2000, 0, 2 * 1024 * 1024)];
        let json_data = serde_json::to_vec(&regions).unwrap();
        sock2.send_with_fd(&json_data, &[]).unwrap();
        drop(sock2);

        // Read back and parse as HandshakeRequest
        let mut data_buf = [0u8; RECV_BUF_SIZE];
        let mut fds = [0i32; MAX_RANGES_PER_MSG];
        let (bytes_read, fd_count) = sock1.recv_with_fd(&mut data_buf, &mut fds).unwrap();
        assert!(bytes_read > 0);
        assert_eq!(fd_count, 0);

        let json_str = std::str::from_utf8(&data_buf[..bytes_read]).unwrap();
        let json_val: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert!(json_val.is_array());

        // Parse as HandshakeRequest (should accept bare array)
        let request: HandshakeRequest = if json_val.is_array() {
            let regions: Vec<VmaRegion> = serde_json::from_value(json_val).unwrap();
            HandshakeRequest {
                r#type: MessageType::Handshake,
                regions,
                policy: FaultPolicy::default(),
                enable_prefault: false,
            }
        } else {
            serde_json::from_value(json_val).unwrap()
        };

        assert_eq!(request.regions.len(), 1);
        assert_eq!(request.policy, FaultPolicy::Zerocopy);
        assert!(!request.enable_prefault);
    }

    // --- do_prefault test ---

    #[test]
    fn test_do_prefault() {
        tokio_uring::start(async {
            let tmpdir = TempDir::new().unwrap();
            let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
            let (sock1, sock2) = std::os::unix::net::UnixStream::pair().unwrap();
            sock2.set_nonblocking(true).unwrap();

            let vma_regions = vec![VmaRegion::new(
                0,
                device.blocks_to_size(device.blocks()) as usize,
                0,
                device.block_size() as usize,
            )];

            // Run do_prefault in background
            let prefault_task = tokio_uring::spawn(async move {
                UffdWorker::do_prefault(device, sock2, vma_regions).await
            });

            // Read messages from sock1
            sock1
                .set_read_timeout(Some(std::time::Duration::from_millis(500)))
                .unwrap();
            let mut total_messages = 0;
            loop {
                let mut buf = [0u8; 4096];
                let mut fds = Vec::new();
                match sock1.recv_with_fd(&mut buf, &mut fds) {
                    Ok((bytes_read, _fd_count)) => {
                        if bytes_read == 0 {
                            break;
                        }
                        total_messages += 1;
                    }
                    Err(_) => break,
                }
            }

            let res = prefault_task.await.unwrap();
            assert!(res.is_ok());
            let _ = total_messages;
        });
    }

    // --- send_batch_response test ---

    #[test]
    fn test_send_batch_response() {
        tokio_uring::start(async {
            let (sock1, sock2) = std::os::unix::net::UnixStream::pair().unwrap();
            let sock_async = AsyncFd::new(sock1).unwrap();

            // Create a mock batch response
            let batch = vec![
                (sock2.as_raw_fd(), 0u64, 4096usize, 0u64),
                (sock2.as_raw_fd(), 4096u64, 4096usize, 4096u64),
            ];

            let res = UffdWorker::send_batch_response(&sock_async, &batch).await;
            assert!(res.is_ok());

            // Read back and verify via sock2
            sock2
                .set_read_timeout(Some(std::time::Duration::from_millis(100)))
                .unwrap();
            let mut buf = [0u8; 4096];
            let mut fds = [0i32; MAX_RANGES_PER_MSG];
            let (bytes_read, fd_count) = sock2.recv_with_fd(&mut buf, &mut fds).unwrap();
            assert!(bytes_read > 0);
            assert_eq!(fd_count, 2); // 2 fds in batch

            let response: PageFaultResponse = serde_json::from_slice(&buf[..bytes_read]).unwrap();
            assert_eq!(response.ranges.len(), 2);
            assert_eq!(response.ranges[0].len, 4096);
            assert_eq!(response.ranges[1].blob_offset, 4096);
        });
    }

    // --- dispatch_message tests ---

    #[test]
    fn test_dispatch_message_stat() {
        tokio_uring::start(async {
            let (sock1, sock2) = std::os::unix::net::UnixStream::pair().unwrap();
            sock2.set_nonblocking(true).unwrap();
            let sock_async = AsyncFd::new(sock1).unwrap();

            let tmpdir = TempDir::new().unwrap();
            let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
            let core = UffdCore::new(device);
            let mut conn_state: Option<ConnState> = None;

            let json_val = serde_json::to_value(StatRequest::new()).unwrap();
            let res = UffdWorker::dispatch_message(
                MessageType::Stat,
                json_val,
                &[],
                &sock_async,
                &core,
                &mut conn_state,
                1024 * 1024,
                4096,
            )
            .await;
            assert!(res.is_ok());
            assert!(conn_state.is_none()); // stat doesn't change conn_state
        });
    }

    #[test]
    fn test_dispatch_message_unexpected_type() {
        tokio_uring::start(async {
            let (sock1, _sock2) = std::os::unix::net::UnixStream::pair().unwrap();
            sock1.set_nonblocking(true).unwrap();
            let sock_async = AsyncFd::new(sock1).unwrap();

            let tmpdir = TempDir::new().unwrap();
            let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
            let core = UffdCore::new(device);
            let mut conn_state: Option<ConnState> = None;

            let json_val = serde_json::json!({"type": 99});
            let res = UffdWorker::dispatch_message(
                MessageType::PageFault,
                json_val,
                &[],
                &sock_async,
                &core,
                &mut conn_state,
                1024 * 1024,
                4096,
            )
            .await;
            assert!(res.is_ok()); // unexpected type is logged but not an error
        });
    }

    #[test]
    fn test_dispatch_message_handshake_already_handshaked() {
        tokio_uring::start(async {
            let (sock1, _sock2) = std::os::unix::net::UnixStream::pair().unwrap();
            sock1.set_nonblocking(true).unwrap();
            let sock_async = AsyncFd::new(sock1).unwrap();

            let tmpdir = TempDir::new().unwrap();
            let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
            let core = UffdCore::new(device);

            // Pre-set conn_state to simulate already handshaked
            let (uffd_sock, _) = std::os::unix::net::UnixStream::pair().unwrap();
            uffd_sock.set_nonblocking(true).unwrap();
            let uffd_fd = unsafe { OwnedFd::from_raw_fd(uffd_sock.as_raw_fd()) };
            let uffd_async = AsyncFd::new(uffd_fd).unwrap();
            let mut conn_state: Option<ConnState> = Some(ConnState {
                vma_regions: vec![VmaRegion::new(0x1000, 0x2000, 0, 4096)],
                policy: FaultPolicy::Zerocopy,
                uffd_async,
            });

            let json_val = serde_json::to_value(HandshakeRequest {
                r#type: MessageType::Handshake,
                regions: vec![VmaRegion::new(0x1000, 0x2000, 0, 4096)],
                policy: FaultPolicy::Zerocopy,
                enable_prefault: false,
            })
            .unwrap();

            let res = UffdWorker::dispatch_message(
                MessageType::Handshake,
                json_val,
                &[],
                &sock_async,
                &core,
                &mut conn_state,
                1024 * 1024,
                4096,
            )
            .await;
            assert!(res.is_ok()); // double handshake is logged but not an error
                                  // conn_state should remain unchanged
            assert!(conn_state.is_some());
            std::mem::forget(uffd_sock); // prevent double-close
        });
    }

    // --- handle_stat_request test ---

    #[test]
    fn test_handle_stat_request() {
        tokio_uring::start(async {
            let (sock1, sock2) = std::os::unix::net::UnixStream::pair().unwrap();
            sock1.set_nonblocking(true).unwrap();
            let sock_async = AsyncFd::new(sock1).unwrap();

            let res = UffdWorker::handle_stat_request(&sock_async, 1024 * 1024, 4096).await;
            assert!(res.is_ok());

            // Read back the stat response from sock2
            sock2
                .set_read_timeout(Some(std::time::Duration::from_millis(500)))
                .unwrap();
            let mut buf = [0u8; 4096];
            let mut fds = [0i32; MAX_RANGES_PER_MSG];
            let (bytes_read, fd_count) = sock2.recv_with_fd(&mut buf, &mut fds).unwrap();
            assert!(bytes_read > 0);
            assert_eq!(fd_count, 0);

            let response: StatResponse = serde_json::from_slice(&buf[..bytes_read]).unwrap();
            assert_eq!(response.r#type, MessageType::StatResp);
            assert_eq!(response.size, 1024 * 1024);
            assert_eq!(response.block_size, 4096);
        });
    }

    // --- handle_handshake with real uffd fd ---

    #[test]
    fn test_handle_handshake_with_uffd_fd() {
        tokio_uring::start(async {
            let tmpdir = TempDir::new().unwrap();
            let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
            let core = UffdCore::new(device);

            let (sock1, _sock2) = std::os::unix::net::UnixStream::pair().unwrap();
            sock1.set_nonblocking(true).unwrap();
            let sock_async = AsyncFd::new(sock1).unwrap();

            let uffd_fd = create_userfaultfd_for_test().unwrap();

            let json_val = serde_json::to_value(HandshakeRequest {
                r#type: MessageType::Handshake,
                regions: vec![VmaRegion::new(0x1000, 0x2000, 0, 2 * 1024 * 1024)],
                policy: FaultPolicy::Zerocopy,
                enable_prefault: false,
            })
            .unwrap();

            let result = UffdWorker::handle_handshake(json_val, &[uffd_fd], &sock_async, &core);
            assert!(result.is_ok());
            let state = result.unwrap();
            assert_eq!(state.vma_regions.len(), 1);
            assert_eq!(state.policy, FaultPolicy::Zerocopy);
        });
    }

    #[test]
    fn test_handle_handshake_no_uffd_fd() {
        tokio_uring::start(async {
            let tmpdir = TempDir::new().unwrap();
            let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
            let core = UffdCore::new(device);

            let (sock1, _sock2) = std::os::unix::net::UnixStream::pair().unwrap();
            sock1.set_nonblocking(true).unwrap();
            let sock_async = AsyncFd::new(sock1).unwrap();

            let json_val = serde_json::to_value(HandshakeRequest {
                r#type: MessageType::Handshake,
                regions: vec![VmaRegion::new(0x1000, 0x2000, 0, 4096)],
                policy: FaultPolicy::Copy,
                enable_prefault: false,
            })
            .unwrap();

            // No uffd fd provided — should fail
            let result = UffdWorker::handle_handshake(json_val, &[], &sock_async, &core);
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_handle_handshake_copy_policy() {
        tokio_uring::start(async {
            let tmpdir = TempDir::new().unwrap();
            let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
            let core = UffdCore::new(device);

            let (sock1, _sock2) = std::os::unix::net::UnixStream::pair().unwrap();
            sock1.set_nonblocking(true).unwrap();
            let sock_async = AsyncFd::new(sock1).unwrap();

            let uffd_fd = create_userfaultfd_for_test().unwrap();

            let json_val = serde_json::to_value(HandshakeRequest {
                r#type: MessageType::Handshake,
                regions: vec![VmaRegion::new(0x1000, 0x2000, 0, 4096)],
                policy: FaultPolicy::Copy,
                enable_prefault: false,
            })
            .unwrap();

            let result = UffdWorker::handle_handshake(json_val, &[uffd_fd], &sock_async, &core);
            assert!(result.is_ok());
            let state = result.unwrap();
            assert_eq!(state.policy, FaultPolicy::Copy);
        });
    }

    // --- UffdService create_worker test ---

    #[test]
    fn test_uffd_service_create_worker() {
        let tmpdir = TempDir::new().unwrap();
        let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
        let sock_path = format!("{}/test_worker.sock", tmpdir.as_path().display());
        let service = UffdService::new(device, sock_path).unwrap();
        let service = Arc::new(service);

        // Create a waker for the worker
        let poll = mio::Poll::new().unwrap();
        let waker = Arc::new(Waker::new(poll.registry(), mio::Token(0)).unwrap());

        assert!(service.create_worker(waker).is_ok());
        assert_eq!(service.worker_threads.lock().unwrap().len(), 1);
        assert_eq!(service.worker_senders.lock().unwrap().len(), 1);

        service.stop();
    }

    // --- async_send_with_fd test ---

    #[test]
    fn test_async_send_with_fd() {
        tokio_uring::start(async {
            let (sock1, sock2) = std::os::unix::net::UnixStream::pair().unwrap();
            sock1.set_nonblocking(true).unwrap();
            let sock_async = AsyncFd::new(sock1).unwrap();

            let data = b"hello world";
            let res = UffdWorker::async_send_with_fd(&sock_async, data, &[]).await;
            assert!(res.is_ok());

            // Read back
            sock2
                .set_read_timeout(Some(std::time::Duration::from_millis(100)))
                .unwrap();
            let mut buf = [0u8; 64];
            let mut fds = [0i32; 4];
            let (n, fd_count) = sock2.recv_with_fd(&mut buf, &mut fds).unwrap();
            assert_eq!(&buf[..n], b"hello world");
            assert_eq!(fd_count, 0);
        });
    }

    // --- stop() shutdown socket test ---

    #[test]
    fn test_service_stop_shutdown_sockets() {
        let tmpdir = TempDir::new().unwrap();
        let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
        let sock_path = format!("{}/test_stop.sock", tmpdir.as_path().display());

        let service = Arc::new(UffdService::new(device, sock_path.clone()).unwrap());

        // Create a worker
        let poll = mio::Poll::new().unwrap();
        let waker = Arc::new(Waker::new(poll.registry(), mio::Token(0)).unwrap());
        service.create_worker(waker).unwrap();

        // Start service in background thread
        let service_clone = service.clone();
        let handle = std::thread::spawn(move || {
            service_clone.run().unwrap();
        });

        // Wait for service to start listening by retrying connect
        let mut client = None;
        for _ in 0..50 {
            match std::os::unix::net::UnixStream::connect(&sock_path) {
                Ok(c) => {
                    client = Some(c);
                    break;
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        let mut client = client.expect("service did not start listening");

        let client_fd = client.as_raw_fd();

        // Register the fd in active_conns (simulating what handle_conn does)
        service.active_conns.lock().unwrap().push(client_fd);

        // Call stop - this should shutdown the client socket
        service.stop();

        // Wait for service thread to exit
        let _ = handle.join();

        // Verify client socket was shutdown (reading should return EOF/error)
        let mut buf = [0u8; 1];
        let result = client.read(&mut buf);
        // After shutdown, read should return Ok(0) (EOF) or error
        assert!(result.is_err() || result.unwrap() == 0);

        drop(client);
    }

    // --- handle_conn graceful shutdown test ---

    #[test]
    fn test_handle_conn_graceful_shutdown() {
        tokio_uring::start(async {
            let tmpdir = TempDir::new().unwrap();
            let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();

            let (client_sock, server_sock) = std::os::unix::net::UnixStream::pair().unwrap();
            client_sock.set_nonblocking(true).unwrap();
            server_sock.set_nonblocking(true).unwrap();

            let client_async = AsyncFd::new(client_sock).unwrap();

            let (uffd_fd, addr, mmap_size) = setup_uffd_region(4096).unwrap();

            // Send handshake with uffd fd via SCM_RIGHTS.
            // After send_with_fd, the fd ownership transfers to the receiver,
            // so we must NOT close it via cleanup_uffd_region afterward.
            let handshake = HandshakeRequest {
                r#type: MessageType::Handshake,
                regions: vec![VmaRegion::new(addr as u64, 4096, 0, 4096)],
                policy: FaultPolicy::Zerocopy,
                enable_prefault: false,
            };
            let json = serde_json::to_vec(&handshake).unwrap();
            client_async
                .get_ref()
                .send_with_fd(&json, &[uffd_fd])
                .unwrap();

            // Spawn handle_conn with broadcast sender for graceful shutdown
            let active = Arc::new(AtomicBool::new(true));
            let (sender, _receiver) = tokio::sync::broadcast::channel(4);
            let sender = Arc::new(sender);
            let sender_clone = sender.clone();
            let handle = tokio_uring::spawn(async move {
                UffdWorker::handle_conn(
                    active,
                    Arc::new(Mutex::new(Vec::new())),
                    device,
                    server_sock,
                    sender_clone,
                )
                .await
            });

            // Yield to let the runtime process the handshake
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }

            // Graceful shutdown via broadcast signal
            let _ = sender.send(0);

            // Only unmap the memory region; do NOT close uffd_fd since
            // ownership was transferred to handle_conn via SCM_RIGHTS.
            unsafe {
                libc::munmap(addr as *mut _, mmap_size);
            }

            let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
            assert!(result.is_ok(), "handle_conn did not exit within timeout");
        });
    }

    // --- handle_uffd_event test ---

    #[test]
    fn test_handle_uffd_event_no_event() {
        tokio_uring::start(async {
            let tmpdir = TempDir::new().unwrap();
            let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
            let core = UffdCore::new(device);

            // Create sockets for communication
            let (sock1, _sock2) = std::os::unix::net::UnixStream::pair().unwrap();
            sock1.set_nonblocking(true).unwrap();
            let sock_async = AsyncFd::new(sock1).unwrap();

            // Setup uffd region - OwnedFd takes ownership of uffd_fd
            let (uffd_fd, addr, mmap_size) = setup_uffd_region(4096).unwrap();
            let vma_regions = vec![VmaRegion::new(addr as u64, 4096, 0, 4096)];
            let state = ConnState {
                vma_regions,
                policy: FaultPolicy::Zerocopy,
                uffd_async: AsyncFd::new(unsafe { OwnedFd::from_raw_fd(uffd_fd) }).unwrap(),
            };

            // Call handle_uffd_event without triggering a page fault.
            // Since no fault occurred, read_uffd_msg returns WouldBlock -> Ok(None)
            // and handle_uffd_event should return Ok(()).
            let result = UffdWorker::handle_uffd_event(&state, &core, &sock_async).await;
            assert!(result.is_ok());

            // Only unmap; OwnedFd owns uffd_fd and will close it on drop.
            unsafe {
                libc::munmap(addr as *mut _, mmap_size);
            }
        });
    }

    // Helper function to create test blob entry
    fn create_test_blob_entry(tmpdir: PathBuf) -> BlobCacheEntry {
        let root_dir = std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(&root_dir);
        source_path.push("../tests/texture/blobs/be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef");
        let mut dest_path = tmpdir.clone();
        dest_path.push("be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef");
        std::fs::copy(&source_path, &dest_path).unwrap();

        let mut boot_source = PathBuf::from(&root_dir);
        boot_source.push("../tests/texture/bootstrap/rafs-v6-2.2.boot");
        let mut boot_dest = tmpdir.clone();
        boot_dest.push("image.boot");
        std::fs::copy(&boot_source, &boot_dest).unwrap();

        let config = format!(
            r#"{{
                "type": "bootstrap",
                "id": "test-daemon",
                "domain_id": "test-domain",
                "config_v2": {{
                    "version": 2,
                    "id": "test-factory",
                    "backend": {{
                        "type": "localfs",
                        "localfs": {{ "dir": "{}" }}
                    }},
                    "cache": {{
                        "type": "filecache",
                        "filecache": {{ "work_dir": "{}" }}
                    }},
                    "metadata_path": "{}/image.boot"
                }}
            }}"#,
            tmpdir.display(),
            tmpdir.display(),
            tmpdir.display()
        );
        let mut entry: BlobCacheEntry = serde_json::from_str(&config).unwrap();
        assert!(
            entry.prepare_configuration_info(),
            "prepare_configuration_info failed"
        );
        entry
    }

    // ---- UffdCore tests (from merged uffd_core module) ----

    #[test]
    fn test_read_uffd_msg_would_block() {
        let (read_fd, write_fd) = unsafe {
            let mut fds: [libc::c_int; 2] = [-1, -1];
            let ret = libc::pipe(fds.as_mut_ptr());
            assert_eq!(ret, 0);
            (fds[0], fds[1])
        };
        let flags = unsafe { libc::fcntl(read_fd, libc::F_GETFL, 0) };
        assert!(flags >= 0);
        unsafe { libc::fcntl(read_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };

        let result = read_uffd_msg(read_fd);
        assert!(result.unwrap().is_none());

        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
    }

    #[test]
    fn test_uffd_core_new_and_device() {
        let tmpdir = TempDir::new().unwrap();
        let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
        let device_size = device.blocks_to_size(device.blocks());
        let block_size = device.block_size();

        let core = UffdCore::new(device.clone());
        assert_eq!(core.device_size, device_size);
        assert_eq!(core.block_size, block_size);
        assert!(Arc::ptr_eq(core.device(), &device));
    }

    #[test]
    fn test_handle_page_fault_not_pagefault_event() {
        let tmpdir = TempDir::new().unwrap();
        let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
        let core = UffdCore::new(device);
        let vma_regions = vec![VmaRegion::new(0x1000, 0x2000, 0, 4096)];

        let msg = UffdMsg {
            event: 0x01,
            _reserved1: [0; 3],
            _reserved2: 0,
            pagefault: UffdPagefault {
                flags: 0,
                address: 0x1000,
                feat: 0,
            },
        };

        tokio_uring::start(async {
            let result = core
                .handle_page_fault(&msg, &vma_regions, FaultPolicy::Copy, -1)
                .await
                .unwrap();
            assert!(matches!(result, PageFaultResult::Noop));
        });
    }

    #[test]
    fn test_handle_page_fault_addr_not_in_vma() {
        let tmpdir = TempDir::new().unwrap();
        let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
        let core = UffdCore::new(device);
        let vma_regions = vec![VmaRegion::new(0x1000, 0x2000, 0, 4096)];

        let msg = UffdMsg {
            event: UFFD_EVENT_PAGEFAULT,
            _reserved1: [0; 3],
            _reserved2: 0,
            pagefault: UffdPagefault {
                flags: 0,
                address: 0x5000,
                feat: 0,
            },
        };

        tokio_uring::start(async {
            let result = core
                .handle_page_fault(&msg, &vma_regions, FaultPolicy::Copy, -1)
                .await
                .unwrap();
            assert!(matches!(result, PageFaultResult::Noop));
        });
    }

    #[test]
    fn test_handle_page_fault_copy_mode() {
        let tmpdir = TempDir::new().unwrap();
        let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
        let device_size = device.blocks_to_size(device.blocks()) as usize;
        let core = UffdCore::new(device);

        let (uffd_fd, addr, mmap_size) = setup_uffd_region(device_size).unwrap();
        let vma_regions = vec![VmaRegion::new(addr, device_size, 0, 4096)];

        let msg = UffdMsg {
            event: UFFD_EVENT_PAGEFAULT,
            _reserved1: [0; 3],
            _reserved2: 0,
            pagefault: UffdPagefault {
                flags: 0,
                address: addr,
                feat: 0,
            },
        };

        tokio_uring::start(async {
            let result = core
                .handle_page_fault(&msg, &vma_regions, FaultPolicy::Copy, uffd_fd)
                .await
                .unwrap();
            assert!(matches!(result, PageFaultResult::Copy));

            let magic_ptr = (addr + 1024) as *const u8;
            let magic = unsafe {
                (*magic_ptr) as u32
                    | (*magic_ptr.add(1) as u32) << 8
                    | (*magic_ptr.add(2) as u32) << 16
                    | (*magic_ptr.add(3) as u32) << 24
            };
            assert_eq!(magic, 0xE0F5E1E2, "EROFS magic mismatch in copy mode");
        });

        cleanup_uffd_region(uffd_fd, addr, mmap_size);
    }

    #[test]
    fn test_handle_page_fault_zerocopy_mode() {
        let tmpdir = TempDir::new().unwrap();
        let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
        let device_size = device.blocks_to_size(device.blocks()) as usize;
        let core = UffdCore::new(device);

        let (uffd_fd, addr, mmap_size) = setup_uffd_region(device_size).unwrap();
        let vma_regions = vec![VmaRegion::new(addr, device_size, 0, 4096)];

        let msg = UffdMsg {
            event: UFFD_EVENT_PAGEFAULT,
            _reserved1: [0; 3],
            _reserved2: 0,
            pagefault: UffdPagefault {
                flags: 0,
                address: addr,
                feat: 0,
            },
        };

        tokio_uring::start(async {
            let result = core
                .handle_page_fault(&msg, &vma_regions, FaultPolicy::Zerocopy, uffd_fd)
                .await
                .unwrap();
            match result {
                PageFaultResult::Zerocopy(zr) => {
                    assert!(!zr.ranges.is_empty(), "zerocopy should return data ranges");
                }
                other => panic!("expected Zerocopy result, got {:?}", other),
            }
        });

        cleanup_uffd_region(uffd_fd, addr, mmap_size);
    }

    #[test]
    fn test_resolve_copy() {
        let tmpdir = TempDir::new().unwrap();
        let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
        let device_size = device.blocks_to_size(device.blocks()) as usize;
        let core = UffdCore::new(device);

        let (uffd_fd, addr, mmap_size) = setup_uffd_region(device_size).unwrap();

        tokio_uring::start(async {
            core.resolve_copy(0, 4096, addr, uffd_fd).await.unwrap();
            let magic_ptr = (addr + 1024) as *const u8;
            let magic = unsafe {
                (*magic_ptr) as u32
                    | (*magic_ptr.add(1) as u32) << 8
                    | (*magic_ptr.add(2) as u32) << 16
                    | (*magic_ptr.add(3) as u32) << 24
            };
            assert_eq!(magic, 0xE0F5E1E2);
        });

        cleanup_uffd_region(uffd_fd, addr, mmap_size);
    }

    #[test]
    fn test_resolve_zerocopy_ranges() {
        let tmpdir = TempDir::new().unwrap();
        let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
        let device_size = device.blocks_to_size(device.blocks()) as usize;
        let core = UffdCore::new(device);

        let (uffd_fd, addr, mmap_size) = setup_uffd_region(device_size).unwrap();
        let vma_region = VmaRegion::new(addr, device_size, 0, 4096);

        tokio_uring::start(async {
            let result = core
                .resolve_zerocopy_ranges(0, 4096, &vma_region, uffd_fd)
                .await
                .unwrap();
            assert!(!result.ranges.is_empty());
        });

        cleanup_uffd_region(uffd_fd, addr, mmap_size);
    }

    #[test]
    fn test_prefault_ranges() {
        let tmpdir = TempDir::new().unwrap();
        let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
        let device_size = device.blocks_to_size(device.blocks()) as usize;
        let core = UffdCore::new(device);

        let vma_regions = vec![VmaRegion::new(0, device_size, 0, 4096)];

        tokio_uring::start(async {
            let _ranges = core.prefault_ranges(&vma_regions).await.unwrap();
        });
    }

    #[test]
    fn test_handle_page_fault_beyond_device_zerocopy() {
        let tmpdir = TempDir::new().unwrap();
        let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
        let device_size = device.blocks_to_size(device.blocks());

        let vma_size = device_size as usize + 0x200000;
        let core = UffdCore::new(device);

        let (uffd_fd, addr, mmap_size) = setup_uffd_region(vma_size).unwrap();
        let vma_regions = vec![VmaRegion::new(addr, vma_size, 0, 4096)];

        let fault_addr = addr + device_size + 4096;
        let msg = UffdMsg {
            event: UFFD_EVENT_PAGEFAULT,
            _reserved1: [0; 3],
            _reserved2: 0,
            pagefault: UffdPagefault {
                flags: 0,
                address: fault_addr,
                feat: 0,
            },
        };

        tokio_uring::start(async {
            let result = core
                .handle_page_fault(&msg, &vma_regions, FaultPolicy::Zerocopy, uffd_fd)
                .await
                .unwrap();
            match result {
                PageFaultResult::Zerocopy(zr) => {
                    assert!(
                        zr.ranges.is_empty(),
                        "beyond-device should have no data ranges"
                    );
                }
                other => panic!("expected Zerocopy, got {:?}", other),
            }
        });

        cleanup_uffd_region(uffd_fd, addr, mmap_size);
    }

    #[test]
    fn test_handle_page_fault_beyond_device_copy() {
        let tmpdir = TempDir::new().unwrap();
        let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
        let device_size = device.blocks_to_size(device.blocks());

        let vma_size = device_size as usize + 0x200000;
        let core = UffdCore::new(device);

        let (uffd_fd, addr, mmap_size) = setup_uffd_region(vma_size).unwrap();
        let vma_regions = vec![VmaRegion::new(addr, vma_size, 0, 4096)];

        let fault_addr = addr + device_size + 4096;
        let msg = UffdMsg {
            event: UFFD_EVENT_PAGEFAULT,
            _reserved1: [0; 3],
            _reserved2: 0,
            pagefault: UffdPagefault {
                flags: 0,
                address: fault_addr,
                feat: 0,
            },
        };

        tokio_uring::start(async {
            let result = core
                .handle_page_fault(&msg, &vma_regions, FaultPolicy::Copy, uffd_fd)
                .await
                .unwrap();
            assert!(matches!(result, PageFaultResult::Copy));
        });

        cleanup_uffd_region(uffd_fd, addr, mmap_size);
    }

    #[test]
    fn test_uffdio_wake() {
        tokio_uring::start(async {
            let (uffd_fd, addr, mmap_size) = setup_uffd_region(4096).unwrap();

            let result = uffdio_wake(uffd_fd, addr as u64, 4096).await;
            assert!(
                result.is_ok(),
                "uffdio_wake on registered region failed: {:?}",
                result.err()
            );

            let zeropage_result = uffdio_zeropage(uffd_fd, addr as u64, 4096).await;
            assert!(
                zeropage_result.is_ok(),
                "uffdio_zeropage failed: {:?}",
                zeropage_result.err()
            );

            let result = uffdio_wake(uffd_fd, addr as u64, 4096).await;
            assert!(
                result.is_ok(),
                "uffdio_wake after zeropage should return Ok (EEXIST): {:?}",
                result.err()
            );

            cleanup_uffd_region(uffd_fd, addr, mmap_size);
        });
    }

    #[test]
    fn test_uffdio_wake_invalid_fd() {
        tokio_uring::start(async {
            let result = uffdio_wake(-1, 0x1000, 4096).await;
            assert!(result.is_err());
        });
    }
}
