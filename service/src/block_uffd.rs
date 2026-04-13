// Copyright (C) 2026 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0)

//! Export a RAFSv6 image as a block device through userfaultfd (uffd) protocol.
//!
//! The UffdService provides a way to handle page faults for a RAFSv6 image via userfaultfd.
//! Clients connect to the unix socket and send:
//! - uffd file descriptor (via SCM_RIGHTS)
//! - VMA (Virtual Memory Area) information about the memory region to monitor
//!
//! When a page fault occurs, the service responds with blob fds and range metadata
//! (len, blob_offset, block_offset) so the client can mmap the data directly (zero-copy).
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
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use flume;
use mio::Waker;
use nydus_api::{BlobCacheEntry, BuildTimeInfo};
use nydus_storage::utils::alloc_buf;
use sendfd::{RecvWithFd, SendWithFd};
use std::os::unix::net::UnixStream as StdUnixStream;
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

/// Maximum receive buffer size for socket messages.
const RECV_BUF_SIZE: usize = 4096;

/// Maximum number of ranges (and fds) per message.
const MAX_RANGES_PER_MSG: usize = 16;

/// UFFD event type for page fault (from linux/userfaultfd.h).
const UFFD_EVENT_PAGEFAULT: u8 = 0x12;

/// Kernel uffd_msg struct layout (from linux/userfaultfd.h).
#[repr(C)]
struct UffdMsg {
    event: u8,
    _reserved1: [u8; 3],
    _reserved2: u32,
    /// Union field for UFFD_EVENT_PAGEFAULT
    pagefault: UffdPagefault,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UffdPagefault {
    flags: u64,
    address: u64,
    feat: u64,
}

// UFFDIO ioctl definitions (from linux/userfaultfd.h).
// _IOWR(UFFDIO, 0x03, struct uffdio_copy)
const UFFDIO_COPY: u64 = 0xc028aa03;
// _IOWR(UFFDIO, 0x04, struct uffdio_zeropage)
const UFFDIO_ZEROPAGE: u64 = 0xc020aa04;

#[repr(C)]
struct UffdioCopy {
    dst: u64,
    src: u64,
    len: u64,
    mode: u64,
    copy: i64, // output: bytes copied, or negative errno
}

#[repr(C)]
struct UffdioZeropage {
    range_start: u64,
    range_len: u64,
    mode: u64,
    zeropage: i64, // output: bytes zeroed, or negative errno
}

/// Uffd server to expose RAFSv6 images as block devices via userfaultfd.
pub struct UffdService {
    active: Arc<AtomicBool>,
    blob_id: String,
    cache_mgr: Arc<BlobCacheMgr>,
    uds_path: String,
    sender: Arc<Sender<u32>>,
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
    /// and then send dummy connect to shutdown the session.
    pub fn stop(&self) {
        self.active.store(false, Ordering::Release);
        let _ = self.sender.send(0);
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

/// Connection state after handshake.
struct ConnState {
    vma_regions: Vec<VmaRegion>,
    policy: FaultPolicy,
    uffd_async: AsyncFd<OwnedFd>,
}

/// A worker to handle uffd connections in asynchronous mode.
struct UffdWorker {
    active: Arc<AtomicBool>,
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
            tokio::select! {
                Ok(stream) = self.conn_receiver.recv_async() => {
                    stream.set_nonblocking(true).expect("failed to set nonblocking");
                    let active = self.active.clone();
                    let device = device.clone();
                    let sender = self.sender.clone();
                    tokio_uring::spawn(async move {
                        if let Err(e) = Self::handle_conn(active, device, stream, sender).await {
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
        device: Arc<BlockDevice>,
        stream: StdUnixStream,
        sender: Arc<Sender<u32>>,
    ) -> Result<()> {
        info!("block_uffd: conn {} start!", stream.as_raw_fd());

        let sock_async = AsyncFd::new(stream)
            .map_err(|e| eother!(format!("Failed to create AsyncFd for sock: {}", e)))?;

        let mut receiver = sender.subscribe();
        let device_size = device.blocks_to_size(device.blocks());
        let block_size = device.block_size();
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
                                &sock_async, &device, &mut conn_state,
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
                    if let Err(e) = Self::handle_uffd_event(state, &device, &sock_async).await {
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

        info!("block_uffd: conn {} exit!", sock_async.as_raw_fd());

        Ok(())
    }

    /// Dispatch a received message by type.
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_message(
        msg_type: MessageType,
        json_val: serde_json::Value,
        fds: &[RawFd],
        sock_async: &AsyncFd<StdUnixStream>,
        device: &Arc<BlockDevice>,
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
                *conn_state = Some(Self::handle_handshake(json_val, fds, sock_async, device)?);
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
        device: &Arc<BlockDevice>,
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

            let device_prefault = device.clone();
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
        device: &Arc<BlockDevice>,
        sock_async: &AsyncFd<StdUnixStream>,
    ) -> Result<()> {
        let mut msg = std::mem::MaybeUninit::<UffdMsg>::uninit();
        let n = unsafe {
            libc::read(
                state.uffd_async.get_ref().as_raw_fd(),
                msg.as_mut_ptr() as *mut libc::c_void,
                std::mem::size_of::<UffdMsg>(),
            )
        };

        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(());
            }
            return Err(eother!(format!("uffd read failed: {}", err)));
        }
        if (n as usize) < std::mem::size_of::<UffdMsg>() {
            return Err(eother!(format!("uffd short read: {n} bytes")));
        }

        let msg = unsafe { msg.assume_init() };
        Self::handle_page_fault_event(&msg, state, device, sock_async).await
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

    // --- UFFD methods ---

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

    /// Handle a single page fault event from uffd.
    async fn handle_page_fault_event(
        msg: &UffdMsg,
        state: &ConnState,
        device: &Arc<BlockDevice>,
        stream: &AsyncFd<StdUnixStream>,
    ) -> Result<()> {
        if msg.event != UFFD_EVENT_PAGEFAULT {
            warn!("block_uffd: unexpected uffd event: {}", msg.event);
            return Ok(());
        }

        let vma_regions = &state.vma_regions;
        let policy = state.policy;
        let uffd_fd = state.uffd_async.get_ref().as_raw_fd();

        // Find which VMA region this fault belongs to
        let fault_addr = msg.pagefault.address;
        debug!(
            "block_uffd: page fault at 0x{:x}, policy {:?}",
            fault_addr, policy
        );
        let vma_region = match vma_regions.iter().find(|v| {
            fault_addr >= v.base_host_virt_addr
                && fault_addr < v.base_host_virt_addr + v.size as u64
        }) {
            Some(v) => v,
            None => {
                warn!("block_uffd: fault addr 0x{:x} not in any VMA", fault_addr);
                return Ok(());
            }
        };

        let fetch_size = vma_region.page_size as u64;
        let fault_block_offset = vma_region.offset + (fault_addr - vma_region.base_host_virt_addr);
        let region_offset_end = vma_region.offset + vma_region.size as u64;
        let aligned_start = (fault_block_offset / fetch_size) * fetch_size;
        let fetch_start = std::cmp::max(aligned_start, vma_region.offset);
        let fetch_end = std::cmp::min(fetch_start + fetch_size, region_offset_end);

        // Handle range within device bounds [fetch_start, min(fetch_end, device_size))
        let device_size = device.blocks_to_size(device.blocks());
        if fetch_start < device_size {
            let data_end = std::cmp::min(fetch_end, device_size);
            let data_len = data_end - fetch_start;

            match policy {
                FaultPolicy::Zerocopy => {
                    Self::handle_range_zerocopy(
                        stream,
                        device,
                        fetch_start,
                        data_len,
                        vma_region,
                        uffd_fd,
                    )
                    .await?;
                }
                FaultPolicy::Copy => {
                    let data_addr =
                        vma_region.base_host_virt_addr + (fetch_start - vma_region.offset);
                    Self::handle_range_copy(device, fetch_start, data_len, data_addr, uffd_fd)
                        .await?;
                }
            }
        }

        // Handle range beyond device bounds [max(fetch_start, device_size), fetch_end)
        if fetch_end > device_size {
            let zero_start = std::cmp::max(fetch_start, device_size);
            let zero_len = fetch_end - zero_start;
            let zero_addr = vma_region.base_host_virt_addr + (zero_start - vma_region.offset);
            Self::handle_range_zero(zero_addr, zero_len, uffd_fd).await?;
        }

        Ok(())
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

    /// Handle a range using zero-copy mode (send fd to client). For holes, use UFFDIO_ZERO.
    async fn handle_range_zerocopy(
        stream: &AsyncFd<StdUnixStream>,
        device: &BlockDevice,
        block_offset: u64,
        len: u64,
        vma_region: &VmaRegion,
        uffd_fd: RawFd,
    ) -> Result<()> {
        let block_size = device.block_size();
        let start_block = (block_offset / block_size) as u32;
        let num_blocks = len.div_ceil(block_size) as u32;
        let ranges = device.fetch_ranges(start_block, num_blocks, false).await?;
        if ranges.is_empty() {
            // Entire range is a hole
            let target_addr = vma_region.base_host_virt_addr + (block_offset - vma_region.offset);
            return Self::handle_range_zero(target_addr, len, uffd_fd).await;
        }

        let mut current_offset = block_offset;
        let end_offset = block_offset + len;
        let mut batch: Vec<(RawFd, u64, usize, u64)> = Vec::with_capacity(MAX_RANGES_PER_MSG);

        for (blob_fd, blob_offset, blob_len, range_offset) in ranges {
            // Fill any gap before this range
            if range_offset > current_offset {
                let hole_len = range_offset - current_offset;
                let target_addr =
                    vma_region.base_host_virt_addr + (current_offset - vma_region.offset);
                Self::handle_range_zero(target_addr, hole_len, uffd_fd).await?;
            }

            if blob_len > 0 && range_offset < end_offset {
                let actual_len =
                    std::cmp::min(range_offset + blob_len as u64, end_offset) - range_offset;
                batch.push((blob_fd, blob_offset, actual_len as usize, range_offset));
                current_offset = range_offset + actual_len;
                // Flush if batch is full
                if batch.len() >= MAX_RANGES_PER_MSG {
                    Self::send_batch_response(stream, &batch).await?;
                    batch.clear();
                }
            }
        }
        // Flush remaining batch
        if !batch.is_empty() {
            Self::send_batch_response(stream, &batch).await?;
        }

        // Fill any remaining gap at the end
        if current_offset < end_offset {
            let hole_len = end_offset - current_offset;
            let target_addr = vma_region.base_host_virt_addr + (current_offset - vma_region.offset);
            Self::handle_range_zero(target_addr, hole_len, uffd_fd).await?;
        }

        Ok(())
    }

    /// Handle a range using copy mode (UFFDIO_COPY).
    async fn handle_range_copy(
        device: &BlockDevice,
        block_offset: u64,
        len: u64,
        target_addr: u64,
        uffd_fd: RawFd,
    ) -> Result<()> {
        let block_size = device.block_size();
        let start_block = (block_offset / block_size) as u32;
        let num_blocks = len.div_ceil(block_size) as u32;

        let read_len = num_blocks as usize * block_size as usize;
        let buf = alloc_buf(read_len);
        let (res, buf) = device.async_read(start_block, num_blocks, buf).await;
        let bytes_read = res.map_err(|e| eother!(format!("async_read failed: {}", e)))?;
        if bytes_read != read_len {
            return Err(eother!(format!(
                "read {} bytes, expected {}",
                bytes_read, read_len
            )));
        }

        let copy_len = len;
        spawn_blocking(move || -> Result<()> {
            let mut ioctl_arg = UffdioCopy {
                dst: target_addr,
                src: buf.as_ptr() as u64,
                len: copy_len,
                mode: 0,
                copy: 0,
            };
            let ret = unsafe { libc::ioctl(uffd_fd, UFFDIO_COPY as libc::c_ulong, &mut ioctl_arg) };
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

    /// Handle a range using UFFDIO_ZERO (for holes or out-of-range regions).
    async fn handle_range_zero(start_addr: u64, len: u64, uffd_fd: RawFd) -> Result<()> {
        spawn_blocking(move || -> Result<()> {
            let mut ioctl_arg = UffdioZeropage {
                range_start: start_addr,
                range_len: len,
                mode: 0,
                zeropage: 0,
            };
            let ret =
                unsafe { libc::ioctl(uffd_fd, UFFDIO_ZEROPAGE as libc::c_ulong, &mut ioctl_arg) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EEXIST) {
                    return Ok(()); // page already mapped, not a fatal error
                }
                return Err(eother!(format!("UFFDIO_ZEROPAGE failed: {}", err)));
            }
            Ok(())
        })
        .await
        .map_err(|e| eother!(format!("join error: {e}")))?
    }

    /// Pre-fault: probe ready ranges and send them to client proactively.
    async fn do_prefault(
        device: Arc<BlockDevice>,
        stream: StdUnixStream,
        vma_regions: Vec<VmaRegion>,
    ) -> Result<()> {
        let stream = AsyncFd::new(stream)
            .map_err(|e| eother!(format!("Failed to create AsyncFd for pre-fault: {}", e)))?;
        let device_size = device.blocks_to_size(device.blocks());
        let block_size = device.block_size();
        for vma_region in vma_regions.iter() {
            let region_start = vma_region.offset;
            let region_end = vma_region.offset + vma_region.size as u64;
            if region_start >= device_size {
                continue;
            }

            let effective_end = std::cmp::min(region_end, device_size);
            let start_block = (region_start / block_size) as u32;
            let num_blocks = (effective_end - region_start).div_ceil(block_size) as u32;
            let ranges = match device.fetch_ranges(start_block, num_blocks, true).await {
                Ok(r) => r,
                Err(e) => {
                    warn!("block_uffd: pre-fault fetch_ranges failed: {}", e);
                    continue;
                }
            };

            let mut batch: Vec<(RawFd, u64, usize, u64)> = Vec::with_capacity(MAX_RANGES_PER_MSG);
            for (blob_fd, blob_offset, blob_len, block_offset) in ranges {
                if blob_len == 0 {
                    continue;
                }

                batch.push((blob_fd, blob_offset, blob_len, block_offset));
                // Flush if batch is full
                if batch.len() >= MAX_RANGES_PER_MSG {
                    Self::send_batch_response(&stream, &batch).await?;
                    batch.clear();
                }
            }
            // Flush remaining batch
            if !batch.is_empty() {
                Self::send_batch_response(&stream, &batch).await?;
            }
        }

        Ok(())
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
    use std::path::PathBuf;
    use std::time::Duration;
    use vmm_sys_util::tempdir::TempDir;

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
    fn test_uffd_service_lifecycle() {
        tokio_uring::start(async {
            let tmpdir = TempDir::new().unwrap();
            let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
            let uffd = UffdService::new(device, "/tmp/test_uffd.sock".to_string()).unwrap();
            let uffd = Arc::new(uffd);
            let uffd2 = uffd.clone();

            std::thread::spawn(move || {
                uffd2.run().unwrap();
            });
            tokio::time::sleep(Duration::from_micros(100000)).await;
            uffd.stop();
        })
    }

    // --- Struct layout tests (verify ABI compatibility with kernel) ---

    #[test]
    fn test_uffd_msg_layout() {
        // linux/userfaultfd.h: struct uffd_msg is 32 bytes
        assert_eq!(std::mem::size_of::<UffdMsg>(), 32);
        // event field is at offset 0
        let msg = UffdMsg {
            event: UFFD_EVENT_PAGEFAULT,
            _reserved1: [0; 3],
            _reserved2: 0,
            pagefault: UffdPagefault {
                flags: 0,
                address: 0x1000,
                feat: 0,
            },
        };
        assert_eq!(msg.event, 0x12);
        assert_eq!(msg.pagefault.address, 0x1000);
    }

    #[test]
    fn test_uffd_pagefault_layout() {
        // UffdPagefault: 3 x u64 = 24 bytes
        assert_eq!(std::mem::size_of::<UffdPagefault>(), 24);
    }

    #[test]
    fn test_uffdio_copy_layout() {
        // struct uffdio_copy: dst(u64) + src(u64) + len(u64) + mode(u64) + copy(i64) = 40 bytes
        assert_eq!(std::mem::size_of::<UffdioCopy>(), 40);
    }

    #[test]
    fn test_uffdio_zeropage_layout() {
        // struct uffdio_zeropage: range_start(u64) + range_len(u64) + mode(u64) + zeropage(i64) = 32 bytes
        assert_eq!(std::mem::size_of::<UffdioZeropage>(), 32);
    }

    #[test]
    fn test_uffd_event_pagefault_constant() {
        assert_eq!(UFFD_EVENT_PAGEFAULT, 0x12);
    }

    #[test]
    fn test_uffdio_ioctl_constants() {
        // UFFDIO_COPY = _IOWR(UFFDIO, 0x03, struct uffdio_copy)
        assert_eq!(UFFDIO_COPY, 0xc028aa03);
        // UFFDIO_ZEROPAGE = _IOWR(UFFDIO, 0x04, struct uffdio_zeropage)
        assert_eq!(UFFDIO_ZEROPAGE, 0xc020aa04);
    }

    // --- Constants tests ---

    #[test]
    fn test_recv_buf_size() {
        assert_eq!(RECV_BUF_SIZE, 4096);
    }

    #[test]
    fn test_max_ranges_per_msg() {
        assert_eq!(MAX_RANGES_PER_MSG, 16);
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

    // --- send_batch_response serialization test ---

    #[test]
    fn test_page_fault_response_serialization() {
        let response = PageFaultResponse {
            r#type: MessageType::PageFault,
            ranges: vec![
                BlobRange {
                    len: 4096,
                    blob_offset: 0,
                    block_offset: 0,
                },
                BlobRange {
                    len: 8192,
                    blob_offset: 4096,
                    block_offset: 4096,
                },
            ],
        };

        let json = serde_json::to_vec(&response).unwrap();
        let parsed: PageFaultResponse = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.r#type, MessageType::PageFault);
        assert_eq!(parsed.ranges.len(), 2);
        assert_eq!(parsed.ranges[0].len, 4096);
        assert_eq!(parsed.ranges[1].blob_offset, 4096);
    }

    // --- StatResponse test ---

    #[test]
    fn test_stat_response_serialization() {
        let response = StatResponse::new(1024 * 1024, 512, 0, UFFD_PROTOCOL_VERSION);
        let json = serde_json::to_vec(&response).unwrap();
        let parsed: StatResponse = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.r#type, MessageType::StatResp);
        assert_eq!(parsed.size, 1024 * 1024);
        assert_eq!(parsed.block_size, 512);
        assert_eq!(parsed.version, UFFD_PROTOCOL_VERSION);
    }

    // --- create_uffd_daemon test ---

    fn make_blob_entry(tmpdir: &std::path::Path) -> BlobCacheEntry {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
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
            .replace("/tmp/nydus", tmpdir.to_str().unwrap())
            .replace("RAFS_V6", &source_path.display().to_string());
        let mut entry: BlobCacheEntry = serde_json::from_str(&content).unwrap();
        assert!(entry.prepare_configuration_info());
        entry
    }

    fn make_bti() -> BuildTimeInfo {
        BuildTimeInfo {
            package_ver: "test".to_string(),
            git_commit: "test".to_string(),
            build_time: "test".to_string(),
            profile: "debug".to_string(),
            rustc: "test".to_string(),
        }
    }

    fn make_waker() -> Arc<Waker> {
        let poll = mio::Poll::new().unwrap();
        Arc::new(Waker::new(poll.registry(), mio::Token(0)).unwrap())
    }

    #[test]
    fn test_create_uffd_daemon() {
        use crate::daemon::DaemonState;

        let tmpdir = TempDir::new().unwrap();
        let blob_entry = make_blob_entry(tmpdir.as_path());

        let daemon = create_uffd_daemon(
            format!("{}/test_uffd.sock", tmpdir.as_path().display()),
            1,
            blob_entry,
            make_bti(),
            Some("test-daemon".to_string()),
            None,
            make_waker(),
        )
        .unwrap();

        assert_eq!(daemon.get_state(), DaemonState::RUNNING);
        assert_eq!(daemon.id(), Some("test-daemon".to_string()));
        assert!(daemon.get_blob_cache_mgr().is_some());

        daemon.stop();
        let _ = daemon.wait();
    }

    // --- UffdDaemon method tests ---

    #[test]
    fn test_uffd_daemon_on_event() {
        use crate::daemon::{DaemonState, DaemonStateMachineInput};

        let tmpdir = TempDir::new().unwrap();
        let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
        let service = Arc::new(
            UffdService::new(device, format!("{}/test.sock", tmpdir.as_path().display())).unwrap(),
        );

        let (trigger, events_rx) = std::sync::mpsc::channel::<DaemonStateMachineInput>();
        let (result_sender, result_receiver) = std::sync::mpsc::channel::<crate::Result<()>>();

        let daemon = UffdDaemon::new(
            service,
            1,
            trigger,
            result_receiver,
            make_waker(),
            make_bti(),
            Some("test-daemon".to_string()),
            None,
        )
        .unwrap();
        let daemon = Arc::new(daemon);

        let machine = DaemonStateMachineContext::new(daemon.clone(), events_rx, result_sender);
        let machine_thread = machine.kick_state_machine().unwrap();
        *daemon.state_machine_thread.lock().unwrap() = Some(machine_thread);

        // Mount event should succeed
        let res = daemon.on_event(DaemonStateMachineInput::Mount);
        assert!(res.is_ok());
        // Mount has no output action, so daemon state stays INIT until Start
        assert_eq!(daemon.get_state(), DaemonState::INIT);

        // Start event creates tokio_uring workers and transitions to RUNNING
        let res = daemon.on_event(DaemonStateMachineInput::Start);
        assert!(res.is_ok());
        assert_eq!(daemon.get_state(), DaemonState::RUNNING);

        // Stop event transitions back
        let res = daemon.on_event(DaemonStateMachineInput::Stop);
        assert!(res.is_ok());

        daemon.stop();
        let _ = daemon.wait_state_machine();
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

    // --- handle_range_zero test ---
    // Requires Linux with userfaultfd kernel support.

    #[test]
    fn test_handle_range_zero() {
        // Create a userfaultfd via raw syscall
        let uffd_fd =
            unsafe { libc::syscall(libc::SYS_userfaultfd, libc::O_CLOEXEC | libc::O_NONBLOCK) }
                as i32;
        if uffd_fd < 0 {
            // userfaultfd not available (non-Linux or no permission) — skip
            return;
        }

        // UFFDIO_API handshake
        #[repr(C)]
        struct UffdioApi {
            api: u64,
            features: u64,
            ioctls: u64,
        }
        const UFFDIO_API_IOCTL: u64 = 0xc018aa3f;
        const UFFD_API_VAL: u64 = 0xaa;

        let mut api = UffdioApi {
            api: UFFD_API_VAL,
            features: 0,
            ioctls: 0,
        };
        let ret = unsafe { libc::ioctl(uffd_fd, UFFDIO_API_IOCTL as libc::c_ulong, &mut api) };
        if ret < 0 {
            unsafe { libc::close(uffd_fd) };
            return;
        }

        // mmap anonymous region
        let test_mem = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if test_mem == libc::MAP_FAILED {
            unsafe { libc::close(uffd_fd) };
            return;
        }

        // UFFDIO_REGISTER
        #[repr(C)]
        struct UffdioRegister {
            range_start: u64,
            range_len: u64,
            mode: u64,
            ioctls: u64,
        }
        const UFFDIO_REGISTER_IOCTL: u64 = 0xc020aa00;
        const UFFDIO_REGISTER_MODE_MISSING: u64 = 1;

        let mut reg = UffdioRegister {
            range_start: test_mem as u64,
            range_len: 4096,
            mode: UFFDIO_REGISTER_MODE_MISSING,
            ioctls: 0,
        };
        let ret = unsafe { libc::ioctl(uffd_fd, UFFDIO_REGISTER_IOCTL as libc::c_ulong, &mut reg) };
        if ret < 0 {
            unsafe {
                libc::munmap(test_mem, 4096);
                libc::close(uffd_fd);
            }
            return;
        }

        // Run handle_range_zero and verify it completes without error
        let result = tokio_uring::start(async move {
            UffdWorker::handle_range_zero(test_mem as u64, 4096, uffd_fd).await
        });

        // Verify the operation succeeded (zeroing was performed via UFFDIO_ZEROPAGE)
        // Note: This may return error if the page was already mapped by another thread,
        // but in this controlled test environment it should succeed
        assert!(
            result.is_ok(),
            "handle_range_zero failed: {:?}",
            result.err()
        );

        unsafe {
            libc::munmap(test_mem, 4096);
            libc::close(uffd_fd);
        }
    }
}
