// Copyright (C) 2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0)

//! Export a RAFSv6 image as a block device through NBD(Network Block Device) protocol.
//!
//! The [Network Block Device](https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md)
//! is a Linux-originated lightweight block access protocol that allows one to export a block device
//! to a client. RAFSv6 images have an block address based encoding, so an RAFSv6 image can be
//! exposed as a block device. The [NbdService] exposes a RAFSv6 image as a block device based on
//! the Linux Network Block Device driver.

use std::any::Any;
use std::fs::{self, OpenOptions};
use std::io::{Error, Result};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use bytes::{Buf, BufMut};
use mio::Waker;
use nydus_api::{BlobCacheEntry, BuildTimeInfo};
use nydus_storage::utils::alloc_buf;
use tokio::sync::broadcast::{channel, Sender};
use tokio_uring::buf::IoBuf;
use tokio_uring::net::UnixStream;

use crate::blob_cache::{generate_blob_key, BlobCacheMgr};
use crate::block_device::BlockDevice;
use crate::daemon::{
    DaemonState, DaemonStateMachineContext, DaemonStateMachineInput, DaemonStateMachineSubscriber,
    NydusDaemon,
};
use crate::{Error as NydusError, Result as NydusResult};

const NBD_SET_SOCK: u32 = 0;
const NBD_SET_BLOCK_SIZE: u32 = 1;
const NBD_DO_IT: u32 = 3;
const NBD_CLEAR_SOCK: u32 = 4;
const NBD_SET_BLOCKS: u32 = 7;
//const NBD_DISCONNECT: u32 = 8;
const NBD_SET_TIMEOUT: u32 = 9;
const NBD_SET_FLAGS: u32 = 10;
const NBD_FLAG_HAS_FLAGS: u32 = 0x1;
const NBD_FLAG_READ_ONLY: u32 = 0x2;
const NBD_FLAG_CAN_MULTI_CONN: u32 = 0x100;
const NBD_CMD_READ: u32 = 0;
const NBD_CMD_DISC: u32 = 2;
const NBD_REQUEST_HEADER_SIZE: usize = 28;
const NBD_REQUEST_MAGIC: u32 = 0x25609513;
const NBD_REPLY_MAGIC: u32 = 0x67446698;
const NBD_OK: u32 = 0;
const NBD_EIO: u32 = 5;
const NBD_EINVAL: u32 = 22;

fn nbd_ioctl(fd: RawFd, cmd: u32, arg: u64) -> nix::Result<libc::c_int> {
    let code = nix::request_code_none!(0xab, cmd);
    unsafe { nix::convert_ioctl_res!(libc::ioctl(fd, code, arg)) }
}

/// Network Block Device server to expose RAFSv6 images as block devices.
pub struct NbdService {
    active: Arc<AtomicBool>,
    blob_id: String,
    cache_mgr: Arc<BlobCacheMgr>,
    nbd_dev: fs::File,
    sender: Arc<Sender<u32>>,
}

impl NbdService {
    /// Create a new instance of [NbdService] to expose a RAFSv6 image as a block device.
    ///
    /// It opens the NBD device at `nbd_path` and initialize it according to information from
    /// the block device composed from a RAFSv6 image. The caller needs to ensure that the NBD
    /// device is available.
    pub fn new(device: Arc<BlockDevice>, nbd_path: String) -> Result<Self> {
        // Initialize the NBD device: set block size, block count and flags.
        let nbd_dev = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&nbd_path)
            .map_err(|e| {
                error!("block_nbd: failed to open NBD device {}", nbd_path);
                e
            })?;
        nbd_ioctl(nbd_dev.as_raw_fd(), NBD_SET_BLOCK_SIZE, device.block_size())?;
        nbd_ioctl(nbd_dev.as_raw_fd(), NBD_SET_BLOCKS, device.blocks() as u64)?;
        nbd_ioctl(nbd_dev.as_raw_fd(), NBD_SET_TIMEOUT, 60)?;
        nbd_ioctl(nbd_dev.as_raw_fd(), NBD_CLEAR_SOCK, 0)?;
        nbd_ioctl(
            nbd_dev.as_raw_fd(),
            NBD_SET_FLAGS,
            (NBD_FLAG_HAS_FLAGS | NBD_FLAG_READ_ONLY | NBD_FLAG_CAN_MULTI_CONN) as u64,
        )?;

        let (sender, _receiver) = channel(4);

        Ok(NbdService {
            active: Arc::new(AtomicBool::new(true)),
            blob_id: device.meta_blob_id().to_string(),
            cache_mgr: device.cache_mgr().clone(),
            nbd_dev,
            sender: Arc::new(sender),
        })
    }

    /// Create a [NbdWoker] to run the event loop to handle NBD requests from kernel.
    pub fn create_worker(&self) -> Result<NbdWorker> {
        // Let the NBD driver go.
        let (sock1, sock2) = std::os::unix::net::UnixStream::pair()?;
        nbd_ioctl(
            self.nbd_dev.as_raw_fd(),
            NBD_SET_SOCK,
            sock1.as_raw_fd() as u64,
        )?;

        Ok(NbdWorker {
            active: self.active.clone(),
            blob_id: self.blob_id.clone(),
            cache_mgr: self.cache_mgr.clone(),
            _sock_kern: sock1,
            sock_user: sock2,
            sender: self.sender.clone(),
        })
    }

    /// Run the event loop to handle incoming NBD requests.
    ///
    /// The caller will get blocked until the NBD device get destroyed or `NbdService::stop()` get
    /// called.
    pub fn run(&self) -> Result<()> {
        let _ = nbd_ioctl(self.nbd_dev.as_raw_fd(), NBD_DO_IT, 0);
        self.active.store(false, Ordering::Release);
        let _ = self.sender.send(1);
        let _ = nbd_ioctl(self.nbd_dev.as_raw_fd(), NBD_CLEAR_SOCK, 0);

        Ok(())
    }

    /// Shutdown the NBD session and send exit notification to workers.
    pub fn stop(&self) {
        self.active.store(false, Ordering::Release);
        let _ = self.sender.send(0);
        //let _ = nbd_ioctl(self.nbd_dev.as_raw_fd(), NBD_DISCONNECT, 0);
        let _ = nbd_ioctl(self.nbd_dev.as_raw_fd(), NBD_CLEAR_SOCK, 0);
    }
}

/// A worker to handle NBD requests in asynchronous mode.
pub struct NbdWorker {
    active: Arc<AtomicBool>,
    blob_id: String,
    cache_mgr: Arc<BlobCacheMgr>,
    _sock_kern: std::os::unix::net::UnixStream,
    sock_user: std::os::unix::net::UnixStream,
    sender: Arc<Sender<u32>>,
}

impl NbdWorker {
    /// Run the event loop to handle NBD requests from kernel in asynchronous mode.
    pub async fn run(self) {
        let device = match BlockDevice::new(self.blob_id.clone(), self.cache_mgr.clone()) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    "block_nbd: failed to create block device for {}, {}",
                    self.blob_id, e
                );
                return;
            }
        };

        // Safe because the RawFd is valid during the lifetime of run().
        let mut sock = unsafe { UnixStream::from_raw_fd(self.sock_user.as_raw_fd()) };
        let mut receiver = self.sender.subscribe();
        let mut buf = vec![0u8; NBD_REQUEST_HEADER_SIZE];
        let mut pos = 0;

        while self.active.load(Ordering::Acquire) {
            tokio::select! {
                (res, s) = sock.read(buf.slice(pos..)) => {
                    match res {
                        Err(e) => {
                            warn!("block_nbd: failed to get request from kernel for {}, {}", self.blob_id, e);
                            break;
                        }
                        Ok(sz) => {
                            buf = s.into_inner();
                            pos += sz;
                            if pos == NBD_REQUEST_HEADER_SIZE {
                                match self.handle_request(&buf, &mut sock, &device).await {
                                    Ok(true) => {}
                                    Ok(false) => break,
                                    Err(e) => {
                                        warn!("block_nbd: failed to handle request for {}, {}", self.blob_id, e);
                                        break;
                                    }
                                }
                                pos = 0;
                            }
                        }
                    }
                }
                _ = receiver.recv() => {
                   break;
                }
            }
        }
    }

    async fn handle_request(
        &self,
        mut request: &[u8],
        sock: &mut UnixStream,
        device: &BlockDevice,
    ) -> Result<bool> {
        let magic = request.get_u32();
        let ty = request.get_u32();
        let handle = request.get_u64();
        let pos = request.get_u64();
        let len = request.get_u32();

        let block_size = device.block_size();
        let mut code = NBD_OK;
        let mut data_buf = alloc_buf(len as usize);
        if magic != NBD_REQUEST_MAGIC || pos % block_size != 0 || len as u64 % block_size != 0 {
            warn!(
                "block_nbd: invalid request magic 0x{:x}, type {}, pos 0x{:x}, len 0x{:x}",
                magic, ty, pos, len
            );
            code = NBD_EINVAL;
        } else if ty == NBD_CMD_READ {
            let start = (pos / block_size) as u32;
            let count = len / block_size as u32;
            let (res, buf) = device.async_read(start, count, data_buf).await;
            data_buf = buf;
            match res {
                Ok(sz) => {
                    if sz != len as usize {
                        warn!("block_nbd: got 0x{:x} bytes, expect 0x{:x}", sz, len);
                        code = NBD_EIO;
                    }
                }
                Err(e) => {
                    warn!("block_nbd: failed to read data from block device, {}", e);
                    code = NBD_EIO;
                }
            }
        } else if ty == NBD_CMD_DISC {
            return Ok(false);
        }

        let mut reply = Vec::with_capacity(16);
        reply.put_u32(NBD_REPLY_MAGIC);
        reply.put_u32(code);
        reply.put_u64(handle);
        assert_eq!(reply.len(), 16);
        assert_eq!(data_buf.len(), len as usize);
        sock.write_all(reply).await.0?;
        if code == NBD_OK {
            sock.write_all(data_buf).await.0?;
        }

        Ok(true)
    }
}

/// A [NydusDaemon] implementation to expose RAFS v6 images as block devices through NBD.
pub struct NbdDaemon {
    cache_mgr: Arc<BlobCacheMgr>,
    service: Arc<NbdService>,

    bti: BuildTimeInfo,
    id: Option<String>,
    supervisor: Option<String>,

    nbd_threads: u32,
    nbd_control_thread: Mutex<Option<JoinHandle<()>>>,
    nbd_service_threads: Mutex<Vec<JoinHandle<Result<()>>>>,
    request_sender: Arc<Mutex<std::sync::mpsc::Sender<DaemonStateMachineInput>>>,
    result_receiver: Mutex<std::sync::mpsc::Receiver<NydusResult<()>>>,
    state: AtomicI32,
    state_machine_thread: Mutex<Option<JoinHandle<Result<()>>>>,
    waker: Arc<Waker>,
}

impl NbdDaemon {
    fn new(
        nbd_path: String,
        threads: u32,
        blob_entry: BlobCacheEntry,
        trigger: std::sync::mpsc::Sender<DaemonStateMachineInput>,
        receiver: std::sync::mpsc::Receiver<NydusResult<()>>,
        waker: Arc<Waker>,
        bti: BuildTimeInfo,
        id: Option<String>,
        supervisor: Option<String>,
    ) -> Result<Self> {
        let blob_id = generate_blob_key(&blob_entry.domain_id, &blob_entry.blob_id);
        let cache_mgr = Arc::new(BlobCacheMgr::new());
        cache_mgr.add_blob_entry(&blob_entry)?;
        let block_device = BlockDevice::new(blob_id.clone(), cache_mgr.clone())?;
        let nbd_service = NbdService::new(Arc::new(block_device), nbd_path)?;

        Ok(NbdDaemon {
            cache_mgr,
            service: Arc::new(nbd_service),

            bti,
            id,
            supervisor,

            nbd_threads: threads,
            nbd_control_thread: Mutex::new(None),
            nbd_service_threads: Mutex::new(Vec::new()),
            state: AtomicI32::new(DaemonState::INIT as i32),
            request_sender: Arc::new(Mutex::new(trigger)),
            result_receiver: Mutex::new(receiver),
            state_machine_thread: Mutex::new(None),
            waker,
        })
    }
}

impl DaemonStateMachineSubscriber for NbdDaemon {
    fn on_event(&self, event: DaemonStateMachineInput) -> NydusResult<()> {
        self.request_sender
            .lock()
            .expect("block_nbd: failed to lock request sender!")
            .send(event)
            .map_err(NydusError::ChannelSend)?;

        self.result_receiver
            .lock()
            .expect("block_nbd: failed to lock result receiver!")
            .recv()
            .map_err(NydusError::ChannelReceive)?
    }
}

impl NydusDaemon for NbdDaemon {
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
        info!("start NBD service with {} worker threads", self.nbd_threads);
        for _ in 0..self.nbd_threads {
            let waker = self.waker.clone();
            let worker = self
                .service
                .create_worker()
                .map_err(|e| NydusError::StartService(format!("{}", e)))?;
            let thread = std::thread::Builder::new()
                .name("nbd_worker".to_string())
                .spawn(move || {
                    tokio_uring::start(async move {
                        worker.run().await;
                        // Notify the daemon controller that one working thread has exited.
                        if let Err(err) = waker.wake() {
                            error!("block_nbd: fail to exit daemon, error: {:?}", err);
                        }
                    });
                    Ok(())
                })
                .map_err(NydusError::ThreadSpawn)?;
            self.nbd_service_threads.lock().unwrap().push(thread);
        }

        let nbd = self.service.clone();
        let thread = std::thread::spawn(move || {
            if let Err(e) = nbd.run() {
                error!("block_nbd: failed to run NBD control loop, {e}");
            }
        });
        *self.nbd_control_thread.lock().unwrap() = Some(thread);

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
            let handle = self.nbd_service_threads.lock().unwrap().pop();
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
        unimplemented!()
    }

    fn restore(&self) -> NydusResult<()> {
        unimplemented!()
    }

    fn get_blob_cache_mgr(&self) -> Option<Arc<BlobCacheMgr>> {
        Some(self.cache_mgr.clone())
    }
}

/// Create and start a [NbdDaemon] instance to expose a RAFS v6 image as a block device through NBD.
#[allow(clippy::too_many_arguments)]
pub fn create_nbd_daemon(
    device: String,
    threads: u32,
    blob_entry: BlobCacheEntry,
    bti: BuildTimeInfo,
    id: Option<String>,
    supervisor: Option<String>,
    waker: Arc<Waker>,
) -> Result<Arc<dyn NydusDaemon>> {
    let (trigger, events_rx) = std::sync::mpsc::channel::<DaemonStateMachineInput>();
    let (result_sender, result_receiver) = std::sync::mpsc::channel::<NydusResult<()>>();
    let daemon = NbdDaemon::new(
        device,
        threads,
        blob_entry,
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

    /*
    // TODO: support crash recover and hot-upgrade.
    // Without api socket, nydusd can't do neither live-upgrade nor failover, so the helper
    // finding a victim is not necessary.
    if (api_sock.as_ref().is_some() && !upgrade && !is_crashed(&mnt, api_sock.as_ref().unwrap())?)
        || api_sock.is_none()
    {
        if let Some(cmd) = mount_cmd {
            daemon.service.mount(cmd)?;
        }
        daemon
            .service
            .session
            .lock()
            .unwrap()
            .mount()
            .map_err(|e| eother!(e))?;
        daemon
            .on_event(DaemonStateMachineInput::Mount)
            .map_err(|e| eother!(e))?;
        daemon
            .on_event(DaemonStateMachineInput::Start)
            .map_err(|e| eother!(e))?;
        daemon
            .service
            .conn
            .store(calc_fuse_conn(mnt)?, Ordering::Relaxed);
    }
     */

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

    fn create_block_device(tmpdir: PathBuf) -> Result<Arc<BlockDevice>> {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/blobs/be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef");
        let mut dest_path = tmpdir.clone();
        dest_path.push("be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef");
        fs::copy(&source_path, &dest_path).unwrap();

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
                "metadata_path": "RAFS_V5"
            }
          }"#;
        let content = config
            .replace("/tmp/nydus", tmpdir.as_path().to_str().unwrap())
            .replace("RAFS_V5", &source_path.display().to_string());
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
        let device = BlockDevice::new(blob_id.clone(), mgr).unwrap();

        Ok(Arc::new(device))
    }

    #[ignore]
    #[test]
    fn test_nbd_device() {
        tokio_uring::start(async {
            let tmpdir = TempDir::new().unwrap();
            let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
            let nbd = NbdService::new(device, "/dev/nbd15".to_string()).unwrap();
            let nbd = Arc::new(nbd);
            let nbd2 = nbd.clone();
            let worker1 = nbd.create_worker().unwrap();
            let worker2 = nbd.create_worker().unwrap();

            tokio_uring::spawn(async move { worker1.run().await });
            tokio_uring::spawn(async move { worker2.run().await });
            std::thread::spawn(move || {
                nbd2.run().unwrap();
            });
            tokio::time::sleep(Duration::from_micros(100000)).await;
            nbd.stop();
        })
    }
}
