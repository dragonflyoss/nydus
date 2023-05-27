// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Nydus FUSE filesystem daemon.

use std::any::Any;
use std::ffi::{CStr, CString};
use std::fs::metadata;
use std::io::{Error, ErrorKind, Result};
use std::ops::Deref;
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "macos")]
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{
    atomic::{AtomicI32, AtomicU64, Ordering},
    mpsc::{channel, Receiver, Sender},
    Arc, Mutex, MutexGuard,
};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use fuse_backend_rs::abi::fuse_abi::{InHeader, OutHeader};
use fuse_backend_rs::api::server::{MetricsHook, Server};
use fuse_backend_rs::api::Vfs;
use fuse_backend_rs::transport::{FuseChannel, FuseSession};
use mio::Waker;
#[cfg(target_os = "linux")]
use nix::sys::stat::{major, minor};
use nydus_api::BuildTimeInfo;
use serde::Serialize;

use crate::daemon::{
    DaemonState, DaemonStateMachineContext, DaemonStateMachineInput, DaemonStateMachineSubscriber,
    NydusDaemon,
};
use crate::fs_service::{FsBackendCollection, FsBackendMountCmd, FsService};
use crate::upgrade::{self, FailoverPolicy, UpgradeManager};
use crate::{Error as NydusError, FsBackendType, Result as NydusResult};

#[derive(Serialize)]
struct FuseOp {
    inode: u64,
    opcode: u32,
    unique: u64,
    timestamp_secs: u64,
}

impl Default for FuseOp {
    fn default() -> Self {
        // unwrap because time can't be earlier than EPOCH.
        let timestamp_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            inode: u64::default(),
            opcode: u32::default(),
            unique: u64::default(),
            timestamp_secs,
        }
    }
}

#[derive(Default, Clone, Serialize)]
struct FuseOpWrapper {
    // Mutex should be acceptable since `inflight_op` is always updated
    // within the same thread, which means locking is always directly acquired.
    op: Arc<Mutex<Option<FuseOp>>>,
}

impl MetricsHook for FuseOpWrapper {
    fn collect(&self, ih: &InHeader) {
        let (n, u, o) = (ih.nodeid, ih.unique, ih.opcode);
        // Unwrap is safe because time can't be earlier than EPOCH
        let timestamp_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let op = FuseOp {
            inode: n,
            unique: u,
            opcode: o,
            timestamp_secs,
        };

        *self.op.lock().expect("Not expect poisoned lock") = Some(op);
    }

    fn release(&self, _oh: Option<&OutHeader>) {
        *self.op.lock().expect("Not expect poisoned lock") = None
    }
}

struct FuseServer {
    server: Arc<Server<Arc<Vfs>>>,
    ch: FuseChannel,
}

impl FuseServer {
    fn new(server: Arc<Server<Arc<Vfs>>>, se: &FuseSession) -> Result<FuseServer> {
        let ch = se.new_channel().map_err(|e| eother!(e))?;
        Ok(FuseServer { server, ch })
    }

    fn svc_loop(&mut self, metrics_hook: &dyn MetricsHook) -> Result<()> {
        // Given error EBADF, it means kernel has shut down this session.
        let _ebadf = Error::from_raw_os_error(libc::EBADF);

        loop {
            if let Some((reader, writer)) = self.ch.get_request().map_err(|e| {
                Error::new(
                    ErrorKind::Other,
                    format!("failed to get fuse request from /dev/fuse, {}", e),
                )
            })? {
                if let Err(e) =
                    self.server
                        .handle_message(reader, writer.into(), None, Some(metrics_hook))
                {
                    match e {
                        fuse_backend_rs::Error::EncodeMessage(_ebadf) => {
                            return Err(eio!("fuse session has been shut down"));
                        }
                        _ => {
                            error!("Handling fuse message, {}", NydusError::ProcessQueue(e));
                            continue;
                        }
                    }
                }
            } else {
                info!("fuse server exits");
                break;
            }
        }

        Ok(())
    }
}

struct FusedevFsService {
    /// Fuse connection ID which usually equals to `st_dev`
    pub conn: AtomicU64,
    #[allow(dead_code)]
    pub failover_policy: FailoverPolicy,
    pub session: Mutex<FuseSession>,

    server: Arc<Server<Arc<Vfs>>>,
    upgrade_mgr: Option<Mutex<UpgradeManager>>,
    vfs: Arc<Vfs>,

    backend_collection: Mutex<FsBackendCollection>,
    inflight_ops: Mutex<Vec<FuseOpWrapper>>,
}

impl FusedevFsService {
    fn new(
        vfs: Arc<Vfs>,
        mnt: &Path,
        supervisor: Option<&String>,
        failover_policy: FailoverPolicy,
        readonly: bool,
    ) -> Result<Self> {
        let session = FuseSession::new(mnt, "rafs", "", readonly).map_err(|e| eother!(e))?;
        let upgrade_mgr = supervisor
            .as_ref()
            .map(|s| Mutex::new(UpgradeManager::new(s.to_string().into())));

        Ok(FusedevFsService {
            vfs: vfs.clone(),
            conn: AtomicU64::new(0),
            failover_policy,
            session: Mutex::new(session),
            server: Arc::new(Server::new(vfs)),
            upgrade_mgr,

            backend_collection: Default::default(),
            inflight_ops: Default::default(),
        })
    }

    fn create_fuse_server(&self) -> Result<FuseServer> {
        FuseServer::new(self.server.clone(), self.session.lock().unwrap().deref())
    }

    fn create_inflight_op(&self) -> FuseOpWrapper {
        let inflight_op = FuseOpWrapper::default();

        // "Not expected poisoned lock"
        self.inflight_ops.lock().unwrap().push(inflight_op.clone());

        inflight_op
    }

    fn umount(&self) -> NydusResult<()> {
        let mut session = self.session.lock().expect("Not expect poisoned lock.");
        session.umount().map_err(NydusError::SessionShutdown)?;
        session.wake().map_err(NydusError::SessionShutdown)?;
        Ok(())
    }
}

impl FsService for FusedevFsService {
    fn get_vfs(&self) -> &Vfs {
        &self.vfs
    }

    fn upgrade_mgr(&self) -> Option<MutexGuard<UpgradeManager>> {
        self.upgrade_mgr.as_ref().map(|mgr| mgr.lock().unwrap())
    }

    fn backend_collection(&self) -> MutexGuard<FsBackendCollection> {
        self.backend_collection.lock().unwrap()
    }

    fn export_inflight_ops(&self) -> NydusResult<Option<String>> {
        let ops = self.inflight_ops.lock().unwrap();

        let r = ops
            .iter()
            .filter(|w| w.op.lock().unwrap().is_some())
            .map(|w| &w.op)
            .collect::<Vec<&Arc<Mutex<Option<FuseOp>>>>>();

        if r.is_empty() {
            Ok(None)
        } else {
            let resp = serde_json::to_string(&r).map_err(NydusError::Serde)?;
            Ok(Some(resp))
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Nydus daemon to implement FUSE servers by accessing `/dev/fuse`.
///
/// One FUSE mountpoint will be created for each [FusedevDaemon] object. Every [FusedevDaemon]
/// object has a built-in [Vfs](https://docs.rs/fuse-backend-rs/latest/fuse_backend_rs/api/vfs/struct.Vfs.html)
/// object, which can be used to mount multiple RAFS and/or passthroughfs instances.
pub struct FusedevDaemon {
    bti: BuildTimeInfo,
    id: Option<String>,
    request_sender: Arc<Mutex<Sender<DaemonStateMachineInput>>>,
    result_receiver: Mutex<Receiver<NydusResult<()>>>,
    service: Arc<FusedevFsService>,
    state: AtomicI32,
    supervisor: Option<String>,
    threads_cnt: u32,
    state_machine_thread: Mutex<Option<JoinHandle<Result<()>>>>,
    fuse_service_threads: Mutex<Vec<JoinHandle<Result<()>>>>,
    waker: Arc<Waker>,
}

impl FusedevDaemon {
    /// Create a new instance of [FusedevDaemon].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trigger: Sender<DaemonStateMachineInput>,
        receiver: Receiver<NydusResult<()>>,
        vfs: Arc<Vfs>,
        mountpoint: &Path,
        threads_cnt: u32,
        waker: Arc<Waker>,
        bti: BuildTimeInfo,
        id: Option<String>,
        supervisor: Option<String>,
        readonly: bool,
        fp: FailoverPolicy,
    ) -> Result<Self> {
        let service = FusedevFsService::new(vfs, mountpoint, supervisor.as_ref(), fp, readonly)?;

        Ok(FusedevDaemon {
            bti,
            id,
            supervisor,
            threads_cnt,
            waker,

            state: AtomicI32::new(DaemonState::INIT as i32),
            result_receiver: Mutex::new(receiver),
            request_sender: Arc::new(Mutex::new(trigger)),
            service: Arc::new(service),
            state_machine_thread: Mutex::new(None),
            fuse_service_threads: Mutex::new(Vec::new()),
        })
    }

    fn kick_one_server(&self, waker: Arc<Waker>) -> NydusResult<()> {
        let mut s = self
            .service
            .create_fuse_server()
            .map_err(NydusError::CreateFuseServer)?;
        let inflight_op = self.service.create_inflight_op();
        let thread = thread::Builder::new()
            .name("fuse_server".to_string())
            .spawn(move || {
                if let Err(_err) = s.svc_loop(&inflight_op) {
                    // Notify the daemon controller that one working thread has exited.
                    if let Err(err) = waker.wake() {
                        error!("fail to exit daemon, error: {:?}", err);
                    }
                }
                Ok(())
            })
            .map_err(NydusError::ThreadSpawn)?;

        self.fuse_service_threads.lock().unwrap().push(thread);

        Ok(())
    }
}

impl DaemonStateMachineSubscriber for FusedevDaemon {
    fn on_event(&self, event: DaemonStateMachineInput) -> NydusResult<()> {
        self.request_sender
            .lock()
            .unwrap()
            .send(event)
            .map_err(NydusError::ChannelSend)?;

        self.result_receiver
            .lock()
            .expect("Not expect poisoned lock!")
            .recv()
            .map_err(NydusError::ChannelReceive)?
    }
}

impl NydusDaemon for FusedevDaemon {
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
        info!(
            "start fuse servers with {} worker threads",
            self.threads_cnt
        );
        for _ in 0..self.threads_cnt {
            let waker = self.waker.clone();
            self.kick_one_server(waker)
                .map_err(|e| NydusError::StartService(format!("{}", e)))?;
        }

        Ok(())
    }

    fn umount(&self) -> NydusResult<()> {
        self.service.umount()
    }

    fn stop(&self) {
        let session = self
            .service
            .session
            .lock()
            .expect("Not expect poisoned lock.");
        if let Err(e) = session.wake().map_err(NydusError::SessionShutdown) {
            error!("failed to stop FUSE service thread: {:?}", e);
        }
    }

    fn wait(&self) -> NydusResult<()> {
        self.wait_state_machine()?;
        self.wait_service()
    }

    fn wait_service(&self) -> NydusResult<()> {
        loop {
            let handle = self.fuse_service_threads.lock().unwrap().pop();
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
        upgrade::fusedev_upgrade::save(self)
    }

    fn restore(&self) -> NydusResult<()> {
        upgrade::fusedev_upgrade::restore(self)
    }

    fn get_default_fs_service(&self) -> Option<Arc<dyn FsService>> {
        Some(self.service.clone())
    }
}

#[cfg(target_os = "macos")]
fn is_mounted(mp: impl AsRef<Path>) -> Result<bool> {
    let mp = mp
        .as_ref()
        .to_str()
        .ok_or_else(|| Error::from_raw_os_error(libc::EINVAL))?;
    let mp = CString::new(String::from(mp)).map_err(|_| Error::from_raw_os_error(libc::EINVAL))?;
    let mut mpb: Vec<libc::statfs> = Vec::new();
    let mut mpb_ptr = mpb.as_mut_ptr();
    let mpb_ptr = &mut mpb_ptr;

    let mpb: Vec<libc::statfs> = unsafe {
        let res = libc::getmntinfo(mpb_ptr, libc::MNT_NOWAIT);
        if res < 0 {
            return Err(Error::from_raw_os_error(res));
        }
        let size = res as usize;
        Vec::from_raw_parts(*mpb_ptr, size, size)
    };
    let match_mp = mpb.iter().find(|mp_stat| unsafe {
        let mp_name = CStr::from_ptr(&mp_stat.f_mntonname as *const i8);
        let mp = CStr::from_ptr(mp.as_ptr());
        mp.eq(mp_name)
    });

    Ok(match_mp.is_some())
}

// TODO: Perhaps, we can't rely on `/proc/self/mounts` to tell if it is mounted.
#[cfg(target_os = "linux")]
fn is_mounted(mp: impl AsRef<Path>) -> Result<bool> {
    let mounts = CString::new("/proc/self/mounts").unwrap();
    let ty = CString::new("r").unwrap();

    let mounts_stream = unsafe {
        libc::setmntent(
            mounts.as_ptr() as *const libc::c_char,
            ty.as_ptr() as *const libc::c_char,
        )
    };

    loop {
        let mnt = unsafe { libc::getmntent(mounts_stream) };
        if mnt as u32 == libc::PT_NULL {
            break;
        }

        // Mount point path
        if unsafe { CStr::from_ptr((*mnt).mnt_dir) }
            == CString::new(mp.as_ref().as_os_str().as_bytes())?.as_c_str()
        {
            unsafe { libc::endmntent(mounts_stream) };
            return Ok(true);
        }
    }

    unsafe { libc::endmntent(mounts_stream) };

    Ok(false)
}

fn is_sock_residual(sock: impl AsRef<Path>) -> bool {
    if metadata(&sock).is_ok() {
        return UnixStream::connect(&sock).is_err();
    }

    false
}

/// When nydusd starts, it checks that whether a previous nydusd died unexpected by:
///     1. Checking whether the mount point is residual by retrieving `/proc/self/mounts`.
///     2. Checking whether the API socket exists and the connection can established or not.
fn is_crashed(path: impl AsRef<Path>, sock: &impl AsRef<Path>) -> Result<bool> {
    if is_mounted(path)? && is_sock_residual(sock) {
        warn!("A previous daemon crashed! Try to failover later.");
        return Ok(true);
    }

    Ok(false)
}

#[cfg(target_os = "macos")]
fn calc_fuse_conn(mp: impl AsRef<Path>) -> Result<u64> {
    let st = metadata(mp.as_ref()).map_err(|e| {
        error!("Stat mountpoint {:?}, {}", mp.as_ref(), &e);
        e
    })?;
    Ok(st.dev())
}

#[cfg(target_os = "linux")]
fn calc_fuse_conn(mp: impl AsRef<Path>) -> Result<u64> {
    let st = metadata(mp.as_ref()).map_err(|e| {
        error!("Stat mountpoint {:?}, {}", mp.as_ref(), &e);
        e
    })?;
    let dev = st.st_dev();
    let (major, minor) = (major(dev), minor(dev));

    // According to kernel formula:  MKDEV(ma,mi) (((ma) << 20) | (mi))
    Ok(major << 20 | minor)
}

/// Create and start a [FusedevDaemon] instance.
#[allow(clippy::too_many_arguments)]
pub fn create_fuse_daemon(
    mountpoint: &str,
    vfs: Arc<Vfs>,
    supervisor: Option<String>,
    id: Option<String>,
    threads_cnt: u32,
    waker: Arc<Waker>,
    api_sock: Option<impl AsRef<Path>>,
    upgrade: bool,
    readonly: bool,
    fp: FailoverPolicy,
    mount_cmd: Option<FsBackendMountCmd>,
    bti: BuildTimeInfo,
) -> Result<Arc<dyn NydusDaemon>> {
    let mnt = Path::new(mountpoint).canonicalize()?;
    let (trigger, events_rx) = channel::<DaemonStateMachineInput>();
    let (result_sender, result_receiver) = channel::<NydusResult<()>>();
    let daemon = FusedevDaemon::new(
        trigger,
        result_receiver,
        vfs,
        &mnt,
        threads_cnt,
        waker,
        bti,
        id,
        supervisor,
        readonly,
        fp,
    )?;
    let daemon = Arc::new(daemon);
    let machine = DaemonStateMachineContext::new(daemon.clone(), events_rx, result_sender);
    let machine_thread = machine.kick_state_machine()?;
    *daemon.state_machine_thread.lock().unwrap() = Some(machine_thread);

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

    Ok(daemon)
}

/// Create vfs backend with rafs or passthrough as the fuse filesystem driver
pub fn create_vfs_backend(
    fs_type: FsBackendType,
    is_fuse: bool,
    hybrid_mode: bool,
) -> Result<Arc<Vfs>> {
    let mut opts = fuse_backend_rs::api::VfsOptions::default();
    match fs_type {
        FsBackendType::PassthroughFs => {
            // passthroughfs requires !no_open
            opts.no_open = false;
            opts.no_opendir = false;
            opts.killpriv_v2 = true;
        }
        FsBackendType::Rafs => {
            // rafs can be readonly and skip open
            opts.no_open = true;
        }
    };

    if !is_fuse && hybrid_mode {
        opts.no_open = false;
        opts.no_opendir = false;
        opts.killpriv_v2 = true;
    }

    let vfs = fuse_backend_rs::api::Vfs::new(opts);
    Ok(Arc::new(vfs))
}
