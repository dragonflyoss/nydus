// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::any::Any;
use std::ffi::{CStr, CString};
use std::fs::metadata;
use std::io::{Error, Result};
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
use fuse_backend_rs::transport::fusedev::{FuseChannel, FuseSession};
use mio::Waker;
#[cfg(target_os = "linux")]
use nix::sys::stat::{major, minor};
use nydus_app::BuildTimeInfo;
use serde::Serialize;

use crate::daemon::{
    DaemonError, DaemonResult, DaemonState, DaemonStateMachineContext, DaemonStateMachineInput,
    DaemonStateMachineSubscriber, NydusDaemon,
};
use crate::fs_service::{FsBackendCollection, FsBackendMountCmd, FsService};
use crate::upgrade::{self, FailoverPolicy, UpgradeManager};
use crate::DAEMON_CONTROLLER;

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
        Ok(FuseServer {
            server,
            ch: se.new_channel()?,
        })
    }

    fn svc_loop(&mut self, metrics_hook: &dyn MetricsHook) -> Result<()> {
        // Given error EBADF, it means kernel has shut down this session.
        let _ebadf = Error::from_raw_os_error(libc::EBADF);

        loop {
            if let Some((reader, writer)) = self.ch.get_request().map_err(|e| {
                warn!("get fuse request failed: {:?}", e);
                Error::from_raw_os_error(libc::EINVAL)
            })? {
                if let Err(e) = self
                    .server
                    .handle_message(reader, writer, None, Some(metrics_hook))
                {
                    match e {
                        fuse_backend_rs::Error::EncodeMessage(_ebadf) => {
                            return Err(eio!("fuse session has been shut down"));
                        }
                        _ => {
                            error!("Handling fuse message, {}", DaemonError::ProcessQueue(e));
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

pub struct FusedevFsService {
    /// Fuse connection ID which usually equals to `st_dev`
    pub conn: AtomicU64,
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
        fp: FailoverPolicy,
        readonly: bool,
    ) -> Result<Self> {
        let session = FuseSession::new(mnt, "rafs", "", readonly)?;
        let upgrade_mgr = supervisor
            .as_ref()
            .map(|s| Mutex::new(UpgradeManager::new(s.to_string().into())));

        Ok(FusedevFsService {
            vfs: vfs.clone(),
            conn: AtomicU64::new(0),
            failover_policy: fp,
            session: Mutex::new(session),
            server: Arc::new(Server::new(vfs)),
            upgrade_mgr,

            backend_collection: Default::default(),
            inflight_ops: Mutex::new(Vec::new()),
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

    fn disconnect(&self) -> DaemonResult<()> {
        let mut session = self.session.lock().expect("Not expect poisoned lock.");
        session.umount().map_err(DaemonError::SessionShutdown)?;
        session.wake().map_err(DaemonError::SessionShutdown)?;
        Ok(())
    }
}

impl FsService for FusedevFsService {
    #[inline]
    fn get_vfs(&self) -> &Vfs {
        &self.vfs
    }

    #[inline]
    fn upgrade_mgr(&self) -> Option<MutexGuard<UpgradeManager>> {
        self.upgrade_mgr.as_ref().map(|mgr| mgr.lock().unwrap())
    }

    fn backend_collection(&self) -> MutexGuard<FsBackendCollection> {
        self.backend_collection.lock().unwrap()
    }

    fn export_inflight_ops(&self) -> DaemonResult<Option<String>> {
        let ops = self.inflight_ops.lock().unwrap();

        let r = ops
            .iter()
            .filter(|w| w.op.lock().unwrap().is_some())
            .map(|w| &w.op)
            .collect::<Vec<&Arc<Mutex<Option<FuseOp>>>>>();

        if r.is_empty() {
            Ok(None)
        } else {
            let resp = serde_json::to_string(&r).map_err(DaemonError::Serde)?;
            Ok(Some(resp))
        }
    }
}

pub struct FusedevDaemon {
    bti: BuildTimeInfo,
    id: Option<String>,
    request_sender: Arc<Mutex<Sender<DaemonStateMachineInput>>>,
    result_receiver: Mutex<Receiver<DaemonResult<()>>>,
    service: Arc<FusedevFsService>,
    state: AtomicI32,
    supervisor: Option<String>,
    threads_cnt: u32,
    threads: Mutex<Vec<JoinHandle<Result<()>>>>,
}

impl FusedevDaemon {
    fn kick_one_server(&self, waker: Arc<Waker>) -> Result<()> {
        let mut s = self.service.create_fuse_server()?;
        let inflight_op = self.service.create_inflight_op();
        let thread = thread::Builder::new()
            .name("fuse_server".to_string())
            .spawn(move || {
                let _ = s.svc_loop(&inflight_op);
                // Notify the daemon controller that one working thread has exited.
                let _ = waker.wake();
                Ok(())
            })
            .map_err(DaemonError::ThreadSpawn)?;

        self.threads.lock().unwrap().push(thread);

        Ok(())
    }
}

impl DaemonStateMachineSubscriber for FusedevDaemon {
    fn on_event(&self, event: DaemonStateMachineInput) -> DaemonResult<()> {
        self.request_sender
            .lock()
            .unwrap()
            .send(event)
            .map_err(|e| DaemonError::Channel(format!("send {:?}", e)))?;

        self.result_receiver
            .lock()
            .expect("Not expect poisoned lock!")
            .recv()
            .map_err(|e| DaemonError::Channel(format!("recv {:?}", e)))?
    }
}

impl NydusDaemon for FusedevDaemon {
    #[inline]
    fn as_any(&self) -> &dyn Any {
        self
    }

    #[inline]
    fn id(&self) -> Option<String> {
        self.id.clone()
    }

    #[inline]
    fn get_state(&self) -> DaemonState {
        self.state.load(Ordering::Relaxed).into()
    }

    #[inline]
    fn set_state(&self, state: DaemonState) {
        self.state.store(state as i32, Ordering::Relaxed);
    }

    fn version(&self) -> BuildTimeInfo {
        self.bti.clone()
    }

    fn start(&self) -> DaemonResult<()> {
        info!("start {} fuse servers", self.threads_cnt);
        for _ in 0..self.threads_cnt {
            let waker = DAEMON_CONTROLLER.alloc_waker();
            self.kick_one_server(waker)
                .map_err(|e| DaemonError::StartService(format!("{:?}", e)))?;
        }

        Ok(())
    }

    fn disconnect(&self) -> DaemonResult<()> {
        self.service.disconnect()
    }

    #[inline]
    fn interrupt(&self) {
        let session = self
            .service
            .session
            .lock()
            .expect("Not expect poisoned lock.");
        if let Err(e) = session.wake().map_err(DaemonError::SessionShutdown) {
            error!("stop fuse service thread failed: {:?}", e);
        }
    }

    fn wait(&self) -> DaemonResult<()> {
        loop {
            let handle = self.threads.lock().unwrap().pop();
            if let Some(handle) = handle {
                handle
                    .join()
                    .map_err(|e| {
                        DaemonError::WaitDaemon(
                            *e.downcast::<Error>()
                                .unwrap_or_else(|e| Box::new(eother!(e))),
                        )
                    })?
                    .map_err(DaemonError::WaitDaemon)?;
            } else {
                // No more handles to wait
                break;
            }
        }

        Ok(())
    }

    #[inline]
    fn supervisor(&self) -> Option<String> {
        self.supervisor.clone()
    }

    fn save(&self) -> DaemonResult<()> {
        upgrade::fusedev_upgrade::save(self)
    }

    fn restore(&self) -> DaemonResult<()> {
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
        mp.eq(&mp_name)
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

#[allow(clippy::too_many_arguments)]
pub fn create_fuse_daemon(
    mountpoint: &str,
    vfs: Arc<Vfs>,
    supervisor: Option<String>,
    id: Option<String>,
    threads_cnt: u32,
    api_sock: Option<impl AsRef<Path>>,
    upgrade: bool,
    readonly: bool,
    fp: FailoverPolicy,
    mount_cmd: Option<FsBackendMountCmd>,
    bti: BuildTimeInfo,
) -> Result<Arc<dyn NydusDaemon>> {
    let mnt = Path::new(mountpoint).canonicalize()?;
    let (trigger, events_rx) = channel::<DaemonStateMachineInput>();
    let (result_sender, result_receiver) = channel::<DaemonResult<()>>();
    let service = FusedevFsService::new(vfs, &mnt, supervisor.as_ref(), fp, readonly)?;
    let daemon = Arc::new(FusedevDaemon {
        bti,
        id,
        supervisor,
        threads_cnt,

        state: AtomicI32::new(DaemonState::INIT as i32),
        result_receiver: Mutex::new(result_receiver),
        request_sender: Arc::new(Mutex::new(trigger)),
        service: Arc::new(service),
        threads: Mutex::new(Vec::new()),
    });
    let machine = DaemonStateMachineContext::new(daemon.clone(), events_rx, result_sender);
    let machine_thread = machine.kick_state_machine()?;
    daemon.threads.lock().unwrap().push(machine_thread);

    // Without api socket, nydusd can't do neither live-upgrade nor failover, so the helper
    // finding a victim is not necessary.
    if (api_sock.as_ref().is_some() && !upgrade && !is_crashed(&mnt, api_sock.as_ref().unwrap())?)
        || api_sock.is_none()
    {
        if let Some(cmd) = mount_cmd {
            daemon.service.mount(cmd)?;
        }
        daemon.service.session.lock().unwrap().mount()?;
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
