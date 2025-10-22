// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Nydus FUSE filesystem daemon.

use core::option::Option::None;
use nydus_rafs::metadata::{RafsInode, RafsInodeWalkAction};
use std::any::Any;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::metadata;
use std::io::{Error, ErrorKind, Result, Write};
use std::ops::Deref;
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "macos")]
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
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
use fuse_backend_rs::transport::{FuseChannel, FuseSession, FuseSessionExt};
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
use crate::{Error as NydusError, FsBackendType, FuseNotifyError, Result as NydusResult};

const FS_IDX_SHIFT: u64 = 56;

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

struct FusedevNotifier<'a> {
    session: &'a Mutex<FuseSession>,
    server: &'a Arc<Server<Arc<Vfs>>>,
}

impl<'a> FusedevNotifier<'a> {
    fn new(session: &'a Mutex<FuseSession>, server: &'a Arc<Server<Arc<Vfs>>>) -> Self {
        FusedevNotifier { session, server }
    }

    fn notify_resend(&self) -> NydusResult<()> {
        let mut session = self.session.lock().unwrap();
        session
            .try_with_writer(|writer| {
                self.server
                    .notify_resend(writer)
                    .map_err(FuseNotifyError::FuseWriteError)
            })
            .map_err(NydusError::NotifyError)
    }
}

struct FuseSysfsNotifier<'a> {
    conn: &'a AtomicU64,
}

impl<'a> FuseSysfsNotifier<'a> {
    fn new(conn: &'a AtomicU64) -> Self {
        Self { conn }
    }

    fn get_possible_base_paths() -> Vec<&'static str> {
        vec!["/proc/sys/fs/fuse/connections", "/sys/fs/fuse/connections"]
    }

    fn try_notify_with_path(
        &self,
        base_path: &str,
        event: &str,
    ) -> std::result::Result<(), FuseNotifyError> {
        let path = PathBuf::from(base_path)
            .join(self.conn.load(Ordering::Acquire).to_string())
            .join(event);

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .map_err(FuseNotifyError::SysfsOpenError)?;

        file.write_all(b"1")
            .map_err(FuseNotifyError::SysfsWriteError)?;
        Ok(())
    }

    fn notify(&self, event: &str) -> NydusResult<()> {
        let paths = Self::get_possible_base_paths();

        for (idx, path) in paths.iter().enumerate() {
            match self.try_notify_with_path(path, event) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if !matches!(e, FuseNotifyError::SysfsOpenError(_)) || idx == paths.len() - 1 {
                        return Err(e.into());
                    }
                }
            }
        }

        Ok(())
    }

    fn notify_resend(&self) -> NydusResult<()> {
        self.notify("resend")
    }

    fn notify_flush(&self) -> NydusResult<()> {
        self.notify("flush")
    }
}

#[allow(dead_code)]
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

    pub fn drain_fuse_requests(&self) -> NydusResult<()> {
        let fusedev_notifier = FusedevNotifier::new(&self.session, &self.server);
        let sysfs_notifier = FuseSysfsNotifier::new(&self.conn);

        match self.failover_policy {
            FailoverPolicy::None => Ok(()),
            FailoverPolicy::Flush => sysfs_notifier.notify_flush(),
            FailoverPolicy::Resend => fusedev_notifier.notify_resend().or_else(|e| {
                error!(
                    "Failed to notify resend by /dev/fuse, {:?}. Trying to do it by sysfs",
                    e
                );
                sysfs_notifier.notify_resend()
            }),
        }
    }
}

impl FsService for FusedevFsService {
    fn get_vfs(&self) -> &Vfs {
        &self.vfs
    }

    fn upgrade_mgr(&self) -> Option<MutexGuard<'_, UpgradeManager>> {
        self.upgrade_mgr.as_ref().map(|mgr| mgr.lock().unwrap())
    }

    fn backend_collection(&self) -> MutexGuard<'_, FsBackendCollection> {
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

    /// Recursively walk the inode tree and send cache invalidation notifications.
    fn walk_and_notify_invalidation(
        &self,
        parent_kernel_ino: u64,
        cur_name: &str,
        cur_inode: Arc<dyn RafsInode>,
        fs_idx: u8,
    ) -> NydusResult<()> {
        let cur_kernel_ino = ((fs_idx as u64) << FS_IDX_SHIFT) | cur_inode.ino();

        if cur_inode.is_dir() {
            let mut handler =
                |child: Option<Arc<dyn RafsInode>>, name: OsString, _ino: u64, _offset: u64| {
                    if name != OsStr::new(".") && name != OsStr::new("..") {
                        if let Some(child_inode) = child {
                            let child_name = name.to_string_lossy().to_string();
                            // Recursive call
                            if let Err(e) = self.walk_and_notify_invalidation(
                                cur_kernel_ino,
                                &child_name,
                                child_inode,
                                fs_idx,
                            ) {
                                warn!("recursive walk failed for {}: {:?}", child_name, e);
                            }
                        }
                    }
                    Ok(RafsInodeWalkAction::Continue)
                };

            cur_inode.walk_children_inodes(0, &mut handler)?;
        }

        // === Post-order: invalidate cache of the current node ===
        let cstr_name = CString::new(cur_name).map_err(|_| eother!("invalid file name"))?;
        // Invalidate inode cache
        self.session.lock().unwrap().with_writer(|writer| {
            if let Err(e) = self.server.notify_inval_inode(writer, cur_kernel_ino, 0, 0) {
                warn!("notify_inval_inode failed: {} {:?}", cur_name, e);
            }
        });

        self.session.lock().unwrap().with_writer(|writer| {
            if let Err(e) =
                self.server
                    .notify_inval_entry(writer, parent_kernel_ino, cstr_name.as_c_str())
            {
                warn!("notify_inval_entry failed: {} {:?}", cur_name, e);
            }
        });

        Ok(())
    }

    /// Check whether the filesystem service is a FUSE service.
    fn is_fuse(&self) -> bool {
        true
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
    pub supervisor: Option<String>,
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
    let st = metadata(mp.as_ref()).inspect_err(|e| {
        error!("Stat mountpoint {:?}, {}", mp.as_ref(), &e);
    })?;
    Ok(st.dev())
}

#[cfg(target_os = "linux")]
fn calc_fuse_conn(mp: impl AsRef<Path>) -> Result<u64> {
    let st = metadata(mp.as_ref()).inspect_err(|e| {
        error!("Stat mountpoint {:?}, {}", mp.as_ref(), &e);
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
            daemon.service.mount(cmd).map_err(|e| {
                error!("service mount error: {}", &e);
                eother!(e)
            })?;
        }
        daemon
            .service
            .session
            .lock()
            .unwrap()
            .mount()
            .map_err(|e| {
                error!("service session mount error: {}", &e);
                eother!(e)
            })?;

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

        if let Some(f) = daemon.service.session.lock().unwrap().get_fuse_file() {
            if let Some(mut m) = daemon.service.upgrade_mgr() {
                m.hold_file(f).map_err(|e| {
                    error!("Failed to hold fusedev fd, {:?}", e);
                    eother!(e)
                })?;
                m.save_fuse_cid(daemon.service.conn.load(Ordering::Acquire));
            }
        }
    }

    Ok(daemon)
}

/// Create vfs backend with rafs or passthrough as the fuse filesystem driver
#[cfg(target_os = "macos")]
pub fn create_vfs_backend(
    _fs_type: FsBackendType,
    _is_fuse: bool,
    _hybrid_mode: bool,
) -> Result<Arc<Vfs>> {
    let vfs = fuse_backend_rs::api::Vfs::new(fuse_backend_rs::api::VfsOptions::default());
    Ok(Arc::new(vfs))
}

#[cfg(target_os = "linux")]
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
