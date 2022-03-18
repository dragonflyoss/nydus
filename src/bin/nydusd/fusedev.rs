// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::any::Any;
use std::ffi::{CStr, CString};
use std::fs::metadata;
use std::io::Result;
use std::ops::Deref;
use std::os::linux::fs::MetadataExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{
    atomic::{AtomicI32, AtomicU64, Ordering},
    mpsc::{channel, Receiver},
    Arc, Mutex, MutexGuard,
};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use fuse_backend_rs::abi::linux_abi::{InHeader, OutHeader};
use fuse_backend_rs::api::server::{MetricsHook, Server};
use fuse_backend_rs::api::Vfs;
use fuse_backend_rs::transport::fusedev::{FuseChannel, FuseSession};
use nix::sys::stat::{major, minor};
use nydus_app::BuildTimeInfo;
use serde::Serialize;
use vmm_sys_util::eventfd::EventFd;

use crate::daemon::{
    DaemonError, DaemonResult, DaemonState, DaemonStateMachineContext, DaemonStateMachineInput,
    DaemonStateMachineSubscriber, FsBackendCollection, FsBackendMountCmd, NydusDaemon, Trigger,
};
use crate::exit_event_manager;
use crate::upgrade::{self, FailoverPolicy, UpgradeManager};

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
    fn new(server: Arc<Server<Arc<Vfs>>>, se: &FuseSession, evtfd: EventFd) -> Result<FuseServer> {
        Ok(FuseServer {
            server,
            ch: se.new_channel(evtfd)?,
        })
    }

    fn svc_loop(&mut self, metrics_hook: &dyn MetricsHook) -> Result<()> {
        // Given error EBADF, it means kernel has shut down this session.
        let _ebadf = std::io::Error::from_raw_os_error(libc::EBADF);

        loop {
            if let Some((reader, writer)) = self
                .ch
                .get_request()
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?
            {
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

pub struct FusedevDaemon {
    /// Fuse connection ID which usually equals to `st_dev`
    pub conn: AtomicU64,
    pub failover_policy: FailoverPolicy,
    pub session: Mutex<FuseSession>,

    bti: BuildTimeInfo,
    id: Option<String>,
    supervisor: Option<String>,
    vfs: Arc<Vfs>,
    threads_cnt: u32,

    event_fd: EventFd,
    state: AtomicI32,
    server: Arc<Server<Arc<Vfs>>>,
    upgrade_mgr: Option<Mutex<UpgradeManager>>,

    backend_collection: Mutex<FsBackendCollection>,
    inflight_ops: Mutex<Vec<FuseOpWrapper>>,
    result_receiver: Mutex<Receiver<DaemonResult<()>>>,
    trigger: Arc<Mutex<Trigger>>,
    threads: Mutex<Vec<JoinHandle<Result<()>>>>,
}

impl FusedevDaemon {
    fn kick_one_server(&self) -> Result<()> {
        // Clone event fd must succeed, otherwise fusedev daemon should not work.
        let evtfd = self.event_fd.try_clone()?;
        let mut s = FuseServer::new(
            self.server.clone(),
            self.session.lock().unwrap().deref(),
            evtfd,
        )?;

        let inflight_op = self.create_inflight_op();
        let thread = thread::Builder::new()
            .name("fuse_server".to_string())
            .spawn(move || {
                let _ = s.svc_loop(&inflight_op);
                exit_event_manager();
                Ok(())
            })
            .map_err(DaemonError::ThreadSpawn)?;

        self.threads.lock().unwrap().push(thread);

        Ok(())
    }

    fn create_inflight_op(&self) -> FuseOpWrapper {
        let inflight_op = FuseOpWrapper::default();

        // "Not expected poisoned lock"
        self.inflight_ops.lock().unwrap().push(inflight_op.clone());

        inflight_op
    }
}

impl DaemonStateMachineSubscriber for FusedevDaemon {
    fn on_event(&self, event: DaemonStateMachineInput) -> DaemonResult<()> {
        self.trigger
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

    fn start(&self) -> DaemonResult<()> {
        for _ in 0..self.threads_cnt {
            self.kick_one_server()
                .map_err(|e| DaemonError::StartService(format!("{:?}", e)))?;
        }

        Ok(())
    }

    fn wait(&self) -> DaemonResult<()> {
        let mut guard = self.threads.lock().unwrap();

        while let Some(handle) = guard.pop() {
            handle
                .join()
                .map_err(|e| {
                    DaemonError::WaitDaemon(
                        *e.downcast::<std::io::Error>()
                            .unwrap_or_else(|e| Box::new(eother!(e))),
                    )
                })?
                .map_err(DaemonError::WaitDaemon)?;
        }

        Ok(())
    }

    fn disconnect(&self) -> DaemonResult<()> {
        self.session
            .lock()
            .expect("Not expect poisoned lock.")
            .umount()
            .map_err(DaemonError::SessionShutdown)
    }

    #[inline]
    fn id(&self) -> Option<String> {
        self.id.clone()
    }

    #[inline]
    fn supervisor(&self) -> Option<String> {
        self.supervisor.clone()
    }

    #[inline]
    fn interrupt(&self) {
        self.event_fd.write(1).expect("Stop fuse service loop");
    }

    #[inline]
    fn set_state(&self, state: DaemonState) {
        self.state.store(state as i32, Ordering::Relaxed);
    }

    #[inline]
    fn get_state(&self) -> DaemonState {
        self.state.load(Ordering::Relaxed).into()
    }

    fn save(&self) -> DaemonResult<()> {
        upgrade::fusedev_upgrade::save(self)
    }

    fn restore(&self) -> DaemonResult<()> {
        upgrade::fusedev_upgrade::restore(self)
    }

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

    fn version(&self) -> BuildTimeInfo {
        self.bti.clone()
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

// TODO: Perhaps, we can't rely on `/proc/self/mounts` to tell if it is mounted.
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
pub fn create_nydus_daemon(
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
) -> Result<Arc<dyn NydusDaemon + Send + Sync>> {
    let mnt = Path::new(mountpoint).canonicalize()?;
    let session = FuseSession::new(&mnt, "rafs", "", readonly)?;

    // Create upgrade manager
    let upgrade_mgr = supervisor
        .as_ref()
        .map(|s| Mutex::new(UpgradeManager::new(s.to_string().into())));

    let (trigger, events_rx) = channel::<DaemonStateMachineInput>();
    let (result_sender, result_receiver) = channel::<DaemonResult<()>>();

    let daemon = Arc::new(FusedevDaemon {
        conn: AtomicU64::new(0),
        failover_policy: fp,
        session: Mutex::new(session),

        bti,
        id,
        supervisor,
        threads_cnt,
        vfs: vfs.clone(),

        event_fd: EventFd::new(0).unwrap(),
        state: AtomicI32::new(DaemonState::INIT as i32),
        server: Arc::new(Server::new(vfs)),
        upgrade_mgr,

        backend_collection: Default::default(),
        inflight_ops: Mutex::new(Vec::new()),
        result_receiver: Mutex::new(result_receiver),
        trigger: Arc::new(Mutex::new(trigger)),
        threads: Mutex::new(Vec::new()),
    });

    let machine = DaemonStateMachineContext::new(daemon.clone(), events_rx, result_sender);
    machine.kick_state_machine()?;

    // Without api socket, nydusd can't do neither live-upgrade nor failover, so the helper
    // finding a victim is not necessary.
    if (api_sock.as_ref().is_some() && !upgrade && !is_crashed(&mnt, api_sock.as_ref().unwrap())?)
        || api_sock.is_none()
    {
        if let Some(cmd) = mount_cmd {
            daemon.mount(cmd)?;
        }
        daemon.session.lock().unwrap().mount()?;
        daemon
            .on_event(DaemonStateMachineInput::Mount)
            .map_err(|e| eother!(e))?;
        daemon.conn.store(calc_fuse_conn(mnt)?, Ordering::Relaxed);
    }

    Ok(daemon)
}
