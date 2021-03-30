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
    mpsc::{channel, Receiver, Sender},
    Arc, Mutex, MutexGuard,
};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use nix::sys::stat::{major, minor};
use serde::Serialize;

use fuse_rs::api::{
    server::{MetricsHook, Server},
    Vfs,
};

use fuse_rs::abi::linux_abi::{InHeader, OutHeader};
use vmm_sys_util::eventfd::EventFd;

use crate::upgrade::{self, FailoverPolicy, UpgradeManager};
use crate::{daemon, exit_event_manager};
use daemon::{
    DaemonError, DaemonResult, DaemonState, DaemonStateMachineContext, DaemonStateMachineInput,
    DaemonStateMachineSubscriber, FsBackendCollection, FsBackendMountCmd, NydusDaemon, Trigger,
};
use nydus_utils::{BuildTimeInfo, FuseChannel, FuseSession};

#[derive(Serialize)]
struct FuseOp {
    inode: u64,
    opcode: u32,
    unique: u64,
    timestamp_secs: u64,
}

#[derive(Default, Clone, Serialize)]
struct FuseOpWrapper {
    op: Arc<Mutex<Option<FuseOp>>>,
}

impl Default for FuseOp {
    fn default() -> Self {
        Self {
            inode: u64::default(),
            opcode: u32::default(),
            unique: u64::default(),
            // unwrap because time can't be earlier than EPOCH.
            timestamp_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

pub(crate) struct FuseServer {
    server: Arc<Server<Arc<Vfs>>>,
    ch: FuseChannel,
    // read buffer for fuse requests
    buf: Vec<u8>,
}

impl FuseServer {
    fn new(server: Arc<Server<Arc<Vfs>>>, se: &FuseSession, evtfd: EventFd) -> Result<FuseServer> {
        Ok(FuseServer {
            server,
            ch: se.new_channel(evtfd)?,
            buf: Vec::with_capacity(se.bufsize()),
        })
    }

    fn svc_loop(&mut self, metrics_hook: &dyn MetricsHook) -> Result<()> {
        // Safe because we have already reserved the capacity
        unsafe {
            self.buf.set_len(self.buf.capacity());
        }

        // Given error EBADF, it means kernel has shut down this session.
        let _ebadf = std::io::Error::from_raw_os_error(libc::EBADF);
        loop {
            if let Some(reader) = self.ch.get_reader(&mut self.buf)? {
                let writer = self.ch.get_writer()?;
                if let Err(e) = self
                    .server
                    .handle_message(reader, writer, None, Some(metrics_hook))
                {
                    match e {
                        fuse_rs::Error::EncodeMessage(_ebadf) => {
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
    server: Arc<Server<Arc<Vfs>>>,
    vfs: Arc<Vfs>,
    pub session: Mutex<FuseSession>,
    thread_tx: Mutex<Option<Sender<JoinHandle<Result<()>>>>>,
    thread_rx: Mutex<Receiver<JoinHandle<Result<()>>>>,
    running_threads: AtomicI32,
    event_fd: EventFd,
    state: AtomicI32,
    pub threads_cnt: u32,
    trigger: Arc<Mutex<Trigger>>,
    result_receiver: Mutex<Receiver<DaemonResult<()>>>,
    pub supervisor: Option<String>,
    pub id: Option<String>,
    /// Fuse connection ID which usually equals to `st_dev`
    pub(crate) conn: AtomicU64,
    #[allow(dead_code)]
    pub(crate) failover_policy: FailoverPolicy,
    upgrade_mgr: Option<Mutex<UpgradeManager>>,
    backend_collection: Mutex<FsBackendCollection>,
    bti: BuildTimeInfo,
    inflight_ops: Mutex<Vec<FuseOpWrapper>>,
}

impl MetricsHook for FuseOpWrapper {
    fn collect(&self, ih: &InHeader) {
        let (n, u, o) = (ih.nodeid, ih.unique, ih.opcode);
        // Mutex should be acceptable since `inflight_op` is always updated
        // within the same thread, which means locking is always directly acquired.
        *self.op.lock().expect("Not expect poisoned lock") = Some(FuseOp {
            inode: n,
            unique: u,
            opcode: o,
            // Unwrap is safe because time can't be earlier than EPOCH
            timestamp_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    fn release(&self, _oh: Option<&OutHeader>) {
        *self.op.lock().expect("Not expect poisoned lock") = None
    }
}

impl FusedevDaemon {
    fn kick_one_server(&self) -> Result<()> {
        let mut s = FuseServer::new(
            self.server.clone(),
            self.session.lock().unwrap().deref(),
            // Clone event fd must succeed, otherwise fusedev daemon should not work.
            self.event_fd.try_clone().unwrap(),
        )?;

        let inflight_op = FuseOpWrapper::default();
        // "Not expected poisoned lock"
        self.inflight_ops.lock().unwrap().push(inflight_op.clone());
        let thread = thread::Builder::new()
            .name("fuse_server".to_string())
            .spawn(move || {
                let _ = s.svc_loop(&inflight_op);
                exit_event_manager();
                // Ignore fuse service error when joining them.
                Ok(())
            })
            .map_err(DaemonError::ThreadSpawn)?;

        // Safe to unwrap because it should be initialized as Some when daemon being created.
        self.thread_tx
            .lock()
            .expect("Not expect poisoned lock.")
            .as_ref()
            .unwrap()
            .send(thread)
            .map_err(|e| eother!(e))?;
        self.running_threads.fetch_add(1, Ordering::AcqRel);
        Ok(())
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

        // Safe to unwrap because it is should be initialized as Some when daemon is being created.
        drop(
            self.thread_tx
                .lock()
                .expect("Not expect poisoned lock")
                .take()
                .unwrap(),
        );
        Ok(())
    }

    fn wait(&self) -> DaemonResult<()> {
        while let Ok(handle) = self.thread_rx.lock().unwrap().recv() {
            self.running_threads.fetch_sub(1, Ordering::AcqRel);
            handle
                .join()
                .map_err(|e| {
                    DaemonError::WaitDaemon(
                        *e.downcast::<std::io::Error>()
                            .unwrap_or_else(|e| Box::new(eother!(e))),
                    )
                })?
                .map_err(DaemonError::WaitDaemon)?
        }
        if self.running_threads.load(Ordering::Acquire) != 0 {
            warn!("Not all threads are joined.");
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

/// When a nydusd starts, it checks the environment to see if a previous nydusd dies beyond expect.
///     1. See if the mount point is residual by retrieving `/proc/self/mounts`.
///     2. See if the API socket exists and the connection can established or not.
fn is_crashed(path: impl AsRef<Path>, sock: &impl AsRef<Path>) -> Result<bool> {
    if is_mounted(path)? && is_sock_residual(sock) {
        warn!("A previous daemon crashed! Try to failover later.");
        return Ok(true);
    }

    Ok(false)
}

fn calc_fuse_conn(mp: impl AsRef<Path>) -> Result<u64> {
    let st = metadata(mp)?;
    let dev = st.st_dev();
    let (major, minor) = (major(dev), minor(dev));
    // According to kernel formula:
    //      MKDEV(ma,mi) (((ma) << 20) | (mi))
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
    fp: FailoverPolicy,
    mount_cmd: Option<FsBackendMountCmd>,
    bti: BuildTimeInfo,
) -> Result<Arc<dyn NydusDaemon + Send>> {
    let (trigger, events_rx) = channel::<DaemonStateMachineInput>();
    let session = FuseSession::new(Path::new(mountpoint), "rafs", "")?;

    // Create upgrade manager
    let upgrade_mgr = if let Some(s) = &supervisor {
        Some(Mutex::new(UpgradeManager::new(s.to_string().into())))
    } else {
        None
    };

    let (tx, rx) = channel::<JoinHandle<Result<()>>>();
    let (result_sender, result_receiver) = channel::<DaemonResult<()>>();

    let daemon = Arc::new(FusedevDaemon {
        session: Mutex::new(session),
        server: Arc::new(Server::new(vfs.clone())),
        vfs,
        thread_tx: Mutex::new(Some(tx)),
        thread_rx: Mutex::new(rx),
        running_threads: AtomicI32::new(0),
        event_fd: EventFd::new(0).unwrap(),
        state: AtomicI32::new(DaemonState::INIT as i32),
        threads_cnt,
        trigger: Arc::new(Mutex::new(trigger)),
        result_receiver: Mutex::new(result_receiver),
        supervisor,
        id,
        conn: AtomicU64::new(0),
        failover_policy: fp,
        upgrade_mgr,
        backend_collection: Default::default(),
        bti,
        inflight_ops: Mutex::new(Vec::new()),
    });

    let machine = DaemonStateMachineContext::new(daemon.clone(), events_rx, result_sender);
    machine.kick_state_machine()?;

    // Without api socket, nydusd can't do neither live-upgrade nor failover, so the helper
    // finding a victim is not necessary.
    if (api_sock.as_ref().is_some()
        && !upgrade
        && !is_crashed(mountpoint, api_sock.as_ref().unwrap())?)
        || api_sock.is_none()
    {
        if let Some(cmd) = mount_cmd {
            daemon.mount(cmd)?;
        }
        daemon.session.lock().unwrap().mount()?;
        daemon
            .on_event(DaemonStateMachineInput::Mount)
            .map_err(|e| eother!(e))?;
        daemon
            .conn
            .store(calc_fuse_conn(mountpoint)?, Ordering::Relaxed);
    }

    Ok(daemon)
}
