// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::any::Any;
use std::io::Result;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::thread;

use fuse_backend_rs::api::{server::Server, Vfs};
use fuse_backend_rs::transport::{FsCacheReqHandler, Reader, Writer};
use vhost::vhost_user::{message::*, Listener, SlaveFsCacheReq};
use vhost_user_backend::{
    VhostUserBackend, VhostUserBackendMut, VhostUserDaemon, VringMutex, VringState, VringT,
};
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use virtio_queue::DescriptorChain;
use vm_memory::{GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use nydus_app::BuildTimeInfo;

use crate::daemon::{
    DaemonError, DaemonResult, DaemonState, DaemonStateMachineContext, DaemonStateMachineInput,
    DaemonStateMachineSubscriber, NydusDaemon,
};
use crate::fs_service::{FsBackendCollection, FsService};
use crate::upgrade::UpgradeManager;
use crate::FsBackendMountCmd;

const VIRTIO_F_VERSION_1: u32 = 32;
const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 2;

// The guest queued an available buffer for the high priority queue.
const HIPRIO_QUEUE_EVENT: u16 = 0;
// The guest queued an available buffer for the request queue.
const REQ_QUEUE_EVENT: u16 = 1;
// The device has been dropped.
// const KILL_EVENT: u16 = 2;

type VhostUserBackendResult<T> = std::io::Result<T>;

struct VhostUserFsBackend {
    event_idx: bool,
    kill_evt: EventFd,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    server: Arc<Server<Arc<Vfs>>>,
    // handle request from slave to master
    vu_req: Option<SlaveFsCacheReq>,
}

impl VhostUserFsBackend {
    // There's no way to recover if error happens during processing a virtq, let the caller
    // to handle it.
    fn process_queue(&mut self, vring_state: &mut MutexGuard<VringState>) -> Result<bool> {
        let mut used_any = false;

        let avail_chains: Vec<DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>> = vring_state
            .get_queue_mut()
            .iter()
            .map_err(|_| DaemonError::IterateQueue)?
            .collect();

        for chain in avail_chains {
            used_any = true;

            let head_index = chain.head_index();
            let mem = chain.memory();

            let reader =
                Reader::new(mem, chain.clone()).map_err(DaemonError::InvalidDescriptorChain)?;
            let writer =
                Writer::new(mem, chain.clone()).map_err(DaemonError::InvalidDescriptorChain)?;

            self.server
                .handle_message(
                    reader,
                    writer,
                    self.vu_req
                        .as_mut()
                        .map(|x| x as &mut dyn FsCacheReqHandler),
                    None,
                )
                .map_err(DaemonError::ProcessQueue)?;

            if self.event_idx {
                if vring_state.add_used(head_index, 0).is_err() {
                    warn!("Couldn't return used descriptors to the ring");
                }

                match vring_state.needs_notification() {
                    Err(_) => {
                        warn!("Couldn't check if queue needs to be notified");
                        vring_state.signal_used_queue().unwrap();
                    }
                    Ok(needs_notification) => {
                        if needs_notification {
                            vring_state.signal_used_queue().unwrap();
                        }
                    }
                }
            } else {
                if vring_state.add_used(head_index, 0).is_err() {
                    warn!("Couldn't return used descriptors to the ring");
                }
                vring_state.signal_used_queue().unwrap();
            }
        }

        Ok(used_any)
    }
}

struct VhostUserFsBackendHandler {
    backend: Mutex<VhostUserFsBackend>,
}

impl VhostUserFsBackendHandler {
    fn new(vfs: Arc<Vfs>) -> Result<Self> {
        let backend = VhostUserFsBackend {
            event_idx: false,
            kill_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(DaemonError::Epoll)?,
            mem: None,
            server: Arc::new(Server::new(vfs)),
            vu_req: None,
        };

        Ok(VhostUserFsBackendHandler {
            backend: Mutex::new(backend),
        })
    }
}

impl VhostUserBackendMut<VringMutex> for VhostUserFsBackendHandler {
    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::SLAVE_REQ
    }

    fn set_event_idx(&mut self, _enabled: bool) {
        self.backend.lock().unwrap().event_idx = true
    }

    fn update_memory(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> VhostUserBackendResult<()> {
        self.backend.lock().unwrap().mem = Some(mem);
        Ok(())
    }

    fn set_slave_req_fd(&mut self, vu_req: SlaveFsCacheReq) {
        self.backend.lock().unwrap().vu_req = Some(vu_req);
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        // FIXME: need to patch vhost-user-backend to return KILL_EVENT
        // so that daemon stop event gets popped up.
        Some(self.backend.lock().unwrap().kill_evt.try_clone().unwrap())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringMutex],
        _thread_id: usize,
    ) -> VhostUserBackendResult<bool> {
        if evset != EventSet::IN {
            return Err(DaemonError::HandleEventNotEpollIn.into());
        }

        let mut vring_state = match device_event {
            HIPRIO_QUEUE_EVENT => {
                debug!("HIPRIO_QUEUE_EVENT");
                vrings[0].get_mut()
            }
            REQ_QUEUE_EVENT => {
                debug!("QUEUE_EVENT");
                vrings[1].get_mut()
            }
            _ => return Err(DaemonError::HandleEventUnknownEvent.into()),
        };

        if self.backend.lock().unwrap().event_idx {
            // vm-virtio's Queue implementation only checks avail_index
            // once, so to properly support EVENT_IDX we need to keep
            // calling process_queue() until it stops finding new
            // requests on the queue.
            loop {
                vring_state.disable_notification().unwrap();
                self.backend
                    .lock()
                    .unwrap()
                    .process_queue(&mut vring_state)?;
                if !vring_state.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            // Without EVENT_IDX, a single call is enough.
            self.backend
                .lock()
                .unwrap()
                .process_queue(&mut vring_state)?;
        }

        Ok(false)
    }
}

pub struct VirtioFsService {
    vfs: Arc<Vfs>,
    upgrade_mgr: Option<Mutex<UpgradeManager>>,
    backend_collection: Mutex<FsBackendCollection>,
}

impl VirtioFsService {
    fn new(vfs: Arc<Vfs>) -> Self {
        VirtioFsService {
            vfs,
            upgrade_mgr: None,
            backend_collection: Default::default(),
        }
    }
}

impl FsService for VirtioFsService {
    fn get_vfs(&self) -> &Vfs {
        &self.vfs
    }

    fn upgrade_mgr(&self) -> Option<MutexGuard<UpgradeManager>> {
        self.upgrade_mgr.as_ref().map(|mgr| mgr.lock().unwrap())
    }

    fn backend_collection(&self) -> MutexGuard<FsBackendCollection> {
        self.backend_collection.lock().unwrap()
    }

    fn export_inflight_ops(&self) -> DaemonResult<Option<String>> {
        Err(DaemonError::Unsupported)
    }
}

struct VirtiofsDaemon<S: 'static + VhostUserBackend<VringMutex> + Clone> {
    bti: BuildTimeInfo,
    id: Option<String>,
    request_sender: Arc<Mutex<Sender<DaemonStateMachineInput>>>,
    result_receiver: Mutex<Receiver<DaemonResult<()>>>,
    service: Arc<VirtioFsService>,
    state: AtomicI32,
    supervisor: Option<String>,

    daemon: Arc<Mutex<VhostUserDaemon<S, VringMutex>>>,
    sock: String,
}

impl<S: 'static + VhostUserBackend<VringMutex> + Clone> NydusDaemon for VirtiofsDaemon<S> {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn id(&self) -> Option<String> {
        self.id.clone()
    }

    fn get_state(&self) -> DaemonState {
        self.state.load(Ordering::Relaxed).into()
    }

    fn set_state(&self, state: DaemonState) {
        self.state.store(state as i32, Ordering::Relaxed);
    }

    fn version(&self) -> BuildTimeInfo {
        self.bti.clone()
    }

    fn start(&self) -> DaemonResult<()> {
        let listener = Listener::new(&self.sock, true)
            .map_err(|e| DaemonError::StartService(format!("{:?}", e)))?;
        let vu_daemon = self.daemon.clone();
        let _ = thread::Builder::new()
            .name("vhost_user_listener".to_string())
            .spawn(move || {
                vu_daemon
                    .lock()
                    .unwrap()
                    .start(listener)
                    .unwrap_or_else(|e| error!("{:?}", e));
            })
            .map_err(DaemonError::ThreadSpawn)?;

        Ok(())
    }

    fn disconnect(&self) -> DaemonResult<()> {
        Ok(())
    }

    fn wait(&self) -> DaemonResult<()> {
        self.daemon
            .lock()
            .unwrap()
            .wait()
            .map_err(|e| DaemonError::WaitDaemon(eother!(e)))
    }

    fn supervisor(&self) -> Option<String> {
        self.supervisor.clone()
    }

    fn save(&self) -> DaemonResult<()> {
        unimplemented!();
    }

    fn restore(&self) -> DaemonResult<()> {
        unimplemented!();
    }

    fn get_default_fs_service(&self) -> Option<Arc<dyn FsService>> {
        Some(self.service.clone())
    }
}

impl<S: 'static + VhostUserBackend<VringMutex> + Clone> DaemonStateMachineSubscriber
    for VirtiofsDaemon<S>
{
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

pub fn create_virtiofs_daemon(
    id: Option<String>,
    supervisor: Option<String>,
    sock: &str,
    vfs: Arc<Vfs>,
    mount_cmd: Option<FsBackendMountCmd>,
    bti: BuildTimeInfo,
) -> Result<Arc<dyn NydusDaemon + Send + Sync>> {
    let vu_daemon = VhostUserDaemon::new(
        String::from("vhost-user-fs-backend"),
        Arc::new(RwLock::new(VhostUserFsBackendHandler::new(vfs.clone())?)),
        GuestMemoryAtomic::new(GuestMemoryMmap::new()),
    )
    .map_err(|e| DaemonError::DaemonFailure(format!("{:?}", e)))?;
    let (trigger, events_rx) = channel::<DaemonStateMachineInput>();
    let (result_sender, result_receiver) = channel::<DaemonResult<()>>();
    let service = VirtioFsService::new(vfs);
    let daemon = Arc::new(VirtiofsDaemon {
        bti,
        id,
        request_sender: Arc::new(Mutex::new(trigger)),
        result_receiver: Mutex::new(result_receiver),
        service: Arc::new(service),
        state: AtomicI32::new(DaemonState::INIT as i32),
        supervisor,

        daemon: Arc::new(Mutex::new(vu_daemon)),
        sock: sock.to_string(),
    });
    let machine = DaemonStateMachineContext::new(daemon.clone(), events_rx, result_sender);

    machine.kick_state_machine()?;
    if let Some(cmd) = mount_cmd {
        daemon.service.mount(cmd)?;
    }
    // TODO: In fact, for virtiofs, below event triggers virtio-queue setup and some other
    // preparation/connection work. So this event name `Mount` might not be suggestive.
    // I'd like to rename it someday.
    daemon
        .on_event(DaemonStateMachineInput::Mount)
        .map_err(|e| eother!(e))?;

    Ok(daemon)
}
