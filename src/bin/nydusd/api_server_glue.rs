// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020-2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::convert::From;
use std::str::FromStr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;

use event_manager::{EventManager, EventOps, EventSubscriber, Events, SubscriberOps};
use nix::sys::signal::{kill, SIGTERM};
use nix::unistd::Pid;
//use vm_memory::Bytes;
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use nydus::{FsBackendType, NydusError};
use nydus_api::http::start_http_thread;
use nydus_api::http_endpoint::{
    ApiError, ApiMountCmd, ApiRequest, ApiResponse, ApiResponsePayload, ApiResult, DaemonConf,
    DaemonErrorKind, MetricsErrorKind,
};
use nydus_utils::metrics;

use crate::daemon::{DaemonError, FsBackendMountCmd, FsBackendUmountCmd, NydusDaemon};
#[cfg(fusedev)]
use crate::fusedev::FusedevDaemon;

type Result<T> = ApiResult<T>;

impl From<DaemonError> for DaemonErrorKind {
    fn from(e: DaemonError) -> Self {
        use DaemonError::*;
        match e {
            UpgradeManager(_) => DaemonErrorKind::UpgradeManager,
            NotReady => DaemonErrorKind::NotReady,
            Unsupported => DaemonErrorKind::Unsupported,
            Serde(e) => DaemonErrorKind::Serde(e),
            UnexpectedEvent(e) => DaemonErrorKind::UnexpectedEvent(format!("{:?}", e)),
            o => DaemonErrorKind::Other(o.to_string()),
        }
    }
}

impl From<NydusError> for DaemonError {
    fn from(e: NydusError) -> Self {
        use NydusError::*;
        match e {
            InvalidArguments(e) => DaemonError::FsTypeMismatch(e),
        }
    }
}

struct ApiServer {
    to_http: Sender<ApiResponse>,
    daemon: Arc<dyn NydusDaemon>,
}

impl ApiServer {
    pub fn new(
        to_http: Sender<ApiResponse>,
        daemon: Arc<dyn NydusDaemon>,
    ) -> std::io::Result<Self> {
        Ok(ApiServer { to_http, daemon })
    }

    fn process_request(&self, from_http: &Receiver<ApiRequest>) -> std::io::Result<()> {
        let request = from_http
            .recv()
            .map_err(|e| epipe!(format!("receive API channel failed {}", e)))?;

        let resp = match request {
            ApiRequest::DaemonInfo => self.daemon_info(),
            ApiRequest::ExportFsBackendInfo(mountpoint) => self.backend_info(&mountpoint),
            ApiRequest::ConfigureDaemon(conf) => self.configure_daemon(conf),
            ApiRequest::Exit => self.do_exit(),

            ApiRequest::Mount(mountpoint, info) => self.do_mount(mountpoint, info),
            ApiRequest::Remount(mountpoint, info) => self.do_remount(mountpoint, info),
            ApiRequest::Umount(mountpoint) => self.do_umount(mountpoint),

            ApiRequest::Events => Self::events(),
            ApiRequest::ExportGlobalMetrics(id) => Self::export_global_metrics(id),
            ApiRequest::ExportFilesMetrics(id, latest_read_files) => {
                Self::export_files_metrics(id, latest_read_files)
            }
            ApiRequest::ExportAccessPatterns(id) => Self::export_access_patterns(id),
            ApiRequest::ExportBackendMetrics(id) => Self::export_backend_metrics(id),
            ApiRequest::ExportBlobcacheMetrics(id) => Self::export_blobcache_metrics(id),
            ApiRequest::ExportInflightMetrics => self.export_inflight_metrics(),

            ApiRequest::SendFuseFd => self.send_fuse_fd(),
            ApiRequest::Takeover => self.do_takeover(),
        };

        self.respond(resp);

        Ok(())
    }

    fn respond(&self, resp: Result<ApiResponsePayload>) {
        if let Err(e) = self.to_http.send(resp) {
            error!("send API response failed {}", e);
        }
    }

    fn daemon_info(&self) -> ApiResponse {
        let d = self.daemon.as_ref();
        let info = d
            .export_info()
            .map_err(|e| ApiError::Metrics(MetricsErrorKind::Daemon(e.into())))?;
        Ok(ApiResponsePayload::DaemonInfo(info))
    }

    fn backend_info(&self, mountpoint: &str) -> ApiResponse {
        let d = self.daemon.as_ref();
        let info = d
            .export_backend_info(mountpoint)
            .map_err(|e| ApiError::Metrics(MetricsErrorKind::Daemon(e.into())))?;
        Ok(ApiResponsePayload::FsBackendInfo(info))
    }

    fn configure_daemon(&self, conf: DaemonConf) -> ApiResponse {
        conf.log_level
            .parse::<log::LevelFilter>()
            .map_err(|e| {
                error!("Invalid log level passed, {}", e);
                ApiError::ResponsePayloadType
            })
            .map(|v| {
                log::set_max_level(v);
                ApiResponsePayload::Empty
            })
    }

    fn events() -> ApiResponse {
        let events = metrics::export_events().map_err(|e| ApiError::Events(format!("{:?}", e)))?;
        Ok(ApiResponsePayload::Events(events))
    }

    fn export_global_metrics(id: Option<String>) -> ApiResponse {
        metrics::export_global_stats(&id)
            .map(ApiResponsePayload::FsGlobalMetrics)
            .map_err(|e| ApiError::Metrics(MetricsErrorKind::Stats(e)))
    }

    fn export_files_metrics(id: Option<String>, latest_read_files: bool) -> ApiResponse {
        // TODO: Use mount point name to refer to per rafs metrics.
        metrics::export_files_stats(&id, latest_read_files)
            .map(ApiResponsePayload::FsFilesMetrics)
            .map_err(|e| ApiError::Metrics(MetricsErrorKind::Stats(e)))
    }

    fn export_access_patterns(id: Option<String>) -> ApiResponse {
        metrics::export_files_access_pattern(&id)
            .map(ApiResponsePayload::FsFilesPatterns)
            .map_err(|e| ApiError::Metrics(MetricsErrorKind::Stats(e)))
    }

    fn export_backend_metrics(id: Option<String>) -> ApiResponse {
        metrics::export_backend_metrics(&id)
            .map(ApiResponsePayload::BackendMetrics)
            .map_err(|e| ApiError::Metrics(MetricsErrorKind::Stats(e)))
    }

    fn export_blobcache_metrics(id: Option<String>) -> ApiResponse {
        metrics::export_blobcache_metrics(&id)
            .map(ApiResponsePayload::BlobcacheMetrics)
            .map_err(|e| ApiError::Metrics(MetricsErrorKind::Stats(e)))
    }

    /// Detect if there is fop being hang.
    /// `ApiResponsePayload::Empty` will be converted to http status code 204, which means
    /// there is no requests being processed right now.
    /// Otherwise, json body within http response is provided,
    /// ```json
    /// [
    ///  {
    ///    "inode": 72057594037929010,
    ///    "opcode": 44,
    ///    "unique": 22728,
    ///    "timestamp_secs": 1612245570
    ///  },
    ///  {
    ///    "inode": 72057594037928480,
    ///    "opcode": 15,
    ///    "unique": 22656,
    ///    "timestamp_secs": 1612245570
    ///  },
    ///  {
    ///    "inode": 72057594037928940,
    ///    "opcode": 15,
    ///    "unique": 22700,
    ///    "timestamp_secs": 1612245570
    ///  }
    /// ]
    /// It means 3 threads are processing inflight requests.
    fn export_inflight_metrics(&self) -> ApiResponse {
        // TODO: Implement automatic error conversion between DaemonError and ApiError.
        let d = self.daemon.as_ref();
        if let Some(ops) = d
            .export_inflight_ops()
            .map_err(|e| ApiError::Metrics(MetricsErrorKind::Daemon(e.into())))?
        {
            Ok(ApiResponsePayload::InflightMetrics(ops))
        } else {
            Ok(ApiResponsePayload::Empty)
        }
    }

    /// External supervisor wants this instance to exit. But it can't just die leave
    /// some pending or in-flight fuse messages un-handled. So this method guarantees
    /// all fuse messages read from kernel are handled and replies are sent back.
    /// Before http response are sent back, this must can ensure that current process
    /// has absolutely stopped. Otherwise, multiple processes might read from single
    /// fuse session simultaneously.
    fn do_exit(&self) -> ApiResponse {
        let d = self.daemon.as_ref();
        d.trigger_exit()
            .map(|_| {
                info!("exit daemon by http request");
                ApiResponsePayload::Empty
            })
            .map_err(|e| ApiError::DaemonAbnormal(e.into()))?;

        // Should be reliable since this Api server works under event manager.
        kill(Pid::this(), SIGTERM).unwrap_or_else(|e| error!("Send signal error. {}", e));

        Ok(ApiResponsePayload::Empty)
    }

    fn do_mount(&self, mountpoint: String, cmd: ApiMountCmd) -> ApiResponse {
        let fs_type = FsBackendType::from_str(&cmd.fs_type)
            .map_err(|e| ApiError::MountFailure(DaemonError::from(e).into()))?;
        self.daemon
            .mount(FsBackendMountCmd {
                fs_type,
                mountpoint,
                config: cmd.config,
                source: cmd.source,
                prefetch_files: cmd.prefetch_files,
            })
            .map(|_| ApiResponsePayload::Empty)
            .map_err(|e| ApiError::MountFailure(e.into()))
    }

    fn do_remount(&self, mountpoint: String, cmd: ApiMountCmd) -> ApiResponse {
        let fs_type = FsBackendType::from_str(&cmd.fs_type)
            .map_err(|e| ApiError::MountFailure(DaemonError::from(e).into()))?;
        self.daemon
            .remount(FsBackendMountCmd {
                fs_type,
                mountpoint,
                config: cmd.config,
                source: cmd.source,
                prefetch_files: cmd.prefetch_files,
            })
            .map(|_| ApiResponsePayload::Empty)
            .map_err(|e| ApiError::MountFailure(e.into()))
    }

    fn do_umount(&self, mountpoint: String) -> ApiResponse {
        self.daemon
            .umount(FsBackendUmountCmd { mountpoint })
            .map(|_| ApiResponsePayload::Empty)
            .map_err(|e| ApiError::MountFailure(e.into()))
    }

    fn send_fuse_fd(&self) -> ApiResponse {
        let d = self.daemon.as_ref();

        d.save()
            .map(|_| ApiResponsePayload::Empty)
            .map_err(|e| ApiError::DaemonAbnormal(e.into()))
    }

    /// External supervisor wants this instance to fetch `/dev/fuse` fd. Before
    /// invoking this method, supervisor should already listens on a Unix socket and
    /// waits for connection from this instance. Then supervisor should send the *fd*
    /// back. Note, the http response does not mean this process already finishes Takeover
    /// procedure. Supervisor has to continuously query the state of Nydusd until it gets
    /// to *RUNNING*, which means new Nydusd has successfully served as a fuse server.
    fn do_takeover(&self) -> ApiResponse {
        let d = self.daemon.as_ref();
        d.trigger_takeover()
            .map(|_| ApiResponsePayload::Empty)
            .map_err(|e| ApiError::DaemonAbnormal(e.into()))
    }
}

struct ApiSeverHandler {
    event_fd: EventFd,
    server: ApiServer,
    api_receiver: Receiver<ApiRequest>,
}

impl ApiSeverHandler {
    fn new(server: ApiServer, api_receiver: Receiver<ApiRequest>) -> std::io::Result<Self> {
        match EventFd::new(0) {
            Ok(event_fd) => Ok(Self {
                event_fd,
                server,
                api_receiver,
            }),
            Err(e) => {
                error!("Creating event fd failed. {}", e);
                Err(e)
            }
        }
    }

    fn get_event_fd(&self) -> std::io::Result<EventFd> {
        self.event_fd.try_clone()
    }
}

impl EventSubscriber for ApiSeverHandler {
    fn process(&self, events: Events, event_ops: &mut EventOps) {
        match events.event_set() {
            EventSet::IN => {
                // Consume notification from the EventFd, which should always be valid.
                let _ = self
                    .event_fd
                    .read()
                    .expect("failed to read data from HTTP API EventFd");
                self.server
                    .process_request(&self.api_receiver)
                    .unwrap_or_else(|e| error!("API server failed to process event, {}", e));
            }
            EventSet::ERROR => error!("Unexpected error from HTTP API EventFd."),
            EventSet::HANG_UP => {
                event_ops
                    .remove(events)
                    .unwrap_or_else(|e| error!("Encountered error during cleanup, {}", e));
            }
            _ => {}
        }
    }

    fn init(&self, ops: &mut EventOps) {
        ops.add(Events::new(&self.event_fd, EventSet::IN))
            .expect("Failed to register HTTP API EventFd to event manager")
    }
}

/// HTTP API server to serve the administration socket.
pub struct ApiServerController {
    sock: Option<String>,
    eventfd: Option<EventFd>,
    thread: Option<JoinHandle<std::io::Result<()>>>,
}

impl ApiServerController {
    /// Create a new instance of `ApiServerController`.
    pub fn new(sock: Option<&str>) -> Self {
        ApiServerController {
            sock: sock.map(|v| v.to_string()),
            eventfd: None,
            thread: None,
        }
    }

    /// Try to start the HTTP working thread.
    pub fn start(
        &mut self,
        event_manager: &mut EventManager<Arc<dyn EventSubscriber>>,
        daemon: Arc<dyn NydusDaemon>,
    ) -> std::io::Result<()> {
        if let Some(apisock) = self.sock.as_ref() {
            let http_exit_evtfd = EventFd::new(0)?;
            let http_exit_evtfd2 = http_exit_evtfd.try_clone()?;
            let (to_api, from_http) = channel();
            let (to_http, from_api) = channel();
            let api_server = ApiServer::new(to_http, daemon)?;
            let api_handler = ApiSeverHandler::new(api_server, from_http)?;
            let api_server_subscriber = Arc::new(api_handler);
            let evtfd = api_server_subscriber.get_event_fd()?;

            event_manager.add_subscriber(api_server_subscriber);
            let ret = start_http_thread(apisock, evtfd, to_api, from_api, http_exit_evtfd2)?;
            info!("api server running at {}", apisock);

            self.thread = Some(ret);
            self.eventfd = Some(http_exit_evtfd);
        }

        Ok(())
    }

    /// Stop the HTTP working thread.
    pub fn stop(&mut self) {
        if let Some(eventfd) = self.eventfd.take() {
            let _ = eventfd.write(1);
        }
        if let Some(t) = self.thread.take() {
            if let Err(e) = t.join() {
                error!("Failed to join the HTTP thread, execution error. {:?}", e);
            }
        }
    }
}
