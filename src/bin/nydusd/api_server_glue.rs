// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::convert::From;
use std::str::FromStr;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;

use event_manager::{EventOps, EventSubscriber, Events};
use nix::sys::signal::{kill, SIGTERM};
use nix::unistd::Pid;
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use nydus_api::http_endpoint::{
    ApiError, ApiMountCmd, ApiRequest, ApiResponse, ApiResponsePayload, ApiResult, DaemonConf,
    DaemonErrorKind, MetricsErrorKind,
};
use nydus_utils::metrics;

use crate::daemon::{
    DaemonError, FsBackendMountCmd, FsBackendType, FsBackendUmountCmd, NydusDaemon,
};
#[cfg(fusedev)]
use crate::fusedev::FusedevDaemon;

pub struct ApiServer {
    to_http: Sender<ApiResponse>,
    daemon: Arc<dyn NydusDaemon>,
}

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
            ApiRequest::Events => Self::events(),
            ApiRequest::Mount((mountpoint, info)) => self.do_mount(mountpoint, info),
            ApiRequest::Remount((mountpoint, info)) => self.do_remount(mountpoint, info),
            ApiRequest::Umount(mountpoint) => self.do_umount(mountpoint),
            ApiRequest::ConfigureDaemon(conf) => self.configure_daemon(conf),
            ApiRequest::ExportGlobalMetrics(id) => Self::export_global_metrics(id),
            ApiRequest::ExportFilesMetrics(id, latest_read_files) => {
                Self::export_files_metrics(id, latest_read_files)
            }
            ApiRequest::ExportAccessPatterns(id) => Self::export_access_patterns(id),
            ApiRequest::ExportBackendMetrics(id) => Self::export_backend_metrics(id),
            ApiRequest::ExportBlobcacheMetrics(id) => Self::export_blobcache_metrics(id),
            ApiRequest::ExportInflightMetrics => self.export_inflight_metrics(),
            ApiRequest::ExportFsBackendInfo(mountpoint) => self.backend_info(&mountpoint),
            ApiRequest::SendFuseFd => self.send_fuse_fd(),
            ApiRequest::Takeover => self.do_takeover(),
            ApiRequest::Exit => self.do_exit(),
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

    fn events() -> ApiResponse {
        let events = metrics::export_events().map_err(|e| ApiError::Events(format!("{:?}", e)))?;
        Ok(ApiResponsePayload::Events(events))
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
        let fs_type =
            FsBackendType::from_str(&cmd.fs_type).map_err(|e| ApiError::MountFailure(e.into()))?;
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
        let fs_type =
            FsBackendType::from_str(&cmd.fs_type).map_err(|e| ApiError::MountFailure(e.into()))?;
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
}

pub struct ApiSeverSubscriber {
    event_fd: EventFd,
    server: ApiServer,
    api_receiver: Receiver<ApiRequest>,
}

impl ApiSeverSubscriber {
    pub fn new(server: ApiServer, api_receiver: Receiver<ApiRequest>) -> std::io::Result<Self> {
        match EventFd::new(0) {
            Ok(fd) => Ok(Self {
                event_fd: fd,
                server,
                api_receiver,
            }),
            Err(e) => {
                error!("Creating event fd failed. {}", e);
                Err(e)
            }
        }
    }

    pub fn get_event_fd(&self) -> std::io::Result<EventFd> {
        self.event_fd.try_clone()
    }
}

impl EventSubscriber for ApiSeverSubscriber {
    fn process(&self, events: Events, event_ops: &mut EventOps) {
        self.event_fd
            .read()
            .map(|_| ())
            .map_err(|e| last_error!(e))
            .unwrap_or_else(|_| {});
        match events.event_set() {
            EventSet::IN => {
                self.server
                    .process_request(&self.api_receiver)
                    .unwrap_or_else(|e| error!("API server process events failed, {}", e));
            }
            EventSet::ERROR => {
                error!("Got error on the monitored event.");
            }
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
            .expect("Cannot register event")
    }
}
