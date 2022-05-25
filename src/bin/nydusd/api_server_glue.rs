// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use mio::{Events, Poll, Token, Waker};
use std::convert::From;
use std::str::FromStr;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;

use nydus::{FsBackendType, NydusError};
use nydus_api::http::{
    ApiError, ApiMountCmd, ApiRequest, ApiResponse, ApiResponsePayload, ApiResult, DaemonConf,
    DaemonErrorKind, MetricsErrorKind,
};
use nydus_utils::metrics;

use crate::daemon::{DaemonError, FsBackendMountCmd, FsBackendUmountCmd, NydusDaemon};
#[cfg(fusedev)]
use crate::fusedev::FusedevDaemon;

type Result<T> = ApiResult<T>;
const API_WAKE_TOKEN: Token = Token(0);

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

pub struct ApiServer {
    to_http: Sender<ApiResponse>,
    daemon: Arc<dyn NydusDaemon + Send + Sync>,
}

impl ApiServer {
    pub fn new(
        to_http: Sender<ApiResponse>,
        daemon: Arc<dyn NydusDaemon + Send + Sync>,
    ) -> std::io::Result<Self> {
        Ok(ApiServer { to_http, daemon })
    }

    fn process_request(&self, request: ApiRequest) -> std::io::Result<()> {
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

            // Nydus API v2
            ApiRequest::DaemonInfoV2 => todo!(),
            ApiRequest::GetBlobObject(_param) => todo!(),
            ApiRequest::CreateBlobObject(_cfg) => todo!(),
            ApiRequest::DeleteBlobObject(_param) => todo!(),
            ApiRequest::ListBlobObject => todo!(),
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

    /// External supervisor wants this instance to exit without umounting rafs. We can't
    /// leave some in-flight fuse messages un-handled. So this method guarantees
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
            .map_err(|e| {
                error!("exit fuse service failed {:}", e);
                ApiError::DaemonAbnormal(e.into())
            })?;

        // Ensure both fuse and state machine threads have been terminated thus this
        // nydusd won't race fuse messages when upgrading.
        d.wait()
            .map(|_| {
                info!("fuse service exited by http request");
                ApiResponsePayload::Empty
            })
            .map_err(|e| {
                error!("wait for fuse service failed {:}", e);
                ApiError::DaemonAbnormal(e.into())
            })?;

        Ok(ApiResponsePayload::Empty)
    }

    fn do_mount(&self, mountpoint: String, cmd: ApiMountCmd) -> ApiResponse {
        let fs_type = FsBackendType::from_str(&cmd.fs_type)
            .map_err(|e| ApiError::MountFilesystem(DaemonError::from(e).into()))?;
        self.daemon
            .mount(FsBackendMountCmd {
                fs_type,
                mountpoint,
                config: cmd.config,
                source: cmd.source,
                prefetch_files: cmd.prefetch_files,
            })
            .map(|_| ApiResponsePayload::Empty)
            .map_err(|e| ApiError::MountFilesystem(e.into()))
    }

    fn do_remount(&self, mountpoint: String, cmd: ApiMountCmd) -> ApiResponse {
        let fs_type = FsBackendType::from_str(&cmd.fs_type)
            .map_err(|e| ApiError::MountFilesystem(DaemonError::from(e).into()))?;
        self.daemon
            .remount(FsBackendMountCmd {
                fs_type,
                mountpoint,
                config: cmd.config,
                source: cmd.source,
                prefetch_files: cmd.prefetch_files,
            })
            .map(|_| ApiResponsePayload::Empty)
            .map_err(|e| ApiError::MountFilesystem(e.into()))
    }

    fn do_umount(&self, mountpoint: String) -> ApiResponse {
        self.daemon
            .umount(FsBackendUmountCmd { mountpoint })
            .map(|_| ApiResponsePayload::Empty)
            .map_err(|e| ApiError::MountFilesystem(e.into()))
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

pub struct ApiSeverSubscriber {
    poll: Poll,
    waker: Arc<Waker>,
    server: ApiServer,
    api_receiver: Receiver<Option<ApiRequest>>,
}

impl ApiSeverSubscriber {
    pub fn new(
        server: ApiServer,
        api_receiver: Receiver<Option<ApiRequest>>,
    ) -> std::io::Result<Self> {
        let poll = Poll::new()?;
        let waker = Waker::new(poll.registry(), API_WAKE_TOKEN)?;
        Ok(Self {
            waker: Arc::new(waker),
            poll,
            server,
            api_receiver,
        })
    }

    pub fn get_waker(&self) -> Arc<Waker> {
        self.waker.clone()
    }

    pub fn run(self) -> std::io::Result<JoinHandle<()>> {
        std::thread::Builder::new()
            .name("api-server".to_string())
            .spawn(move || {
                let ApiSeverSubscriber {
                    mut poll,
                    server,
                    api_receiver,
                    ..
                } = self;
                let mut events = Events::with_capacity(100);
                'wait: loop {
                    match poll.poll(&mut events, None) {
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => {
                            error!("API server poll events failed, {}", e);
                            return;
                        }
                        Ok(_) => {}
                    }

                    for event in &events {
                        match event.token() {
                            API_WAKE_TOKEN => {
                                if let Some(request) = api_receiver.recv().unwrap_or_else(|e| {
                                    error!("API server recv failed, {}", e);
                                    None
                                }) {
                                    server.process_request(request).unwrap_or_else(|e| {
                                        error!("API server process events failed, {}", e)
                                    });
                                } else {
                                    break 'wait;
                                }
                            }
                            _ => {
                                unreachable!("unknown event token");
                            }
                        }
                    }
                }
                info!("api-server thread exits");
            })
    }
}
