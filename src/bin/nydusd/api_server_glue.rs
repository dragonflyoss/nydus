// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020-2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::convert::From;
use std::io::Result;
use std::str::FromStr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;

use mio::Waker;
use nix::sys::signal::{kill, SIGTERM};
use nix::unistd::Pid;

use nydus::{FsBackendType, NydusError};
use nydus_api::http::{
    start_http_thread, ApiError, ApiMountCmd, ApiRequest, ApiResponse, ApiResponsePayload,
    ApiResult, BlobCacheEntry, DaemonConf, DaemonErrorKind, MetricsErrorKind,
};
use nydus_utils::metrics;

use crate::daemon::{DaemonError, NydusDaemon};
use crate::fs_service::{FsBackendMountCmd, FsBackendUmountCmd, FsService};
use crate::DAEMON_CONTROLLER;

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
}

impl ApiServer {
    fn new(to_http: Sender<ApiResponse>) -> Result<Self> {
        Ok(ApiServer { to_http })
    }

    fn process_request(&self, request: ApiRequest) -> Result<()> {
        let resp = match request {
            // Common (v1/v2)
            ApiRequest::ConfigureDaemon(conf) => self.configure_daemon(conf),
            ApiRequest::DaemonInfo => self.daemon_info(true),
            ApiRequest::Exit => self.do_exit(),
            ApiRequest::Takeover => self.do_takeover(),
            ApiRequest::Events => Self::events(),
            ApiRequest::ExportGlobalMetrics(id) => Self::export_global_metrics(id),
            ApiRequest::ExportFilesMetrics(id, latest_read_files) => {
                Self::export_files_metrics(id, latest_read_files)
            }
            ApiRequest::ExportAccessPatterns(id) => Self::export_access_patterns(id),
            ApiRequest::ExportBackendMetrics(id) => Self::export_backend_metrics(id),
            ApiRequest::ExportBlobcacheMetrics(id) => Self::export_blobcache_metrics(id),

            // Filesystem (v1)
            ApiRequest::ExportFsBackendInfo(mountpoint) => self.backend_info(&mountpoint),
            ApiRequest::ExportInflightMetrics => self.export_inflight_metrics(),
            ApiRequest::Mount(mountpoint, info) => self.do_mount(mountpoint, info),
            ApiRequest::Remount(mountpoint, info) => self.do_remount(mountpoint, info),
            ApiRequest::Umount(mountpoint) => self.do_umount(mountpoint),
            ApiRequest::SendFuseFd => self.send_fuse_fd(),

            // Nydus API v2
            ApiRequest::DaemonInfoV2 => self.daemon_info(false),
            ApiRequest::GetBlobObject(_param) => todo!(),
            ApiRequest::CreateBlobObject(entry) => self.create_blob_cache_entry(&entry),
            ApiRequest::DeleteBlobObject(_param) => todo!(),
            ApiRequest::ListBlobObject => todo!(),
        };

        self.respond(resp);

        Ok(())
    }

    fn respond(&self, resp: ApiResult<ApiResponsePayload>) {
        if let Err(e) = self.to_http.send(resp) {
            error!("send API response failed {}", e);
        }
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

    fn daemon_info(&self, include_fs_info: bool) -> ApiResponse {
        self.get_daemon_object()?
            .export_info(include_fs_info)
            .map_err(|e| ApiError::Metrics(MetricsErrorKind::Daemon(e.into())))
            .map(ApiResponsePayload::DaemonInfo)
    }

    /// External supervisor wants this instance to exit. But it can't just die leave
    /// some pending or in-flight fuse messages un-handled. So this method guarantees
    /// all fuse messages read from kernel are handled and replies are sent back.
    /// Before http response are sent back, this must can ensure that current process
    /// has absolutely stopped. Otherwise, multiple processes might read from single
    /// fuse session simultaneously.
    fn do_exit(&self) -> ApiResponse {
        let d = self.get_daemon_object()?;
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

    /// External supervisor wants this instance to fetch `/dev/fuse` fd. Before
    /// invoking this method, supervisor should already listens on a Unix socket and
    /// waits for connection from this instance. Then supervisor should send the *fd*
    /// back. Note, the http response does not mean this process already finishes Takeover
    /// procedure. Supervisor has to continuously query the state of Nydusd until it gets
    /// to *RUNNING*, which means new Nydusd has successfully served as a fuse server.
    fn do_takeover(&self) -> ApiResponse {
        let d = self.get_daemon_object()?;
        d.trigger_takeover()
            .map(|_| ApiResponsePayload::Empty)
            .map_err(|e| ApiError::DaemonAbnormal(e.into()))
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

    #[inline]
    fn get_daemon_object(&self) -> std::result::Result<Arc<dyn NydusDaemon>, ApiError> {
        Ok(DAEMON_CONTROLLER.get_daemon())
    }

    fn backend_info(&self, mountpoint: &str) -> ApiResponse {
        let info = self
            .get_default_fs_service()?
            .export_backend_info(mountpoint)
            .map_err(|e| ApiError::Metrics(MetricsErrorKind::Daemon(e.into())))?;
        Ok(ApiResponsePayload::FsBackendInfo(info))
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
        let fs = self.get_default_fs_service()?;
        if let Some(ops) = fs
            .export_inflight_ops()
            .map_err(|e| ApiError::Metrics(MetricsErrorKind::Daemon(e.into())))?
        {
            Ok(ApiResponsePayload::InflightMetrics(ops))
        } else {
            Ok(ApiResponsePayload::Empty)
        }
    }

    fn do_mount(&self, mountpoint: String, cmd: ApiMountCmd) -> ApiResponse {
        let fs_type = FsBackendType::from_str(&cmd.fs_type)
            .map_err(|e| ApiError::MountFilesystem(DaemonError::from(e).into()))?;
        let fs = self.get_default_fs_service()?;
        fs.mount(FsBackendMountCmd {
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
        self.get_default_fs_service()?
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
        self.get_default_fs_service()?
            .umount(FsBackendUmountCmd { mountpoint })
            .map(|_| ApiResponsePayload::Empty)
            .map_err(|e| ApiError::MountFilesystem(e.into()))
    }

    fn send_fuse_fd(&self) -> ApiResponse {
        let d = self.get_daemon_object()?;

        d.save()
            .map(|_| ApiResponsePayload::Empty)
            .map_err(|e| ApiError::DaemonAbnormal(e.into()))
    }

    fn get_default_fs_service(&self) -> std::result::Result<Arc<dyn FsService>, ApiError> {
        DAEMON_CONTROLLER
            .get_fs_service()
            .ok_or(ApiError::DaemonAbnormal(DaemonErrorKind::Unsupported))
    }

    // HTTP API v2
    fn create_blob_cache_entry(&self, entry: &BlobCacheEntry) -> ApiResponse {
        match DAEMON_CONTROLLER.get_blob_cache_mgr() {
            None => Err(ApiError::DaemonAbnormal(DaemonErrorKind::Unsupported)),
            Some(mgr) => {
                if let Err(e) = mgr.add_blob_entry(entry) {
                    Err(ApiError::DaemonAbnormal(DaemonErrorKind::Other(format!(
                        "{}",
                        e
                    ))))
                } else {
                    Ok(ApiResponsePayload::Empty)
                }
            }
        }
    }
}

struct ApiServerHandler {
    server: ApiServer,
    api_receiver: Receiver<Option<ApiRequest>>,
}

impl ApiServerHandler {
    fn new(server: ApiServer, api_receiver: Receiver<Option<ApiRequest>>) -> Result<Self> {
        Ok(Self {
            server,
            api_receiver,
        })
    }

    fn handle_requests_from_router(&self) {
        loop {
            match self.api_receiver.recv() {
                Ok(request) => {
                    if let Some(req) = request {
                        self.server.process_request(req).unwrap_or_else(|e| {
                            error!("HTTP handler failed to process request, {}", e)
                        });
                    } else {
                        debug!("Received exit notification from the HTTP router");
                        return;
                    }
                }
                Err(_e) => {
                    error!("Failed to receive request from the HTTP router");
                    return;
                }
            }
        }
    }
}

/// HTTP API server to serve the administration socket.
pub struct ApiServerController {
    http_handler_thread: Option<JoinHandle<Result<()>>>,
    http_router_thread: Option<JoinHandle<Result<()>>>,
    sock: Option<String>,
    waker: Option<Arc<Waker>>,
}

impl ApiServerController {
    /// Create a new instance of `ApiServerController`.
    pub fn new(sock: Option<&str>) -> Self {
        ApiServerController {
            sock: sock.map(|v| v.to_string()),
            http_handler_thread: None,
            http_router_thread: None,
            waker: None,
        }
    }

    /// Try to start the HTTP working thread.
    pub fn start(&mut self) -> Result<()> {
        if self.sock.is_none() {
            return Ok(());
        }

        // Safe to unwrap() because self.sock is valid.
        let apisock = self.sock.as_ref().unwrap();
        let (to_handler, from_router) = channel();
        let (to_router, from_handler) = channel();
        let api_server = ApiServer::new(to_router)?;
        let api_handler = ApiServerHandler::new(api_server, from_router)?;
        let (router_thread, waker) = start_http_thread(apisock, None, to_handler, from_handler)?;
        let daemon_waker = DAEMON_CONTROLLER.waker.clone();

        info!("HTTP API server running at {}", apisock);
        let handler_thread = std::thread::Builder::new()
            .name("api-server".to_string())
            .spawn(move || {
                api_handler.handle_requests_from_router();
                info!("HTTP api-server handler thread exits");
                let _ = daemon_waker.wake();
                Ok(())
            })
            .map_err(|_e| einval!("Failed to start work thread for HTTP handler"))?;

        self.waker = Some(waker);
        self.http_handler_thread = Some(handler_thread);
        self.http_router_thread = Some(router_thread);

        Ok(())
    }

    /// Stop the HTTP working thread.
    pub fn stop(&mut self) {
        // Signal the HTTP router thread to exit, which will then notify the HTTP handler thread.
        if let Some(waker) = self.waker.take() {
            if let Err(e) = waker.wake() {
                error!("Failed to signal http router thread for exiting, {}", e);
            }
            if let Some(t) = self.http_router_thread.take() {
                if let Err(e) = t.join() {
                    error!(
                        "Failed to join the HTTP router thread, execution error. {:?}",
                        e
                    );
                }
            }
            if let Some(t) = self.http_handler_thread.take() {
                if let Err(e) = t.join() {
                    error!(
                        "Failed to join the HTTP handler thread, execution error. {:?}",
                        e
                    );
                }
            }
        }
    }
}
