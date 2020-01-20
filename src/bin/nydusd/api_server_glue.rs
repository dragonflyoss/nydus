// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use event_manager::{EventOps, EventSubscriber, Events};
use fuse_rs::api::Vfs;
use nydus_api::http_endpoint::{
    ApiError, ApiRequest, ApiResponse, ApiResponsePayload, ApiResult, DaemonConf, DaemonInfo,
    MountInfo,
};
use nydus_utils::{einval, enoent, eother, epipe, last_error};
use rafs::fs::{Rafs, RafsConfig};
use rafs::io_stats;
use std::fs::File;
use std::ops::Deref;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use crate::SubscriberWrapper;

pub struct ApiServer {
    id: String,
    version: String,
    to_http: Sender<ApiResponse>,
}

type Result<T> = ApiResult<T>;

impl ApiServer {
    pub fn new(id: String, version: String, to_http: Sender<ApiResponse>) -> std::io::Result<Self> {
        Ok(ApiServer {
            id,
            version,
            to_http,
        })
    }

    fn process_request(
        &self,
        from_http: &Receiver<ApiRequest>,
        rafs_conf: &RafsConfig,
        vfs: &Arc<Vfs>,
    ) -> std::io::Result<()> {
        let request = from_http
            .recv()
            .map_err(|e| epipe!(format!("receive API channel failed {}", e)))?;

        let resp = match request {
            ApiRequest::DaemonInfo => self.get_rafs_instance_info(),
            ApiRequest::Mount(info) => Self::mount_rafs(info, rafs_conf, vfs),
            ApiRequest::ConfigureDaemon(conf) => self.configure_rafs_instance(conf),
            ApiRequest::ExportGlobalMetrics(id) => Self::export_global_metrics(id),
            ApiRequest::ExportFilesMetrics(id) => Self::export_files_metrics(id),
            ApiRequest::ExportAccessPatterns(id) => Self::export_access_patterns(id),
        };

        self.respond(resp);

        Ok(())
    }

    fn respond(&self, resp: Result<ApiResponsePayload>) {
        if let Err(e) = self.to_http.send(resp) {
            error!("send API response failed {}", e);
        }
    }

    fn get_rafs_instance_info(&self) -> ApiResponse {
        let response = DaemonInfo {
            id: self.id.to_string(),
            version: self.version.to_string(),
            state: "Running".to_string(),
        };

        Ok(ApiResponsePayload::DaemonInfo(response))
    }

    fn mount_rafs(info: MountInfo, rafs_conf: &RafsConfig, vfs: &Arc<Vfs>) -> ApiResponse {
        rafs_mount(info, &rafs_conf, vfs)
            .map(|_| ApiResponsePayload::Mount)
            .map_err(ApiError::MountFailure)
    }

    fn configure_rafs_instance(&self, conf: DaemonConf) -> ApiResponse {
        conf.log_level
            .parse::<log::LevelFilter>()
            .map_err(|e| {
                error!("Invalid log level passed, {}", e);
                ApiError::ResponsePayloadType
            })
            .map(|v| {
                log::set_max_level(v);
                ApiResponsePayload::Mount
            })
    }

    fn export_global_metrics(id: Option<String>) -> ApiResponse {
        io_stats::export_global_stats(&id)
            .map(ApiResponsePayload::FsGlobalMetrics)
            .map_err(|_| ApiError::ResponsePayloadType)
    }

    fn export_files_metrics(id: Option<String>) -> ApiResponse {
        // TODO: Use mount point name to refer to per rafs metrics.
        io_stats::export_files_stats(&id)
            .map(ApiResponsePayload::FsFilesMetrics)
            .map_err(|_| ApiError::ResponsePayloadType)
    }

    fn export_access_patterns(id: Option<String>) -> ApiResponse {
        io_stats::export_files_access_pattern(&id)
            .map(ApiResponsePayload::FsFilesPatterns)
            .map_err(|_| ApiError::ResponsePayloadType)
    }
}

/// Mount Rafs per as to provided mount-info.
pub fn rafs_mount(
    info: MountInfo,
    default_rafs_conf: &RafsConfig,
    vfs: &Arc<Vfs>,
) -> std::io::Result<()> {
    match info.ops.as_str() {
        "mount" => {
            let mut rafs;

            if let Some(source) = info.source.as_ref() {
                let mut file = Box::new(File::open(source).map_err(|e| eother!(e))?)
                    as Box<dyn rafs::RafsIoRead>;

                rafs = match info.config.as_ref() {
                    Some(config) => {
                        let content = std::fs::read_to_string(config).map_err(|e| einval!(e))?;
                        let rafs_conf: RafsConfig =
                            serde_json::from_str(&content).map_err(|e| einval!(e))?;
                        Rafs::new(rafs_conf, &info.mountpoint, &mut file)?
                    }
                    None => Rafs::new(default_rafs_conf.clone(), &info.mountpoint, &mut file)?,
                };

                rafs.import(&mut file, None)?;

                match vfs.mount(Box::new(rafs), &info.mountpoint) {
                    Ok(()) => {
                        info!("rafs mounted");
                        Ok(())
                    }
                    Err(e) => Err(eother!(e)),
                }
            } else {
                Err(eother!("No source was provided!"))
            }
        }

        "umount" => match vfs.umount(&info.mountpoint) {
            Ok(()) => Ok(()),
            Err(e) => Err(e),
        },
        "update" => {
            info!("switch backend");
            let rafs_conf = match info.config.as_ref() {
                Some(config) => {
                    let content = std::fs::read_to_string(config).map_err(|e| einval!(e))?;
                    let rafs_conf: RafsConfig =
                        serde_json::from_str(&content).map_err(|e| einval!(e))?;
                    rafs_conf
                }
                None => {
                    return Err(enoent!("No rafs configuration was provided!"));
                }
            };

            let rootfs = vfs.get_rootfs(&info.mountpoint).map_err(|e| enoent!(e))?;
            let any_fs = rootfs.deref().as_any();
            if let Some(fs_swap) = any_fs.downcast_ref::<Rafs>() {
                if let Some(source) = info.source.as_ref() {
                    let mut file = Box::new(File::open(source).map_err(|e| last_error!(e))?)
                        as Box<dyn rafs::RafsIoRead>;

                    fs_swap
                        .update(&mut file, rafs_conf)
                        .map_err(|e| eother!(e))?;
                    Ok(())
                } else {
                    error!("no info.source is found, invalid mount info {:?}", info);
                    Err(enoent!("No source file was provided!"))
                }
            } else {
                Err(eother!("Can't swap fs"))
            }
        }
        _ => Err(einval!("Invalid op")),
    }
}

impl SubscriberWrapper for ApiSeverSubscriber {
    fn get_event_fd(&self) -> std::io::Result<EventFd> {
        self.event_fd.try_clone()
    }
}

pub struct ApiSeverSubscriber {
    event_fd: EventFd,
    server: ApiServer,
    api_receiver: Receiver<ApiRequest>,
    rafs_conf: RafsConfig,
    vfs: Arc<Vfs>,
}

impl ApiSeverSubscriber {
    pub fn new(
        vfs: Arc<Vfs>,
        server: ApiServer,
        api_receiver: Receiver<ApiRequest>,
    ) -> std::io::Result<Self> {
        match EventFd::new(0) {
            Ok(fd) => Ok(Self {
                event_fd: fd,
                rafs_conf: RafsConfig::new(),
                vfs,
                server,
                api_receiver,
            }),
            Err(e) => {
                error!("Creating event fd failed. {}", e);
                Err(e)
            }
        }
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
                    .process_request(&self.api_receiver, &self.rafs_conf, &self.vfs)
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
