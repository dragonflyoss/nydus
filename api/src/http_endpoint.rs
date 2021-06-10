// Copyright 2020 Ant Group. All rights reserved.
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

//! We keep HTTP and endpoints handlers in the separated crate because not only
//! nydusd is using api server. Other component like `rafs` crate also rely this
//! to export running metrics. So it will be easier to wrap different crates' Error
//! into.

use std::fmt::Debug;
use std::io;
use std::sync::mpsc::{RecvError, SendError};

use micro_http::{Body, Method, Request, Response, StatusCode, Version};

use serde::Deserialize;
use serde_json::Error as SerdeError;

use crate::http::{extract_query_part, EndpointHandler};

use nydus_utils::metrics::IoStatsError;

#[derive(Debug)]
pub enum DaemonErrorKind {
    NotReady,
    UpgradeManager,
    Unsupported,
    Connect(io::Error),
    SendFd,
    RecvFd,
    Disconnect(io::Error),
    Channel,
    Serde(SerdeError),
    UnexpectedEvent(String),
    Other(String),
}

#[derive(Debug)]
pub enum MetricsErrorKind {
    // Errors about daemon working status
    Daemon(DaemonErrorKind),
    // Errors about metrics/stats recorders
    Stats(IoStatsError),
}

/// API errors are sent back from the Nydusd API server through the ApiResponse.
#[derive(Debug)]
pub enum ApiError {
    /// Cannot write to EventFd.
    EventFdWrite(io::Error),
    /// Cannot mount a resource
    MountFailure(DaemonErrorKind),
    /// API request send error
    RequestSend(SendError<ApiRequest>),
    /// Wrong response payload type
    ResponsePayloadType,
    /// API response receive error
    ResponseRecv(RecvError),
    DaemonAbnormal(DaemonErrorKind),
    Events(String),
    Metrics(MetricsErrorKind),
}
pub type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Serialize)]
pub enum ApiResponsePayload {
    /// No data is sent on the channel.
    Empty,
    /// Nydus daemon general working information.
    DaemonInfo(String),
    Events(String),
    FsBackendInfo(String),
    /// Nydus filesystem global metrics
    FsGlobalMetrics(String),
    /// Nydus filesystem per-file metrics
    FsFilesMetrics(String),
    FsFilesPatterns(String),
    BackendMetrics(String),
    BlobcacheMetrics(String),
    InflightMetrics(String),
}

/// This is the response sent by the API server through the mpsc channel.
pub type ApiResponse = std::result::Result<ApiResponsePayload, ApiError>;
pub type HttpResult = std::result::Result<Response, HttpError>;

#[derive(Debug)]
pub enum ApiRequest {
    DaemonInfo,
    Events,
    Mount((String, ApiMountCmd)),
    Remount((String, ApiMountCmd)),
    Umount(String),
    ConfigureDaemon(DaemonConf),
    ExportGlobalMetrics(Option<String>),
    ExportFilesMetrics(Option<String>, bool),
    ExportAccessPatterns(Option<String>),
    ExportBackendMetrics(Option<String>),
    ExportBlobcacheMetrics(Option<String>),
    ExportInflightMetrics,
    ExportFsBackendInfo(String),
    SendFuseFd,
    Takeover,
    Exit,
}

#[derive(Clone, Deserialize, Debug)]
pub struct ApiMountCmd {
    pub source: String,
    #[serde(default)]
    pub fs_type: String,
    pub config: String,
    #[serde(default)]
    pub prefetch_files: Option<Vec<String>>,
}

#[derive(Clone, Deserialize, Debug)]
pub struct ApiUmountCmd {
    pub mountpoint: String,
}

fn parse_body<'a, F: Deserialize<'a>>(b: &'a Body) -> Result<F, HttpError> {
    serde_json::from_slice::<F>(b.raw()).map_err(HttpError::ParseBody)
}

#[derive(Clone, Deserialize, Debug)]
pub struct DaemonConf {
    pub log_level: String,
}

/// Errors associated with Nydus management
#[derive(Debug)]
pub enum HttpError {
    NoRoute,
    BadRequest,
    QueryString(String),
    /// API request receive error
    SerdeJsonDeserialize(SerdeError),
    SerdeJsonSerialize(SerdeError),
    ParseBody(SerdeError),
    /// Could not query daemon info
    Info(ApiError),
    Events(ApiError),
    /// Could not mount resource
    Mount(ApiError),
    GlobalMetrics(ApiError),
    FsFilesMetrics(ApiError),
    Pattern(ApiError),
    Configure(ApiError),
    Upgrade(ApiError),
    BlobcacheMetrics(ApiError),
    BackendMetrics(ApiError),
    FsBackendInfo(ApiError),
    InflightMetrics(ApiError),
}

fn success_response(body: Option<String>) -> Response {
    let status_code = if body.is_some() {
        StatusCode::OK
    } else {
        StatusCode::NoContent
    };
    let mut r = Response::new(Version::Http11, status_code);
    if let Some(b) = body {
        r.set_body(Body::new(b));
    }
    r
}

#[derive(Serialize, Debug)]
struct ErrorMessage {
    code: String,
    message: String,
}

pub fn error_response(error: HttpError, status: StatusCode) -> Response {
    let mut response = Response::new(Version::Http11, status);

    let err_msg = ErrorMessage {
        code: "UNDEFINED".to_string(),
        message: format!("{:?}", error),
    };
    response.set_body(Body::new(serde_json::to_string(&err_msg).unwrap()));

    response
}

fn translate_status_code(e: &ApiError) -> StatusCode {
    match e {
        ApiError::DaemonAbnormal(kind) | ApiError::MountFailure(kind) => match kind {
            DaemonErrorKind::NotReady => StatusCode::ServiceUnavailable,
            DaemonErrorKind::Unsupported => StatusCode::NotImplemented,
            DaemonErrorKind::UnexpectedEvent(_) => StatusCode::BadRequest,
            _ => StatusCode::InternalServerError,
        },
        ApiError::Metrics(MetricsErrorKind::Stats(IoStatsError::NoCounter)) => StatusCode::NotFound,
        _ => StatusCode::InternalServerError,
    }
}

// API server has successfully processed the request, but can't fulfill that. Therefore,
// a `error_response` is generated whose status code is 4XX or 5XX. With error response,
// it still returns Ok(error_response) to http request handling framework, which means
// nydusd api server receives the request and try handle it, even the request can't be fulfilled.
fn convert_to_response<O: FnOnce(ApiError) -> HttpError>(api_resp: ApiResponse, op: O) -> Response {
    match api_resp {
        Ok(r) => {
            use ApiResponsePayload::*;
            match r {
                Empty => success_response(None),
                DaemonInfo(d) => success_response(Some(d)),
                Events(d) => success_response(Some(d)),
                FsFilesMetrics(d) => success_response(Some(d)),
                FsGlobalMetrics(d) => success_response(Some(d)),
                FsFilesPatterns(d) => success_response(Some(d)),
                BackendMetrics(d) => success_response(Some(d)),
                BlobcacheMetrics(d) => success_response(Some(d)),
                FsBackendInfo(d) => success_response(Some(d)),
                InflightMetrics(d) => success_response(Some(d)),
            }
        }
        Err(e) => {
            let sc = translate_status_code(&e);
            error_response(op(e), sc)
        }
    }
}

pub struct InfoHandler {}
impl EndpointHandler for InfoHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let r = kicker(ApiRequest::DaemonInfo);
                Ok(convert_to_response(r, HttpError::Info))
            }
            (Method::Put, Some(body)) => {
                let conf = parse_body(body)?;
                let r = kicker(ApiRequest::ConfigureDaemon(conf));
                Ok(convert_to_response(r, HttpError::Configure))
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

pub struct EventsHandler {}
impl EndpointHandler for EventsHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let r = kicker(ApiRequest::Events);
                Ok(convert_to_response(r, HttpError::Events))
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

pub struct MountHandler {}
impl EndpointHandler for MountHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        let mountpoint = extract_query_part(req, "mountpoint").ok_or_else(|| {
            HttpError::QueryString("'mountpoint' should be specified in query string".to_string())
        })?;
        match (req.method(), req.body.as_ref()) {
            (Method::Post, Some(body)) => {
                let cmd = parse_body(body)?;
                let r = kicker(ApiRequest::Mount((mountpoint, cmd)));
                Ok(convert_to_response(r, HttpError::Mount))
            }
            (Method::Put, Some(body)) => {
                let cmd = parse_body(body)?;
                let r = kicker(ApiRequest::Remount((mountpoint, cmd)));
                Ok(convert_to_response(r, HttpError::Mount))
            }
            (Method::Delete, None) => {
                let r = kicker(ApiRequest::Umount(mountpoint));
                Ok(convert_to_response(r, HttpError::Mount))
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

pub struct MetricsHandler {}
impl EndpointHandler for MetricsHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let id = extract_query_part(req, "id");
                let r = kicker(ApiRequest::ExportGlobalMetrics(id));
                Ok(convert_to_response(r, HttpError::GlobalMetrics))
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

pub struct MetricsFilesHandler {}
impl EndpointHandler for MetricsFilesHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let id = extract_query_part(req, "id");
                let latest_read_files = extract_query_part(req, "latest")
                    .map_or(false, |b| b.parse::<bool>().unwrap_or(false));
                let r = kicker(ApiRequest::ExportFilesMetrics(id, latest_read_files));
                Ok(convert_to_response(r, HttpError::FsFilesMetrics))
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

pub struct MetricsPatternHandler {}
impl EndpointHandler for MetricsPatternHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let id = extract_query_part(req, "id");
                let r = kicker(ApiRequest::ExportAccessPatterns(id));
                Ok(convert_to_response(r, HttpError::Pattern))
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

pub struct MetricsBackendHandler {}
impl EndpointHandler for MetricsBackendHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let id = extract_query_part(req, "id");
                let r = kicker(ApiRequest::ExportBackendMetrics(id));
                Ok(convert_to_response(r, HttpError::BackendMetrics))
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

pub struct MetricsBlobcacheHandler {}
impl EndpointHandler for MetricsBlobcacheHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let id = extract_query_part(req, "id");
                let r = kicker(ApiRequest::ExportBlobcacheMetrics(id));
                Ok(convert_to_response(r, HttpError::BlobcacheMetrics))
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

pub struct MetricsInflightHandler {}
impl EndpointHandler for MetricsInflightHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let r = kicker(ApiRequest::ExportInflightMetrics);
                Ok(convert_to_response(r, HttpError::InflightMetrics))
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

pub struct SendFuseFdHandler {}
impl EndpointHandler for SendFuseFdHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Put, None) => {
                let r = kicker(ApiRequest::SendFuseFd);
                Ok(convert_to_response(r, HttpError::Upgrade))
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

pub struct TakeoverHandler {}
impl EndpointHandler for TakeoverHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Put, None) => {
                let r = kicker(ApiRequest::Takeover);
                Ok(convert_to_response(r, HttpError::Upgrade))
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

pub struct ExitHandler {}
impl EndpointHandler for ExitHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Put, None) => {
                let r = kicker(ApiRequest::Exit);
                Ok(convert_to_response(r, HttpError::Upgrade))
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

pub struct FsBackendInfo {}

impl EndpointHandler for FsBackendInfo {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let mountpoint = extract_query_part(req, "mountpoint").ok_or_else(|| {
                    HttpError::QueryString(
                        "'mountpoint' should be specified in query string".to_string(),
                    )
                })?;
                let r = kicker(ApiRequest::ExportFsBackendInfo(mountpoint));
                Ok(convert_to_response(r, HttpError::FsBackendInfo))
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}
