// Copyright 2020 Ant Group. All rights reserved.
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

//! We keep HTTP and endpoints handlers in the separated crate because not only
//! nydusd is using api server. Other component like `rafs` crate also rely this
//! to export running metrics. So it will be easier to wrap different crates' Error
//! into.

use dbs_uhttp::{Method, Request, Response};

use crate::http::{
    error_response, extract_query_part, parse_body, success_response, translate_status_code,
    ApiError, ApiRequest, ApiResponse, ApiResponsePayload, EndpointHandler, HttpError, HttpResult,
};

pub const HTTP_ROOT_V1: &str = "/api/v1";

// Convert an ApiResponse to a HTTP response.
//
// API server has successfully processed the request, but can't fulfill that. Therefore,
// a `error_response` is generated whose status code is 4XX or 5XX. With error response,
// it still returns Ok(error_response) to http request handling framework, which means
// nydusd api server receives the request and try handle it, even the request can't be fulfilled.
fn convert_to_response<O: FnOnce(ApiError) -> HttpError>(api_resp: ApiResponse, op: O) -> Response {
    match api_resp {
        Ok(r) => {
            use ApiResponsePayload::*;
            match r {
                // Daemon Common
                Empty => success_response(None),
                DaemonInfo(d) => success_response(Some(d)),
                Events(d) => success_response(Some(d)),
                BackendMetrics(d) => success_response(Some(d)),
                BlobcacheMetrics(d) => success_response(Some(d)),
                FsFilesMetrics(d) => success_response(Some(d)),
                FsFilesPatterns(d) => success_response(Some(d)),
                FsGlobalMetrics(d) => success_response(Some(d)),
                // Filesystem Specific
                FsBackendInfo(d) => success_response(Some(d)),
                InflightMetrics(d) => success_response(Some(d)),
                _ => panic!("Unexpected response message from API service"),
            }
        }
        Err(e) => {
            let status_code = translate_status_code(&e);
            error_response(op(e), status_code)
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
                Ok(convert_to_response(r, HttpError::DaemonInfo))
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
                let r = kicker(ApiRequest::Mount(mountpoint, cmd));
                Ok(convert_to_response(r, HttpError::Mount))
            }
            (Method::Put, Some(body)) => {
                let cmd = parse_body(body)?;
                let r = kicker(ApiRequest::Remount(mountpoint, cmd));
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

pub struct StartHandler {}
impl EndpointHandler for StartHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Put, None) => {
                let r = kicker(ApiRequest::Start);
                Ok(convert_to_response(r, HttpError::Upgrade))
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
