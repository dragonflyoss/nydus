// Copyright 2020 Ant Group. All rights reserved.
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

//! Nydus API v1.

use dbs_uhttp::{Method, Request, Response};

use crate::http::{ApiError, ApiRequest, ApiResponse, ApiResponsePayload, Config, HttpError};
use crate::http_handler::{
    error_response, extract_query_part, parse_body, success_response, translate_status_code,
    EndpointHandler, HttpResult,
};

/// HTTP URI prefix for API v1.
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
                Empty => success_response(None),
                DaemonInfo(d) => success_response(Some(d)),
                FsGlobalMetrics(d) => success_response(Some(d)),
                FsFilesMetrics(d) => success_response(Some(d)),
                FsFilesPatterns(d) => success_response(Some(d)),
                FsBackendInfo(d) => success_response(Some(d)),
                FsInflightMetrics(d) => success_response(Some(d)),
                Config(conf) => {
                    let json = serde_json::to_string(&conf).unwrap_or_else(|_| "{}".to_string());
                    success_response(Some(json))
                }
                _ => panic!("Unexpected response message from API service"),
            }
        }
        Err(e) => {
            let status_code = translate_status_code(&e);
            error_response(op(e), status_code)
        }
    }
}

/// Get daemon information and set daemon configuration.
pub struct InfoHandler {}
impl EndpointHandler for InfoHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let r = kicker(ApiRequest::GetDaemonInfo);
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

/// Get filesystem backend information.
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

/// Get filesystem global metrics.
pub struct MetricsFsGlobalHandler {}
impl EndpointHandler for MetricsFsGlobalHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let id = extract_query_part(req, "id");
                let r = kicker(ApiRequest::ExportFsGlobalMetrics(id));
                Ok(convert_to_response(r, HttpError::GlobalMetrics))
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

/// Get filesystem access pattern log.
pub struct MetricsFsAccessPatternHandler {}
impl EndpointHandler for MetricsFsAccessPatternHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let id = extract_query_part(req, "id");
                let r = kicker(ApiRequest::ExportFsAccessPatterns(id));
                Ok(convert_to_response(r, HttpError::Pattern))
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

/// Get filesystem file metrics.
pub struct MetricsFsFilesHandler {}
impl EndpointHandler for MetricsFsFilesHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let id = extract_query_part(req, "id");
                let latest_read_files = extract_query_part(req, "latest")
                    .is_some_and(|b| b.parse::<bool>().unwrap_or(false));
                let r = kicker(ApiRequest::ExportFsFilesMetrics(id, latest_read_files));
                Ok(convert_to_response(r, HttpError::FsFilesMetrics))
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

/// Get information about filesystem inflight requests.
pub struct MetricsFsInflightHandler {}
impl EndpointHandler for MetricsFsInflightHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let r = kicker(ApiRequest::ExportFsInflightMetrics);
                Ok(convert_to_response(r, HttpError::InflightMetrics))
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

/// Update global configuration of the daemon.
pub struct ConfigHandler {}
impl EndpointHandler for ConfigHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let id = extract_query_part(req, "id");
                let r = kicker(ApiRequest::GetConfig(id));
                Ok(convert_to_response(r, HttpError::Configure))
            }
            (Method::Put, Some(body)) => {
                let conf: Config = parse_body(body)?;
                let id = extract_query_part(req, "id");
                let r = kicker(ApiRequest::UpdateConfig(id, conf));
                Ok(convert_to_response(r, HttpError::Configure))
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{ApiResponse, ApiResponsePayload, HttpError};
    use dbs_uhttp::Request;
    use std::collections::HashMap;

    fn get_req(url: &str) -> Request {
        let raw = format!("GET {} HTTP/1.0\r\n\r\n", url);
        Request::try_from(raw.as_bytes(), None).unwrap()
    }

    fn put_req_body(url: &str, body: &str) -> Request {
        let raw = format!(
            "PUT {} HTTP/1.0\r\nContent-Length: {}\r\n\r\n{}",
            url,
            body.len(),
            body
        );
        Request::try_from(raw.as_bytes(), None).unwrap()
    }

    fn ok_empty() -> ApiResponse {
        Ok(ApiResponsePayload::Empty)
    }

    #[test]
    fn test_info_handler_get() {
        let handler = InfoHandler {};
        let req = get_req("http://localhost/api/v1/daemon");
        let result = handler.handle_request(&req, &|_| {
            Ok(ApiResponsePayload::DaemonInfo("{}".to_string()))
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_info_handler_put() {
        let handler = InfoHandler {};
        let body = r#"{"log_level":"info"}"#;
        let req = put_req_body("http://localhost/api/v1/daemon", body);
        let result = handler.handle_request(&req, &|_| ok_empty());
        assert!(result.is_ok());
    }

    #[test]
    fn test_info_handler_bad_method() {
        let handler = InfoHandler {};
        let raw = b"DELETE http://localhost/api/v1/daemon HTTP/1.0\r\n\r\n";
        let req = Request::try_from(raw.as_slice(), None).unwrap();
        let result = handler.handle_request(&req, &|_| ok_empty());
        assert!(matches!(result, Err(HttpError::BadRequest)));
    }

    #[test]
    fn test_fs_backend_info_get_with_mountpoint() {
        let handler = FsBackendInfo {};
        let req = get_req("http://localhost/api/v1/daemon/backend?mountpoint=/test");
        let result = handler.handle_request(&req, &|_| {
            Ok(ApiResponsePayload::FsBackendInfo("{}".to_string()))
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_fs_backend_info_get_without_mountpoint() {
        let handler = FsBackendInfo {};
        let req = get_req("http://localhost/api/v1/daemon/backend");
        let result = handler.handle_request(&req, &|_| ok_empty());
        assert!(matches!(result, Err(HttpError::QueryString(_))));
    }

    #[test]
    fn test_metrics_global_handler_get() {
        let handler = MetricsFsGlobalHandler {};
        let req = get_req("http://localhost/api/v1/metrics");
        let result = handler.handle_request(&req, &|_| {
            Ok(ApiResponsePayload::FsGlobalMetrics("{}".to_string()))
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_metrics_global_handler_bad_method() {
        let handler = MetricsFsGlobalHandler {};
        let raw = b"DELETE http://localhost/api/v1/metrics HTTP/1.0\r\n\r\n";
        let req = Request::try_from(raw.as_slice(), None).unwrap();
        let result = handler.handle_request(&req, &|_| ok_empty());
        assert!(matches!(result, Err(HttpError::BadRequest)));
    }

    #[test]
    fn test_metrics_access_pattern_handler_get() {
        let handler = MetricsFsAccessPatternHandler {};
        let req = get_req("http://localhost/api/v1/metrics/pattern");
        let result = handler.handle_request(&req, &|_| {
            Ok(ApiResponsePayload::FsFilesPatterns("[]".to_string()))
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_metrics_files_handler_get() {
        let handler = MetricsFsFilesHandler {};
        let req = get_req("http://localhost/api/v1/metrics/files");
        let result = handler.handle_request(&req, &|_| {
            Ok(ApiResponsePayload::FsFilesMetrics("[]".to_string()))
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_metrics_files_handler_get_with_latest() {
        let handler = MetricsFsFilesHandler {};
        let req = get_req("http://localhost/api/v1/metrics/files?latest=true");
        let result = handler.handle_request(&req, &|_| {
            Ok(ApiResponsePayload::FsFilesMetrics("[]".to_string()))
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_metrics_inflight_handler_get() {
        let handler = MetricsFsInflightHandler {};
        let req = get_req("http://localhost/api/v1/metrics/inflight");
        let result = handler.handle_request(&req, &|_| {
            Ok(ApiResponsePayload::FsInflightMetrics("{}".to_string()))
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_handler_get() {
        let handler = ConfigHandler {};
        let req = get_req("http://localhost/api/v1/daemon/config?id=test");
        let result =
            handler.handle_request(&req, &|_| Ok(ApiResponsePayload::Config(HashMap::new())));
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_handler_put() {
        let handler = ConfigHandler {};
        let body = r#"{"key":"value"}"#;
        let req = put_req_body("http://localhost/api/v1/daemon/config", body);
        let result = handler.handle_request(&req, &|_| ok_empty());
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_handler_bad_method() {
        let handler = ConfigHandler {};
        let raw = b"DELETE http://localhost/api/v1/daemon/config HTTP/1.0\r\n\r\n";
        let req = Request::try_from(raw.as_slice(), None).unwrap();
        let result = handler.handle_request(&req, &|_| ok_empty());
        assert!(matches!(result, Err(HttpError::BadRequest)));
    }

    #[test]
    fn test_info_handler_error_response() {
        use crate::http::ApiError;
        let handler = InfoHandler {};
        let req = get_req("http://localhost/api/v1/daemon");
        // kicker returns error → handler still returns Ok(error_response)
        let result = handler.handle_request(&req, &|_| Err(ApiError::ResponsePayloadType));
        assert!(result.is_ok());
    }
}
