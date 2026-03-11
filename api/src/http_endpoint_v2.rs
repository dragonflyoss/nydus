// Copyright 2022 Alibaba Cloud. All rights reserved.
// Copyright 2020 Ant Group. All rights reserved.
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

//! Nydus API v2.

use crate::BlobCacheEntry;
use dbs_uhttp::{Method, Request, Response};

use crate::http::{
    ApiError, ApiRequest, ApiResponse, ApiResponsePayload, BlobCacheObjectId, HttpError,
};
use crate::http_handler::{
    error_response, extract_query_part, parse_body, success_response, translate_status_code,
    EndpointHandler, HttpResult,
};

/// HTTP URI prefix for API v2.
pub const HTTP_ROOT_V2: &str = "/api/v2";

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
                BlobObjectList(d) => success_response(Some(d)),
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
pub struct InfoV2Handler {}
impl EndpointHandler for InfoV2Handler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let r = kicker(ApiRequest::GetDaemonInfoV2);
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

/// List blob objects managed by the blob cache manager.
pub struct BlobObjectListHandlerV2 {}
impl EndpointHandler for BlobObjectListHandlerV2 {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                if let Some(domain_id) = extract_query_part(req, "domain_id") {
                    let blob_id = extract_query_part(req, "blob_id").unwrap_or_default();
                    let param = BlobCacheObjectId { domain_id, blob_id };
                    let r = kicker(ApiRequest::GetBlobObject(param));
                    return Ok(convert_to_response(r, HttpError::GetBlobObjects));
                }
                Err(HttpError::BadRequest)
            }
            (Method::Put, Some(body)) => {
                let mut conf: Box<BlobCacheEntry> = parse_body(body)?;
                if !conf.prepare_configuration_info() {
                    return Err(HttpError::BadRequest);
                }
                let r = kicker(ApiRequest::CreateBlobObject(conf));
                Ok(convert_to_response(r, HttpError::CreateBlobObject))
            }
            (Method::Delete, None) => {
                if let Some(domain_id) = extract_query_part(req, "domain_id") {
                    let blob_id = extract_query_part(req, "blob_id").unwrap_or_default();
                    let param = BlobCacheObjectId { domain_id, blob_id };
                    let r = kicker(ApiRequest::DeleteBlobObject(param));
                    return Ok(convert_to_response(r, HttpError::DeleteBlobObject));
                }
                if let Some(blob_id) = extract_query_part(req, "blob_id") {
                    let r = kicker(ApiRequest::DeleteBlobFile(blob_id));
                    return Ok(convert_to_response(r, HttpError::DeleteBlobFile));
                }
                Err(HttpError::BadRequest)
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{ApiError, ApiResponse, ApiResponsePayload, HttpError};
    use dbs_uhttp::Request;

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

    fn delete_req(url: &str) -> Request {
        let raw = format!("DELETE {} HTTP/1.0\r\n\r\n", url);
        Request::try_from(raw.as_bytes(), None).unwrap()
    }

    fn ok_empty() -> ApiResponse {
        Ok(ApiResponsePayload::Empty)
    }

    #[test]
    fn test_info_v2_handler_get() {
        let handler = InfoV2Handler {};
        let req = get_req("http://localhost/api/v2/daemon");
        let result = handler
            .handle_request(&req, &|_| Ok(ApiResponsePayload::DaemonInfo("{}".to_string())));
        assert!(result.is_ok());
    }

    #[test]
    fn test_info_v2_handler_put() {
        let handler = InfoV2Handler {};
        let body = r#"{"log_level":"info"}"#;
        let req = put_req_body("http://localhost/api/v2/daemon", body);
        let result = handler.handle_request(&req, &|_| ok_empty());
        assert!(result.is_ok());
    }

    #[test]
    fn test_info_v2_handler_bad_method() {
        let handler = InfoV2Handler {};
        let raw = b"DELETE http://localhost/api/v2/daemon HTTP/1.0\r\n\r\n";
        let req = Request::try_from(raw.as_slice(), None).unwrap();
        let result = handler.handle_request(&req, &|_| ok_empty());
        assert!(matches!(result, Err(HttpError::BadRequest)));
    }

    #[test]
    fn test_blob_list_handler_get_with_domain_id() {
        let handler = BlobObjectListHandlerV2 {};
        let req = get_req("http://localhost/api/v2/blobs?domain_id=test_domain");
        let result = handler.handle_request(
            &req,
            &|_| Ok(ApiResponsePayload::BlobObjectList("[]".to_string())),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_blob_list_handler_get_without_domain_id() {
        let handler = BlobObjectListHandlerV2 {};
        let req = get_req("http://localhost/api/v2/blobs");
        let result = handler.handle_request(&req, &|_| ok_empty());
        assert!(matches!(result, Err(HttpError::BadRequest)));
    }

    #[test]
    fn test_blob_list_handler_put_invalid_config() {
        // Valid JSON body for BlobCacheEntry but no config → prepare_configuration_info returns false
        let handler = BlobObjectListHandlerV2 {};
        let body = r#"{"type":"bootstrap","id":"test-blob"}"#;
        let req = put_req_body("http://localhost/api/v2/blobs", body);
        let result = handler.handle_request(&req, &|_| ok_empty());
        assert!(matches!(result, Err(HttpError::BadRequest)));
    }

    #[test]
    fn test_blob_list_handler_delete_with_domain_id() {
        let handler = BlobObjectListHandlerV2 {};
        let req = delete_req("http://localhost/api/v2/blobs?domain_id=test_domain");
        let result = handler.handle_request(&req, &|_| ok_empty());
        assert!(result.is_ok());
    }

    #[test]
    fn test_blob_list_handler_delete_with_blob_id_only() {
        let handler = BlobObjectListHandlerV2 {};
        let req = delete_req("http://localhost/api/v2/blobs?blob_id=test_blob");
        let result = handler.handle_request(&req, &|_| ok_empty());
        assert!(result.is_ok());
    }

    #[test]
    fn test_blob_list_handler_delete_without_params() {
        let handler = BlobObjectListHandlerV2 {};
        let req = delete_req("http://localhost/api/v2/blobs");
        let result = handler.handle_request(&req, &|_| ok_empty());
        assert!(matches!(result, Err(HttpError::BadRequest)));
    }

    #[test]
    fn test_blob_list_handler_bad_method() {
        let handler = BlobObjectListHandlerV2 {};
        let raw = b"POST http://localhost/api/v2/blobs HTTP/1.0\r\n\r\n";
        let req = Request::try_from(raw.as_slice(), None).unwrap();
        let result = handler.handle_request(&req, &|_| ok_empty());
        assert!(matches!(result, Err(HttpError::BadRequest)));
    }

    #[test]
    fn test_info_v2_handler_api_error_response() {
        let handler = InfoV2Handler {};
        let req = get_req("http://localhost/api/v2/daemon");
        // kicker returns error → handler still returns Ok(error_response)
        let result = handler.handle_request(&req, &|_| Err(ApiError::ResponsePayloadType));
        assert!(result.is_ok());
    }
}
