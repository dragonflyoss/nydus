// Copyright 2022 Alibaba Cloud. All rights reserved.
// Copyright 2020 Ant Group. All rights reserved.
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::{self, Error, ErrorKind, Result};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvError, SendError, Sender};
use std::sync::Arc;
use std::thread;
use std::time::SystemTime;

use dbs_uhttp::{Body, HttpServer, MediaType, Request, Response, ServerError, StatusCode, Version};
use http::uri::Uri;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};
use nydus_utils::metrics::IoStatsError;
use serde::Deserialize;
use serde_json::{Error as SerdeError, Value};
use url::Url;

use crate::http_endpoint_v1::{
    EventsHandler, ExitHandler, FsBackendInfo, InfoHandler, MetricsBackendHandler,
    MetricsBlobcacheHandler, MetricsFilesHandler, MetricsHandler, MetricsInflightHandler,
    MetricsPatternHandler, MountHandler, SendFuseFdHandler, TakeoverHandler, HTTP_ROOT_V1,
};
use crate::http_endpoint_v2::{BlobObjectListHandlerV2, HTTP_ROOT_V2};

const EXIT_TOKEN: Token = Token(usize::MAX);
const REQUEST_TOKEN: Token = Token(1);

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

#[derive(Clone, Deserialize, Debug)]
pub struct DaemonConf {
    pub log_level: String,
}

/// Configuration information for a cached blob, corresponding to `storage::FactoryConfig`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlobCacheEntryConfig {
    /// Identifier for the blob cache configuration: corresponding to `FactoryConfig::id`.
    #[serde(default)]
    pub id: String,
    /// Type of storage backend, corresponding to `FactoryConfig::BackendConfig::backend_type`.
    pub backend_type: String,
    /// Configuration for storage backend, corresponding to `FactoryConfig::BackendConfig::backend_config`.
    /// One of `LocalFsConfig`, `CommonConfig`.
    pub backend_config: Value,
    /// Type of blob cache, corresponding to `FactoryConfig::CacheConfig::cache_type`.
    #[serde(default)]
    pub cache_type: String,
    /// Configuration for blob cache, corresponding to `FactoryConfig::CacheConfig::cache_config`.
    /// One of `FileCacheConfig`, `FsCacheConfig`, or empty.
    #[serde(default)]
    pub cache_config: Value,
    /// Optional file path for metadata blobs.
    #[serde(default)]
    pub metadata_path: Option<String>,
}

/// Blob cache object type for nydus/rafs bootstrap blob.
pub const BLOB_CACHE_TYPE_BOOTSTRAP: &str = "bootstrap";
/// Blob cache object type for nydus/rafs data blob.
pub const BLOB_CACHE_TYPE_DATA_BLOB: &str = "datablob";

/// Configuration information for a cached blob.
#[derive(Debug, Deserialize, Serialize)]
pub struct BlobCacheEntry {
    /// Type of blob object, bootstrap or data blob.
    #[serde(rename = "type")]
    pub blob_type: String,
    /// Blob id.
    #[serde(rename = "id")]
    pub blob_id: String,
    /// Configuration information to generate blob cache object.
    #[serde(rename = "config")]
    pub blob_config: BlobCacheEntryConfig,
    /// Domain id for the blob, which is used to group cached blobs into management domains.
    #[serde(default)]
    pub domain_id: String,
}

/// Configuration information for a list of cached blob objects.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct BlobCacheList {
    /// List of blob configuration information.
    pub blobs: Vec<BlobCacheEntry>,
}

#[derive(Clone, Deserialize, Debug)]
pub struct BlobObjectParam {
    pub blob_id: String,
}

#[derive(Debug)]
pub enum ApiRequest {
    // Common requests
    ConfigureDaemon(DaemonConf),

    // Nydus API v1 requests
    DaemonInfo,
    Events,
    ExportGlobalMetrics(Option<String>),
    ExportAccessPatterns(Option<String>),
    ExportBackendMetrics(Option<String>),
    ExportBlobcacheMetrics(Option<String>),
    ExportFilesMetrics(Option<String>, bool),
    Exit,
    Takeover,

    // Filesystem Related
    Mount(String, ApiMountCmd),
    Remount(String, ApiMountCmd),
    Umount(String),
    ExportFsBackendInfo(String),
    ExportInflightMetrics,
    SendFuseFd,

    // Nydus API v2
    DaemonInfoV2,
    CreateBlobObject(BlobCacheEntry),
    GetBlobObject(BlobObjectParam),
    DeleteBlobObject(BlobObjectParam),
    ListBlobObject,
}

#[derive(Debug)]
pub enum DaemonErrorKind {
    NotReady,
    Other(String),
    Serde(SerdeError),
    UnexpectedEvent(String),
    UpgradeManager,
    Unsupported,
}

#[derive(Debug)]
pub enum MetricsErrorKind {
    // Errors about daemon working status
    Daemon(DaemonErrorKind),
    // Errors about metrics/stats recorders
    Stats(IoStatsError),
}

/// Errors generated by/related to the API service, sent back through `ApiResponse`.
#[derive(Debug)]
pub enum ApiError {
    /// Daemon internal error
    DaemonAbnormal(DaemonErrorKind),
    /// Failed to get events information
    Events(String),
    /// Failed to get metrics information
    Metrics(MetricsErrorKind),
    /// Failed to mount filesystem
    MountFilesystem(DaemonErrorKind),
    /// Failed to send request to the API service
    RequestSend(SendError<Option<ApiRequest>>),
    /// Unrecognized payload content
    ResponsePayloadType,
    /// Failed to receive response from the API service
    ResponseRecv(RecvError),
    /// Failed to send wakeup notification
    Wakeup(io::Error),
}

/// Specialized `std::result::Result` for API replies.
pub type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Serialize)]
pub enum ApiResponsePayload {
    /// Daemon version, configuration and status information in json.
    DaemonInfo(String),
    /// No data is sent on the channel.
    Empty,

    /// Filesystem backend metrics.
    BackendMetrics(String),
    /// Blobcache metrics.
    BlobcacheMetrics(String),
    /// Global events.
    Events(String),
    /// Filesystem global metrics.
    FsGlobalMetrics(String),
    /// Filesystem per-file metrics.
    FsFilesMetrics(String),
    /// Filesystem access pattern trace log.
    FsFilesPatterns(String),

    // Filesystem Backend Information
    FsBackendInfo(String),
    // Filesystem Inflight Requests
    InflightMetrics(String),

    /// List of blob objects, v2
    BlobObjectList(String),
}

/// HTTP error messages sent back to the clients.
///
/// The `HttpError` object will be sent back to client with `format!("{:?}", http_error)`.
/// So unfortunately it implicitly becomes parts of the API, please keep it stable.
#[derive(Debug)]
pub enum HttpError {
    // Daemon common related errors
    /// Invalid HTTP request
    BadRequest,
    /// Failed to configure the daemon.
    Configure(ApiError),
    /// Failed to query information about daemon.
    DaemonInfo(ApiError),
    /// No handler registered for HTTP request URI
    NoRoute,
    /// Failed to parse HTTP request message body
    ParseBody(SerdeError),
    /// Query parameter is missed from the HTTP request.
    QueryString(String),

    // Metrics related errors
    /// Failed to query global events.
    Events(ApiError),
    /// Failed to get backend metrics.
    BackendMetrics(ApiError),
    /// Failed to get blobcache metrics.
    BlobcacheMetrics(ApiError),
    /// Failed to get global metrics.
    GlobalMetrics(ApiError),
    /// Failed to get filesystem per-file metrics.
    FsFilesMetrics(ApiError),
    /// Failed to get filesystem file access trace.
    Pattern(ApiError),

    // Filesystem related errors (v1)
    /// Failed to get filesystem backend information
    FsBackendInfo(ApiError),
    /// Failed to get information about inflight request
    InflightMetrics(ApiError),
    /// Failed to mount filesystem.
    Mount(ApiError),
    /// Failed to remount filesystem.
    Upgrade(ApiError),

    // Blob cache management related errors (v2)
    /// Failed to create blob object
    CreateBlobObject(ApiError),
    /// Failed to create blob object
    DeleteBlobObject(ApiError),
    /// Failed to list existing blob objects
    GetBlobObjects(ApiError),
}

// This is the response sent by the API server through the mpsc channel.
pub type ApiResponse = std::result::Result<ApiResponsePayload, ApiError>;
pub type HttpResult = std::result::Result<Response, HttpError>;

#[derive(Serialize, Debug)]
struct ErrorMessage {
    code: String,
    message: String,
}

impl From<ErrorMessage> for Vec<u8> {
    fn from(msg: ErrorMessage) -> Self {
        // Safe to unwrap since `ErrorMessage` must succeed in serialization
        serde_json::to_vec(&msg).unwrap()
    }
}

pub fn extract_query_part(req: &Request, key: &str) -> Option<String> {
    // Splicing req.uri with "http:" prefix might look weird, but since it depends on
    // crate `Url` to generate query_pairs HashMap, which is working on top of Url not Uri.
    // Better that we can add query part support to Micro-http in the future. But
    // right now, below way makes it easy to obtain query parts from uri.
    let http_prefix = format!("http:{}", req.uri().get_abs_path());
    let url = Url::parse(&http_prefix)
        .map_err(|e| {
            error!("Can't parse request {:?}", e);
            e
        })
        .ok()?;

    for (k, v) in url.query_pairs() {
        if k == key {
            trace!("Got query part {:?}", (k, &v));
            return Some(v.into_owned());
        }
    }
    None
}

/// Parse HTTP request body.
pub(crate) fn parse_body<'a, F: Deserialize<'a>>(b: &'a Body) -> std::result::Result<F, HttpError> {
    serde_json::from_slice::<F>(b.raw()).map_err(HttpError::ParseBody)
}

/// Translate ApiError message to HTTP status code.
pub(crate) fn translate_status_code(e: &ApiError) -> StatusCode {
    match e {
        ApiError::DaemonAbnormal(kind) | ApiError::MountFilesystem(kind) => match kind {
            DaemonErrorKind::NotReady => StatusCode::ServiceUnavailable,
            DaemonErrorKind::Unsupported => StatusCode::NotImplemented,
            DaemonErrorKind::UnexpectedEvent(_) => StatusCode::BadRequest,
            _ => StatusCode::InternalServerError,
        },
        ApiError::Metrics(MetricsErrorKind::Stats(IoStatsError::NoCounter)) => StatusCode::NotFound,
        _ => StatusCode::InternalServerError,
    }
}

/// Generate a successful HTTP response message.
pub(crate) fn success_response(body: Option<String>) -> Response {
    if let Some(body) = body {
        let mut r = Response::new(Version::Http11, StatusCode::OK);
        r.set_body(Body::new(body));
        r
    } else {
        Response::new(Version::Http11, StatusCode::NoContent)
    }
}

/// Generate a HTTP error response message with status code and error message.
pub(crate) fn error_response(error: HttpError, status: StatusCode) -> Response {
    let mut response = Response::new(Version::Http11, status);
    let err_msg = ErrorMessage {
        code: "UNDEFINED".to_string(),
        message: format!("{:?}", error),
    };
    response.set_body(Body::new(err_msg));
    response
}

/// Trait for HTTP endpoints to handle HTTP requests.
pub trait EndpointHandler: Sync + Send {
    /// Handles an HTTP request.
    ///
    /// The main responsibilities of the handlers includes:
    /// - parse and validate incoming request message
    /// - send the request to subscriber
    /// - wait response from the subscriber
    /// - generate HTTP result
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult;
}

/// Struct to route HTTP requests to corresponding registered endpoint handlers.
pub struct HttpRoutes {
    /// routes is a hash table mapping endpoint URIs to their endpoint handlers.
    pub routes: HashMap<String, Box<dyn EndpointHandler + Sync + Send>>,
}

macro_rules! endpoint_v1 {
    ($path:expr) => {
        format!("{}{}", HTTP_ROOT_V1, $path)
    };
}

macro_rules! endpoint_v2 {
    ($path:expr) => {
        format!("{}{}", HTTP_ROOT_V2, $path)
    };
}

lazy_static! {
    /// HTTP_ROUTES contain all the nydusd HTTP routes.
    pub static ref HTTP_ROUTES: HttpRoutes = {
        let mut r = HttpRoutes {
            routes: HashMap::new(),
        };

        // Global
        r.routes.insert(endpoint_v1!("/daemon"), Box::new(InfoHandler{}));
        r.routes.insert(endpoint_v2!("/daemon"), Box::new(InfoHandler{}));
        r.routes.insert(endpoint_v1!("/daemon/backend"), Box::new(FsBackendInfo{}));
        r.routes.insert(endpoint_v2!("/daemon/backend"), Box::new(FsBackendInfo{}));
        r.routes.insert(endpoint_v1!("/daemon/events"), Box::new(EventsHandler{}));
        r.routes.insert(endpoint_v2!("/daemon/events"), Box::new(EventsHandler{}));
        r.routes.insert(endpoint_v1!("/daemon/exit"), Box::new(ExitHandler{}));
        r.routes.insert(endpoint_v2!("/daemon/exit"), Box::new(ExitHandler{}));
        r.routes.insert(endpoint_v1!("/metrics/backend"), Box::new(MetricsBackendHandler{}));
        r.routes.insert(endpoint_v2!("/metrics/backend"), Box::new(MetricsBackendHandler{}));
        r.routes.insert(endpoint_v1!("/metrics/blobcache"), Box::new(MetricsBlobcacheHandler{}));
        r.routes.insert(endpoint_v2!("/metrics/blobcache"), Box::new(MetricsBlobcacheHandler{}));
        r.routes.insert(endpoint_v1!("/metrics/files"), Box::new(MetricsFilesHandler{}));
        r.routes.insert(endpoint_v2!("/metrics/files"), Box::new(MetricsFilesHandler{}));
        r.routes.insert(endpoint_v1!("/metrics/pattern"), Box::new(MetricsPatternHandler{}));
        r.routes.insert(endpoint_v2!("/metrics/pattern"), Box::new(MetricsPatternHandler{}));

        // Nydus API, v1
        r.routes.insert(endpoint_v1!("/mount"), Box::new(MountHandler{}));
        r.routes.insert(endpoint_v1!("/metrics"), Box::new(MetricsHandler{}));
        r.routes.insert(endpoint_v1!("/metrics/inflight"), Box::new(MetricsInflightHandler{}));
        r.routes.insert(endpoint_v1!("/daemon/fuse/sendfd"), Box::new(SendFuseFdHandler{}));
        r.routes.insert(endpoint_v1!("/daemon/fuse/takeover"), Box::new(TakeoverHandler{}));

        // Nydus API, v2
        r.routes.insert(endpoint_v2!("/blobs"), Box::new(BlobObjectListHandlerV2{}));

        r
    };
}

fn kick_api_server(
    api_notifier: Option<Arc<Waker>>,
    to_api: &Sender<Option<ApiRequest>>,
    from_api: &Receiver<ApiResponse>,
    request: ApiRequest,
) -> ApiResponse {
    to_api.send(Some(request)).map_err(ApiError::RequestSend)?;
    if let Some(waker) = api_notifier {
        waker.wake().map_err(ApiError::Wakeup)?;
    }
    from_api.recv().map_err(ApiError::ResponseRecv)?
}

// Example:
// <-- GET /
// --> GET / 200 835ms 746b

fn trace_api_begin(request: &dbs_uhttp::Request) {
    info!("<--- {:?} {:?}", request.method(), request.uri());
}

fn trace_api_end(response: &dbs_uhttp::Response, method: dbs_uhttp::Method, recv_time: SystemTime) {
    let elapse = SystemTime::now().duration_since(recv_time);
    info!(
        "---> {:?} Status Code: {:?}, Elapse: {:?}, Body Size: {:?}",
        method,
        response.status(),
        elapse,
        response.content_length()
    );
}

fn exit_api_server(api_notifier: Option<Arc<Waker>>, to_api: &Sender<Option<ApiRequest>>) {
    if to_api.send(None).is_err() {
        error!("failed to send stop request api server");
        return;
    }
    if let Some(waker) = api_notifier {
        let _ = waker
            .wake()
            .map_err(|_e| error!("failed to send notify api server for exit"));
    }
}

fn handle_http_request(
    request: &Request,
    api_notifier: Option<Arc<Waker>>,
    to_api: &Sender<Option<ApiRequest>>,
    from_api: &Receiver<ApiResponse>,
) -> Response {
    let begin_time = SystemTime::now();
    trace_api_begin(request);

    // Micro http should ensure that req path is legal.
    let uri_parsed = request.uri().get_abs_path().parse::<Uri>();
    let mut response = match uri_parsed {
        Ok(uri) => match HTTP_ROUTES.routes.get(uri.path()) {
            Some(route) => route
                .handle_request(&request, &|r| {
                    kick_api_server(api_notifier.clone(), to_api, from_api, r)
                })
                .unwrap_or_else(|err| error_response(err, StatusCode::BadRequest)),
            None => error_response(HttpError::NoRoute, StatusCode::NotFound),
        },
        Err(e) => {
            error!("Failed parse URI, {}", e);
            error_response(HttpError::BadRequest, StatusCode::BadRequest)
        }
    };
    response.set_server("Nydus API");
    response.set_content_type(MediaType::ApplicationJson);

    trace_api_end(&response, request.method(), begin_time);

    response
}

/// Start a HTTP server parsing http requests and send to nydus API server a concrete
/// request to operate nydus or fetch working status.
/// The HTTP server sends request by `to_api` channel and wait for response from `from_api` channel.
pub fn start_http_thread(
    path: &str,
    api_notifier: Option<Arc<Waker>>,
    to_api: Sender<Option<ApiRequest>>,
    from_api: Receiver<ApiResponse>,
) -> Result<(thread::JoinHandle<Result<()>>, Arc<Waker>)> {
    // Try to remove existed unix domain socket
    std::fs::remove_file(path).unwrap_or_default();
    let socket_path = PathBuf::from(path);

    let mut pool = Poll::new()?;
    let waker = Waker::new(pool.registry(), EXIT_TOKEN)?;
    let waker = Arc::new(waker);
    let mut server = HttpServer::new(socket_path).map_err(|e| {
        if let ServerError::IOError(e) = e {
            e
        } else {
            Error::new(ErrorKind::Other, format!("{:?}", e))
        }
    })?;
    pool.registry().register(
        &mut SourceFd(&server.epoll().as_raw_fd()),
        REQUEST_TOKEN,
        Interest::READABLE,
    )?;

    let thread = thread::Builder::new()
        .name("http-server".to_string())
        .spawn(move || {
            // Must start the server successfully or just die by panic
            server.start_server().unwrap();
            info!("http server started");

            let mut events = Events::with_capacity(100);
            'wait: loop {
                match pool.poll(&mut events, None) {
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        error!("http server poll events failed, {}", e);
                        return Err(e);
                    }
                    Ok(_) => {}
                }

                for event in &events {
                    match event.token() {
                        EXIT_TOKEN => {
                            exit_api_server(api_notifier.clone(), &to_api);
                            break 'wait;
                        }
                        REQUEST_TOKEN => match server.requests() {
                            Ok(request_vec) => {
                                for server_request in request_vec {
                                    let reply = server_request.process(|request| {
                                        handle_http_request(
                                            request,
                                            api_notifier.clone(),
                                            &to_api,
                                            &from_api,
                                        )
                                    });
                                    // Ignore error when sending response
                                    server.respond(reply).unwrap_or_else(|e| {
                                        error!("HTTP server error on response: {}", e)
                                    });
                                }
                            }
                            Err(e) => {
                                error!("HTTP server error on retrieving incoming request: {}", e);
                            }
                        },
                        _ => unreachable!("unknown poll token."),
                    }
                }
            }

            info!("http-server thread exits");
            Ok(())
        })?;

    Ok((thread, waker))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;
    use vmm_sys_util::tempfile::TempFile;

    #[test]
    fn test_http_api_routes_v1() {
        assert!(HTTP_ROUTES.routes.get("/api/v1/daemon").is_some());
        assert!(HTTP_ROUTES.routes.get("/api/v1/daemon/events").is_some());
        assert!(HTTP_ROUTES.routes.get("/api/v1/daemon/backend").is_some());
        assert!(HTTP_ROUTES.routes.get("/api/v1/daemon/exit").is_some());
        assert!(HTTP_ROUTES
            .routes
            .get("/api/v1/daemon/fuse/sendfd")
            .is_some());
        assert!(HTTP_ROUTES
            .routes
            .get("/api/v1/daemon/fuse/takeover")
            .is_some());
        assert!(HTTP_ROUTES.routes.get("/api/v1/metrics").is_some());
        assert!(HTTP_ROUTES.routes.get("/api/v1/metrics/files").is_some());
        assert!(HTTP_ROUTES.routes.get("/api/v1/metrics/pattern").is_some());
        assert!(HTTP_ROUTES.routes.get("/api/v1/metrics/backend").is_some());
        assert!(HTTP_ROUTES
            .routes
            .get("/api/v1/metrics/blobcache")
            .is_some());
        assert!(HTTP_ROUTES.routes.get("/api/v1/metrics/inflight").is_some());
    }

    #[test]
    fn test_http_api_routes_v2() {
        assert!(HTTP_ROUTES.routes.get("/api/v2/daemon").is_some());
    }

    #[test]
    fn test_kick_api_server() {
        let (to_api, from_route) = channel();
        let (to_route, from_api) = channel();
        let request = ApiRequest::DaemonInfo;
        let thread =
            thread::spawn(
                move || match kick_api_server(None, &to_api, &from_api, request) {
                    Err(reply) => matches!(reply, ApiError::ResponsePayloadType),
                    Ok(_) => panic!("unexpected reply message"),
                },
            );
        let req2 = from_route.recv().unwrap();
        matches!(req2.as_ref().unwrap(), ApiRequest::DaemonInfo);
        let reply: ApiResponse = Err(ApiError::ResponsePayloadType);
        to_route.send(reply).unwrap();
        thread.join().unwrap();

        let (to_api, from_route) = channel();
        let (to_route, from_api) = channel();
        drop(to_route);
        let request = ApiRequest::DaemonInfo;
        assert!(kick_api_server(None, &to_api, &from_api, request).is_err());
        drop(from_route);
        let request = ApiRequest::DaemonInfo;
        assert!(kick_api_server(None, &to_api, &from_api, request).is_err());
    }

    #[test]
    fn test_extract_query_part() {
        let req = Request::try_from(
            b"GET http://localhost/api/v1/daemon?arg1=test HTTP/1.0\r\n\r\n",
            None,
        )
        .unwrap();
        let arg1 = extract_query_part(&req, "arg1").unwrap();
        assert_eq!(arg1, "test");
        assert!(extract_query_part(&req, "arg2").is_none());
    }

    #[test]
    fn test_start_http_thread() {
        let tmpdir = TempFile::new().unwrap();
        let path = tmpdir.as_path().to_str().unwrap();
        let (to_api, from_route) = channel();
        let (_to_route, from_api) = channel();
        let (thread, waker) = start_http_thread(path, None, to_api, from_api).unwrap();
        waker.wake().unwrap();

        let msg = from_route.recv().unwrap();
        assert!(msg.is_none());
        let _ = thread.join().unwrap();
    }
}
