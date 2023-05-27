use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::SystemTime;
use std::{fs, thread};

use dbs_uhttp::{Body, HttpServer, MediaType, Request, Response, ServerError, StatusCode, Version};

use http::uri::Uri;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};
use serde::Deserialize;
use url::Url;

use crate::http::{
    ApiError, ApiRequest, ApiResponse, DaemonErrorKind, ErrorMessage, HttpError, MetricsError,
    MetricsErrorKind,
};
use crate::http_endpoint_common::{
    EventsHandler, ExitHandler, MetricsBackendHandler, MetricsBlobcacheHandler, MountHandler,
    SendFuseFdHandler, StartHandler, TakeoverFuseFdHandler,
};
use crate::http_endpoint_v1::{
    FsBackendInfo, InfoHandler, MetricsFsAccessPatternHandler, MetricsFsFilesHandler,
    MetricsFsGlobalHandler, MetricsFsInflightHandler, HTTP_ROOT_V1,
};
use crate::http_endpoint_v2::{BlobObjectListHandlerV2, InfoV2Handler, HTTP_ROOT_V2};

const EXIT_TOKEN: Token = Token(usize::MAX);
const REQUEST_TOKEN: Token = Token(1);

/// Specialized version of [`std::result::Result`] for value returned by [`EndpointHandler`].
pub type HttpResult = std::result::Result<Response, HttpError>;

/// Get query parameter with `key` from the HTTP request.
pub fn extract_query_part(req: &Request, key: &str) -> Option<String> {
    // Splicing req.uri with "http:" prefix might look weird, but since it depends on
    // crate `Url` to generate query_pairs HashMap, which is working on top of Url not Uri.
    // Better that we can add query part support to Micro-http in the future. But
    // right now, below way makes it easy to obtain query parts from uri.
    let http_prefix = format!("http:{}", req.uri().get_abs_path());
    let url = Url::parse(&http_prefix)
        .map_err(|e| {
            error!("api: can't parse request {:?}", e);
            e
        })
        .ok()?;

    for (k, v) in url.query_pairs() {
        if k == key {
            trace!("api: got query param {}={}", k, v);
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
        ApiError::Metrics(MetricsErrorKind::Stats(MetricsError::NoCounter)) => StatusCode::NotFound,
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

        // Common
        r.routes.insert(endpoint_v1!("/daemon/events"), Box::new(EventsHandler{}));
        r.routes.insert(endpoint_v1!("/daemon/exit"), Box::new(ExitHandler{}));
        r.routes.insert(endpoint_v1!("/daemon/start"), Box::new(StartHandler{}));
        r.routes.insert(endpoint_v1!("/daemon/fuse/sendfd"), Box::new(SendFuseFdHandler{}));
        r.routes.insert(endpoint_v1!("/daemon/fuse/takeover"), Box::new(TakeoverFuseFdHandler{}));
        r.routes.insert(endpoint_v1!("/mount"), Box::new(MountHandler{}));
        r.routes.insert(endpoint_v1!("/metrics/backend"), Box::new(MetricsBackendHandler{}));
        r.routes.insert(endpoint_v1!("/metrics/blobcache"), Box::new(MetricsBlobcacheHandler{}));

        // Nydus API, v1
        r.routes.insert(endpoint_v1!("/daemon"), Box::new(InfoHandler{}));
        r.routes.insert(endpoint_v1!("/daemon/backend"), Box::new(FsBackendInfo{}));
        r.routes.insert(endpoint_v1!("/metrics"), Box::new(MetricsFsGlobalHandler{}));
        r.routes.insert(endpoint_v1!("/metrics/files"), Box::new(MetricsFsFilesHandler{}));
        r.routes.insert(endpoint_v1!("/metrics/inflight"), Box::new(MetricsFsInflightHandler{}));
        r.routes.insert(endpoint_v1!("/metrics/pattern"), Box::new(MetricsFsAccessPatternHandler{}));

        // Nydus API, v2
        r.routes.insert(endpoint_v2!("/daemon"), Box::new(InfoV2Handler{}));
        r.routes.insert(endpoint_v2!("/blobs"), Box::new(BlobObjectListHandlerV2{}));

        r
    };
}

fn kick_api_server(
    to_api: &Sender<Option<ApiRequest>>,
    from_api: &Receiver<ApiResponse>,
    request: ApiRequest,
) -> ApiResponse {
    to_api.send(Some(request)).map_err(ApiError::RequestSend)?;
    from_api.recv().map_err(ApiError::ResponseRecv)?
}

// Example:
// <-- GET /
// --> GET / 200 835ms 746b

fn trace_api_begin(request: &dbs_uhttp::Request) {
    debug!("<--- {:?} {:?}", request.method(), request.uri());
}

fn trace_api_end(response: &dbs_uhttp::Response, method: dbs_uhttp::Method, recv_time: SystemTime) {
    let elapse = SystemTime::now().duration_since(recv_time);
    debug!(
        "---> {:?} Status Code: {:?}, Elapse: {:?}, Body Size: {:?}",
        method,
        response.status(),
        elapse,
        response.content_length()
    );
}

fn exit_api_server(to_api: &Sender<Option<ApiRequest>>) {
    if to_api.send(None).is_err() {
        error!("failed to send stop request api server");
    }
}

fn handle_http_request(
    request: &Request,
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
                .handle_request(request, &|r| kick_api_server(to_api, from_api, r))
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

/// Start a HTTP server to serve API requests.
///
/// Start a HTTP server parsing http requests and send to nydus API server a concrete
/// request to operate nydus or fetch working status.
/// The HTTP server sends request by `to_api` channel and wait for response from `from_api` channel.
pub fn start_http_thread(
    path: &str,
    to_api: Sender<Option<ApiRequest>>,
    from_api: Receiver<ApiResponse>,
) -> Result<(thread::JoinHandle<Result<()>>, Arc<Waker>)> {
    // Try to remove existed unix domain socket
    let _ = fs::remove_file(path);
    let socket_path = PathBuf::from(path);

    let mut poll = Poll::new()?;
    let waker = Arc::new(Waker::new(poll.registry(), EXIT_TOKEN)?);
    let waker2 = waker.clone();
    let mut server = HttpServer::new(socket_path).map_err(|e| {
        if let ServerError::IOError(e) = e {
            e
        } else {
            Error::new(ErrorKind::Other, format!("{:?}", e))
        }
    })?;
    poll.registry().register(
        &mut SourceFd(&server.epoll().as_raw_fd()),
        REQUEST_TOKEN,
        Interest::READABLE,
    )?;

    let thread = thread::Builder::new()
        .name("nydus-http-server".to_string())
        .spawn(move || {
            // Must start the server successfully or just die by panic
            server.start_server().unwrap();
            info!("http server started");

            let mut events = Events::with_capacity(100);
            let mut do_exit = false;
            loop {
                match poll.poll(&mut events, None) {
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        error!("http server poll events failed, {}", e);
                        exit_api_server(&to_api);
                        return Err(e);
                    }
                    Ok(_) => {}
                }

                for event in &events {
                    match event.token() {
                        EXIT_TOKEN => do_exit = true,
                        REQUEST_TOKEN => match server.requests() {
                            Ok(request_vec) => {
                                for server_request in request_vec {
                                    let reply = server_request.process(|request| {
                                        handle_http_request(request, &to_api, &from_api)
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

                if do_exit {
                    exit_api_server(&to_api);
                    break;
                }
            }

            info!("http-server thread exits");
            // Keep the Waker alive to match the lifetime of the poll loop above
            drop(waker2);
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
        assert!(HTTP_ROUTES.routes.get("/api/v1/daemon/start").is_some());
        assert!(HTTP_ROUTES.routes.get("/api/v1/daemon/exit").is_some());
        assert!(HTTP_ROUTES
            .routes
            .get("/api/v1/daemon/fuse/sendfd")
            .is_some());
        assert!(HTTP_ROUTES
            .routes
            .get("/api/v1/daemon/fuse/takeover")
            .is_some());
        assert!(HTTP_ROUTES.routes.get("/api/v1/mount").is_some());
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
        assert!(HTTP_ROUTES.routes.get("/api/v2/blobs").is_some());
    }

    #[test]
    fn test_kick_api_server() {
        let (to_api, from_route) = channel();
        let (to_route, from_api) = channel();
        let request = ApiRequest::GetDaemonInfo;
        let thread = thread::spawn(move || match kick_api_server(&to_api, &from_api, request) {
            Err(reply) => matches!(reply, ApiError::ResponsePayloadType),
            Ok(_) => panic!("unexpected reply message"),
        });
        let req2 = from_route.recv().unwrap();
        matches!(req2.as_ref().unwrap(), ApiRequest::GetDaemonInfo);
        let reply: ApiResponse = Err(ApiError::ResponsePayloadType);
        to_route.send(reply).unwrap();
        thread.join().unwrap();

        let (to_api, from_route) = channel();
        let (to_route, from_api) = channel();
        drop(to_route);
        let request = ApiRequest::GetDaemonInfo;
        assert!(kick_api_server(&to_api, &from_api, request).is_err());
        drop(from_route);
        let request = ApiRequest::GetDaemonInfo;
        assert!(kick_api_server(&to_api, &from_api, request).is_err());
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
        let (thread, waker) = start_http_thread(path, to_api, from_api).unwrap();
        waker.wake().unwrap();

        let msg = from_route.recv().unwrap();
        assert!(msg.is_none());
        let _ = thread.join().unwrap();
    }
}
