// Copyright 2020 Ant Group. All rights reserved.
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::SystemTime;

use http::uri::Uri;
use url::Url;

use dbs_uhttp::{HttpServer, MediaType, Request, Response, ServerError, StatusCode};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};

use crate::http_endpoint_v1::{
    error_response, ApiError, ApiRequest, ApiResponse, EventsHandler, ExitHandler, FsBackendInfo,
    HttpError, HttpResult, InfoHandler, MetricsBackendHandler, MetricsBlobcacheHandler,
    MetricsFilesHandler, MetricsHandler, MetricsInflightHandler, MetricsPatternHandler,
    MountHandler, SendFuseFdHandler, TakeoverHandler,
};

const HTTP_ROOT_V1: &str = "/api/v1";
const EXIT_TOKEN: Token = Token(usize::MAX);
const REQUEST_TOKEN: Token = Token(1);

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

lazy_static! {
    /// HTTP_ROUTES contain all the nydusd HTTP routes.
    pub static ref HTTP_ROUTES: HttpRoutes = {
        let mut r = HttpRoutes {
            routes: HashMap::new(),
        };

        // Nydus API, v1
        r.routes.insert(endpoint_v1!("/daemon"), Box::new(InfoHandler{}));
        r.routes.insert(endpoint_v1!("/daemon/events"), Box::new(EventsHandler{}));
        r.routes.insert(endpoint_v1!("/daemon/backend"), Box::new(FsBackendInfo{}));
        r.routes.insert(endpoint_v1!("/daemon/exit"), Box::new(ExitHandler{}));
        r.routes.insert(endpoint_v1!("/daemon/fuse/sendfd"), Box::new(SendFuseFdHandler{}));
        r.routes.insert(endpoint_v1!("/daemon/fuse/takeover"), Box::new(TakeoverHandler{}));
        r.routes.insert(endpoint_v1!("/mount"), Box::new(MountHandler{}));
        r.routes.insert(endpoint_v1!("/metrics"), Box::new(MetricsHandler{}));
        r.routes.insert(endpoint_v1!("/metrics/files"), Box::new(MetricsFilesHandler{}));
        r.routes.insert(endpoint_v1!("/metrics/pattern"), Box::new(MetricsPatternHandler{}));
        r.routes.insert(endpoint_v1!("/metrics/backend"), Box::new(MetricsBackendHandler{}));
        r.routes.insert(endpoint_v1!("/metrics/blobcache"), Box::new(MetricsBlobcacheHandler{}));
        r.routes.insert(endpoint_v1!("/metrics/inflight"), Box::new(MetricsInflightHandler{}));

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
        waker.wake().map_err(ApiError::EventFdWrite)?;
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
/// The HTTP server sends request by `to_api` channel and wait for response from `from_api` channel
/// `api_notifier` is used to notify an execution context to fetch above request and handle it.
/// We can't forward signal to native rust thread, so we rely on `exit_evtfd` to notify
/// the server to exit. Therefore, it adds the unix domain socket fd receiving http request
/// to a global epoll_fd associated with a event_fd which will be used later to notify
/// the server thread to exit.
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
                    Err(e) => return Err(e),
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
