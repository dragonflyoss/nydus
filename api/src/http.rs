// Copyright 2020 Ant Group. All rights reserved.
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::Result;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::SystemTime;

use std::os::unix::io::AsRawFd;

use http::uri::Uri;
use url::Url;

use micro_http::{HttpServer, MediaType, Request, Response, StatusCode};
use vmm_sys_util::eventfd::EventFd;

use crate::http_endpoint::{
    error_response, ApiError, ApiRequest, ApiResponse, EventsHandler, ExitHandler, FsBackendInfo,
    HttpError, HttpResult, InfoHandler, MetricsBackendHandler, MetricsBlobcacheHandler,
    MetricsFilesHandler, MetricsHandler, MetricsInflightHandler, MetricsLatestReadFilesHandler,
    MetricsPatternHandler, MountHandler, SendFuseFdHandler, TakeoverHandler,
};

const HTTP_ROOT: &str = "/api/v1";

/// An HTTP endpoint handler interface
pub trait EndpointHandler: Sync + Send {
    /// Handles an HTTP request.
    /// After parsing the request, the handler could decide to send an
    /// associated API request down to the Nydusd API server to e.g. get current working status.
    /// The request will block waiting for an answer from the
    /// API server and translate that into an HTTP response.
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult;
}

/// An HTTP routes structure.
pub struct HttpRoutes {
    /// routes is a hash table mapping endpoint URIs to their endpoint handlers.
    pub routes: HashMap<String, Box<dyn EndpointHandler + Sync + Send>>,
}

macro_rules! endpoint {
    ($path:expr) => {
        format!("{}{}", HTTP_ROOT, $path)
    };
}

lazy_static! {
    /// HTTP_ROUTES contain all the cloud-hypervisor HTTP routes.
    pub static ref HTTP_ROUTES: HttpRoutes = {
        let mut r = HttpRoutes {
            routes: HashMap::new(),
        };

        r.routes.insert(endpoint!("/daemon"), Box::new(InfoHandler{}));
        r.routes.insert(endpoint!("/daemon/events"), Box::new(EventsHandler{}));
        r.routes.insert(endpoint!("/daemon/backend"), Box::new(FsBackendInfo{}));
        r.routes.insert(endpoint!("/daemon/exit"), Box::new(ExitHandler{}));
        r.routes.insert(endpoint!("/daemon/fuse/sendfd"), Box::new(SendFuseFdHandler{}));
        r.routes.insert(endpoint!("/daemon/fuse/takeover"), Box::new(TakeoverHandler{}));
        r.routes.insert(endpoint!("/mount"), Box::new(MountHandler{}));
        r.routes.insert(endpoint!("/metrics"), Box::new(MetricsHandler{}));
        r.routes.insert(endpoint!("/metrics/files"), Box::new(MetricsFilesHandler{}));
        r.routes.insert(endpoint!("/metrics/pattern"), Box::new(MetricsPatternHandler{}));
        r.routes.insert(endpoint!("/metrics/latest_read_files"), Box::new(MetricsLatestReadFilesHandler{}));
        r.routes.insert(endpoint!("/metrics/backend"), Box::new(MetricsBackendHandler{}));
        r.routes.insert(endpoint!("/metrics/blobcache"), Box::new(MetricsBlobcacheHandler{}));
        r.routes.insert(endpoint!("/metrics/inflight"), Box::new(MetricsInflightHandler{}));
        r
    };
}

fn kick_api_server(
    api_evt: &EventFd,
    to_api: &Sender<ApiRequest>,
    from_api: &Receiver<ApiResponse>,
    request: ApiRequest,
) -> ApiResponse {
    to_api.send(request).map_err(ApiError::RequestSend)?;
    api_evt.write(1).map_err(ApiError::EventFdWrite)?;
    from_api.recv().map_err(ApiError::ResponseRecv)?
}

// Example:
// <-- GET /
// --> GET / 200 835ms 746b
//

fn trace_api_begin(request: &micro_http::Request) {
    info!("<--- {:?} {:?}", request.method(), request.uri());
}
fn trace_api_end(
    response: &micro_http::Response,
    method: micro_http::Method,
    recv_time: SystemTime,
) {
    let elapse = SystemTime::now().duration_since(recv_time);
    info!(
        "---> {:?} Status Code: {:?}, Elapse: {:?}, Body Size: {:?}",
        method,
        response.status(),
        elapse,
        response.content_length()
    );
}

fn handle_http_request(
    request: &Request,
    api_notifier: &EventFd,
    to_api: &Sender<ApiRequest>,
    from_api: &Receiver<ApiResponse>,
) -> Response {
    trace_api_begin(request);
    let begin_time = SystemTime::now();

    // Micro http should ensure that req path is legal.
    let uri_parsed = request.uri().get_abs_path().parse::<Uri>();

    let mut response = match uri_parsed {
        Ok(uri) => match HTTP_ROUTES.routes.get(uri.path()) {
            Some(route) => route
                .handle_request(&request, &|r| {
                    kick_api_server(api_notifier, to_api, from_api, r)
                })
                .unwrap_or_else(|err| error_response(err, StatusCode::BadRequest)),
            None => error_response(HttpError::NoRoute, StatusCode::NotFound),
        },
        Err(e) => {
            error!("URI can't be parsed, {}", e);
            error_response(HttpError::BadRequest, StatusCode::BadRequest)
        }
    };

    response.set_server("Nydus API");
    response.set_content_type(MediaType::ApplicationJson);

    trace_api_end(&response, request.method(), begin_time);

    response
}

pub fn extract_query_part(req: &Request, key: &str) -> Option<String> {
    // Splicing req.uri with "http:" prefix might look weird, but since it depends on
    // crate `Url` to generate query_pairs HashMap, which is working on top of Url not Uri.
    // Better that we can add query part support to Micro-http in the future. But
    // right now, below way makes it easy to obtain query parts from uri.
    let http_prefix: String = String::from("http:");
    let url = Url::parse(&(http_prefix + req.uri().get_abs_path()))
        .map_err(|e| {
            error!("Can't parse request {:?}", e);
            e
        })
        .ok()?;
    let v: Option<String> = None;
    for (k, v) in url.query_pairs() {
        if k != key {
            continue;
        } else {
            trace!("Got query part {:?}", (k, &v));
            return Some(v.into_owned());
        }
    }
    v
}

const EVENT_UNIX_SOCKET: u64 = 1;
const EVENT_HTTP_DIE: u64 = 2;

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
    api_notifier: EventFd,
    to_api: Sender<ApiRequest>,
    from_api: Receiver<ApiResponse>,
    exit_evtfd: EventFd,
) -> Result<thread::JoinHandle<Result<()>>> {
    // Try to remove existed unix domain socket
    std::fs::remove_file(path).unwrap_or_default();
    let socket_path = PathBuf::from(path);

    let thread = thread::Builder::new()
        .name("http-server".to_string())
        .spawn(move || {
            let epoll_fd = epoll::create(true).unwrap();

            let mut server = HttpServer::new(socket_path).unwrap();
            // Must start the server successfully or just die by panic
            server.start_server().unwrap();
            epoll::ctl(
                epoll_fd,
                epoll::ControlOptions::EPOLL_CTL_ADD,
                server.epoll_fd(),
                epoll::Event::new(epoll::Events::EPOLLIN, EVENT_UNIX_SOCKET),
            )?;

            epoll::ctl(
                epoll_fd,
                epoll::ControlOptions::EPOLL_CTL_ADD,
                exit_evtfd.as_raw_fd(),
                epoll::Event::new(epoll::Events::EPOLLIN, EVENT_HTTP_DIE),
            )?;

            let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); 100];

            info!("http server started");

            'wait: loop {
                let num = epoll::wait(epoll_fd, -1, events.as_mut_slice()).map_err(|e| {
                    error!("Wait event error. {:?}", e);
                    e
                })?;

                for event in &events[..num] {
                    match event.data {
                        EVENT_UNIX_SOCKET => match server.requests() {
                            Ok(request_vec) => {
                                for server_request in request_vec {
                                    // Ignore error when sending response
                                    server
                                        .respond(server_request.process(|request| {
                                            handle_http_request(
                                                request,
                                                &api_notifier,
                                                &to_api,
                                                &from_api,
                                            )
                                        }))
                                        .unwrap_or_else(|e| {
                                            error!("HTTP server error on response: {}", e)
                                        });
                                }
                            }
                            Err(e) => {
                                error!(
                                    "HTTP server error on retrieving incoming request. Error: {}",
                                    e
                                );
                            }
                        },
                        EVENT_HTTP_DIE => break 'wait Ok(()),
                        _ => error!("Invalid event"),
                    }
                }
            }
        })?;

    Ok(thread)
}
