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

use crate::http_endpoint::{
    error_response, ApiError, ApiRequest, ApiResponse, EventsHandler, ExitHandler, FsBackendInfo,
    HttpError, HttpResult, InfoHandler, MetricsBackendHandler, MetricsBlobcacheHandler,
    MetricsFilesHandler, MetricsHandler, MetricsInflightHandler, MetricsPatternHandler,
    MountHandler, SendFuseFdHandler, TakeoverHandler,
};

const HTTP_ROOT: &str = "/api/v1";
const EXIT_TOKEN: Token = Token(usize::MAX);
const REQUEST_TOKEN: Token = Token(1);

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
    /// HTTP_ROUTES contain all the nydusd HTTP routes.
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
        r.routes.insert(endpoint!("/metrics/backend"), Box::new(MetricsBackendHandler{}));
        r.routes.insert(endpoint!("/metrics/blobcache"), Box::new(MetricsBlobcacheHandler{}));
        r.routes.insert(endpoint!("/metrics/inflight"), Box::new(MetricsInflightHandler{}));
        r
    };
}

fn kick_api_server(
    api_evt: Arc<Waker>,
    to_api: Sender<Option<ApiRequest>>,
    from_api: &Receiver<ApiResponse>,
    request: ApiRequest,
) -> ApiResponse {
    to_api.send(Some(request)).map_err(ApiError::RequestSend)?;
    api_evt.wake().map_err(ApiError::EventFdWrite)?;
    from_api.recv().map_err(ApiError::ResponseRecv)?
}

// Example:
// <-- GET /
// --> GET / 200 835ms 746b
//

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

fn exit_api_server(
    api_notifier: Arc<Waker>,
    to_api: &Sender<Option<ApiRequest>>,
) -> std::result::Result<(), ApiError> {
    to_api.send(None).map_err(ApiError::RequestSend)?;
    api_notifier.wake().map_err(ApiError::EventFdWrite)?;
    Ok(())
}

fn handle_http_request(
    request: &Request,
    api_notifier: Arc<Waker>,
    to_api: &Sender<Option<ApiRequest>>,
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
                    kick_api_server(api_notifier.clone(), to_api.clone(), from_api, r)
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
    api_notifier: Arc<Waker>,
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
            let api_notifier = api_notifier.clone();

            // Must start the server successfully or just die by panic
            server.start_server().unwrap();
            let mut events = Events::with_capacity(100);

            info!("http server started");

            'wait: loop {
                pool.poll(&mut events, None)?;
                for event in &events {
                    match event.token() {
                        EXIT_TOKEN => {
                            exit_api_server(api_notifier, &to_api).unwrap_or_else(|e| {
                                error!("exit api server failed: {:?}", e);
                            });
                            info!("http-server thread exits");
                            break 'wait Ok(());
                        }
                        REQUEST_TOKEN => match server.requests() {
                            Ok(request_vec) => {
                                for server_request in request_vec {
                                    // Ignore error when sending response
                                    server
                                        .respond(server_request.process(|request| {
                                            handle_http_request(
                                                request,
                                                api_notifier.clone(),
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
                        _ => {
                            unreachable!("unknown token.");
                        }
                    }
                }
            }
        })?;

    Ok((thread, waker))
}
