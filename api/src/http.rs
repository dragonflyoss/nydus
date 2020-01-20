// Copyright 2020 Ant Financial. All rights reserved.
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::Result;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use http::uri::Uri;
use url::Url;

use micro_http::{Body, HttpServer, MediaType, Request, Response, StatusCode, Version};
use vmm_sys_util::eventfd::EventFd;

use crate::http_endpoint::{
    ApiRequest, ApiResponse, InfoHandler, MetricsFilesHandler, MetricsHandler,
    MetricsPatternHandler, MountHandler,
};

const HTTP_ROOT: &str = "/api/v1";

/// An HTTP endpoint handler interface
pub trait EndpointHandler: Sync + Send {
    /// Handles an HTTP request.
    /// After parsing the request, the handler could decide to send an
    /// associated API request down to the VMM API server to e.g. create
    /// or start a VM. The request will block waiting for an answer from the
    /// API server and translate that into an HTTP response.
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        to_api: Sender<ApiRequest>,
        from_api: &Receiver<ApiResponse>,
    ) -> Response;
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
        r.routes.insert(endpoint!("/mount"), Box::new(MountHandler{}));
        r.routes.insert(endpoint!("/metrics"), Box::new(MetricsHandler{}));
        r.routes.insert(endpoint!("/metrics/files"), Box::new(MetricsFilesHandler{}));
        r.routes.insert(endpoint!("/metrics/pattern"), Box::new(MetricsPatternHandler{}));
        r
    };
}

fn handle_http_request(
    request: &Request,
    api_notifier: &EventFd,
    to_api: &Sender<ApiRequest>,
    from_api: &Receiver<ApiResponse>,
) -> Response {
    // Micro http should ensure that req path is legal.
    let uri = request.uri().get_abs_path().parse::<Uri>().unwrap();
    let mut response = match HTTP_ROUTES.routes.get(&uri.path().to_string()) {
        Some(route) => match api_notifier.try_clone() {
            Ok(notifier) => route.handle_request(&request, notifier, to_api.clone(), from_api),
            Err(_) => {
                let mut r = Response::new(Version::Http11, StatusCode::InternalServerError);
                r.set_body(Body::new("Internal error!"));
                r
            }
        },
        None => {
            let mut r = Response::new(Version::Http11, StatusCode::NotFound);
            r.set_body(Body::new(format!(
                "No route to {}",
                request.uri().get_abs_path().to_string()
            )));
            r
        }
    };

    response.set_server("Nydus API");
    response.set_content_type(MediaType::ApplicationJson);
    response
}

pub fn extract_query_part(req: &Request, key: &str) -> Option<String> {
    // Splicing req.uri with "http:" prefix might look weird, but since it depends on
    // crate `Url` to generate query_pairs HashMap, which is working on top of Url not Uri.
    // Better that we can add query part support to Micro-http in the future. But
    // right now, below way makes it easy to obtain query parts from uri.
    let http_prefix: String = String::from("http:");
    let url = Url::parse((http_prefix + &req.uri().get_abs_path().to_string()).as_str()).unwrap();
    let v: Option<String> = None;
    for (k, v) in url.query_pairs().into_owned() {
        if k.as_str() != key.chars().as_str() {
            continue;
        } else {
            trace!("Got query part {:?}", (k, &v));
            return Some(v);
        }
    }
    v
}

pub fn start_http_thread(
    path: &str,
    evt_fd: EventFd,
    to_api: Sender<ApiRequest>,
    from_api: Receiver<ApiResponse>,
) -> Result<thread::JoinHandle<Result<()>>> {
    std::fs::remove_file(path).unwrap_or_default();
    let socket_path = PathBuf::from(path);

    thread::Builder::new()
        .name("http-server".to_string())
        .spawn(move || {
            let mut server = HttpServer::new(socket_path).unwrap();
            server.start_server().unwrap();
            info!("http server started");
            loop {
                match server.requests() {
                    Ok(request_vec) => {
                        for server_request in request_vec {
                            server
                                .respond(server_request.process(|request| {
                                    handle_http_request(request, &evt_fd, &to_api, &from_api)
                                }))
                                .or_else(|e| -> Result<()> {
                                    error!("HTTP server error on response: {}", e);
                                    Ok(())
                                })?;
                        }
                    }
                    Err(e) => {
                        error!(
                            "HTTP server error on retrieving incoming request. Error: {}",
                            e
                        );
                    }
                }
            }
        })
}
