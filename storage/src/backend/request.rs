// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::Read;
use std::io::Result;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use reqwest::{
    self,
    blocking::{Body, Client, Response},
    redirect::Policy,
    Method, StatusCode, Url,
};

use crate::backend::CommonConfig;

pub use reqwest::header::HeaderMap;

const HEADER_AUTHORIZATION: &str = "Authorization";

#[derive(Debug)]
pub enum RequestError {
    ErrorWithMsg(String),
    Common(reqwest::Error),
    Format(reqwest::Error),
}

pub type RequestResult<T> = std::result::Result<T, RequestError>;

#[derive(Clone)]
pub struct Progress<R> {
    inner: R,
    current: usize,
    total: usize,
    callback: fn((usize, usize)),
}

impl<R> Progress<R> {
    pub fn new(r: R, total: usize, callback: fn((usize, usize))) -> Progress<R> {
        Progress {
            inner: r,
            current: 0,
            total,
            callback,
        }
    }
}

impl<R: Read + Send + 'static> Read for Progress<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.inner.read(buf).map(|count| {
            self.current += count as usize;
            (self.callback)((self.current, self.total));
            count
        })
    }
}

#[derive(Clone)]
pub enum ReqBody<R> {
    Read(Progress<R>, usize),
    Buf(Vec<u8>),
    Form(HashMap<String, String>),
}

#[derive(Debug)]
struct ProxyHealth {
    status: AtomicBool,
    ping_url: Option<Url>,
    check_interval: Duration,
}

impl ProxyHealth {
    fn new(check_interval: u64, ping_url: Option<Url>) -> Self {
        ProxyHealth {
            status: AtomicBool::from(true),
            ping_url,
            check_interval: Duration::from_secs(check_interval),
        }
    }
    fn ok(&self) -> bool {
        self.status.load(Ordering::Relaxed)
    }
    fn set(&self, health: bool) {
        self.status.store(health, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct Proxy {
    client: Client,
    health: ProxyHealth,
    fallback: bool,
}

#[derive(Debug)]
pub struct Request {
    client: Client,
    proxy: Option<Proxy>,
}

pub fn is_success_status(status: StatusCode) -> bool {
    status >= StatusCode::OK && status < StatusCode::BAD_REQUEST
}

pub fn respond(resp: Response) -> RequestResult<Response> {
    if is_success_status(resp.status()) {
        return Ok(resp);
    }
    let msg = resp.text().map_err(RequestError::Format)?;
    Err(RequestError::ErrorWithMsg(msg))
}

impl Request {
    fn build_client(proxy: &str, config: &CommonConfig) -> Result<Client> {
        let connect_timeout = if config.connect_timeout != 0 {
            Some(Duration::from_secs(config.connect_timeout))
        } else {
            None
        };
        let timeout = if config.timeout != 0 {
            Some(Duration::from_secs(config.timeout))
        } else {
            None
        };

        let mut cb = Client::builder()
            .timeout(timeout)
            .connect_timeout(connect_timeout)
            .redirect(Policy::none());

        if !proxy.is_empty() {
            cb = cb.proxy(reqwest::Proxy::all(proxy).map_err(|e| einval!(e))?)
        }

        cb.build().map_err(|e| einval!(e))
    }

    pub fn new(config: CommonConfig) -> Result<Arc<Request>> {
        info!("backend config: {:?}", config);
        let client = Self::build_client("", &config)?;
        let proxy = if !config.proxy.url.is_empty() {
            let ping_url = if !config.proxy.ping_url.is_empty() {
                Some(Url::from_str(&config.proxy.ping_url).map_err(|e| einval!(e))?)
            } else {
                None
            };
            Some(Proxy {
                client: Self::build_client(&config.proxy.url, &config)?,
                health: ProxyHealth::new(config.proxy.check_interval, ping_url),
                fallback: config.proxy.fallback,
            })
        } else {
            None
        };

        let request = Arc::new(Request { client, proxy });

        if let Some(proxy) = &request.proxy {
            let request = request.clone();
            if proxy.health.ping_url.is_some() {
                // Spawn thread to update the health status of proxy server
                thread::spawn(move || loop {
                    let proxy = request.proxy.as_ref().unwrap();
                    let ping_url = proxy.health.ping_url.as_ref().unwrap();
                    let client = Client::new();
                    let resp = client
                        .get(ping_url.clone())
                        .timeout(Duration::from_secs(config.connect_timeout))
                        .send();
                    match resp {
                        Ok(resp) => {
                            proxy.health.set(is_success_status(resp.status()));
                        }
                        Err(_err) => {
                            proxy.health.set(false);
                        }
                    }
                    thread::sleep(proxy.health.check_interval);
                });
            }
        }

        Ok(request)
    }

    #[allow(clippy::too_many_arguments)]
    fn call_inner<R: Read + Send + 'static>(
        &self,
        client: &Client,
        method: Method,
        url: &str,
        data: Option<ReqBody<R>>,
        headers: HeaderMap,
        catch_status: bool,
        proxy: bool,
    ) -> RequestResult<Response> {
        debug!(
            "Request: {} {} headers: {:?}, proxy: {}, data: {}",
            method,
            url,
            {
                let mut display_headers = headers.clone();
                display_headers.remove(HEADER_AUTHORIZATION);
                display_headers
            },
            proxy,
            data.is_some(),
        );

        let rb = client.request(method, url).headers(headers);

        let ret;
        if let Some(data) = data {
            match data {
                ReqBody::Read(body, total) => {
                    let body = Body::sized(body, total as u64);
                    ret = rb.body(body).send();
                }
                ReqBody::Buf(buf) => {
                    ret = rb.body(buf).send();
                }
                ReqBody::Form(form) => {
                    ret = rb.form(&form).send();
                }
            }
        } else {
            ret = rb.body("").send();
        }

        match ret {
            Ok(resp) => {
                if !catch_status {
                    return Ok(resp);
                }
                respond(resp)
            }
            Err(err) => Err(RequestError::Common(err)),
        }
    }

    pub fn call<R: Read + Send + 'static>(
        &self,
        method: Method,
        url: &str,
        data: Option<ReqBody<R>>,
        headers: HeaderMap,
        catch_status: bool,
    ) -> RequestResult<Response> {
        if let Some(proxy) = &self.proxy {
            if proxy.health.ok() {
                let data_cloned: Option<ReqBody<R>> = match data.as_ref() {
                    Some(ReqBody::Form(form)) => Some(ReqBody::Form(form.clone())),
                    Some(ReqBody::Buf(buf)) => Some(ReqBody::Buf(buf.clone())),
                    _ => None,
                };
                let result = self.call_inner(
                    &proxy.client,
                    method.clone(),
                    url,
                    data_cloned,
                    headers.clone(),
                    catch_status,
                    true,
                );
                match result {
                    Ok(resp) => {
                        if !proxy.fallback || resp.status() < StatusCode::INTERNAL_SERVER_ERROR {
                            return Ok(resp);
                        }
                    }
                    Err(err) => {
                        if !proxy.fallback {
                            return Err(err);
                        }
                    }
                }
                // If proxy server respond invalid status code or http connection failed, we need to
                // fallback to origin server, the policy only applicable to non-upload operation
                warn!("Request proxy server failed, fallback to origin server");
            } else {
                warn!("Proxy server not health, fallback to origin server");
            }
        }
        self.call_inner(
            &self.client,
            method,
            url,
            data,
            headers,
            catch_status,
            false,
        )
    }
}
