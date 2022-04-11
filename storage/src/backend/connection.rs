// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Help library to manage network connections.
use std::collections::HashMap;
use std::io::Read;
use std::io::Result;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use reqwest::header::HeaderMap;
use reqwest::{
    self,
    blocking::{Body, Client, Response},
    redirect::Policy,
    Method, StatusCode, Url,
};

use crate::backend::CommonConfig;

const HEADER_AUTHORIZATION: &str = "Authorization";

/// Error codes related to network communication.
#[derive(Debug)]
pub enum ConnectionError {
    Disconnected,
    ErrorWithMsg(String),
    Common(reqwest::Error),
    Format(reqwest::Error),
}

/// Specialized `Result` for network communication.
type ConnectionResult<T> = std::result::Result<T, ConnectionError>;

/// HTTP request data with progress callback.
#[derive(Clone)]
pub struct Progress<R> {
    inner: R,
    current: usize,
    total: usize,
    callback: fn((usize, usize)),
}

impl<R> Progress<R> {
    /// Create a new `Progress` object.
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

/// HTTP request data to send to server.
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

/// Check whether the HTTP status code is a success result.
pub(crate) fn is_success_status(status: StatusCode) -> bool {
    status >= StatusCode::OK && status < StatusCode::BAD_REQUEST
}

/// Convert a HTTP `Response` into an `Result<Response>`.
pub(crate) fn respond(resp: Response, catch_status: bool) -> ConnectionResult<Response> {
    if !catch_status || is_success_status(resp.status()) {
        Ok(resp)
    } else {
        let msg = resp.text().map_err(ConnectionError::Format)?;
        Err(ConnectionError::ErrorWithMsg(msg))
    }
}

/// A network connection to communicate with remote server.
#[derive(Debug)]
pub(crate) struct Connection {
    client: Client,
    proxy: Option<Proxy>,
    shutdown: AtomicBool,
}

impl Connection {
    /// Create a new connection according to the configuration.
    pub fn new(config: &CommonConfig) -> Result<Arc<Connection>> {
        info!("backend config: {:?}", config);
        let client = Self::build_connection("", config)?;
        let proxy = if !config.proxy.url.is_empty() {
            let ping_url = if !config.proxy.ping_url.is_empty() {
                Some(Url::from_str(&config.proxy.ping_url).map_err(|e| einval!(e))?)
            } else {
                None
            };
            Some(Proxy {
                client: Self::build_connection(&config.proxy.url, config)?,
                health: ProxyHealth::new(config.proxy.check_interval, ping_url),
                fallback: config.proxy.fallback,
            })
        } else {
            None
        };
        let connection = Arc::new(Connection {
            client,
            proxy,
            shutdown: AtomicBool::new(false),
        });

        if let Some(proxy) = &connection.proxy {
            if proxy.health.ping_url.is_some() {
                let conn = connection.clone();
                let connect_timeout = config.connect_timeout;

                // Spawn thread to update the health status of proxy server
                thread::spawn(move || {
                    let proxy = conn.proxy.as_ref().unwrap();
                    let ping_url = proxy.health.ping_url.as_ref().unwrap();

                    loop {
                        let client = Client::new();
                        let _ = client
                            .get(ping_url.clone())
                            .timeout(Duration::from_secs(connect_timeout))
                            .send()
                            .map(|resp| {
                                proxy.health.set(is_success_status(resp.status()));
                            })
                            .map_err(|_e| proxy.health.set(false));

                        if conn.shutdown.load(Ordering::Acquire) {
                            break;
                        }
                        thread::sleep(proxy.health.check_interval);
                        if conn.shutdown.load(Ordering::Acquire) {
                            break;
                        }
                    }
                });
            }
        }

        Ok(connection)
    }

    /// Shutdown the connection.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    /// Send a request to server and wait for response.
    pub fn call<R: Read + Send + 'static>(
        &self,
        method: Method,
        url: &str,
        query: Option<Vec<(&str, &str)>>,
        data: Option<ReqBody<R>>,
        headers: HeaderMap,
        catch_status: bool,
    ) -> ConnectionResult<Response> {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(ConnectionError::Disconnected);
        }

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
                    &query,
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
            &query,
            data,
            headers,
            catch_status,
            false,
        )
    }

    fn build_connection(proxy: &str, config: &CommonConfig) -> Result<Client> {
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

        if config.skip_verify {
            cb = cb.danger_accept_invalid_certs(true);
        }

        if !proxy.is_empty() {
            cb = cb.proxy(reqwest::Proxy::all(proxy).map_err(|e| einval!(e))?)
        }

        cb.build().map_err(|e| einval!(e))
    }

    #[allow(clippy::too_many_arguments)]
    fn call_inner<R: Read + Send + 'static>(
        &self,
        client: &Client,
        method: Method,
        url: &str,
        query: &Option<Vec<(&str, &str)>>,
        data: Option<ReqBody<R>>,
        headers: HeaderMap,
        catch_status: bool,
        proxy: bool,
    ) -> ConnectionResult<Response> {
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

        let mut rb = client.request(method, url).headers(headers);
        if let Some(q) = query.as_ref() {
            rb = rb.query(q);
        }

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
            Err(err) => Err(ConnectionError::Common(err)),
            Ok(resp) => respond(resp, catch_status),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_progress() {
        let buf = vec![0x1u8, 2, 3, 4, 5];
        let mut progress = Progress::new(Cursor::new(buf), 5, |(curr, total)| {
            assert!(curr == 2 || curr == 4);
            assert_eq!(total, 5);
        });

        let mut buf1 = [0x0u8; 2];
        assert_eq!(progress.read(&mut buf1).unwrap(), 2);
        assert_eq!(buf1[0], 1);
        assert_eq!(buf1[1], 2);

        assert_eq!(progress.read(&mut buf1).unwrap(), 2);
        assert_eq!(buf1[0], 3);
        assert_eq!(buf1[1], 4);
    }

    #[test]
    fn test_proxy_health() {
        let checker = ProxyHealth::new(5, None);

        assert!(checker.ok());
        assert!(checker.ok());
        checker.set(false);
        assert!(!checker.ok());
        assert!(!checker.ok());
        checker.set(true);
        assert!(checker.ok());
        assert!(checker.ok());
    }

    #[test]
    fn test_is_success_status() {
        assert_eq!(is_success_status(StatusCode::CONTINUE), false);
        assert_eq!(is_success_status(StatusCode::OK), true);
        assert_eq!(is_success_status(StatusCode::PERMANENT_REDIRECT), true);
        assert_eq!(is_success_status(StatusCode::BAD_REQUEST), false);
    }
}
