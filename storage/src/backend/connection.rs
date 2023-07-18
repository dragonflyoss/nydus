// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Help library to manage network connections.
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{Read, Result};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicI16, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{fmt, thread};

use log::{max_level, Level};

use reqwest::header::{HeaderName, HeaderValue};
use reqwest::{
    self,
    blocking::{Body, Client, Response},
    header::HeaderMap,
    redirect::Policy,
    Method, StatusCode, Url,
};

use nydus_api::{HttpProxyConfig, MirrorConfig, OssConfig, ProxyConfig, RegistryConfig, S3Config};
use url::ParseError;

const HEADER_AUTHORIZATION: &str = "Authorization";

const RATE_LIMITED_LOG_TIME: u8 = 2;

thread_local! {
    pub static LAST_FALLBACK_AT: RefCell<SystemTime> = RefCell::new(UNIX_EPOCH);
}

/// Error codes related to network communication.
#[derive(Debug)]
pub enum ConnectionError {
    Disconnected,
    ErrorWithMsg(String),
    Common(reqwest::Error),
    Format(reqwest::Error),
    Url(String, ParseError),
    Scheme(String),
    MirrorHost,
    MirrorPort,
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionError::Disconnected => write!(f, "network connection disconnected"),
            ConnectionError::ErrorWithMsg(s) => write!(f, "network error, {}", s),
            ConnectionError::Common(e) => write!(f, "network error, {}", e),
            ConnectionError::Format(e) => write!(f, "{}", e),
            ConnectionError::Url(s, e) => write!(f, "failed to parse URL {}, {}", s, e),
            ConnectionError::Scheme(s) => write!(f, "invalid scheme {}", s),
            ConnectionError::MirrorHost => write!(f, "invalid mirror host"),
            ConnectionError::MirrorPort => write!(f, "invalid mirror port"),
        }
    }
}

/// Specialized `Result` for network communication.
type ConnectionResult<T> = std::result::Result<T, ConnectionError>;

/// Generic configuration for storage backends.
#[derive(Debug, Clone)]
pub(crate) struct ConnectionConfig {
    pub proxy: ProxyConfig,
    pub mirrors: Vec<MirrorConfig>,
    pub skip_verify: bool,
    pub timeout: u32,
    pub connect_timeout: u32,
    pub retry_limit: u8,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            proxy: ProxyConfig::default(),
            mirrors: Vec::<MirrorConfig>::new(),
            skip_verify: false,
            timeout: 5,
            connect_timeout: 5,
            retry_limit: 0,
        }
    }
}

impl From<OssConfig> for ConnectionConfig {
    fn from(c: OssConfig) -> ConnectionConfig {
        ConnectionConfig {
            proxy: c.proxy,
            mirrors: c.mirrors,
            skip_verify: c.skip_verify,
            timeout: c.timeout,
            connect_timeout: c.connect_timeout,
            retry_limit: c.retry_limit,
        }
    }
}

impl From<S3Config> for ConnectionConfig {
    fn from(c: S3Config) -> ConnectionConfig {
        ConnectionConfig {
            proxy: c.proxy,
            mirrors: c.mirrors,
            skip_verify: c.skip_verify,
            timeout: c.timeout,
            connect_timeout: c.connect_timeout,
            retry_limit: c.retry_limit,
        }
    }
}

impl From<RegistryConfig> for ConnectionConfig {
    fn from(c: RegistryConfig) -> ConnectionConfig {
        ConnectionConfig {
            proxy: c.proxy,
            mirrors: c.mirrors,
            skip_verify: c.skip_verify,
            timeout: c.timeout,
            connect_timeout: c.connect_timeout,
            retry_limit: c.retry_limit,
        }
    }
}

impl From<HttpProxyConfig> for ConnectionConfig {
    fn from(c: HttpProxyConfig) -> ConnectionConfig {
        ConnectionConfig {
            proxy: c.proxy,
            mirrors: c.mirrors,
            skip_verify: c.skip_verify,
            timeout: c.timeout,
            connect_timeout: c.connect_timeout,
            retry_limit: c.retry_limit,
        }
    }
}

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
pub enum ReqBody<R: Clone> {
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

const SCHEME_REVERSION_CACHE_UNSET: i16 = 0;
const SCHEME_REVERSION_CACHE_REPLACE: i16 = 1;
const SCHEME_REVERSION_CACHE_RETAIN: i16 = 2;

#[derive(Debug)]
struct Proxy {
    client: Client,
    health: ProxyHealth,
    fallback: bool,
    use_http: bool,
    // Cache whether should try to replace scheme for proxy url.
    replace_scheme: AtomicI16,
}

impl Proxy {
    fn try_use_http(&self, url: &str) -> Option<String> {
        if self.replace_scheme.load(Ordering::Relaxed) == SCHEME_REVERSION_CACHE_REPLACE {
            Some(url.replacen("https", "http", 1))
        } else if self.replace_scheme.load(Ordering::Relaxed) == SCHEME_REVERSION_CACHE_UNSET {
            if url.starts_with("https:") {
                self.replace_scheme
                    .store(SCHEME_REVERSION_CACHE_REPLACE, Ordering::Relaxed);
                info!("Will replace backend's URL's scheme with http");
                Some(url.replacen("https", "http", 1))
            } else if url.starts_with("http:") {
                self.replace_scheme
                    .store(SCHEME_REVERSION_CACHE_RETAIN, Ordering::Relaxed);
                None
            } else {
                warn!("Can't replace http scheme, url {}", url);
                None
            }
        } else {
            None
        }
    }
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
    proxy: Option<Arc<Proxy>>,
    pub mirrors: Vec<Arc<Mirror>>,
    pub shutdown: AtomicBool,
}

#[derive(Debug)]
pub(crate) struct Mirror {
    /// Information for mirror from configuration file.
    pub config: MirrorConfig,
    /// Mirror status, it will be set to false by atomic operation when mirror is not work.
    status: AtomicBool,
    /// Failed times requesting mirror, the status will be marked as false when failed_times = failure_limit.
    failed_times: AtomicU8,
    /// Failure count for which mirror is considered unavailable.
    failure_limit: u8,
}

impl Mirror {
    /// Convert original URL to mirror URL.
    fn mirror_url(&self, url: &str) -> ConnectionResult<Url> {
        let mirror_host = Url::parse(&self.config.host)
            .map_err(|e| ConnectionError::Url(self.config.host.clone(), e))?;
        let mut current_url =
            Url::parse(url).map_err(|e| ConnectionError::Url(url.to_string(), e))?;

        current_url
            .set_scheme(mirror_host.scheme())
            .map_err(|_| ConnectionError::Scheme(mirror_host.scheme().to_string()))?;
        current_url
            .set_host(mirror_host.host_str())
            .map_err(|_| ConnectionError::MirrorHost)?;
        current_url
            .set_port(mirror_host.port())
            .map_err(|_| ConnectionError::MirrorPort)?;
        Ok(current_url)
    }
}

impl Connection {
    /// Create a new connection according to the configuration.
    pub fn new(config: &ConnectionConfig) -> Result<Arc<Connection>> {
        info!("backend config: {:?}", config);
        let client = Self::build_connection("", config)?;

        let proxy = if !config.proxy.url.is_empty() {
            let ping_url = if !config.proxy.ping_url.is_empty() {
                Some(Url::from_str(&config.proxy.ping_url).map_err(|e| einval!(e))?)
            } else {
                None
            };
            Some(Arc::new(Proxy {
                client: Self::build_connection(&config.proxy.url, config)?,
                health: ProxyHealth::new(config.proxy.check_interval, ping_url),
                fallback: config.proxy.fallback,
                use_http: config.proxy.use_http,
                replace_scheme: AtomicI16::new(SCHEME_REVERSION_CACHE_UNSET),
            }))
        } else {
            None
        };

        let mut mirrors = Vec::new();
        for mirror_config in config.mirrors.iter() {
            if !mirror_config.host.is_empty() {
                mirrors.push(Arc::new(Mirror {
                    config: mirror_config.clone(),
                    status: AtomicBool::from(true),
                    failed_times: AtomicU8::from(0),
                    failure_limit: mirror_config.failure_limit,
                }));
            }
        }

        let connection = Arc::new(Connection {
            client,
            proxy,
            mirrors,
            shutdown: AtomicBool::new(false),
        });

        // Start  proxy's health checking thread.
        connection.start_proxy_health_thread(config.connect_timeout as u64);

        // Start mirrors' health checking thread.
        connection.start_mirrors_health_thread(config.timeout as u64);

        Ok(connection)
    }

    fn start_proxy_health_thread(&self, connect_timeout: u64) {
        if let Some(proxy) = self.proxy.as_ref() {
            if proxy.health.ping_url.is_some() {
                let proxy = proxy.clone();
                // Spawn thread to update the health status of proxy server
                thread::spawn(move || {
                    let ping_url = proxy.health.ping_url.as_ref().unwrap();
                    let mut last_success = true;

                    loop {
                        let client = Client::new();
                        let _ = client
                            .get(ping_url.clone())
                            .timeout(Duration::from_secs(connect_timeout as u64))
                            .send()
                            .map(|resp| {
                                let success = is_success_status(resp.status());
                                if last_success && !success {
                                    warn!(
                                        "Detected proxy unhealthy when pinging proxy, response status {}",
                                        resp.status()
                                    );
                                } else if !last_success && success {
                                    info!("Backend proxy recovered")
                                }
                                last_success = success;
                                proxy.health.set(success);
                            })
                            .map_err(|e| {
                                if last_success {
                                    warn!("Detected proxy unhealthy when ping proxy, {}", e);
                                }
                                last_success = false;
                                proxy.health.set(false)
                            });

                        thread::sleep(proxy.health.check_interval);
                    }
                });
            }
        }
    }

    fn start_mirrors_health_thread(&self, timeout: u64) {
        for mirror in self.mirrors.iter() {
            let mirror_cloned = mirror.clone();
            thread::spawn(move || {
                let mirror_health_url = if mirror_cloned.config.ping_url.is_empty() {
                    format!("{}/v2", mirror_cloned.config.host)
                } else {
                    mirror_cloned.config.ping_url.clone()
                };
                info!(
                    "[mirror] start health check, ping url: {}",
                    mirror_health_url
                );

                let client = Client::new();
                loop {
                    // Try to recover the mirror server when it is unavailable.
                    if !mirror_cloned.status.load(Ordering::Relaxed) {
                        info!(
                            "[mirror] server unhealthy, try to recover: {}",
                            mirror_cloned.config.host
                        );

                        let _ = client
                            .get(mirror_health_url.as_str())
                            .timeout(Duration::from_secs(timeout as u64))
                            .send()
                            .map(|resp| {
                                // If the response status is less than StatusCode::INTERNAL_SERVER_ERROR,
                                // the mirror server is recovered.
                                if resp.status() < StatusCode::INTERNAL_SERVER_ERROR {
                                    info!(
                                        "[mirror] server recovered: {}",
                                        mirror_cloned.config.host
                                    );
                                    mirror_cloned.failed_times.store(0, Ordering::Relaxed);
                                    mirror_cloned.status.store(true, Ordering::Relaxed);
                                }
                            })
                            .map_err(|e| {
                                warn!(
                                    "[mirror] failed to recover server: {}, {}",
                                    mirror_cloned.config.host, e
                                );
                            });
                    }

                    thread::sleep(Duration::from_secs(
                        mirror_cloned.config.health_check_interval,
                    ));
                }
            });
        }
    }

    /// Shutdown the connection.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn call<R: Read + Clone + Send + 'static>(
        &self,
        method: Method,
        url: &str,
        query: Option<&[(&str, &str)]>,
        data: Option<ReqBody<R>>,
        headers: &mut HeaderMap,
        catch_status: bool,
    ) -> ConnectionResult<Response> {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(ConnectionError::Disconnected);
        }

        if let Some(proxy) = &self.proxy {
            if proxy.health.ok() {
                let data_cloned = data.as_ref().cloned();

                let http_url: Option<String>;
                let mut replaced_url = url;

                if proxy.use_http {
                    http_url = proxy.try_use_http(url);
                    if let Some(ref r) = http_url {
                        replaced_url = r.as_str();
                    }
                }

                let result = self.call_inner(
                    &proxy.client,
                    method.clone(),
                    replaced_url,
                    &query,
                    data_cloned,
                    headers,
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
                // If proxy server responds invalid status code or http connection failed, we need to
                // fallback to origin server, the policy only applicable to non-upload operation
                warn!("Request proxy server failed, fallback to original server");
            } else {
                LAST_FALLBACK_AT.with(|f| {
                    let current = SystemTime::now();
                    if current.duration_since(*f.borrow()).unwrap().as_secs()
                        >= RATE_LIMITED_LOG_TIME as u64
                    {
                        warn!("Proxy server is not healthy, fallback to original server");
                        f.replace(current);
                    }
                })
            }
        }

        let mut mirror_enabled = false;
        if !self.mirrors.is_empty() {
            mirror_enabled = true;
            for mirror in self.mirrors.iter() {
                if mirror.status.load(Ordering::Relaxed) {
                    let data_cloned = data.as_ref().cloned();

                    for (key, value) in mirror.config.headers.iter() {
                        headers.insert(
                            HeaderName::from_str(key).unwrap(),
                            HeaderValue::from_str(value).unwrap(),
                        );
                    }

                    let current_url = mirror.mirror_url(url)?;
                    debug!("[mirror] replace to: {}", current_url);

                    let result = self.call_inner(
                        &self.client,
                        method.clone(),
                        current_url.as_str(),
                        &query,
                        data_cloned,
                        headers,
                        catch_status,
                        false,
                    );

                    match result {
                        Ok(resp) => {
                            // If the response status >= INTERNAL_SERVER_ERROR, move to the next mirror server.
                            if resp.status() < StatusCode::INTERNAL_SERVER_ERROR {
                                return Ok(resp);
                            }
                        }
                        Err(err) => {
                            warn!(
                                "[mirror] request failed, server: {:?}, {:?}",
                                mirror.config.host, err
                            );
                            mirror.failed_times.fetch_add(1, Ordering::Relaxed);

                            if mirror.failed_times.load(Ordering::Relaxed) >= mirror.failure_limit {
                                warn!(
                                    "[mirror] exceed failure limit {}, server disabled: {:?}",
                                    mirror.failure_limit, mirror
                                );
                                mirror.status.store(false, Ordering::Relaxed);
                            }
                        }
                    }
                }
                // Remove mirror-related headers to avoid sending them to the next mirror server and original registry.
                for (key, _) in mirror.config.headers.iter() {
                    headers.remove(HeaderName::from_str(key).unwrap());
                }
            }
        }

        if mirror_enabled {
            warn!("[mirror] request all servers failed, fallback to original server.");
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

    fn build_connection(proxy: &str, config: &ConnectionConfig) -> Result<Client> {
        let connect_timeout = if config.connect_timeout != 0 {
            Some(Duration::from_secs(config.connect_timeout as u64))
        } else {
            None
        };
        let timeout = if config.timeout != 0 {
            Some(Duration::from_secs(config.timeout as u64))
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
    fn call_inner<R: Read + Clone + Send + 'static>(
        &self,
        client: &Client,
        method: Method,
        url: &str,
        query: &Option<&[(&str, &str)]>,
        data: Option<ReqBody<R>>,
        headers: &HeaderMap,
        catch_status: bool,
        proxy: bool,
    ) -> ConnectionResult<Response> {
        // Only clone header when debugging to reduce potential overhead.
        let display_headers = if max_level() >= Level::Debug {
            let mut display_headers = headers.clone();
            display_headers.remove(HEADER_AUTHORIZATION);
            Some(display_headers)
        } else {
            None
        };
        let has_data = data.is_some();
        let start = Instant::now();

        let mut rb = client.request(method.clone(), url).headers(headers.clone());
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

        debug!(
            "{} Request: {} {} headers: {:?}, proxy: {}, data: {}, duration: {}ms",
            std::thread::current().name().unwrap_or_default(),
            method,
            url,
            display_headers,
            proxy,
            has_data,
            Instant::now().duration_since(start).as_millis(),
        );

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
        assert!(!is_success_status(StatusCode::CONTINUE));
        assert!(is_success_status(StatusCode::OK));
        assert!(is_success_status(StatusCode::PERMANENT_REDIRECT));
        assert!(!is_success_status(StatusCode::BAD_REQUEST));
    }

    #[test]
    fn test_connection_config_default() {
        let config = ConnectionConfig::default();

        assert_eq!(config.timeout, 5);
        assert_eq!(config.connect_timeout, 5);
        assert_eq!(config.retry_limit, 0);
        assert_eq!(config.proxy.check_interval, 5);
        assert!(config.proxy.fallback);
        assert_eq!(config.proxy.ping_url, "");
        assert_eq!(config.proxy.url, "");
        assert!(config.mirrors.is_empty());
    }
}
