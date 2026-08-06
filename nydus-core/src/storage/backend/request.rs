//! Unified request routing for HTTP-based backends.
//!
//! [`Request`] dispatches a logical HTTP call across one of three transports —
//! the direct origin, an HTTP forward proxy, or the Dragonfly SDK proxy — and
//! normalizes the outcome into a single [`Response`]. Proxy errors are surfaced
//! with enough structure for the retry policy to tell `403` / `429` apart from
//! transient network failures.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::header::HeaderMap;
use reqwest::{Client, Method, StatusCode};
use tracing::debug;

use super::http::{runtime, Connection};
use super::proxy::HttpProxy;
use super::{ReadContext, RequestSource};

#[cfg(feature = "backend-dragonfly-proxy")]
use super::dragonfly_sdk::{DragonflyError, DragonflyResponse, DragonflySdk};

/// Errors produced while issuing a request.
#[derive(Debug)]
pub(crate) enum RequestError {
    /// Transient network/transport failure (connection, timeout, ...).
    Network(io::Error),
    /// Proxy denied the request (`403`).
    #[cfg_attr(not(feature = "backend-dragonfly-proxy"), allow(dead_code))]
    ProxyForbidden(String),
    /// Proxy rate-limited the request (`429`).
    #[cfg_attr(not(feature = "backend-dragonfly-proxy"), allow(dead_code))]
    ProxyTooManyRequests(String),
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestError::Network(e) => write!(f, "network error: {e}"),
            RequestError::ProxyForbidden(s) => write!(f, "proxy forbidden: {s}"),
            RequestError::ProxyTooManyRequests(s) => write!(f, "proxy too many requests: {s}"),
        }
    }
}

pub(crate) type RequestResult<T> = Result<T, RequestError>;

/// A normalized response from any transport.
pub(crate) enum Response {
    Http(reqwest::Response),
    #[cfg(feature = "backend-dragonfly-proxy")]
    Dragonfly(DragonflyResponse),
}

impl Response {
    pub(crate) fn status(&self) -> StatusCode {
        match self {
            Response::Http(r) => r.status(),
            #[cfg(feature = "backend-dragonfly-proxy")]
            Response::Dragonfly(r) => r.status,
        }
    }

    pub(crate) fn headers(&self) -> &HeaderMap {
        match self {
            Response::Http(r) => r.headers(),
            #[cfg(feature = "backend-dragonfly-proxy")]
            Response::Dragonfly(r) => &r.headers,
        }
    }

    /// Consume the response and return its body as a UTF-8 string.
    pub(crate) fn text(self) -> io::Result<String> {
        match self {
            Response::Http(r) => runtime()
                .block_on(async { r.text().await })
                .map_err(|e| io::Error::other(format!("failed to read response body: {e}"))),
            #[cfg(feature = "backend-dragonfly-proxy")]
            Response::Dragonfly(_) => Err(io::Error::other(
                "text body not supported for dragonfly responses",
            )),
        }
    }

    /// Consume the response and copy up to `buf.len()` body bytes into `buf`,
    /// returning the number of bytes written.
    pub(crate) fn copy_to(self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Response::Http(r) => {
                let bytes = runtime()
                    .block_on(async { r.bytes().await })
                    .map_err(|e| io::Error::other(format!("failed to read response body: {e}")))?;
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                Ok(n)
            }
            #[cfg(feature = "backend-dragonfly-proxy")]
            Response::Dragonfly(r) => r.read_into(buf),
        }
    }
}

/// Which transport actually served a request, recorded in completion logs.
#[derive(Debug, Clone, Copy)]
enum ProxyType {
    /// Direct request to the origin.
    None,
    /// Request routed through an HTTP forward proxy.
    Http,
    /// Request routed through the Dragonfly SDK proxy.
    #[cfg_attr(not(feature = "backend-dragonfly-proxy"), allow(dead_code))]
    DragonflySdk,
}

impl ProxyType {
    fn as_str(self) -> &'static str {
        match self {
            ProxyType::None => "none",
            ProxyType::Http => "http",
            ProxyType::DragonflySdk => "dragonfly_sdk",
        }
    }
}

/// Dispatches requests across direct / HTTP-proxy / Dragonfly transports.
pub(crate) struct Request {
    connection: Arc<Connection>,
    proxy: Option<Arc<HttpProxy>>,
    #[cfg(feature = "backend-dragonfly-proxy")]
    dragonfly: Option<Arc<DragonflySdk>>,
}

impl Request {
    pub(crate) fn new(
        connection: Arc<Connection>,
        proxy: Option<Arc<HttpProxy>>,
        #[cfg(feature = "backend-dragonfly-proxy")] dragonfly: Option<Arc<DragonflySdk>>,
    ) -> Arc<Request> {
        Arc::new(Request {
            connection,
            proxy,
            #[cfg(feature = "backend-dragonfly-proxy")]
            dragonfly,
        })
    }

    /// Issue a request. When `allow_proxy` is false (e.g. auth token requests),
    /// the call always goes directly to the origin.
    pub(crate) fn call(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        ctx: ReadContext,
        allow_proxy: bool,
    ) -> RequestResult<Response> {
        if allow_proxy {
            #[cfg(feature = "backend-dragonfly-proxy")]
            if let Some(dragonfly) = &self.dragonfly {
                if method == Method::GET {
                    return self.call_dragonfly(dragonfly, url, headers, ctx);
                }
            }

            if let Some(proxy) = &self.proxy {
                let mut headers = headers;
                HttpProxy::decorate(&mut headers, ctx.source);
                return self.send(proxy.client(), method, url, headers, ctx, ProxyType::Http);
            }
        }

        self.send(
            self.connection.client(),
            method,
            url,
            headers,
            ctx,
            ProxyType::None,
        )
    }

    /// Send a request with the given client and log its completion.
    fn send(
        &self,
        client: &Client,
        method: Method,
        url: &str,
        headers: HeaderMap,
        ctx: ReadContext,
        proxy_type: ProxyType,
    ) -> RequestResult<Response> {
        let start = Instant::now();
        let result = runtime().block_on(async {
            client
                .request(method.clone(), url)
                .headers(headers.clone())
                .send()
                .await
        });
        let duration = start.elapsed();

        match result {
            Ok(resp) => {
                let status = resp.status();
                log_backend_request_done(
                    proxy_type,
                    &method,
                    url,
                    &headers,
                    ctx,
                    Some(status),
                    Some(resp.headers()),
                    None,
                    duration,
                );
                Ok(Response::Http(resp))
            }
            Err(e) => {
                let msg = e.to_string();
                log_backend_request_done(
                    proxy_type,
                    &method,
                    url,
                    &headers,
                    ctx,
                    None,
                    None,
                    Some(&msg),
                    duration,
                );
                Err(RequestError::Network(io::Error::other(e)))
            }
        }
    }

    #[cfg(feature = "backend-dragonfly-proxy")]
    fn call_dragonfly(
        &self,
        dragonfly: &Arc<DragonflySdk>,
        url: &str,
        mut headers: HeaderMap,
        ctx: ReadContext,
    ) -> RequestResult<Response> {
        HttpProxy::decorate(&mut headers, ctx.source);
        let priority = super::proxy::dragonfly_priority(ctx.source);

        let start = Instant::now();
        let result = dragonfly.get(url, headers.clone(), priority);
        let duration = start.elapsed();
        match result {
            Ok(resp) => {
                let status = resp.status;
                let response_headers = resp.headers.clone();
                log_backend_request_done(
                    ProxyType::DragonflySdk,
                    &Method::GET,
                    url,
                    &headers,
                    ctx,
                    Some(status),
                    Some(&response_headers),
                    None,
                    duration,
                );
                Ok(Response::Dragonfly(resp))
            }
            Err(err) => {
                let msg = err.to_string();
                log_backend_request_done(
                    ProxyType::DragonflySdk,
                    &Method::GET,
                    url,
                    &headers,
                    ctx,
                    None,
                    None,
                    Some(&msg),
                    duration,
                );
                match err {
                    DragonflyError::TooManyRequests(s) => {
                        Err(RequestError::ProxyTooManyRequests(s))
                    }
                    DragonflyError::Forbidden(s) => Err(RequestError::ProxyForbidden(s)),
                    DragonflyError::Other(s) => Err(RequestError::Network(io::Error::other(s))),
                }
            }
        }
    }
}

/// Whether an HTTP status code denotes success (2xx).
pub(crate) fn is_success_status(status: StatusCode) -> bool {
    status.is_success()
}

/// Log a completed backend request at debug level so it can be inspected during
/// a `check` (run with `--log-level debug`). The line carries the request
/// source, the transport that served it, the method, final URL and full request
/// headers, plus the outcome: response status and headers when the transport
/// returned a response, an error string on transport failure, and the
/// wall-clock duration in human-readable form.
#[allow(clippy::too_many_arguments)]
fn log_backend_request_done(
    proxy_type: ProxyType,
    method: &Method,
    url: &str,
    headers: &HeaderMap,
    ctx: ReadContext,
    status: Option<StatusCode>,
    response_headers: Option<&HeaderMap>,
    error: Option<&str>,
    duration: Duration,
) {
    let request_source = match ctx.source {
        RequestSource::OnDemand => "ondemand",
        RequestSource::Prefetch => "prefetch",
    };
    debug!(
        "backend request done: request_source={request_source} proxy_type={} method={method} url={url} headers={headers:?} status={status:?} response_headers={response_headers:?} error={error:?} duration={}",
        proxy_type.as_str(),
        format_duration(duration),
    );
}

/// Format a duration in a compact, human-readable unit (ns/µs/ms/s).
fn format_duration(d: Duration) -> String {
    let nanos = d.as_nanos();
    if nanos < 1_000 {
        format!("{nanos}ns")
    } else if nanos < 1_000_000 {
        format!("{:.3}µs", nanos as f64 / 1_000.0)
    } else if nanos < 1_000_000_000 {
        format!("{:.3}ms", nanos as f64 / 1_000_000.0)
    } else {
        format!("{:.3}s", d.as_secs_f64())
    }
}
