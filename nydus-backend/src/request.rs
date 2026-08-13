//! Unified request routing for HTTP-based backends.
//!
//! [`RequestDispatcher`] dispatches a logical HTTP call across one of three transports —
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

use super::http::{runtime, HttpClient};
use super::proxy::HttpProxy;
use super::{ReadContext, ReadKind};

#[cfg(feature = "backend-dragonfly-proxy")]
use super::dragonfly_sdk::{DragonflyClient, DragonflyError, DragonflyResponse};

/// Errors produced while issuing a request.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RequestError {
    /// Transient network/transport failure (origin, timeout, ...).
    #[error("network error: {0}")]
    Network(io::Error),
    /// Proxy denied the request (`403`).
    #[cfg_attr(not(feature = "backend-dragonfly-proxy"), allow(dead_code))]
    #[error("proxy forbidden: {0}")]
    ProxyForbidden(String),
    /// Proxy rate-limited the request (`429`).
    #[cfg_attr(not(feature = "backend-dragonfly-proxy"), allow(dead_code))]
    #[error("proxy too many requests: {0}")]
    ProxyTooManyRequests(String),
}

pub(crate) type RequestResult<T> = Result<T, RequestError>;

/// A normalized response from any transport.
pub(crate) enum TransportResponse {
    Http(reqwest::Response),
    #[cfg(feature = "backend-dragonfly-proxy")]
    Dragonfly(DragonflyResponse),
}

impl TransportResponse {
    pub(crate) fn status(&self) -> StatusCode {
        match self {
            TransportResponse::Http(r) => r.status(),
            #[cfg(feature = "backend-dragonfly-proxy")]
            TransportResponse::Dragonfly(r) => r.status,
        }
    }

    pub(crate) fn headers(&self) -> &HeaderMap {
        match self {
            TransportResponse::Http(r) => r.headers(),
            #[cfg(feature = "backend-dragonfly-proxy")]
            TransportResponse::Dragonfly(r) => &r.headers,
        }
    }

    /// Consume the response and return its body as a UTF-8 string.
    pub(crate) fn text(self) -> io::Result<String> {
        match self {
            TransportResponse::Http(r) => runtime()
                .block_on(async { r.text().await })
                .map_err(|err| io::Error::other(format!("failed to read response body: {err}"))),
            #[cfg(feature = "backend-dragonfly-proxy")]
            TransportResponse::Dragonfly(_) => Err(io::Error::other(
                "text body not supported for dragonfly responses",
            )),
        }
    }

    /// Consume the response and copy up to `buf.len()` body bytes into `buf`,
    /// returning the number of bytes written.
    pub(crate) fn read_into(self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            TransportResponse::Http(r) => {
                let bytes = runtime()
                    .block_on(async { r.bytes().await })
                    .map_err(|err| {
                        io::Error::other(format!("failed to read response body: {err}"))
                    })?;
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                Ok(n)
            }
            #[cfg(feature = "backend-dragonfly-proxy")]
            TransportResponse::Dragonfly(r) => r.read_into(buf),
        }
    }
}

/// Which transport actually served a request, recorded in completion logs.
#[derive(Debug, Clone, Copy)]
enum Transport {
    /// Direct request to the origin.
    Direct,
    /// Routed through an HTTP forward proxy.
    HttpProxy,
    /// Routed through the Dragonfly SDK proxy.
    #[cfg_attr(not(feature = "backend-dragonfly-proxy"), allow(dead_code))]
    DragonflySdk,
}

impl Transport {
    /// Log label; values are load-bearing for log consumers and stay as-is.
    fn as_str(self) -> &'static str {
        match self {
            Transport::Direct => "none",
            Transport::HttpProxy => "http",
            Transport::DragonflySdk => "dragonfly_sdk",
        }
    }
}

/// Dispatches requests across direct / HTTP-proxy / Dragonfly transports.
pub(crate) struct RequestDispatcher {
    origin: Arc<HttpClient>,
    proxy: Option<Arc<HttpProxy>>,
    #[cfg(feature = "backend-dragonfly-proxy")]
    dragonfly: Option<Arc<DragonflyClient>>,
}

impl RequestDispatcher {
    pub(crate) fn new(
        origin: Arc<HttpClient>,
        proxy: Option<Arc<HttpProxy>>,
        #[cfg(feature = "backend-dragonfly-proxy")] dragonfly: Option<Arc<DragonflyClient>>,
    ) -> Arc<RequestDispatcher> {
        Arc::new(RequestDispatcher {
            origin,
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
    ) -> RequestResult<TransportResponse> {
        if allow_proxy {
            #[cfg(feature = "backend-dragonfly-proxy")]
            if let Some(dragonfly) = &self.dragonfly {
                if method == Method::GET {
                    return self.call_dragonfly(dragonfly, url, headers, ctx);
                }
            }

            if let Some(proxy) = &self.proxy {
                let mut headers = headers;
                HttpProxy::apply_dragonfly_hints(&mut headers, ctx.kind);
                return self.send(
                    proxy.client(),
                    method,
                    url,
                    headers,
                    ctx,
                    Transport::HttpProxy,
                );
            }
        }

        self.send(
            self.origin.client(),
            method,
            url,
            headers,
            ctx,
            Transport::Direct,
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
        transport: Transport,
    ) -> RequestResult<TransportResponse> {
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
                    transport,
                    &method,
                    url,
                    &headers,
                    ctx,
                    Some(status),
                    Some(resp.headers()),
                    None,
                    duration,
                );
                Ok(TransportResponse::Http(resp))
            }
            Err(err) => {
                let msg = err.to_string();
                log_backend_request_done(
                    transport,
                    &method,
                    url,
                    &headers,
                    ctx,
                    None,
                    None,
                    Some(&msg),
                    duration,
                );
                Err(RequestError::Network(io::Error::other(err)))
            }
        }
    }

    #[cfg(feature = "backend-dragonfly-proxy")]
    fn call_dragonfly(
        &self,
        dragonfly: &Arc<DragonflyClient>,
        url: &str,
        mut headers: HeaderMap,
        ctx: ReadContext,
    ) -> RequestResult<TransportResponse> {
        HttpProxy::apply_dragonfly_hints(&mut headers, ctx.kind);
        let priority = super::proxy::dragonfly_priority(ctx.kind);

        let start = Instant::now();
        let result = dragonfly.get(url, headers.clone(), priority);
        let duration = start.elapsed();
        match result {
            Ok(resp) => {
                let status = resp.status;
                let response_headers = resp.headers.clone();
                log_backend_request_done(
                    Transport::DragonflySdk,
                    &Method::GET,
                    url,
                    &headers,
                    ctx,
                    Some(status),
                    Some(&response_headers),
                    None,
                    duration,
                );
                Ok(TransportResponse::Dragonfly(resp))
            }
            Err(err) => {
                let msg = err.to_string();
                log_backend_request_done(
                    Transport::DragonflySdk,
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

/// Log a completed backend request at debug level so it can be inspected during
/// a `check` (run with `--log-level debug`). The line carries the request
/// source, the transport that served it, the method, final URL and full request
/// headers, plus the outcome: response status and headers when the transport
/// returned a response, an error string on transport failure, and the
/// wall-clock duration in human-readable form.
#[allow(clippy::too_many_arguments)]
fn log_backend_request_done(
    transport: Transport,
    method: &Method,
    url: &str,
    headers: &HeaderMap,
    ctx: ReadContext,
    status: Option<StatusCode>,
    response_headers: Option<&HeaderMap>,
    error: Option<&str>,
    duration: Duration,
) {
    let read_kind = match ctx.kind {
        ReadKind::OnDemand => "ondemand",
        ReadKind::Prefetch => "prefetch",
    };
    debug!(
        "backend request done: read_kind={read_kind} transport={} method={method} url={url} headers={headers:?} status={status:?} response_headers={response_headers:?} error={error:?} duration={}",
        transport.as_str(),
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
