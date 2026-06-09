//! Request routing for the registry backend.
//!
//! [`Request`] dispatches a logical HTTP call to one of three transports —
//! direct origin, HTTP mirror proxy, or Dragonfly SDK proxy — and normalizes
//! the result into a single [`Response`] type. Proxy errors are surfaced with
//! enough structure for the retry policy to distinguish `403`/`429` from
//! transient network failures.

use std::io;
use std::sync::Arc;

use reqwest::header::{HeaderMap, RANGE};
use reqwest::{Method, StatusCode};
use tracing::debug;
use url::Url;

use super::http::{runtime, Connection};
use super::proxy::HttpMirror;
use crate::storage::backend::{ReadContext, RequestSource};

#[cfg(feature = "backend-dragonfly-proxy")]
use super::proxy::{
    DragonflyProxy, DragonflyResponse, DRAGONFLY_PRIORITY_ONDEMAND, DRAGONFLY_PRIORITY_PREFETCH,
    HEADER_DRAGONFLY_PRIORITY, HEADER_DRAGONFLY_USE_P2P,
};

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

/// Dispatches requests across direct / mirror / Dragonfly transports.
pub(crate) struct Request {
    connection: Arc<Connection>,
    mirror: Option<Arc<HttpMirror>>,
    #[cfg(feature = "backend-dragonfly-proxy")]
    dragonfly: Option<Arc<DragonflyProxy>>,
}

impl Request {
    pub(crate) fn new(
        connection: Arc<Connection>,
        mirror: Option<Arc<HttpMirror>>,
        #[cfg(feature = "backend-dragonfly-proxy")] dragonfly: Option<Arc<DragonflyProxy>>,
    ) -> Arc<Request> {
        Arc::new(Request {
            connection,
            mirror,
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

            if let Some(mirror) = &self.mirror {
                let origin = Url::parse(url).map_err(|e| {
                    RequestError::Network(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid url {url}: {e}"),
                    ))
                })?;
                let mirror_url = mirror.rewrite(&origin);
                return self.direct(method, mirror_url.as_str(), headers, ctx);
            }
        }

        self.direct(method, url, headers, ctx)
    }

    fn direct(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        ctx: ReadContext,
    ) -> RequestResult<Response> {
        log_backend_request("http", &method, url, &headers, ctx);
        let client = self.connection.client();
        let result =
            runtime().block_on(async { client.request(method, url).headers(headers).send().await });

        result
            .map(Response::Http)
            .map_err(|e| RequestError::Network(io::Error::other(e)))
    }

    #[cfg(feature = "backend-dragonfly-proxy")]
    fn call_dragonfly(
        &self,
        dragonfly: &Arc<DragonflyProxy>,
        url: &str,
        mut headers: HeaderMap,
        ctx: ReadContext,
    ) -> RequestResult<Response> {
        let priority = match ctx.source {
            RequestSource::Prefetch => DRAGONFLY_PRIORITY_PREFETCH,
            RequestSource::OnDemand => DRAGONFLY_PRIORITY_ONDEMAND,
        };
        headers.insert(
            HEADER_DRAGONFLY_PRIORITY,
            priority.to_string().parse().unwrap(),
        );
        headers.insert(HEADER_DRAGONFLY_USE_P2P, "true".parse().unwrap());

        log_backend_request("dragonfly", &Method::GET, url, &headers, ctx);
        use super::proxy::DragonflyError;
        match dragonfly.get(url, headers, priority) {
            Ok(resp) => Ok(Response::Dragonfly(resp)),
            Err(DragonflyError::TooManyRequests(s)) => Err(RequestError::ProxyTooManyRequests(s)),
            Err(DragonflyError::Forbidden(s)) => Err(RequestError::ProxyForbidden(s)),
            Err(DragonflyError::Other(s)) => Err(RequestError::Network(io::Error::other(s))),
        }
    }
}

/// Whether an HTTP status code denotes success (2xx).
pub(crate) fn is_success_status(status: StatusCode) -> bool {
    status.is_success()
}

/// Log an outgoing backend request at debug level so it can be inspected during
/// a `check` (run with `--log-level debug`): the transport, method, final link,
/// request type, and the read's compressed (registry byte range) and
/// uncompressed (decoded group) geometry. Requests without a `Range` header
/// (HEAD, auth token) and reads without a group span log the corresponding
/// fields as `-`.
fn log_backend_request(
    transport: &str,
    method: &Method,
    url: &str,
    headers: &HeaderMap,
    ctx: ReadContext,
) {
    let request_type = match ctx.source {
        RequestSource::OnDemand => "ondemand",
        RequestSource::Prefetch => "prefetch",
    };
    let (compressed_offset, compressed_size) = match headers
        .get(RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_byte_range)
    {
        Some((offset, size)) => (offset.to_string(), size.to_string()),
        None => ("-".to_string(), "-".to_string()),
    };
    let (uncompressed_offset, uncompressed_size) = match ctx.uncompressed {
        Some((offset, size)) => (offset.to_string(), size.to_string()),
        None => ("-".to_string(), "-".to_string()),
    };
    debug!(
        "backend {transport} request: {method} {url} request_type={request_type} compressed_offset={compressed_offset} compressed_size={compressed_size} uncompressed_offset={uncompressed_offset} uncompressed_size={uncompressed_size}"
    );
}

/// Parse a `bytes=START-END` range header value into `(offset, size)`.
fn parse_byte_range(value: &str) -> Option<(u64, u64)> {
    let spec = value.trim().strip_prefix("bytes=")?;
    let (start, end) = spec.split_once('-')?;
    let start: u64 = start.trim().parse().ok()?;
    let end: u64 = end.trim().parse().ok()?;
    if end < start {
        return None;
    }
    Some((start, end - start + 1))
}
