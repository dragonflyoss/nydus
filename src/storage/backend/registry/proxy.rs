//! Proxy support for the registry backend.
//!
//! Two independent proxy mechanisms are supported, both configured under the
//! `proxy` block:
//!
//! * **HTTP mirror** ([`HttpMirror`]): blob requests are rewritten to a mirror
//!   endpoint (e.g. a local P2P agent's HTTP proxy) given by `proxy.url`.
//! * **Dragonfly SDK** ([`DragonflyProxy`], feature `backend-dragonfly-proxy`):
//!   blob requests go through the Dragonfly client SDK using the scheduler
//!   endpoint `proxy.dragonfly_scheduler_endpoint`, returning a streaming reader.

use std::sync::Arc;

use serde::Deserialize;
use url::Url;

/// Priority hint passed to Dragonfly for prefetch (background) requests.
#[cfg(feature = "backend-dragonfly-proxy")]
pub(crate) const DRAGONFLY_PRIORITY_PREFETCH: i32 = 3;
/// Priority hint passed to Dragonfly for on-demand (foreground) requests.
#[cfg(feature = "backend-dragonfly-proxy")]
pub(crate) const DRAGONFLY_PRIORITY_ONDEMAND: i32 = 6;

#[cfg(feature = "backend-dragonfly-proxy")]
pub(crate) const HEADER_DRAGONFLY_PRIORITY: &str = "X-Dragonfly-Priority";
#[cfg(feature = "backend-dragonfly-proxy")]
pub(crate) const HEADER_DRAGONFLY_USE_P2P: &str = "X-Dragonfly-Use-P2P";

/// Proxy configuration. Either or both transports may be set; an empty block
/// (or an omitted one) talks to the origin registry directly.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ProxyConfig {
    /// HTTP mirror base URL, e.g. `http://127.0.0.1:65001`. Blob requests are
    /// rewritten to this mirror, preserving the original path and query.
    #[serde(default)]
    pub url: Option<String>,
    /// Dragonfly scheduler endpoint (gRPC), e.g. `http://127.0.0.1:65000`.
    /// Only used when built with the `backend-dragonfly-proxy` feature.
    #[cfg(feature = "backend-dragonfly-proxy")]
    #[serde(default)]
    pub dragonfly_scheduler_endpoint: Option<String>,
}

/// HTTP mirror proxy that rewrites blob requests to a mirror endpoint.
pub(crate) struct HttpMirror {
    base: Url,
}

impl HttpMirror {
    pub(crate) fn new(url: &str) -> std::io::Result<Arc<HttpMirror>> {
        let base = Url::parse(url).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid proxy url {url}: {e}"),
            )
        })?;
        Ok(Arc::new(HttpMirror { base }))
    }

    /// Rewrite an origin URL to route through the mirror, preserving the path
    /// and query of the original request.
    pub(crate) fn rewrite(&self, origin: &Url) -> Url {
        let mut url = self.base.clone();
        url.set_path(origin.path());
        url.set_query(origin.query());
        url
    }
}

#[cfg(feature = "backend-dragonfly-proxy")]
pub(crate) use dragonfly::{DragonflyError, DragonflyProxy, DragonflyResponse};

#[cfg(feature = "backend-dragonfly-proxy")]
mod dragonfly {
    use std::sync::Arc;
    use std::time::Duration;

    use reqwest::header::HeaderMap;
    use reqwest::StatusCode;
    use tokio::io::AsyncReadExt;

    use dragonfly_client_util::request::errors::Error;
    use dragonfly_client_util::request::{Body, Builder, GetRequest, Proxy, Request as _};

    use super::super::http::runtime;

    /// Error categories surfaced by the Dragonfly SDK proxy.
    #[derive(Debug)]
    pub(crate) enum DragonflyError {
        TooManyRequests(String),
        Forbidden(String),
        Other(String),
    }

    impl std::fmt::Display for DragonflyError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                DragonflyError::TooManyRequests(s) => write!(f, "dragonfly too many requests: {s}"),
                DragonflyError::Forbidden(s) => write!(f, "dragonfly forbidden: {s}"),
                DragonflyError::Other(s) => write!(f, "dragonfly error: {s}"),
            }
        }
    }

    /// Response from a Dragonfly SDK request.
    pub(crate) struct DragonflyResponse {
        pub status: StatusCode,
        pub headers: HeaderMap,
        reader: Option<Body>,
    }

    impl DragonflyResponse {
        /// Read the entire response body into `buf`, returning the byte count.
        pub(crate) fn read_into(self, buf: &mut [u8]) -> std::io::Result<usize> {
            let Some(mut reader) = self.reader else {
                return Ok(0);
            };
            runtime().block_on(async move {
                let mut filled = 0usize;
                while filled < buf.len() {
                    let n = reader.read(&mut buf[filled..]).await?;
                    if n == 0 {
                        break;
                    }
                    filled += n;
                }
                Ok(filled)
            })
        }
    }

    /// Dragonfly SDK proxy client wrapping a scheduler connection.
    pub(crate) struct DragonflyProxy {
        client: Proxy,
    }

    impl DragonflyProxy {
        pub(crate) fn new(scheduler_endpoint: &str) -> std::io::Result<Arc<DragonflyProxy>> {
            let endpoint = scheduler_endpoint.to_string();
            let client = runtime()
                .block_on(async move {
                    Builder::default()
                        .scheduler_endpoint(endpoint)
                        .max_retries(0)
                        .build()
                        .await
                })
                .map_err(|e| {
                    std::io::Error::other(format!("failed to build dragonfly proxy: {e}"))
                })?;
            Ok(Arc::new(DragonflyProxy { client }))
        }

        /// Issue a blob GET through Dragonfly with the given priority hint.
        pub(crate) fn get(
            &self,
            url: &str,
            headers: HeaderMap,
            priority: i32,
        ) -> Result<DragonflyResponse, DragonflyError> {
            let request = GetRequest {
                url: url.to_string(),
                header: Some(headers),
                piece_length: None,
                tag: None,
                application: None,
                filtered_query_params: Vec::new(),
                content_for_calculating_task_id: None,
                priority: Some(priority),
                timeout: Duration::from_secs(30),
                client_cert: None,
            };

            let resp: Result<dragonfly_client_util::request::GetResponse<Body>, Error> =
                runtime().block_on(async { self.client.get(request).await });

            match resp {
                Ok(resp) => Ok(DragonflyResponse {
                    status: resp.status_code.unwrap_or(StatusCode::OK),
                    headers: resp.header.unwrap_or_default(),
                    reader: resp.reader,
                }),
                Err(Error::ProxyError(err)) => match err.status_code {
                    Some(StatusCode::TOO_MANY_REQUESTS) => {
                        Err(DragonflyError::TooManyRequests(format!("{err}")))
                    }
                    Some(StatusCode::FORBIDDEN) => Err(DragonflyError::Forbidden(format!("{err}"))),
                    _ => Err(DragonflyError::Other(format!("{err}"))),
                },
                Err(e) => Err(DragonflyError::Other(format!("{e:?}"))),
            }
        }
    }
}
