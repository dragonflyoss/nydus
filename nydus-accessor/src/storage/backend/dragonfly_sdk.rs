//! Dragonfly SDK proxy transport (feature `backend-dragonfly-proxy`).
//!
//! Routes a blob `GET` through the Dragonfly client SDK using a scheduler
//! endpoint, returning a streaming response. This bypasses plain HTTP and lets
//! Dragonfly schedule P2P piece distribution directly. It is the alternative to
//! the [`HttpProxy`](super::proxy::HttpProxy) transport, selected when a
//! scheduler endpoint is configured.

use std::sync::Arc;
use std::time::Duration;

use reqwest::header::HeaderMap;
use reqwest::StatusCode;
use tokio::io::AsyncReadExt;

use dragonfly_client_request::errors::Error;
use dragonfly_client_request::{Body, Builder, GetRequest, Proxy, Request as _};

use super::http::runtime;

/// Error categories surfaced by the Dragonfly SDK proxy, mapped to the retry
/// policy by the request layer.
#[derive(Debug)]
pub(crate) enum DragonflyError {
    /// Proxy rate-limited the request (`429`).
    TooManyRequests(String),
    /// Proxy denied the request (`403`).
    Forbidden(String),
    /// Any other transport or scheduler failure.
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

/// A streaming response from a Dragonfly SDK request.
pub(crate) struct DragonflyResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    reader: Option<Body>,
}

impl DragonflyResponse {
    /// Read the response body into `buf`, returning the number of bytes filled.
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

/// Dragonfly SDK client wrapping a scheduler connection.
pub(crate) struct DragonflySdk {
    client: Proxy,
}

impl DragonflySdk {
    /// Connect to the Dragonfly scheduler at `scheduler_endpoint`.
    pub(crate) fn new(scheduler_endpoint: &str) -> std::io::Result<Arc<DragonflySdk>> {
        let endpoint = scheduler_endpoint.to_string();
        let client = runtime()
            .block_on(async move {
                Builder::default()
                    .scheduler_endpoint(endpoint)
                    .max_retries(0)
                    .build()
                    .await
            })
            .map_err(|e| std::io::Error::other(format!("failed to build dragonfly proxy: {e}")))?;
        Ok(Arc::new(DragonflySdk { client }))
    }

    /// Issue a blob `GET` through Dragonfly with the given priority hint.
    pub(crate) fn get(
        &self,
        url: &str,
        headers: HeaderMap,
        priority: i32,
    ) -> Result<DragonflyResponse, DragonflyError> {
        let request = GetRequest {
            url: url.to_string(),
            header: headers,
            filtered_query_params: Vec::new(),
            priority: Some(priority),
            timeout: Duration::from_secs(30),
            ..Default::default()
        };

        let resp: Result<dragonfly_client_request::GetResponse<Body>, Error> =
            runtime().block_on(async { self.client.get(&request).await });

        match resp {
            Ok(resp) => Ok(DragonflyResponse {
                status: resp.status_code.unwrap_or(StatusCode::OK),
                headers: resp.header,
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
