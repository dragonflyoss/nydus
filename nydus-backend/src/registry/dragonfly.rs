//! Dragonfly SDK transport (feature `backend-dragonfly-proxy`).
//!
//! Routes a blob `GET` through the Dragonfly client SDK using a scheduler
//! endpoint, returning a streaming response. This bypasses plain HTTP and lets
//! Dragonfly schedule P2P piece distribution directly; it is selected for blob
//! `GET`s when a scheduler endpoint is configured, while every other request
//! goes directly to the origin.

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::StatusCode;

use dragonfly_client_request::errors::Error;
use dragonfly_client_request::{Body, Builder, GetRequest, Proxy, Request as _};

use nydus_config::DragonflyConfig;

use super::{runtime, RegistryError, Response};
use crate::ReadKind;

/// The fallback request timeout when the configured timeout is `0` (disabled):
/// SDK requests always need a bounded timeout.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The priority hint for background prefetch requests.
const PRIORITY_PREFETCH: i32 = 3;

/// The priority hint for on-demand (foreground) requests.
const PRIORITY_ONDEMAND: i32 = 6;

/// The header carrying the Dragonfly scheduling priority of a request.
const HEADER_PRIORITY: &str = "X-Dragonfly-Priority";

/// The header opting a request into Dragonfly P2P distribution.
const HEADER_USE_P2P: &str = "X-Dragonfly-Use-P2P";

/// Map a read kind to its Dragonfly priority value.
fn priority(kind: ReadKind) -> i32 {
    match kind {
        ReadKind::Prefetch => PRIORITY_PREFETCH,
        ReadKind::OnDemand => PRIORITY_ONDEMAND,
    }
}

/// The Dragonfly SDK transport, wrapping a scheduler connection.
pub(crate) struct Dragonfly {
    /// The SDK client bound to the scheduler.
    client: Proxy,

    /// The per-request timeout.
    timeout: Duration,
}

impl Dragonfly {
    /// Create a new Dragonfly transport connected to the configured scheduler.
    /// `timeout` is the configured per-request timeout, `0s` (disabled)
    /// falling back to [`DEFAULT_TIMEOUT`]; `max_retries` is the maximum
    /// number of retry attempts the SDK performs per request.
    pub(crate) fn new(
        config: &DragonflyConfig,
        timeout: Duration,
        max_retries: u32,
    ) -> std::io::Result<Dragonfly> {
        let endpoint = config.scheduler_endpoint.clone();
        // The SDK builder takes a `u8` retry count; saturate larger values.
        let max_retries = u8::try_from(max_retries).unwrap_or(u8::MAX);
        let client = runtime()
            .block_on(async move {
                Builder::default()
                    .scheduler_endpoint(endpoint)
                    .max_retries(max_retries)
                    .build()
                    .await
            })
            .map_err(|err| {
                std::io::Error::other(format!("failed to build dragonfly client: {err}"))
            })?;

        let timeout = if timeout.is_zero() {
            DEFAULT_TIMEOUT
        } else {
            timeout
        };
        Ok(Dragonfly { client, timeout })
    }

    /// Issue a blob `GET` through Dragonfly, attaching the priority and P2P
    /// hints derived from the read kind.
    pub(crate) fn get(
        &self,
        url: &str,
        mut headers: HeaderMap,
        kind: ReadKind,
    ) -> Result<Response, RegistryError> {
        let priority = priority(kind);
        if let Ok(value) = priority.to_string().parse() {
            headers.insert(HEADER_PRIORITY, value);
        }
        headers.insert(HEADER_USE_P2P, HeaderValue::from_static("true"));

        let request = GetRequest {
            url: url.to_string(),
            header: headers,
            filtered_query_params: Vec::new(),
            priority: Some(priority),
            timeout: self.timeout,
            ..Default::default()
        };

        let response: Result<dragonfly_client_request::GetResponse<Body>, Error> =
            runtime().block_on(async { self.client.get(&request).await });

        match response {
            Ok(response) => Ok(Response {
                status: response.status_code.unwrap_or(StatusCode::OK),
                headers: response.header,
                reader: match response.reader {
                    Some(reader) => Box::new(reader),
                    None => Box::new(tokio::io::empty()),
                },
            }),
            Err(Error::ProxyError(err)) => match err.status_code {
                Some(StatusCode::TOO_MANY_REQUESTS) => {
                    Err(RegistryError::TooManyRequests(format!("{err}")))
                }
                Some(StatusCode::FORBIDDEN) => Err(RegistryError::Forbidden(format!("{err}"))),
                _ => Err(RegistryError::Io(std::io::Error::other(format!(
                    "dragonfly error: {err}"
                )))),
            },
            Err(err) => Err(RegistryError::Io(std::io::Error::other(format!(
                "dragonfly error: {err}"
            )))),
        }
    }
}
