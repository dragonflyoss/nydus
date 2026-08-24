//! Dragonfly SDK transport (feature `backend-dragonfly-proxy`).
//!
//! Routes a blob `GET` through the Dragonfly client SDK using a scheduler
//! endpoint, returning a streaming response. This bypasses plain HTTP and lets
//! Dragonfly schedule P2P piece distribution directly; it is selected for blob
//! `GET`s when a scheduler endpoint is configured, while every other request
//! goes directly to the origin. SDK errors are classified into the
//! load-shedding policy's failure classes here; retries are owned by the
//! policy loop in the parent module, so the SDK's internal retries are
//! disabled to keep the policy's attempt counts exact.

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::StatusCode;

use dragonfly_client_request::errors::Error;
use dragonfly_client_request::{Body, Builder, GetRequest, Proxy, Request as _};

use nydus_config::DragonflyConfig;

use super::{
    runtime, DragonflyError, DragonflyFailure, DragonflyTransport, Response, RetryableCause,
};
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
    /// falling back to [`DEFAULT_TIMEOUT`]. The SDK's internal retries are
    /// disabled (`max_retries(0)`): the load-shedding policy in the parent
    /// module owns retry counts, so they stay exact and observable.
    pub(crate) fn new(config: &DragonflyConfig, timeout: Duration) -> std::io::Result<Dragonfly> {
        let endpoint = config.scheduler_endpoint.clone();
        let client = runtime()
            .block_on(async move {
                Builder::default()
                    .scheduler_endpoint(endpoint)
                    .max_retries(0)
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
}

/// Classify an SDK error into the load-shedding policy's failure classes:
/// a proxy `429` is `RateLimited`, a proxy `403` is `Forbidden`, and
/// everything else is `Retryable` tagged with its cause — request timeout,
/// dfdaemon connectivity, a proxy/backend `5xx`, or any other transport
/// error.
fn classify(err: &Error) -> DragonflyFailure {
    match err {
        Error::RequestTimeout(_) => DragonflyFailure::Retryable(RetryableCause::Timeout),
        Error::DfdaemonError(_) => DragonflyFailure::Retryable(RetryableCause::Connect),
        Error::ProxyError(proxy) => match proxy.status_code {
            Some(StatusCode::TOO_MANY_REQUESTS) => DragonflyFailure::RateLimited,
            Some(StatusCode::FORBIDDEN) => DragonflyFailure::Forbidden,
            Some(code) if code.is_server_error() => {
                DragonflyFailure::Retryable(RetryableCause::ServerError)
            }
            _ => DragonflyFailure::Retryable(RetryableCause::Other),
        },
        Error::BackendError(backend) => match backend.status_code {
            Some(code) if code.is_server_error() => {
                DragonflyFailure::Retryable(RetryableCause::ServerError)
            }
            _ => DragonflyFailure::Retryable(RetryableCause::Other),
        },
        _ => DragonflyFailure::Retryable(RetryableCause::Other),
    }
}

impl DragonflyTransport for Dragonfly {
    /// Issue a blob `GET` through Dragonfly, attaching the priority and P2P
    /// hints derived from the read kind.
    fn get(
        &self,
        url: &str,
        mut headers: HeaderMap,
        kind: ReadKind,
    ) -> Result<Response, DragonflyError> {
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
            Err(err) => Err(DragonflyError {
                failure: classify(&err),
                message: err.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dragonfly_client_request::errors::{BackendError, DfdaemonError, ProxyError};
    use std::collections::HashMap;

    fn proxy_error(status_code: Option<StatusCode>) -> Error {
        Error::ProxyError(ProxyError {
            message: Some("proxy".to_string()),
            header: HashMap::new(),
            status_code,
        })
    }

    #[test]
    fn classifies_sdk_errors() {
        assert_eq!(
            classify(&proxy_error(Some(StatusCode::TOO_MANY_REQUESTS))),
            DragonflyFailure::RateLimited
        );
        assert_eq!(
            classify(&proxy_error(Some(StatusCode::FORBIDDEN))),
            DragonflyFailure::Forbidden
        );
        assert_eq!(
            classify(&proxy_error(Some(StatusCode::BAD_GATEWAY))),
            DragonflyFailure::Retryable(RetryableCause::ServerError)
        );
        assert_eq!(
            classify(&proxy_error(Some(StatusCode::NOT_FOUND))),
            DragonflyFailure::Retryable(RetryableCause::Other)
        );
        assert_eq!(
            classify(&proxy_error(None)),
            DragonflyFailure::Retryable(RetryableCause::Other)
        );
        assert_eq!(
            classify(&Error::RequestTimeout("deadline exceeded".to_string())),
            DragonflyFailure::Retryable(RetryableCause::Timeout)
        );
        assert_eq!(
            classify(&Error::DfdaemonError(DfdaemonError {
                message: Some("connection refused".to_string()),
            })),
            DragonflyFailure::Retryable(RetryableCause::Connect)
        );
        assert_eq!(
            classify(&Error::BackendError(BackendError {
                message: Some("origin 503".to_string()),
                header: HashMap::new(),
                status_code: Some(StatusCode::SERVICE_UNAVAILABLE),
            })),
            DragonflyFailure::Retryable(RetryableCause::ServerError)
        );
        assert_eq!(
            classify(&Error::Internal("boom".to_string())),
            DragonflyFailure::Retryable(RetryableCause::Other)
        );
    }
}
