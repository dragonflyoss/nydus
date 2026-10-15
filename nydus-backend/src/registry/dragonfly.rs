//! The Dragonfly SDK transport, feature `backend-dragonfly`.
//!
//! A blob `GET` rides the Dragonfly client SDK to the seed peers named by the
//! scheduler, every other request going straight to the origin. The SDK owns
//! the retries: an on-demand read retries a transient failure, a `429`
//! included, on the next seed peer up to the configured budget, while a
//! prefetch read never retries, the storage layer rescheduling a failed
//! prefetch hours later instead. An answer the SDK reports as an error but
//! that carries an HTTP status is handed back as a [`Response`], so
//! [`policy`](super::policy) classifies it by status like an origin answer.

use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::BytesMut;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, StatusCode};

use dragonfly_client_request::errors::{BackendError, DfdaemonError, Error, ProxyError};
use dragonfly_client_request::{GetRequest, GetResponse, Proxy, Request as _};

use nydus_config::DragonflyConfig;

use super::response::Response;
use super::rt::Runtime;
use super::{BlobTransport, RegistryError, RegistryResult};
use crate::{Protocol, ReadKind};

/// The priority hint for background prefetch requests.
const PRIORITY_PREFETCH: i32 = 3;

/// The priority hint for on-demand (foreground) requests.
const PRIORITY_ONDEMAND: i32 = 6;

/// Returns the Dragonfly priority of a read kind.
fn priority(kind: ReadKind) -> i32 {
    match kind {
        ReadKind::Prefetch => PRIORITY_PREFETCH,
        ReadKind::OnDemand => PRIORITY_ONDEMAND,
    }
}

/// The Dragonfly SDK transport, one client per read kind so each kind keeps
/// its own retry budget.
pub(crate) struct Dragonfly {
    /// The client serving on-demand reads, retrying at once because a FUSE
    /// reader is waiting, a `429` included since another seed peer may not be
    /// rate limited.
    ondemand: Proxy,

    /// The client serving prefetch reads, never retrying: a failed prefetch
    /// is rescheduled hours later instead.
    prefetch: Proxy,

    /// The per-attempt timeout.
    timeout: Duration,
}

/// Implements the Dragonfly transport.
impl Dragonfly {
    /// Creates the transport, connecting to the configured scheduler on
    /// `runtime`.
    ///
    /// Only the on-demand client retries, `max_retries` times across seed
    /// peers.
    pub(crate) fn new(config: &DragonflyConfig, runtime: &Runtime) -> io::Result<Dragonfly> {
        let max_retries = u8::try_from(config.max_retries).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "dragonfly.max_retries {} exceeds the SDK limit",
                    config.max_retries
                ),
            )
        })?;
        let endpoint = config.scheduler_endpoint.clone();
        let (ondemand, prefetch) = runtime
            .block_on_worker(async move {
                let ondemand = Proxy::builder()
                    .scheduler_endpoint(endpoint.clone())
                    .max_retries(max_retries)
                    .build()
                    .await?;
                let prefetch = Proxy::builder()
                    .scheduler_endpoint(endpoint)
                    .max_retries(0)
                    .build()
                    .await?;
                Ok::<_, Error>((ondemand, prefetch))
            })?
            .map_err(|err| io::Error::other(format!("failed to build dragonfly client: {err}")))?;

        Ok(Dragonfly {
            ondemand,
            prefetch,
            timeout: config.timeout,
        })
    }

    /// Returns the client serving reads of `kind`.
    fn client(&self, kind: ReadKind) -> &Proxy {
        match kind {
            ReadKind::OnDemand => &self.ondemand,
            ReadKind::Prefetch => &self.prefetch,
        }
    }
}

/// Converts an SDK outcome into a transport outcome.
///
/// A success carries the buffered `body`. A proxy, backend or dfdaemon error
/// carrying an HTTP status is an answer, rebuilt as a [`Response`] with its
/// status, headers and message, so a `429`, `403` or a dfdaemon `422` reaches
/// the policy the same way an origin answer does. Anything else, a request
/// timeout, seed peer connectivity, a failed body stream, is a transport
/// failure.
fn into_response(result: Result<GetResponse, Error>, body: BytesMut) -> RegistryResult<Response> {
    match result {
        Ok(response) => Ok(Response {
            status: response.status_code.unwrap_or(StatusCode::OK),
            headers: response.header,
            reader: Box::new(std::io::Cursor::new(body.freeze())),
            protocol: Protocol::Dragonfly,
        }),
        Err(Error::ProxyError(ProxyError {
            status_code: Some(status),
            header,
            message,
        }))
        | Err(Error::BackendError(BackendError {
            status_code: Some(status),
            header,
            message,
        }))
        | Err(Error::DfdaemonError(DfdaemonError {
            status_code: Some(status),
            header,
            message,
        })) => Ok(Response {
            status,
            headers: header_map(header),
            reader: Box::new(std::io::Cursor::new(
                message.unwrap_or_default().into_bytes(),
            )),
            protocol: Protocol::Dragonfly,
        }),
        Err(Error::RequestTimeout(message)) => Err(RegistryError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("dragonfly request timed out: {message}"),
        ))),
        Err(err) => Err(RegistryError::Io(io::Error::other(format!(
            "dragonfly error: {err}"
        )))),
    }
}

/// Rebuilds a header map from the SDK's string map, dropping entries that are
/// not valid HTTP headers.
fn header_map(headers: HashMap<String, String>) -> HeaderMap {
    headers
        .into_iter()
        .filter_map(|(name, value)| {
            Some((
                HeaderName::from_bytes(name.as_bytes()).ok()?,
                HeaderValue::from_str(&value).ok()?,
            ))
        })
        .collect()
}

/// Implements the blob transport over the Dragonfly SDK.
#[async_trait]
impl BlobTransport for Dragonfly {
    /// Fetches `url` through the client of the read kind with its priority
    /// hint, the SDK adding the P2P and priority headers itself, and logs the
    /// outcome.
    async fn get(&self, url: &str, headers: HeaderMap, kind: ReadKind) -> RegistryResult<Response> {
        let request = GetRequest {
            url: url.to_string(),
            header: headers.clone(),
            filtered_query_params: Vec::new(),
            priority: Some(priority(kind)),
            timeout: self.timeout,
            ..Default::default()
        };
        let start = Instant::now();
        let mut body = BytesMut::new();
        let result = self.client(kind).get_into(&request, &mut body).await;
        let result = into_response(result, body);
        Response::log(
            &result,
            "dragonfly_sdk",
            &Method::GET,
            url,
            &headers,
            kind,
            start.elapsed(),
        );
        result
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::*;

    fn proxy_error(status_code: Option<StatusCode>) -> Error {
        Error::ProxyError(ProxyError {
            message: Some("proxy".to_string()),
            header: HashMap::new(),
            status_code,
        })
    }

    fn dfdaemon_error(status_code: Option<StatusCode>, message: &str) -> Error {
        Error::DfdaemonError(DfdaemonError {
            message: Some(message.to_string()),
            header: HashMap::new(),
            status_code,
        })
    }

    fn ok_response(status_code: StatusCode) -> GetResponse {
        GetResponse {
            success: status_code.is_success(),
            header: HeaderMap::new(),
            status_code: Some(status_code),
            body: None,
        }
    }

    #[tokio::test]
    async fn into_response_rebuilds_answers_that_carry_a_status() {
        let test_cases: Vec<(
            Result<GetResponse, Error>,
            BytesMut,
            StatusCode,
            &str,
            Option<(&str, &str)>,
        )> = vec![
            (
                Ok(ok_response(StatusCode::PARTIAL_CONTENT)),
                BytesMut::from(&b"payload"[..]),
                StatusCode::PARTIAL_CONTENT,
                "payload",
                None,
            ),
            (
                Err(proxy_error(Some(StatusCode::TOO_MANY_REQUESTS))),
                BytesMut::new(),
                StatusCode::TOO_MANY_REQUESTS,
                "proxy",
                None,
            ),
            (
                Err(proxy_error(Some(StatusCode::BAD_GATEWAY))),
                BytesMut::new(),
                StatusCode::BAD_GATEWAY,
                "proxy",
                None,
            ),
            (
                Err(Error::BackendError(BackendError {
                    message: Some("origin said no".to_string()),
                    header: HashMap::from([("x-served-by".to_string(), "origin".to_string())]),
                    status_code: Some(StatusCode::FORBIDDEN),
                })),
                BytesMut::new(),
                StatusCode::FORBIDDEN,
                "origin said no",
                Some(("x-served-by", "origin")),
            ),
            (
                Err(dfdaemon_error(
                    Some(StatusCode::INTERNAL_SERVER_ERROR),
                    "no space",
                )),
                BytesMut::new(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "no space",
                None,
            ),
            (
                Err(dfdaemon_error(
                    Some(StatusCode::INSUFFICIENT_STORAGE),
                    "no space",
                )),
                BytesMut::new(),
                StatusCode::INSUFFICIENT_STORAGE,
                "no space",
                None,
            ),
            (
                Err(dfdaemon_error(
                    Some(StatusCode::UNPROCESSABLE_ENTITY),
                    "no space",
                )),
                BytesMut::new(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "no space",
                None,
            ),
        ];

        for (result, body, status, text, header) in test_cases {
            let response = into_response(result, body).unwrap();
            assert_eq!(response.status, status);
            assert_eq!(response.protocol, Protocol::Dragonfly);
            if let Some((name, value)) = header {
                assert_eq!(response.headers.get(name).unwrap(), value);
            }
            assert_eq!(response.text().await.unwrap(), text, "status={status}");
        }
    }

    #[test]
    fn into_response_turns_failures_without_a_status_into_transport_errors() {
        let test_cases = vec![
            (
                Error::RequestTimeout("deadline exceeded".to_string()),
                io::ErrorKind::TimedOut,
            ),
            (proxy_error(None), io::ErrorKind::Other),
            (
                dfdaemon_error(None, "connection refused"),
                io::ErrorKind::Other,
            ),
            (
                Error::Internal("failed to read response body".to_string()),
                io::ErrorKind::Other,
            ),
        ];

        for (err, kind) in test_cases {
            assert!(matches!(
                into_response(Err(err), BytesMut::new()),
                Err(RegistryError::Io(io_err)) if io_err.kind() == kind
            ));
        }
    }

    #[test]
    fn header_map_drops_invalid_entries() {
        let headers = header_map(HashMap::from([
            ("content-length".to_string(), "4".to_string()),
            ("bad header".to_string(), "x".to_string()),
            ("x-ok".to_string(), "bad\nvalue".to_string()),
        ]));
        assert_eq!(headers.len(), 1);
        assert_eq!(headers.get("content-length").unwrap(), "4");
    }
}
