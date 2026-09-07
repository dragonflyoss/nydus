//! Dragonfly SDK transport (feature `backend-dragonfly-proxy`).
//!
//! Routes a blob `GET` through the Dragonfly client SDK using a scheduler
//! endpoint. This bypasses plain HTTP and lets Dragonfly schedule P2P piece
//! distribution directly, it is selected for blob `GET`s when a scheduler
//! endpoint is configured, while every other request goes directly to the
//! origin. The SDK owns the retries: an on-demand read retries a transient
//! failure, a `429` included, on the next seed peer up to the configured
//! budget, while a prefetch read never retries, a failed prefetch being left
//! to the storage layer's long delayed reschedule instead. An answer the SDK
//! reports as an error but that carries an HTTP status is handed back as a
//! [`Response`], so the policy in the parent module classifies it by status
//! like an origin answer.

use std::collections::HashMap;
use std::io;
use std::time::Duration;

use async_trait::async_trait;
use bytes::BytesMut;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::StatusCode;

use dragonfly_client_request::errors::{BackendError, DfdaemonError, Error, ProxyError};
use dragonfly_client_request::{GetRequest, GetResponse, Proxy, Request as _};

use nydus_config::DragonflyConfig;

use super::{runtime, DragonflyTransport, RegistryError, RegistryResult, Response};
use crate::ReadKind;

/// The priority hint for background prefetch requests.
const PRIORITY_PREFETCH: i32 = 3;

/// The priority hint for on-demand (foreground) requests.
const PRIORITY_ONDEMAND: i32 = 6;

/// Map a read kind to its Dragonfly priority value.
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

impl Dragonfly {
    /// Create a new Dragonfly transport connected to the configured scheduler.
    /// Only the on-demand client retries, `max_retries` times across seed
    /// peers.
    pub(crate) fn new(config: &DragonflyConfig) -> io::Result<Dragonfly> {
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
        let (ondemand, prefetch) = runtime()
            .block_on(async move {
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
            })
            .map_err(|err| io::Error::other(format!("failed to build dragonfly client: {err}")))?;

        Ok(Dragonfly {
            ondemand,
            prefetch,
            timeout: config.timeout,
        })
    }

    /// The client serving reads of `kind`.
    fn client(&self, kind: ReadKind) -> &Proxy {
        match kind {
            ReadKind::OnDemand => &self.ondemand,
            ReadKind::Prefetch => &self.prefetch,
        }
    }
}

/// Convert an SDK outcome into a transport outcome. A success carries the
/// buffered `body`. A proxy, backend or dfdaemon error carrying an HTTP
/// status is an answer, rebuilt as a [`Response`] with its status, headers and
/// message, so a `429`, `403` or a dfdaemon `422` reaches the policy the same
/// way an origin answer does. Anything else, a request timeout, seed peer
/// connectivity, a failed body stream, is a transport failure.
fn into_response(result: Result<GetResponse, Error>, body: BytesMut) -> RegistryResult<Response> {
    match result {
        Ok(response) => Ok(Response {
            status: response.status_code.unwrap_or(StatusCode::OK),
            headers: response.header,
            reader: Box::new(std::io::Cursor::new(body.freeze())),
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

/// Rebuild a header map from the SDK's string map, dropping entries that are
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

#[async_trait]
impl DragonflyTransport for Dragonfly {
    /// Issue a blob `GET` through the client of the read kind with its
    /// priority hint. The SDK adds the P2P and priority headers itself.
    async fn get(&self, url: &str, headers: HeaderMap, kind: ReadKind) -> RegistryResult<Response> {
        let request = GetRequest {
            url: url.to_string(),
            header: headers,
            filtered_query_params: Vec::new(),
            priority: Some(priority(kind)),
            timeout: self.timeout,
            ..Default::default()
        };
        let mut body = BytesMut::new();
        let result = self.client(kind).get_into(&request, &mut body).await;
        into_response(result, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy_error(status_code: Option<StatusCode>) -> Error {
        Error::ProxyError(ProxyError {
            message: Some("proxy".to_string()),
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

    #[test]
    fn a_success_carries_the_buffered_body() {
        let response = into_response(
            Ok(ok_response(StatusCode::PARTIAL_CONTENT)),
            BytesMut::from(&b"payload"[..]),
        )
        .unwrap();
        assert_eq!(response.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.text().unwrap(), "payload");
    }

    #[test]
    fn answers_with_a_status_become_responses() {
        let response = into_response(
            Err(proxy_error(Some(StatusCode::TOO_MANY_REQUESTS))),
            BytesMut::new(),
        )
        .unwrap();
        assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);

        let response = into_response(
            Err(Error::BackendError(BackendError {
                message: Some("origin said no".to_string()),
                header: HashMap::from([("x-served-by".to_string(), "origin".to_string())]),
                status_code: Some(StatusCode::FORBIDDEN),
            })),
            BytesMut::new(),
        )
        .unwrap();
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert_eq!(response.headers.get("x-served-by").unwrap(), "origin");
        assert_eq!(response.text().unwrap(), "origin said no");

        let response = into_response(
            Err(proxy_error(Some(StatusCode::BAD_GATEWAY))),
            BytesMut::new(),
        )
        .unwrap();
        assert_eq!(response.status, StatusCode::BAD_GATEWAY);

        for status in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::INSUFFICIENT_STORAGE,
            StatusCode::UNPROCESSABLE_ENTITY,
        ] {
            let response = into_response(
                Err(Error::DfdaemonError(DfdaemonError {
                    message: Some("no space".to_string()),
                    header: HashMap::new(),
                    status_code: Some(status),
                })),
                BytesMut::new(),
            )
            .unwrap();
            assert_eq!(response.status, status);
            assert_eq!(response.text().unwrap(), "no space");
        }
    }

    #[test]
    fn failures_without_a_status_are_transport_errors() {
        let err = into_response(
            Err(Error::RequestTimeout("deadline exceeded".to_string())),
            BytesMut::new(),
        )
        .err()
        .unwrap();
        assert!(
            matches!(&err, RegistryError::Io(io_err) if io_err.kind() == io::ErrorKind::TimedOut)
        );

        for err in [
            proxy_error(None),
            Error::DfdaemonError(DfdaemonError {
                message: Some("connection refused".to_string()),
                header: HashMap::new(),
                status_code: None,
            }),
            Error::Internal("failed to read response body".to_string()),
        ] {
            assert!(matches!(
                into_response(Err(err), BytesMut::new()),
                Err(RegistryError::Io(_))
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
