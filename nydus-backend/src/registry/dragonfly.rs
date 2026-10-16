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

use std::io;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::BytesMut;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::StatusCode;
use tracing::debug;

use dragonfly_api::common::v2::Priority;
use dragonfly_client_request::errors::{BackendError, DfdaemonError, Error, ProxyError};
use dragonfly_client_request::{GetRequest, GetResponse, Proxy, Request as _};

use nydus_config::DragonflyConfig;

use super::response::{Body, Response};
use super::rt::Runtime;
use super::Transport;
use crate::{Protocol, ReadKind};

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

    /// The timeout of each attempt of a request.
    request_timeout: Duration,
}

/// Implements the Dragonfly transport.
impl Dragonfly {
    /// Creates the transport, each client connecting to the configured
    /// scheduler on the runtime of its read kind.
    ///
    /// Only the on-demand client retries, `max_retries` times across seed
    /// peers.
    pub(crate) fn new(config: DragonflyConfig, runtime: &Runtime) -> io::Result<Self> {
        Ok(Self {
            ondemand: Self::client(
                runtime,
                ReadKind::OnDemand,
                config.scheduler_endpoint.clone(),
                config.max_retries as u8,
            )?,
            prefetch: Self::client(runtime, ReadKind::Prefetch, config.scheduler_endpoint, 0)?,
            request_timeout: config.request_timeout,
        })
    }

    /// Creates the client of reads of `kind`, connected to the scheduler at
    /// `scheduler_endpoint` on that kind's runtime so it is reached from the
    /// runtime's netns, retrying a request `max_retries` times across seed
    /// peers.
    fn client(
        runtime: &Runtime,
        kind: ReadKind,
        scheduler_endpoint: String,
        max_retries: u8,
    ) -> io::Result<Proxy> {
        runtime
            .block_on_worker(kind, async move {
                Proxy::builder()
                    .scheduler_endpoint(scheduler_endpoint)
                    .max_retries(max_retries)
                    .build()
                    .await
            })?
            .map_err(|err| io::Error::other(format!("failed to build dragonfly client: {err}")))
    }

    /// Converts the SDK's answer into a transport response.
    ///
    /// A success carries the buffered `body`. A proxy, backend or dfdaemon
    /// error carrying an HTTP status is an answer, rebuilt as a [`Response`]
    /// with its status, headers and message, so a `429`, `403` or a dfdaemon
    /// `422` reaches the policy the same way an origin answer does. Anything
    /// else, a request timeout, seed peer connectivity, a failed body stream,
    /// is a transport failure.
    fn response(result: Result<GetResponse, Error>, body: BytesMut) -> io::Result<Response> {
        match result {
            Ok(response) => Ok(Response {
                status: response.status_code.unwrap_or(StatusCode::OK),
                headers: response.header,
                body: Body::Bytes(body.freeze()),
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
                headers: header
                    .into_iter()
                    .filter_map(|(name, value)| {
                        Some((
                            HeaderName::from_bytes(name.as_bytes()).ok()?,
                            HeaderValue::from_str(&value).ok()?,
                        ))
                    })
                    .collect(),
                body: Body::Bytes(message.unwrap_or_default().into()),
                protocol: Protocol::Dragonfly,
            }),
            Err(Error::RequestTimeout(message)) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("dragonfly request timed out: {message}"),
            )),
            Err(err) => Err(io::Error::other(format!("dragonfly error: {err}"))),
        }
    }
}

/// Implements the blob transport over the Dragonfly SDK.
#[async_trait]
impl Transport for Dragonfly {
    /// Fetches `url` through the client of the read kind at its scheduling
    /// priority, the SDK adding the P2P and priority headers itself, and
    /// logs the outcome.
    ///
    /// An on-demand read a FUSE reader waits on goes at `Level6`, the SDK's
    /// default, a background prefetch at `Level3` so a first download lets a
    /// normal peer go back to source ahead of it.
    async fn get(&self, url: &str, headers: HeaderMap, kind: ReadKind) -> io::Result<Response> {
        let (client, priority) = match kind {
            ReadKind::OnDemand => (&self.ondemand, Priority::Level6),
            ReadKind::Prefetch => (&self.prefetch, Priority::Level3),
        };
        let request = GetRequest {
            url: url.to_string(),
            header: headers,
            priority: Some(priority as i32),
            timeout: self.request_timeout,
            ..Default::default()
        };

        let start = Instant::now();
        let mut body = BytesMut::new();
        let result = Self::response(client.get_into(&request, &mut body).await, body);

        match &result {
            Ok(response) => debug!(
                "GET {url} ({kind}) through dragonfly returned {} in {:?}",
                response.status,
                start.elapsed()
            ),
            Err(err) => debug!(
                "GET {url} ({kind}) through dragonfly failed in {:?}: {err}",
                start.elapsed()
            ),
        }
        result
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn response_rebuilds_answers_that_carry_a_status() {
        let test_cases: Vec<(
            Result<GetResponse, Error>,
            &[u8],
            StatusCode,
            &str,
            Vec<(&str, &str)>,
        )> = vec![
            (
                Ok(GetResponse {
                    success: true,
                    header: HeaderMap::new(),
                    status_code: Some(StatusCode::PARTIAL_CONTENT),
                    body: None,
                }),
                b"payload",
                StatusCode::PARTIAL_CONTENT,
                "payload",
                vec![],
            ),
            (
                Err(Error::ProxyError(ProxyError {
                    message: Some("proxy".to_string()),
                    header: HashMap::new(),
                    status_code: Some(StatusCode::TOO_MANY_REQUESTS),
                })),
                b"",
                StatusCode::TOO_MANY_REQUESTS,
                "proxy",
                vec![],
            ),
            (
                Err(Error::ProxyError(ProxyError {
                    message: Some("proxy".to_string()),
                    header: HashMap::new(),
                    status_code: Some(StatusCode::BAD_GATEWAY),
                })),
                b"",
                StatusCode::BAD_GATEWAY,
                "proxy",
                vec![],
            ),
            (
                Err(Error::BackendError(BackendError {
                    message: Some("origin said no".to_string()),
                    header: HashMap::from([
                        ("x-served-by".to_string(), "origin".to_string()),
                        ("bad header".to_string(), "x".to_string()),
                        ("x-bad-value".to_string(), "bad\nvalue".to_string()),
                    ]),
                    status_code: Some(StatusCode::FORBIDDEN),
                })),
                b"",
                StatusCode::FORBIDDEN,
                "origin said no",
                vec![("x-served-by", "origin")],
            ),
            (
                Err(Error::DfdaemonError(DfdaemonError {
                    message: Some("no space".to_string()),
                    header: HashMap::new(),
                    status_code: Some(StatusCode::INTERNAL_SERVER_ERROR),
                })),
                b"",
                StatusCode::INTERNAL_SERVER_ERROR,
                "no space",
                vec![],
            ),
            (
                Err(Error::DfdaemonError(DfdaemonError {
                    message: Some("no space".to_string()),
                    header: HashMap::new(),
                    status_code: Some(StatusCode::INSUFFICIENT_STORAGE),
                })),
                b"",
                StatusCode::INSUFFICIENT_STORAGE,
                "no space",
                vec![],
            ),
            (
                Err(Error::DfdaemonError(DfdaemonError {
                    message: Some("no space".to_string()),
                    header: HashMap::new(),
                    status_code: Some(StatusCode::UNPROCESSABLE_ENTITY),
                })),
                b"",
                StatusCode::UNPROCESSABLE_ENTITY,
                "no space",
                vec![],
            ),
        ];

        for (result, body, status, text, headers) in test_cases {
            let response = Dragonfly::response(result, BytesMut::from(body)).unwrap();
            assert_eq!(response.status, status);
            assert_eq!(response.protocol, Protocol::Dragonfly);
            assert_eq!(response.headers.len(), headers.len(), "status={status}");
            for (name, value) in headers {
                assert_eq!(response.headers.get(name).unwrap(), value);
            }
            assert_eq!(response.text().await.unwrap(), text, "status={status}");
        }
    }

    #[test]
    fn response_turns_failures_without_a_status_into_transport_errors() {
        let test_cases = vec![
            (
                Error::RequestTimeout("deadline exceeded".to_string()),
                io::ErrorKind::TimedOut,
            ),
            (
                Error::ProxyError(ProxyError {
                    message: Some("proxy".to_string()),
                    header: HashMap::new(),
                    status_code: None,
                }),
                io::ErrorKind::Other,
            ),
            (
                Error::DfdaemonError(DfdaemonError {
                    message: Some("connection refused".to_string()),
                    header: HashMap::new(),
                    status_code: None,
                }),
                io::ErrorKind::Other,
            ),
            (
                Error::Internal("failed to read response body".to_string()),
                io::ErrorKind::Other,
            ),
        ];

        for (err, kind) in test_cases {
            assert!(matches!(
                Dragonfly::response(Err(err), BytesMut::new()),
                Err(err) if err.kind() == kind
            ));
        }
    }
}
