//! The answer a transport hands back.

use std::io;
use std::time::Duration;

use reqwest::header::{HeaderMap, CONTENT_LENGTH, LOCATION};
use reqwest::{Method, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::debug;

use super::{RegistryError, RegistryResult};
use crate::{Protocol, ReadKind};

/// A response from the origin registry or a Dragonfly seed peer: the status
/// and headers up front, plus the body as an async reader.
///
/// Origin bodies stream, Dragonfly bodies are already buffered by the SDK.
pub(crate) struct Response {
    /// The HTTP status.
    pub(crate) status: StatusCode,

    /// The response headers.
    pub(crate) headers: HeaderMap,

    /// The body, streamed from the origin or buffered by the Dragonfly SDK.
    pub(crate) reader: Box<dyn AsyncRead + Send + Unpin>,

    /// How the answer was fetched: the origin over HTTP, or Dragonfly.
    pub(crate) protocol: Protocol,
}

/// Implements the response.
impl Response {
    /// Reads the body so it exactly fills `dst` and returns the protocol that
    /// served it, a short body being an [`io::ErrorKind::UnexpectedEof`].
    pub(crate) async fn read_exact(mut self, dst: &mut [u8]) -> RegistryResult<Protocol> {
        self.reader
            .read_exact(dst)
            .await
            .map_err(RegistryError::Io)?;
        Ok(self.protocol)
    }

    /// Reads the body as a UTF-8 string.
    pub(crate) async fn text(mut self) -> io::Result<String> {
        let mut body = String::new();
        self.reader.read_to_string(&mut body).await?;
        Ok(body)
    }

    /// Consumes a non-success response into the error carrying its status and
    /// body.
    pub(crate) async fn into_error(self) -> RegistryError {
        let status = self.status;
        let body = self.text().await.unwrap_or_default();
        RegistryError::UnexpectedStatus(status, body)
    }

    /// Returns whether the status is one another attempt might change: `429`,
    /// `5xx` and `408`. Every other status is definitive.
    pub(crate) fn is_transient(&self) -> bool {
        self.status.is_server_error()
            || self.status == StatusCode::REQUEST_TIMEOUT
            || self.status == StatusCode::TOO_MANY_REQUESTS
    }

    /// Returns the `Location` a redirect points at.
    pub(crate) fn location(&self) -> RegistryResult<String> {
        self.headers
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| {
                RegistryError::UnexpectedResponse("missing redirect location".to_string())
            })
    }

    /// Returns the `Content-Length` a `HEAD` answered with.
    pub(crate) fn content_length(&self) -> RegistryResult<u64> {
        self.headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| {
                RegistryError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "registry HEAD response missing a valid content-length",
                ))
            })
    }

    /// Logs a completed request at debug level.
    ///
    /// The line carries the read kind, the transport, the method, URL and
    /// request headers, then the status and headers of the answer or the
    /// error, and how long it took. The transport labels `none` and
    /// `dragonfly_sdk` are read by log consumers and must not change.
    pub(crate) fn log(
        result: &RegistryResult<Self>,
        transport: &'static str,
        method: &Method,
        url: &str,
        headers: &HeaderMap,
        kind: ReadKind,
        duration: Duration,
    ) {
        let read_kind = match kind {
            ReadKind::OnDemand => "ondemand",
            ReadKind::Prefetch => "prefetch",
        };
        let (status, response_headers, error) = match result {
            Ok(response) => (Some(response.status), Some(&response.headers), None),
            Err(err) => (None, None, Some(err.to_string())),
        };
        debug!(
            "backend request done: read_kind={read_kind} transport={transport} method={method} url={url} headers={headers:?} status={status:?} response_headers={response_headers:?} error={error:?} duration={duration:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::*;

    #[test]
    fn is_transient_marks_the_statuses_another_attempt_might_change() {
        let test_cases = vec![
            (StatusCode::INTERNAL_SERVER_ERROR, true),
            (StatusCode::BAD_GATEWAY, true),
            (StatusCode::SERVICE_UNAVAILABLE, true),
            (StatusCode::INSUFFICIENT_STORAGE, true),
            (StatusCode::REQUEST_TIMEOUT, true),
            (StatusCode::TOO_MANY_REQUESTS, true),
            (StatusCode::OK, false),
            (StatusCode::PARTIAL_CONTENT, false),
            (StatusCode::TEMPORARY_REDIRECT, false),
            (StatusCode::UNAUTHORIZED, false),
            (StatusCode::FORBIDDEN, false),
            (StatusCode::NOT_FOUND, false),
            (StatusCode::UNPROCESSABLE_ENTITY, false),
        ];

        for (status, expected) in test_cases {
            let response = Response {
                status,
                headers: HeaderMap::new(),
                reader: Box::new(io::Cursor::new(Vec::new())),
                protocol: Protocol::Http,
            };
            assert_eq!(response.is_transient(), expected, "{status}");
        }
    }

    #[tokio::test]
    async fn read_exact_fills_the_buffer_or_rejects_a_short_body() {
        let test_cases: Vec<(&[u8], fn(RegistryResult<Protocol>, &[u8; 4]))> = vec![
            (b"abcd", |result, dst| {
                assert_eq!(result.unwrap(), Protocol::Http);
                assert_eq!(dst, b"abcd");
            }),
            (b"ab", |result, _| {
                assert!(matches!(
                    result,
                    Err(RegistryError::Io(err)) if err.kind() == io::ErrorKind::UnexpectedEof
                ));
            }),
        ];

        for (body, assert_fn) in test_cases {
            let response = Response {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                reader: Box::new(io::Cursor::new(body.to_vec())),
                protocol: Protocol::Http,
            };
            let mut dst = [0u8; 4];
            let result = response.read_exact(&mut dst).await;
            assert_fn(result, &dst);
        }
    }

    #[tokio::test]
    async fn into_error_carries_the_status_and_body() {
        let response = Response {
            status: StatusCode::NOT_FOUND,
            headers: HeaderMap::new(),
            reader: Box::new(io::Cursor::new(b"no such blob".to_vec())),
            protocol: Protocol::Http,
        };
        assert!(matches!(
            response.into_error().await,
            RegistryError::UnexpectedStatus(StatusCode::NOT_FOUND, body) if body == "no such blob"
        ));
    }
}
