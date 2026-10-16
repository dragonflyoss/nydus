//! The answer a transport hands back.

use std::io;

use bytes::{Bytes, BytesMut};
use reqwest::header::{HeaderMap, CONTENT_LENGTH, LOCATION};
use reqwest::StatusCode;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::Protocol;

/// A response from the origin registry or a Dragonfly seed peer: the status
/// and headers up front, plus the body still streaming.
pub(crate) struct Response {
    /// The HTTP status.
    pub(crate) status: StatusCode,

    /// The response headers.
    pub(crate) headers: HeaderMap,

    /// The body, streamed from the origin or a seed peer.
    pub(crate) body: Box<dyn AsyncRead + Send + Unpin>,

    /// How the answer was fetched: the origin over HTTP, or Dragonfly.
    pub(crate) protocol: Protocol,
}

/// Implements the response.
impl Response {
    /// Reads exactly `len` bytes of the body, a shorter body being an
    /// [`io::ErrorKind::UnexpectedEof`].
    pub(crate) async fn bytes(mut self, len: usize) -> io::Result<Bytes> {
        let mut buf = BytesMut::zeroed(len);
        self.body.read_exact(&mut buf).await?;
        Ok(buf.freeze())
    }

    /// Reads the body as a UTF-8 string.
    pub(crate) async fn text(mut self) -> io::Result<String> {
        let mut body = String::new();
        self.body.read_to_string(&mut body).await?;
        Ok(body)
    }

    /// Consumes a response of a status the request did not expect into an
    /// error naming the status, the body as the rest of the message.
    ///
    /// The status is the error, so a body that cannot be read only blanks
    /// the message.
    pub(crate) async fn into_io_error(self) -> io::Error {
        let status = self.status;
        let body = self.text().await.unwrap_or_default();
        io::Error::other(format!("unexpected status {status}: {body}"))
    }

    /// Returns whether another attempt might get a different answer: a `429`,
    /// `5xx` or `408`. Every other status is definitive.
    pub(crate) fn is_retryable(&self) -> bool {
        self.status.is_server_error()
            || self.status == StatusCode::REQUEST_TIMEOUT
            || self.status == StatusCode::TOO_MANY_REQUESTS
    }

    /// Returns the `Location` a redirect points at.
    pub(crate) fn location(&self) -> io::Result<String> {
        self.headers
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "registry redirect missing a valid location",
                )
            })
    }

    /// Returns the `Content-Length` a `HEAD` answered with.
    pub(crate) fn content_length(&self) -> io::Result<u64> {
        self.headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "registry HEAD response missing a valid content-length",
                )
            })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::*;

    #[test]
    fn is_retryable_marks_the_statuses_another_attempt_might_change() {
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
                body: Box::new(io::Cursor::new(Vec::new())),
                protocol: Protocol::Http,
            };
            assert_eq!(response.is_retryable(), expected, "{status}");
        }
    }

    #[tokio::test]
    async fn bytes_reads_exactly_len_or_rejects_a_short_body() {
        let test_cases: Vec<(&[u8], fn(io::Result<Bytes>))> = vec![
            (b"abcd", |result| assert_eq!(result.unwrap(), "abcd")),
            (b"abcdef", |result| assert_eq!(result.unwrap(), "abcd")),
            (b"ab", |result| {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
            }),
        ];

        for (body, assert_fn) in test_cases {
            let response = Response {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: Box::new(io::Cursor::new(body.to_vec())),
                protocol: Protocol::Http,
            };
            assert_fn(response.bytes(4).await);
        }
    }

    #[tokio::test]
    async fn into_io_error_names_the_status_and_carries_the_body() {
        let response = Response {
            status: StatusCode::NOT_FOUND,
            headers: HeaderMap::new(),
            body: Box::new(io::Cursor::new(b"no such blob".to_vec())),
            protocol: Protocol::Http,
        };
        assert_eq!(
            response.into_io_error().await.to_string(),
            "unexpected status 404 Not Found: no such blob"
        );
    }
}
