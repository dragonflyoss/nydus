//! The answer a transport hands back and the helpers that consume it.

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
    /// Reads the body into `buf`, returning how many bytes were filled.
    pub(crate) async fn read_into(mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut filled = 0usize;
        while filled < buf.len() {
            let n = self.reader.read(&mut buf[filled..]).await?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        Ok(filled)
    }

    /// Reads the body as a UTF-8 string.
    pub(crate) async fn text(mut self) -> io::Result<String> {
        let mut body = String::new();
        self.reader.read_to_string(&mut body).await?;
        Ok(body)
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
}

/// Reads the body so it exactly fills `dst` and returns the protocol that
/// served it, a short body being an [`io::ErrorKind::UnexpectedEof`].
pub(crate) async fn fill_exact(response: Response, dst: &mut [u8]) -> RegistryResult<Protocol> {
    let protocol = response.protocol;
    let n = response.read_into(dst).await.map_err(RegistryError::Io)?;
    if n != dst.len() {
        return Err(RegistryError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("registry returned {} bytes, expected {}", n, dst.len()),
        )));
    }
    Ok(protocol)
}

/// Turns a non-success response into [`RegistryError::UnexpectedStatus`],
/// consuming the body as the message.
pub(crate) async fn status_error(response: Response) -> RegistryError {
    let status = response.status;
    let body = response.text().await.unwrap_or_default();
    RegistryError::UnexpectedStatus(status, body)
}

/// Logs a completed request at debug level.
///
/// The line carries the read kind, the transport, the method, URL and request
/// headers, then the status and headers of the answer or the error, and how
/// long it took. The transport labels `none` and `dragonfly_sdk` are read by
/// log consumers and must not change.
pub(crate) fn log_request_done(
    transport: &'static str,
    method: &Method,
    url: &str,
    headers: &HeaderMap,
    kind: ReadKind,
    result: &RegistryResult<Response>,
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
        "backend request done: read_kind={read_kind} transport={transport} method={method} url={url} headers={headers:?} status={status:?} response_headers={response_headers:?} error={error:?} duration={}",
        format_duration(duration),
    );
}

/// Formats a duration in the largest unit that keeps three decimals readable.
fn format_duration(d: Duration) -> String {
    let nanos = d.as_nanos();
    if nanos < 1_000 {
        format!("{nanos}ns")
    } else if nanos < 1_000_000 {
        format!("{:.3}µs", nanos as f64 / 1_000.0)
    } else if nanos < 1_000_000_000 {
        format!("{:.3}ms", nanos as f64 / 1_000_000.0)
    } else {
        format!("{:.3}s", d.as_secs_f64())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::*;

    fn response(status: StatusCode, body: &[u8]) -> Response {
        Response {
            status,
            headers: HeaderMap::new(),
            reader: Box::new(std::io::Cursor::new(body.to_vec())),
            protocol: Protocol::Http,
        }
    }

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
            assert_eq!(response(status, b"").is_transient(), expected, "{status}");
        }
    }

    #[tokio::test]
    async fn fill_exact_fills_the_buffer_or_rejects_a_short_body() {
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
            let mut dst = [0u8; 4];
            let result = fill_exact(response(StatusCode::OK, body), &mut dst).await;
            assert_fn(result, &dst);
        }
    }

    #[tokio::test]
    async fn status_error_carries_the_status_and_body() {
        let err = status_error(response(StatusCode::NOT_FOUND, b"no such blob")).await;
        assert!(matches!(
            err,
            RegistryError::UnexpectedStatus(StatusCode::NOT_FOUND, body) if body == "no such blob"
        ));
    }

    #[test]
    fn format_duration_picks_the_unit() {
        let test_cases = vec![
            (Duration::from_nanos(999), "999ns"),
            (Duration::from_micros(1500), "1.500ms"),
            (Duration::from_millis(2), "2.000ms"),
            (Duration::from_secs(3), "3.000s"),
        ];

        for (duration, expected) in test_cases {
            assert_eq!(format_duration(duration), expected);
        }
    }
}
