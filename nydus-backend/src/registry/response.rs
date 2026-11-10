//! The answer a transport hands back.

use std::io;

use bytes::{Bytes, BytesMut};
use reqwest::header::{HeaderMap, CONTENT_RANGE, LOCATION};
use reqwest::StatusCode;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::range::{ContentRange, Range};
use crate::Source;

/// A response from the origin or a Dragonfly seed peer.
pub(crate) struct Response {
    /// The HTTP status.
    pub(crate) status: StatusCode,

    /// The response headers.
    pub(crate) headers: HeaderMap,

    /// The body.
    pub(crate) body: Body,

    /// Where the answer was fetched from, the `source` label of the read.
    pub(crate) source: Source,
}

/// The body of a response.
pub(crate) enum Body {
    /// A body still streaming from the origin.
    Stream(Box<dyn AsyncRead + Send + Unpin>),

    /// A body already in memory, read whole by the Dragonfly SDK.
    #[cfg(feature = "dragonfly")]
    Bytes(Bytes),
}

/// Implements the response.
impl Response {
    /// Validates that a `206` names exactly `range` in its `Content-Range`,
    /// refer to RFC 9110 Section 15.3.7.1.
    pub(crate) fn validate_range(&self, range: &Range) -> io::Result<()> {
        if self.status != StatusCode::PARTIAL_CONTENT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "expected 206 Partial Content for range {range}, got {}",
                    self.status
                ),
            ));
        }

        let content_range = self.content_range()?;
        let expected = range.satisfiable_range(content_range.complete_length);
        if content_range.range != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Content-Range {content_range} mismatches requested range {range}"),
            ));
        }

        #[cfg(feature = "dragonfly")]
        if let Body::Bytes(bytes) = &self.body {
            if bytes.len() as u64 != expected.end() - expected.start() + 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "body of {} bytes mismatches Content-Range {content_range}",
                        bytes.len()
                    ),
                ));
            }
        }

        Ok(())
    }

    /// Reads exactly `length` bytes of the body, without a copy when in memory.
    pub(crate) async fn bytes(self, length: usize) -> io::Result<Bytes> {
        let bytes = match self.body {
            #[cfg(feature = "dragonfly")]
            Body::Bytes(bytes) => bytes,
            Body::Stream(mut reader) => {
                let mut buf = BytesMut::zeroed(length);
                reader.read_exact(&mut buf).await?;
                buf.freeze()
            }
        };

        if bytes.len() < length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("registry returned {} bytes, expected {length}", bytes.len()),
            ));
        }

        Ok(bytes.slice(..length))
    }

    /// Reads the body as a UTF-8 string.
    pub(crate) async fn text(self) -> io::Result<String> {
        let bytes: Bytes = match self.body {
            #[cfg(feature = "dragonfly")]
            Body::Bytes(bytes) => bytes,
            Body::Stream(mut reader) => {
                let mut buf = Vec::new();
                reader.read_to_end(&mut buf).await?;
                buf.into()
            }
        };

        String::from_utf8(bytes.into())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
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

    /// Returns the byte range the answer names in its `Content-Range`.
    pub(crate) fn content_range(&self) -> io::Result<ContentRange> {
        self.headers
            .get(CONTENT_RANGE)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing Content-Range"))?
            .parse()
    }

    /// Converts an unexpected response into an error of its status and body.
    pub(crate) async fn into_io_error(self) -> io::Error {
        let status = self.status;
        let body = self.text().await.unwrap_or_default();
        io::Error::other(format!("unexpected status {status}: {body}"))
    }

    /// Returns whether an on-demand read falls back to the origin, on a `429`,
    /// `5xx` or `408`.
    #[cfg(feature = "dragonfly")]
    pub(crate) fn needs_fallback(&self) -> bool {
        self.status.is_server_error()
            || self.status == StatusCode::REQUEST_TIMEOUT
            || self.status == StatusCode::TOO_MANY_REQUESTS
    }

    /// Returns whether a prefetch read is sent once more, on a `429`, `5xx` or
    /// `408`.
    pub(crate) fn needs_retry(&self) -> bool {
        self.status.is_server_error()
            || self.status == StatusCode::REQUEST_TIMEOUT
            || self.status == StatusCode::TOO_MANY_REQUESTS
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::*;

    #[test]
    fn validate_range_accepts_only_a_206() {
        let test_cases = vec![
            (StatusCode::PARTIAL_CONTENT, Source::Origin, true),
            (StatusCode::PARTIAL_CONTENT, Source::Dragonfly, true),
            (StatusCode::OK, Source::Dragonfly, false),
            (StatusCode::OK, Source::Origin, false),
            (StatusCode::OK, Source::Fallback, false),
            (StatusCode::NO_CONTENT, Source::Origin, false),
        ];

        for (status, source, expected) in test_cases {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_RANGE, "bytes 2-5/8".parse().unwrap());
            let response = Response {
                status,
                headers,
                body: Body::Stream(Box::new(io::Cursor::new(b"abcd".to_vec()))),
                source,
            };
            assert_eq!(
                response.validate_range(&Range::Bounded(2..=5)).is_ok(),
                expected
            );
        }
    }

    #[test]
    fn validate_range_requires_the_content_range_to_name_the_range() {
        let test_cases = vec![
            (Source::Origin, Some("bytes 2-5/8"), true),
            (Source::Origin, Some("bytes 1-4/8"), false),
            (Source::Origin, Some("bytes 2-5/*"), false),
            (Source::Origin, None, false),
            (Source::Dragonfly, Some("bytes 2-5/8"), true),
            (Source::Dragonfly, Some("bytes 1-4/8"), false),
            (Source::Dragonfly, None, false),
        ];

        for (source, content_range, expected) in test_cases {
            let mut headers = HeaderMap::new();
            if let Some(value) = content_range {
                headers.insert(CONTENT_RANGE, value.parse().unwrap());
            }
            let response = Response {
                status: StatusCode::PARTIAL_CONTENT,
                headers,
                body: Body::Stream(Box::new(io::Cursor::new(b"abcd".to_vec()))),
                source,
            };
            assert_eq!(
                response.validate_range(&Range::Bounded(2..=5)).is_ok(),
                expected
            );
        }
    }

    #[cfg(feature = "dragonfly")]
    #[test]
    fn validate_range_requires_a_buffered_body_as_long_as_the_range() {
        let test_cases = vec![
            (Body::Bytes(Bytes::from_static(b"abcd")), true),
            (Body::Bytes(Bytes::from_static(b"abc")), false),
            (Body::Bytes(Bytes::from_static(b"abcde")), false),
            (
                Body::Stream(Box::new(io::Cursor::new(b"abc".to_vec()))),
                true,
            ),
        ];

        for (body, expected) in test_cases {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_RANGE, "bytes 2-5/8".parse().unwrap());
            let response = Response {
                status: StatusCode::PARTIAL_CONTENT,
                headers,
                body,
                source: Source::Dragonfly,
            };
            assert_eq!(
                response.validate_range(&Range::Bounded(2..=5)).is_ok(),
                expected
            );
        }
    }

    #[test]
    fn needs_fallback_and_needs_retry_mark_the_statuses_the_transport_failed_with() {
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
                body: Body::Stream(Box::new(io::Cursor::new(Vec::new()))),
                source: Source::Origin,
            };
            #[cfg(feature = "dragonfly")]
            assert_eq!(response.needs_fallback(), expected);
            assert_eq!(response.needs_retry(), expected);
        }
    }

    #[tokio::test]
    async fn bytes_reads_exactly_len_from_a_streaming_body() {
        let test_cases: Vec<(&[u8], fn(io::Result<Bytes>))> = vec![
            (b"abcd", |result| assert_eq!(result.unwrap(), "abcd")),
            (b"abcdef", |result| assert_eq!(result.unwrap(), "abcd")),
            (b"ab", |result| {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof)
            }),
        ];

        for (body, assert_fn) in test_cases {
            let response = Response {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: Body::Stream(Box::new(io::Cursor::new(body.to_vec()))),
                source: Source::Origin,
            };
            assert_fn(response.bytes(4).await);
        }
    }

    #[cfg(feature = "dragonfly")]
    #[tokio::test]
    async fn bytes_reads_exactly_len_from_a_buffered_body() {
        let test_cases: Vec<(&'static [u8], fn(io::Result<Bytes>))> = vec![
            (b"abcd", |result| assert_eq!(result.unwrap(), "abcd")),
            (b"abcdef", |result| assert_eq!(result.unwrap(), "abcd")),
            (b"ab", |result| {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof)
            }),
        ];

        for (body, assert_fn) in test_cases {
            let response = Response {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: Body::Bytes(Bytes::from_static(body)),
                source: Source::Dragonfly,
            };
            assert_fn(response.bytes(4).await);
        }
    }

    #[tokio::test]
    async fn into_io_error_names_the_status_and_carries_the_body() {
        let response = Response {
            status: StatusCode::NOT_FOUND,
            headers: HeaderMap::new(),
            body: Body::Stream(Box::new(io::Cursor::new(b"no such blob".to_vec()))),
            source: Source::Origin,
        };
        assert_eq!(
            response.into_io_error().await.to_string(),
            "unexpected status 404 Not Found: no such blob"
        );
    }
}
