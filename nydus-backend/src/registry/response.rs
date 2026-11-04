//! The answer a transport hands back.

use std::io;

use bytes::{Bytes, BytesMut};
use reqwest::header::{HeaderMap, CONTENT_RANGE, LOCATION};
use reqwest::StatusCode;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::range::{ContentRange, GetRange};
use crate::Source;

/// A response from the origin registry or a Dragonfly seed peer: the status
/// and headers up front, plus the body.
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

    /// A body already in memory: the one the Dragonfly SDK read whole, so a
    /// seed peer failing mid-body was retried before the answer got here.
    #[cfg_attr(not(feature = "dragonfly"), allow(dead_code))]
    Bytes(Bytes),
}

/// Implements the response.
impl Response {
    /// Turns the answer to a `range` read into an error unless it carries
    /// exactly that range: a `206` whose `Content-Range` names it, and a body
    /// already in memory as long as it (RFC 9110 §15.3.7). A `206` without a
    /// `Content-Range` is taken as the range it answers.
    ///
    /// Dragonfly 1.3 answers a partial download with a `200` and the exact
    /// `Content-Range`, so a seed peer's `200` goes through the same checks;
    /// an origin's `200` is the whole blob and never does.
    pub(crate) fn error_for_range(self, range: &GetRange) -> io::Result<Self> {
        match (self.status, self.source) {
            (StatusCode::PARTIAL_CONTENT, _) if !self.headers.contains_key(CONTENT_RANGE) => {
                return Ok(self);
            }
            (StatusCode::PARTIAL_CONTENT, _) | (StatusCode::OK, Source::Dragonfly) => {}
            (status, _) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "registry range request returned {status}, expected 206 Partial Content"
                    ),
                ));
            }
        }

        let content_range = self.content_range()?;
        let expected = range.to_range(content_range.complete_length);
        if content_range.range != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "registry returned bytes {:?}, expected {expected:?}",
                    content_range.range
                ),
            ));
        }

        let length = expected.end() - expected.start() + 1;
        if let Body::Bytes(bytes) = &self.body {
            if bytes.len() as u64 != length {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("registry returned {} bytes, expected {length}", bytes.len()),
                ));
            }
        }

        Ok(self)
    }

    /// Reads exactly `length` bytes of the body, a shorter body being an
    /// [`io::ErrorKind::UnexpectedEof`]. A body already in memory is handed
    /// over without a copy.
    pub(crate) async fn bytes(self, length: usize) -> io::Result<Bytes> {
        let bytes = match self.body {
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
        let bytes = match self.body {
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

    /// Returns whether an on-demand read falls back to the origin: the seed
    /// peers failed to serve it with a `429`, `5xx` or `408`. Every other
    /// status is the registry's definitive answer.
    #[cfg_attr(not(feature = "dragonfly"), allow(dead_code))]
    pub(crate) fn needs_fallback(&self) -> bool {
        self.status.is_server_error()
            || self.status == StatusCode::REQUEST_TIMEOUT
            || self.status == StatusCode::TOO_MANY_REQUESTS
    }

    /// Returns whether a prefetch read is sent once more hours later: the
    /// transport failed to serve it with a `429`, `5xx` or `408`. Every other
    /// status is the registry's definitive answer.
    pub(crate) fn needs_retry(&self) -> bool {
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

    /// Returns the byte range the answer names in its `Content-Range`.
    pub(crate) fn content_range(&self) -> io::Result<ContentRange> {
        self.headers
            .get(CONTENT_RANGE)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "registry range response missing a valid content-range",
                )
            })?
            .parse()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::*;

    #[test]
    fn error_for_range_accepts_a_206_or_a_dragonfly_200() {
        let test_cases = vec![
            (StatusCode::PARTIAL_CONTENT, Source::Origin, true),
            (StatusCode::PARTIAL_CONTENT, Source::Dragonfly, true),
            (StatusCode::OK, Source::Dragonfly, true),
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
                body: Body::Bytes(Bytes::from_static(b"abcd")),
                source,
            };
            assert_eq!(
                response.error_for_range(&GetRange::Bounded(2..=5)).is_ok(),
                expected,
                "{status} {source:?}"
            );
        }
    }

    #[test]
    fn error_for_range_requires_the_content_range_to_name_the_range() {
        let test_cases = vec![
            (StatusCode::PARTIAL_CONTENT, Some("bytes 2-5/8"), true),
            (StatusCode::PARTIAL_CONTENT, Some("bytes 1-4/8"), false),
            (StatusCode::PARTIAL_CONTENT, Some("bytes 2-5/*"), false),
            (StatusCode::PARTIAL_CONTENT, None, true),
            (StatusCode::OK, Some("bytes 2-5/8"), true),
            (StatusCode::OK, Some("bytes 0-7/8"), false),
            (StatusCode::OK, None, false),
        ];

        for (status, content_range, expected) in test_cases {
            let mut headers = HeaderMap::new();
            if let Some(value) = content_range {
                headers.insert(CONTENT_RANGE, value.parse().unwrap());
            }
            let response = Response {
                status,
                headers,
                body: Body::Bytes(Bytes::from_static(b"abcd")),
                source: Source::Dragonfly,
            };
            assert_eq!(
                response.error_for_range(&GetRange::Bounded(2..=5)).is_ok(),
                expected,
                "{status} {content_range:?}"
            );
        }
    }

    #[test]
    fn error_for_range_requires_a_buffered_body_as_long_as_the_range() {
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
                response.error_for_range(&GetRange::Bounded(2..=5)).is_ok(),
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
                body: Body::Bytes(Bytes::new()),
                source: Source::Origin,
            };
            assert_eq!(response.needs_fallback(), expected, "{status}");
            assert_eq!(response.needs_retry(), expected, "{status}");
        }
    }

    #[tokio::test]
    async fn bytes_reads_exactly_len_from_either_body() {
        let test_cases: Vec<(Body, fn(io::Result<Bytes>))> = vec![
            (Body::Bytes(Bytes::from_static(b"abcd")), |result| {
                assert_eq!(result.unwrap(), "abcd");
            }),
            (Body::Bytes(Bytes::from_static(b"abcdef")), |result| {
                assert_eq!(result.unwrap(), "abcd");
            }),
            (Body::Bytes(Bytes::from_static(b"ab")), |result| {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
            }),
            (
                Body::Stream(Box::new(io::Cursor::new(b"abcd".to_vec()))),
                |result| {
                    assert_eq!(result.unwrap(), "abcd");
                },
            ),
            (
                Body::Stream(Box::new(io::Cursor::new(b"abcdef".to_vec()))),
                |result| {
                    assert_eq!(result.unwrap(), "abcd");
                },
            ),
            (
                Body::Stream(Box::new(io::Cursor::new(b"ab".to_vec()))),
                |result| {
                    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
                },
            ),
        ];

        for (body, assert_fn) in test_cases {
            let response = Response {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body,
                source: Source::Origin,
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
