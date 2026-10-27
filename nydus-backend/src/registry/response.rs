//! The answer a transport hands back.

use std::io;

use bytes::{Bytes, BytesMut};
use reqwest::header::{HeaderMap, CONTENT_RANGE, LOCATION};
use reqwest::StatusCode;
use tokio::io::{AsyncRead, AsyncReadExt};

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
    /// Rejects a successful whole-blob answer before its bytes can be used
    /// at the requested range's offset.
    pub(crate) fn require_partial(self, range: &str) -> io::Result<Self> {
        // Dragonfly 1.3 returns 200 for a partial download but supplies the
        // exact Content-Range. Do not extend this exception to origin servers.
        if self.status == StatusCode::OK && self.source == Source::Dragonfly {
            let decimal = |value: &str| {
                if value.bytes().all(|byte| byte.is_ascii_digit()) {
                    value.parse::<u64>().ok()
                } else {
                    None
                }
            };
            if let Some((start, end, total)) = self
                .headers
                .get(CONTENT_RANGE)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("bytes "))
                .and_then(|value| {
                    let (span, total) = value.split_once('/')?;
                    let (start, end) = span.split_once('-')?;
                    Some((decimal(start)?, decimal(end)?, decimal(total)?))
                })
            {
                let requested = range.strip_prefix("bytes=").and_then(|value| {
                    let (first, last) = value.split_once('-')?;
                    if first.is_empty() {
                        let length = decimal(last)?;
                        Some((total.saturating_sub(length), total.checked_sub(1)?))
                    } else {
                        Some((decimal(first)?, decimal(last)?))
                    }
                });
                if start <= end
                    && end < total
                    && requested == Some((start, end))
                    && matches!(&self.body, Body::Bytes(bytes) if bytes.len() as u64 == end - start + 1)
                {
                    return Ok(self);
                }
            }
        }
        if self.status != StatusCode::PARTIAL_CONTENT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "registry range request returned {}, expected 206 Partial Content",
                    self.status
                ),
            ));
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

    /// Returns the complete length of the blob a `206` carries in its
    /// `Content-Range`, the `complete-length` of `bytes first-last/complete-length`.
    pub(crate) fn complete_length(&self) -> io::Result<u64> {
        self.headers
            .get(CONTENT_RANGE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.rsplit_once('/'))
            .and_then(|(_, complete_length)| complete_length.parse().ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "registry range response missing a valid content-range",
                )
            })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::*;

    #[test]
    fn require_partial_dragonfly_200_requires_an_exact_buffered_range() {
        for (range, content_range, length, accepted) in [
            ("bytes=2-5", Some("bytes 2-5/8"), 4, true),
            ("bytes=0-7", Some("bytes 0-7/8"), 8, true),
            ("bytes=-4", Some("bytes 4-7/8"), 4, true),
            ("bytes=-8", Some("bytes 0-7/8"), 8, true),
            ("bytes=-9", Some("bytes 0-7/8"), 8, true),
            ("bytes=0-0", Some("bytes 0-0/1"), 1, true),
            ("bytes=2-5", None, 4, false),
            ("bytes=2-5", Some("bytes 2-5/*"), 4, false),
            ("bytes=2-5", Some("items 2-5/8"), 4, false),
            ("bytes=2-5", Some("bytes 2/8"), 4, false),
            ("bytes=2-5", Some("bytes x-5/8"), 4, false),
            ("bytes=2-5", Some("bytes 2-x/8"), 4, false),
            ("bytes=2-5", Some("bytes 2-5/x"), 4, false),
            ("bytes=2-5", Some("bytes +2-5/8"), 4, false),
            ("bytes=2-5", Some("bytes 2-+5/8"), 4, false),
            ("bytes=2-5", Some("bytes 2-5/+8"), 4, false),
            ("bytes=+2-5", Some("bytes 2-5/8"), 4, false),
            ("bytes=2-+5", Some("bytes 2-5/8"), 4, false),
            ("bytes=-+4", Some("bytes 4-7/8"), 4, false),
            ("bytes=2-5", Some("bytes 2-5/8/9"), 4, false),
            ("bytes=2-5", Some("bytes 2-5/8 "), 4, false),
            ("bytes=2-5", Some("bytes \u{80}-5/8"), 4, false),
            ("bytes=2-5", Some("bytes 1-4/8"), 4, false),
            ("bytes=2-5", Some("bytes 5-2/8"), 4, false),
            ("bytes=2-5", Some("bytes 2-5/5"), 4, false),
            ("bytes=2-5", Some("bytes 2-5/0"), 4, false),
            ("bytes=2-5", Some("bytes 2-5/8"), 3, false),
            ("bytes=2-5", Some("bytes 2-5/8"), 5, false),
            ("bytes=2-5", Some("bytes 2-5/8"), 0, false),
            ("bytes=-0", Some("bytes 0-0/1"), 1, false),
            ("bytes=-1", Some("bytes 0-0/0"), 1, false),
            ("bytes=-x", Some("bytes 4-7/8"), 4, false),
            ("bytes=2-", Some("bytes 2-7/8"), 6, false),
            ("bytes=x-5", Some("bytes 2-5/8"), 4, false),
            ("bytes=2-x", Some("bytes 2-5/8"), 4, false),
            ("bytes=2", Some("bytes 2-5/8"), 4, false),
            ("items=2-5", Some("bytes 2-5/8"), 4, false),
            ("bytes=2-5,6-7", Some("bytes 2-5/8"), 4, false),
            ("bytes=-18446744073709551616", Some("bytes 0-7/8"), 8, false),
            (
                "bytes=18446744073709551616-5",
                Some("bytes 2-5/8"),
                4,
                false,
            ),
            (
                "bytes=2-18446744073709551616",
                Some("bytes 2-5/8"),
                4,
                false,
            ),
            (
                "bytes=2-5",
                Some("bytes 18446744073709551616-5/8"),
                4,
                false,
            ),
            (
                "bytes=2-5",
                Some("bytes 2-18446744073709551616/8"),
                4,
                false,
            ),
            (
                "bytes=2-5",
                Some("bytes 2-5/18446744073709551616"),
                4,
                false,
            ),
            (
                "bytes=0-18446744073709551615",
                Some("bytes 0-18446744073709551615/18446744073709551615"),
                0,
                false,
            ),
            (
                "bytes=-1",
                Some("bytes 18446744073709551614-18446744073709551614/18446744073709551615"),
                1,
                true,
            ),
        ] {
            for source in [Source::Dragonfly, Source::Origin] {
                for streaming in [false, true] {
                    let mut headers = HeaderMap::new();
                    if let Some(value) = content_range {
                        headers.insert(CONTENT_RANGE, value.parse().unwrap());
                    }
                    let bytes = Bytes::from(vec![42; length]);
                    let body = if streaming {
                        Body::Stream(Box::new(io::Cursor::new(bytes)))
                    } else {
                        Body::Bytes(bytes)
                    };
                    let result = Response {
                        status: StatusCode::OK,
                        headers,
                        body,
                        source,
                    }
                    .require_partial(range);
                    let expected = accepted && source == Source::Dragonfly && !streaming;
                    assert_eq!(
                        result.is_ok(),
                        expected,
                        "{source:?} {streaming} {range} {content_range:?}"
                    );
                    match result {
                        Ok(response) => {
                            assert_eq!(response.headers[CONTENT_RANGE], content_range.unwrap());
                            assert!(matches!(response.body, Body::Bytes(bytes)
                                if bytes.as_ref() == vec![42; length]));
                        }
                        Err(error) => {
                            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                            assert!(error.to_string().contains("expected 206 Partial Content"));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn require_partial_preserves_206_and_rejects_other_statuses() {
        for source in [Source::Origin, Source::Dragonfly] {
            for status in [
                StatusCode::PARTIAL_CONTENT,
                StatusCode::NO_CONTENT,
                StatusCode::TEMPORARY_REDIRECT,
                StatusCode::RANGE_NOT_SATISFIABLE,
            ] {
                let result = Response {
                    status,
                    source,
                    headers: HeaderMap::new(),
                    body: Body::Bytes(Bytes::from_static(b"range")),
                }
                .require_partial("bytes=0-4");
                assert_eq!(result.is_ok(), status == StatusCode::PARTIAL_CONTENT);
                if let Ok(response) = result {
                    assert_eq!(response.status, status);
                    assert_eq!(response.source, source);
                    assert!(matches!(response.body, Body::Bytes(bytes) if bytes == "range"));
                }
            }
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
