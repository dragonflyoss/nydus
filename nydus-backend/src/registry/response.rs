//! The answer a transport hands back.

use std::future::Future;
use std::io;

use bytes::{Bytes, BytesMut};
use futures::stream::{self, BoxStream};
use futures::{Stream, StreamExt, TryStreamExt};
use reqwest::header::{HeaderMap, CONTENT_RANGE, LOCATION};
use reqwest::StatusCode;

use super::range::{ContentRange, Range};

/// A response from the origin or a Dragonfly seed peer.
pub(crate) struct Response {
    /// The HTTP status.
    pub(crate) status: StatusCode,

    /// The response headers.
    pub(crate) headers: HeaderMap,

    /// The body, streaming in the chunks it arrives in.
    pub(crate) body: Body,

    /// Whether the transport can still fall back for the body.
    pub(crate) fallback: bool,
}

/// The body of a response, the chunks it arrives in.
pub(crate) type Body = BoxStream<'static, io::Result<Bytes>>;

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

        Ok(())
    }

    /// Converts into the stream of the first `length` bytes of the body.
    pub(crate) fn bytes_stream(self, length: usize) -> impl Stream<Item = io::Result<Bytes>> {
        stream::try_unfold((self.body, 0), move |(mut body, offset)| async move {
            if offset == length {
                return Ok(None);
            }

            loop {
                let Some(chunk) = body.try_next().await? else {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("registry returned {offset} bytes, expected {length}"),
                    ));
                };

                let chunk = chunk.slice(..chunk.len().min(length - offset));
                if chunk.is_empty() {
                    continue;
                }

                let offset = offset + chunk.len();
                return Ok(Some((chunk, (body, offset))));
            }
        })
    }

    /// Makes the body of a `206` resume once through `resume`, for the bytes
    /// left when it breaks off.
    ///
    /// ```text
    /// 206 bytes 0-14/15 ──▶ chunk ──▶ breaks off at byte 6
    /// resume(err, bytes=6-14) ──▶ 206 bytes 6-14/15 ──▶ chunk ──▶ end
    /// ```
    pub(crate) fn resumable<F, Fut>(self, resume: F) -> io::Result<Self>
    where
        F: FnOnce(io::Error, Range) -> Fut + Send + 'static,
        Fut: Future<Output = io::Result<Response>> + Send + 'static,
    {
        let remaining = self.content_range()?.range;
        let body = stream::try_unfold(
            (self.body, remaining, Some(resume)),
            |(mut body, remaining, mut resume)| async move {
                loop {
                    let err = match body.try_next().await {
                        Ok(Some(chunk)) => {
                            let start = remaining.start().saturating_add(chunk.len() as u64);
                            return Ok(Some((chunk, (body, start..=*remaining.end(), resume))));
                        }
                        Ok(None) if remaining.is_empty() => return Ok(None),
                        Ok(None) => io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!(
                                "response body ended without {}",
                                Range::Bounded(remaining.clone())
                            ),
                        ),
                        Err(err) => err,
                    };

                    // Resume the body once, while bytes are left.
                    let Some(resume) = resume.take().filter(|_| !remaining.is_empty()) else {
                        return Err(err);
                    };
                    body = resume(err, Range::Bounded(remaining.clone())).await?.body;
                }
            },
        )
        .boxed();
        Ok(Self { body, ..self })
    }

    /// Reads exactly `length` bytes of the body.
    pub(crate) async fn bytes(self, length: usize) -> io::Result<Bytes> {
        self.bytes_stream(length)
            .try_fold(
                BytesMut::with_capacity(length),
                |mut bytes, chunk| async move {
                    bytes.extend_from_slice(&chunk);
                    Ok(bytes)
                },
            )
            .await
            .map(BytesMut::freeze)
    }

    /// Reads the body as a UTF-8 string.
    pub(crate) async fn text(self) -> io::Result<String> {
        let bytes: Vec<u8> = self
            .body
            .try_fold(Vec::new(), |mut bytes, chunk| async move {
                bytes.extend_from_slice(&chunk);
                Ok(bytes)
            })
            .await?;

        String::from_utf8(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
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
    use futures::stream::{self, StreamExt};
    use std::future;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn resumable_resumes_the_body_once_while_bytes_are_left() {
        let test_cases: Vec<(
            Vec<io::Result<&'static [u8]>>,
            Vec<io::Result<&'static [u8]>>,
            fn(io::Result<Vec<u8>>),
            Option<Range>,
        )> = vec![
            (
                vec![Ok(b"ab"), Ok(b"cd")],
                vec![],
                |result| assert_eq!(result.unwrap(), b"abcd"),
                None,
            ),
            (
                vec![Ok(b"ab"), Err(io::Error::other("reset"))],
                vec![Ok(b"cd")],
                |result| assert_eq!(result.unwrap(), b"abcd"),
                Some(Range::Bounded(2..=3)),
            ),
            (
                vec![Ok(b"abc")],
                vec![Ok(b"d")],
                |result| assert_eq!(result.unwrap(), b"abcd"),
                Some(Range::Bounded(3..=3)),
            ),
            (
                vec![Ok(b"ab"), Err(io::Error::other("reset"))],
                vec![Ok(b"c"), Err(io::Error::other("reset again"))],
                |result| assert_eq!(result.unwrap_err().to_string(), "reset again"),
                Some(Range::Bounded(2..=3)),
            ),
            (
                vec![Ok(b"abcd"), Err(io::Error::other("reset"))],
                vec![],
                |result| assert_eq!(result.unwrap_err().to_string(), "reset"),
                None,
            ),
        ];

        for (chunks, resumed_chunks, expect, expected_range) in test_cases {
            let response = |chunks: Vec<io::Result<&'static [u8]>>| {
                let mut headers = HeaderMap::new();
                headers.insert(CONTENT_RANGE, "bytes 0-3/4".parse().unwrap());
                Response {
                    status: StatusCode::PARTIAL_CONTENT,
                    headers,
                    body: stream::iter(chunks).map_ok(Bytes::from_static).boxed(),
                    fallback: false,
                }
            };
            let resumed_range = Arc::new(Mutex::new(None));
            let response = response(chunks)
                .resumable({
                    let resumed_range = resumed_range.clone();
                    move |_, range| async move {
                        *resumed_range.lock().unwrap() = Some(range);
                        Ok(response(resumed_chunks))
                    }
                })
                .unwrap();

            let result = response
                .body
                .try_fold(Vec::new(), |mut bytes, chunk| async move {
                    bytes.extend_from_slice(&chunk);
                    Ok(bytes)
                })
                .await;

            expect(result);
            assert_eq!(*resumed_range.lock().unwrap(), expected_range);
        }
    }

    #[test]
    fn validate_range_accepts_only_a_206() {
        let test_cases = vec![
            (StatusCode::PARTIAL_CONTENT, true),
            (StatusCode::OK, false),
            (StatusCode::NO_CONTENT, false),
        ];

        for (status, expected) in test_cases {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_RANGE, "bytes 2-5/8".parse().unwrap());
            let response = Response {
                status,
                headers,
                body: stream::iter([Ok(Bytes::from_static(b"abcd"))]).boxed(),
                fallback: false,
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
            (Some("bytes 2-5/8"), true),
            (Some("bytes 1-4/8"), false),
            (Some("bytes 2-5/*"), false),
            (None, false),
        ];

        for (content_range, expected) in test_cases {
            let mut headers = HeaderMap::new();
            if let Some(value) = content_range {
                headers.insert(CONTENT_RANGE, value.parse().unwrap());
            }
            let response = Response {
                status: StatusCode::PARTIAL_CONTENT,
                headers,
                body: stream::iter([Ok(Bytes::from_static(b"abcd"))]).boxed(),
                fallback: false,
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
                body: stream::empty().boxed(),
                fallback: false,
            };
            #[cfg(feature = "dragonfly")]
            assert_eq!(response.needs_fallback(), expected);
            assert_eq!(response.needs_retry(), expected);
        }
    }

    #[tokio::test]
    async fn bytes_reads_exactly_len_across_chunks() {
        let test_cases: Vec<(Vec<&'static [u8]>, fn(io::Result<Bytes>))> = vec![
            (vec![b"abcd"], |result| assert_eq!(result.unwrap(), "abcd")),
            (vec![b"abcdef"], |result| {
                assert_eq!(result.unwrap(), "abcd")
            }),
            (vec![b"ab", b"c", b"def"], |result| {
                assert_eq!(result.unwrap(), "abcd")
            }),
            (vec![b"ab"], |result| {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof)
            }),
            (vec![], |result| {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof)
            }),
        ];

        for (chunks, assert_fn) in test_cases {
            let response = Response {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: stream::iter(
                    chunks
                        .into_iter()
                        .map(|chunk| Ok(Bytes::from_static(chunk))),
                )
                .boxed(),
                fallback: false,
            };
            assert_fn(response.bytes(4).await);
        }
    }

    #[tokio::test]
    async fn bytes_stream_yields_the_chunks_until_the_length_or_an_error() {
        let test_cases: Vec<(Vec<io::Result<&'static [u8]>>, fn(io::Result<()>, &[u8]))> = vec![
            (vec![Ok(b"ab"), Ok(b"cd")], |result, bytes| {
                result.unwrap();
                assert_eq!(bytes, b"abcd");
            }),
            (vec![Ok(b"ab"), Ok(b""), Ok(b"cdef")], |result, bytes| {
                result.unwrap();
                assert_eq!(bytes, b"abcd");
            }),
            (
                vec![Ok(b"ab"), Err(io::Error::other("connection reset"))],
                |result, bytes| {
                    assert_eq!(result.unwrap_err().to_string(), "connection reset");
                    assert_eq!(bytes, b"ab");
                },
            ),
            (vec![Ok(b"ab")], |result, bytes| {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
                assert_eq!(bytes, b"ab");
            }),
        ];

        for (chunks, expect) in test_cases {
            let response = Response {
                status: StatusCode::PARTIAL_CONTENT,
                headers: HeaderMap::new(),
                body: stream::iter(
                    chunks
                        .into_iter()
                        .map(|chunk| chunk.map(Bytes::from_static)),
                )
                .boxed(),
                fallback: false,
            };

            let mut bytes = Vec::new();
            let result = response
                .bytes_stream(4)
                .try_for_each(|chunk| {
                    bytes.extend_from_slice(&chunk);
                    future::ready(Ok(()))
                })
                .await;

            expect(result, &bytes);
        }
    }

    #[tokio::test]
    async fn into_io_error_names_the_status_and_carries_the_body() {
        let response = Response {
            status: StatusCode::NOT_FOUND,
            headers: HeaderMap::new(),
            body: stream::iter([Ok(Bytes::from_static(b"no such blob"))]).boxed(),
            fallback: false,
        };
        assert_eq!(
            response.into_io_error().await.to_string(),
            "unexpected status 404 Not Found: no such blob"
        );
    }
}
