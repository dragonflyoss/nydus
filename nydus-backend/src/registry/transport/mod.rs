//! The transport of blob `GET`s: how a request reaches the origin, a proxy
//! or the Dragonfly seed peers.

#[cfg(feature = "dragonfly")]
mod dragonfly;
mod http;

use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::{stream, StreamExt};
use reqwest::header::{HeaderMap, RANGE};
use reqwest::StatusCode;
use tracing::warn;

use crate::Source;

use super::range::Range;
use super::response::Response;

#[cfg(feature = "dragonfly")]
pub(crate) use self::dragonfly::Dragonfly;
pub(crate) use self::http::{Http, RateLimit};

/// A fetcher of blob ranges, each call returning after its own retries.
///
/// ```text
/// Fetcher
///   ├─ Http        the origin, directly or through `http.proxy`
///   ├─ Dragonfly   the Dragonfly seed peers
///   └─ Transport   one of the two, then the origin client it falls back to
/// ```
#[async_trait]
pub(crate) trait Fetcher: Send + Sync {
    /// Sends the `GET` of an on-demand read, which a FUSE reader waits on.
    async fn get(&self, url: &str, headers: HeaderMap) -> io::Result<Response>;

    /// Sends the `GET` of a prefetch read, once more after the retry interval
    /// on a `429`, `5xx` or `408`.
    async fn prefetch(&self, url: &str, headers: HeaderMap) -> io::Result<Response>;

    /// Returns the `source` label of the reads the fetcher serves.
    fn source(&self) -> Source;
}

/// The transport of blob `GET`s: the fetcher the configuration names, then
/// the origin client the on-demand reads it fails fall back to.
///
/// ```text
/// GET ──▶ fetcher ──▶ 2xx in the range / 3xx / 4xx ───────────────────▶ handed back as is
///           │ 429 / 5xx / 408 / transport failure / 2xx outside the range
///           ├─ on-demand ─▶ origin ──▶ any answer ────────────────────▶ handed back as is
///           │                 └─ transport failure ───────────────────▶ handed back as a 502
///           ├─ on-demand, no fallback ────────────────────────────────▶ handed back as the error
///           └─ prefetch ──▶ handed back as is, never the origin
/// ```
pub(crate) struct Transport {
    /// The fetcher the reads go through first: the Dragonfly seed peers, the
    /// proxy or the origin.
    fetcher: Box<dyn Fetcher>,

    /// The origin client of on-demand fallbacks, never through the proxy and
    /// limited by `fallback.rate_limit`, none when the reads go to the origin
    /// first.
    fallback_http_client: Option<Http>,
}

/// Implements the transport.
impl Transport {
    /// Creates the transport that falls back from `fetcher` to
    /// `fallback_http_client`.
    pub(crate) fn new(fetcher: Box<dyn Fetcher>, fallback_http_client: Option<Http>) -> Self {
        Self {
            fetcher,
            fallback_http_client,
        }
    }

    /// Returns the origin client an on-demand read falls back to after `err`,
    /// or `err` without one.
    pub(crate) fn fallback(&self, err: io::Error) -> io::Result<&Http> {
        let Some(fallback_http_client) = &self.fallback_http_client else {
            return Err(err);
        };

        warn!("request failed, falling back to the origin: {err}");
        Ok(fallback_http_client)
    }
}

/// Implements the fetcher over a fetcher and its fallback.
#[async_trait]
impl Fetcher for Transport {
    /// Sends the `GET` through the fetcher, then through the origin client
    /// when the fetcher fails it.
    async fn get(&self, url: &str, headers: HeaderMap) -> io::Result<Response> {
        let result = self.fetcher.get(url, headers.clone()).await;

        // Fall back to the origin on an answer outside the range.
        let range = headers
            .get(RANGE)
            .and_then(|value| value.to_str().ok())
            .map(str::parse::<Range>)
            .transpose()?;

        let result = match (result, &range) {
            (Ok(response), Some(range)) if response.status.is_success() => {
                response.validate_range(range).map(|()| response)
            }
            (result, _) => result,
        };

        // Serve a definitive answer, fall back to the origin on anything else.
        let err = match result {
            Ok(response) if response.is_transient() => response.into_io_error().await,
            Ok(response) => return Ok(response),
            Err(err) => err,
        };

        // Serve what the origin answers, a `502` in its place when it does not.
        let response = match self.fallback(err)?.get(url, headers).await {
            Ok(response) => response,
            Err(err) => Response {
                status: StatusCode::BAD_GATEWAY,
                headers: HeaderMap::new(),
                body: stream::iter([Ok(Bytes::from(err.to_string()))]).boxed(),
                fallback: Arc::default(),
            },
        };

        Ok(Response {
            fallback: Arc::new(AtomicBool::new(true)),
            ..response
        })
    }

    /// Sends the `GET` through the fetcher, a prefetch read never falls back.
    async fn prefetch(&self, url: &str, headers: HeaderMap) -> io::Result<Response> {
        self.fetcher.prefetch(url, headers).await
    }

    /// Returns the `source` label of the reads the fetcher serves itself.
    fn source(&self) -> Source {
        self.fetcher.source()
    }
}
