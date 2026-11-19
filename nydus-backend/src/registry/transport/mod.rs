//! The transport of blob `GET`s: how a request reaches the origin, a proxy
//! or the Dragonfly seed peers.

#[cfg(feature = "dragonfly")]
mod dragonfly;
mod http;
mod middleware;

use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::{stream, StreamExt};
use reqwest::header::{HeaderMap, RANGE};
use reqwest::StatusCode;
use tracing::warn;
use url::Url;

use crate::Source;

use super::range::Range;
use super::response::Response;

#[cfg(feature = "dragonfly")]
pub(crate) use self::dragonfly::Dragonfly;
pub(crate) use self::http::Http;
pub(crate) use self::middleware::RateLimit;

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
    /// Returns the `source` label of the reads the fetcher serves.
    fn source(&self) -> Source;

    /// Sends the `GET` of an on-demand read, which a FUSE reader waits on.
    async fn get(&self, url: &Url, headers: HeaderMap) -> io::Result<Response>;

    /// Sends the `GET` of a prefetch read.
    async fn prefetch(&self, url: &Url, headers: HeaderMap) -> io::Result<Response>;
}

/// The transport of blob `GET`s: the fetcher the configuration names, alone
/// or with the origin client the on-demand reads it fails fall back to.
///
/// ```text
/// GET ──▶ fetcher ──▶ 2xx in the range / 3xx / 4xx ───────────────────▶ handed back as is
///           │ 429 / 5xx / 408 / transport failure / 2xx outside the range
///           ├─ Direct ────────────────────────────────────────────────▶ handed back as is
///           ├─ on-demand ─▶ origin ──▶ 2xx in the range / not a 2xx ──▶ handed back as is
///           │                 └─ no answer / 2xx outside the range ───▶ handed back as a 502
///           └─ prefetch ──▶ handed back as is, never the origin
/// ```
pub(crate) enum Transport {
    /// The reads go to the origin directly, with nothing to fall back to.
    Direct {
        /// The fetcher of the origin.
        fetcher: Box<dyn Fetcher>,
    },

    /// The reads go through the Dragonfly seed peers or the proxy, the
    /// on-demand ones falling back to the origin.
    Fallback {
        /// The fetcher the reads go through first, Dragonfly or the proxy.
        fetcher: Box<dyn Fetcher>,

        /// The origin client of on-demand fallbacks, never through the proxy
        /// and limited by `fallback.rate_limit`.
        fallback_http_client: Http,
    },
}

/// Implements the transport.
impl Transport {
    /// Returns the origin client an on-demand read falls back to after `err`,
    /// or `err` without one.
    pub(crate) fn fallback(&self, err: io::Error) -> io::Result<&Http> {
        match self {
            Self::Direct { .. } => Err(err),
            Self::Fallback {
                fallback_http_client,
                ..
            } => {
                warn!("request failed, falling back to the origin: {err}");
                Ok(fallback_http_client)
            }
        }
    }
}

/// Implements the fetcher over a fetcher and its fallback.
#[async_trait]
impl Fetcher for Transport {
    /// Returns the `source` label of the reads the fetcher serves itself.
    fn source(&self) -> Source {
        match self {
            Self::Direct { fetcher } | Self::Fallback { fetcher, .. } => fetcher.source(),
        }
    }

    /// Sends the `GET` through the fetcher, then through the origin client
    /// when the fetcher fails it.
    async fn get(&self, url: &Url, headers: HeaderMap) -> io::Result<Response> {
        let fetcher = match self {
            Self::Direct { fetcher } => return fetcher.get(url, headers).await,
            Self::Fallback { fetcher, .. } => fetcher,
        };

        let range = headers
            .get(RANGE)
            .and_then(|value| value.to_str().ok())
            .map(str::parse::<Range>)
            .transpose()?;

        // Fall back to the origin on an answer outside the range.
        let result = match (fetcher.get(url, headers.clone()).await, &range) {
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

        // Fail an answer of the origin outside the range.
        let result = match (self.fallback(err)?.get(url, headers).await, &range) {
            (Ok(response), Some(range)) if response.status.is_success() => {
                response.validate_range(range).map(|()| response)
            }
            (result, _) => result,
        };

        // Serve what the origin answers, a `502` in its place when it fails.
        let response = match result {
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
    async fn prefetch(&self, url: &Url, headers: HeaderMap) -> io::Result<Response> {
        match self {
            Self::Direct { fetcher } | Self::Fallback { fetcher, .. } => {
                fetcher.prefetch(url, headers).await
            }
        }
    }
}
