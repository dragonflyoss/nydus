//! The Dragonfly SDK transport, feature `dragonfly`.
//!
//! A blob `GET` rides the Dragonfly client SDK to the seed peers named by the
//! scheduler, every other request going straight to the origin. The SDK owns
//! the retries: an on-demand read retries a transient failure, a `429`
//! included, on the next seed peer up to the configured budget, while a
//! prefetch read never retries, the storage layer rescheduling a failed
//! prefetch hours later instead. The SDK reads the body whole, so a seed peer
//! failing mid-body is retried like any other transient failure, and the
//! buffer it filled is handed on without a copy.
//!
//! What a read does once the SDK's own retries are spent is decided here: a
//! `429`, `5xx`, `408` or transport failure sends an on-demand read back to
//! the origin through the rate-limited client, as dfdaemon itself goes back
//! to source, and defers a prefetch read to the storage layer's reschedule
//! instead, so a Dragonfly outage degrades prefetch rather than flooding the
//! registry. Any other answer is served as is, a dfdaemon `422` included.

use std::io;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::BytesMut;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::StatusCode;
use tracing::{debug, warn};

use dragonfly_api::common::v2::Priority;
use dragonfly_client_request::errors::{BackendError, DfdaemonError, Error, ProxyError};
use dragonfly_client_request::{ExponentialBuilder, GetRequest, Proxy, Request as _};

use nydus_config::{DragonflyConfig, HttpConfig};
use nydus_telemetry::metrics::collect_read_backend_failure_metrics;

use super::http::{Http, RateLimit};
use super::response::{Body, Response};
use super::rt::Runtime;
use super::Transport;
use crate::{BackendKind, Protocol, ReadKind};

/// The Dragonfly SDK transport, one client per read kind so each kind keeps
/// its own retry budget.
pub(crate) struct Dragonfly {
    /// The seed peer client of on-demand reads, retrying on the next seed
    /// peer after an exponential backoff, a `429` included since another seed
    /// peer may not be rate limited.
    ondemand_client: Proxy,

    /// The seed peer client of prefetch reads, never retrying: a failed
    /// prefetch is rescheduled hours later instead.
    prefetch_client: Proxy,

    /// The HTTP client of the requests P2P does not carry, a `HEAD` for a
    /// blob's size, as dfdaemon's own proxy forwards non-`GET` requests
    /// straight to the origin.
    http_client: Http,

    /// The rate-limited origin client an on-demand read falls back to when
    /// the seed peers cannot serve it, every attempt claiming a slot first.
    fallback_client: Http,

    /// The timeout of each attempt of a request.
    request_timeout: Duration,
}

/// Implements the Dragonfly transport.
impl Dragonfly {
    /// Creates the transport, each seed peer client connecting to the
    /// configured scheduler on the runtime of its read kind, with
    /// `http_client` for the requests that go to the origin and a fallback
    /// client built from `http_config` under the configured rate limit.
    ///
    /// Only the on-demand client retries, `max_retries` times across seed
    /// peers.
    pub(crate) fn new(
        config: DragonflyConfig,
        http_config: &HttpConfig,
        http_client: Http,
        runtime: &Runtime,
    ) -> io::Result<Self> {
        Ok(Self {
            ondemand_client: Self::client(
                runtime,
                ReadKind::OnDemand,
                config.scheduler_endpoint.clone(),
                config.max_retries as u8,
            )?,
            prefetch_client: Self::client(
                runtime,
                ReadKind::Prefetch,
                config.scheduler_endpoint,
                0,
            )?,
            http_client,
            fallback_client: Http::new(
                http_config,
                Some(RateLimit::new(
                    config.back_to_source.request_rate_limit,
                    Duration::from_secs(1),
                )),
            )?,
            request_timeout: config.request_timeout,
        })
    }

    /// Creates the client of reads of `kind`, connected to the scheduler at
    /// `scheduler_endpoint` on that kind's runtime so it is reached from the
    /// runtime's netns, retrying a request `max_retries` times across seed
    /// peers with a jittered exponential backoff.
    fn client(
        runtime: &Runtime,
        kind: ReadKind,
        scheduler_endpoint: String,
        max_retries: u8,
    ) -> io::Result<Proxy> {
        runtime.block_on_worker(kind, async move {
            Proxy::builder()
                .scheduler_endpoint(scheduler_endpoint)
                .max_retries(max_retries)
                .backoff(ExponentialBuilder::default().with_jitter())
                .build()
                .await
                .map_err(|err| io::Error::other(format!("failed to build dragonfly client: {err}")))
        })
    }
}

/// Implements the blob transport over the Dragonfly SDK.
#[async_trait]
impl Transport for Dragonfly {
    /// Sends the `HEAD` to the origin, as dfdaemon's own proxy does for every
    /// request that is not a `GET`.
    async fn head(&self, url: &str, headers: HeaderMap) -> io::Result<Response> {
        self.http_client.head(url, headers).await
    }

    /// Fetches `url` through the on-demand client at `Level6`, the SDK's
    /// default priority, the SDK adding the P2P and priority headers itself,
    /// and logs the outcome; a `429`, `5xx`, `408` or transport failure the
    /// SDK's retries did not cure goes back to the origin.
    ///
    /// The SDK reads the body whole, retrying a seed peer that fails mid-body,
    /// and the buffer is handed on as is. An SDK error carrying an HTTP status
    /// becomes a [`Response`] so it is settled by status like an origin
    /// answer; anything else is a transport failure.
    async fn get(&self, url: &str, headers: HeaderMap) -> io::Result<Response> {
        let request = GetRequest {
            url: url.to_string(),
            header: headers.clone(),
            priority: Some(Priority::Level6 as i32),
            timeout: self.request_timeout,
            ..Default::default()
        };

        let start = Instant::now();
        let mut body = BytesMut::new();
        let result = match self.ondemand_client.get_into(&request, &mut body).await {
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
        };

        match &result {
            Ok(response) => debug!(
                "GET {url} (ondemand) through dragonfly returned {} in {:?}",
                response.status,
                start.elapsed()
            ),
            Err(err) => debug!(
                "GET {url} (ondemand) through dragonfly failed in {:?}: {err}",
                start.elapsed()
            ),
        }

        // Serve a definitive answer; go back to the origin on anything else.
        let err = match result {
            Ok(response) if response.needs_back_to_source() => response.into_io_error().await,
            Ok(response) => return Ok(response),
            Err(err) => err,
        };
        warn!("dragonfly request failed, falling back to the origin: {err}");

        let start = Instant::now();
        self.fallback_client
            .get(url, headers)
            .await
            .inspect_err(|_| {
                collect_read_backend_failure_metrics(
                    ReadKind::OnDemand,
                    BackendKind::Registry,
                    Some(Protocol::Http),
                    start.elapsed(),
                )
            })
    }

    /// Fetches `url` through the prefetch client at `Level3`, so a first
    /// download lets a normal peer go back to source ahead of it, and logs
    /// the outcome; a `429`, `5xx`, `408` or transport failure defers the
    /// read as an [`io::ErrorKind::QuotaExceeded`] for the storage layer to
    /// reschedule hours later, never touching the origin. The body and
    /// errors are otherwise handled as in [`get`](Self::get).
    async fn prefetch(&self, url: &str, headers: HeaderMap) -> io::Result<Response> {
        let request = GetRequest {
            url: url.to_string(),
            header: headers,
            priority: Some(Priority::Level3 as i32),
            timeout: self.request_timeout,
            ..Default::default()
        };

        let start = Instant::now();
        let mut body = BytesMut::new();
        let result = match self.prefetch_client.get_into(&request, &mut body).await {
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
        };

        match &result {
            Ok(response) => debug!(
                "GET {url} (prefetch) through dragonfly returned {} in {:?}",
                response.status,
                start.elapsed()
            ),
            Err(err) => debug!(
                "GET {url} (prefetch) through dragonfly failed in {:?}: {err}",
                start.elapsed()
            ),
        }

        // Serve a definitive answer; defer the read on anything else, as a
        // prefetch never goes back to the origin.
        let err = match result {
            Ok(response) if response.needs_back_to_source() => response.into_io_error().await,
            Ok(response) => return Ok(response),
            Err(err) => err,
        };
        warn!("dragonfly request failed: {err}");
        Err(io::Error::new(
            io::ErrorKind::QuotaExceeded,
            format!("prefetch deferred: {err}"),
        ))
    }
}
