//! The Dragonfly SDK transport, feature `dragonfly`.

use std::io;
use std::ops::RangeInclusive;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::BytesMut;
use rand::Rng;
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

/// The Dragonfly SDK transport: a blob `GET` rides the SDK to the seed peers
/// named by the scheduler, one client per read kind.
///
/// ```text
/// GET ──▶ seed peer ──▶ 2xx / 3xx / 4xx ────────────────────────────▶ handed back as is
///           │ 429 / 5xx / 408 / transport failure
///           ├─ on-demand ─▶ next seed peer, max_retries times ─▶ origin, rate limited
///           └─ prefetch ──┬─ 429 / 5xx / 408 ─▶ once more after the retry interval ─▶ error
///                         └─ transport failure ───────────────────────────▶ error
/// ```
pub(crate) struct Dragonfly {
    /// The seed peer client of on-demand reads, retrying on the next seed
    /// peer after an exponential backoff, a `429` included since another seed
    /// peer may not be rate limited.
    ondemand_client: Proxy,

    /// The seed peer client of prefetch reads, never retrying at once: a
    /// failed prefetch is sent once more after the retry interval instead.
    prefetch_client: Proxy,

    /// The window of the random interval before a prefetch read is sent once
    /// more, the configured interval up to twice that.
    prefetch_retry_interval: RangeInclusive<Duration>,

    /// The rate-limited HTTP client an on-demand read falls back to when the
    /// seed peers cannot serve it, every attempt claiming a slot first.
    fallback_http_client: Http,

    /// The timeout of each attempt of a request.
    request_timeout: Duration,
}

/// Implements the Dragonfly transport.
impl Dragonfly {
    /// Creates the transport, each seed peer client connecting to the
    /// configured scheduler on the runtime of its read kind, with a fallback
    /// client built from `http_config` under the configured rate limit.
    ///
    /// Only the on-demand client retries, `max_retries` times across seed
    /// peers; a failed prefetch read is sent once more after
    /// `prefetch_retry_interval`.
    pub(crate) fn new(
        config: DragonflyConfig,
        http_config: &HttpConfig,
        prefetch_retry_interval: Duration,
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
            fallback_http_client: Http::new(
                http_config,
                prefetch_retry_interval,
                Some(RateLimit::new(
                    config.back_to_source.request_rate_limit,
                    Duration::from_secs(1),
                )),
            )?,
            request_timeout: config.request_timeout,
            prefetch_retry_interval: prefetch_retry_interval
                ..=prefetch_retry_interval.saturating_mul(2),
        })
    }

    /// Creates the client of reads of `kind` on that kind's runtime, so the
    /// scheduler is reached from the runtime's netns, retrying `max_retries`
    /// times across seed peers with a jittered exponential backoff.
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
    /// Fetches `url` through the on-demand client at `Level6`, the SDK's
    /// default priority, going back to the origin on a `429`, `5xx`, `408` or
    /// transport failure its retries did not cure. An SDK error carrying an
    /// HTTP status becomes a [`Response`], settled by status like an origin
    /// answer.
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
            Ok(response) if response.needs_fallback() => response.into_io_error().await,
            Ok(response) => return Ok(response),
            Err(err) => err,
        };
        warn!("dragonfly request failed, falling back to the origin: {err}");

        // The origin client logs the outcome and its duration itself.
        let start = Instant::now();
        self.fallback_http_client
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

    /// Fetches `url` through the prefetch client at `Level3`, so a normal
    /// peer goes back to source ahead of it, sending a `429`, `5xx` or `408`
    /// once more after the retry interval and failing a transport failure at once, never
    /// touching the origin.
    async fn prefetch(&self, url: &str, headers: HeaderMap) -> io::Result<Response> {
        let request = GetRequest {
            url: url.to_string(),
            header: headers,
            priority: Some(Priority::Level3 as i32),
            timeout: self.request_timeout,
            ..Default::default()
        };

        let mut retried = false;
        loop {
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

            // Serve a definitive answer, or the second transient one, as a
            // prefetch never falls back to the origin.
            let response = result?;
            if !response.needs_retry() || retried {
                return Ok(response);
            }

            // Retry once after a random interval in the configured window.
            let err = response.into_io_error().await;
            let delay = rand::rng().random_range(self.prefetch_retry_interval.clone());
            warn!("dragonfly request failed, retrying in {delay:?}: {err}");
            tokio::time::sleep(delay).await;
            retried = true;
        }
    }
}
