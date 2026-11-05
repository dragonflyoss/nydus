//! The Dragonfly SDK transport, feature `dragonfly`.

use std::io;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::BytesMut;
use rand::Rng;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, RANGE};
use reqwest::StatusCode;
use tokio::sync::SetOnce;
use tracing::{debug, error, warn};

use dragonfly_api::common::v2::Priority;
use dragonfly_client_request::errors::{BackendError, DfdaemonError, Error, ProxyError};
use dragonfly_client_request::{ExponentialBuilder, GetRequest, Proxy, Request as _};

use nydus_config::{DragonflyConfig, HttpConfig};

use super::http::{Http, RateLimit};
use super::range::Range;
use super::response::{Body, Response};
use super::rt::Runtime;
use super::Transport;
use crate::Source;

/// A seed peer client a read waits for, set once its background connect to
/// the scheduler finishes.
type SeedPeerClient = Arc<SetOnce<Result<Proxy, Error>>>;

/// The Dragonfly SDK transport: a blob `GET` rides the SDK to the seed peers
/// named by the scheduler, one client per read kind on the backend's
/// runtime. Both connect to the scheduler in the background so building the
/// transport never delays a mount, and a failed connect stops the process
/// with SIGTERM, since a daemon configured with Dragonfly fails without it.
///
/// ```text
/// GET ──▶ wait for the client ──▶ seed peer ──▶ 2xx / 3xx / 4xx ──────▶ handed back as is
///           │ connect failed       │ 429 / 5xx / 408 / transport failure
///           │                      ├─ on-demand ─▶ next seed peer, max_retries times ─▶ origin
///           │                      └─ prefetch ──┬─ 429 / 5xx / 408 ─▶ once more ─▶ error
///           │                                    └─ transport failure ──────────▶ error
///           ├─ on-demand ─▶ origin, rate limited
///           └─ prefetch ──▶ error
/// ```
pub(crate) struct Dragonfly {
    /// The seed peer client of on-demand reads, retrying on the next seed
    /// peer after an exponential backoff, a `429` included since another seed
    /// peer may not be rate limited.
    ondemand_client: SeedPeerClient,

    /// The seed peer client of prefetch reads, never retrying at once: a
    /// failed prefetch is sent once more after the retry interval instead.
    prefetch_client: SeedPeerClient,

    /// The rate-limited client an on-demand read falls back to the origin
    /// through when the seed peers cannot serve it, the registry's `http`
    /// settings under `fallback_rate_limit`, every attempt claiming a slot
    /// first.
    fallback_http_client: Http,

    /// The window of the random interval before a prefetch read is sent once
    /// more, the configured interval up to twice that.
    prefetch_retry_interval: RangeInclusive<Duration>,

    /// The timeout of each attempt of a request.
    request_timeout: Duration,
}

/// Implements the Dragonfly transport.
impl Dragonfly {
    /// Creates the transport, the seed peer clients connecting to the
    /// configured scheduler on `runtime` in the background, with the fallback
    /// client built from the registry's `http` settings under
    /// `fallback_rate_limit`.
    ///
    /// Only the on-demand client retries, `max_retries` times across seed
    /// peers; a failed prefetch read is sent once more after
    /// `prefetch_retry_interval`.
    pub(crate) fn new(
        config: DragonflyConfig,
        http: &HttpConfig,
        prefetch_retry_interval: Duration,
        runtime: &Runtime,
    ) -> io::Result<Self> {
        let (ondemand_client, prefetch_client) = Self::clients(
            runtime,
            config.scheduler_endpoint.clone(),
            config.max_retries as u8,
        );

        Ok(Self {
            ondemand_client,
            prefetch_client,
            fallback_http_client: Http::new(
                http.request_timeout,
                http.max_retries,
                http.proxy.as_ref(),
                &http.tls,
                prefetch_retry_interval,
                Some(RateLimit::new(
                    config.fallback_rate_limit,
                    Duration::from_secs(1),
                )),
                Source::Fallback,
            )?,
            request_timeout: config.request_timeout,
            prefetch_retry_interval: prefetch_retry_interval
                ..=prefetch_retry_interval.saturating_mul(2),
        })
    }

    /// Creates the on-demand and prefetch seed peer clients without waiting
    /// for them to connect: a task on `runtime` connects them to the
    /// scheduler in the background, from the runtime's netns, and reads wait
    /// on the clients until it does. Both retry across seed peers with a
    /// jittered exponential backoff, the on-demand one `max_retries` times and
    /// the prefetch one never. Either failing raises SIGTERM once, since a
    /// second one forces the daemon out before it unmounts.
    fn clients(
        runtime: &Runtime,
        scheduler_endpoint: String,
        max_retries: u8,
    ) -> (SeedPeerClient, SeedPeerClient) {
        let ondemand_client = Arc::new(SetOnce::new());
        let prefetch_client = Arc::new(SetOnce::new());

        runtime.spawn({
            let ondemand_client = ondemand_client.clone();
            let prefetch_client = prefetch_client.clone();
            async move {
                let (ondemand, prefetch) = tokio::join!(
                    Proxy::builder()
                        .scheduler_endpoint(scheduler_endpoint.clone())
                        .max_retries(max_retries)
                        .backoff(ExponentialBuilder::default().with_jitter())
                        .build(),
                    Proxy::builder()
                        .scheduler_endpoint(scheduler_endpoint)
                        .max_retries(0)
                        .backoff(ExponentialBuilder::default().with_jitter())
                        .build(),
                );

                if let Err(err) = ondemand.as_ref().and(prefetch.as_ref()) {
                    error!("dragonfly client failed, stopping the process: {err}");

                    // SAFETY: raise only delivers SIGTERM to this thread, whose
                    // handler the daemon registered for its graceful shutdown.
                    if unsafe { libc::raise(libc::SIGTERM) } != 0 {
                        error!("failed to raise SIGTERM: {}", io::Error::last_os_error());
                    }
                }

                if ondemand_client.set(ondemand).is_err() {
                    error!("dragonfly on-demand client is built twice");
                }

                if prefetch_client.set(prefetch).is_err() {
                    error!("dragonfly prefetch client is built twice");
                }
            }
        });

        (ondemand_client, prefetch_client)
    }

    /// Waits for `client` to connect to the scheduler, returning the error
    /// that failed it.
    async fn wait(client: &SeedPeerClient) -> io::Result<&Proxy> {
        client
            .wait()
            .await
            .as_ref()
            .map_err(|err| io::Error::other(format!("failed to build dragonfly client: {err}")))
    }
}

/// Implements the blob transport over the Dragonfly SDK.
#[async_trait]
impl Transport for Dragonfly {
    /// Waits for both seed peer clients to connect to the scheduler,
    /// returning the error that failed either.
    async fn ready(&self) -> io::Result<()> {
        Self::wait(&self.ondemand_client).await?;
        Self::wait(&self.prefetch_client).await?;
        Ok(())
    }

    /// Fetches `url` through the on-demand client at `Level6`, the SDK's
    /// default priority, going back to the origin on a `429`, `5xx`, `408` or
    /// transport failure its retries did not cure. An SDK error carrying an
    /// HTTP status becomes a [`Response`], settled by status like an origin
    /// answer.
    async fn get(&self, url: &str, headers: HeaderMap) -> io::Result<Response> {
        // Keep the requested range to validate the seed peer's answer.
        let range = headers
            .get(RANGE)
            .and_then(|value| value.to_str().ok())
            .map(str::parse::<Range>)
            .transpose()?;
        let request = GetRequest {
            url: url.to_string(),
            header: headers.clone(),
            priority: Some(Priority::Level6 as i32),
            timeout: self.request_timeout,
            ..Default::default()
        };

        // Wait for the seed peer client, going back to the origin when it
        // failed to connect to the scheduler.
        let client = match Self::wait(&self.ondemand_client).await {
            Ok(client) => client,
            Err(err) => {
                warn!("dragonfly client is unavailable, falling back to the origin: {err}");
                return self.fallback_http_client.get(url, headers).await;
            }
        };

        let start = Instant::now();
        let mut body = BytesMut::new();
        let result = match client.get_into(&request, &mut body).await {
            Ok(response) => Ok(Response {
                status: response.status_code.unwrap_or(StatusCode::OK),
                headers: response.header,
                body: Body::Bytes(body.freeze()),
                source: Source::Dragonfly,
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
                source: Source::Dragonfly,
            }),
            Err(Error::RequestTimeout(message)) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("dragonfly request timed out: {message}"),
            )),
            Err(err) => Err(io::Error::other(format!("dragonfly error: {err}"))),
        };

        // Treat an answer outside the requested range as a failure, so the
        // origin serves the read instead.
        let result = match (result, &range) {
            (Ok(response), Some(range)) if response.status.is_success() => {
                response.validate_range(range).map(|()| response)
            }
            (result, _) => result,
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

        // Serve a definitive answer; fall back to the origin on anything else.
        let err = match result {
            Ok(response) if response.needs_fallback() => response.into_io_error().await,
            Ok(response) => return Ok(response),
            Err(err) => err,
        };
        warn!("dragonfly request failed, falling back to the origin: {err}");

        // The fallback client logs the outcome and its duration itself; the
        // backend records the read's metrics once, whichever client failed.
        self.fallback_http_client.get(url, headers).await
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

        // Wait for the seed peer client, failing at once when it failed to
        // connect to the scheduler.
        let client = Self::wait(&self.prefetch_client).await?;
        let mut retried = false;
        loop {
            let start = Instant::now();
            let mut body = BytesMut::new();
            let result = match client.get_into(&request, &mut body).await {
                Ok(response) => Ok(Response {
                    status: response.status_code.unwrap_or(StatusCode::OK),
                    headers: response.header,
                    body: Body::Bytes(body.freeze()),
                    source: Source::Dragonfly,
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
                    source: Source::Dragonfly,
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
