//! The Dragonfly SDK transport, feature `dragonfly`.

use std::io;
use std::ops::RangeInclusive;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::BytesMut;
use rand::Rng;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, RANGE};
use reqwest::StatusCode;
use tokio::sync::watch;
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

/// The Dragonfly SDK transport: a blob `GET` rides the SDK to the seed peers
/// named by the scheduler, one client per read kind on the backend's
/// runtime. Both are [`ReconnectingProxy`]s, so building the transport never
/// delays a mount; while one is not connected, an on-demand read falls back
/// to the origin and a prefetch read fails.
///
/// ```text
/// GET ──▶ wait for the client ──▶ seed peer ──▶ 2xx / 3xx / 4xx ──────▶ handed back as is
///           │ not connected        │ 429 / 5xx / 408 / transport failure
///           │                      ├─ on-demand ─▶ next seed peer, max_retries times ─▶ origin
///           │                      └─ prefetch ──┬─ 429 / 5xx / 408 ─▶ once more ─▶ error
///           │                                    └─ transport failure ──────────▶ error
///           ├─ on-demand ─▶ origin
///           └─ prefetch ──▶ error
/// ```
pub(crate) struct Dragonfly {
    /// The seed peer client of on-demand reads, retrying on the next seed
    /// peer after an exponential backoff, a `429` included since another seed
    /// peer may not be rate limited.
    ondemand_client: ReconnectingProxy,

    /// The seed peer client of prefetch reads, never retrying at once: a
    /// failed prefetch is sent once more after the retry interval instead.
    prefetch_client: ReconnectingProxy,

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
        Ok(Self {
            ondemand_client: ReconnectingProxy::new(
                runtime,
                config.scheduler_endpoint.clone(),
                config.max_retries as u8,
            ),
            prefetch_client: ReconnectingProxy::new(runtime, config.scheduler_endpoint, 0),
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
}

/// Implements the blob transport over the Dragonfly SDK.
#[async_trait]
impl Transport for Dragonfly {
    /// Fetches `url` through the on-demand client at `Level6`, the SDK's
    /// default priority, going back to the origin while the client is not
    /// connected, or on a `429`, `5xx`, `408` or transport failure its retries
    /// did not cure. An SDK error carrying an HTTP status becomes a
    /// [`Response`], settled by status like an origin answer.
    async fn get(&self, url: &str, headers: HeaderMap) -> io::Result<Response> {
        let request = GetRequest {
            url: url.to_string(),
            header: headers.clone(),
            priority: Some(Priority::Level6 as i32),
            timeout: self.request_timeout,
            ..Default::default()
        };

        // Wait for the first connect of the seed peer client to the
        // scheduler, falling back to the origin while it is not connected.
        let Ok(client) = self.ondemand_client.ready().await else {
            return self.fallback_http_client.get(url, headers).await;
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

        let client = self.prefetch_client.ready().await?;
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

/// The connectivity state of a [`ReconnectingProxy`], named after gRPC's,
/// refer to
/// <https://github.com/grpc/grpc/blob/master/doc/connectivity-semantics-and-api.md>.
enum ConnectivityState {
    /// The first connect is in progress.
    Connecting,

    /// The proxy has connected to the scheduler.
    Ready(Proxy),

    /// The last connect failed, and the next one starts after
    /// [`ReconnectingProxy::RECONNECT_INTERVAL`].
    TransientFailure,
}

/// A Dragonfly SDK proxy connecting to the scheduler in the background, once
/// more every [`ReconnectingProxy::RECONNECT_INTERVAL`] until it succeeds, so
/// creating it never waits on the scheduler. Like a gRPC channel failing
/// fast, a caller waits for the first connect only and fails at once while a
/// later one is due.
///
/// ```text
/// Connecting ──┬─ connected ──────────────────────────────▶ Ready
///              └─ failed ──▶ TransientFailure ──┬─ connected 60s later ──▶ Ready
///                                 ▲             └─ failed 60s later ──┐
///                                 └───────────────────────────────────┘
/// ```
struct ReconnectingProxy {
    /// The connectivity state, which the connect task publishes.
    state: watch::Receiver<ConnectivityState>,
}

/// Implements the reconnecting proxy.
impl ReconnectingProxy {
    /// The interval between the connects to the scheduler, until one
    /// succeeds.
    const RECONNECT_INTERVAL: Duration = Duration::from_secs(10);

    /// Creates the proxy, a task on `runtime` connecting it to the scheduler
    /// at `scheduler_endpoint` from the runtime's netns. The proxy retries a
    /// read across seed peers `max_retries` times with a jittered exponential
    /// backoff.
    fn new(runtime: &Runtime, scheduler_endpoint: String, max_retries: u8) -> Self {
        let (tx, rx) = watch::channel(ConnectivityState::Connecting);
        runtime.spawn(async move {
            let proxy = loop {
                match Proxy::builder()
                    .scheduler_endpoint(scheduler_endpoint.clone())
                    .max_retries(max_retries)
                    .backoff(ExponentialBuilder::default().with_jitter())
                    .build()
                    .await
                {
                    Ok(proxy) => break proxy,
                    Err(err) => {
                        error!(
                            "failed to connect dragonfly proxy, retrying in {:?}: {err}",
                            Self::RECONNECT_INTERVAL
                        );
                        tx.send_replace(ConnectivityState::TransientFailure);
                        tokio::time::sleep(Self::RECONNECT_INTERVAL).await;
                    }
                }
            };

            tx.send_replace(ConnectivityState::Ready(proxy));
        });

        Self { state: rx }
    }

    /// Returns the proxy once it has connected, waiting for the first connect
    /// only: while a later connect is due, it fails at once with
    /// [`io::ErrorKind::NotConnected`].
    async fn ready(&self) -> io::Result<Proxy> {
        let mut rx = self.state.clone();
        let state = rx
            .wait_for(|state| !matches!(state, ConnectivityState::Connecting))
            .await
            .map_err(|_| io::Error::other("dragonfly proxy connect task is gone"))?;

        match &*state {
            ConnectivityState::Ready(proxy) => Ok(proxy.clone()),
            _ => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "dragonfly proxy is not connected to the scheduler",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ready_waits_for_the_first_connect() {
        let (tx, rx) = watch::channel(ConnectivityState::Connecting);
        let proxy = ReconnectingProxy { state: rx };
        let ready = proxy.ready();
        tokio::pin!(ready);

        assert!(tokio::time::timeout(Duration::from_millis(100), &mut ready)
            .await
            .is_err());

        tx.send_replace(ConnectivityState::TransientFailure);
        assert!(matches!(ready.await, Err(err) if err.kind() == io::ErrorKind::NotConnected));
    }

    #[tokio::test]
    async fn ready_fails_at_once_unless_connected() {
        let test_cases = vec![
            (
                ConnectivityState::TransientFailure,
                io::ErrorKind::NotConnected,
            ),
            (ConnectivityState::Connecting, io::ErrorKind::Other),
        ];

        for (state, expected) in test_cases {
            let (_, rx) = watch::channel(state);
            let proxy = ReconnectingProxy { state: rx };
            assert!(matches!(proxy.ready().await, Err(err) if err.kind() == expected));
        }
    }
}
