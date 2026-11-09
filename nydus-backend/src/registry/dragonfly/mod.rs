//! The Dragonfly SDK transport, feature `dragonfly`.

mod seed_peer_resolver;

use std::fs::DirBuilder;
use std::io;
use std::ops::RangeInclusive;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use bytes::BytesMut;
use rand::Rng;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, RANGE};
use reqwest::StatusCode;
use tokio::sync::watch;
use tracing::{debug, error, warn};

use dragonfly_api::common::v2::Priority;
use dragonfly_client_request::errors::{BackendError, DfdaemonError, Error, ProxyError};
use dragonfly_client_request::{
    ExponentialBuilder, GetRequest, ProxyWithSeedPeers, RequestWithSeedPeers as _,
};

use nydus_config::{DragonflyConfig, HttpConfig};

use super::http::{Http, RateLimit};
use super::range::Range;
use super::response::{Body, Response};
use super::rt::Runtime;
use super::Transport;
use crate::Source;

use self::seed_peer_resolver::SeedPeerResolver;

/// The Dragonfly transport, one [`SeedPeerClient`] per read kind.
///
/// ```text
/// GET ──▶ wait for the client ──▶ seed peer ──▶ 2xx / 3xx / 4xx ──────▶ handed back as is
///           │ no seed peer         │ 429 / 5xx / 408 / transport failure
///           │                      ├─ on-demand ─▶ next seed peer, max_retries times ─▶ origin
///           │                      └─ prefetch ──┬─ 429 / 5xx / 408 ─▶ once more ─▶ error
///           │                                    └─ transport failure ──────────▶ error
///           ├─ on-demand ─▶ origin
///           └─ prefetch ──▶ error
/// ```
pub(crate) struct Dragonfly {
    /// The seed peer client of on-demand reads, retrying on the next seed peer.
    ondemand_client: SeedPeerClient,

    /// The seed peer client of prefetch reads, never retrying at once.
    prefetch_client: SeedPeerClient,

    /// The origin client of on-demand fallbacks, limited by
    /// `fallback_rate_limit`.
    fallback_http_client: Http,

    /// The random wait before a prefetch read is sent once more.
    prefetch_retry_interval: RangeInclusive<Duration>,

    /// The timeout of each attempt of a request.
    request_timeout: Duration,
}

/// Implements the Dragonfly transport.
impl Dragonfly {
    /// Creates the transport, sharing the seed peers under
    /// `<runtime_dir>/dragonfly`.
    pub(crate) fn new(
        config: DragonflyConfig,
        http: &HttpConfig,
        prefetch_retry_interval: Duration,
        runtime_dir: &Path,
        runtime_dir_mode: u32,
        runtime: &Runtime,
    ) -> io::Result<Self> {
        let dir = runtime_dir.join("dragonfly");
        DirBuilder::new()
            .recursive(true)
            .mode(runtime_dir_mode)
            .create(&dir)
            .map_err(|err| {
                io::Error::new(
                    err.kind(),
                    format!(
                        "failed to create dragonfly runtime directory {}: {err}",
                        dir.display()
                    ),
                )
            })?;

        let (ondemand_client, prefetch_client) = SeedPeerClient::clients(
            runtime,
            SeedPeerResolver::new(&dir, config.scheduler_endpoint.into()),
            config.max_retries as u8,
            config.request_timeout,
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
}

/// Implements the blob transport over the Dragonfly SDK.
#[async_trait]
impl Transport for Dragonfly {
    /// Fetches `url` through the on-demand client at `Level6`, falling back to
    /// the origin.
    async fn get(&self, url: &str, headers: HeaderMap) -> io::Result<Response> {
        let request = GetRequest {
            url: url.to_string(),
            header: headers.clone(),
            priority: Some(Priority::Level6 as i32),
            timeout: self.request_timeout,
            ..Default::default()
        };

        // Fall back to the origin while there is no seed peer.
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
        self.fallback_http_client.get(url, headers).await
    }

    /// Fetches `url` through the prefetch client at `Level3`, below normal
    /// peers, never touching the origin.
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

            // Serve a definitive answer, or the second transient one.
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

/// The connectivity state of a [`SeedPeerClient`], named after gRPC's, refer to
/// <https://github.com/grpc/grpc/blob/master/doc/connectivity-semantics-and-api.md>.
enum ConnectivityState {
    /// The first resolution is in progress.
    Connecting,

    /// The proxy serves the seed peers.
    Ready(ProxyWithSeedPeers),

    /// No seed peer is known.
    TransientFailure,
}

/// A client of the seed peers like gRPC's `ClientConn`.
///
/// ```text
/// Connecting ──┬─ seed peers ───────────────────────────────▶ Ready ──▶ seed peers updated at every resolution
///              └─ none, build or listing failure ──▶ TransientFailure
/// TransientFailure ── seed peers at a later resolution ──▶ Ready
/// Ready ── the scheduler lists none ──▶ TransientFailure
/// Ready ── listing alone fails ──▶ Ready with the seed peers known so far
/// ```
struct SeedPeerClient {
    /// The connectivity state the resolve task publishes.
    state: watch::Receiver<ConnectivityState>,

    /// The longest wait for the first resolution, unbounded when `None`.
    ready_timeout: Option<Duration>,
}

/// Implements the seed peer client.
impl SeedPeerClient {
    /// Creates the on-demand and prefetch clients, sharing one resolve task on
    /// `runtime`.
    fn clients(
        runtime: &Runtime,
        seed_peer_resolver: SeedPeerResolver,
        max_retries: u8,
        ready_timeout: Duration,
    ) -> (Self, Self) {
        let (ondemand_tx, ondemand_rx) = watch::channel(ConnectivityState::Connecting);
        let (prefetch_tx, prefetch_rx) = watch::channel(ConnectivityState::Connecting);
        runtime.spawn(async move {
            let mut clients = [
                (ondemand_tx, max_retries, None::<ProxyWithSeedPeers>),
                (prefetch_tx, 0, None),
            ];
            loop {
                let next_refresh_at = match seed_peer_resolver.resolve().await {
                    Ok(resolved) => {
                        let seed_peers = resolved.seed_peers();
                        for (tx, max_retries, proxy) in &mut clients {
                            if seed_peers.is_empty() {
                                // Serve no seed peer once the scheduler lists none.
                                *proxy = None;
                                tx.send_replace(ConnectivityState::TransientFailure);
                            } else if let Some(proxy) = proxy.as_ref() {
                                proxy.update_seed_peers(seed_peers.clone()).await;
                            } else {
                                match ProxyWithSeedPeers::builder()
                                    .seed_peers(seed_peers.clone())
                                    .max_retries(*max_retries)
                                    .backoff(ExponentialBuilder::default().with_jitter())
                                    .build()
                                    .await
                                {
                                    Ok(new_proxy) => {
                                        tx.send_replace(ConnectivityState::Ready(
                                            new_proxy.clone(),
                                        ));
                                        *proxy = Some(new_proxy);
                                    }
                                    Err(err) => {
                                        error!("failed to build dragonfly proxy: {err}");
                                        tx.send_replace(ConnectivityState::TransientFailure);
                                    }
                                }
                            }
                        }

                        resolved.next_refresh_at
                    }
                    Err(err) => {
                        error!("{err}, retrying in {:?}", SeedPeerResolver::RETRY_INTERVAL);

                        // Keep serving the seed peers known so far.
                        for (tx, _, proxy) in &mut clients {
                            if proxy.is_none() {
                                tx.send_replace(ConnectivityState::TransientFailure);
                            }
                        }

                        SystemTime::now() + SeedPeerResolver::RETRY_INTERVAL
                    }
                };

                // Resolve again when the seed peers are due, within a refresh
                // interval.
                let remaining = next_refresh_at
                    .duration_since(SystemTime::now())
                    .unwrap_or_default()
                    .min(SeedPeerResolver::REFRESH_INTERVAL);
                tokio::time::sleep(remaining).await;
            }
        });

        (
            Self {
                state: ondemand_rx,
                ready_timeout: Some(ready_timeout),
            },
            Self {
                state: prefetch_rx,
                ready_timeout: None,
            },
        )
    }

    /// Returns the proxy after the first resolution, failing on timeout or
    /// without a seed peer.
    async fn ready(&self) -> io::Result<ProxyWithSeedPeers> {
        let mut rx = self.state.clone();
        let loaded = rx.wait_for(|state| !matches!(state, ConnectivityState::Connecting));
        let state = match self.ready_timeout {
            Some(timeout) => tokio::time::timeout(timeout, loaded).await.map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("dragonfly seed peers not loaded within {timeout:?}"),
                )
            })?,
            None => loaded.await,
        }
        .map_err(|_| io::Error::other("dragonfly seed peer resolve task is gone"))?;

        match &*state {
            ConnectivityState::Ready(proxy) => Ok(proxy.clone()),
            _ => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "dragonfly proxy has no seed peer",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_config::default_runtime_dir_mode;
    use serde_json::json;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn seed_peers() -> serde_json::Value {
        json!([{
            "id": "seed-peer-0",
            "name": "seed-peer-0",
            "hostname": "seed-peer-0",
            "ip": "127.0.0.1",
            "port": 1,
            "proxy_port": 1,
            "healthy": true,
        }])
    }

    fn write_cache_file(dir: &Path, seed_peers: serde_json::Value, due_in: Duration) {
        let next_refresh_at =
            humantime_serde::re::humantime::format_rfc3339(SystemTime::now() + due_in);
        fs::write(
            dir.join("e87f700bacfeed52.v1.json"),
            json!({
                "scheduler_endpoint": "http://127.0.0.1:1/",
                "next_refresh_at": next_refresh_at.to_string(),
                "seed_peers": seed_peers,
            })
            .to_string(),
        )
        .unwrap();
    }

    #[test]
    fn new_creates_the_runtime_directory_with_its_mode() {
        let dir = tempdir().unwrap();
        let runtime_dir = dir.path().join("run");
        let config: DragonflyConfig =
            serde_yaml::from_str("scheduler_endpoint: http://127.0.0.1:1\n").unwrap();
        let runtime = Runtime::new(None).unwrap();

        Dragonfly::new(
            config,
            &HttpConfig::default(),
            Duration::from_secs(1),
            &runtime_dir,
            0o700,
            &runtime,
        )
        .unwrap();

        let metadata = fs::metadata(runtime_dir.join("dragonfly")).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn new_fails_when_the_runtime_directory_cannot_be_created() {
        let dir = tempdir().unwrap();
        let runtime_dir = dir.path().join("run");
        fs::write(&runtime_dir, b"").unwrap();
        let config: DragonflyConfig =
            serde_yaml::from_str("scheduler_endpoint: http://127.0.0.1:1\n").unwrap();
        let runtime = Runtime::new(None).unwrap();

        let err = Dragonfly::new(
            config,
            &HttpConfig::default(),
            Duration::from_secs(1),
            &runtime_dir,
            default_runtime_dir_mode(),
            &runtime,
        )
        .err()
        .unwrap();

        assert!(err.to_string().contains("dragonfly runtime directory"));
    }

    #[test]
    fn clients_serve_the_seed_peers_of_the_first_load() {
        let test_cases = vec![(seed_peers(), true), (json!([]), false)];

        for (seed_peers, ready) in test_cases {
            let dir = tempdir().unwrap();
            write_cache_file(dir.path(), seed_peers, Duration::from_secs(20));

            let runtime = Runtime::new(None).unwrap();
            let (ondemand_client, prefetch_client) = SeedPeerClient::clients(
                &runtime,
                SeedPeerResolver::new(dir.path(), "http://127.0.0.1:1/".to_string()),
                0,
                Duration::from_secs(5),
            );

            assert_eq!(
                runtime.tokio().block_on(ondemand_client.ready()).is_ok(),
                ready
            );
            assert_eq!(
                runtime.tokio().block_on(prefetch_client.ready()).is_ok(),
                ready
            );
        }
    }

    #[test]
    fn clients_drop_the_seed_peers_once_the_scheduler_lists_none() {
        let dir = tempdir().unwrap();
        write_cache_file(dir.path(), seed_peers(), Duration::from_secs(2));
        let runtime = Runtime::new(None).unwrap();
        let (ondemand_client, prefetch_client) = SeedPeerClient::clients(
            &runtime,
            SeedPeerResolver::new(dir.path(), "http://127.0.0.1:1/".to_string()),
            0,
            Duration::from_secs(5),
        );
        assert!(runtime.tokio().block_on(ondemand_client.ready()).is_ok());

        write_cache_file(dir.path(), json!([]), Duration::from_secs(20));

        for client in [ondemand_client, prefetch_client] {
            let mut state = client.state.clone();
            runtime
                .tokio()
                .block_on(async {
                    tokio::time::timeout(
                        Duration::from_secs(10),
                        state
                            .wait_for(|state| matches!(state, ConnectivityState::TransientFailure)),
                    )
                    .await
                    .unwrap()
                    .map(|_| ())
                })
                .unwrap();
        }
    }

    #[test]
    fn clients_keep_the_seed_peers_when_listing_alone_fails() {
        let dir = tempdir().unwrap();
        write_cache_file(dir.path(), seed_peers(), Duration::from_secs(2));
        let runtime = Runtime::new(None).unwrap();
        let (ondemand_client, prefetch_client) = SeedPeerClient::clients(
            &runtime,
            SeedPeerResolver::new(dir.path(), "http://127.0.0.1:1/".to_string()),
            0,
            Duration::from_secs(5),
        );
        assert!(runtime.tokio().block_on(ondemand_client.ready()).is_ok());

        let cache_file = dir.path().join("e87f700bacfeed52.v1.json");
        fs::remove_file(&cache_file).unwrap();
        fs::create_dir(&cache_file).unwrap();
        std::thread::sleep(Duration::from_secs(4));

        assert!(runtime.tokio().block_on(ondemand_client.ready()).is_ok());
        assert!(runtime.tokio().block_on(prefetch_client.ready()).is_ok());
    }

    #[tokio::test]
    async fn ready_waits_for_the_first_load() {
        let (tx, rx) = watch::channel(ConnectivityState::Connecting);
        let proxy = SeedPeerClient {
            state: rx,
            ready_timeout: None,
        };
        let ready = proxy.ready();
        tokio::pin!(ready);

        assert!(tokio::time::timeout(Duration::from_millis(100), &mut ready)
            .await
            .is_err());

        tx.send_replace(ConnectivityState::TransientFailure);
        assert!(matches!(ready.await, Err(err) if err.kind() == io::ErrorKind::NotConnected));
    }

    #[tokio::test]
    async fn ready_fails_at_once_without_seed_peers() {
        let (_tx, rx) = watch::channel(ConnectivityState::TransientFailure);
        let proxy = SeedPeerClient {
            state: rx,
            ready_timeout: None,
        };

        let err = proxy.ready().await.err().unwrap();

        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
    }

    #[tokio::test]
    async fn ready_fails_once_the_first_load_outlasts_the_ready_timeout() {
        let (_tx, rx) = watch::channel(ConnectivityState::Connecting);
        let proxy = SeedPeerClient {
            state: rx,
            ready_timeout: Some(Duration::from_millis(10)),
        };

        let err = proxy.ready().await.err().unwrap();

        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn ready_fails_when_the_load_task_is_gone() {
        let (_, rx) = watch::channel(ConnectivityState::Connecting);
        let proxy = SeedPeerClient {
            state: rx,
            ready_timeout: None,
        };

        let err = proxy.ready().await.err().unwrap();

        assert_eq!(err.kind(), io::ErrorKind::Other);
    }
}
