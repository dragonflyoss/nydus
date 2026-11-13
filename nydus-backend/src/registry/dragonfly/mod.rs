//! The Dragonfly SDK transport, feature `dragonfly`.

mod seed_peer_resolver;

use std::fs::DirBuilder;
use std::io;
use std::ops::RangeInclusive;
use std::os::unix::fs::DirBuilderExt;
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use bytes::Bytes;
use futures::{stream, StreamExt, TryStreamExt};
use rand::Rng;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, RANGE};
use reqwest::StatusCode;
use tokio::sync::watch;
use tracing::{debug, error, warn};

use dragonfly_api::common::v2::Priority;
use dragonfly_client_request::errors::{BackendError, DfdaemonError, Error, ProxyError};
use dragonfly_client_request::{
    ExponentialBuilder, GetRequest, GetResponse, ProxyWithSeedPeers, RequestWithSeedPeers as _,
};

use nydus_config::{BackendConfig, Config};

use super::http::{Http, RateLimit};
use super::range::Range;
use super::response::Response;
use super::rt::Runtime;
use super::Transport;

use self::seed_peer_resolver::SeedPeerResolver;

/// The Dragonfly transport, one [`SeedPeerClient`] per read kind.
///
/// ```text
/// GET ──▶ wait for the client ──▶ seed peer ──▶ 2xx / 3xx / 4xx ──────▶ handed back as is
///           │                      │            └─ on-demand body breaks off ─▶ SDK: the next seed peer
///           │ no seed peer         │ 429 / 5xx / 408 / transport failure
///           │                      ├─ on-demand ─▶ next seed peer, max_retries times ─▶ origin
///           │                      └─ prefetch ──┬─ 429 / 5xx / 408 ─▶ once more ─▶ error
///           │                                    └─ transport failure ──────────▶ error
///           ├─ on-demand ─▶ origin
///           └─ prefetch ──▶ wait for a seed peer, within the prefetch request timeout
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
    /// Creates the transport the registry backend of `config` configures,
    /// sharing the seed peers under `<runtime_dir>/dragonfly`.
    pub(crate) fn new(config: &Config, runtime: &Runtime) -> io::Result<Self> {
        let dir = config.runtime_dir.join("dragonfly");
        DirBuilder::new()
            .recursive(true)
            .mode(0o755)
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

        let (http, dragonfly) = match &config.backend {
            BackendConfig::Registry(registry) => registry
                .dragonfly
                .as_ref()
                .map(|dragonfly| (&registry.http, dragonfly)),
            BackendConfig::Local(_) => None,
        }
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "backend has no dragonfly configuration",
            )
        })?;

        let (ondemand_client, prefetch_client) = SeedPeerClient::clients(
            runtime,
            SeedPeerResolver::new(&dir, dragonfly.scheduler_endpoint.to_string()),
            dragonfly.max_retries as u8,
            dragonfly.request_timeout,
            config.prefetch.request_timeout,
        );
        Ok(Self {
            ondemand_client,
            prefetch_client,
            fallback_http_client: Http::new(
                http.request_timeout,
                http.max_retries,
                http.proxy.as_ref(),
                &http.tls,
                config.prefetch.retry_interval,
                Some(RateLimit::new(
                    dragonfly.fallback_rate_limit,
                    Duration::from_secs(1),
                )),
            )?,
            request_timeout: dragonfly.request_timeout,
            prefetch_retry_interval: config.prefetch.retry_interval
                ..=config.prefetch.retry_interval.saturating_mul(2),
        })
    }

    /// Converts the SDK answer to a `GET` into a response, an SDK error with
    /// an HTTP status included.
    fn response(result: dragonfly_client_request::Result<GetResponse>) -> io::Result<Response> {
        match result {
            Ok(response) => Ok(Response {
                status: response.status_code.unwrap_or(StatusCode::OK),
                headers: response.header,
                body: match response.body {
                    Some(body) => body
                        .map_err(|err| match err {
                            Error::RequestTimeout(message) => io::Error::new(
                                io::ErrorKind::TimedOut,
                                format!("dragonfly request timed out: {message}"),
                            ),
                            err => io::Error::other(format!("dragonfly error: {err}")),
                        })
                        .boxed(),
                    None => stream::empty().boxed(),
                },
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
                body: stream::iter([Ok(Bytes::from(message.unwrap_or_default()))]).boxed(),
            }),
            Err(Error::RequestTimeout(message)) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("dragonfly request timed out: {message}"),
            )),
            Err(err) => Err(io::Error::other(format!("dragonfly error: {err}"))),
        }
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
        let client = match self.ondemand_client.ready().await {
            Ok(client) => client,
            Err(err) => {
                warn!("dragonfly request failed, falling back to the origin: {err}");
                return self.fallback_http_client.get(url, headers).await;
            }
        };

        let now = Instant::now();
        let result = Self::response(client.get(&request).await);

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
                now.elapsed()
            ),
            Err(err) => debug!(
                "GET {url} (ondemand) through dragonfly failed in {:?}: {err}",
                now.elapsed()
            ),
        }

        // Serve a definitive answer, fall back to the origin on anything else.
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
            let now = Instant::now();
            let result = Self::response(client.get(&request).await);

            match &result {
                Ok(response) => debug!(
                    "GET {url} (prefetch) through dragonfly returned {} in {:?}",
                    response.status,
                    now.elapsed()
                ),
                Err(err) => debug!(
                    "GET {url} (prefetch) through dragonfly failed in {:?}: {err}",
                    now.elapsed()
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
/// Connecting ──┬─ seed peers ─────────────────────▶ Ready ──▶ seed peers updated at every resolution
///              └─ none, or a build or listing failure ──▶ TransientFailure
/// TransientFailure ── seed peers at a later resolution ──▶ Ready
/// Ready ── none, or a listing failure ──▶ Ready with the seed peers known so far
/// ```
struct SeedPeerClient {
    /// The connectivity state the resolve task publishes.
    state: watch::Receiver<ConnectivityState>,

    /// The longest wait for the proxy.
    ready_timeout: Duration,

    /// Whether to wait through `TransientFailure` until `Ready` rather than
    /// fail fast, like grpc-go's `WaitForReady` call option.
    wait_for_ready: bool,
}

/// Implements the seed peer client.
impl SeedPeerClient {
    /// Creates the on-demand client, failing fast without a seed peer, and the
    /// prefetch client, waiting for one, sharing one resolve task on `runtime`.
    fn clients(
        runtime: &Runtime,
        seed_peer_resolver: SeedPeerResolver,
        max_retries: u8,
        ondemand_ready_timeout: Duration,
        prefetch_ready_timeout: Duration,
    ) -> (Self, Self) {
        let (ondemand_tx, ondemand_rx) = watch::channel(ConnectivityState::Connecting);
        let (prefetch_tx, prefetch_rx) = watch::channel(ConnectivityState::Connecting);
        runtime.spawn(async move {
            let mut clients = [
                (ondemand_tx, max_retries, None::<ProxyWithSeedPeers>),
                (prefetch_tx, 0, None),
            ];
            loop {
                let resolved = seed_peer_resolver.resolve().await.and_then(|resolved| {
                    let seed_peers = resolved.seed_peers();
                    if seed_peers.is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            "no dragonfly seed peer resolved",
                        ));
                    }

                    Ok((seed_peers, resolved.next_refresh_at))
                });

                let next_refresh_at = match resolved {
                    Ok((seed_peers, next_refresh_at)) => {
                        for (tx, max_retries, proxy) in &mut clients {
                            if let Some(proxy) = proxy.as_ref() {
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

                        next_refresh_at
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
                ready_timeout: ondemand_ready_timeout,
                wait_for_ready: false,
            },
            Self {
                state: prefetch_rx,
                ready_timeout: prefetch_ready_timeout,
                wait_for_ready: true,
            },
        )
    }

    /// Returns the proxy once the seed peers are resolved, failing on timeout,
    /// or at once without a seed peer unless waiting for ready.
    async fn ready(&self) -> io::Result<ProxyWithSeedPeers> {
        let mut rx = self.state.clone();
        let resolved = rx.wait_for(|state| match state {
            ConnectivityState::Connecting => false,
            ConnectivityState::Ready(_) => true,
            ConnectivityState::TransientFailure => !self.wait_for_ready,
        });
        let state = tokio::time::timeout(self.ready_timeout, resolved)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("dragonfly proxy not ready within {:?}", self.ready_timeout),
                )
            })?
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
    use dragonfly_api::common::v2::Host;
    use dragonfly_client_request::SeedPeer;
    use serde_json::json;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
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

    fn dragonfly_config(runtime_dir: &Path) -> Config {
        serde_yaml::from_str(&format!(
            "runtime_dir: {}\nbackend:\n  type: registry\n  config:\n    addr: http://127.0.0.1:5000\n    repository: library/ubuntu\n    dragonfly:\n      scheduler_endpoint: http://127.0.0.1:1\n",
            runtime_dir.display()
        ))
        .unwrap()
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
    fn new_creates_the_runtime_directory_unwritable_by_others() {
        let dir = tempdir().unwrap();
        let runtime_dir = dir.path().join("run");
        let runtime = Runtime::new(None).unwrap();

        Dragonfly::new(&dragonfly_config(&runtime_dir), &runtime).unwrap();

        for dir in [runtime_dir.clone(), runtime_dir.join("dragonfly")] {
            let metadata = fs::metadata(dir).unwrap();
            assert!(metadata.is_dir());
            assert_eq!(metadata.permissions().mode() & 0o022, 0);
        }
    }

    #[test]
    fn new_fails_when_the_runtime_directory_cannot_be_created() {
        let dir = tempdir().unwrap();
        let runtime_dir = dir.path().join("run");
        fs::write(&runtime_dir, b"").unwrap();
        let runtime = Runtime::new(None).unwrap();

        let err = Dragonfly::new(&dragonfly_config(&runtime_dir), &runtime)
            .err()
            .unwrap();

        assert!(err.to_string().contains("dragonfly runtime directory"));
    }

    #[tokio::test]
    async fn response_reports_a_body_that_times_out_as_timed_out() {
        let test_cases = vec![
            (
                Error::RequestTimeout("deadline".to_string()),
                io::ErrorKind::TimedOut,
            ),
            (Error::Internal("reset".to_string()), io::ErrorKind::Other),
        ];

        for (err, expected) in test_cases {
            let response = Dragonfly::response(Ok(GetResponse {
                success: true,
                header: HeaderMap::new(),
                status_code: Some(StatusCode::PARTIAL_CONTENT),
                body: Some(Box::new(stream::iter([Err(err)]))),
            }))
            .unwrap();

            assert_eq!(response.bytes(4).await.unwrap_err().kind(), expected);
        }
    }

    #[test]
    fn clients_serve_the_seed_peers_of_the_first_load() {
        let test_cases = vec![
            (seed_peers(), Ok(()), Ok(())),
            (
                json!([]),
                Err(io::ErrorKind::NotConnected),
                Err(io::ErrorKind::TimedOut),
            ),
        ];

        for (seed_peers, ondemand_ready, prefetch_ready) in test_cases {
            let dir = tempdir().unwrap();
            write_cache_file(dir.path(), seed_peers, Duration::from_secs(20));

            let runtime = Runtime::new(None).unwrap();
            let (ondemand_client, prefetch_client) = SeedPeerClient::clients(
                &runtime,
                SeedPeerResolver::new(dir.path(), "http://127.0.0.1:1/".to_string()),
                0,
                Duration::from_secs(5),
                Duration::from_millis(100),
            );

            assert_eq!(
                runtime
                    .tokio()
                    .block_on(ondemand_client.ready())
                    .map(|_| ())
                    .map_err(|err| err.kind()),
                ondemand_ready
            );
            assert_eq!(
                runtime
                    .tokio()
                    .block_on(prefetch_client.ready())
                    .map(|_| ())
                    .map_err(|err| err.kind()),
                prefetch_ready
            );
        }
    }

    #[test]
    fn clients_keep_the_seed_peers_when_none_resolve() {
        let test_cases: Vec<fn(&Path)> = vec![
            |dir| write_cache_file(dir, json!([]), Duration::from_secs(20)),
            |dir| fs::remove_file(dir.join("e87f700bacfeed52.v1.json")).unwrap(),
            |dir| {
                let cache_file = dir.join("e87f700bacfeed52.v1.json");
                fs::remove_file(&cache_file).unwrap();
                fs::create_dir(&cache_file).unwrap();
            },
        ];

        for lose_seed_peers in test_cases {
            let dir = tempdir().unwrap();
            write_cache_file(dir.path(), seed_peers(), Duration::from_secs(1));
            let runtime = Runtime::new(None).unwrap();
            let (ondemand_client, prefetch_client) = SeedPeerClient::clients(
                &runtime,
                SeedPeerResolver::new(dir.path(), "http://127.0.0.1:1/".to_string()),
                0,
                Duration::from_secs(5),
                Duration::from_secs(5),
            );
            assert!(runtime.tokio().block_on(ondemand_client.ready()).is_ok());

            lose_seed_peers(dir.path());
            std::thread::sleep(Duration::from_secs(3));

            assert!(runtime.tokio().block_on(ondemand_client.ready()).is_ok());
            assert!(runtime.tokio().block_on(prefetch_client.ready()).is_ok());
        }
    }

    #[tokio::test]
    async fn ready_waits_for_the_first_load() {
        let (tx, rx) = watch::channel(ConnectivityState::Connecting);
        let proxy = SeedPeerClient {
            state: rx,
            ready_timeout: Duration::from_secs(60),
            wait_for_ready: false,
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
            ready_timeout: Duration::from_secs(60),
            wait_for_ready: false,
        };

        let err = proxy.ready().await.err().unwrap();

        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
    }

    #[tokio::test]
    async fn ready_fails_once_the_proxy_outlasts_the_ready_timeout() {
        let test_cases = vec![
            (ConnectivityState::Connecting, false),
            (ConnectivityState::TransientFailure, true),
        ];

        for (state, wait_for_ready) in test_cases {
            let (_tx, rx) = watch::channel(state);
            let proxy = SeedPeerClient {
                state: rx,
                ready_timeout: Duration::from_millis(10),
                wait_for_ready,
            };

            let err = proxy.ready().await.err().unwrap();

            assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        }
    }

    #[tokio::test]
    async fn ready_waits_through_a_transient_failure_when_waiting_for_ready() {
        let (tx, rx) = watch::channel(ConnectivityState::TransientFailure);
        let proxy = SeedPeerClient {
            state: rx,
            ready_timeout: Duration::from_secs(60),
            wait_for_ready: true,
        };
        let ready = proxy.ready();
        tokio::pin!(ready);

        assert!(tokio::time::timeout(Duration::from_millis(100), &mut ready)
            .await
            .is_err());

        tx.send_replace(ConnectivityState::Ready(
            ProxyWithSeedPeers::builder()
                .seed_peers(vec![SeedPeer {
                    host: Host {
                        name: "seed-peer-0".to_string(),
                        ip: "127.0.0.1".to_string(),
                        port: 1,
                        proxy_port: 1,
                        ..Default::default()
                    },
                    healthy: true,
                }])
                .build()
                .await
                .unwrap(),
        ));
        assert!(ready.await.is_ok());
    }

    #[tokio::test]
    async fn ready_fails_when_the_load_task_is_gone() {
        let (_, rx) = watch::channel(ConnectivityState::Connecting);
        let proxy = SeedPeerClient {
            state: rx,
            ready_timeout: Duration::from_secs(60),
            wait_for_ready: false,
        };

        let err = proxy.ready().await.err().unwrap();

        assert_eq!(err.kind(), io::ErrorKind::Other);
    }
}
