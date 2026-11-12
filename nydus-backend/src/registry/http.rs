//! The direct HTTP transport to the origin registry.

use std::fmt;
use std::io;
use std::ops::RangeInclusive;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::TryStreamExt;
use http::Extensions;
use leaky_bucket::RateLimiter;
use rand::Rng;
use reqwest::header::HeaderMap;
use reqwest::redirect::Policy;
use reqwest::{Certificate, Client, Request};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware, Middleware, Next};
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};
use tokio_util::io::StreamReader;
use tracing::{debug, warn};
use url::Url;

use nydus_config::{ProxyConfig, TlsConfig};

use super::redirect::without_query;
use super::response::{Body, Response};
use super::Transport;
use crate::Source;

/// The HTTP client of the origin registry.
///
/// ```text
/// GET ──▶ origin ──▶ 2xx / 3xx / 4xx ────────────────────────────────▶ handed back as is
///           │ 429 / 5xx / 408 / transport failure
///           ├─ again, max_retries times, exponential backoff
///           ├─ on-demand ─▶ error
///           └─ prefetch ──┬─ 429 / 5xx / 408 ─▶ once more after the retry interval ─▶ error
///                         └─ transport failure ───────────────────────────▶ error
/// ```
#[derive(Clone)]
pub(crate) struct Http {
    /// The reqwest client behind the retry and rate limit middleware.
    client: ClientWithMiddleware,

    /// The random wait before a prefetch read is sent once more.
    prefetch_retry_interval: RangeInclusive<Duration>,

    /// Where the client's answers come from, the `source` label of its reads.
    source: Source,
}

/// Implements the origin HTTP client.
impl Http {
    /// Creates a client, through `proxy` and limited by `rate_limit` when
    /// given.
    pub(crate) fn new(
        request_timeout: Duration,
        max_retries: u32,
        proxy: Option<&ProxyConfig>,
        tls: &TlsConfig,
        prefetch_retry_interval: Duration,
        rate_limit: Option<RateLimit>,
        source: Source,
    ) -> io::Result<Self> {
        // Return redirects so the caller caches them, and keep rustls even when
        // another crate enables reqwest's `default-tls`. Speak HTTP/1.1 even
        // when another crate enables reqwest's `http2`: a request that times
        // out closes its HTTP/1.1 connection, while an HTTP/2 connection the
        // network dropped silently stays pooled, and every read fails on it
        // until TCP gives up minutes later.
        let mut builder = Client::builder()
            .use_rustls_tls()
            .http1_only()
            .redirect(Policy::none())
            .hickory_dns(true);

        builder = match proxy {
            Some(proxy) => builder.proxy(reqwest::Proxy::all(&proxy.addr).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid proxy addr {}: {err}", proxy.addr),
                )
            })?),
            None => builder.no_proxy(),
        };

        builder = builder
            .timeout(request_timeout)
            .connect_timeout(request_timeout);

        if tls.skip_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }

        if let Some(certs) = tls.load_ca_cert_der().map_err(io::Error::other)? {
            for cert in certs {
                builder = builder
                    .add_root_certificate(Certificate::from_der(&cert).map_err(io::Error::other)?);
            }
        }
        let client = builder.build().map_err(io::Error::other)?;

        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(max_retries);
        let mut client = ClientBuilder::new(client)
            .with(RetryTransientMiddleware::new_with_policy(retry_policy));

        if let Some(rate_limit) = rate_limit {
            client = client.with(rate_limit);
        }

        Ok(Self {
            client: client.build(),
            prefetch_retry_interval: prefetch_retry_interval
                ..=prefetch_retry_interval.saturating_mul(2),
            source,
        })
    }

    /// Returns where the client's answers come from.
    pub(crate) fn source(&self) -> Source {
        self.source
    }
}

/// The failure of a request and its causes, their messages naming the request
/// URL without its query.
#[derive(Debug)]
struct RequestError {
    /// The message of the error, the query removed.
    message: String,

    /// The cause of the error.
    source: Option<Box<RequestError>>,
}

/// Implements the request error.
impl RequestError {
    /// Copies `err` and its cause chain, removing `query` from the messages.
    fn new(err: &(dyn std::error::Error + 'static), query: &str) -> Self {
        Self {
            message: err.to_string().replace(query, ""),
            source: err
                .source()
                .map(|source| Box::new(Self::new(source, query))),
        }
    }
}

/// Implements the message of the request error.
impl fmt::Display for RequestError {
    /// Writes the message.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// Implements the cause chain of the request error.
impl std::error::Error for RequestError {
    /// Returns the cause of the error.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

/// Converts the failure of the request to `url` into an I/O error that names
/// the URL without its query.
fn request_error(url: &str, err: reqwest_middleware::Error) -> io::Error {
    let query = Url::parse(url)
        .ok()
        .and_then(|url| url.query().map(|query| format!("?{query}")));
    match query {
        Some(query) => io::Error::other(RequestError::new(&err, &query)),
        None => io::Error::other(err),
    }
}

/// Implements the blob transport over the origin HTTP client.
#[async_trait]
impl Transport for Http {
    /// Sends the `GET` of an on-demand read, the body left streaming.
    async fn get(&self, url: &str, headers: HeaderMap) -> io::Result<Response> {
        let start = Instant::now();
        let result = self
            .client
            .get(url)
            .headers(headers)
            .send()
            .await
            .map(|response| Response {
                status: response.status(),
                headers: response.headers().clone(),
                body: Body::Stream(Box::new(StreamReader::new(
                    response.bytes_stream().map_err(io::Error::other),
                ))),
                source: self.source,
            })
            .map_err(|err| request_error(url, err));

        let url = without_query(url);
        match &result {
            Ok(response) => debug!(
                "GET {url} (ondemand) from the origin returned {} in {:?}",
                response.status,
                start.elapsed()
            ),
            Err(err) => debug!(
                "GET {url} (ondemand) from the origin failed in {:?}: {err}",
                start.elapsed()
            ),
        }
        result
    }

    /// Sends the `GET` of a prefetch read, the body left streaming.
    async fn prefetch(&self, url: &str, headers: HeaderMap) -> io::Result<Response> {
        let mut retried = false;
        loop {
            let start = Instant::now();
            let result = self
                .client
                .get(url)
                .headers(headers.clone())
                .send()
                .await
                .map(|response| Response {
                    status: response.status(),
                    headers: response.headers().clone(),
                    body: Body::Stream(Box::new(StreamReader::new(
                        response.bytes_stream().map_err(io::Error::other),
                    ))),
                    source: self.source,
                })
                .map_err(|err| request_error(url, err));

            match &result {
                Ok(response) => debug!(
                    "GET {} (prefetch) from the origin returned {} in {:?}",
                    without_query(url),
                    response.status,
                    start.elapsed()
                ),
                Err(err) => debug!(
                    "GET {} (prefetch) from the origin failed in {:?}: {err}",
                    without_query(url),
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
            warn!("origin request failed, retrying in {delay:?}: {err}");
            tokio::time::sleep(delay).await;
            retried = true;
        }
    }
}

/// A fair leaky bucket of one slot per attempt, inside the retry middleware.
pub(crate) struct RateLimit {
    /// The request rate limiter.
    limiter: RateLimiter,
}

/// Implements the rate limit.
impl RateLimit {
    /// Creates a limit of `request_rate_limit` requests per `interval`, both
    /// at least one.
    #[cfg(feature = "dragonfly")]
    pub(crate) fn new(request_rate_limit: u64, interval: Duration) -> Self {
        Self {
            limiter: RateLimiter::builder()
                .initial(request_rate_limit as usize)
                .refill(request_rate_limit as usize)
                .max(request_rate_limit as usize)
                .interval(interval)
                .fair(true)
                .build(),
        }
    }
}

/// Implements the rate limit as a reqwest middleware.
#[async_trait]
impl Middleware for RateLimit {
    /// Claims a slot, then runs the request.
    async fn handle(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        self.limiter.acquire_one().await;
        next.run(req, extensions).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::CertifiedKey;
    use std::fs;
    use std::net::TcpListener;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio_rustls::rustls::crypto::ring;
    use tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer;
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::TlsAcceptor;

    #[tokio::test]
    async fn prefetch_fails_at_once_on_a_transport_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/blob", listener.local_addr().unwrap());
        drop(listener);
        let retry_interval = Duration::from_secs(60 * 60);
        let http = Http::new(
            Duration::from_secs(5),
            0,
            None,
            &TlsConfig::default(),
            retry_interval,
            None,
            Source::Origin,
        )
        .unwrap();

        let start = Instant::now();
        let message = http
            .prefetch(&format!("{url}?sig=secret"), HeaderMap::new())
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(start.elapsed() < retry_interval);
        assert!(message.contains(&url), "{message}");
        assert!(!message.contains("secret"), "{message}");
    }

    #[cfg(feature = "dragonfly")]
    #[test]
    fn new_accepts_an_optional_rate_limit() {
        let tls = TlsConfig::default();
        assert!(Http::new(
            Duration::from_secs(5),
            3,
            None,
            &tls,
            Duration::from_secs(1),
            None,
            Source::Origin,
        )
        .is_ok());
        assert!(Http::new(
            Duration::from_secs(5),
            3,
            None,
            &tls,
            Duration::from_secs(1),
            Some(RateLimit::new(10, Duration::from_secs(1))),
            Source::Origin,
        )
        .is_ok());
    }

    #[cfg(feature = "dragonfly")]
    #[test]
    fn new_fills_a_fair_bucket_to_the_limit() {
        let limit = RateLimit::new(10, Duration::from_millis(100));
        assert_eq!(limit.limiter.max(), 10);
        assert_eq!(limit.limiter.refill(), 10);
        assert_eq!(limit.limiter.balance(), 10);
        assert_eq!(limit.limiter.interval(), Duration::from_millis(100));
        assert!(limit.limiter.is_fair());
    }

    /// Starts an HTTPS server that offers HTTP/2 before HTTP/1.1 and answers
    /// in HTTP/1.1, returning its URL and the protocol of each connection.
    async fn start_https_server(
        cert: CertifiedKey,
    ) -> (String, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) {
        let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
            )
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (protocols_tx, protocols) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                let protocols_tx = protocols_tx.clone();
                tokio::spawn(async move {
                    let Ok(stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let protocol = stream.get_ref().1.alpn_protocol().unwrap_or_default();
                    let _ = protocols_tx.send(protocol.to_vec());
                    let mut stream = BufReader::new(stream);
                    let mut line = String::new();
                    while stream.read_line(&mut line).await.unwrap() > 2 {
                        line.clear();
                    }
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                        )
                        .await
                        .unwrap();
                    stream.flush().await.unwrap();
                });
            }
        });

        (format!("https://{addr}/"), protocols)
    }

    #[tokio::test]
    async fn new_speaks_http1_to_a_server_that_offers_http2() {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let (url, mut protocols) = start_https_server(cert).await;
        let http = Http::new(
            Duration::from_secs(5),
            0,
            None,
            &TlsConfig {
                skip_verify: true,
                ca_cert: None,
            },
            Duration::from_secs(1),
            None,
            Source::Origin,
        )
        .unwrap();

        assert!(http
            .get(&url, HeaderMap::new())
            .await
            .unwrap()
            .status
            .is_success());
        assert_ne!(protocols.recv().await.unwrap(), b"h2");
    }

    #[tokio::test]
    async fn new_trusts_the_ca_cert_or_skips_verification() {
        let dir = tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let wrong_cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let ca_cert = dir.path().join("ca.pem");
        let wrong_ca_cert = dir.path().join("wrong_ca.pem");
        fs::write(&ca_cert, cert.cert.pem()).unwrap();
        fs::write(&wrong_ca_cert, wrong_cert.cert.pem()).unwrap();
        let test_cases = vec![
            (false, Some(ca_cert), true),
            (false, Some(wrong_ca_cert), false),
            (false, None, false),
            (true, None, true),
        ];

        let (url, _protocols) = start_https_server(cert).await;
        for (skip_verify, ca_cert, expected) in test_cases {
            let http = Http::new(
                Duration::from_secs(5),
                0,
                None,
                &TlsConfig {
                    skip_verify,
                    ca_cert,
                },
                Duration::from_secs(1),
                None,
                Source::Origin,
            )
            .unwrap();
            assert_eq!(http.get(&url, HeaderMap::new()).await.is_ok(), expected);
        }
    }
}
