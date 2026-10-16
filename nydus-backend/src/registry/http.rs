//! The direct HTTP transport to the origin registry.

use std::io;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
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

use nydus_config::HttpConfig;

use super::response::{Body, Response};
use super::{Transport, PREFETCH_RETRY_DELAY};
use crate::Protocol;

/// An HTTP client talking straight to the origin registry.
///
/// Its middleware stack retries transient failures with exponential backoff
/// and, when built with a [`RateLimit`], claims a slot before every attempt.
///
/// ```text
/// request ──▶ RetryTransientMiddleware ──▶ RateLimit ──▶ reqwest::Client ──▶ origin
///                 │                          │
///                 └── retry ─────────────────┘  every attempt claims its own slot
/// ```
#[derive(Clone)]
pub(crate) struct Http {
    /// The reqwest client behind the retry and rate limit middleware.
    client: ClientWithMiddleware,
}

/// Implements the origin HTTP client.
impl Http {
    /// Creates a client from the HTTP configuration, every attempt claiming a
    /// slot from `rate_limit` first when one is given.
    ///
    /// Requests go through the configured proxy or, without one, straight to
    /// the origin with any ambient proxy ignored. Names are resolved by
    /// hickory, which caches lookups and honours record TTLs. Redirects are
    /// returned rather than followed so the caller can cache the signed URL a
    /// blob `GET` is redirected to. Transient failures are retried up to the
    /// configured `max_retries`.
    pub(crate) fn new(config: &HttpConfig, rate_limit: Option<RateLimit>) -> io::Result<Self> {
        let mut builder = Client::builder().redirect(Policy::none()).hickory_dns(true);

        // Route through the configured proxy, or ignore any ambient one.
        builder = match &config.proxy {
            Some(proxy) => builder.proxy(reqwest::Proxy::all(&proxy.addr).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid proxy addr {}: {err}", proxy.addr),
                )
            })?),
            None => builder.no_proxy(),
        };

        // Bound each request and its connect by the configured timeout.
        builder = builder
            .timeout(config.request_timeout)
            .connect_timeout(config.request_timeout);

        // Apply the TLS settings.
        if config.tls.skip_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }

        if let Some(certs) = config.tls.load_ca_cert_der().map_err(io::Error::other)? {
            for cert in certs {
                builder = builder
                    .add_root_certificate(Certificate::from_der(&cert).map_err(io::Error::other)?);
            }
        }
        let client = builder.build().map_err(io::Error::other)?;

        // Retry transient failures, every attempt claiming a rate limit slot first.
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(config.max_retries);
        let mut client = ClientBuilder::new(client)
            .with(RetryTransientMiddleware::new_with_policy(retry_policy));

        if let Some(rate_limit) = rate_limit {
            client = client.with(rate_limit);
        }

        Ok(Self {
            client: client.build(),
        })
    }
}

/// Implements the blob transport over the origin HTTP client.
#[async_trait]
impl Transport for Http {
    /// Sends a `HEAD` to `url` with `headers` and logs the outcome.
    async fn head(&self, url: &str, headers: HeaderMap) -> io::Result<Response> {
        let start = Instant::now();
        let result = self
            .client
            .head(url)
            .headers(headers)
            .send()
            .await
            .map(|response| Response {
                status: response.status(),
                headers: response.headers().clone(),
                body: Body::Bytes(Bytes::new()),
                protocol: Protocol::Http,
            })
            .map_err(io::Error::other);

        match &result {
            Ok(response) => debug!(
                "HEAD {url} from the origin returned {} in {:?}",
                response.status,
                start.elapsed()
            ),
            Err(err) => debug!(
                "HEAD {url} from the origin failed in {:?}: {err}",
                start.elapsed()
            ),
        }
        result
    }

    /// Sends the `GET` of an on-demand read to `url` with `headers`, the body
    /// left streaming, and logs the outcome.
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
                protocol: Protocol::Http,
            })
            .map_err(io::Error::other);

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

    /// Sends the `GET` of a prefetch read to `url` with `headers`, the body
    /// left streaming, and logs the outcome; a `429`, `5xx` or `408` the
    /// retry middleware did not cure is sent once more after a random delay
    /// of hours, a transport failure fails the read at once.
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
                    protocol: Protocol::Http,
                })
                .map_err(io::Error::other);

            match &result {
                Ok(response) => debug!(
                    "GET {url} (prefetch) from the origin returned {} in {:?}",
                    response.status,
                    start.elapsed()
                ),
                Err(err) => debug!(
                    "GET {url} (prefetch) from the origin failed in {:?}: {err}",
                    start.elapsed()
                ),
            }

            // Serve a definitive answer, or the second transient one.
            let response = result?;
            if !response.needs_fallback() || retried {
                return Ok(response);
            }

            // Retry once after a random delay of hours.
            let err = response.into_io_error().await;
            let delay = rand::rng().random_range(PREFETCH_RETRY_DELAY);
            warn!("origin request failed, retrying in {delay:?}: {err}");
            tokio::time::sleep(delay).await;
            retried = true;
        }
    }
}

/// A fair leaky bucket handing out one slot per request, the limiter dfdaemon
/// puts in front of its own proxy.
///
/// As a middleware it sits inside the retry middleware so every retry attempt
/// waits for its own slot.
pub(crate) struct RateLimit {
    /// The request rate limiter.
    limiter: RateLimiter,
}

/// Implements the rate limit.
impl RateLimit {
    /// Creates a limit of `request_rate_limit` requests per `interval`, both
    /// at least one.
    #[cfg_attr(not(feature = "dragonfly"), allow(dead_code))]
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

    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::thread;

    use reqwest::StatusCode;

    fn origin(statuses: &'static [&'static str]) -> (String, Arc<AtomicU32>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/blob", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicU32::new(0));
        let served = hits.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                while !buf.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(1) => buf.push(byte[0]),
                        _ => break,
                    }
                }
                let hit = served.fetch_add(1, Ordering::SeqCst) as usize;
                let status = statuses[hit.min(statuses.len() - 1)];
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                    )
                    .as_bytes(),
                );
            }
        });
        (url, hits)
    }

    #[tokio::test]
    async fn prefetch_retries_a_transient_failure_once_after_the_delay() {
        let test_cases = vec![
            (
                &["503 Service Unavailable", "200 OK"][..],
                StatusCode::OK,
                2,
            ),
            (
                &["429 Too Many Requests", "404 Not Found"][..],
                StatusCode::NOT_FOUND,
                2,
            ),
            (
                &["503 Service Unavailable"][..],
                StatusCode::SERVICE_UNAVAILABLE,
                2,
            ),
            (&["404 Not Found"][..], StatusCode::NOT_FOUND, 1),
        ];

        for (statuses, expected, expected_hits) in test_cases {
            let (url, hits) = origin(statuses);
            let config = HttpConfig {
                max_retries: 0,
                ..Default::default()
            };
            let http = Http::new(&config, None).unwrap();

            let start = Instant::now();
            let response = http.prefetch(&url, HeaderMap::new()).await.unwrap();

            assert_eq!(response.status, expected, "{statuses:?}");
            assert_eq!(hits.load(Ordering::SeqCst), expected_hits, "{statuses:?}");
            if expected_hits == 2 {
                assert!(
                    start.elapsed() >= *PREFETCH_RETRY_DELAY.start(),
                    "{statuses:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn prefetch_fails_at_once_on_a_transport_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/blob", listener.local_addr().unwrap());
        drop(listener);
        let config = HttpConfig {
            max_retries: 0,
            ..Default::default()
        };
        let http = Http::new(&config, None).unwrap();

        let start = Instant::now();
        assert!(http.prefetch(&url, HeaderMap::new()).await.is_err());
        assert!(start.elapsed() < *PREFETCH_RETRY_DELAY.start());
    }

    #[test]
    fn new_accepts_an_optional_rate_limit() {
        let config = HttpConfig::default();
        assert!(Http::new(&config, None).is_ok());
        assert!(Http::new(&config, Some(RateLimit::new(10, Duration::from_secs(1)))).is_ok());
    }

    #[test]
    fn new_fills_a_fair_bucket_to_the_limit() {
        let limit = RateLimit::new(10, Duration::from_millis(100));
        assert_eq!(limit.limiter.max(), 10);
        assert_eq!(limit.limiter.refill(), 10);
        assert_eq!(limit.limiter.balance(), 10);
        assert_eq!(limit.limiter.interval(), Duration::from_millis(100));
        assert!(limit.limiter.is_fair());
    }
}
