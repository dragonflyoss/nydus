//! The direct HTTP transport to the origin registry.

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

use nydus_config::{ProxyConfig, TlsConfig};

use super::response::{Body, Response};
use super::Transport;
use crate::Source;

/// An HTTP client talking straight to the origin registry, every attempt
/// claiming a [`RateLimit`] slot first when built with one.
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

    /// The window of the random interval before a prefetch read is sent once
    /// more, the configured interval up to twice that.
    prefetch_retry_interval: RangeInclusive<Duration>,

    /// Where the client's answers come from, the `source` label of its reads.
    source: Source,
}

/// Implements the origin HTTP client.
impl Http {
    /// Creates a client timing every request out after `request_timeout`,
    /// retrying it `max_retries` times, reaching the origin through `proxy`
    /// when one is given and trusting it as `tls` says, sending a failed
    /// prefetch read once more after `prefetch_retry_interval` and every
    /// attempt claiming a slot from `rate_limit` first when one is given;
    /// its answers are labelled `source`.
    ///
    /// Redirects are returned rather than followed so the caller can cache
    /// the signed URL a blob `GET` is redirected to; names are resolved by
    /// hickory, which honours record TTLs.
    pub(crate) fn new(
        request_timeout: Duration,
        max_retries: u32,
        proxy: Option<&ProxyConfig>,
        tls: &TlsConfig,
        prefetch_retry_interval: Duration,
        rate_limit: Option<RateLimit>,
        source: Source,
    ) -> io::Result<Self> {
        let mut builder = Client::builder().redirect(Policy::none()).hickory_dns(true);

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

/// Implements the blob transport over the origin HTTP client.
#[async_trait]
impl Transport for Http {
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
                source: self.source,
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

    /// Sends the `GET` of a prefetch read, the body left streaming, sending
    /// a `429`, `5xx` or `408` once more after the retry interval and failing
    /// a transport failure at once.
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
    use std::net::TcpListener;

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
        assert!(http.prefetch(&url, HeaderMap::new()).await.is_err());
        assert!(start.elapsed() < retry_interval);
    }

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
