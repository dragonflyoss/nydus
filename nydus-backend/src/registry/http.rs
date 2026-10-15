//! The direct HTTP transport to the origin registry.

use std::io;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::TryStreamExt;
use http::Extensions;
use leaky_bucket::RateLimiter;
use reqwest::header::HeaderMap;
use reqwest::redirect::Policy;
use reqwest::{Certificate, Client, Method, Request};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware, Middleware, Next};
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};
use tokio_util::io::StreamReader;
use tracing::debug;

use nydus_config::HttpConfig;

use super::response::Response;
use super::Transport;
use crate::{Protocol, ReadKind};

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
            .timeout(config.timeout)
            .connect_timeout(config.timeout);

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

    /// Sends `method` to `url` with `headers` and logs the outcome.
    pub(crate) async fn request(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        kind: ReadKind,
    ) -> io::Result<Response> {
        let start = Instant::now();
        let result = self
            .client
            .request(method.clone(), url)
            .headers(headers.clone())
            .send()
            .await
            .map(|response| Response {
                status: response.status(),
                headers: response.headers().clone(),
                reader: Box::new(StreamReader::new(
                    response.bytes_stream().map_err(io::Error::other),
                )),
                protocol: Protocol::Http,
            })
            .map_err(io::Error::other);

        match &result {
            Ok(response) => debug!(
                "{method} {url} ({kind}) from the origin returned {} in {:?}",
                response.status,
                start.elapsed()
            ),
            Err(err) => debug!(
                "{method} {url} ({kind}) from the origin failed in {:?}: {err}",
                start.elapsed()
            ),
        }
        result
    }
}

/// Implements the blob transport over the origin HTTP client.
#[async_trait]
impl Transport for Http {
    /// Sends a `GET` to `url`.
    async fn get(&self, url: &str, headers: HeaderMap, kind: ReadKind) -> io::Result<Response> {
        self.request(Method::GET, url, headers, kind).await
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
