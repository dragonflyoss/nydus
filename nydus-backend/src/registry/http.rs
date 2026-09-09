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

use nydus_config::HttpConfig;

use super::response::{log_request_done, Response};
use super::{BlobTransport, RegistryError, RegistryResult};
use crate::{Protocol, ReadKind};

/// An HTTP client talking straight to the origin registry. Its middleware
/// stack retries transient failures with exponential backoff and, when built
/// with a [`RateLimit`], claims a slot before every attempt.
///
/// ```text
/// request ──▶ RetryTransientMiddleware ──▶ RateLimit ──▶ reqwest::Client ──▶ origin
///                 │                          │
///                 └── retry ─────────────────┘  every attempt claims its own slot
/// ```
pub(crate) struct Http {
    client: ClientWithMiddleware,
}

impl Http {
    /// Start building a client from the HTTP configuration.
    pub(crate) fn builder(config: &HttpConfig) -> HttpBuilder {
        HttpBuilder {
            config: config.clone(),
            rate_limit: None,
        }
    }

    /// Send `method` to `url` with `headers` and log the outcome. Redirects
    /// are returned rather than followed so the caller can cache the signed
    /// URL a blob `GET` is redirected to.
    pub(crate) async fn request(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        kind: ReadKind,
    ) -> RegistryResult<Response> {
        let start = Instant::now();
        let result = match self
            .client
            .request(method.clone(), url)
            .headers(headers.clone())
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                let response_headers = response.headers().clone();
                Ok(Response {
                    status,
                    headers: response_headers,
                    reader: Box::new(StreamReader::new(Box::pin(
                        response.bytes_stream().map_err(io::Error::other),
                    ))),
                    protocol: Protocol::Http,
                })
            }
            Err(err) => Err(RegistryError::Io(io::Error::other(err))),
        };
        log_request_done(
            "none",
            &method,
            url,
            &headers,
            kind,
            &result,
            start.elapsed(),
        );
        result
    }
}

#[async_trait]
impl BlobTransport for Http {
    async fn get(&self, url: &str, headers: HeaderMap, kind: ReadKind) -> RegistryResult<Response> {
        self.request(Method::GET, url, headers, kind).await
    }
}

/// Builds an [`Http`] client: the connection settings from the configuration,
/// plus an optional rate limit on every attempt.
pub(crate) struct HttpBuilder {
    config: HttpConfig,
    rate_limit: Option<RateLimit>,
}

impl HttpBuilder {
    /// Make every attempt the client sends claim a slot from `limit` first.
    pub(crate) fn rate_limit(mut self, limit: RateLimit) -> Self {
        self.rate_limit = Some(limit);
        self
    }

    /// Build the client. Requests go through the configured proxy or, without
    /// one, straight to the origin with any ambient proxy ignored. Names are
    /// resolved by hickory, which caches lookups and honours record TTLs.
    /// Transient failures are retried up to the configured `max_retries`.
    pub(crate) fn build(self) -> io::Result<Http> {
        let config = &self.config;
        let mut builder = Client::builder().redirect(Policy::none()).hickory_dns(true);

        builder = match &config.proxy {
            Some(proxy) => {
                let proxy = reqwest::Proxy::all(&proxy.addr).map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid proxy addr {}: {err}", proxy.addr),
                    )
                })?;
                builder.proxy(proxy)
            }
            None => builder.no_proxy(),
        };

        if !config.timeout.is_zero() {
            builder = builder
                .timeout(config.timeout)
                .connect_timeout(config.timeout);
        }

        if config.tls.skip_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }

        if let Some(certs) = config.tls.load_ca_cert_der().map_err(io::Error::other)? {
            for cert in certs {
                builder =
                    builder.add_root_certificate(Certificate::from_der(&cert).map_err(|err| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("invalid CA cert: {err}"),
                        )
                    })?);
            }
        }

        let client = builder
            .build()
            .map_err(|err| io::Error::other(format!("failed to build http client: {err}")))?;

        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(config.max_retries);
        let mut client = ClientBuilder::new(client)
            .with(RetryTransientMiddleware::new_with_policy(retry_policy));
        if let Some(rate_limit) = self.rate_limit {
            client = client.with(rate_limit);
        }
        Ok(Http {
            client: client.build(),
        })
    }
}

/// A fair leaky bucket handing out one slot per request per interval, the
/// same limiter dfdaemon puts in front of its own proxy. As a middleware it
/// sits inside the retry middleware so every retry attempt waits for its own
/// slot. A zero limit disables it.
pub(crate) struct RateLimit {
    limiter: Option<RateLimiter>,
}

impl RateLimit {
    /// A limit of `requests_per_second`, zero disabling it.
    pub(crate) fn new(requests_per_second: u64) -> Self {
        Self::with_interval(requests_per_second, Duration::from_secs(1))
    }

    /// A limit of `requests` per `interval`, a zero limit or interval
    /// disabling it.
    pub(crate) fn with_interval(requests: u64, interval: Duration) -> Self {
        let limiter = (requests > 0 && !interval.is_zero()).then(|| {
            let limit = usize::try_from(requests).unwrap_or(usize::MAX);
            RateLimiter::builder()
                .max(limit)
                .initial(limit)
                .refill(limit)
                .interval(interval)
                .fair(true)
                .build()
        });
        Self { limiter }
    }

    /// Wait for this caller's slot, returning how long it waited.
    async fn acquire(&self) -> Duration {
        let Some(limiter) = &self.limiter else {
            return Duration::ZERO;
        };
        let start = Instant::now();
        limiter.acquire_one().await;
        start.elapsed()
    }
}

#[async_trait]
impl Middleware for RateLimit {
    async fn handle(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        self.acquire().await;
        next.run(req, extensions).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::RUNTIME;

    #[test]
    fn builds_with_and_without_a_rate_limit() {
        let config = HttpConfig::default();
        assert!(Http::builder(&config).build().is_ok());
        assert!(Http::builder(&config)
            .rate_limit(RateLimit::new(10))
            .build()
            .is_ok());
    }

    #[test]
    fn rate_limit_spaces_slots_by_the_interval() {
        let interval = Duration::from_millis(40);
        let start = Instant::now();
        let limit = RateLimit::with_interval(1, interval);

        RUNTIME.block_on(async {
            limit.acquire().await;
            assert!(start.elapsed() < interval);

            let waited = limit.acquire().await;
            assert!(start.elapsed() >= interval);
            assert!(waited > Duration::ZERO);
        });
    }

    #[test]
    fn a_zero_rate_limit_never_waits() {
        let limit = RateLimit::new(0);
        RUNTIME.block_on(async {
            let start = Instant::now();
            for _ in 0..3 {
                assert_eq!(limit.acquire().await, Duration::ZERO);
            }
            assert!(start.elapsed() < Duration::from_millis(20));
        });
    }
}
