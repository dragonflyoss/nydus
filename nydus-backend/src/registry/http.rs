//! Direct HTTP transport to the origin registry.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use http::Extensions;
use leaky_bucket::RateLimiter;
use reqwest::redirect::Policy;
use reqwest::{Certificate, Client, Request, Response};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware, Middleware, Next};
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};

use nydus_config::HttpConfig;

use super::dns::SystemResolver;

/// The direct HTTP transport to the origin registry.
// Named after the protocol like dragonfly-client-backend's `HTTP` backend.
#[allow(clippy::upper_case_acronyms)]
pub(crate) struct HTTP {
    /// The configured async HTTP client, wrapped with the retry middleware.
    client: ClientWithMiddleware,
    /// The same client with the back-to-source rate limiter inside the retry
    /// middleware, for origin requests issued when Dragonfly cannot serve a
    /// read.
    back_to_source_client: ClientWithMiddleware,
}

impl HTTP {
    /// Create a new HTTP transport from the HTTP client configuration.
    /// Requests are routed through [`proxy`](HttpConfig::proxy) when it is
    /// set; otherwise any ambient proxy from the environment is explicitly
    /// disabled so the connection truly goes direct. Transient failures are
    /// retried by the client middleware with exponential backoff, up to
    /// [`max_retries`](HttpConfig::max_retries) attempts. Back-to-source
    /// requests share the budget, and every attempt of theirs first claims a
    /// slot from `rate_limiter`.
    pub(crate) fn new(
        config: &HttpConfig,
        rate_limiter: BackToSourceRateLimiter,
    ) -> io::Result<HTTP> {
        let mut builder = Client::builder()
            // The registry handles 3xx redirects manually so it can cache the
            // redirected blob-storage URL.
            .redirect(Policy::none())
            .dns_resolver(Arc::new(SystemResolver::default()));

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
        let back_to_source_client = ClientBuilder::new(client.clone())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .with(rate_limiter)
            .build();
        let client = ClientBuilder::new(client)
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();
        Ok(HTTP {
            client,
            back_to_source_client,
        })
    }

    /// The underlying async HTTP client.
    pub(crate) fn client(&self) -> &ClientWithMiddleware {
        &self.client
    }

    /// The async HTTP client for origin requests issued when Dragonfly cannot
    /// serve a read, whose every attempt waits for a back-to-source rate limit
    /// slot.
    pub(crate) fn back_to_source_client(&self) -> &ClientWithMiddleware {
        &self.back_to_source_client
    }
}

/// Shapes origin requests issued when Dragonfly cannot serve a read to a
/// number of requests per interval, per registry backend. A fair leaky bucket
/// hands out slots FIFO, the same limiter dfdaemon puts in front of its own
/// proxy, and the middleware sits inside the retry middleware so every retry
/// attempt claims its own slot. Disabled when the limit is zero.
pub(crate) struct BackToSourceRateLimiter {
    /// The bucket, `None` when the limit is disabled.
    limiter: Option<RateLimiter>,
}

impl BackToSourceRateLimiter {
    /// Create a limiter allowing `request_rate_limit` requests per second,
    /// zero disabling it.
    pub(crate) fn new(request_rate_limit: u64) -> Self {
        Self::with_interval(request_rate_limit, Duration::from_secs(1))
    }

    /// Create a limiter allowing `request_rate_limit` requests per `interval`,
    /// a zero limit or interval disabling it.
    pub(crate) fn with_interval(request_rate_limit: u64, interval: Duration) -> Self {
        let limiter = (request_rate_limit > 0 && !interval.is_zero()).then(|| {
            let limit = usize::try_from(request_rate_limit).unwrap_or(usize::MAX);
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
impl Middleware for BackToSourceRateLimiter {
    async fn handle(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        let waited = self.acquire().await;
        nydus_telemetry::metrics::record_fallback_throttle_wait(waited);
        next.run(req, extensions).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::runtime;

    #[test]
    fn back_to_source_rate_limiter_spaces_slots_by_the_interval() {
        let interval = Duration::from_millis(40);
        let start = Instant::now();
        let limiter = BackToSourceRateLimiter::with_interval(1, interval);

        runtime().block_on(async {
            limiter.acquire().await;
            assert!(start.elapsed() < interval);

            let waited = limiter.acquire().await;
            assert!(start.elapsed() >= interval);
            assert!(waited > Duration::ZERO);
        });
    }

    #[test]
    fn a_zero_rate_limit_disables_the_back_to_source_rate_limiter() {
        let limiter = BackToSourceRateLimiter::new(0);
        runtime().block_on(async {
            let start = Instant::now();
            for _ in 0..3 {
                assert_eq!(limiter.acquire().await, Duration::ZERO);
            }
            assert!(start.elapsed() < Duration::from_millis(20));
        });
    }
}
