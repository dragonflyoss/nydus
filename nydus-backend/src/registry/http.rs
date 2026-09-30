//! Direct HTTP transport to the origin registry.

use std::io;
use std::sync::Arc;

use reqwest::redirect::Policy;
use reqwest::{Certificate, Client};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};

use nydus_config::HttpConfig;

use super::dns::SystemResolver;

/// The direct HTTP transport to the origin registry.
// Named after the protocol like dragonfly-client-backend's `HTTP` backend.
#[allow(clippy::upper_case_acronyms)]
pub(crate) struct HTTP {
    /// The configured async HTTP client, wrapped with the retry middleware.
    client: ClientWithMiddleware,
    /// The same client without the retry middleware, for callers that pace
    /// their own retries (the Dragonfly fallback path).
    raw_client: Client,
    /// The configured retry budget ([`max_retries`](HttpConfig::max_retries)).
    max_retries: u32,
}

impl HTTP {
    /// Create a new HTTP transport from the HTTP client configuration.
    /// Requests are routed through [`proxy`](HttpConfig::proxy) when it is
    /// set; otherwise any ambient proxy from the environment is explicitly
    /// disabled so the connection truly goes direct. Transient failures are
    /// retried by the client middleware with exponential backoff, up to
    /// [`max_retries`](HttpConfig::max_retries) attempts.
    pub(crate) fn new(config: &HttpConfig) -> io::Result<HTTP> {
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
        let raw_client = client.clone();
        let client = ClientBuilder::new(client)
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();
        Ok(HTTP {
            client,
            raw_client,
            max_retries: config.max_retries,
        })
    }

    /// The underlying async HTTP client.
    pub(crate) fn client(&self) -> &ClientWithMiddleware {
        &self.client
    }

    /// The async HTTP client without the retry middleware: one call issues
    /// exactly one request attempt.
    pub(crate) fn raw_client(&self) -> &Client {
        &self.raw_client
    }

    /// The configured retry budget ([`max_retries`](HttpConfig::max_retries)).
    pub(crate) fn max_retries(&self) -> u32 {
        self.max_retries
    }
}
