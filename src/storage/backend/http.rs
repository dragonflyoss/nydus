//! Low-level HTTP transport shared by HTTP-based backends (registry, and future
//! object-storage backends).
//!
//! The [`BlobBackend`](crate::storage::backend::BlobBackend) trait is
//! synchronous, but `reqwest`'s ergonomic client is asynchronous. This module
//! owns a single shared multi-threaded Tokio runtime and bridges the two with
//! `block_on`, so the rest of the backend can stay synchronous while still
//! using the async client (with custom DNS, connection pooling, etc.).

use std::io;
use std::sync::Arc;
use std::time::Duration;

use once_cell::sync::Lazy;
use reqwest::redirect::Policy;
use reqwest::Client;
use tokio::runtime::Runtime;

use super::dns::HickoryResolver;

/// Shared runtime used for every backend network operation (direct HTTP and,
/// when enabled, the Dragonfly SDK proxy).
static HTTP_RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .thread_name("nydus-backend")
        .enable_all()
        .build()
        .expect("failed to build backend tokio runtime")
});

/// Access the shared backend runtime.
pub(crate) fn runtime() -> &'static Runtime {
    &HTTP_RUNTIME
}

/// Shared configuration for HTTP-based backend connections.
#[derive(Debug, Clone)]
pub(crate) struct ConnectionConfig {
    /// Skip TLS certificate verification (also enables HTTPS->HTTP fallback).
    pub skip_verify: bool,
    /// Per-request timeout in seconds (0 disables the timeout).
    pub timeout: u64,
    /// Extra CA certificate PEM files to trust.
    pub ca_cert_files: Vec<String>,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            skip_verify: false,
            timeout: 30,
            ca_cert_files: Vec::new(),
        }
    }
}

/// Build a reqwest [`Client`] from the shared [`ConnectionConfig`].
///
/// When `proxy_url` is `Some`, every request is routed through that HTTP forward
/// proxy while preserving the original upstream URL (so the proxy knows what to
/// back-source); when `None`, any ambient proxy from the environment is
/// explicitly disabled so the connection truly goes direct.
pub(crate) fn build_client(
    config: &ConnectionConfig,
    proxy_url: Option<&str>,
) -> io::Result<Client> {
    let mut builder = Client::builder()
        // Backends handle 3xx redirects manually so they can cache the
        // redirected blob-storage URL.
        .redirect(Policy::none())
        .dns_resolver(Arc::new(HickoryResolver::default()));

    builder = match proxy_url {
        Some(url) => {
            let proxy = reqwest::Proxy::all(url).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid proxy url {url}: {e}"),
                )
            })?;
            builder.proxy(proxy)
        }
        None => builder.no_proxy(),
    };

    if config.timeout > 0 {
        builder = builder
            .timeout(Duration::from_secs(config.timeout))
            .connect_timeout(Duration::from_secs(config.timeout));
    }

    if config.skip_verify {
        builder = builder.danger_accept_invalid_certs(true);
    }

    for ca in &config.ca_cert_files {
        let pem = std::fs::read(ca).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("failed to read CA cert {ca}: {e}"),
            )
        })?;
        let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid CA cert {ca}: {e}"),
            )
        })?;
        builder = builder.add_root_certificate(cert);
    }

    builder
        .build()
        .map_err(|e| io::Error::other(format!("failed to build http client: {e}")))
}

/// A direct HTTP connection, wrapping a configured async client.
pub(crate) struct Connection {
    client: Client,
}

impl Connection {
    pub(crate) fn new(config: &ConnectionConfig) -> io::Result<Arc<Connection>> {
        Ok(Arc::new(Connection {
            client: build_client(config, None)?,
        }))
    }

    /// The underlying async HTTP client.
    pub(crate) fn client(&self) -> &Client {
        &self.client
    }
}
