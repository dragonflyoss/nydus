//! Low-level HTTP transport for the registry backend.
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
        .thread_name("lepton-backend")
        .enable_all()
        .build()
        .expect("failed to build backend tokio runtime")
});

/// Access the shared backend runtime.
pub(crate) fn runtime() -> &'static Runtime {
    &HTTP_RUNTIME
}

/// Configuration for the direct HTTP connection to a registry.
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

/// A direct HTTP connection to the registry, wrapping a configured async client.
pub(crate) struct Connection {
    client: Client,
}

impl Connection {
    pub(crate) fn new(config: &ConnectionConfig) -> io::Result<Arc<Connection>> {
        let mut builder = Client::builder()
            // The registry backend handles 3xx redirects manually so it can
            // cache the redirected blob-storage URL.
            .redirect(Policy::none())
            // Ignore environment proxies; proxying is configured explicitly.
            .no_proxy()
            .dns_resolver(Arc::new(HickoryResolver::default()));

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

        let client = builder
            .build()
            .map_err(|e| io::Error::other(format!("failed to build http client: {e}")))?;

        Ok(Arc::new(Connection { client }))
    }

    /// The underlying async HTTP client.
    pub(crate) fn client(&self) -> &Client {
        &self.client
    }
}
