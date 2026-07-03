//! HTTP forward-proxy transport for HTTP-based backends.
//!
//! Routes a request through an HTTP forward proxy (e.g. a Dragonfly `dfdaemon`
//! P2P agent) using reqwest's native proxy support. Unlike a *mirror* — which
//! rewrites the request host and therefore has to tell the proxy the upstream
//! out of band — a forward proxy preserves the original upstream URL, so the
//! proxy already knows which registry / object store to back-source from.
//!
//! Two Dragonfly transports are configured under the same `proxy` block:
//! * **HTTP proxy** ([`HttpProxy`]): the request is sent through `proxy.url`
//!   with Dragonfly hint headers (priority, P2P) attached.
//! * **Dragonfly SDK** ([`crate::storage::backend::dragonfly_sdk`], feature
//!   `backend-dragonfly-proxy`): the request goes through the Dragonfly client
//!   SDK using `proxy.dragonfly_scheduler_endpoint`.

use std::sync::Arc;

use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Client;
use serde::Deserialize;

use super::http::{build_client, ConnectionConfig};
use super::RequestSource;

/// Dragonfly priority hint for background prefetch requests.
pub(crate) const DRAGONFLY_PRIORITY_PREFETCH: i32 = 3;
/// Dragonfly priority hint for on-demand (foreground) requests.
pub(crate) const DRAGONFLY_PRIORITY_ONDEMAND: i32 = 6;

/// Header carrying the Dragonfly scheduling priority of a request.
pub(crate) const HEADER_DRAGONFLY_PRIORITY: &str = "X-Dragonfly-Priority";
/// Header opting a request into Dragonfly P2P distribution.
pub(crate) const HEADER_DRAGONFLY_USE_P2P: &str = "X-Dragonfly-Use-P2P";

/// Map a request source to its Dragonfly priority value.
pub(crate) fn dragonfly_priority(source: RequestSource) -> i32 {
    match source {
        RequestSource::Prefetch => DRAGONFLY_PRIORITY_PREFETCH,
        RequestSource::OnDemand => DRAGONFLY_PRIORITY_ONDEMAND,
    }
}

/// Proxy configuration. Either or both transports may be set; an omitted block
/// talks to the origin directly.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ProxyConfig {
    /// HTTP forward-proxy URL, e.g. `http://127.0.0.1:65001`.
    #[serde(default)]
    pub url: Option<String>,
    /// Dragonfly scheduler endpoint (gRPC), e.g. `http://127.0.0.1:65000`. Only
    /// honored when built with the `backend-dragonfly-proxy` feature.
    #[cfg(feature = "backend-dragonfly-proxy")]
    #[serde(default)]
    pub dragonfly_scheduler_endpoint: Option<String>,
}

/// An HTTP forward proxy: a reqwest [`Client`] bound to the proxy endpoint plus
/// the Dragonfly hint behaviour applied to requests it serves.
pub(crate) struct HttpProxy {
    client: Client,
}

impl HttpProxy {
    /// Build a proxy transport routing through `url`, reusing the shared
    /// connection settings (TLS, DNS, timeouts) of the direct connection.
    pub(crate) fn new(config: &ConnectionConfig, url: &str) -> std::io::Result<Arc<HttpProxy>> {
        let client = build_client(config, Some(url))?;
        Ok(Arc::new(HttpProxy { client }))
    }

    /// The proxy-bound HTTP client.
    pub(crate) fn client(&self) -> &Client {
        &self.client
    }

    /// Attach Dragonfly hint headers (priority + P2P opt-in) to a request the
    /// HTTP proxy will serve.
    pub(crate) fn decorate(headers: &mut HeaderMap, source: RequestSource) {
        if let Ok(priority) = dragonfly_priority(source).to_string().parse() {
            headers.insert(HEADER_DRAGONFLY_PRIORITY, priority);
        }
        headers.insert(HEADER_DRAGONFLY_USE_P2P, HeaderValue::from_static("true"));
    }
}
