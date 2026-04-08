// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Unified request routing layer for backend operations.
//!
//! Routes requests through one of three paths:
//! 1. Direct HTTP via `Connection`
//! 2. HTTP proxy via `Connection` (with Dragonfly headers)
//! 3. Dragonfly SDK via `ProxySDKClients` (feature-gated)

use std::io::Read;
use std::str::FromStr;
use std::sync::Arc;

use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Method, StatusCode,
};

use nydus_api::ProxyConfig;

use crate::backend::connection::{Connection, ConnectionError, ReqBody};
use crate::backend::BackendContext;

#[cfg(feature = "backend-dragonfly-proxy")]
use crate::backend::proxy::{self, ProxySDKClients};
#[cfg(feature = "backend-dragonfly-proxy")]
use crate::backend::RequestSource;

const HEADER_ENV_PREFIX: &str = "NYDUS_HEADER_";
const HEADER_USER_AGENT: &str = "User-Agent";
const HEADER_VALUE_USER_AGENT: &str = "nydusd/1.0.0";

#[derive(Debug)]
pub enum RequestError {
    Common(String),
    Connection(ConnectionError),
    #[cfg(feature = "backend-dragonfly-proxy")]
    Proxy(proxy::ProxyError),
}

pub type RequestResult<T> = std::result::Result<T, RequestError>;

fn parse_custom_headers_from_env() -> HeaderMap {
    let mut custom_headers = HeaderMap::new();
    custom_headers.insert(HEADER_USER_AGENT, HEADER_VALUE_USER_AGENT.parse().unwrap());
    for (key, value) in std::env::vars() {
        if key.starts_with(HEADER_ENV_PREFIX) {
            let header_key = key.trim_start_matches(HEADER_ENV_PREFIX);
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_str(header_key),
                HeaderValue::from_str(&value),
            ) {
                custom_headers.insert(name, val);
            }
        }
    }
    custom_headers
}

/// Unified request layer that wraps `Connection` and adds Dragonfly SDK routing.
#[derive(Debug)]
pub struct Request {
    connection: Arc<Connection>,
    custom_headers: HeaderMap,
    proxy_config: ProxyConfig,
    #[allow(dead_code)]
    disable_proxy_prefetch: bool,
}

/// Check whether the HTTP status code is a success result.
pub fn is_success_status(status: StatusCode) -> bool {
    status >= StatusCode::OK && status < StatusCode::BAD_REQUEST
}

impl Request {
    /// Create a new Request wrapping the given Connection.
    #[allow(dead_code)]
    pub(crate) fn new(
        connection: Arc<Connection>,
        proxy_config: ProxyConfig,
        disable_proxy_prefetch: bool,
    ) -> Arc<Request> {
        let custom_headers = parse_custom_headers_from_env();
        Arc::new(Request {
            connection,
            custom_headers,
            proxy_config,
            disable_proxy_prefetch,
        })
    }

    /// Returns the dragonfly scheduler endpoint, or empty string if not configured.
    pub fn dragonfly_scheduler_endpoint(&self) -> &str {
        &self.proxy_config.dragonfly_scheduler_endpoint
    }

    /// Returns true if using HTTP proxy mode (no Dragonfly SDK scheduler).
    pub fn is_proxy_mode(&self) -> bool {
        self.dragonfly_scheduler_endpoint().is_empty()
    }

    /// Route a request through the appropriate path.
    #[allow(clippy::too_many_arguments)]
    pub fn call<R: Read + Clone + Send + 'static>(
        &self,
        method: Method,
        url: &str,
        query: Option<&[(&str, &str)]>,
        data: Option<ReqBody<R>>,
        headers: &mut HeaderMap,
        catch_status: bool,
        context: &mut BackendContext,
    ) -> RequestResult<reqwest::blocking::Response> {
        // Inject custom headers from environment variables
        headers.extend(self.custom_headers.clone());

        // If proxy is disabled for this request or no proxy is configured, go direct
        if context.disable_proxy || self.proxy_config.url.is_empty() {
            return self
                .connection
                .call(method, url, query, data, headers, catch_status)
                .map_err(RequestError::Connection);
        }

        // Try Dragonfly SDK path if configured and enabled
        #[cfg(feature = "backend-dragonfly-proxy")]
        {
            let endpoint = self.dragonfly_scheduler_endpoint().to_string();
            if !endpoint.is_empty() && !context.disable_proxy_sdk {
                if method != Method::GET {
                    return Err(RequestError::Common(
                        "only GET method is supported with Dragonfly SDK proxy".to_string(),
                    ));
                }

                context.using_proxy_sdk = true;
                let priority = Some(match context.request_source {
                    RequestSource::Prefetch => proxy::HEADER_VALUE_DRAGONFLY_PRIORITY_3,
                    RequestSource::OnDemand => proxy::HEADER_VALUE_DRAGONFLY_PRIORITY_6,
                });

                let proxy_sdk_client = ProxySDKClients::get(&endpoint).map_err(|e| {
                    RequestError::Proxy(proxy::ProxyError::Internal(format!(
                        "failed to get proxy sdk client: {}",
                        e
                    )))
                })?;

                return match proxy_sdk_client.request(
                    url,
                    Some(headers.clone()),
                    priority,
                    catch_status,
                ) {
                    Ok(resp) => {
                        let status = resp.status();
                        if status >= StatusCode::INTERNAL_SERVER_ERROR {
                            return Err(RequestError::Common(format!(
                                "proxy server returned error status: {}",
                                status,
                            )));
                        }
                        // SDK response path — backends will consume this in Phase 3
                        Err(RequestError::Common(
                            "SDK response path not yet wired to backends".to_string(),
                        ))
                    }
                    Err(err) => Err(RequestError::Proxy(err)),
                };
            }
        }

        // Inject Dragonfly priority headers for HTTP proxy mode
        #[cfg(feature = "backend-dragonfly-proxy")]
        if !self.is_proxy_mode() {
            let priority_val = match context.request_source {
                RequestSource::Prefetch => proxy::HEADER_VALUE_DRAGONFLY_PRIORITY_3.to_string(),
                RequestSource::OnDemand => proxy::HEADER_VALUE_DRAGONFLY_PRIORITY_6.to_string(),
            };
            if let Ok(val) = HeaderValue::from_str(&priority_val) {
                headers.insert(
                    HeaderName::from_str(proxy::HEADER_DRAGONFLY_PRIORITY).unwrap(),
                    val,
                );
            }
            headers.insert(
                HeaderName::from_str(proxy::HEADER_DRAGONFLY_USE_P2P).unwrap(),
                proxy::HEADER_VALUE_DRAGONFLY_USE_P2P_TRUE.parse().unwrap(),
            );
            if let Ok(val) =
                HeaderValue::from_str((!self.disable_proxy_prefetch).to_string().as_str())
            {
                headers.insert(
                    HeaderName::from_str(proxy::HEADER_DRAGONFLY_PREFETCH).unwrap(),
                    val,
                );
            }
        }

        // Fall through to Connection which handles HTTP proxy + health + fallback
        self.connection
            .call(method, url, query, data, headers, catch_status)
            .map_err(RequestError::Connection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_custom_headers_from_env() {
        std::env::set_var("NYDUS_HEADER_X-TEST-PROXY-1", "value1");
        std::env::set_var("NYDUS_HEADER_X-TEST-PROXY-2", "value2");

        let headers = parse_custom_headers_from_env();

        assert_eq!(
            headers.get("User-Agent").unwrap(),
            &HeaderValue::from_str("nydusd/1.0.0").unwrap()
        );
        assert_eq!(
            headers.get("X-TEST-PROXY-1").unwrap(),
            &HeaderValue::from_str("value1").unwrap()
        );
        assert_eq!(
            headers.get("X-TEST-PROXY-2").unwrap(),
            &HeaderValue::from_str("value2").unwrap()
        );

        std::env::remove_var("NYDUS_HEADER_X-TEST-PROXY-1");
        std::env::remove_var("NYDUS_HEADER_X-TEST-PROXY-2");
    }

    #[test]
    fn test_is_success_status() {
        assert!(is_success_status(StatusCode::OK));
        assert!(is_success_status(StatusCode::MOVED_PERMANENTLY));
        assert!(!is_success_status(StatusCode::BAD_REQUEST));
        assert!(!is_success_status(StatusCode::INTERNAL_SERVER_ERROR));
    }
}
