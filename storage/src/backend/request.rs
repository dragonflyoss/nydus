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
use crate::backend::proxy;
#[cfg(feature = "backend-dragonfly-proxy")]
use crate::backend::proxy::ProxySDKClients;
#[cfg(feature = "backend-dragonfly-proxy")]
use crate::backend::RequestSource;

#[cfg(feature = "backend-dragonfly-proxy")]
use dragonfly_client_util::request::GetResponse;
#[cfg(feature = "backend-dragonfly-proxy")]
use lazy_static::lazy_static;

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

// --- Response enum: available for all network backends ---

pub enum Response {
    HTTP(reqwest::blocking::Response),
    #[cfg(feature = "backend-dragonfly-proxy")]
    ProxySDK(GetResponse),
}

impl Response {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::HTTP(resp) => resp.status(),
            #[cfg(feature = "backend-dragonfly-proxy")]
            Self::ProxySDK(resp) => resp.status_code.unwrap_or(StatusCode::BAD_GATEWAY),
        }
    }

    pub fn headers(&self) -> &HeaderMap {
        #[cfg(feature = "backend-dragonfly-proxy")]
        lazy_static! {
            static ref EMPTY_HEADERS: HeaderMap = HeaderMap::new();
        }
        match self {
            Self::HTTP(resp) => resp.headers(),
            #[cfg(feature = "backend-dragonfly-proxy")]
            Self::ProxySDK(resp) => resp.header.as_ref().unwrap_or(&EMPTY_HEADERS),
        }
    }

    pub fn reader(self) -> Box<dyn Read + Send> {
        match self {
            Self::HTTP(resp) => Box::new(resp),
            #[cfg(feature = "backend-dragonfly-proxy")]
            Self::ProxySDK(resp) => {
                let reader = resp.reader.unwrap_or(Box::new(tokio::io::empty()));
                Box::new(proxy::SyncAdapter::new(reader))
            }
        }
    }

    pub fn text(self) -> Result<String, String> {
        let mut content = String::new();
        self.reader()
            .read_to_string(&mut content)
            .map_err(|e| format!("{}", e))?;
        Ok(content)
    }

    pub fn copy_to(self, writer: &mut [u8]) -> Result<u64, String> {
        match self {
            Self::HTTP(resp) => {
                std::io::copy(&mut Box::new(resp), &mut &mut *writer).map_err(|e| format!("{}", e))
            }
            #[cfg(feature = "backend-dragonfly-proxy")]
            Self::ProxySDK(resp) => {
                use crate::factory::ASYNC_RUNTIME;
                let mut reader = resp.reader.unwrap_or(Box::new(tokio::io::empty()));
                ASYNC_RUNTIME
                    .block_on(async {
                        tokio::io::copy(&mut reader, &mut std::io::Cursor::new(writer)).await
                    })
                    .map_err(|e| format!("{}", e))
            }
        }
    }
}

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
    /// Shut down the underlying connection.
    pub fn shutdown(&self) {
        self.connection.shutdown();
    }

    /// Check whether the connection has been shut down.
    pub fn is_shutdown(&self) -> bool {
        self.connection
            .shutdown
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Create a new Request wrapping the given Connection.
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
        temp_disable_proxy: bool,
    ) -> RequestResult<Response> {
        // Inject custom headers from environment variables
        headers.extend(self.custom_headers.clone());

        // If proxy is disabled for this request or no proxy is configured, go direct
        if temp_disable_proxy || context.disable_proxy || self.proxy_config.url.is_empty() {
            return self
                .connection
                .call(method, url, query, data, headers, catch_status)
                .map(Response::HTTP)
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
                        Ok(resp)
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
            .map(Response::HTTP)
            .map_err(RequestError::Connection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::connection::ConnectionConfig;

    fn make_request(proxy_url: &str, scheduler_endpoint: &str) -> Arc<Request> {
        let config = ConnectionConfig {
            proxy: ProxyConfig {
                url: proxy_url.to_string(),
                dragonfly_scheduler_endpoint: scheduler_endpoint.to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let connection = Connection::new(&config).unwrap();
        Request::new(connection, config.proxy.clone(), false)
    }

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
    fn test_parse_custom_headers_always_includes_user_agent() {
        let headers = parse_custom_headers_from_env();
        assert_eq!(headers.get("User-Agent").unwrap(), "nydusd/1.0.0");
    }

    #[test]
    fn test_is_success_status() {
        assert!(is_success_status(StatusCode::OK));
        assert!(is_success_status(StatusCode::MOVED_PERMANENTLY));
        assert!(!is_success_status(StatusCode::BAD_REQUEST));
        assert!(!is_success_status(StatusCode::INTERNAL_SERVER_ERROR));
    }

    #[test]
    fn test_is_success_status_boundary() {
        assert!(is_success_status(StatusCode::from_u16(200).unwrap()));
        assert!(is_success_status(StatusCode::from_u16(399).unwrap()));
        assert!(!is_success_status(StatusCode::from_u16(400).unwrap()));
        assert!(!is_success_status(StatusCode::from_u16(100).unwrap()));
    }

    #[test]
    fn test_request_new() {
        let req = make_request("", "");
        assert!(req.is_proxy_mode());
        assert!(!req.is_shutdown());
    }

    #[test]
    fn test_is_proxy_mode_no_scheduler() {
        let req = make_request("http://proxy:8080", "");
        assert!(req.is_proxy_mode());
    }

    #[test]
    fn test_is_proxy_mode_with_scheduler() {
        let req = make_request("http://proxy:8080", "http://scheduler:8002");
        assert!(!req.is_proxy_mode());
    }

    #[test]
    fn test_dragonfly_scheduler_endpoint() {
        let req = make_request("", "http://scheduler:8002");
        assert_eq!(req.dragonfly_scheduler_endpoint(), "http://scheduler:8002");
    }

    #[test]
    fn test_dragonfly_scheduler_endpoint_empty() {
        let req = make_request("", "");
        assert_eq!(req.dragonfly_scheduler_endpoint(), "");
    }

    #[test]
    fn test_shutdown_and_is_shutdown() {
        let req = make_request("", "");
        assert!(!req.is_shutdown());
        req.shutdown();
        assert!(req.is_shutdown());
    }

    #[test]
    fn test_call_direct_no_proxy() {
        let req = make_request("", "");
        let mut headers = HeaderMap::new();
        let mut ctx = BackendContext::default();

        // Calling a non-existent URL should fail with ConnectionError
        let result = req.call::<&[u8]>(
            Method::GET,
            "http://127.0.0.1:1/nonexistent",
            None,
            None,
            &mut headers,
            true,
            &mut ctx,
            false,
        );
        assert!(result.is_err());
        assert!(matches!(result, Err(RequestError::Connection(_))));
    }

    #[test]
    fn test_call_temp_disable_proxy_bypasses_proxy() {
        let req = make_request("http://proxy:8080", "http://scheduler:8002");
        let mut headers = HeaderMap::new();
        let mut ctx = BackendContext::default();

        // Even with proxy configured, temp_disable_proxy routes direct
        let result = req.call::<&[u8]>(
            Method::GET,
            "http://127.0.0.1:1/nonexistent",
            None,
            None,
            &mut headers,
            true,
            &mut ctx,
            true, // temp_disable_proxy
        );
        assert!(result.is_err());
        assert!(matches!(result, Err(RequestError::Connection(_))));
    }

    #[test]
    fn test_call_context_disable_proxy_bypasses_proxy() {
        let req = make_request("http://proxy:8080", "http://scheduler:8002");
        let mut headers = HeaderMap::new();
        let mut ctx = BackendContext {
            disable_proxy: true,
            ..Default::default()
        };

        let result = req.call::<&[u8]>(
            Method::GET,
            "http://127.0.0.1:1/nonexistent",
            None,
            None,
            &mut headers,
            true,
            &mut ctx,
            false,
        );
        assert!(result.is_err());
        assert!(matches!(result, Err(RequestError::Connection(_))));
    }

    #[test]
    fn test_call_injects_custom_headers() {
        std::env::set_var("NYDUS_HEADER_X-TEST-INJECT", "injected");
        let req = make_request("", "");
        let mut headers = HeaderMap::new();
        let mut ctx = BackendContext::default();

        // The call will fail, but custom headers are injected before the attempt
        let _ = req.call::<&[u8]>(
            Method::GET,
            "http://127.0.0.1:1/nonexistent",
            None,
            None,
            &mut headers,
            true,
            &mut ctx,
            false,
        );

        // Verify headers were injected into the mutable headers map
        assert_eq!(headers.get("X-TEST-INJECT").unwrap(), "injected");
        assert_eq!(headers.get("User-Agent").unwrap(), "nydusd/1.0.0");

        std::env::remove_var("NYDUS_HEADER_X-TEST-INJECT");
    }

    #[test]
    fn test_call_empty_proxy_url_goes_direct() {
        // Even with scheduler configured, empty proxy URL → direct
        let req = make_request("", "http://scheduler:8002");
        let mut headers = HeaderMap::new();
        let mut ctx = BackendContext::default();

        let result = req.call::<&[u8]>(
            Method::GET,
            "http://127.0.0.1:1/nonexistent",
            None,
            None,
            &mut headers,
            true,
            &mut ctx,
            false,
        );
        assert!(result.is_err());
        assert!(matches!(result, Err(RequestError::Connection(_))));
    }
}
