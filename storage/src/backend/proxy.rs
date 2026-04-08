// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Unified response type for backend request routing.
//!
//! Provides a `Response` enum that wraps both HTTP and Dragonfly SDK responses.
//! The HTTP variant is always available; the ProxySDK variant and all Dragonfly
//! SDK types are gated behind `backend-dragonfly-proxy`.

// --- Always-available imports (any network backend) ---
use reqwest::header::HeaderMap;
use reqwest::StatusCode;
use std::io::Read;

// --- Dragonfly-only imports ---
#[cfg(feature = "backend-dragonfly-proxy")]
use std::time::Duration;
#[cfg(feature = "backend-dragonfly-proxy")]
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
#[cfg(feature = "backend-dragonfly-proxy")]
use tokio::io::AsyncRead;
#[cfg(feature = "backend-dragonfly-proxy")]
use tokio::runtime::Runtime;

#[cfg(feature = "backend-dragonfly-proxy")]
use dragonfly_client_util::request::errors::Error;
#[cfg(feature = "backend-dragonfly-proxy")]
use dragonfly_client_util::request::Request;
#[cfg(feature = "backend-dragonfly-proxy")]
use dragonfly_client_util::request::{GetRequest, GetResponse, Proxy};
#[cfg(feature = "backend-dragonfly-proxy")]
use lazy_static::lazy_static;

#[cfg(feature = "backend-dragonfly-proxy")]
use crate::factory::ASYNC_RUNTIME;

// --- Dragonfly header constants ---
#[cfg(feature = "backend-dragonfly-proxy")]
pub const HEADER_DRAGONFLY_PRIORITY: &str = "X-Dragonfly-Priority";
#[cfg(feature = "backend-dragonfly-proxy")]
pub const HEADER_DRAGONFLY_USE_P2P: &str = "X-Dragonfly-Use-P2P";
#[cfg(feature = "backend-dragonfly-proxy")]
pub const HEADER_DRAGONFLY_OUTPUT_PATH: &str = "X-Dragonfly-Output-Path";
#[cfg(feature = "backend-dragonfly-proxy")]
pub const HEADER_DRAGONFLY_PIECE_LENGTH: &str = "X-Dragonfly-Piece-Length";
#[cfg(feature = "backend-dragonfly-proxy")]
pub const HEADER_DRAGONFLY_FORCE_HARD_LINK: &str = "X-Dragonfly-Force-Hard-Link";
#[cfg(feature = "backend-dragonfly-proxy")]
pub const HEADER_DRAGONFLY_CONTENT_FOR_CALCULATING_TASK_ID: &str =
    "X-Dragonfly-Content-For-Calculating-Task-ID";
#[cfg(feature = "backend-dragonfly-proxy")]
pub const HEADER_DRAGONFLY_PREFETCH: &str = "X-Dragonfly-Prefetch";
#[cfg(feature = "backend-dragonfly-proxy")]
pub const HEADER_DRAGONFLY_ERROR_TYPE: &str = "X-Dragonfly-Error-Type";

#[cfg(feature = "backend-dragonfly-proxy")]
pub const HEADER_VALUE_DRAGONFLY_PRIORITY_3: i32 = 3;
#[cfg(feature = "backend-dragonfly-proxy")]
pub const HEADER_VALUE_DRAGONFLY_PRIORITY_6: i32 = 6;
#[cfg(feature = "backend-dragonfly-proxy")]
pub const HEADER_VALUE_DRAGONFLY_USE_P2P_TRUE: &str = "true";
#[cfg(feature = "backend-dragonfly-proxy")]
pub const HEADER_VALUE_DRAGONFLY_ERROR_TYPE_PROXY: &str = "proxy";

#[cfg(feature = "backend-dragonfly-proxy")]
#[derive(Debug)]
pub enum ProxyError {
    Common(String),
    Internal(String),
    TooManyRequests(String),
    Forbidden(String),
}

#[cfg(feature = "backend-dragonfly-proxy")]
lazy_static! {
    static ref PROXY_SDK_CLIENT: Arc<RwLock<HashMap<String, Arc<ProxySDKClient>>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

#[cfg(feature = "backend-dragonfly-proxy")]
fn runtime() -> &'static Runtime {
    &ASYNC_RUNTIME
}

#[cfg(feature = "backend-dragonfly-proxy")]
struct SyncAdapter<R> {
    inner: R,
}

#[cfg(feature = "backend-dragonfly-proxy")]
impl<R> SyncAdapter<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }
}

#[cfg(feature = "backend-dragonfly-proxy")]
impl<R: AsyncRead + Unpin> Read for SyncAdapter<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        runtime().block_on(async { tokio::io::AsyncReadExt::read(&mut self.inner, buf).await })
    }
}

// --- Response enum: always available for all network backends ---

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
                Box::new(SyncAdapter::new(reader))
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
                let mut reader = resp.reader.unwrap_or(Box::new(tokio::io::empty()));
                runtime()
                    .block_on(async {
                        tokio::io::copy(&mut reader, &mut std::io::Cursor::new(writer)).await
                    })
                    .map_err(|e| format!("{}", e))
            }
        }
    }
}

#[cfg(feature = "backend-dragonfly-proxy")]
pub struct ProxySDKClient {
    client: Proxy,
}

#[cfg(feature = "backend-dragonfly-proxy")]
impl ProxySDKClient {
    pub fn request(
        &self,
        url: &str,
        headers: Option<HeaderMap>,
        priority: Option<i32>,
        catch_status: bool,
    ) -> Result<Response, ProxyError> {
        let request = GetRequest {
            url: url.to_string(),
            header: headers,
            piece_length: None,
            tag: None,
            application: None,
            filtered_query_params: Vec::new(),
            content_for_calculating_task_id: None,
            priority,
            timeout: Duration::from_secs(5),
            client_cert: None,
        };
        let resp = runtime().block_on(async { self.client.get(request).await });
        match resp {
            Ok(resp) => Ok(Response::ProxySDK(resp)),
            Err(e) => match e {
                Error::BackendError(err) => {
                    if catch_status {
                        return Err(ProxyError::Common(format!(
                            "[proxy] backend error: {}",
                            err
                        )));
                    }
                    let mut header_map = HeaderMap::new();
                    for (key, value) in err.header {
                        if let Ok(header_name) =
                            reqwest::header::HeaderName::from_bytes(key.as_bytes())
                        {
                            if let Ok(val) = value.as_str().parse() {
                                header_map.insert(header_name, val);
                            }
                        }
                    }
                    Ok(Response::ProxySDK(GetResponse {
                        success: true,
                        status_code: err.status_code,
                        header: Some(header_map),
                        reader: None,
                    }))
                }
                Error::ProxyError(err) => match err.status_code {
                    Some(StatusCode::TOO_MANY_REQUESTS) => {
                        Err(ProxyError::TooManyRequests(format!("{}", err)))
                    }
                    Some(StatusCode::FORBIDDEN) => Err(ProxyError::Forbidden(format!("{}", err))),
                    _ => Err(ProxyError::Common(format!("[proxy] proxy error: {}", err))),
                },
                Error::DfdaemonError(err) => Err(ProxyError::Common(format!(
                    "[proxy] dfdaemon error: {}",
                    err
                ))),
                Error::RequestTimeout(err) => Err(ProxyError::Common(format!(
                    "[proxy] request timeout: {}",
                    err
                ))),
                Error::Internal(err) => Err(ProxyError::Internal(err)),
                _ => Err(ProxyError::Common(format!("[proxy] other error: {:?}", e))),
            },
        }
    }
}

#[cfg(feature = "backend-dragonfly-proxy")]
pub struct ProxySDKClients {}

#[cfg(feature = "backend-dragonfly-proxy")]
impl ProxySDKClients {
    pub fn get(endpoint: &str) -> Result<Arc<ProxySDKClient>, String> {
        {
            let guard = PROXY_SDK_CLIENT.read().unwrap();
            if let Some(client) = guard.get(endpoint) {
                return Ok(Arc::clone(client));
            }
        }

        let mut guard = PROXY_SDK_CLIENT.write().unwrap();
        if let Some(existing) = guard.get(endpoint) {
            return Ok(Arc::clone(existing));
        }

        info!("[PERF] creating new proxy sdk client for {}", endpoint);

        let client = Arc::new(ProxySDKClient {
            client: runtime()
                .block_on(async {
                    Proxy::builder()
                        .scheduler_endpoint(endpoint.to_string())
                        .max_retries(0)
                        .build()
                        .await
                })
                .map_err(|e| format!("{}", e))?,
        });
        guard.insert(endpoint.to_string(), client.clone());

        Ok(client)
    }
}
