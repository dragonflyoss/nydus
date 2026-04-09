// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Dragonfly SDK proxy client and related types.
//!
//! This entire module is gated behind `backend-dragonfly-proxy`.

use std::io::Read;
use std::time::Duration;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tokio::io::AsyncRead;
use tokio::runtime::Runtime;

use dragonfly_client_util::request::errors::Error;
use dragonfly_client_util::request::Request;
use dragonfly_client_util::request::{GetRequest, GetResponse, Proxy};
use lazy_static::lazy_static;
use log::info;
use reqwest::header::HeaderMap;
use reqwest::StatusCode;

use crate::backend::request::Response;
use crate::factory::ASYNC_RUNTIME;

// --- Dragonfly header constants ---
pub const HEADER_DRAGONFLY_PRIORITY: &str = "X-Dragonfly-Priority";
pub const HEADER_DRAGONFLY_USE_P2P: &str = "X-Dragonfly-Use-P2P";
pub const HEADER_DRAGONFLY_OUTPUT_PATH: &str = "X-Dragonfly-Output-Path";
pub const HEADER_DRAGONFLY_PIECE_LENGTH: &str = "X-Dragonfly-Piece-Length";
pub const HEADER_DRAGONFLY_FORCE_HARD_LINK: &str = "X-Dragonfly-Force-Hard-Link";
pub const HEADER_DRAGONFLY_CONTENT_FOR_CALCULATING_TASK_ID: &str =
    "X-Dragonfly-Content-For-Calculating-Task-ID";
pub const HEADER_DRAGONFLY_PREFETCH: &str = "X-Dragonfly-Prefetch";
pub const HEADER_DRAGONFLY_ERROR_TYPE: &str = "X-Dragonfly-Error-Type";

pub const HEADER_VALUE_DRAGONFLY_PRIORITY_3: i32 = 3;
pub const HEADER_VALUE_DRAGONFLY_PRIORITY_6: i32 = 6;
pub const HEADER_VALUE_DRAGONFLY_USE_P2P_TRUE: &str = "true";
pub const HEADER_VALUE_DRAGONFLY_ERROR_TYPE_PROXY: &str = "proxy";

#[derive(Debug)]
pub enum ProxyError {
    Common(String),
    Internal(String),
    TooManyRequests(String),
    Forbidden(String),
}

lazy_static! {
    static ref PROXY_SDK_CLIENT: Arc<RwLock<HashMap<String, Arc<ProxySDKClient>>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

fn runtime() -> &'static Runtime {
    &ASYNC_RUNTIME
}

pub(crate) struct SyncAdapter<R> {
    inner: R,
}

impl<R> SyncAdapter<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }
}

impl<R: AsyncRead + Unpin> Read for SyncAdapter<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        runtime().block_on(async { tokio::io::AsyncReadExt::read(&mut self.inner, buf).await })
    }
}

pub struct ProxySDKClient {
    client: Proxy,
}

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

pub struct ProxySDKClients {}

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
