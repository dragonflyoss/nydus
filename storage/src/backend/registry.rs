// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Storage backend driver to access blobs on container image registry.
use std::collections::HashMap;
use std::error::Error;
use std::io::{Read, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fmt, thread};

use arc_swap::{ArcSwap, ArcSwapOption};
use base64::Engine;
pub use reqwest::header::HeaderMap;
use reqwest::header::{HeaderValue, CONTENT_LENGTH};
use reqwest::{Method, StatusCode};
use url::{ParseError, Url};

use nydus_api::RegistryConfig;
use nydus_utils::metrics::BackendMetrics;

use crate::backend::connection::{Connection, ConnectionConfig, ConnectionError, ReqBody};
use crate::backend::request;
use crate::backend::request::is_success_status;
use crate::backend::{BackendContext, BackendError, BackendResult, BlobBackend, BlobReader};

const REGISTRY_CLIENT_ID: &str = "nydus-registry-client";
const HEADER_AUTHORIZATION: &str = "Authorization";
const HEADER_WWW_AUTHENTICATE: &str = "www-authenticate";

const REGISTRY_DEFAULT_TOKEN_EXPIRATION: u64 = 10 * 60; // in seconds
const REGISTRY_CONFIG_POLL_INTERVAL: u64 = 5; // in seconds

// Refresh tokens this many seconds before they expire to avoid using an expired token.
const REGISTRY_TOKEN_REFRESH_MARGIN: u64 = 20; // in seconds

/// Error codes related to registry storage backend operations.
#[derive(Debug)]
pub enum RegistryError {
    Common(String),
    Url(String, ParseError),
    Request(ConnectionError),
    Scheme(String),
    Transport(std::io::Error),
    #[cfg(feature = "backend-dragonfly-proxy")]
    Proxy(request::RequestError),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::Common(s) => write!(f, "failed to access blob from registry, {}", s),
            RegistryError::Url(u, e) => write!(f, "failed to parse URL {}, {}", u, e),
            RegistryError::Request(e) => write!(f, "failed to issue request, {}", e),
            RegistryError::Scheme(s) => write!(f, "invalid scheme, {}", s),
            RegistryError::Transport(e) => write!(f, "network transport error, {}", e),
            #[cfg(feature = "backend-dragonfly-proxy")]
            RegistryError::Proxy(e) => write!(f, "proxy error: {:?}", e),
        }
    }
}

impl From<RegistryError> for BackendError {
    fn from(error: RegistryError) -> Self {
        // Proxy errors must surface as BackendError::Request so that
        // retry_op's is_proxy_forbidden/is_proxy_limited checks match.
        #[cfg(feature = "backend-dragonfly-proxy")]
        if let RegistryError::Proxy(e) = error {
            return BackendError::Request(e);
        }
        BackendError::Registry(error)
    }
}

type RegistryResult<T> = std::result::Result<T, RegistryError>;

/// Convert a `RequestError` into a `RegistryError`, preserving proxy error types
/// so that retry_op's is_proxy_forbidden/is_proxy_limited checks work correctly.
fn request_err_to_registry(e: request::RequestError) -> RegistryError {
    match e {
        request::RequestError::Connection(ce) => RegistryError::Request(ce),
        #[cfg(feature = "backend-dragonfly-proxy")]
        e @ request::RequestError::Proxy(_) => RegistryError::Proxy(e),
        other => RegistryError::Request(ConnectionError::ErrorWithMsg(format!("{:?}", other))),
    }
}

/// Convert a request::Response into a RegistryResult, checking status if needed.
fn respond(resp: request::Response, catch_status: bool) -> RegistryResult<request::Response> {
    if !catch_status || is_success_status(resp.status()) {
        Ok(resp)
    } else {
        let msg = resp
            .text()
            .unwrap_or_else(|e| format!("failed to read response body: {}", e));
        Err(RegistryError::Request(ConnectionError::ErrorWithMsg(msg)))
    }
}

#[derive(Default)]
struct Cache(RwLock<String>);

impl Cache {
    fn new(val: String) -> Self {
        Cache(RwLock::new(val))
    }

    fn get(&self) -> String {
        let cached_guard = self.0.read().unwrap();
        if !cached_guard.is_empty() {
            return cached_guard.clone();
        }
        String::new()
    }

    fn set(&self, last: &str, current: String) {
        if last != current {
            let mut cached_guard = self.0.write().unwrap();
            *cached_guard = current;
        }
    }
}

enum ConfigAuthUpdate {
    Clear,
    Basic(String),
    RefreshBearer(BearerAuth),
}

#[derive(Default)]
struct HashCache<T>(RwLock<HashMap<String, T>>);

impl<T> HashCache<T> {
    fn new() -> Self {
        HashCache(RwLock::new(HashMap::new()))
    }

    fn get(&self, key: &str) -> Option<T>
    where
        T: Clone,
    {
        let cached_guard = self.0.read().unwrap();
        cached_guard.get(key).cloned()
    }

    fn set(&self, key: String, value: T) {
        let mut cached_guard = self.0.write().unwrap();
        cached_guard.insert(key, value);
    }

    fn remove(&self, key: &str) {
        let mut cached_guard = self.0.write().unwrap();
        cached_guard.remove(key);
    }
}

#[derive(Clone, serde::Deserialize)]
struct TokenResponse {
    /// Registry token string.
    /// This field might vary depending on the registry server.
    #[serde(default)]
    token: String,
    #[serde(default)]
    access_token: String,
    /// Registry token period of validity, in seconds.
    #[serde(default = "default_expires_in")]
    expires_in: u64,
}

fn default_expires_in() -> u64 {
    REGISTRY_DEFAULT_TOKEN_EXPIRATION
}

impl TokenResponse {
    // Extract the bearer token from the registry auth server response
    fn from_resp(resp: request::Response) -> Result<Self> {
        let body = resp.text().map_err(|e| einval!(e))?;
        let mut token: TokenResponse = serde_json::from_str(&body).map_err(|e| {
            einval!(format!(
                "failed to decode registry auth server response: {:?}",
                e
            ))
        })?;

        if token.token.is_empty() {
            if token.access_token.is_empty() {
                return Err(einval!("failed to get auth token from registry"));
            }
            token.token = token.access_token.clone();
        }
        Ok(token)
    }
}

#[derive(Debug)]
struct BasicAuth {
    #[allow(unused)]
    realm: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct BearerAuth {
    realm: String,
    service: String,
    scope: String,
}

#[derive(Debug)]
#[allow(dead_code)]
enum Auth {
    Basic(BasicAuth),
    Bearer(BearerAuth),
}

pub struct Scheme(AtomicBool);

impl Scheme {
    fn new(value: bool) -> Self {
        Scheme(AtomicBool::new(value))
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.load(Ordering::Relaxed) {
            write!(f, "https")
        } else {
            write!(f, "http")
        }
    }
}

struct RegistryState {
    id: String,
    // HTTP scheme like: https, http
    scheme: Scheme,
    host: String,
    // Image repo name like: library/ubuntu
    repo: String,
    // Retry limit for read operation
    retry_limit: u8,
    // When true, skip TLS certificate verification AND allow HTTPS-to-HTTP fallback.
    // When false (default), TLS errors propagate as-is without falling back to HTTP.
    skip_verify: bool,
    // Scheme specified for blob server
    blob_url_scheme: String,
    // Replace registry redirected url host with the given host
    blob_redirected_host: String,
    // Cache bearer token (get from registry authentication server) or basic authentication auth string.
    // We need use it to reduce the pressure on token authentication server or reduce the base64 compute workload for every request.
    // Use RwLock here to avoid using mut backend trait object.
    // Example: RwLock<"Bearer <token>">
    //          RwLock<"Basic base64(<username:password>)">
    cached_auth: Cache,
    // Cache the last registry_auth value observed from the dynamic config API.
    cached_config_auth: Cache,
    // Cache for the HTTP method when getting auth, it is "true" when using "GET" method.
    // Due to the different implementations of various image registries, auth requests
    // may use the GET or POST methods, we need to cache the method after the
    // fallback, so it can be reused next time and reduce an unnecessary request.
    cached_auth_using_http_get: HashCache<bool>,
    // Cache 30X redirect url
    // Example: RwLock<HashMap<"<blob_id>", "<redirected_url>">>
    cached_redirect: HashCache<String>,
    // The epoch timestamp of token expiration, which is obtained from the registry server.
    token_expired_at: ArcSwapOption<u64>,
    // Cache bearer auth for refreshing token.
    cached_bearer_auth: ArcSwapOption<BearerAuth>,
}

impl RegistryState {
    fn url(&self, path: &str, query: &[&str]) -> std::result::Result<String, ParseError> {
        let path = if query.is_empty() {
            format!("/v2/{}{}", self.repo, path)
        } else {
            format!("/v2/{}{}?{}", self.repo, path, query.join("&"))
        };
        let url = format!("{}://{}", self.scheme, self.host.as_str());
        let url = Url::parse(url.as_str())?;
        let url = url.join(path.as_str())?;

        Ok(url.to_string())
    }

    fn needs_fallback_http(&self, e: &dyn Error) -> bool {
        if !self.skip_verify {
            return false;
        }
        match e.source() {
            Some(err) => match err.source() {
                Some(err) => {
                    if !self.scheme.0.load(Ordering::Relaxed) {
                        return false;
                    }
                    let msg = err.to_string().to_lowercase();
                    // If we attempt to establish a TLS connection with the HTTP registry server,
                    // we are likely to encounter these types of error:
                    // https://github.com/openssl/openssl/blob/6b3d28757620e0781bb1556032bb6961ee39af63/crypto/err/openssl.txt#L1574
                    // https://github.com/containerd/nerdctl/blob/225a70bdc3b93cdb00efac7db1ceb50c098a8a16/pkg/cmd/image/push.go#LL135C66-L135C66
                    let fallback = msg.contains("wrong version number")
                        || msg.contains("connection refused")
                        || msg.to_lowercase().contains("ssl");
                    if fallback {
                        warn!("fallback to http due to tls connection error: {}", err);
                    }
                    fallback
                }
                None => false,
            },
            None => false,
        }
    }

    fn get_config_auth(&self) -> String {
        nydus_utils::config::get(&self.id, &nydus_utils::config::Keys::RegistryAuth)
    }

    fn set_config_auth(&self, auth: Option<String>) {
        if let Some(auth) = auth {
            nydus_utils::config::set(
                &self.id,
                &nydus_utils::config::Keys::RegistryAuth,
                auth.clone(),
            );
        }
    }

    fn clear_cached_auth(&self) {
        let last_cached_auth = self.cached_auth.get();
        self.cached_auth.set(&last_cached_auth, String::new());
        self.token_expired_at.store(None);
    }

    fn detect_config_auth_update(&self) -> Option<ConfigAuthUpdate> {
        let last_config_auth = self.cached_config_auth.get();
        let (config_auth, changed) = nydus_utils::config::get_changed(
            &self.id,
            &nydus_utils::config::Keys::RegistryAuth,
            &last_config_auth,
        );
        if !changed {
            return None;
        }

        self.cached_config_auth
            .set(&last_config_auth, config_auth.clone());

        if config_auth.is_empty() {
            return Some(ConfigAuthUpdate::Clear);
        }

        if let Some(cached_bearer_auth) = self.cached_bearer_auth.load().as_deref() {
            return Some(ConfigAuthUpdate::RefreshBearer(
                cached_bearer_auth.to_owned(),
            ));
        }

        Some(ConfigAuthUpdate::Basic(config_auth))
    }

    fn refresh_cached_auth_from_config(&self, request: &request::Request) {
        match self.detect_config_auth_update() {
            None => {}
            Some(ConfigAuthUpdate::Clear) => self.clear_cached_auth(),
            Some(ConfigAuthUpdate::Basic(config_auth)) => {
                let last_cached_auth = self.cached_auth.get();
                self.cached_auth
                    .set(&last_cached_auth, format!("Basic {}", config_auth));
                self.token_expired_at.store(None);
                debug!("refreshed basic registry auth after registry_auth config update");
            }
            Some(ConfigAuthUpdate::RefreshBearer(auth)) => match self.get_token(auth, request) {
                Ok(token) => {
                    let last_cached_auth = self.cached_auth.get();
                    self.cached_auth
                        .set(&last_cached_auth, format!("Bearer {}", token.token));
                    debug!("refreshed bearer registry token after registry_auth config update");
                }
                Err(err) => {
                    warn!(
                        "failed to refresh registry token after registry_auth config update: {}",
                        err
                    );
                    self.clear_cached_auth();
                }
            },
        }
    }

    // Request registry authentication server to get bearer token
    fn get_token(&self, auth: BearerAuth, request: &request::Request) -> Result<TokenResponse> {
        let http_get = self
            .cached_auth_using_http_get
            .get(&self.host)
            .unwrap_or_default();
        let resp = if http_get {
            self.fetch_token(&auth, request, Method::GET)?
        } else {
            match self.fetch_token(&auth, request, Method::POST) {
                Ok(resp) => resp,
                Err(_) => {
                    warn!("retry http GET method to get auth token");
                    let resp = self.fetch_token(&auth, request, Method::GET)?;
                    // Cache http method for next use.
                    self.cached_auth_using_http_get.set(self.host.clone(), true);
                    resp
                }
            }
        };

        let ret = TokenResponse::from_resp(resp)
            .map_err(|e| einval!(format!("failed to get auth token from registry: {:?}", e)))?;

        if let Ok(now_timestamp) = SystemTime::now().duration_since(UNIX_EPOCH) {
            self.token_expired_at
                .store(Some(Arc::new(now_timestamp.as_secs() + ret.expires_in)));
            debug!(
                "cached bearer auth, next time: {}",
                now_timestamp.as_secs() + ret.expires_in
            );
        }

        // Cache bearer auth for refreshing token.
        self.cached_bearer_auth.store(Some(Arc::new(auth)));

        Ok(ret)
    }

    // Fetches a bearer token from the registry's authentication
    fn fetch_token(
        &self,
        auth: &BearerAuth,
        request: &request::Request,
        method: Method,
    ) -> Result<request::Response> {
        let mut headers = HeaderMap::new();

        let config_auth = self.get_config_auth();
        if !config_auth.is_empty() {
            headers.insert(
                HEADER_AUTHORIZATION,
                format!("Basic {}", config_auth).parse().unwrap(),
            );
        }

        let mut query: Option<&[(&str, &str)]> = None;
        let mut body = None;

        let query_params_get;

        match method {
            Method::GET => {
                query_params_get = [
                    ("service", auth.service.as_str()),
                    ("scope", auth.scope.as_str()),
                    ("client_id", REGISTRY_CLIENT_ID),
                ];
                query = Some(&query_params_get);
            }
            Method::POST => {
                let mut form = HashMap::new();
                form.insert("service".to_string(), auth.service.clone());
                form.insert("scope".to_string(), auth.scope.clone());
                form.insert("client_id".to_string(), REGISTRY_CLIENT_ID.to_string());
                body = Some(ReqBody::Form(form));
            }
            _ => return Err(einval!()),
        }

        let mut ctx = BackendContext::default();
        let token_resp = request
            .call::<&[u8]>(
                method.clone(),
                auth.realm.as_str(),
                query,
                body,
                &mut headers,
                true,
                &mut ctx,
                true, // temp_disable_proxy: auth always goes direct
            )
            .map_err(move |e| {
                warn!(
                    "failed to request registry auth server by {:?} method: {:?}",
                    method, e
                );
                einval!()
            })?;

        Ok(token_resp)
    }

    fn get_auth_header(&self, auth: Auth, request: &request::Request) -> Result<String> {
        match auth {
            Auth::Basic(_) => Ok(format!("Basic {}", self.get_config_auth())),
            Auth::Bearer(auth) => {
                let token = self.get_token(auth, request)?;
                Ok(format!("Bearer {}", token.token))
            }
        }
    }

    /// Parse `www-authenticate` response header respond from registry server
    /// The header format like: `Bearer realm="https://auth.my-registry.com/token",service="my-registry.com",scope="repository:test/repo:pull,push"`
    fn parse_auth(source: &HeaderValue) -> Option<Auth> {
        let source = source.to_str().unwrap();
        let source: Vec<&str> = source.splitn(2, ' ').collect();
        if source.len() < 2 {
            return None;
        }
        let scheme = source[0].trim();
        let pairs = source[1].trim();
        let pairs = pairs.split("\",");
        let mut paras = HashMap::new();
        for pair in pairs {
            let pair: Vec<&str> = pair.trim().split('=').collect();
            if pair.len() < 2 {
                return None;
            }
            let key = pair[0].trim();
            let value = pair[1].trim().trim_matches('"');
            paras.insert(key, value);
        }

        match scheme {
            "Basic" => {
                let realm = if let Some(realm) = paras.get("realm") {
                    (*realm).to_string()
                } else {
                    String::new()
                };
                Some(Auth::Basic(BasicAuth { realm }))
            }
            "Bearer" => {
                if !paras.contains_key("realm") || !paras.contains_key("service") {
                    return None;
                }

                let scope = if let Some(scope) = paras.get("scope") {
                    (*scope).to_string()
                } else {
                    debug!("no scope specified for token auth challenge");
                    String::new()
                };

                Some(Auth::Bearer(BearerAuth {
                    realm: (*paras.get("realm").unwrap()).to_string(),
                    service: (*paras.get("service").unwrap()).to_string(),
                    scope,
                }))
            }
            _ => None,
        }
    }

    fn fallback_http(&self) {
        self.scheme.0.store(false, Ordering::Relaxed);
    }
}

#[derive(Clone)]
struct First {
    inner: Arc<ArcSwap<Once>>,
}

impl First {
    fn new() -> Self {
        First {
            inner: Arc::new(ArcSwap::new(Arc::new(Once::new()))),
        }
    }

    fn once<F>(&self, f: F)
    where
        F: FnOnce(),
    {
        self.inner.load().call_once(f)
    }

    fn renew(&self) {
        self.inner.store(Arc::new(Once::new()));
    }

    fn handle<F, T>(&self, handle: &mut F) -> Option<BackendResult<T>>
    where
        F: FnMut() -> BackendResult<T>,
    {
        let mut ret = None;
        // Call once twice to ensure the subsequent requests use the new
        // Once instance after renew happens.
        for _ in 0..=1 {
            self.once(|| {
                ret = Some(handle().inspect_err(|_err| {
                    // Replace the Once instance so that we can retry it when
                    // the handle call failed.
                    self.renew();
                }));
            });
            if ret.is_some() {
                break;
            }
        }
        ret
    }

    /// When invoking concurrently, only one of the handle methods will be executed first,
    /// then subsequent handle methods will be allowed to execute concurrently.
    ///
    /// Nydusd uses a registry backend which generates a surge of blob requests without
    /// auth tokens on initial startup, this caused mirror backends (e.g. dragonfly)
    /// to process very slowly. The method implements waiting for the first blob request
    /// to complete before making other blob requests, this ensures the first request
    /// caches a valid registry auth token, and subsequent concurrent blob requests can
    /// reuse the cached token.
    fn handle_force<F, T>(&self, handle: &mut F) -> BackendResult<T>
    where
        F: FnMut() -> BackendResult<T>,
    {
        self.handle(handle).unwrap_or_else(handle)
    }
}

struct RegistryReader {
    blob_id: String,
    request: Arc<request::Request>,
    state: Arc<RegistryState>,
    metrics: Arc<BackendMetrics>,
    first: First,
}

impl RegistryReader {
    /// Request registry server with `authorization` header
    ///
    /// Bearer token authenticate workflow:
    ///
    /// Request:  POST https://my-registry.com/test/repo/blobs/uploads
    /// Response: status: 401 Unauthorized
    ///           header: www-authenticate: Bearer realm="https://auth.my-registry.com/token",service="my-registry.com",scope="repository:test/repo:pull,push"
    ///
    /// Request:  POST https://auth.my-registry.com/token
    ///           body: "service=my-registry.com&scope=repository:test/repo:pull,push&grant_type=password&username=x&password=x&client_id=nydus-registry-client"
    /// Response: status: 200 Ok
    ///           body: { "token": "<token>" }
    ///
    /// Request:  POST https://my-registry.com/test/repo/blobs/uploads
    ///           header: authorization: Bearer <token>
    /// Response: status: 200 Ok
    ///
    /// Basic authenticate workflow:
    ///
    /// Request:  POST https://my-registry.com/test/repo/blobs/uploads
    /// Response: status: 401 Unauthorized
    ///           header: www-authenticate: Basic
    ///
    /// Request:  POST https://my-registry.com/test/repo/blobs/uploads
    ///           header: authorization: Basic base64(<username:password>)
    /// Response: status: 200 Ok
    fn request<R: Read + Clone + Send + 'static>(
        &self,
        method: Method,
        url: &str,
        data: Option<ReqBody<R>>,
        mut headers: HeaderMap,
        catch_status: bool,
        context: &mut BackendContext,
    ) -> RegistryResult<request::Response> {
        // Try get authorization header from cache for this request
        let mut last_cached_auth = String::new();
        let cached_auth = self.state.cached_auth.get();
        if !cached_auth.is_empty() {
            last_cached_auth = cached_auth.clone();
            headers.insert(
                HEADER_AUTHORIZATION,
                HeaderValue::from_str(cached_auth.as_str()).unwrap(),
            );
        }

        // For upload request with payload, the auth header should be cached
        // after create_upload(), so we can request registry server directly
        if let Some(data) = data {
            return self
                .request
                .call(
                    method,
                    url,
                    None,
                    Some(data),
                    &mut headers,
                    catch_status,
                    context,
                    false,
                )
                .map_err(request_err_to_registry);
        }

        // Try to request registry server with `authorization` header
        let mut resp = self
            .request
            .call::<&[u8]>(
                method.clone(),
                url,
                None,
                None,
                &mut headers,
                false,
                context,
                false,
            )
            .map_err(request_err_to_registry)?;
        if resp.status() == StatusCode::UNAUTHORIZED {
            if headers.contains_key(HEADER_AUTHORIZATION) {
                // If we request registry (harbor server) with expired authorization token,
                // the `www-authenticate: Basic realm="harbor"` in response headers is not expected.
                // Related code in harbor:
                // https://github.com/goharbor/harbor/blob/v2.5.3/src/server/middleware/v2auth/auth.go#L98
                //
                // We can remove the expired authorization token and
                // resend the request to get the correct "www-authenticate" value.
                headers.remove(HEADER_AUTHORIZATION);

                resp = self
                    .request
                    .call::<&[u8]>(
                        method.clone(),
                        url,
                        None,
                        None,
                        &mut headers,
                        false,
                        context,
                        false,
                    )
                    .map_err(request_err_to_registry)?;
            };

            if let Some(resp_auth_header) = resp.headers().get(HEADER_WWW_AUTHENTICATE) {
                // Get token from registry authorization server
                if let Some(auth) = RegistryState::parse_auth(resp_auth_header) {
                    let auth_header = self
                        .state
                        .get_auth_header(auth, &self.request)
                        .map_err(|e| RegistryError::Common(e.to_string()))?;

                    headers.insert(
                        HEADER_AUTHORIZATION,
                        HeaderValue::from_str(auth_header.as_str()).unwrap(),
                    );

                    // Try to request registry server with `authorization` header again
                    let resp = self
                        .request
                        .call(
                            method,
                            url,
                            None,
                            data,
                            &mut headers,
                            catch_status,
                            context,
                            false,
                        )
                        .map_err(request_err_to_registry)?;

                    let status = resp.status();
                    if is_success_status(status) {
                        // Cache authorization header for next request
                        self.state.cached_auth.set(&last_cached_auth, auth_header)
                    }
                    return respond(resp, catch_status);
                }
            }
        }

        respond(resp, catch_status)
    }

    /// Read data from registry server
    ///
    /// Step:
    ///
    /// Request:  GET /blobs/sha256:<blob_id>
    /// Response: status: 307 Temporary Redirect
    ///           header: location: https://raw-blob-storage-host.com/signature=x
    ///
    /// Request:  GET https://raw-blob-storage-host.com/signature=x
    /// Response: status: 200 Ok / 403 Forbidden
    /// If responding 403, we need to repeat step one
    fn _try_read(
        &self,
        buf: &mut [u8],
        offset: u64,
        allow_retry: bool,
        context: &mut BackendContext,
    ) -> RegistryResult<usize> {
        let url = format!("/blobs/sha256:{}", self.blob_id);
        let url = self
            .state
            .url(url.as_str(), &[])
            .map_err(|e| RegistryError::Url(url, e))?;
        let mut headers = HeaderMap::new();
        let end_at = offset + buf.len() as u64 - 1;
        let range = format!("bytes={}-{}", offset, end_at);
        headers.insert("Range", range.parse().unwrap());

        let mut resp;
        let cached_redirect = self.state.cached_redirect.get(&self.blob_id);

        if let Some(cached_redirect) = cached_redirect {
            resp = self
                .request
                .call::<&[u8]>(
                    Method::GET,
                    cached_redirect.as_str(),
                    None,
                    None,
                    &mut headers,
                    false,
                    context,
                    false,
                )
                .map_err(request_err_to_registry)?;

            // The request has expired or has been denied, need to re-request
            if allow_retry
                && [StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN].contains(&resp.status())
            {
                warn!(
                    "The redirected link has expired: {}, will retry read",
                    cached_redirect.as_str()
                );
                self.state.cached_redirect.remove(&self.blob_id);
                // Try read again only once
                return self._try_read(buf, offset, false, context);
            }
        } else {
            resp = match self.request::<&[u8]>(
                Method::GET,
                url.as_str(),
                None,
                headers.clone(),
                false,
                context,
            ) {
                Ok(res) => res,
                Err(RegistryError::Request(ConnectionError::Common(e)))
                    if self.state.needs_fallback_http(&e) =>
                {
                    self.state.fallback_http();
                    let url = format!("/blobs/sha256:{}", self.blob_id);
                    let url = self
                        .state
                        .url(url.as_str(), &[])
                        .map_err(|e| RegistryError::Url(url, e))?;
                    self.request::<&[u8]>(
                        Method::GET,
                        url.as_str(),
                        None,
                        headers.clone(),
                        false,
                        context,
                    )?
                }
                Err(RegistryError::Request(ConnectionError::Common(e))) => {
                    if e.to_string().contains("self signed certificate") {
                        warn!("try to enable \"skip_verify: true\" option");
                    }
                    return Err(RegistryError::Request(ConnectionError::Common(e)));
                }
                Err(e) => {
                    return Err(e);
                }
            };
            let status = resp.status();
            let need_redirect =
                status >= StatusCode::MULTIPLE_CHOICES && status < StatusCode::BAD_REQUEST;

            // Handle redirect request and cache redirect url
            if need_redirect {
                if let Some(location) = resp.headers().get("location") {
                    let location = location.to_str().unwrap();
                    let mut location = Url::parse(location)
                        .map_err(|e| RegistryError::Url(location.to_string(), e))?;
                    // Note: Some P2P proxy server supports only scheme specified origin blob server,
                    // so we need change scheme to `blob_url_scheme` here
                    if !self.state.blob_url_scheme.is_empty() {
                        location
                            .set_scheme(&self.state.blob_url_scheme)
                            .map_err(|_| {
                                RegistryError::Scheme(self.state.blob_url_scheme.clone())
                            })?;
                    }
                    if !self.state.blob_redirected_host.is_empty() {
                        location
                            .set_host(Some(self.state.blob_redirected_host.as_str()))
                            .map_err(|e| {
                                error!(
                                    "Failed to set blob redirected host to {}: {:?}",
                                    self.state.blob_redirected_host.as_str(),
                                    e
                                );
                                RegistryError::Url(location.to_string(), e)
                            })?;
                        debug!("New redirected location {:?}", location.host_str());
                    }
                    let resp_ret = self
                        .request
                        .call::<&[u8]>(
                            Method::GET,
                            location.as_str(),
                            None,
                            None,
                            &mut headers,
                            true,
                            context,
                            false,
                        )
                        .map_err(request_err_to_registry);
                    match resp_ret {
                        Ok(_resp) => {
                            trace!(
                                "redirect cache for blob={}, status={}",
                                self.blob_id,
                                status,
                            );
                            resp = _resp;
                            self.state
                                .cached_redirect
                                .set(self.blob_id.clone(), location.as_str().to_string())
                        }
                        Err(err) => {
                            return Err(err);
                        }
                    }
                };
            } else {
                resp = respond(resp, true)?;
            }
        }

        resp.copy_to(buf)
            .map_err(|e| RegistryError::Transport(std::io::Error::other(e)))
            .map(|size| size as usize)
    }

    /// Start a streaming read from the blob at the given offset.
    ///
    /// When `offset` is 0, the request is sent WITHOUT a Range header, causing
    /// Dragonfly dfdaemon to download and cache the entire blob. When `offset > 0`,
    /// an open-ended Range header (`bytes=offset-`) is used.
    fn _stream_read(
        &self,
        offset: u64,
        allow_retry: bool,
        context: &mut BackendContext,
    ) -> RegistryResult<Box<dyn Read + Send>> {
        let url = format!("/blobs/sha256:{}", self.blob_id);
        let url = self
            .state
            .url(url.as_str(), &[])
            .map_err(|e| RegistryError::Url(url, e))?;
        let mut headers = HeaderMap::new();

        // Only add Range header if offset > 0 (open-ended range to stream from offset).
        // When offset == 0: NO Range header — dfdaemon downloads full blob and caches it.
        if offset > 0 {
            let range = format!("bytes={}-", offset);
            headers.insert("Range", range.parse().unwrap());
        }

        let resp = self.request::<&[u8]>(
            Method::GET,
            url.as_str(),
            None,
            headers,
            allow_retry,
            context,
        )?;

        let status = resp.status();
        if !is_success_status(status) {
            return Err(RegistryError::Common(format!(
                "stream_read failed, status: {}",
                status,
            )));
        }

        Ok(resp.reader())
    }
}

impl BlobReader for RegistryReader {
    fn blob_size(&self) -> BackendResult<u64> {
        self.first.handle_force(&mut || -> BackendResult<u64> {
            let url = format!("/blobs/sha256:{}", self.blob_id);
            let url = self
                .state
                .url(&url, &[])
                .map_err(|e| RegistryError::Url(url, e))?;

            let mut ctx = BackendContext::default();
            let resp = match self.request::<&[u8]>(
                Method::HEAD,
                url.as_str(),
                None,
                HeaderMap::new(),
                true,
                &mut ctx,
            ) {
                Ok(res) => res,
                Err(RegistryError::Request(ConnectionError::Common(e)))
                    if self.state.needs_fallback_http(&e) =>
                {
                    self.state.fallback_http();
                    let url = format!("/blobs/sha256:{}", self.blob_id);
                    let url = self
                        .state
                        .url(&url, &[])
                        .map_err(|e| RegistryError::Url(url, e))?;
                    self.request::<&[u8]>(
                        Method::HEAD,
                        url.as_str(),
                        None,
                        HeaderMap::new(),
                        true,
                        &mut ctx,
                    )?
                }
                Err(e) => {
                    return Err(BackendError::from(e));
                }
            };
            let content_length = resp
                .headers()
                .get(CONTENT_LENGTH)
                .ok_or_else(|| RegistryError::Common("invalid content length".to_string()))?;

            Ok(content_length
                .to_str()
                .map_err(|err| RegistryError::Common(format!("invalid content length: {:?}", err)))?
                .parse::<u64>()
                .map_err(|err| {
                    RegistryError::Common(format!("invalid content length: {:?}", err))
                })?)
        })
    }

    fn try_read(&self, buf: &mut [u8], offset: u64) -> BackendResult<usize> {
        self.try_read_ctx(buf, offset, None)
    }

    fn try_read_ctx(
        &self,
        buf: &mut [u8],
        offset: u64,
        ctx: Option<&mut BackendContext>,
    ) -> BackendResult<usize> {
        let mut default_ctx = BackendContext::default();
        let ctx = ctx.unwrap_or(&mut default_ctx);
        self.first.handle_force(&mut || -> BackendResult<usize> {
            self._try_read(buf, offset, true, ctx)
                .map_err(BackendError::from)
        })
    }

    fn try_stream_read(
        &self,
        offset: u64,
        ctx: Option<&mut BackendContext>,
    ) -> BackendResult<Box<dyn Read + Send>> {
        let mut default_ctx = BackendContext::default();
        let ctx = ctx.unwrap_or(&mut default_ctx);
        self.first
            .handle_force(&mut || -> BackendResult<Box<dyn Read + Send>> {
                self._stream_read(offset, true, ctx)
                    .map_err(BackendError::from)
            })
    }

    fn metrics(&self) -> &BackendMetrics {
        &self.metrics
    }

    fn retry_limit(&self) -> u8 {
        self.state.retry_limit
    }
}

/// Storage backend based on image registry.
pub struct Registry {
    request: Arc<request::Request>,
    state: Arc<RegistryState>,
    metrics: Arc<BackendMetrics>,
    first: First,
}

impl Registry {
    #[allow(clippy::useless_let_if_seq)]
    pub fn new(config: &RegistryConfig, id: Option<&str>) -> Result<Registry> {
        let id = id.ok_or_else(|| einval!("Registry backend requires id"))?;
        let con_config: ConnectionConfig = config.clone().into();

        let retry_limit = con_config.retry_limit;
        let proxy_config = con_config.proxy.clone();
        let connection = Connection::new(&con_config)?;
        let request = request::Request::new(connection, proxy_config, false, id);
        let auth = trim(config.auth.clone());
        let registry_token = trim(config.registry_token.clone());
        Self::validate_authorization_info(&auth)?;
        let cached_auth = if let Some(registry_token) = registry_token {
            // Store the registry bearer token to cached_auth, prefer to
            // use the token stored in cached_auth to request registry.
            Cache::new(format!("Bearer {}", registry_token))
        } else {
            Cache::new(String::new())
        };

        let scheme = if !config.scheme.is_empty() && config.scheme == "http" {
            Scheme::new(false)
        } else {
            Scheme::new(true)
        };

        let state = Arc::new(RegistryState {
            id: id.to_owned(),
            scheme,
            host: config.host.clone(),
            repo: config.repo.clone(),
            cached_auth,
            cached_config_auth: Cache::new(auth.clone().unwrap_or_default()),
            retry_limit,
            skip_verify: config.skip_verify,
            blob_url_scheme: config.blob_url_scheme.clone(),
            blob_redirected_host: config.blob_redirected_host.clone(),
            cached_auth_using_http_get: HashCache::new(),
            cached_redirect: HashCache::new(),
            token_expired_at: ArcSwapOption::new(None),
            cached_bearer_auth: ArcSwapOption::new(None),
        });
        state.set_config_auth(auth);

        let registry = Registry {
            request,
            state,
            metrics: BackendMetrics::new(id, "registry"),
            first: First::new(),
        };

        registry.start_refresh_token_thread();
        info!("Refresh token thread started.");

        Ok(registry)
    }

    fn validate_authorization_info(auth: &Option<String>) -> Result<()> {
        if let Some(auth) = &auth {
            let auth: Vec<u8> = base64::engine::general_purpose::STANDARD
                .decode(auth.as_bytes())
                .map_err(|e| {
                    einval!(format!(
                        "Invalid base64 encoded registry auth config: {:?}",
                        e
                    ))
                })?;
            let auth = std::str::from_utf8(&auth).map_err(|e| {
                einval!(format!(
                    "Invalid utf-8 encoded registry auth config: {:?}",
                    e
                ))
            })?;
            let auth: Vec<&str> = auth.splitn(2, ':').collect();
            if auth.len() < 2 {
                return Err(einval!("Invalid registry auth config"));
            }
        }
        Ok(())
    }

    fn start_refresh_token_thread(&self) {
        let request = self.request.clone();
        let state = self.state.clone();
        thread::spawn(move || {
            loop {
                // Check for config auth changes every tick.
                state.refresh_cached_auth_from_config(&request);

                if let Ok(now_timestamp) = SystemTime::now().duration_since(UNIX_EPOCH) {
                    if let Some(token_expired_at) = state.token_expired_at.load().as_deref() {
                        // Refresh the token if it will expire within the margin.
                        if now_timestamp.as_secs() + REGISTRY_TOKEN_REFRESH_MARGIN
                            >= *token_expired_at
                        {
                            if let Some(cached_bearer_auth) =
                                state.cached_bearer_auth.load().as_deref()
                            {
                                if let Ok(token) =
                                    state.get_token(cached_bearer_auth.to_owned(), &request)
                                {
                                    let new_cached_auth = format!("Bearer {}", token.token);
                                    debug!(
                                        "[refresh_token_thread] registry token has been refreshed"
                                    );
                                    state
                                        .cached_auth
                                        .set(&state.cached_auth.get(), new_cached_auth);
                                } else {
                                    error!(
                                        "[refresh_token_thread] failed to refresh registry token"
                                    );
                                }
                            }
                        }
                    }
                }

                if request.is_shutdown() {
                    break;
                }
                thread::sleep(Duration::from_secs(REGISTRY_CONFIG_POLL_INTERVAL));
                if request.is_shutdown() {
                    break;
                }
            }
        });
    }
}

impl BlobBackend for Registry {
    fn shutdown(&self) {
        self.request.shutdown();
    }

    fn metrics(&self) -> &BackendMetrics {
        &self.metrics
    }

    fn get_reader(&self, blob_id: &str) -> BackendResult<Arc<dyn BlobReader>> {
        Ok(Arc::new(RegistryReader {
            blob_id: blob_id.to_owned(),
            state: self.state.clone(),
            request: self.request.clone(),
            metrics: self.metrics.clone(),
            first: self.first.clone(),
        }))
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        self.metrics.release().unwrap_or_else(|e| error!("{:?}", e));
    }
}

fn trim(value: Option<String>) -> Option<String> {
    if let Some(val) = value.as_ref() {
        let trimmed_val = val.trim();
        if trimmed_val.is_empty() {
            None
        } else if trimmed_val.len() == val.len() {
            value
        } else {
            Some(trimmed_val.to_string())
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::error::Error as StdError;
    use std::fmt::{Display, Formatter};

    #[cfg(feature = "backend-registry")]
    use http;

    #[derive(Debug)]
    struct NestedErr {
        msg: &'static str,
        source: Option<Box<dyn StdError + Send + Sync>>,
    }

    impl Display for NestedErr {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.msg)
        }
    }

    impl StdError for NestedErr {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            self.source
                .as_ref()
                .map(|source| &**source as &(dyn StdError + 'static))
        }
    }

    fn create_state(use_https: bool) -> RegistryState {
        create_state_with_skip_verify(use_https, false)
    }

    fn create_state_with_skip_verify(use_https: bool, skip_verify: bool) -> RegistryState {
        RegistryState {
            id: String::from("/"),
            scheme: Scheme::new(use_https),
            host: "example.com".to_string(),
            repo: "library/test".to_string(),
            retry_limit: 5,
            skip_verify,
            blob_url_scheme: "https".to_string(),
            blob_redirected_host: "blob.example.com".to_string(),
            cached_auth_using_http_get: Default::default(),
            cached_auth: Default::default(),
            cached_config_auth: Default::default(),
            cached_redirect: Default::default(),
            token_expired_at: ArcSwapOption::new(None),
            cached_bearer_auth: ArcSwapOption::new(None),
        }
    }

    fn nested_error(msg: &'static str) -> NestedErr {
        NestedErr {
            msg: "outer",
            source: Some(Box::new(NestedErr {
                msg: "middle",
                source: Some(Box::new(NestedErr { msg, source: None })),
            })),
        }
    }

    #[test]
    fn test_string_cache() {
        let cache = Cache::new("test".to_owned());

        assert_eq!(cache.get(), "test");

        cache.set("test", "test1".to_owned());
        assert_eq!(cache.get(), "test1");
        cache.set("test1", "test1".to_owned());
        assert_eq!(cache.get(), "test1");
    }

    #[test]
    fn test_hash_cache() {
        let cache = HashCache::new();

        assert_eq!(cache.get("test"), None);
        cache.set("test".to_owned(), "test".to_owned());
        assert_eq!(cache.get("test"), Some("test".to_owned()));
        cache.set("test".to_owned(), "test1".to_owned());
        assert_eq!(cache.get("test"), Some("test1".to_owned()));
        cache.remove("test");
        assert_eq!(cache.get("test"), None);
    }

    #[test]
    fn test_no_fallback_http_by_default() {
        // With skip_verify=false (default), never fall back to http.
        let state = create_state(true);
        assert_eq!(state.scheme.to_string(), "https");
        assert!(!state.needs_fallback_http(&nested_error("wrong version number")));
        assert!(!state.needs_fallback_http(&nested_error("SSL routines")));
    }

    #[test]
    fn test_scheme_and_fallback_http() {
        // With skip_verify=true and https, TLS errors trigger fallback.
        let state = create_state_with_skip_verify(true, true);
        assert_eq!(state.scheme.to_string(), "https");
        assert!(state.needs_fallback_http(&nested_error("wrong version number")));
        assert!(state.needs_fallback_http(&nested_error("SSL routines")));
        assert!(!state.needs_fallback_http(&nested_error("permission denied")));

        // With skip_verify=true and http, no fallback needed (already http).
        let state = create_state_with_skip_verify(false, true);
        assert_eq!(state.scheme.to_string(), "http");
        assert!(!state.needs_fallback_http(&nested_error("wrong version number")));
    }

    #[test]
    fn test_validate_authorization_info() {
        assert!(Registry::validate_authorization_info(&None).is_ok());

        let valid = Some(base64::engine::general_purpose::STANDARD.encode("user:pass"));
        assert!(Registry::validate_authorization_info(&valid).is_ok());

        let invalid_base64 = Some("%%%".to_string());
        assert!(Registry::validate_authorization_info(&invalid_base64).is_err());

        let invalid_utf8 = Some(base64::engine::general_purpose::STANDARD.encode([0xff, 0xfe]));
        assert!(Registry::validate_authorization_info(&invalid_utf8).is_err());

        let missing_colon = Some(base64::engine::general_purpose::STANDARD.encode("useronly"));
        assert!(Registry::validate_authorization_info(&missing_colon).is_err());
    }

    #[test]
    fn test_detect_config_auth_update_basic() {
        let id = "/test-detect-config-auth-update-basic";
        let state = RegistryState {
            id: id.to_string(),
            scheme: Scheme::new(true),
            host: "example.com".to_string(),
            repo: "library/test".to_string(),
            retry_limit: 5,
            skip_verify: false,
            blob_url_scheme: "https".to_string(),
            blob_redirected_host: "blob.example.com".to_string(),
            cached_auth_using_http_get: Default::default(),
            cached_auth: Default::default(),
            cached_config_auth: Default::default(),
            cached_redirect: Default::default(),
            token_expired_at: ArcSwapOption::new(None),
            cached_bearer_auth: ArcSwapOption::new(None),
        };

        nydus_utils::config::set(
            id,
            &nydus_utils::config::Keys::RegistryAuth,
            "dGVzdDp0ZXN0".to_string(),
        );

        match state.detect_config_auth_update() {
            Some(ConfigAuthUpdate::Basic(auth)) => assert_eq!(auth, "dGVzdDp0ZXN0"),
            _ => panic!("unexpected config auth update result"),
        }
        assert!(state.detect_config_auth_update().is_none());

        nydus_utils::config::remove(id, &nydus_utils::config::Keys::RegistryAuth);
    }

    #[test]
    fn test_detect_config_auth_update_clear_and_refresh_bearer() {
        let id = "/test-detect-config-auth-update-refresh-bearer";
        let state = RegistryState {
            id: id.to_string(),
            scheme: Scheme::new(true),
            host: "example.com".to_string(),
            repo: "library/test".to_string(),
            retry_limit: 5,
            skip_verify: false,
            blob_url_scheme: "https".to_string(),
            blob_redirected_host: "blob.example.com".to_string(),
            cached_auth_using_http_get: Default::default(),
            cached_auth: Default::default(),
            cached_config_auth: Cache::new("old-auth".to_string()),
            cached_redirect: Default::default(),
            token_expired_at: ArcSwapOption::new(None),
            cached_bearer_auth: ArcSwapOption::new(Some(Arc::new(BearerAuth {
                realm: "https://auth.example.com/token".to_string(),
                service: "example.com".to_string(),
                scope: "repository:library/test:pull".to_string(),
            }))),
        };

        nydus_utils::config::set(
            id,
            &nydus_utils::config::Keys::RegistryAuth,
            "bmV3LWF1dGg=".to_string(),
        );

        match state.detect_config_auth_update() {
            Some(ConfigAuthUpdate::RefreshBearer(auth)) => {
                assert_eq!(auth.realm, "https://auth.example.com/token");
                assert_eq!(auth.service, "example.com");
                assert_eq!(auth.scope, "repository:library/test:pull");
            }
            _ => panic!("unexpected config auth update result"),
        }

        nydus_utils::config::remove(id, &nydus_utils::config::Keys::RegistryAuth);

        match state.detect_config_auth_update() {
            Some(ConfigAuthUpdate::Clear) => {}
            _ => panic!("unexpected config auth clear result"),
        }
    }

    #[test]
    fn test_state_url() {
        let state = RegistryState {
            id: String::from("/"),
            scheme: Scheme::new(false),
            host: "alibaba-inc.com".to_string(),
            repo: "nydus".to_string(),
            retry_limit: 5,
            skip_verify: false,
            blob_url_scheme: "https".to_string(),
            blob_redirected_host: "oss.alibaba-inc.com".to_string(),
            cached_auth_using_http_get: Default::default(),
            cached_auth: Default::default(),
            cached_config_auth: Default::default(),
            cached_redirect: Default::default(),
            token_expired_at: ArcSwapOption::new(None),
            cached_bearer_auth: ArcSwapOption::new(None),
        };

        assert_eq!(
            state.url("image", &["blabla"]).unwrap(),
            "http://alibaba-inc.com/v2/nydusimage?blabla".to_owned()
        );
        assert_eq!(
            state.url("image", &[]).unwrap(),
            "http://alibaba-inc.com/v2/nydusimage".to_owned()
        );
    }

    #[test]
    fn test_parse_auth() {
        let str = "Bearer realm=\"https://auth.my-registry.com/token\",service=\"my-registry.com\",scope=\"repository:test/repo:pull,push\"";
        let header = HeaderValue::from_str(str).unwrap();
        let auth = RegistryState::parse_auth(&header).unwrap();
        match auth {
            Auth::Bearer(auth) => {
                assert_eq!(&auth.realm, "https://auth.my-registry.com/token");
                assert_eq!(&auth.service, "my-registry.com");
                assert_eq!(&auth.scope, "repository:test/repo:pull,push");
            }
            _ => panic!("failed to parse `Bearer` authentication header"),
        }

        // No scope is accetpable
        let str = "Bearer realm=\"https://auth.my-registry.com/token\",service=\"my-registry.com\"";
        let header = HeaderValue::from_str(str).unwrap();
        let auth = RegistryState::parse_auth(&header).unwrap();
        match auth {
            Auth::Bearer(auth) => {
                assert_eq!(&auth.realm, "https://auth.my-registry.com/token");
                assert_eq!(&auth.service, "my-registry.com");
                assert_eq!(&auth.scope, "");
            }
            _ => panic!("failed to parse `Bearer` authentication header without scope"),
        }

        let str = "Basic realm=\"https://auth.my-registry.com/token\"";
        let header = HeaderValue::from_str(str).unwrap();
        let auth = RegistryState::parse_auth(&header).unwrap();
        match auth {
            Auth::Basic(auth) => assert_eq!(&auth.realm, "https://auth.my-registry.com/token"),
            _ => panic!("failed to parse `Basic` authentication header"),
        }

        let str = "Base realm=\"https://auth.my-registry.com/token\"";
        let header = HeaderValue::from_str(str).unwrap();
        assert!(RegistryState::parse_auth(&header).is_none());

        let header = HeaderValue::from_static("Basic realm");
        assert!(RegistryState::parse_auth(&header).is_none());

        let header = HeaderValue::from_static("");
        assert!(RegistryState::parse_auth(&header).is_none());

        let header = HeaderValue::from_static(
            "Bearer realm=\"https://auth.my-registry.com/token\",scope=\"repository:test/repo:pull\"",
        );
        assert!(RegistryState::parse_auth(&header).is_none());

        let header = HeaderValue::from_static(
            "Bearer service=\"my-registry.com\",scope=\"repository:test/repo:pull\"",
        );
        assert!(RegistryState::parse_auth(&header).is_none());

        let header = HeaderValue::from_static("Basic realm=\"harbor\"");
        let auth = RegistryState::parse_auth(&header).unwrap();
        match auth {
            Auth::Basic(auth) => assert_eq!(&auth.realm, "harbor"),
            _ => panic!("failed to parse `Basic` authentication header with explicit realm"),
        }
    }

    #[test]
    fn test_trim() {
        assert_eq!(trim(None), None);
        assert_eq!(trim(Some("".to_owned())), None);
        assert_eq!(trim(Some("    ".to_owned())), None);
        assert_eq!(trim(Some("  test  ".to_owned())), Some("test".to_owned()));
        assert_eq!(trim(Some("test  ".to_owned())), Some("test".to_owned()));
        assert_eq!(trim(Some("  test".to_owned())), Some("test".to_owned()));
        assert_eq!(trim(Some("  te st  ".to_owned())), Some("te st".to_owned()));
        assert_eq!(trim(Some("te st".to_owned())), Some("te st".to_owned()));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn test_first_basically() {
        let first = First::new();
        let mut val = 0;
        first.once(|| {
            val += 1;
        });
        assert_eq!(val, 1);

        first.clone().once(|| {
            val += 1;
        });
        assert_eq!(val, 1);

        first.renew();
        first.clone().once(|| {
            val += 1;
        });
        assert_eq!(val, 2);
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn test_first_concurrently() {
        let val = Arc::new(ArcSwap::new(Arc::new(0)));
        let first = First::new();

        let mut handlers = Vec::new();
        for _ in 0..100 {
            let val_cloned = val.clone();
            let first_cloned = first.clone();
            handlers.push(std::thread::spawn(move || {
                let _ = first_cloned.handle(&mut || -> BackendResult<()> {
                    let val = val_cloned.load();
                    let ret = if *val.as_ref() == 0 {
                        std::thread::sleep(std::time::Duration::from_secs(2));
                        Err(BackendError::Registry(RegistryError::Common(String::from(
                            "network error",
                        ))))
                    } else {
                        Ok(())
                    };
                    val_cloned.store(Arc::new(val.as_ref() + 1));
                    ret
                });
            }));
        }

        for handler in handlers {
            handler.join().unwrap();
        }

        assert_eq!(*val.load().as_ref(), 2);
    }

    #[test]
    fn test_token_response_from_resp() {
        // Case 1: Response contains "token"
        let json_with_token = json!({
            "token": "test_token_value",
            "expires_in": 3600
        });
        let response = request::Response::HTTP(reqwest::blocking::Response::from(
            http::response::Builder::new()
                .body(json_with_token.to_string())
                .unwrap(),
        ));
        let result = TokenResponse::from_resp(response).unwrap();
        assert_eq!(result.token, "test_token_value");
        assert_eq!(result.expires_in, 3600);

        // Case 2: Response contains "access_token"
        let json_with_access_token = json!({
            "access_token": "test_access_token_value",
            "expires_in": 7200
        });
        let response = request::Response::HTTP(reqwest::blocking::Response::from(
            http::response::Builder::new()
                .body(json_with_access_token.to_string())
                .unwrap(),
        ));
        let result = TokenResponse::from_resp(response).unwrap();
        assert_eq!(result.token, "test_access_token_value");
        assert_eq!(result.expires_in, 7200);

        // Case 3: Default expiration time when "expires_in" is missing
        let json_with_default_expiration = json!({
            "token": "default_expiration_token"
        });
        let response = request::Response::HTTP(reqwest::blocking::Response::from(
            http::response::Builder::new()
                .body(json_with_default_expiration.to_string())
                .unwrap(),
        ));
        let result = TokenResponse::from_resp(response).unwrap();
        assert_eq!(result.token, "default_expiration_token");
        assert_eq!(result.expires_in, REGISTRY_DEFAULT_TOKEN_EXPIRATION);

        // Case 4: Response contains both token and access_token
        let json_with_both_tokens = json!({
            "token": "test_token_value",
            "access_token": "test_access_token_value",
        });
        let response = request::Response::HTTP(reqwest::blocking::Response::from(
            http::response::Builder::new()
                .body(json_with_both_tokens.to_string())
                .unwrap(),
        ));
        let result = TokenResponse::from_resp(response).unwrap();
        assert_eq!(result.token, "test_token_value");

        // Case 5: Response contains no token
        let json_with_no_token = json!({});
        let response = request::Response::HTTP(reqwest::blocking::Response::from(
            http::response::Builder::new()
                .body(json_with_no_token.to_string())
                .unwrap(),
        ));
        let result = TokenResponse::from_resp(response);
        assert!(result.is_err());
    }

    #[test]
    fn test_registry_error_display() {
        let err = RegistryError::Common("something went wrong".to_string());
        assert!(err
            .to_string()
            .contains("failed to access blob from registry"));
        assert!(err.to_string().contains("something went wrong"));

        let pe = url::Url::parse("::not-a-url").unwrap_err();
        let err = RegistryError::Url("::not-a-url".to_string(), pe);
        assert!(err.to_string().contains("failed to parse URL"));
        assert!(err.to_string().contains("::not-a-url"));

        let err = RegistryError::Request(ConnectionError::ErrorWithMsg(
            "connection refused".to_string(),
        ));
        assert!(err.to_string().contains("failed to issue request"));
        assert!(err.to_string().contains("connection refused"));

        let err = RegistryError::Scheme("ftp".to_string());
        assert!(err.to_string().contains("invalid scheme"));
        assert!(err.to_string().contains("ftp"));

        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "transport failure");
        let err = RegistryError::Transport(io_err);
        assert!(err.to_string().contains("network transport error"));
        assert!(err.to_string().contains("transport failure"));
    }

    #[cfg(feature = "backend-dragonfly-proxy")]
    #[test]
    fn test_registry_error_proxy_display() {
        let proxy_err = request::RequestError::Common("proxy unreachable".to_string());
        let err = RegistryError::Proxy(proxy_err);
        let s = err.to_string();
        assert!(s.contains("proxy"), "expected 'proxy' in '{}' ", s);
    }

    #[test]
    fn test_registry_error_into_backend_error() {
        // RegistryError::Common → BackendError::Registry
        let err: BackendError = RegistryError::Common("test".to_string()).into();
        assert!(
            matches!(err, BackendError::Registry(RegistryError::Common(_))),
            "expected BackendError::Registry, got: {:?}",
            err
        );

        // RegistryError::Request → BackendError::Registry
        let err: BackendError =
            RegistryError::Request(ConnectionError::ErrorWithMsg("msg".to_string())).into();
        assert!(
            matches!(err, BackendError::Registry(RegistryError::Request(_))),
            "expected BackendError::Registry(Request), got: {:?}",
            err
        );
    }

    #[cfg(feature = "backend-dragonfly-proxy")]
    #[test]
    fn test_registry_error_proxy_into_backend_error() {
        // RegistryError::Proxy → BackendError::Request (so retry_op checks work)
        let proxy_req_err = request::RequestError::Common("proxy error".to_string());
        let err: BackendError = RegistryError::Proxy(proxy_req_err).into();
        assert!(
            matches!(err, BackendError::Request(_)),
            "expected BackendError::Request for proxy error, got: {:?}",
            err
        );
    }

    #[test]
    fn test_request_err_to_registry_connection() {
        // RequestError::Connection → RegistryError::Request preserving inner ConnectionError
        let ce = ConnectionError::ErrorWithMsg("conn failed".to_string());
        let result = request_err_to_registry(request::RequestError::Connection(ce));
        match result {
            RegistryError::Request(ConnectionError::ErrorWithMsg(msg)) => {
                assert_eq!(msg, "conn failed");
            }
            other => panic!(
                "expected RegistryError::Request(ErrorWithMsg), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_request_err_to_registry_common() {
        // RequestError::Common → RegistryError::Request(ErrorWithMsg) containing Debug repr
        let result =
            request_err_to_registry(request::RequestError::Common("unknown error".to_string()));
        match result {
            RegistryError::Request(ConnectionError::ErrorWithMsg(msg)) => {
                // The Debug repr of RequestError::Common("unknown error") is embedded
                assert!(
                    msg.contains("unknown error"),
                    "expected debug repr in message, got: {}",
                    msg
                );
            }
            other => panic!(
                "expected RegistryError::Request(ErrorWithMsg), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_respond_returns_ok_when_status_check_disabled() {
        let response = request::Response::HTTP(reqwest::blocking::Response::from(
            http::response::Builder::new()
                .status(StatusCode::UNAUTHORIZED)
                .body("denied".to_string())
                .unwrap(),
        ));

        let result = respond(response, false).unwrap();

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_respond_returns_ok_for_success_status() {
        let response = request::Response::HTTP(reqwest::blocking::Response::from(
            http::response::Builder::new()
                .status(StatusCode::OK)
                .body("ok".to_string())
                .unwrap(),
        ));

        let result = respond(response, true).unwrap();

        assert_eq!(result.status(), StatusCode::OK);
    }

    #[test]
    fn test_respond_returns_request_error_for_failure_status() {
        let response = request::Response::HTTP(reqwest::blocking::Response::from(
            http::response::Builder::new()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .body("rate limited".to_string())
                .unwrap(),
        ));

        let result = respond(response, true);

        assert!(matches!(
            result,
            Err(RegistryError::Request(ConnectionError::ErrorWithMsg(msg)))
                if msg == "rate limited"
        ));
    }

    #[cfg(feature = "backend-dragonfly-proxy")]
    #[test]
    fn test_request_err_to_registry_proxy() {
        use crate::backend::proxy::ProxyError;
        // RequestError::Proxy → RegistryError::Proxy preserving the original error
        let proxy_err = request::RequestError::Proxy(ProxyError::Common("proxy down".to_string()));
        let result = request_err_to_registry(proxy_err);
        assert!(
            matches!(result, RegistryError::Proxy(_)),
            "expected RegistryError::Proxy, got {:?}",
            result
        );
    }

    #[test]
    fn test_first_handle_force_success() {
        let first = First::new();
        let mut call_count = 0u32;
        let result: BackendResult<u32> = first.handle_force(&mut || {
            call_count += 1;
            Ok(42)
        });
        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count, 1);
    }

    #[test]
    fn test_first_handle_force_failure() {
        let first = First::new();
        let mut call_count = 0u32;
        let result: BackendResult<u32> = first.handle_force(&mut || {
            call_count += 1;
            Err(BackendError::Registry(RegistryError::Common(
                "forced fail".to_string(),
            )))
        });
        assert!(result.is_err());
        // The Once fires the closure once; on error it renews, then handle returns
        // Some(Err) and unwrap_or_else doesn't call the closure again.
        assert_eq!(call_count, 1);
    }

    #[test]
    fn test_first_handle_force_always_executes() {
        // Fire the Once successfully so subsequent handle() calls return None.
        let first = First::new();
        first.once(|| {});

        // handle() would return None; handle_force falls back to calling the fn directly.
        let mut call_count = 0u32;
        let result: BackendResult<u32> = first.handle_force(&mut || {
            call_count += 1;
            Ok(99)
        });
        assert_eq!(result.unwrap(), 99);
        assert_eq!(
            call_count, 1,
            "handle_force must always execute the closure"
        );
    }

    #[test]
    fn test_registry_state_fallback_http() {
        let state = create_state(true);
        assert_eq!(state.scheme.to_string(), "https");
        state.fallback_http();
        assert_eq!(state.scheme.to_string(), "http");

        // Calling again on already-http state is idempotent.
        state.fallback_http();
        assert_eq!(state.scheme.to_string(), "http");
    }

    #[test]
    fn test_get_and_set_config_auth() {
        let id = "/test-get-set-config-auth";
        let state = RegistryState {
            id: id.to_string(),
            scheme: Scheme::new(true),
            host: "example.com".to_string(),
            repo: "library/test".to_string(),
            retry_limit: 5,
            skip_verify: false,
            blob_url_scheme: String::new(),
            blob_redirected_host: String::new(),
            cached_auth_using_http_get: Default::default(),
            cached_auth: Default::default(),
            cached_config_auth: Default::default(),
            cached_redirect: Default::default(),
            token_expired_at: ArcSwapOption::new(None),
            cached_bearer_auth: ArcSwapOption::new(None),
        };

        // Initially empty
        assert_eq!(state.get_config_auth(), "");

        // Set a value
        state.set_config_auth(Some("dGVzdDpwYXNz".to_string()));
        assert_eq!(state.get_config_auth(), "dGVzdDpwYXNz");

        // set_config_auth(None) is a no-op
        state.set_config_auth(None);
        assert_eq!(state.get_config_auth(), "dGVzdDpwYXNz");

        // Overwrite
        state.set_config_auth(Some("bmV3OnZhbHVl".to_string()));
        assert_eq!(state.get_config_auth(), "bmV3OnZhbHVl");

        nydus_utils::config::remove(id, &nydus_utils::config::Keys::RegistryAuth);
    }

    #[test]
    fn test_needs_fallback_http_connection_refused() {
        let state = create_state_with_skip_verify(true, true);
        assert!(state.needs_fallback_http(&nested_error("connection refused")));
    }

    #[test]
    fn test_needs_fallback_http_non_tls_error_no_fallback() {
        let state = create_state_with_skip_verify(true, true);
        assert!(!state.needs_fallback_http(&nested_error("timeout")));
        assert!(!state.needs_fallback_http(&nested_error("dns resolution failed")));
    }

    #[test]
    fn test_needs_fallback_http_single_level_error() {
        // Error with only one level of nesting (no source.source) returns false
        let err = NestedErr {
            msg: "wrong version number",
            source: Some(Box::new(NestedErr {
                msg: "no inner source",
                source: None,
            })),
        };
        let state = create_state_with_skip_verify(true, true);
        assert!(!state.needs_fallback_http(&err));
    }

    #[test]
    fn test_needs_fallback_http_no_source() {
        let err = NestedErr {
            msg: "no source at all",
            source: None,
        };
        let state = create_state_with_skip_verify(true, true);
        assert!(!state.needs_fallback_http(&err));
    }

    #[cfg(feature = "backend-registry")]
    #[test]
    fn test_respond_catch_status_disabled_passes_error_status() {
        let response = request::Response::HTTP(reqwest::blocking::Response::from(
            http::response::Builder::new()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("server error".to_string())
                .unwrap(),
        ));
        // catch_status=false, so even 500 is returned as Ok
        let result = respond(response, false);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[cfg(feature = "backend-registry")]
    #[test]
    fn test_token_response_from_resp_invalid_json() {
        let response = request::Response::HTTP(reqwest::blocking::Response::from(
            http::response::Builder::new()
                .body("not valid json {{{{".to_string())
                .unwrap(),
        ));
        let result = TokenResponse::from_resp(response);
        assert!(result.is_err());
    }

    #[test]
    fn test_request_err_to_registry_other_error() {
        let other_err = request::RequestError::Common("some other error".to_string());
        let result = request_err_to_registry(other_err);
        assert!(matches!(
            result,
            RegistryError::Request(ConnectionError::ErrorWithMsg(msg))
                if msg.contains("some other error")
        ));
    }

    #[test]
    fn test_hash_cache_remove_nonexistent() {
        let cache: HashCache<String> = HashCache::new();
        // Removing a key that doesn't exist should not panic
        cache.remove("nonexistent");
        assert_eq!(cache.get("nonexistent"), None);
    }

    #[test]
    fn test_cache_set_skips_when_last_equals_current() {
        let cache = Cache::new("initial".to_owned());
        // set() is a no-op when last == current (dedup guard)
        cache.set("same_value", "same_value".to_owned());
        assert_eq!(cache.get(), "initial");
    }

    #[test]
    fn test_state_url_with_query() {
        let state = create_state(true);
        let url = state.url("/blobs/sha256:abc", &["scope=read"]).unwrap();
        assert!(url.contains("scope=read"));
        assert!(url.contains("/v2/library/test/blobs/sha256:abc"));
    }

    #[test]
    fn test_state_url_with_multiple_queries() {
        let state = create_state(true);
        let url = state.url("/tags/list", &["n=100", "last=latest"]).unwrap();
        assert!(url.contains("n=100"));
        assert!(url.contains("last=latest"));
        assert!(url.contains("&"));
    }

    #[test]
    fn test_parse_auth_basic_with_realm() {
        let hdr = HeaderValue::from_str(r#"Basic realm="https://registry.example.com""#).unwrap();
        let auth = RegistryState::parse_auth(&hdr);
        assert!(matches!(
            auth,
            Some(Auth::Basic(b)) if b.realm == "https://registry.example.com"
        ));
    }

    #[test]
    fn test_parse_auth_bearer_missing_service() {
        let hdr =
            HeaderValue::from_str(r#"Bearer realm="https://auth.example.com/token""#).unwrap();
        let auth = RegistryState::parse_auth(&hdr);
        assert!(auth.is_none(), "Bearer without service should return None");
    }

    #[test]
    fn test_parse_auth_bearer_no_scope() {
        let hdr = HeaderValue::from_str(
            r#"Bearer realm="https://auth.example.com/token",service="example.com""#,
        )
        .unwrap();
        let auth = RegistryState::parse_auth(&hdr);
        assert!(matches!(
            auth,
            Some(Auth::Bearer(b)) if b.scope.is_empty() && b.realm == "https://auth.example.com/token"
        ));
    }

    #[test]
    fn test_parse_auth_unknown_scheme() {
        let hdr = HeaderValue::from_str(r#"Digest realm="example.com""#).unwrap();
        let auth = RegistryState::parse_auth(&hdr);
        assert!(auth.is_none());
    }

    #[test]
    fn test_first_renew_allows_re_execution() {
        let first = First::new();
        let mut count = 0u32;
        first.once(|| count += 1);
        assert_eq!(count, 1);

        // Without renew, once is a no-op
        first.once(|| count += 1);
        assert_eq!(count, 1);

        // After renew, once executes again
        first.renew();
        first.once(|| count += 1);
        assert_eq!(count, 2);
    }

    #[test]
    fn test_first_handle_error_allows_retry() {
        let first = First::new();
        let mut attempts = 0u32;

        // First handle() call fails — error triggers renew() inside once()
        let result: Option<BackendResult<u32>> = first.handle(&mut || {
            attempts += 1;
            Err(BackendError::Registry(RegistryError::Common(
                "fail".to_string(),
            )))
        });
        assert!(result.is_some());
        assert!(result.unwrap().is_err());
        assert_eq!(attempts, 1);

        // After error+renew, a second handle() call can execute again
        let result2: Option<BackendResult<u32>> = first.handle(&mut || {
            attempts += 1;
            Ok(42)
        });
        assert_eq!(result2.unwrap().unwrap(), 42);
        assert_eq!(attempts, 2);
    }

    #[test]
    fn test_registry_state_clear_cached_auth() {
        let state = create_state(true);

        // Set a cached auth token and a token expiry.
        let last = state.cached_auth.get();
        state
            .cached_auth
            .set(&last, "Bearer eyJhbGciOiJSUzI1NiJ9".to_string());
        state
            .token_expired_at
            .store(Some(Arc::new(9_999_999_999u64)));

        assert_eq!(state.cached_auth.get(), "Bearer eyJhbGciOiJSUzI1NiJ9");
        assert!(state.token_expired_at.load().is_some());

        state.clear_cached_auth();

        assert_eq!(
            state.cached_auth.get(),
            "",
            "cached_auth should be empty after clear"
        );
        assert!(
            state.token_expired_at.load().is_none(),
            "token_expired_at should be None after clear"
        );
    }

    #[test]
    fn test_stream_read_default_returns_unsupported() {
        // Verify the default BlobReader::try_stream_read() returns Unsupported.
        // RegistryReader overrides this — tested via integration/e2e with a real server.
        struct DummyReader;
        impl BlobReader for DummyReader {
            fn blob_size(&self) -> BackendResult<u64> {
                Ok(100)
            }
            fn try_read(&self, _buf: &mut [u8], _offset: u64) -> BackendResult<usize> {
                Ok(0)
            }
            fn metrics(&self) -> &nydus_utils::metrics::BackendMetrics {
                unimplemented!()
            }
        }

        let reader = DummyReader;
        let result = reader.try_stream_read(0, None);
        assert!(result.is_err());
        let err = result.err().unwrap();
        match err {
            BackendError::Unsupported(msg) => {
                assert!(msg.contains("streaming read not supported"));
            }
            other => panic!("expected Unsupported, got: {:?}", other),
        }
    }
}
