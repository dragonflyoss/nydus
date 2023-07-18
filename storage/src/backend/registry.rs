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
use reqwest::blocking::Response;
pub use reqwest::header::HeaderMap;
use reqwest::header::{HeaderValue, CONTENT_LENGTH};
use reqwest::{Method, StatusCode};
use url::{ParseError, Url};

use nydus_api::RegistryConfig;
use nydus_utils::metrics::BackendMetrics;

use crate::backend::connection::{
    is_success_status, respond, Connection, ConnectionConfig, ConnectionError, ReqBody,
};
use crate::backend::{BackendError, BackendResult, BlobBackend, BlobReader};

const REGISTRY_CLIENT_ID: &str = "nydus-registry-client";
const HEADER_AUTHORIZATION: &str = "Authorization";
const HEADER_WWW_AUTHENTICATE: &str = "www-authenticate";

const REDIRECTED_STATUS_CODE: [StatusCode; 2] = [
    StatusCode::MOVED_PERMANENTLY,
    StatusCode::TEMPORARY_REDIRECT,
];

const REGISTRY_DEFAULT_TOKEN_EXPIRATION: u64 = 10 * 60; // in seconds

/// Error codes related to registry storage backend operations.
#[derive(Debug)]
pub enum RegistryError {
    Common(String),
    Url(String, ParseError),
    Request(ConnectionError),
    Scheme(String),
    Transport(reqwest::Error),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::Common(s) => write!(f, "failed to access blob from registry, {}", s),
            RegistryError::Url(u, e) => write!(f, "failed to parse URL {}, {}", u, e),
            RegistryError::Request(e) => write!(f, "failed to issue request, {}", e),
            RegistryError::Scheme(s) => write!(f, "invalid scheme, {}", s),
            RegistryError::Transport(e) => write!(f, "network transport error, {}", e),
        }
    }
}

impl From<RegistryError> for BackendError {
    fn from(error: RegistryError) -> Self {
        BackendError::Registry(error)
    }
}

type RegistryResult<T> = std::result::Result<T, RegistryError>;

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

#[derive(Default)]
struct HashCache(RwLock<HashMap<String, String>>);

impl HashCache {
    fn new() -> Self {
        HashCache(RwLock::new(HashMap::new()))
    }

    fn get(&self, key: &str) -> Option<String> {
        let cached_guard = self.0.read().unwrap();
        cached_guard.get(key).cloned()
    }

    fn set(&self, key: String, value: String) {
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
    token: String,
    /// Registry token period of validity, in seconds.
    #[serde(default = "default_expires_in")]
    expires_in: u64,
}

fn default_expires_in() -> u64 {
    REGISTRY_DEFAULT_TOKEN_EXPIRATION
}

#[derive(Debug)]
struct BasicAuth {
    #[allow(unused)]
    realm: String,
}

#[derive(Debug, Clone)]
struct BearerAuth {
    realm: String,
    service: String,
    scope: String,
    header: Option<HeaderValue>,
}

#[derive(Debug)]
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
    // HTTP scheme like: https, http
    scheme: Scheme,
    host: String,
    // Image repo name like: library/ubuntu
    repo: String,
    // Base64 encoded registry auth
    auth: Option<String>,
    username: String,
    password: String,
    // Retry limit for read operation
    retry_limit: u8,
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
    // Cache 30X redirect url
    // Example: RwLock<HashMap<"<blob_id>", "<redirected_url>">>
    cached_redirect: HashCache,

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
                    let fallback =
                        msg.contains("wrong version number") || msg.contains("connection refused");
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

    /// Request registry authentication server to get bearer token
    fn get_token(&self, auth: BearerAuth, connection: &Arc<Connection>) -> Result<TokenResponse> {
        // The information needed for getting token needs to be placed both in
        // the query and in the body to be compatible with different registry
        // implementations, which have been tested on these platforms:
        // docker hub, harbor, github ghcr, aliyun acr.
        let query = [
            ("service", auth.service.as_str()),
            ("scope", auth.scope.as_str()),
            ("grant_type", "password"),
            ("username", self.username.as_str()),
            ("password", self.password.as_str()),
            ("client_id", REGISTRY_CLIENT_ID),
        ];

        let mut form = HashMap::new();
        for (k, v) in &query {
            form.insert(k.to_string(), v.to_string());
        }

        let mut headers = HeaderMap::new();
        if let Some(auth_header) = &auth.header {
            headers.insert(HEADER_AUTHORIZATION, auth_header.clone());
        }

        let token_resp = connection
            .call::<&[u8]>(
                Method::GET,
                auth.realm.as_str(),
                Some(&query),
                Some(ReqBody::Form(form)),
                &mut headers,
                true,
            )
            .map_err(|e| einval!(format!("registry auth server request failed {:?}", e)))?;
        let ret: TokenResponse = token_resp.json().map_err(|e| {
            einval!(format!(
                "registry auth server response decode failed: {:?}",
                e
            ))
        })?;
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

    fn get_auth_header(&self, auth: Auth, connection: &Arc<Connection>) -> Result<String> {
        match auth {
            Auth::Basic(_) => self
                .auth
                .as_ref()
                .map(|auth| format!("Basic {}", auth))
                .ok_or_else(|| einval!("invalid auth config")),
            Auth::Bearer(auth) => {
                let token = self.get_token(auth, connection)?;
                Ok(format!("Bearer {}", token.token))
            }
        }
    }

    /// Parse `www-authenticate` response header respond from registry server
    /// The header format like: `Bearer realm="https://auth.my-registry.com/token",service="my-registry.com",scope="repository:test/repo:pull,push"`
    fn parse_auth(source: &HeaderValue, auth: &Option<String>) -> Option<Auth> {
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
                if paras.get("realm").is_none()
                    || paras.get("service").is_none()
                    || paras.get("scope").is_none()
                {
                    return None;
                }

                let header = auth
                    .as_ref()
                    .map(|auth| HeaderValue::from_str(&format!("Basic {}", auth)).unwrap());

                Some(Auth::Bearer(BearerAuth {
                    realm: (*paras.get("realm").unwrap()).to_string(),
                    service: (*paras.get("service").unwrap()).to_string(),
                    scope: (*paras.get("scope").unwrap()).to_string(),
                    header,
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
                ret = Some(handle().map_err(|err| {
                    // Replace the Once instance so that we can retry it when
                    // the handle call failed.
                    self.renew();
                    err
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
    connection: Arc<Connection>,
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
    ) -> RegistryResult<Response> {
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
                .connection
                .call(method, url, None, Some(data), &mut headers, catch_status)
                .map_err(RegistryError::Request);
        }

        // Try to request registry server with `authorization` header
        let mut resp = self
            .connection
            .call::<&[u8]>(method.clone(), url, None, None, &mut headers, false)
            .map_err(RegistryError::Request)?;
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
                    .connection
                    .call::<&[u8]>(method.clone(), url, None, None, &mut headers, false)
                    .map_err(RegistryError::Request)?;
            };

            if let Some(resp_auth_header) = resp.headers().get(HEADER_WWW_AUTHENTICATE) {
                // Get token from registry authorization server
                if let Some(auth) = RegistryState::parse_auth(resp_auth_header, &self.state.auth) {
                    let auth_header = self
                        .state
                        .get_auth_header(auth, &self.connection)
                        .map_err(|e| RegistryError::Common(e.to_string()))?;

                    headers.insert(
                        HEADER_AUTHORIZATION,
                        HeaderValue::from_str(auth_header.as_str()).unwrap(),
                    );

                    // Try to request registry server with `authorization` header again
                    let resp = self
                        .connection
                        .call(method, url, None, data, &mut headers, catch_status)
                        .map_err(RegistryError::Request)?;

                    let status = resp.status();
                    if is_success_status(status) {
                        // Cache authorization header for next request
                        self.state.cached_auth.set(&last_cached_auth, auth_header)
                    }
                    return respond(resp, catch_status).map_err(RegistryError::Request);
                }
            }
        }

        respond(resp, catch_status).map_err(RegistryError::Request)
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
        mut buf: &mut [u8],
        offset: u64,
        allow_retry: bool,
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
                .connection
                .call::<&[u8]>(
                    Method::GET,
                    cached_redirect.as_str(),
                    None,
                    None,
                    &mut headers,
                    false,
                )
                .map_err(RegistryError::Request)?;

            // The request has expired or has been denied, need to re-request
            if allow_retry
                && vec![StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN].contains(&resp.status())
            {
                warn!(
                    "The redirected link has expired: {}, will retry read",
                    cached_redirect.as_str()
                );
                self.state.cached_redirect.remove(&self.blob_id);
                // Try read again only once
                return self._try_read(buf, offset, false);
            }
        } else {
            resp = match self.request::<&[u8]>(
                Method::GET,
                url.as_str(),
                None,
                headers.clone(),
                false,
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
                    self.request::<&[u8]>(Method::GET, url.as_str(), None, headers.clone(), false)?
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

            // Handle redirect request and cache redirect url
            if REDIRECTED_STATUS_CODE.contains(&status) {
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
                        .connection
                        .call::<&[u8]>(
                            Method::GET,
                            location.as_str(),
                            None,
                            None,
                            &mut headers,
                            true,
                        )
                        .map_err(RegistryError::Request);
                    match resp_ret {
                        Ok(_resp) => {
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
                resp = respond(resp, true).map_err(RegistryError::Request)?;
            }
        }

        resp.copy_to(&mut buf)
            .map_err(RegistryError::Transport)
            .map(|size| size as usize)
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

            let resp = match self.request::<&[u8]>(
                Method::HEAD,
                url.as_str(),
                None,
                HeaderMap::new(),
                true,
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
                    self.request::<&[u8]>(Method::HEAD, url.as_str(), None, HeaderMap::new(), true)?
                }
                Err(e) => {
                    return Err(BackendError::Registry(e));
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
        self.first.handle_force(&mut || -> BackendResult<usize> {
            self._try_read(buf, offset, true)
                .map_err(BackendError::Registry)
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
    connection: Arc<Connection>,
    state: Arc<RegistryState>,
    metrics: Arc<BackendMetrics>,
    first: First,
}

impl Registry {
    #[allow(clippy::useless_let_if_seq)]
    pub fn new(config: &RegistryConfig, id: Option<&str>) -> Result<Registry> {
        let id = id.ok_or_else(|| einval!("Registry backend requires blob_id"))?;
        let con_config: ConnectionConfig = config.clone().into();

        if !config.proxy.url.is_empty() && !config.mirrors.is_empty() {
            return Err(einval!(
                "connection: proxy and mirrors cannot be configured at the same time."
            ));
        }

        let retry_limit = con_config.retry_limit;
        let connection = Connection::new(&con_config)?;
        let auth = trim(config.auth.clone());
        let registry_token = trim(config.registry_token.clone());
        let (username, password) = Self::get_authorization_info(&auth)?;
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
            scheme,
            host: config.host.clone(),
            repo: config.repo.clone(),
            auth,
            cached_auth,
            username,
            password,
            retry_limit,
            blob_url_scheme: config.blob_url_scheme.clone(),
            blob_redirected_host: config.blob_redirected_host.clone(),
            cached_redirect: HashCache::new(),
            token_expired_at: ArcSwapOption::new(None),
            cached_bearer_auth: ArcSwapOption::new(None),
        });

        let registry = Registry {
            connection,
            state,
            metrics: BackendMetrics::new(id, "registry"),
            first: First::new(),
        };

        registry.start_refresh_token_thread();
        info!("Refresh token thread started.");

        Ok(registry)
    }

    fn get_authorization_info(auth: &Option<String>) -> Result<(String, String)> {
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

            Ok((auth[0].to_string(), auth[1].to_string()))
        } else {
            Ok((String::new(), String::new()))
        }
    }

    fn start_refresh_token_thread(&self) {
        let conn = self.connection.clone();
        let state = self.state.clone();
        // FIXME: we'd better allow users to specify the expiration time.
        let mut refresh_interval = REGISTRY_DEFAULT_TOKEN_EXPIRATION;
        thread::spawn(move || {
            loop {
                if let Ok(now_timestamp) = SystemTime::now().duration_since(UNIX_EPOCH) {
                    if let Some(token_expired_at) = state.token_expired_at.load().as_deref() {
                        // If the token will expire within the next refresh interval,
                        // refresh it immediately.
                        if now_timestamp.as_secs() + refresh_interval >= *token_expired_at {
                            if let Some(cached_bearer_auth) =
                                state.cached_bearer_auth.load().as_deref()
                            {
                                if let Ok(token) =
                                    state.get_token(cached_bearer_auth.to_owned(), &conn)
                                {
                                    let new_cached_auth = format!("Bearer {}", token.token);
                                    debug!(
                                        "[refresh_token_thread] registry token has been refreshed"
                                    );
                                    // Refresh cached token.
                                    state
                                        .cached_auth
                                        .set(&state.cached_auth.get(), new_cached_auth);
                                    // Reset refresh interval according to real expiration time,
                                    // and advance 20s to handle the unexpected cases.
                                    refresh_interval = token
                                        .expires_in
                                        .checked_sub(20)
                                        .unwrap_or(token.expires_in);
                                } else {
                                    error!(
                                        "[refresh_token_thread] failed to refresh registry token"
                                    );
                                }
                            }
                        }
                    }
                }

                if conn.shutdown.load(Ordering::Acquire) {
                    break;
                }
                thread::sleep(Duration::from_secs(refresh_interval));
                if conn.shutdown.load(Ordering::Acquire) {
                    break;
                }
            }
        });
    }
}

impl BlobBackend for Registry {
    fn shutdown(&self) {
        self.connection.shutdown();
    }

    fn metrics(&self) -> &BackendMetrics {
        &self.metrics
    }

    fn get_reader(&self, blob_id: &str) -> BackendResult<Arc<dyn BlobReader>> {
        Ok(Arc::new(RegistryReader {
            blob_id: blob_id.to_owned(),
            state: self.state.clone(),
            connection: self.connection.clone(),
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
    fn test_state_url() {
        let state = RegistryState {
            scheme: Scheme::new(false),
            host: "alibaba-inc.com".to_string(),
            repo: "nydus".to_string(),
            auth: None,
            username: "test".to_string(),
            password: "password".to_string(),
            retry_limit: 5,
            blob_url_scheme: "https".to_string(),
            blob_redirected_host: "oss.alibaba-inc.com".to_string(),
            cached_auth: Default::default(),
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
        let auth = RegistryState::parse_auth(&header, &None).unwrap();
        match auth {
            Auth::Bearer(auth) => {
                assert_eq!(&auth.realm, "https://auth.my-registry.com/token");
                assert_eq!(&auth.service, "my-registry.com");
                assert_eq!(&auth.scope, "repository:test/repo:pull,push");
            }
            _ => panic!("failed to pase `Bearer` authentication header"),
        }

        let str = "Basic realm=\"https://auth.my-registry.com/token\"";
        let header = HeaderValue::from_str(str).unwrap();
        let auth = RegistryState::parse_auth(&header, &None).unwrap();
        match auth {
            Auth::Basic(auth) => assert_eq!(&auth.realm, "https://auth.my-registry.com/token"),
            _ => panic!("failed to pase `Bearer` authentication header"),
        }

        let str = "Base realm=\"https://auth.my-registry.com/token\"";
        let header = HeaderValue::from_str(str).unwrap();
        assert!(RegistryState::parse_auth(&header, &None).is_none());
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
}
