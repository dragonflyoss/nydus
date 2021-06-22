// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::{Error, Read, Result};
use std::sync::{Arc, RwLock};

use reqwest::blocking::Response;
pub use reqwest::header::HeaderMap;
use reqwest::header::{HeaderValue, CONTENT_LENGTH};
use reqwest::{Method, StatusCode};
use url::{ParseError, Url};

use crate::backend::request::{is_success_status, respond, ReqBody, Request, RequestError};
use crate::backend::{default_http_scheme, BackendError, BackendResult};
use crate::backend::{BlobBackend, CommonConfig};
use nydus_utils::metrics::BackendMetrics;

const REGISTRY_CLIENT_ID: &str = "nydus-registry-client";
const HEADER_AUTHORIZATION: &str = "Authorization";
const HEADER_WWW_AUTHENTICATE: &str = "www-authenticate";

#[derive(Default)]
struct Cache(RwLock<String>);
#[derive(Default)]
struct HashCache(RwLock<HashMap<String, String>>);

#[derive(Debug)]
pub enum RegistryError {
    Common(String),
    Url(ParseError),
    Request(RequestError),
    Scheme(String),
    Auth(String),
    ResponseHead(String),
    Response(Error),
    Transport(reqwest::Error),
}

impl From<RegistryError> for BackendError {
    fn from(error: RegistryError) -> Self {
        BackendError::Registry(error)
    }
}

type RegistryResult<T> = std::result::Result<T, RegistryError>;

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
    fn set(&self, last: String, current: String) {
        if last != current {
            let mut cached_guard = self.0.write().unwrap();
            *cached_guard = current;
        }
    }
}

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

pub struct Registry {
    request: Arc<Request>,
    // HTTP scheme like: https, http
    scheme: String,
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
    // Cache bearer token (get from registry authentication server) or basic authentication auth string.
    // We need use it to reduce the pressure on token authentication server or reduce the base64 compute workload for every request.
    // Use RwLock here to avoid using mut backend trait object.
    // Example: RwLock<"Bearer <token>">
    //          RwLock<"Basic base64(<username:password>)">
    cached_auth: Cache,
    // Cache 30X redirect url
    // Example: RwLock<HashMap<"<blob_id>", "<redirected_url>">>
    cached_redirect: HashCache,
    metrics: Option<Arc<BackendMetrics>>,
}

#[derive(Clone, Deserialize)]
struct RegistryConfig {
    #[serde(default = "default_http_scheme")]
    scheme: String,
    host: String,
    repo: String,
    // Base64_encoded(username:password), the field should be
    // sent to registry auth server to get a bearer token.
    #[serde(default)]
    auth: Option<String>,
    // The field is a bearer token to be sent to registry
    // to authorize registry requests.
    #[serde(default)]
    registry_token: Option<String>,
    #[serde(default)]
    blob_url_scheme: String,
}

#[derive(Clone, Deserialize)]
struct TokenResponse {
    token: String,
}

#[derive(Debug)]
struct BasicAuth {
    realm: String,
}

#[derive(Debug)]
struct BearerAuth {
    realm: String,
    service: String,
    scope: String,
}

#[derive(Debug)]
enum Auth {
    Basic(BasicAuth),
    Bearer(BearerAuth),
}

fn trim(val: Option<String>) -> Option<String> {
    if let Some(ref _val) = val {
        let trimmed_val = _val.trim();
        if trimmed_val.is_empty() {
            None
        } else if trimmed_val.len() == _val.len() {
            val
        } else {
            Some(trimmed_val.to_string())
        }
    } else {
        None
    }
}

#[allow(clippy::useless_let_if_seq)]
pub fn new(config: serde_json::value::Value, id: Option<&str>) -> Result<Registry> {
    let common_config: CommonConfig =
        serde_json::from_value(config.clone()).map_err(|e| einval!(e))?;
    let retry_limit = common_config.retry_limit;
    let request = Request::new(common_config)?;

    let config: RegistryConfig = serde_json::from_value(config).map_err(|e| einval!(e))?;

    let auth = trim(config.auth);
    let registry_token = trim(config.registry_token);

    let (username, password) = if let Some(auth) = &auth {
        let auth = base64::decode(auth.as_bytes()).map_err(|e| {
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
        (auth[0].to_string(), auth[1].to_string())
    } else {
        (String::new(), String::new())
    };

    let cached_auth = if let Some(registry_token) = registry_token {
        // Store the registry bearer token to cached_auth, prefer to
        // use the token stored in cached_auth to request registry.
        Cache::new(format!("Bearer {}", registry_token))
    } else {
        Cache::new(String::new())
    };

    Ok(Registry {
        request,
        scheme: config.scheme,
        host: config.host,
        repo: config.repo,
        auth,
        cached_auth,
        username,
        password,
        retry_limit,
        blob_url_scheme: config.blob_url_scheme,
        cached_redirect: HashCache::new(),
        metrics: id.map(|i| BackendMetrics::new(i, "registry")),
    })
}

impl Registry {
    fn url(&self, path: &str, query: &[&str]) -> std::result::Result<String, ParseError> {
        let path = if !query.is_empty() {
            format!("/v2/{}{}?{}", self.repo, path, query.join("&"))
        } else {
            format!("/v2/{}{}", self.repo, path)
        };
        let url = format!("{}://{}", self.scheme, self.host.as_str());
        let url = Url::parse(url.as_str())?;
        let url = url.join(path.as_str())?;

        Ok(url.to_string())
    }

    /// Request registry authentication server to get bearer token
    fn get_token(&self, auth: BearerAuth) -> Result<String> {
        let mut query = HashMap::new();

        query.insert(String::from("service"), auth.service);
        query.insert(String::from("scope"), auth.scope);
        query.insert(String::from("grant_type"), String::from("password"));
        query.insert(String::from("username"), self.username.clone());
        query.insert(String::from("password"), self.password.clone());
        query.insert(String::from("client_id"), String::from(REGISTRY_CLIENT_ID));

        let token_resp = self
            .request
            .call::<&[u8]>(
                Method::POST,
                auth.realm.as_str(),
                Some(ReqBody::Form(query)),
                HeaderMap::new(),
                true,
            )
            .map_err(|e| einval!(format!("registry auth server request failed {:?}", e)))?;
        let ret: TokenResponse = token_resp.json().map_err(|e| {
            einval!(format!(
                "registry auth server response decode failed: {:?}",
                e
            ))
        })?;
        Ok(ret.token)
    }

    fn get_auth_header(&self, auth: Auth) -> Result<String> {
        match auth {
            Auth::Basic(_) => self
                .auth
                .as_ref()
                .map(|auth| format!("Basic {}", auth))
                .ok_or_else(|| einval!("invalid auth config")),
            Auth::Bearer(auth) => {
                let token = self.get_token(auth)?;
                Ok(format!("Bearer {}", token))
            }
        }
    }

    /// Parse `www-authenticate` response header respond from registry server
    /// The header format like: `Bearer realm="https://auth.my-registry.com/token",service="my-registry.com",scope="repository:test/repo:pull,push"`
    fn parse_auth(&self, source: &HeaderValue) -> Option<Auth> {
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
                Some(Auth::Bearer(BearerAuth {
                    realm: (*paras.get("realm").unwrap()).to_string(),
                    service: (*paras.get("service").unwrap()).to_string(),
                    scope: (*paras.get("scope").unwrap()).to_string(),
                }))
            }
            _ => None,
        }
    }

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
    fn request<R: Read + Send + 'static>(
        &self,
        method: Method,
        url: &str,
        data: Option<ReqBody<R>>,
        mut headers: HeaderMap,
        catch_status: bool,
    ) -> RegistryResult<Response> {
        // Try get authorization header from cache for this request
        let mut last_cached_auth = String::new();
        let cached_auth = self.cached_auth.get();
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
                .call(method, url, Some(data), headers, catch_status)
                .map_err(RegistryError::Request);
        }

        // Try to request registry server with `authorization` header
        let resp = self
            .request
            .call::<&[u8]>(method.clone(), url, None, headers.clone(), false)
            .map_err(RegistryError::Request)?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            if let Some(resp_auth_header) = resp.headers().get(HEADER_WWW_AUTHENTICATE) {
                // Get token from registry authorization server
                if let Some(auth) = self.parse_auth(resp_auth_header) {
                    let auth_header = self
                        .get_auth_header(auth)
                        .map_err(|e| RegistryError::Common(e.to_string()))?;
                    headers.insert(
                        HEADER_AUTHORIZATION,
                        HeaderValue::from_str(auth_header.as_str()).unwrap(),
                    );

                    // Try to request registry server with `authorization` header again
                    let resp = self
                        .request
                        .call(method, url, data, headers, catch_status)
                        .map_err(RegistryError::Request)?;

                    let status = resp.status();
                    if is_success_status(status) {
                        // Cache authorization header for next request
                        self.cached_auth.set(last_cached_auth, auth_header)
                    }
                    if !catch_status {
                        return Ok(resp);
                    }
                    return respond(resp).map_err(RegistryError::Request);
                }
            }
        }

        if !catch_status {
            return Ok(resp);
        }

        respond(resp).map_err(RegistryError::Request)
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
        blob_id: &str,
        mut buf: &mut [u8],
        offset: u64,
        allow_retry: bool,
    ) -> RegistryResult<usize> {
        let url = format!("/blobs/sha256:{}", blob_id);
        let url = self.url(url.as_str(), &[]).map_err(RegistryError::Url)?;

        let mut headers = HeaderMap::new();
        let end_at = offset + buf.len() as u64 - 1;
        let range = format!("bytes={}-{}", offset, end_at);
        headers.insert("Range", range.parse().unwrap());

        let mut resp;
        let cached_redirect = self.cached_redirect.get(blob_id);

        if let Some(cached_redirect) = cached_redirect {
            resp = self
                .request
                .call::<&[u8]>(Method::GET, cached_redirect.as_str(), None, headers, false)
                .map_err(RegistryError::Request)?;

            // The request has expired or has been denied, need to re-request
            if allow_retry
                && vec![StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN].contains(&resp.status())
            {
                warn!(
                    "The redirected link has expired: {}, will retry read",
                    cached_redirect.as_str()
                );
                self.cached_redirect.remove(blob_id);
                // Try read again only once
                return self._try_read(blob_id, buf, offset, false);
            }
        } else {
            resp =
                self.request::<&[u8]>(Method::GET, url.as_str(), None, headers.clone(), false)?;
            let status = resp.status();
            // Handle redirect request and cache redirect url
            if vec![
                StatusCode::MOVED_PERMANENTLY,
                StatusCode::TEMPORARY_REDIRECT,
            ]
            .contains(&status)
            {
                if let Some(location) = resp.headers().get("location") {
                    let location = location.to_str().unwrap();
                    let mut location = Url::parse(location).map_err(RegistryError::Url)?;
                    // Note: Some P2P proxy server supports only scheme specified origin blob server,
                    // so we need change scheme to `blob_url_scheme` here
                    if !self.blob_url_scheme.is_empty() {
                        location
                            .set_scheme(&self.blob_url_scheme)
                            .map_err(|_| RegistryError::Scheme(self.blob_url_scheme.clone()))?;
                    }
                    let resp_ret = self
                        .request
                        .call::<&[u8]>(Method::GET, location.as_str(), None, headers, true)
                        .map_err(RegistryError::Request);
                    match resp_ret {
                        Ok(_resp) => {
                            resp = _resp;
                            self.cached_redirect
                                .set(blob_id.to_string(), location.as_str().to_string())
                        }
                        Err(err) => {
                            return Err(err);
                        }
                    }
                };
            } else {
                resp = respond(resp).map_err(RegistryError::Request)?;
            }
        }

        resp.copy_to(&mut buf)
            .map_err(RegistryError::Transport)
            .map(|size| size as usize)
    }
}

impl BlobBackend for Registry {
    #[inline]
    fn retry_limit(&self) -> u8 {
        self.retry_limit
    }

    fn metrics(&self) -> &BackendMetrics {
        // Safe because nydusd must have backend attached with id, only image builder can no id
        // but use backend instance to upload blob.
        self.metrics.as_ref().unwrap()
    }

    fn release(&self) {
        self.metrics()
            .release()
            .unwrap_or_else(|e| error!("{:?}", e))
    }

    fn prefetch_blob(
        &self,
        _blob_id: &str,
        _blob_readahead_offset: u32,
        _blob_readahead_size: u32,
    ) -> BackendResult<()> {
        Err(BackendError::Unsupported(
            "Registry backend does not support prefetch as per on-disk blob entries".to_string(),
        ))
    }

    fn blob_size(&self, blob_id: &str) -> BackendResult<u64> {
        let url = self
            .url(&format!("/blobs/sha256:{}", blob_id), &[])
            .map_err(RegistryError::Url)?;

        let resp =
            self.request::<&[u8]>(Method::HEAD, url.as_str(), None, HeaderMap::new(), true)?;

        let content_length = resp
            .headers()
            .get(CONTENT_LENGTH)
            .ok_or_else(|| RegistryError::Common("invalid content length".to_string()))?;

        Ok(content_length
            .to_str()
            .map_err(|err| RegistryError::Common(format!("invalid content length: {:?}", err)))?
            .parse::<u64>()
            .map_err(|err| RegistryError::Common(format!("invalid content length: {:?}", err)))?)
    }

    fn try_read(&self, blob_id: &str, buf: &mut [u8], offset: u64) -> BackendResult<usize> {
        self._try_read(blob_id, buf, offset, true)
            .map_err(BackendError::Registry)
    }

    fn write(&self, _blob_id: &str, _buf: &[u8], _offset: u64) -> BackendResult<usize> {
        Ok(_buf.len())
    }
}
