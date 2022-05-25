// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Storage backend driver to access blobs on container image registry.
use std::collections::HashMap;
use std::io::{Error, Read, Result};
use std::sync::{Arc, RwLock};

use nydus_utils::metrics::BackendMetrics;
use reqwest::blocking::Response;
pub use reqwest::header::HeaderMap;
use reqwest::header::{HeaderValue, CONTENT_LENGTH};
use reqwest::{Method, StatusCode};
use url::{ParseError, Url};

use crate::backend::connection::{
    is_success_status, respond, Connection, ConnectionError, ReqBody,
};
use crate::backend::{
    default_http_scheme, BackendError, BackendResult, BlobBackend, BlobReader, CommonConfig,
};

const REGISTRY_CLIENT_ID: &str = "nydus-registry-client";
const HEADER_AUTHORIZATION: &str = "Authorization";
const HEADER_WWW_AUTHENTICATE: &str = "www-authenticate";

/// Error codes related to registry storage backend operations.
#[derive(Debug)]
pub enum RegistryError {
    Common(String),
    Url(ParseError),
    Request(ConnectionError),
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

/// Container registry configuration information to access blobs.
///
/// This structure is externally visible through configuration file and HTTP API, please keep them
/// stable.
#[derive(Clone, Deserialize, Serialize)]
pub struct RegistryConfig {
    #[serde(default = "default_http_scheme")]
    pub scheme: String,
    pub host: String,
    pub repo: String,
    // Base64_encoded(username:password), the field should be
    // sent to registry auth server to get a bearer token.
    #[serde(default)]
    pub auth: Option<String>,
    // The field is a bearer token to be sent to registry
    // to authorize registry requests.
    #[serde(default)]
    pub registry_token: Option<String>,
    #[serde(default)]
    pub blob_url_scheme: String,
    #[serde(default)]
    pub blob_redirected_host: String,
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
    header: Option<HeaderValue>,
}

#[derive(Debug)]
enum Auth {
    Basic(BasicAuth),
    Bearer(BearerAuth),
}

struct RegistryState {
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

    /// Request registry authentication server to get bearer token
    fn get_token(&self, auth: BearerAuth, connection: &Arc<Connection>) -> Result<String> {
        // The information needed for getting token needs to be placed both in
        // the query and in the body to be compatible with different registry
        // implementations, which have been tested on these platforms:
        // docker hub, harbor, github ghcr, aliyun acr.
        let query = vec![
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
                Some(query),
                Some(ReqBody::Form(form)),
                headers,
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

    fn get_auth_header(&self, auth: Auth, connection: &Arc<Connection>) -> Result<String> {
        match auth {
            Auth::Basic(_) => self
                .auth
                .as_ref()
                .map(|auth| format!("Basic {}", auth))
                .ok_or_else(|| einval!("invalid auth config")),
            Auth::Bearer(auth) => {
                let token = self.get_token(auth, connection)?;
                Ok(format!("Bearer {}", token))
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
}

struct RegistryReader {
    blob_id: String,
    connection: Arc<Connection>,
    state: Arc<RegistryState>,
    metrics: Arc<BackendMetrics>,
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
                .call(method, url, None, Some(data), headers, catch_status)
                .map_err(RegistryError::Request);
        }

        // Try to request registry server with `authorization` header
        let resp = self
            .connection
            .call::<&[u8]>(method.clone(), url, None, None, headers.clone(), false)
            .map_err(RegistryError::Request)?;
        if resp.status() == StatusCode::UNAUTHORIZED {
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
                        .call(method, url, None, data, headers, catch_status)
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
            .map_err(RegistryError::Url)?;
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
                    headers,
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
                                RegistryError::Url(e)
                            })?;
                        debug!("New redirected location {:?}", location.host_str());
                    }
                    let resp_ret = self
                        .connection
                        .call::<&[u8]>(Method::GET, location.as_str(), None, None, headers, true)
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
        let url = self
            .state
            .url(&format!("/blobs/sha256:{}", self.blob_id), &[])
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

    fn try_read(&self, buf: &mut [u8], offset: u64) -> BackendResult<usize> {
        self._try_read(buf, offset, true)
            .map_err(BackendError::Registry)
    }

    fn prefetch_blob_data_range(&self, _ra_offset: u64, _ra_size: u64) -> BackendResult<()> {
        Err(BackendError::Unsupported(
            "Registry backend does not support prefetch as per on-disk blob entries".to_string(),
        ))
    }

    fn stop_data_prefetch(&self) -> BackendResult<()> {
        Err(BackendError::Unsupported(
            "Registry backend does not support prefetch as per on-disk blob entries".to_string(),
        ))
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
}

impl Registry {
    #[allow(clippy::useless_let_if_seq)]
    pub fn new(config: serde_json::value::Value, id: Option<&str>) -> Result<Registry> {
        let id = id.ok_or_else(|| einval!("Registry backend requires blob_id"))?;
        let common_config: CommonConfig =
            serde_json::from_value(config.clone()).map_err(|e| einval!(e))?;
        let retry_limit = common_config.retry_limit;
        let connection = Connection::new(&common_config)?;
        let config: RegistryConfig = serde_json::from_value(config).map_err(|e| einval!(e))?;
        let auth = trim(config.auth);
        let registry_token = trim(config.registry_token);
        let (username, password) = Self::get_authorization_info(&auth)?;
        let cached_auth = if let Some(registry_token) = registry_token {
            // Store the registry bearer token to cached_auth, prefer to
            // use the token stored in cached_auth to request registry.
            Cache::new(format!("Bearer {}", registry_token))
        } else {
            Cache::new(String::new())
        };

        let state = Arc::new(RegistryState {
            scheme: config.scheme,
            host: config.host,
            repo: config.repo,
            auth,
            cached_auth,
            username,
            password,
            retry_limit,
            blob_url_scheme: config.blob_url_scheme,
            blob_redirected_host: config.blob_redirected_host,
            cached_redirect: HashCache::new(),
        });

        Ok(Registry {
            connection,
            state,
            metrics: BackendMetrics::new(id, "registry"),
        })
    }

    fn get_authorization_info(auth: &Option<String>) -> Result<(String, String)> {
        if let Some(auth) = &auth {
            let auth: Vec<u8> = base64::decode(auth.as_bytes()).map_err(|e| {
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
        let mut state = RegistryState {
            scheme: "http".to_string(),
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
        };

        assert_eq!(
            state.url("image", &["blabla"]).unwrap(),
            "http://alibaba-inc.com/v2/nydusimage?blabla".to_owned()
        );
        assert_eq!(
            state.url("image", &[]).unwrap(),
            "http://alibaba-inc.com/v2/nydusimage".to_owned()
        );

        state.scheme = "unknown_schema".to_owned();
        assert!(state.url("image", &[]).is_err());
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
}
