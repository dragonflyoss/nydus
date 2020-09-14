// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Result};
use std::path::Path;
use std::sync::{Arc, RwLock};

use reqwest::blocking::Response;
pub use reqwest::header::HeaderMap;
use reqwest::header::{HeaderValue, CONTENT_LENGTH};
use reqwest::{Method, StatusCode};
use url::Url;

use crate::storage::backend::default_http_scheme;
use crate::storage::backend::request::{is_success_status, respond, Progress, ReqBody, Request};
use crate::storage::backend::{BlobBackend, BlobBackendUploader, CommonConfig};

use nydus_utils::{einval, epipe};

const REGISTRY_CLIENT_ID: &str = "nydus-registry-client";

const HEADER_AUTHORIZATION: &str = "Authorization";
const HEADER_LOCATION: &str = "Location";
const HEADER_WWW_AUTHENTICATE: &str = "www-authenticate";

#[derive(Default)]
struct Cache(RwLock<String>);
#[derive(Default)]
struct HashCache(RwLock<HashMap<String, String>>);

impl Cache {
    fn new() -> Self {
        Cache(RwLock::new(String::new()))
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
    auth: String,
    username: String,
    password: String,
    // Still upload even if blob exists on blob server
    force_upload: bool,
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
}

#[derive(Clone, Deserialize)]
struct RegistryConfig {
    #[serde(default = "default_http_scheme")]
    scheme: String,
    host: String,
    repo: String,
    #[serde(default)]
    auth: String,
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

#[allow(clippy::useless_let_if_seq)]
pub fn new(config: serde_json::value::Value) -> Result<Registry> {
    let common_config: CommonConfig =
        serde_json::from_value(config.clone()).map_err(|e| einval!(e))?;
    let force_upload = common_config.force_upload;
    let retry_limit = common_config.retry_limit;
    let request = Request::new(common_config)?;

    let config: RegistryConfig = serde_json::from_value(config).map_err(|e| einval!(e))?;

    let username;
    let password;

    if config.auth.trim().is_empty() {
        username = String::new();
        password = String::new();
    } else {
        let auth = base64::decode(config.auth.as_bytes()).map_err(|e| {
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
        username = auth[0].to_string();
        password = auth[1].to_string();
    }

    Ok(Registry {
        request,
        scheme: config.scheme,
        host: config.host,
        repo: config.repo,
        auth: config.auth,
        username,
        password,
        force_upload,
        retry_limit,
        blob_url_scheme: config.blob_url_scheme,
        cached_auth: Cache::new(),
        cached_redirect: HashCache::new(),
    })
}

impl Registry {
    fn url(&self, path: &str, query: &[&str]) -> Result<String> {
        let path = if !query.is_empty() {
            format!("/v2/{}{}?{}", self.repo, path, query.join("&"))
        } else {
            format!("/v2/{}{}", self.repo, path)
        };
        let url = format!("{}://{}", self.scheme, self.host.as_str());
        let url = Url::parse(url.as_str()).map_err(|e| einval!(e))?;
        let url = url.join(path.as_str()).map_err(|e| einval!(e))?;

        Ok(url.to_string())
    }

    fn blob_exists(&self, blob_id: &str) -> Result<bool> {
        let url = self.url(&format!("/blobs/sha256:{}", blob_id), &[])?;

        let resp =
            self.request::<&[u8]>(Method::HEAD, url.as_str(), None, HeaderMap::new(), false)?;

        if resp.status() == StatusCode::OK {
            return Ok(true);
        }

        Ok(false)
    }

    fn create_upload(&self) -> Result<String> {
        let url = self.url("/blobs/uploads/", &[])?;

        let resp =
            self.request::<&[u8]>(Method::POST, url.as_str(), None, HeaderMap::new(), true)?;

        match resp.headers().get(HEADER_LOCATION) {
            Some(location) => Ok(location.to_str().map_err(|e| einval!(e))?.to_owned()),
            None => Err(einval!("location not found in header")),
        }
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
            Auth::Basic(_) => Ok(format!("Basic {}", self.auth)),
            Auth::Bearer(auth) => {
                let token = self.get_token(auth)?;
                Ok(format!("Bearer {}", token))
            }
        }
    }

    /// Parse `www-authenticate` response header respond from registry server
    /// The header format like: `Bearer realm="https://auth.my-registry.com/token",service="my-registry.com",scope="repository:test/repo:pull,push"`
    fn parse_auth(&self, source: &HeaderValue) -> Result<Option<Auth>> {
        let source = source.to_str().unwrap();
        let source: Vec<&str> = source.splitn(2, ' ').collect();
        if source.len() < 2 {
            return Ok(None);
        }
        let scheme = source[0].trim();
        let pairs = source[1].trim();
        let pairs = pairs.split("\",");
        let mut paras = HashMap::new();
        for pair in pairs {
            let pair: Vec<&str> = pair.trim().split('=').collect();
            if pair.len() < 2 {
                return Ok(None);
            }
            let key = pair[0].trim();
            let value = pair[1].trim().trim_matches('"');
            paras.insert(key, value);
        }

        let auth = match scheme {
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
                    return Ok(None);
                }
                Some(Auth::Bearer(BearerAuth {
                    realm: (*paras.get("realm").unwrap()).to_string(),
                    service: (*paras.get("service").unwrap()).to_string(),
                    scope: (*paras.get("scope").unwrap()).to_string(),
                }))
            }
            _ => None,
        };

        Ok(auth)
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
    ) -> Result<Response> {
        // Try get authorization header from cache for this request
        let mut last_cached_auth = String::new();
        let cached_auth = self.cached_auth.get();
        if cached_auth != "" {
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
                .map_err(|e| epipe!(format!("registry request failed {:?}", e)));
        }

        // Try to request registry server with `authorization` header
        let resp = self
            .request
            .call::<&[u8]>(method.clone(), url, None, headers.clone(), false)
            .map_err(|e| epipe!(format!("registry try request failed {:?}", e)))?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            if let Some(resp_auth_header) = resp.headers().get(HEADER_WWW_AUTHENTICATE) {
                // Get token from registry authorization server
                if let Some(auth) = self.parse_auth(resp_auth_header)? {
                    let auth_header = self.get_auth_header(auth)?;
                    headers.insert(
                        HEADER_AUTHORIZATION,
                        HeaderValue::from_str(auth_header.as_str()).unwrap(),
                    );

                    // Try to request registry server with `authorization` header again
                    let resp_ret = self
                        .request
                        .call(method, url, data, headers, catch_status)
                        .map_err(|e| epipe!(format!("registry twice request failed {:?}", e)));

                    match resp_ret {
                        Ok(resp) => {
                            let status = resp.status();
                            if is_success_status(status) {
                                // Cache authorization header for next request
                                self.cached_auth.set(last_cached_auth, auth_header)
                            }
                            if !catch_status {
                                return Ok(resp);
                            }
                            return respond(resp);
                        }
                        Err(err) => {
                            return Err(err);
                        }
                    }
                }
            }
        }

        if !catch_status {
            return Ok(resp);
        }
        respond(resp)
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
    ) -> Result<usize> {
        let url = format!("/blobs/sha256:{}", blob_id);
        let url = self.url(url.as_str(), &[])?;

        let mut headers = HeaderMap::new();
        let end_at = offset + buf.len() as u64 - 1;
        let range = format!("bytes={}-{}", offset, end_at);
        headers.insert("Range", range.parse().unwrap());

        let mut resp;
        let cached_redirect = self.cached_redirect.get(blob_id);

        if let Some(cached_redirect) = cached_redirect {
            resp = self.request.call::<&[u8]>(
                Method::GET,
                cached_redirect.as_str(),
                None,
                headers,
                false,
            )?;
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
                    let mut location = Url::parse(location).map_err(|e| einval!(e))?;
                    // Note: Some P2P proxy server supports only scheme specified origin blob server,
                    // so we need change scheme to `blob_url_scheme` here
                    if self.blob_url_scheme != "" {
                        location
                            .set_scheme(&self.blob_url_scheme)
                            .map_err(|e| einval!(e))?;
                    }
                    let resp_ret = self.request.call::<&[u8]>(
                        Method::GET,
                        location.as_str(),
                        None,
                        headers,
                        true,
                    );
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
            }
        }

        resp.copy_to(&mut buf)
            .map_err(|err| epipe!(format!("registry read failed {:?}", err)))
            .map(|size| size as usize)
    }
}

impl BlobBackend for Registry {
    #[inline]
    fn retry_limit(&self) -> u8 {
        self.retry_limit
    }

    fn blob_size(&self, blob_id: &str) -> Result<u64> {
        let url = self.url(&format!("/blobs/sha256:{}", blob_id), &[])?;

        let resp =
            self.request::<&[u8]>(Method::HEAD, url.as_str(), None, HeaderMap::new(), true)?;

        let content_length = resp
            .headers()
            .get(CONTENT_LENGTH)
            .ok_or_else(|| einval!("invalid content length"))?;

        content_length
            .to_str()
            .map_err(|err| einval!(format!("invalid content length: {:?}", err)))?
            .parse::<u64>()
            .map_err(|err| einval!(format!("invalid content length: {:?}", err)))
    }

    fn try_read(&self, blob_id: &str, buf: &mut [u8], offset: u64) -> Result<usize> {
        self._try_read(blob_id, buf, offset, true)
    }

    fn write(&self, _blob_id: &str, _buf: &[u8], _offset: u64) -> Result<usize> {
        Ok(_buf.len())
    }
}

impl BlobBackendUploader for Registry {
    fn upload(
        &self,
        blob_id: &str,
        blob_path: &Path,
        callback: fn((usize, usize)),
    ) -> Result<usize> {
        if !self.force_upload && self.blob_exists(blob_id)? {
            return Ok(0);
        }

        let location = self.create_upload()?;

        let blob_id_storage;
        let blob_id_val = if !blob_id.starts_with("sha256:") {
            blob_id_storage = format!("sha256:{}", blob_id);
            &blob_id_storage
        } else {
            blob_id
        };
        let url = Url::parse_with_params(location.as_str(), &[("digest", blob_id_val)])
            .map_err(|e| einval!(e))?;

        let url = format!(
            "{}://{}{}?{}",
            self.scheme,
            self.host,
            url.path(),
            url.query().unwrap()
        );

        let blob_file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(blob_path)
            .map_err(|e| {
                error!("registry blob upload: open failed {:?}", e);
                e
            })?;
        let size = blob_file.metadata()?.len() as usize;

        let body = Progress::new(blob_file, size, callback);

        self.request(
            Method::PUT,
            url.as_str(),
            Some(ReqBody::Read(body, size)),
            HeaderMap::new(),
            true,
        )?;

        Ok(size as usize)
    }
}
