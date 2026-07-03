//! Container image registry backend (OCI distribution spec).
//!
//! This backend resolves a blob by its full-blob digest and serves byte ranges
//! over HTTP. The merged bootstrap's device slots carry the full-blob digest, so
//! the same digest both addresses the registry blob and names the on-disk blob
//! meta. [`read_range`](BlobBackend::read_range) fetches data ranges; blob meta
//! is normally hydrated from the cache directory (the bootstrap layer ships a
//! `<full-blob>.blob.meta` per layer), and otherwise
//! [`load_blob_meta`](BlobBackend::load_blob_meta) recovers it from the blob's
//! trailing footer via range reads.
//!
//! The HTTP transport stack (connection, DNS, HTTP proxy, request routing) lives
//! at the [`backend`](crate::storage::backend) level so other HTTP-based
//! backends can reuse it; this module holds only the registry-specific logic.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use reqwest::header::{
    HeaderMap, AUTHORIZATION, CONTENT_LENGTH, LOCATION, RANGE, WWW_AUTHENTICATE,
};
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use url::Url;

use super::pauser::BACKEND_PAUSER;
use super::{BlobBackend, ReadContext, RequestSource};
use crate::metadata::{BlobFooter, BlobMeta, EROFS_BLOB_ID_SIZE, LEPTON_BLOB_FOOTER_SIZE};
use crate::utils::hex_string;

use super::http::{Connection, ConnectionConfig};
use super::proxy::{HttpProxy, ProxyConfig};
use super::request::{is_success_status, Request, RequestError, Response};

#[cfg(feature = "backend-dragonfly-proxy")]
use super::dragonfly_sdk::DragonflySdk;

const CLIENT_ID: &str = "lepton-registry-client";
const DEFAULT_TIMEOUT: u64 = 30;
const DEFAULT_RETRY_LIMIT: u8 = 3;
const DEFAULT_TOKEN_EXPIRATION: u64 = 10 * 60;
const TOKEN_REFRESH_MARGIN: u64 = 20;

/// User-facing configuration for the registry backend, parsed from the opaque
/// `backend.config` map.
#[derive(Debug, Clone, Deserialize)]
struct RegistryConfig {
    /// Registry host, e.g. `registry-1.docker.io` or `127.0.0.1:5000`.
    host: String,
    /// Image repository, e.g. `library/ubuntu`.
    repo: String,
    /// Use the `http` scheme instead of `https`.
    #[serde(default)]
    insecure: bool,
    /// Skip TLS certificate verification.
    #[serde(default)]
    skip_verify: bool,
    /// Per-request timeout in seconds.
    #[serde(default = "default_timeout")]
    timeout: u64,
    /// Retry limit for on-demand reads.
    #[serde(default = "default_retry_limit")]
    retry_limit: u8,
    /// Optional credentials: base64-encoded `username:password` for HTTP Basic
    /// auth (the value sent verbatim after `Basic `).
    #[serde(default)]
    auth: Option<String>,
    /// Extra CA certificate PEM files to trust.
    #[serde(default)]
    ca_cert_files: Vec<String>,
    /// Optional proxy (HTTP mirror and/or Dragonfly SDK).
    #[serde(default)]
    proxy: Option<ProxyConfig>,
}

fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT
}

fn default_retry_limit() -> u8 {
    DEFAULT_RETRY_LIMIT
}

/// Errors produced by the registry backend.
#[derive(Debug)]
enum RegistryError {
    Io(io::Error),
    Url(String),
    Auth(String),
    Status(StatusCode, String),
    ProxyForbidden(String),
    ProxyTooManyRequests(String),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::Io(e) => write!(f, "{e}"),
            RegistryError::Url(s) => write!(f, "invalid url: {s}"),
            RegistryError::Auth(s) => write!(f, "authentication failed: {s}"),
            RegistryError::Status(code, s) => write!(f, "unexpected status {code}: {s}"),
            RegistryError::ProxyForbidden(s) => write!(f, "proxy forbidden: {s}"),
            RegistryError::ProxyTooManyRequests(s) => write!(f, "proxy too many requests: {s}"),
        }
    }
}

impl From<RegistryError> for io::Error {
    fn from(err: RegistryError) -> Self {
        match err {
            RegistryError::Io(e) => e,
            other => io::Error::other(other.to_string()),
        }
    }
}

impl From<RequestError> for RegistryError {
    fn from(err: RequestError) -> Self {
        match err {
            RequestError::Network(e) => RegistryError::Io(e),
            RequestError::ProxyForbidden(s) => RegistryError::ProxyForbidden(s),
            RequestError::ProxyTooManyRequests(s) => RegistryError::ProxyTooManyRequests(s),
        }
    }
}

type RegistryResult<T> = Result<T, RegistryError>;

/// Authentication challenge parsed from a `www-authenticate` header.
enum Challenge {
    Basic,
    Bearer {
        realm: String,
        service: String,
        scope: String,
    },
}

/// Shared, mutable state for the registry backend.
struct RegistryState {
    scheme: &'static str,
    host: String,
    repo: String,
    retry_limit: u8,
    /// `Basic base64(user:pass)` value, if credentials were supplied.
    basic_auth: Option<String>,
    /// Cached `Authorization` header value (`Bearer ...` or `Basic ...`).
    cached_auth: RwLock<String>,
    /// Epoch second at which a cached bearer token expires (None for basic).
    token_expires_at: ArcSwapOption<u64>,
    /// Cache of resolved 3xx redirect URLs, keyed by blob hex digest.
    cached_redirect: RwLock<HashMap<String, String>>,
}

impl RegistryState {
    fn blob_url(&self, hex: &str) -> RegistryResult<String> {
        Ok(format!(
            "{}://{}/v2/{}/blobs/sha256:{}",
            self.scheme, self.host, self.repo, hex
        ))
    }

    /// Return the currently valid cached auth header, clearing expired tokens.
    fn current_auth(&self) -> String {
        if let Some(expires_at) = self.token_expires_at.load().as_deref().copied() {
            let now = now_secs();
            if now + TOKEN_REFRESH_MARGIN >= expires_at {
                self.clear_auth();
                return String::new();
            }
        }
        self.cached_auth.read().unwrap().clone()
    }

    fn set_auth(&self, value: String) {
        *self.cached_auth.write().unwrap() = value;
    }

    fn clear_auth(&self) {
        self.cached_auth.write().unwrap().clear();
        self.token_expires_at.store(None);
    }

    fn get_redirect(&self, hex: &str) -> Option<String> {
        self.cached_redirect.read().unwrap().get(hex).cloned()
    }

    fn set_redirect(&self, hex: &str, url: String) {
        self.cached_redirect
            .write()
            .unwrap()
            .insert(hex.to_string(), url);
    }

    fn remove_redirect(&self, hex: &str) {
        self.cached_redirect.write().unwrap().remove(hex);
    }

    /// Parse a `www-authenticate` header value into a [`Challenge`].
    fn parse_challenge(value: &str) -> Option<Challenge> {
        let (scheme, rest) = value.split_once(' ')?;
        match scheme.trim() {
            "Basic" => Some(Challenge::Basic),
            "Bearer" => {
                let mut params = HashMap::new();
                for pair in rest.split(',') {
                    if let Some((k, v)) = pair.trim().split_once('=') {
                        params.insert(k.trim(), v.trim().trim_matches('"'));
                    }
                }
                Some(Challenge::Bearer {
                    realm: (*params.get("realm")?).to_string(),
                    service: params.get("service").copied().unwrap_or("").to_string(),
                    scope: params.get("scope").copied().unwrap_or("").to_string(),
                })
            }
            _ => None,
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Bearer token response from a registry auth server.
#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default)]
    token: String,
    #[serde(default)]
    access_token: String,
    #[serde(default = "default_token_expiration")]
    expires_in: u64,
}

fn default_token_expiration() -> u64 {
    DEFAULT_TOKEN_EXPIRATION
}

/// Storage backend backed by an OCI image registry.
pub struct Registry {
    state: Arc<RegistryState>,
    request: Arc<Request>,
    /// Whether reads are served through a proxy (HTTP mirror or Dragonfly),
    /// used to attribute backend read and CRC metrics.
    target: crate::metrics::BackendTarget,
    // Ensures the first authenticated request completes before a burst of
    // concurrent reads, so they can reuse the cached token instead of each
    // performing their own auth handshake.
    first_done: AtomicBool,
}

impl Registry {
    /// Build a registry backend from its YAML configuration value.
    pub fn from_value(value: &serde_yaml::Value) -> io::Result<Self> {
        let config: RegistryConfig = serde_yaml::from_value(value.clone()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid registry backend config: {e}"),
            )
        })?;
        Self::new(config)
    }

    fn new(config: RegistryConfig) -> io::Result<Self> {
        let conn_config = ConnectionConfig {
            skip_verify: config.skip_verify,
            timeout: config.timeout,
            ca_cert_files: config.ca_cert_files.clone(),
        };
        let connection = Connection::new(&conn_config)?;

        let proxy = match config.proxy.as_ref().and_then(|p| p.url.as_deref()) {
            Some(url) => Some(HttpProxy::new(&conn_config, url)?),
            None => None,
        };

        #[cfg(feature = "backend-dragonfly-proxy")]
        let dragonfly = match config
            .proxy
            .as_ref()
            .and_then(|p| p.dragonfly_scheduler_endpoint.as_deref())
        {
            Some(endpoint) => Some(DragonflySdk::new(endpoint)?),
            None => None,
        };

        // Reads are proxied when an HTTP proxy or Dragonfly endpoint is set.
        #[cfg(feature = "backend-dragonfly-proxy")]
        let via_proxy = proxy.is_some() || dragonfly.is_some();
        #[cfg(not(feature = "backend-dragonfly-proxy"))]
        let via_proxy = proxy.is_some();
        let target = if via_proxy {
            crate::metrics::BackendTarget::Proxy
        } else {
            crate::metrics::BackendTarget::Origin
        };

        let request = Request::new(
            connection,
            proxy,
            #[cfg(feature = "backend-dragonfly-proxy")]
            dragonfly,
        );

        // `auth`, when present, is already a base64-encoded `username:password`
        // string sent verbatim after the `Basic ` scheme prefix.
        let basic_auth = config.auth.clone();

        let state = Arc::new(RegistryState {
            scheme: if config.insecure { "http" } else { "https" },
            host: config.host,
            repo: config.repo,
            retry_limit: config.retry_limit,
            basic_auth,
            cached_auth: RwLock::new(String::new()),
            token_expires_at: ArcSwapOption::from(None),
            cached_redirect: RwLock::new(HashMap::new()),
        });

        Ok(Registry {
            state,
            request,
            target,
            first_done: AtomicBool::new(false),
        })
    }

    /// Fill `dst` with the blob byte range, retrying per the source policy.
    fn retry_read(
        &self,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
        offset: u64,
        dst: &mut [u8],
        ctx: ReadContext,
    ) -> RegistryResult<()> {
        BACKEND_PAUSER.wait_if_paused();

        let max_attempts = match ctx.source {
            RequestSource::Prefetch => 1,
            RequestSource::OnDemand => self.state.retry_limit.max(1),
        };

        let mut attempt = 0u8;
        loop {
            attempt += 1;
            match self.try_read(blob_id, offset, dst, ctx) {
                Ok(()) => return Ok(()),
                // Proxy denials are not retryable.
                Err(e @ RegistryError::ProxyForbidden(_)) => return Err(e),
                // Prefetch should never hammer a rate-limited proxy.
                Err(e @ RegistryError::ProxyTooManyRequests(_))
                    if ctx.source == RequestSource::Prefetch =>
                {
                    return Err(e);
                }
                Err(e) => {
                    if attempt >= max_attempts {
                        return Err(e);
                    }
                    // Back off with jitter before retrying.
                    let base = 50u64 * attempt as u64;
                    let jitter = rand::random::<u64>() % 100;
                    std::thread::sleep(Duration::from_millis(base + jitter));
                }
            }
        }
    }

    fn try_read(
        &self,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
        offset: u64,
        dst: &mut [u8],
        ctx: ReadContext,
    ) -> RegistryResult<()> {
        let hex = hex_string(blob_id);
        let end = offset + dst.len() as u64 - 1;
        let range = format!("bytes={offset}-{end}");

        // Fast path: a previously cached redirect URL.
        if let Some(redirect) = self.state.get_redirect(&hex) {
            let mut headers = HeaderMap::new();
            headers.insert(RANGE, range.parse().unwrap());
            let resp = self
                .request
                .call(Method::GET, &redirect, headers, ctx, true)?;
            let status = resp.status();
            if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                // The signed link expired; drop it and fall through to re-resolve.
                self.state.remove_redirect(&hex);
            } else if is_success_status(status) {
                return fill_exact(resp, dst);
            } else {
                return Err(status_error(resp));
            }
        }

        let url = self.state.blob_url(&hex)?;
        let mut headers = HeaderMap::new();
        headers.insert(RANGE, range.parse().unwrap());
        let resp = self.authorized_request(Method::GET, &url, headers, ctx)?;
        let status = resp.status();

        if is_redirect(status) {
            let location = resp
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| RegistryError::Url("missing redirect location".to_string()))?
                .to_string();

            let mut redirect_headers = HeaderMap::new();
            redirect_headers.insert(RANGE, range.parse().unwrap());
            let redirected =
                self.request
                    .call(Method::GET, &location, redirect_headers, ctx, true)?;
            if !is_success_status(redirected.status()) {
                return Err(status_error(redirected));
            }
            self.state.set_redirect(&hex, location);
            fill_exact(redirected, dst)
        } else if is_success_status(status) {
            fill_exact(resp, dst)
        } else {
            Err(status_error(resp))
        }
    }

    /// Resolve the total size of a blob via a `HEAD` request, following a single
    /// redirect to a signed CDN URL if necessary.
    fn blob_size(&self, blob_id: &[u8; EROFS_BLOB_ID_SIZE]) -> RegistryResult<u64> {
        let hex = hex_string(blob_id);
        let url = self.state.blob_url(&hex)?;
        let resp = self.authorized_request(
            Method::HEAD,
            &url,
            HeaderMap::new(),
            ReadContext::raw(RequestSource::OnDemand),
        )?;
        let status = resp.status();

        let resp = if is_redirect(status) {
            let location = resp
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| RegistryError::Url("missing redirect location".to_string()))?
                .to_string();
            let redirected = self.request.call(
                Method::HEAD,
                &location,
                HeaderMap::new(),
                ReadContext::raw(RequestSource::OnDemand),
                true,
            )?;
            if !is_success_status(redirected.status()) {
                return Err(status_error(redirected));
            }
            redirected
        } else if is_success_status(status) {
            resp
        } else {
            return Err(status_error(resp));
        };

        resp.headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or_else(|| {
                RegistryError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "registry HEAD response missing a valid content-length",
                ))
            })
    }

    /// Recover a blob's metadata from its trailing footer using range reads:
    /// HEAD for the total size, read the footer, then read the blob meta region
    /// it points at. Used only when the cache directory has no prefetched
    /// `<full-blob>.blob.meta` for this blob.
    fn fetch_blob_meta(&self, blob_id: &[u8; EROFS_BLOB_ID_SIZE]) -> RegistryResult<BlobMeta> {
        let size = self.blob_size(blob_id)?;
        if size < LEPTON_BLOB_FOOTER_SIZE as u64 {
            return Err(RegistryError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "registry blob is too small for a lepton footer",
            )));
        }

        let mut footer_bytes = vec![0u8; LEPTON_BLOB_FOOTER_SIZE];
        self.retry_read(
            blob_id,
            size - LEPTON_BLOB_FOOTER_SIZE as u64,
            &mut footer_bytes,
            ReadContext::raw(RequestSource::OnDemand),
        )?;
        let footer = BlobFooter::parse(&footer_bytes, size)
            .map_err(|e| RegistryError::Io(io::Error::other(e.to_string())))?;

        let blob_meta_size = usize::try_from(footer.blob_meta_size()).map_err(|_| {
            RegistryError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "blob meta size exceeds usize",
            ))
        })?;
        let mut blob_meta_bytes = vec![0u8; blob_meta_size];
        self.retry_read(
            blob_id,
            footer.blob_meta_offset(),
            &mut blob_meta_bytes,
            ReadContext::raw(RequestSource::OnDemand),
        )?;

        BlobMeta::from_bytes_with_blob_id(&blob_meta_bytes, *blob_id)
            .map_err(|e| RegistryError::Io(io::Error::other(e.to_string())))
    }

    /// Issue a request, transparently performing the auth handshake on `401`.
    fn authorized_request(
        &self,
        method: Method,
        url: &str,
        mut headers: HeaderMap,
        ctx: ReadContext,
    ) -> RegistryResult<Response> {
        let cached_auth = self.state.current_auth();
        if !cached_auth.is_empty() {
            headers.insert(AUTHORIZATION, cached_auth.parse().unwrap());
        }

        let resp = self
            .request
            .call(method.clone(), url, headers.clone(), ctx, true)?;
        if resp.status() != StatusCode::UNAUTHORIZED {
            return Ok(resp);
        }

        // Drop any stale token so the server returns the expected challenge.
        let challenge_resp = if headers.remove(AUTHORIZATION).is_some() {
            self.request
                .call(method.clone(), url, headers.clone(), ctx, true)?
        } else {
            resp
        };

        let challenge = challenge_resp
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .and_then(RegistryState::parse_challenge);

        let Some(challenge) = challenge else {
            return Ok(challenge_resp);
        };

        let auth_header = self.obtain_auth(challenge)?;
        headers.insert(AUTHORIZATION, auth_header.parse().unwrap());
        let resp = self.request.call(method, url, headers, ctx, true)?;
        if is_success_status(resp.status()) || is_redirect(resp.status()) {
            self.state.set_auth(auth_header);
        }
        Ok(resp)
    }

    fn obtain_auth(&self, challenge: Challenge) -> RegistryResult<String> {
        match challenge {
            Challenge::Basic => {
                let basic = self.state.basic_auth.as_ref().ok_or_else(|| {
                    RegistryError::Auth("registry requires basic-auth credentials".to_string())
                })?;
                Ok(format!("Basic {basic}"))
            }
            Challenge::Bearer {
                realm,
                service,
                scope,
            } => {
                let token = self.fetch_token(&realm, &service, &scope)?;
                Ok(format!("Bearer {token}"))
            }
        }
    }

    fn fetch_token(&self, realm: &str, service: &str, scope: &str) -> RegistryResult<String> {
        let mut url = Url::parse(realm).map_err(|e| RegistryError::Url(format!("{realm}: {e}")))?;
        {
            let mut query = url.query_pairs_mut();
            if !service.is_empty() {
                query.append_pair("service", service);
            }
            if !scope.is_empty() {
                query.append_pair("scope", scope);
            }
            query.append_pair("client_id", CLIENT_ID);
        }

        let mut headers = HeaderMap::new();
        if let Some(basic) = &self.state.basic_auth {
            headers.insert(AUTHORIZATION, format!("Basic {basic}").parse().unwrap());
        }

        // Auth requests always go directly to the auth server, never via proxy.
        let resp = self.request.call(
            Method::GET,
            url.as_str(),
            headers,
            ReadContext::raw(RequestSource::OnDemand),
            false,
        )?;
        if !is_success_status(resp.status()) {
            return Err(status_error(resp));
        }

        let body = resp.text().map_err(RegistryError::Io)?;
        let mut token: TokenResponse = serde_json::from_str(&body)
            .map_err(|e| RegistryError::Auth(format!("invalid token response: {e}")))?;
        if token.token.is_empty() {
            token.token = token.access_token.clone();
        }
        if token.token.is_empty() {
            return Err(RegistryError::Auth("empty token from registry".to_string()));
        }

        self.state
            .token_expires_at
            .store(Some(Arc::new(now_secs() + token.expires_in)));
        Ok(token.token)
    }
}

impl BlobBackend for Registry {
    fn backend_target(&self) -> crate::metrics::BackendTarget {
        self.target
    }

    fn load_blob_meta(&self, blob_id: &[u8; EROFS_BLOB_ID_SIZE]) -> io::Result<BlobMeta> {
        self.fetch_blob_meta(blob_id).map_err(io::Error::from)
    }

    fn read_range_into(
        &self,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
        offset: u64,
        dst: &mut [u8],
        ctx: ReadContext,
    ) -> io::Result<()> {
        if dst.is_empty() {
            return Ok(());
        }
        let source = match ctx.source {
            RequestSource::OnDemand => crate::metrics::ReadSource::OnDemand,
            RequestSource::Prefetch => crate::metrics::ReadSource::Prefetch,
        };
        let bytes = dst.len() as u64;
        let start = std::time::Instant::now();
        // Serialize the very first read so its auth token can be reused.
        let result = if self.first_done.load(Ordering::Acquire) {
            self.retry_read(blob_id, offset, dst, ctx)
        } else {
            let result = self.retry_read(blob_id, offset, dst, ctx);
            self.first_done.store(true, Ordering::Release);
            result
        };
        crate::metrics::record_backend_read(
            self.target,
            source,
            bytes,
            start.elapsed(),
            result.is_err(),
        );
        result?;
        Ok(())
    }

    fn read_range(
        &self,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
        offset: u64,
        len: u32,
        ctx: ReadContext,
    ) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len as usize];
        self.read_range_into(blob_id, offset, &mut buf, ctx)?;
        Ok(buf)
    }
}

fn is_redirect(status: StatusCode) -> bool {
    status.is_redirection()
}

/// Read the response body and ensure it exactly fills `dst`.
fn fill_exact(resp: Response, dst: &mut [u8]) -> RegistryResult<()> {
    let n = resp.copy_to(dst).map_err(RegistryError::Io)?;
    if n != dst.len() {
        return Err(RegistryError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("registry returned {} bytes, expected {}", n, dst.len()),
        )));
    }
    Ok(())
}

/// Build an error from a non-success response, consuming its body for context.
fn status_error(resp: Response) -> RegistryError {
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    RegistryError::Status(status, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bearer_challenge() {
        let header = r#"Bearer realm="https://auth.example.com/token",service="example.com",scope="repository:library/ubuntu:pull""#;
        match RegistryState::parse_challenge(header).unwrap() {
            Challenge::Bearer {
                realm,
                service,
                scope,
            } => {
                assert_eq!(realm, "https://auth.example.com/token");
                assert_eq!(service, "example.com");
                assert_eq!(scope, "repository:library/ubuntu:pull");
            }
            _ => panic!("expected bearer challenge"),
        }
    }

    #[test]
    fn parses_basic_challenge() {
        assert!(matches!(
            RegistryState::parse_challenge(r#"Basic realm="registry""#).unwrap(),
            Challenge::Basic
        ));
    }

    #[test]
    fn builds_blob_url() {
        let state = RegistryState {
            scheme: "https",
            host: "registry.example.com".to_string(),
            repo: "library/ubuntu".to_string(),
            retry_limit: 3,
            basic_auth: None,
            cached_auth: RwLock::new(String::new()),
            token_expires_at: ArcSwapOption::from(None),
            cached_redirect: RwLock::new(HashMap::new()),
        };
        assert_eq!(
            state.blob_url("abc123").unwrap(),
            "https://registry.example.com/v2/library/ubuntu/blobs/sha256:abc123"
        );
    }

    #[test]
    fn from_value_parses_nested_config() {
        let yaml = "
host: registry.example.com
repo: library/ubuntu
insecure: false
auth: YWxpY2U6c2VjcmV0
proxy:
  url: http://127.0.0.1:65001
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let registry = Registry::from_value(&value).unwrap();
        assert_eq!(registry.state.host, "registry.example.com");
        assert_eq!(registry.state.scheme, "https");
        assert!(registry.state.basic_auth.is_some());
    }

    #[test]
    fn expired_token_is_cleared() {
        let state = RegistryState {
            scheme: "https",
            host: "h".to_string(),
            repo: "r".to_string(),
            retry_limit: 3,
            basic_auth: None,
            cached_auth: RwLock::new("Bearer xyz".to_string()),
            token_expires_at: ArcSwapOption::from(Some(Arc::new(now_secs()))),
            cached_redirect: RwLock::new(HashMap::new()),
        };
        // Token expires "now", within the refresh margin, so it is cleared.
        assert_eq!(state.current_auth(), "");
        assert!(state.cached_auth.read().unwrap().is_empty());
    }
}
