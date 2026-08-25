//! Container image registry backend (OCI distribution spec).
//!
//! This backend resolves a blob by its full-blob digest and serves byte ranges
//! over HTTP. The merged bootstrap's device slots carry the full-blob digest, so
//! the same digest both addresses the registry blob and names the on-disk blob
//! meta. [`read_range_into`](BlobBackend::read_range_into) fetches data ranges; blob meta
//! is normally hydrated from the cache directory (the bootstrap layer ships a
//! `<full-blob>.blob.meta` per layer), and otherwise
//! [`blob_metadata`](BlobBackend::blob_metadata) recovers it from the blob's
//! trailing footer via range reads.
//!
//! The HTTP transport helpers (connection building, DNS, the Dragonfly SDK
//! client) live in this module's submodules; this file holds only the
//! registry-specific logic.

mod dns;
#[cfg(feature = "backend-dragonfly-proxy")]
mod dragonfly;
mod http;

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use futures::TryStreamExt;
use reqwest::header::{
    HeaderMap, AUTHORIZATION, CONTENT_LENGTH, LOCATION, RANGE, WWW_AUTHENTICATE,
};
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::runtime::Runtime;
use tokio_util::io::StreamReader;
use tracing::debug;
use url::Url;

use crate::{BlobBackend, ReadContext, ReadKind};
use nydus_config::RegistryConfig;
use nydus_format::blob::{BlobFooter, BlobMetadata, NYDUS_BLOB_FOOTER_SIZE};
use nydus_format::utils::{hex_string, SHA256_DIGEST_SIZE};

use self::http::HTTP;

#[cfg(feature = "backend-dragonfly-proxy")]
use self::dragonfly::Dragonfly;

const CLIENT_ID: &str = "nydus-registry-client";
const DEFAULT_TOKEN_EXPIRATION: u64 = 10 * 60;
const TOKEN_REFRESH_MARGIN: u64 = 20;

/// Shared runtime bridging the synchronous [`BlobBackend`] trait to the
/// asynchronous network clients (direct HTTP and, when enabled, the Dragonfly
/// SDK).
static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .thread_name("nydus-backend")
        .enable_all()
        .build()
        .expect("failed to build backend tokio runtime")
});

/// Access the shared backend runtime.
fn runtime() -> &'static Runtime {
    &RUNTIME
}

/// Errors produced by the registry backend.
#[derive(Debug, thiserror::Error)]
enum RegistryError {
    #[error(transparent)]
    Io(io::Error),

    #[error("invalid url: {0}")]
    InvalidUrl(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("unexpected response: {0}")]
    UnexpectedResponse(String),

    #[error("unexpected status {0}: {1}")]
    UnexpectedStatus(StatusCode, String),

    /// The request was denied by Dragonfly (`403`).
    #[cfg_attr(not(feature = "backend-dragonfly-proxy"), allow(dead_code))]
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// The request was rate-limited by Dragonfly (`429`).
    #[cfg_attr(not(feature = "backend-dragonfly-proxy"), allow(dead_code))]
    #[error("too many requests: {0}")]
    TooManyRequests(String),
}

impl From<RegistryError> for io::Error {
    fn from(err: RegistryError) -> Self {
        match err {
            RegistryError::Io(e) => e,
            other => io::Error::other(other),
        }
    }
}

type RegistryResult<T> = Result<T, RegistryError>;

/// A response from the origin registry or the Dragonfly SDK: the status and
/// headers up front, plus a streaming body.
struct Response {
    status: StatusCode,
    headers: HeaderMap,
    reader: Box<dyn AsyncRead + Send + Unpin>,
}

impl Response {
    /// Read the body into `buf`, returning the number of bytes filled.
    fn read_into(mut self, buf: &mut [u8]) -> io::Result<usize> {
        runtime().block_on(async move {
            let mut filled = 0usize;
            while filled < buf.len() {
                let n = self.reader.read(&mut buf[filled..]).await?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            Ok(filled)
        })
    }

    /// Read the body as a UTF-8 string.
    fn text(mut self) -> io::Result<String> {
        runtime().block_on(async move {
            let mut body = String::new();
            self.reader.read_to_string(&mut body).await?;
            Ok(body)
        })
    }
}

/// Parse a credential string into an `Authorization` header value. Tokens come
/// from the remote auth server and basic credentials from the config, so bytes
/// that are invalid in an HTTP header (e.g. newlines) must surface as an auth
/// error instead of a panic.
fn auth_header_value(value: &str) -> RegistryResult<reqwest::header::HeaderValue> {
    value.parse().map_err(|_| {
        RegistryError::Unauthorized(
            "credentials contain bytes that are invalid in an HTTP header".to_string(),
        )
    })
}

/// Authentication challenge parsed from a `www-authenticate` header.
enum AuthChallenge {
    Basic,
    Bearer {
        realm: String,
        service: String,
        scope: String,
    },
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

/// Split a registry `addr` (scheme-carrying, e.g. `http://127.0.0.1:5000`)
/// into the URL scheme and the `host[:port]` authority.
fn parse_registry_addr(addr: &str) -> io::Result<(&'static str, String)> {
    let invalid = |reason: &str| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid registry addr {addr}: {reason}"),
        )
    };
    let url = Url::parse(addr).map_err(|err| invalid(&err.to_string()))?;
    let scheme = match url.scheme() {
        "http" => "http",
        "https" => "https",
        other => return Err(invalid(&format!("unsupported scheme `{other}`"))),
    };
    let host = url.host_str().ok_or_else(|| invalid("missing host"))?;
    if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
        return Err(invalid("must not carry a path, query, or fragment"));
    }
    let host = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    Ok((scheme, host))
}

/// Storage backend backed by an OCI image registry.
pub(crate) struct Registry {
    /// The URL scheme selected by the configured `addr` (`http` or `https`).
    scheme: &'static str,
    /// The registry `host[:port]` authority.
    host: String,
    /// The image repository, e.g. `library/ubuntu`.
    repository: String,
    /// `Basic base64(user:pass)` value, if credentials were supplied.
    basic_auth: Option<String>,
    /// Cached `Authorization` header value (`Bearer ...` or `Basic ...`).
    cached_auth: RwLock<String>,
    /// Epoch second at which a cached bearer token expires (None for basic).
    token_expires_at: ArcSwapOption<u64>,
    /// Cache of resolved 3xx redirect URLs, keyed by blob hex digest.
    redirect_urls: RwLock<HashMap<String, String>>,
    /// Direct HTTP transport to the origin registry.
    http: HTTP,
    /// Routes blob `GET`s through the Dragonfly SDK when configured.
    #[cfg(feature = "backend-dragonfly-proxy")]
    dragonfly: Option<Dragonfly>,
    /// Whether reads are served through the Dragonfly SDK, used to attribute
    /// backend read and CRC metrics.
    target: nydus_telemetry::metrics::BackendTarget,
    // Ensures the first authenticated request completes before a burst of
    // concurrent reads, so they can reuse the cached token instead of each
    // performing their own auth handshake.
    first_read_done: AtomicBool,
}

impl Registry {
    /// Build a registry backend from its configuration.
    pub(crate) fn new(config: RegistryConfig) -> io::Result<Self> {
        let (scheme, host) = parse_registry_addr(&config.addr)?;
        let http = HTTP::new(&config.http)?;

        #[cfg(feature = "backend-dragonfly-proxy")]
        let dragonfly = match &config.dragonfly {
            Some(dragonfly_config) => Some(Dragonfly::new(
                dragonfly_config,
                config.http.timeout,
                config.http.max_retries,
            )?),
            None => None,
        };
        #[cfg(not(feature = "backend-dragonfly-proxy"))]
        if let Some(dragonfly_config) = &config.dragonfly {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "dragonfly.scheduler_endpoint is set ({}) but this build lacks \
                     the `backend-dragonfly-proxy` feature",
                    dragonfly_config.scheduler_endpoint
                ),
            ));
        }

        #[cfg(feature = "backend-dragonfly-proxy")]
        let target = if dragonfly.is_some() {
            nydus_telemetry::metrics::BackendTarget::Proxy
        } else {
            nydus_telemetry::metrics::BackendTarget::Origin
        };
        #[cfg(not(feature = "backend-dragonfly-proxy"))]
        let target = nydus_telemetry::metrics::BackendTarget::Origin;

        Ok(Registry {
            scheme,
            host,
            repository: config.repository,
            // `auth`, when present, is already a base64-encoded
            // `username:password` string sent verbatim after the `Basic `
            // scheme prefix.
            basic_auth: config.auth,
            cached_auth: RwLock::new(String::new()),
            token_expires_at: ArcSwapOption::from(None),
            redirect_urls: RwLock::new(HashMap::new()),
            http,
            #[cfg(feature = "backend-dragonfly-proxy")]
            dragonfly,
            target,
            first_read_done: AtomicBool::new(false),
        })
    }

    fn blob_url(&self, hex: &str) -> RegistryResult<String> {
        Ok(format!(
            "{}://{}/v2/{}/blobs/sha256:{}",
            self.scheme, self.host, self.repository, hex
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

    fn redirect_url(&self, hex: &str) -> Option<String> {
        self.redirect_urls.read().unwrap().get(hex).cloned()
    }

    fn set_redirect_url(&self, hex: &str, url: String) {
        self.redirect_urls
            .write()
            .unwrap()
            .insert(hex.to_string(), url);
    }

    fn remove_redirect_url(&self, hex: &str) {
        self.redirect_urls.write().unwrap().remove(hex);
    }

    /// Parse a `www-authenticate` header value into an [`AuthChallenge`].
    fn parse_challenge(value: &str) -> Option<AuthChallenge> {
        let (scheme, rest) = value.split_once(' ')?;
        match scheme.trim() {
            "Basic" => Some(AuthChallenge::Basic),
            "Bearer" => {
                let mut params = HashMap::new();
                for pair in rest.split(',') {
                    if let Some((k, v)) = pair.trim().split_once('=') {
                        params.insert(k.trim(), v.trim().trim_matches('"'));
                    }
                }
                Some(AuthChallenge::Bearer {
                    realm: (*params.get("realm")?).to_string(),
                    service: params.get("service").copied().unwrap_or("").to_string(),
                    scope: params.get("scope").copied().unwrap_or("").to_string(),
                })
            }
            _ => None,
        }
    }

    /// Issue a request. Blob `GET`s ride the Dragonfly SDK when it is
    /// configured, falling back to the origin when Dragonfly still fails
    /// after its internal retries; everything else — and requests with
    /// `allow_dragonfly` false (auth token fetches) — goes directly to the
    /// origin. Each transport retries transient failures itself: the HTTP
    /// client's retry middleware for the origin, the SDK for Dragonfly.
    #[cfg_attr(not(feature = "backend-dragonfly-proxy"), allow(unused_variables))]
    fn request(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        context: ReadContext,
        allow_dragonfly: bool,
    ) -> RegistryResult<Response> {
        #[cfg(feature = "backend-dragonfly-proxy")]
        if allow_dragonfly && method == Method::GET {
            if let Some(dragonfly) = &self.dragonfly {
                match self.request_dragonfly(dragonfly, url, headers.clone(), context) {
                    Ok(response) => return Ok(response),
                    Err(err) => {
                        tracing::warn!(
                            "dragonfly request failed, falling back to the origin: {err}"
                        );
                    }
                }
            }
        }

        self.request_http(method, url, headers, context)
    }

    /// Send a request directly to the origin and log its completion.
    fn request_http(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        context: ReadContext,
    ) -> RegistryResult<Response> {
        let start = Instant::now();
        let result = runtime().block_on(async {
            self.http
                .client()
                .request(method.clone(), url)
                .headers(headers.clone())
                .send()
                .await
        });
        let duration = start.elapsed();

        match result {
            Ok(response) => {
                let status = response.status();
                let response_headers = response.headers().clone();
                log_request_done(
                    "none",
                    &method,
                    url,
                    &headers,
                    context,
                    Some(status),
                    Some(&response_headers),
                    None,
                    duration,
                );
                Ok(Response {
                    status,
                    headers: response_headers,
                    reader: Box::new(StreamReader::new(Box::pin(
                        response.bytes_stream().map_err(io::Error::other),
                    ))),
                })
            }
            Err(err) => {
                let message = err.to_string();
                log_request_done(
                    "none",
                    &method,
                    url,
                    &headers,
                    context,
                    None,
                    None,
                    Some(&message),
                    duration,
                );
                Err(RegistryError::Io(io::Error::other(err)))
            }
        }
    }

    /// Send a blob `GET` through the Dragonfly SDK and log its completion.
    #[cfg(feature = "backend-dragonfly-proxy")]
    fn request_dragonfly(
        &self,
        dragonfly: &Dragonfly,
        url: &str,
        headers: HeaderMap,
        context: ReadContext,
    ) -> RegistryResult<Response> {
        let start = Instant::now();
        let result = dragonfly.get(url, headers.clone(), context.kind);
        let duration = start.elapsed();

        match result {
            Ok(response) => {
                log_request_done(
                    "dragonfly_sdk",
                    &Method::GET,
                    url,
                    &headers,
                    context,
                    Some(response.status),
                    Some(&response.headers),
                    None,
                    duration,
                );
                Ok(response)
            }
            Err(err) => {
                let message = err.to_string();
                log_request_done(
                    "dragonfly_sdk",
                    &Method::GET,
                    url,
                    &headers,
                    context,
                    None,
                    None,
                    Some(&message),
                    duration,
                );
                Err(err)
            }
        }
    }

    /// Fill `dst` with the blob byte range. Transient failures are retried
    /// inside each transport: the HTTP client's retry middleware for direct
    /// reads, the SDK's internal retries for Dragonfly reads.
    fn try_read(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        dst: &mut [u8],
        context: ReadContext,
    ) -> RegistryResult<()> {
        let hex = hex_string(blob_id);
        let end = offset + dst.len() as u64 - 1;
        let range = format!("bytes={offset}-{end}");

        // Fast path: a previously cached redirect URL.
        if let Some(redirect) = self.redirect_url(&hex) {
            let mut headers = HeaderMap::new();
            headers.insert(RANGE, range.parse().unwrap());
            let response = self.request(Method::GET, &redirect, headers, context, true)?;
            let status = response.status;
            if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                // The signed link expired; drop it and fall through to re-resolve.
                self.remove_redirect_url(&hex);
            } else if status.is_success() {
                return fill_exact(response, dst);
            } else {
                return Err(status_error(response));
            }
        }

        let url = self.blob_url(&hex)?;
        let mut headers = HeaderMap::new();
        headers.insert(RANGE, range.parse().unwrap());
        let response = self.authorized_request(Method::GET, &url, headers, context)?;
        let status = response.status;

        if status.is_redirection() {
            let location = response
                .headers
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    RegistryError::UnexpectedResponse("missing redirect location".to_string())
                })?
                .to_string();

            let mut redirect_headers = HeaderMap::new();
            redirect_headers.insert(RANGE, range.parse().unwrap());
            let redirected =
                self.request(Method::GET, &location, redirect_headers, context, true)?;
            if !redirected.status.is_success() {
                return Err(status_error(redirected));
            }
            self.set_redirect_url(&hex, location);
            fill_exact(redirected, dst)
        } else if status.is_success() {
            fill_exact(response, dst)
        } else {
            Err(status_error(response))
        }
    }

    /// Resolve the total size of a blob via a `HEAD` request, following a single
    /// redirect to a signed CDN URL if necessary.
    fn fetch_blob_size(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> RegistryResult<u64> {
        let hex = hex_string(blob_id);
        let url = self.blob_url(&hex)?;
        let response = self.authorized_request(
            Method::HEAD,
            &url,
            HeaderMap::new(),
            ReadContext::raw(ReadKind::OnDemand),
        )?;
        let status = response.status;

        let response = if status.is_redirection() {
            let location = response
                .headers
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    RegistryError::UnexpectedResponse("missing redirect location".to_string())
                })?
                .to_string();
            let redirected = self.request(
                Method::HEAD,
                &location,
                HeaderMap::new(),
                ReadContext::raw(ReadKind::OnDemand),
                true,
            )?;
            if !redirected.status.is_success() {
                return Err(status_error(redirected));
            }
            redirected
        } else if status.is_success() {
            response
        } else {
            return Err(status_error(response));
        };

        response
            .headers
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
    fn fetch_blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> RegistryResult<BlobMetadata> {
        let size = self.fetch_blob_size(blob_id)?;
        let footer_offset = BlobFooter::offset_from_size(size)
            .map_err(|err| RegistryError::Io(io::Error::other(err)))?;

        let mut footer_bytes = [0u8; NYDUS_BLOB_FOOTER_SIZE];
        self.try_read(
            blob_id,
            footer_offset,
            &mut footer_bytes,
            ReadContext::raw(ReadKind::OnDemand),
        )?;
        let footer = BlobFooter::from_bytes(&footer_bytes)
            .map_err(|err| RegistryError::Io(io::Error::other(err)))?;

        let blob_metadata_size = usize::try_from(footer.blob_metadata_size()).map_err(|_| {
            RegistryError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "blob meta size exceeds usize",
            ))
        })?;
        let mut blob_metadata_bytes = vec![0u8; blob_metadata_size];
        self.try_read(
            blob_id,
            footer.blob_metadata_offset(),
            &mut blob_metadata_bytes,
            ReadContext::raw(ReadKind::OnDemand),
        )?;

        BlobMetadata::from_bytes(&blob_metadata_bytes, Some(*blob_id), false)
            .map_err(|err| RegistryError::Io(io::Error::other(err)))
    }

    /// Issue a request, transparently performing the auth handshake on `401`.
    fn authorized_request(
        &self,
        method: Method,
        url: &str,
        mut headers: HeaderMap,
        context: ReadContext,
    ) -> RegistryResult<Response> {
        let cached_auth = self.current_auth();
        if !cached_auth.is_empty() {
            headers.insert(AUTHORIZATION, auth_header_value(&cached_auth)?);
        }

        let response = self.request(method.clone(), url, headers.clone(), context, true)?;
        if response.status != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }

        // Drop any stale token so the server returns the expected challenge.
        let challenge_response = if headers.remove(AUTHORIZATION).is_some() {
            self.request(method.clone(), url, headers.clone(), context, true)?
        } else {
            response
        };

        let challenge = challenge_response
            .headers
            .get(WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .and_then(Registry::parse_challenge);

        let Some(challenge) = challenge else {
            return Ok(challenge_response);
        };

        let auth_header = self.obtain_auth(challenge)?;
        headers.insert(AUTHORIZATION, auth_header_value(&auth_header)?);
        let response = self.request(method, url, headers, context, true)?;
        if response.status.is_success() || response.status.is_redirection() {
            self.set_auth(auth_header);
        }
        Ok(response)
    }

    fn obtain_auth(&self, challenge: AuthChallenge) -> RegistryResult<String> {
        match challenge {
            AuthChallenge::Basic => {
                let basic = self.basic_auth.as_ref().ok_or_else(|| {
                    RegistryError::Unauthorized(
                        "registry requires basic-auth credentials".to_string(),
                    )
                })?;
                Ok(format!("Basic {basic}"))
            }
            AuthChallenge::Bearer {
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
        let mut url = Url::parse(realm)
            .map_err(|err| RegistryError::InvalidUrl(format!("{realm}: {err}")))?;
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
        if let Some(basic) = &self.basic_auth {
            headers.insert(AUTHORIZATION, auth_header_value(&format!("Basic {basic}"))?);
        }

        // Auth requests always go directly to the auth server, never via Dragonfly.
        let response = self.request(
            Method::GET,
            url.as_str(),
            headers,
            ReadContext::raw(ReadKind::OnDemand),
            false,
        )?;
        if !response.status.is_success() {
            return Err(status_error(response));
        }

        let body = response.text().map_err(RegistryError::Io)?;
        let mut token: TokenResponse = serde_json::from_str(&body).map_err(|err| {
            RegistryError::UnexpectedResponse(format!("invalid token response: {err}"))
        })?;
        if token.token.is_empty() {
            token.token = token.access_token.clone();
        }
        if token.token.is_empty() {
            return Err(RegistryError::UnexpectedResponse(
                "empty token from registry".to_string(),
            ));
        }

        self.token_expires_at
            .store(Some(Arc::new(now_secs() + token.expires_in)));
        Ok(token.token)
    }
}

impl BlobBackend for Registry {
    fn backend_target(&self) -> nydus_telemetry::metrics::BackendTarget {
        self.target
    }

    fn blob_metadata(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<BlobMetadata> {
        self.fetch_blob_metadata(blob_id).map_err(io::Error::from)
    }

    fn read_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        dst: &mut [u8],
        context: ReadContext,
    ) -> io::Result<()> {
        if dst.is_empty() {
            return Ok(());
        }
        // Serialize the very first read so its auth token can be reused.
        if self.first_read_done.load(Ordering::Acquire) {
            self.try_read(blob_id, offset, dst, context)?;
        } else {
            let result = self.try_read(blob_id, offset, dst, context);
            self.first_read_done.store(true, Ordering::Release);
            result?;
        }
        Ok(())
    }
}

/// Read the response body and ensure it exactly fills `dst`.
fn fill_exact(response: Response, dst: &mut [u8]) -> RegistryResult<()> {
    let n = response.read_into(dst).map_err(RegistryError::Io)?;
    if n != dst.len() {
        return Err(RegistryError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("registry returned {} bytes, expected {}", n, dst.len()),
        )));
    }
    Ok(())
}

/// Build an error from a non-success response, consuming its body for context.
fn status_error(response: Response) -> RegistryError {
    let status = response.status;
    let body = response.text().unwrap_or_default();
    RegistryError::UnexpectedStatus(status, body)
}

/// Log a completed backend request at debug level so it can be inspected during
/// a `check` (run with `--log-level debug`). The line carries the request
/// source, the transport that served it, the method, final URL and full request
/// headers, plus the outcome: response status and headers when the transport
/// returned a response, an error string on transport failure, and the
/// wall-clock duration in human-readable form. The transport labels (`none`
/// for direct, `dragonfly_sdk`) are load-bearing for log consumers and stay
/// as-is.
#[allow(clippy::too_many_arguments)]
fn log_request_done(
    transport: &'static str,
    method: &Method,
    url: &str,
    headers: &HeaderMap,
    context: ReadContext,
    status: Option<StatusCode>,
    response_headers: Option<&HeaderMap>,
    error: Option<&str>,
    duration: Duration,
) {
    let read_kind = match context.kind {
        ReadKind::OnDemand => "ondemand",
        ReadKind::Prefetch => "prefetch",
    };
    debug!(
        "backend request done: read_kind={read_kind} transport={transport} method={method} url={url} headers={headers:?} status={status:?} response_headers={response_headers:?} error={error:?} duration={}",
        format_duration(duration),
    );
}

/// Format a duration in a compact, human-readable unit (ns/µs/ms/s).
fn format_duration(d: Duration) -> String {
    let nanos = d.as_nanos();
    if nanos < 1_000 {
        format!("{nanos}ns")
    } else if nanos < 1_000_000 {
        format!("{:.3}µs", nanos as f64 / 1_000.0)
    } else if nanos < 1_000_000_000 {
        format!("{:.3}ms", nanos as f64 / 1_000_000.0)
    } else {
        format!("{:.3}s", d.as_secs_f64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bearer_challenge() {
        let header = r#"Bearer realm="https://auth.example.com/token",service="example.com",scope="repository:library/ubuntu:pull""#;
        match Registry::parse_challenge(header).unwrap() {
            AuthChallenge::Bearer {
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
            Registry::parse_challenge(r#"Basic realm="registry""#).unwrap(),
            AuthChallenge::Basic
        ));
    }

    /// A registry built from a minimal config, for tests that poke internals.
    fn test_registry() -> Registry {
        let config: RegistryConfig = serde_yaml::from_str(
            "addr: https://registry.example.com\nrepository: library/ubuntu\n",
        )
        .unwrap();
        Registry::new(config).unwrap()
    }

    #[test]
    fn builds_blob_url() {
        let registry = test_registry();
        assert_eq!(
            registry.blob_url("abc123").unwrap(),
            "https://registry.example.com/v2/library/ubuntu/blobs/sha256:abc123"
        );
    }

    #[test]
    fn parses_registry_addr() {
        assert_eq!(
            parse_registry_addr("http://127.0.0.1:5000").unwrap(),
            ("http", "127.0.0.1:5000".to_string())
        );
        assert_eq!(
            parse_registry_addr("https://registry-1.docker.io").unwrap(),
            ("https", "registry-1.docker.io".to_string())
        );
        // A trailing slash is tolerated; anything more is rejected.
        assert_eq!(
            parse_registry_addr("https://registry.example.com/").unwrap(),
            ("https", "registry.example.com".to_string())
        );
        assert!(parse_registry_addr("registry.example.com").is_err());
        assert!(parse_registry_addr("ftp://registry.example.com").is_err());
        assert!(parse_registry_addr("https://registry.example.com/v2").is_err());
    }

    #[test]
    fn new_builds_from_config() {
        let yaml = "
addr: https://registry.example.com
repository: library/ubuntu
auth: YWxpY2U6c2VjcmV0
";
        let config: RegistryConfig = serde_yaml::from_str(yaml).unwrap();
        let registry = Registry::new(config).unwrap();
        assert_eq!(registry.host, "registry.example.com");
        assert_eq!(registry.scheme, "https");
        assert!(registry.basic_auth.is_some());
    }

    #[cfg(not(feature = "backend-dragonfly-proxy"))]
    #[test]
    fn new_rejects_dragonfly_endpoint_without_the_feature() {
        let yaml = "
addr: https://registry.example.com
repository: library/ubuntu
dragonfly:
  scheduler_endpoint: http://127.0.0.1:65000
";
        let config: RegistryConfig = serde_yaml::from_str(yaml).unwrap();
        let err = Registry::new(config)
            .err()
            .expect("dragonfly endpoint must be rejected without the feature");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("backend-dragonfly-proxy"));
    }

    #[test]
    fn expired_token_is_cleared() {
        let registry = test_registry();
        registry.set_auth("Bearer xyz".to_string());
        registry.token_expires_at.store(Some(Arc::new(now_secs())));
        // Token expires "now", within the refresh margin, so it is cleared.
        assert_eq!(registry.current_auth(), "");
        assert!(registry.cached_auth.read().unwrap().is_empty());
    }
}
