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
//! The transport helpers (connection building, DNS, the Dragonfly SDK client,
//! the fallback throttle) and the load-shedding policy live in this module's
//! submodules; this file holds only the registry-specific logic. The Dragonfly
//! SDK retries transient failures across seed peers, then [`policy::decide`]
//! serves the answer, defers a prefetch read to the storage layer's
//! reschedule, or falls back an on-demand read to the origin through the
//! fallback throttle.

mod dns;
#[cfg(feature = "backend-dragonfly-proxy")]
mod dragonfly;
mod http;
mod policy;

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use futures::TryStreamExt;
use reqwest::header::{
    HeaderMap, AUTHORIZATION, CONTENT_LENGTH, LOCATION, RANGE, WWW_AUTHENTICATE,
};
use reqwest::{Method, StatusCode};
use reqwest_middleware::ClientWithMiddleware;
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

use self::http::{BackToSourceRateLimiter, HTTP};
use self::policy::Action;

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

    /// A prefetch read Dragonfly could not serve: a `429`, `5xx` or `408`
    /// answer, or a transport failure. Folds into
    /// [`io::ErrorKind::QuotaExceeded`] so the storage layer reschedules the
    /// blob's prefetch hours later instead of retrying now.
    #[error("prefetch deferred: {0}")]
    PrefetchDeferred(Box<RegistryError>),
}

impl From<RegistryError> for io::Error {
    fn from(err: RegistryError) -> Self {
        match err {
            RegistryError::Io(err) => err,
            err @ RegistryError::PrefetchDeferred(_) => {
                io::Error::new(io::ErrorKind::QuotaExceeded, err)
            }
            err => io::Error::other(err),
        }
    }
}

type RegistryResult<T> = Result<T, RegistryError>;

/// The transport seam for Dragonfly reads: the SDK client in production,
/// scripted fakes in tests. Unconditional (not feature-gated) so the policy
/// and its tests compile without the `backend-dragonfly-proxy` feature. One
/// call spends the SDK's whole retry budget and returns a fully buffered
/// response, so a mid-stream failure surfaces as a transport error here.
#[async_trait]
trait DragonflyTransport: Send + Sync {
    /// Issue a blob `GET` through Dragonfly.
    async fn get(&self, url: &str, headers: HeaderMap, kind: ReadKind) -> RegistryResult<Response>;
}

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
    /// Routes blob `GET`s through the Dragonfly SDK when configured. Always
    /// `None` when the `backend-dragonfly-proxy` feature is off (the config
    /// is rejected), kept unconditional so the policy and its tests compile
    /// without the feature.
    dragonfly: Option<Box<dyn DragonflyTransport>>,
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
        let rate_limiter = BackToSourceRateLimiter::new(
            config
                .dragonfly
                .as_ref()
                .map(|dragonfly_config| dragonfly_config.back_to_source.request_rate_limit)
                .unwrap_or(0),
        );
        let http = HTTP::new(&config.http, rate_limiter)?;

        #[cfg(feature = "backend-dragonfly-proxy")]
        let dragonfly: Option<Box<dyn DragonflyTransport>> = match &config.dragonfly {
            Some(dragonfly_config) => Some(Box::new(Dragonfly::new(dragonfly_config)?)),
            None => None,
        };
        #[cfg(not(feature = "backend-dragonfly-proxy"))]
        let dragonfly: Option<Box<dyn DragonflyTransport>> = match &config.dragonfly {
            Some(dragonfly_config) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "dragonfly.scheduler_endpoint is set ({}) but this build lacks \
                         the `backend-dragonfly-proxy` feature",
                        dragonfly_config.scheduler_endpoint
                    ),
                ))
            }
            None => None,
        };

        let target = if dragonfly.is_some() {
            nydus_telemetry::metrics::BackendTarget::Proxy
        } else {
            nydus_telemetry::metrics::BackendTarget::Origin
        };

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
    /// configured: the SDK retries transient failures across seed peers, then
    /// [`policy::decide`] serves the answer, defers a prefetch read to the
    /// storage layer's reschedule, or falls back an on-demand read to the
    /// origin through the fallback throttle.
    /// Everything else, and requests with `allow_dragonfly` false (auth token
    /// fetches), goes directly to the origin, where the HTTP client's retry
    /// middleware retries transient failures.
    fn request(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        context: ReadContext,
        allow_dragonfly: bool,
    ) -> RegistryResult<Response> {
        if allow_dragonfly && method == Method::GET {
            if let Some(dragonfly) = &self.dragonfly {
                let outcome =
                    self.request_dragonfly(dragonfly.as_ref(), url, headers.clone(), context);
                return match policy::decide(context.kind, outcome) {
                    Action::Serve(response) => Ok(response),
                    Action::Fallback(err) => {
                        nydus_telemetry::metrics::record_dragonfly_error(context.kind);
                        tracing::warn!(
                            "dragonfly request failed, falling back to the origin: {err}"
                        );
                        self.fallback_request_http(method, url, headers, context)
                    }
                    Action::Defer(err) => {
                        nydus_telemetry::metrics::record_dragonfly_error(context.kind);
                        tracing::warn!("dragonfly request failed: {err}");
                        Err(err)
                    }
                };
            }
        }

        self.request_http(method, url, headers, context)
    }

    /// Issue an origin request as a Dragonfly fallback through the fallback
    /// client: the retry middleware retries transient failures up to
    /// `http.max_retries`, and every attempt first claims a fallback throttle
    /// slot, so origin requests never exceed the fallback rate limit.
    fn fallback_request_http(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        context: ReadContext,
    ) -> RegistryResult<Response> {
        // The origin serves (or terminally fails) this read now, so attribute
        // it to the origin side of the proxy/origin split.
        crate::note_read_served_by(nydus_telemetry::metrics::BackendTarget::Origin);

        let result = self.send_http(
            self.http.back_to_source_client(),
            method,
            url,
            headers,
            context,
        );
        nydus_telemetry::metrics::record_fallback_read(result.is_err());
        result
    }

    /// Send a request directly to the origin through the retrying client and
    /// log its completion.
    fn request_http(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        context: ReadContext,
    ) -> RegistryResult<Response> {
        self.send_http(self.http.client(), method, url, headers, context)
    }

    /// Send a request to the origin through `client` and log its completion.
    fn send_http(
        &self,
        client: &ClientWithMiddleware,
        method: Method,
        url: &str,
        headers: HeaderMap,
        context: ReadContext,
    ) -> RegistryResult<Response> {
        let start = Instant::now();
        let result = runtime().block_on(async {
            client
                .request(method.clone(), url)
                .headers(headers.clone())
                .send()
                .await
                .map_err(io::Error::other)
        });
        self.finish_http_request(method, url, headers, context, start, result)
    }

    /// Log a completed origin request and wrap its outcome.
    fn finish_http_request(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        context: ReadContext,
        start: Instant,
        result: Result<reqwest::Response, io::Error>,
    ) -> RegistryResult<Response> {
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
                Err(RegistryError::Io(err))
            }
        }
    }

    /// Send a blob `GET` through the Dragonfly transport and log its
    /// completion. The transport returns a fully buffered response, so a
    /// mid-stream failure surfaces here instead of while the caller consumes
    /// the response.
    fn request_dragonfly(
        &self,
        dragonfly: &dyn DragonflyTransport,
        url: &str,
        headers: HeaderMap,
        context: ReadContext,
    ) -> RegistryResult<Response> {
        let start = Instant::now();
        let result = runtime().block_on(dragonfly.get(url, headers.clone(), context.kind));
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

    /// Fill `dst` with the blob byte range. Direct origin reads retry
    /// transient failures inside the HTTP client's retry middleware,
    /// Dragonfly reads inside the SDK, then [`policy::decide`] settles them.
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

        BlobMetadata::from_bytes(&blob_metadata_bytes, false)
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

    #[test]
    fn registry_error_to_io_error_preserves_dragonfly_messages() {
        let deferred: io::Error = RegistryError::PrefetchDeferred(Box::new(
            RegistryError::UnexpectedStatus(StatusCode::TOO_MANY_REQUESTS, "slow down".to_string()),
        ))
        .into();
        assert_eq!(deferred.kind(), io::ErrorKind::QuotaExceeded);
        assert!(
            deferred.to_string().contains("prefetch deferred"),
            "unexpected error: {deferred}"
        );
        assert!(
            deferred.to_string().contains("429"),
            "unexpected error: {deferred}"
        );

        let inner = io::Error::new(io::ErrorKind::TimedOut, "timed out");
        let passthrough: io::Error = RegistryError::Io(inner).into();
        assert_eq!(passthrough.kind(), io::ErrorKind::TimedOut);
        assert!(passthrough.to_string().contains("timed out"));
    }

    /// One scripted outcome of a Dragonfly `get`: the SDK has spent its
    /// retries and hands back a `200` with `body`, an answer with `status`,
    /// or a transport failure.
    enum Scripted {
        Body(Vec<u8>),
        Status(StatusCode, HeaderMap),
        Transport,
    }

    fn status(status: StatusCode) -> Scripted {
        Scripted::Status(status, HeaderMap::new())
    }

    /// A scripted Dragonfly transport: pops one scripted outcome per `get`,
    /// counting the calls.
    struct ScriptedTransport {
        script: std::sync::Mutex<std::collections::VecDeque<Scripted>>,
        calls: std::sync::atomic::AtomicU32,
    }

    impl ScriptedTransport {
        fn new(script: impl IntoIterator<Item = Scripted>) -> ScriptedTransport {
            ScriptedTransport {
                script: std::sync::Mutex::new(script.into_iter().collect()),
                calls: std::sync::atomic::AtomicU32::new(0),
            }
        }

        fn calls(&self) -> u32 {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl DragonflyTransport for ScriptedTransport {
        async fn get(
            &self,
            _url: &str,
            _headers: HeaderMap,
            _kind: ReadKind,
        ) -> RegistryResult<Response> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let outcome = self
                .script
                .lock()
                .unwrap()
                .pop_front()
                .expect("transport called more times than scripted");
            match outcome {
                Scripted::Body(body) => Ok(Response {
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                    reader: Box::new(std::io::Cursor::new(body)),
                }),
                Scripted::Status(status, headers) => Ok(Response {
                    status,
                    headers,
                    reader: Box::new(std::io::Cursor::new(Vec::new())),
                }),
                Scripted::Transport => Err(RegistryError::Io(io::Error::other("scripted failure"))),
            }
        }
    }

    /// Lets a test keep a handle on its [`ScriptedTransport`] after boxing it
    /// into the registry.
    struct SharedTransport(Arc<ScriptedTransport>);

    #[async_trait]
    impl DragonflyTransport for SharedTransport {
        async fn get(
            &self,
            url: &str,
            headers: HeaderMap,
            kind: ReadKind,
        ) -> RegistryResult<Response> {
            self.0.get(url, headers, kind).await
        }
    }

    /// A minimal origin stub on a loopback listener: serves every request with
    /// `status` and `body`, counting the requests served.
    struct OriginStub {
        addr: std::net::SocketAddr,
        hits: Arc<std::sync::atomic::AtomicU32>,
    }

    impl OriginStub {
        fn serve(body: Vec<u8>) -> OriginStub {
            OriginStub::serve_with_status("206 Partial Content", body)
        }

        fn serve_with_status(status: &'static str, body: Vec<u8>) -> OriginStub {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let hits = Arc::new(std::sync::atomic::AtomicU32::new(0));
            let hits_in_thread = hits.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { break };
                    let body = body.clone();
                    let hits = hits_in_thread.clone();
                    std::thread::spawn(move || {
                        use std::io::{Read, Write};
                        // Read until the end of the request headers.
                        let mut buf = Vec::new();
                        let mut byte = [0u8; 1];
                        while !buf.ends_with(b"\r\n\r\n") {
                            match stream.read(&mut byte) {
                                Ok(1) => buf.push(byte[0]),
                                _ => return,
                            }
                        }
                        hits.fetch_add(1, Ordering::SeqCst);
                        let response = format!(
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.write_all(&body);
                    });
                }
            });
            OriginStub { addr, hits }
        }

        fn hits(&self) -> u32 {
            self.hits.load(Ordering::SeqCst)
        }
    }

    /// A loopback address with nothing listening behind it: bound to claim a
    /// free port, then dropped so connections to it are refused.
    fn dead_addr() -> std::net::SocketAddr {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    /// A registry wired to the origin stub, with a scripted Dragonfly
    /// transport and a fallback throttle of one slot per `throttle_interval`
    /// (zero disabling it).
    fn scripted_registry(
        origin: &OriginStub,
        transport: Arc<ScriptedTransport>,
        throttle_interval: Duration,
    ) -> Registry {
        scripted_registry_at(origin.addr, transport, throttle_interval, 3)
    }

    /// A registry pointed at `addr` as its origin with `origin_max_retries`
    /// HTTP retries, a scripted Dragonfly transport, and a fallback throttle
    /// of one slot per `throttle_interval` (zero disabling it).
    fn scripted_registry_at(
        addr: std::net::SocketAddr,
        transport: Arc<ScriptedTransport>,
        throttle_interval: Duration,
        origin_max_retries: u32,
    ) -> Registry {
        let config: RegistryConfig = serde_yaml::from_str(&format!(
            "addr: http://{addr}\nrepository: library/ubuntu\nhttp:\n  max_retries: {origin_max_retries}\n",
        ))
        .unwrap();
        let http = HTTP::new(
            &config.http,
            BackToSourceRateLimiter::with_interval(1, throttle_interval),
        )
        .unwrap();
        let mut registry = Registry::new(config).unwrap();
        registry.http = http;
        registry.dragonfly = Some(Box::new(SharedTransport(transport)));
        registry.target = nydus_telemetry::metrics::BackendTarget::Proxy;
        registry
    }

    const TEST_BLOB_ID: [u8; SHA256_DIGEST_SIZE] = [7u8; SHA256_DIGEST_SIZE];

    #[test]
    fn ondemand_transport_failure_falls_back_to_origin() {
        let body = b"0123456789".to_vec();
        let origin = OriginStub::serve(body.clone());
        let transport = Arc::new(ScriptedTransport::new(vec![Scripted::Transport]));
        let registry = scripted_registry(&origin, transport.clone(), Duration::ZERO);

        let errors_before = nydus_telemetry::metrics::dragonfly_error_total(ReadKind::OnDemand);
        let mut dst = vec![0u8; body.len()];
        registry
            .try_read(
                &TEST_BLOB_ID,
                0,
                &mut dst,
                ReadContext::raw(ReadKind::OnDemand),
            )
            .unwrap();

        assert_eq!(dst, body);
        assert_eq!(transport.calls(), 1);
        assert_eq!(origin.hits(), 1);
        assert!(
            nydus_telemetry::metrics::dragonfly_error_total(ReadKind::OnDemand) > errors_before
        );
    }

    #[test]
    fn fallback_reads_are_attributed_to_the_origin() {
        let body = b"0123456789".to_vec();
        let origin = OriginStub::serve(body.clone());
        let transport = Arc::new(ScriptedTransport::new(vec![status(
            StatusCode::TOO_MANY_REQUESTS,
        )]));
        let registry = scripted_registry(&origin, transport, Duration::ZERO);
        let metered = crate::metered(Arc::new(registry));

        let origin_before = nydus_telemetry::metrics::backend_read_total(
            nydus_telemetry::metrics::BackendTarget::Origin,
        );
        let mut dst = vec![0u8; body.len()];
        metered
            .read_range_into(
                &TEST_BLOB_ID,
                0,
                &mut dst,
                ReadContext::raw(ReadKind::OnDemand),
            )
            .unwrap();

        assert_eq!(dst, body);
        assert_eq!(origin.hits(), 1);
        // The origin served this read, so the proxy/origin split attributes
        // it to the origin even though the registry's static target is Proxy.
        assert!(
            nydus_telemetry::metrics::backend_read_total(
                nydus_telemetry::metrics::BackendTarget::Origin,
            ) > origin_before
        );
        // The override outlives the read so a subsequent CRC validation of
        // these bytes is attributed to the origin as well.
        assert_eq!(
            crate::last_read_served_by(),
            Some(nydus_telemetry::metrics::BackendTarget::Origin)
        );
    }

    #[test]
    fn prefetch_failures_are_deferred_without_origin_fallback() {
        let test_cases = vec![
            (Scripted::Transport, "scripted failure"),
            (status(StatusCode::TOO_MANY_REQUESTS), "429"),
            (status(StatusCode::SERVICE_UNAVAILABLE), "503"),
            (status(StatusCode::REQUEST_TIMEOUT), "408"),
            (status(StatusCode::INSUFFICIENT_STORAGE), "507"),
        ];

        for (outcome, expected) in test_cases {
            let origin = OriginStub::serve(b"unused".to_vec());
            let transport = Arc::new(ScriptedTransport::new(vec![outcome]));
            let registry = scripted_registry(&origin, transport.clone(), Duration::ZERO);

            let mut dst = vec![0u8; 4];
            let err: io::Error = registry
                .try_read(
                    &TEST_BLOB_ID,
                    0,
                    &mut dst,
                    ReadContext::raw(ReadKind::Prefetch),
                )
                .unwrap_err()
                .into();

            assert_eq!(
                err.kind(),
                io::ErrorKind::QuotaExceeded,
                "expected: {expected}"
            );
            assert!(err.to_string().contains(expected), "error: {err}");
            assert_eq!(transport.calls(), 1, "expected: {expected}");
            assert_eq!(origin.hits(), 0, "expected: {expected}");
        }
    }

    #[test]
    fn transient_answers_fall_back_ondemand() {
        let body = b"0123456789".to_vec();
        let test_cases = vec![
            status(StatusCode::TOO_MANY_REQUESTS),
            status(StatusCode::SERVICE_UNAVAILABLE),
            status(StatusCode::REQUEST_TIMEOUT),
            status(StatusCode::INSUFFICIENT_STORAGE),
            Scripted::Transport,
        ];

        for outcome in test_cases {
            let origin = OriginStub::serve(body.clone());
            let transport = Arc::new(ScriptedTransport::new(vec![outcome]));
            let registry = scripted_registry(&origin, transport.clone(), Duration::ZERO);

            let mut dst = vec![0u8; body.len()];
            registry
                .try_read(
                    &TEST_BLOB_ID,
                    0,
                    &mut dst,
                    ReadContext::raw(ReadKind::OnDemand),
                )
                .unwrap();

            assert_eq!(dst, body);
            assert_eq!(transport.calls(), 1);
            assert_eq!(origin.hits(), 1);
        }
    }

    #[test]
    fn definitive_answers_are_terminal_for_both_read_kinds() {
        for kind in [ReadKind::OnDemand, ReadKind::Prefetch] {
            for terminal in [
                StatusCode::FORBIDDEN,
                StatusCode::NOT_FOUND,
                StatusCode::UNPROCESSABLE_ENTITY,
            ] {
                let origin = OriginStub::serve(b"unused".to_vec());
                let transport = Arc::new(ScriptedTransport::new(vec![status(terminal)]));
                let registry = scripted_registry(&origin, transport.clone(), Duration::ZERO);

                let mut dst = vec![0u8; 4];
                let err = registry
                    .try_read(&TEST_BLOB_ID, 0, &mut dst, ReadContext::raw(kind))
                    .unwrap_err();

                assert!(
                    matches!(err, RegistryError::UnexpectedStatus(got, _) if got == terminal),
                    "kind={kind:?} status={terminal}: {err:?}"
                );
                assert_eq!(transport.calls(), 1, "kind={kind:?} status={terminal}");
                assert_eq!(origin.hits(), 0, "kind={kind:?} status={terminal}");
            }
        }
    }

    #[test]
    fn unauthorized_answer_triggers_the_auth_handshake() {
        for kind in [ReadKind::OnDemand, ReadKind::Prefetch] {
            let body = b"authorized".to_vec();
            let origin = OriginStub::serve(b"unused".to_vec());
            let mut challenge = HeaderMap::new();
            challenge.insert(
                WWW_AUTHENTICATE,
                r#"Basic realm="registry""#.parse().unwrap(),
            );
            let transport = Arc::new(ScriptedTransport::new(vec![
                Scripted::Status(StatusCode::UNAUTHORIZED, challenge),
                Scripted::Body(body.clone()),
            ]));
            let mut registry = scripted_registry(&origin, transport.clone(), Duration::ZERO);
            registry.basic_auth = Some("YWxpY2U6c2VjcmV0".to_string());

            let mut dst = vec![0u8; body.len()];
            registry
                .try_read(&TEST_BLOB_ID, 0, &mut dst, ReadContext::raw(kind))
                .unwrap();

            assert_eq!(dst, body, "kind={kind:?}");
            assert_eq!(transport.calls(), 2, "kind={kind:?}");
            assert_eq!(origin.hits(), 0, "kind={kind:?}");
            assert_eq!(registry.current_auth(), "Basic YWxpY2U6c2VjcmV0");
        }
    }

    #[test]
    fn fallback_origin_failure_surfaces_as_an_io_error() {
        // Nothing listens on the origin address, so the fallback's connect is
        // refused; zero origin retries keep the failure immediate.
        let transport = Arc::new(ScriptedTransport::new(vec![status(
            StatusCode::TOO_MANY_REQUESTS,
        )]));
        let registry = scripted_registry_at(dead_addr(), transport.clone(), Duration::ZERO, 0);

        let errors_before = nydus_telemetry::metrics::backend_fallback_read_error_total();
        let mut dst = vec![0u8; 4];
        let err = registry
            .try_read(
                &TEST_BLOB_ID,
                0,
                &mut dst,
                ReadContext::raw(ReadKind::OnDemand),
            )
            .unwrap_err();

        assert!(matches!(err, RegistryError::Io(_)), "unexpected: {err:?}");
        assert_eq!(transport.calls(), 1);
        assert!(nydus_telemetry::metrics::backend_fallback_read_error_total() > errors_before);
    }

    #[test]
    fn fallback_gives_the_origin_its_http_retry_budget() {
        // The origin answers every fallback attempt with a retryable 500.
        let origin = OriginStub::serve_with_status("500 Internal Server Error", b"boom".to_vec());
        let transport = Arc::new(ScriptedTransport::new(vec![status(
            StatusCode::TOO_MANY_REQUESTS,
        )]));
        // `http.max_retries: 1` gives the origin two attempts before the
        // fallback read fails.
        let registry = scripted_registry_at(origin.addr, transport.clone(), Duration::ZERO, 1);

        let mut dst = vec![0u8; 4];
        let err = registry
            .try_read(
                &TEST_BLOB_ID,
                0,
                &mut dst,
                ReadContext::raw(ReadKind::OnDemand),
            )
            .unwrap_err();

        assert!(
            matches!(
                err,
                RegistryError::UnexpectedStatus(StatusCode::INTERNAL_SERVER_ERROR, _)
            ),
            "unexpected: {err:?}"
        );
        assert_eq!(transport.calls(), 1);
        assert_eq!(origin.hits(), 2);
    }

    #[test]
    fn fallback_retries_are_throttled_per_attempt() {
        // Every fallback attempt answers a retryable 500, so the read burns
        // its full origin budget (1 + 1 retry); each attempt must wait for
        // its own throttle slot.
        let origin = OriginStub::serve_with_status("500 Internal Server Error", b"boom".to_vec());
        let transport = Arc::new(ScriptedTransport::new(vec![status(
            StatusCode::TOO_MANY_REQUESTS,
        )]));
        let interval = Duration::from_millis(80);
        let start = Instant::now();
        let registry = scripted_registry_at(origin.addr, transport.clone(), interval, 1);

        let mut dst = vec![0u8; 4];
        let err = registry
            .try_read(
                &TEST_BLOB_ID,
                0,
                &mut dst,
                ReadContext::raw(ReadKind::OnDemand),
            )
            .unwrap_err();

        assert!(
            matches!(
                err,
                RegistryError::UnexpectedStatus(StatusCode::INTERNAL_SERVER_ERROR, _)
            ),
            "unexpected: {err:?}"
        );
        assert_eq!(origin.hits(), 2);
        // The retry had to wait for the next throttle slot.
        assert!(start.elapsed() >= interval);
    }

    #[test]
    fn consecutive_fallbacks_are_throttled() {
        let body = b"abcd".to_vec();
        let origin = OriginStub::serve(body.clone());
        // Two reads, each rate-limited once, each falling back to the origin.
        let transport = Arc::new(ScriptedTransport::new(vec![
            status(StatusCode::TOO_MANY_REQUESTS),
            status(StatusCode::TOO_MANY_REQUESTS),
        ]));
        let interval = Duration::from_millis(80);
        let start = Instant::now();
        let registry = scripted_registry(&origin, transport.clone(), interval);

        let mut dst = vec![0u8; body.len()];
        for _ in 0..2 {
            registry
                .try_read(
                    &TEST_BLOB_ID,
                    0,
                    &mut dst,
                    ReadContext::raw(ReadKind::OnDemand),
                )
                .unwrap();
            assert_eq!(dst, body);
        }

        assert_eq!(origin.hits(), 2);
        // The second fallback had to wait for the next throttle slot.
        assert!(start.elapsed() >= interval);
    }

    #[test]
    fn cached_redirect_reads_ride_dragonfly() {
        let body = b"redirected".to_vec();
        let origin = OriginStub::serve(b"unused".to_vec());
        let transport = Arc::new(ScriptedTransport::new(vec![Scripted::Body(body.clone())]));
        let registry = scripted_registry(&origin, transport.clone(), Duration::ZERO);
        let hex = hex_string(&TEST_BLOB_ID);
        registry.set_redirect_url(&hex, "http://cdn.example.com/signed".to_string());

        let mut dst = vec![0u8; body.len()];
        registry
            .try_read(
                &TEST_BLOB_ID,
                0,
                &mut dst,
                ReadContext::raw(ReadKind::OnDemand),
            )
            .unwrap();

        assert_eq!(dst, body);
        assert_eq!(transport.calls(), 1);
        assert_eq!(origin.hits(), 0);
    }

    #[test]
    fn forbidden_cached_redirect_is_evicted_and_re_resolved() {
        let body = b"fresh".to_vec();
        let origin = OriginStub::serve(b"unused".to_vec());
        // The cached signed URL answers 403 (expired link); the read evicts it
        // and re-resolves through the blob URL, which succeeds on Dragonfly.
        let transport = Arc::new(ScriptedTransport::new(vec![
            status(StatusCode::FORBIDDEN),
            Scripted::Body(body.clone()),
        ]));
        let registry = scripted_registry(&origin, transport.clone(), Duration::ZERO);
        let hex = hex_string(&TEST_BLOB_ID);
        registry.set_redirect_url(&hex, "http://cdn.example.com/expired".to_string());

        let mut dst = vec![0u8; body.len()];
        registry
            .try_read(
                &TEST_BLOB_ID,
                0,
                &mut dst,
                ReadContext::raw(ReadKind::OnDemand),
            )
            .unwrap();

        assert_eq!(dst, body);
        assert_eq!(transport.calls(), 2);
        assert!(registry.redirect_url(&hex).is_none());
    }
}
