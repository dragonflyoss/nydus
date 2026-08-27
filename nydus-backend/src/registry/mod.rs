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
//! registry-specific logic, including the Dragonfly load-shedding policy that
//! decides per read kind whether a failed Dragonfly read is retried, failed,
//! or falls back to the origin through a throttle (see [`dragonfly_action`]).

mod dns;
#[cfg(feature = "backend-dragonfly-proxy")]
mod dragonfly;
mod http;

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, RwLock};
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
use nydus_config::{DragonflyConfig, RegistryConfig};
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
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// The request was rate-limited by Dragonfly (`429`).
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

/// The underlying cause of a [`DragonflyFailure::Retryable`] failure. Carried
/// for logging and metrics attribution only; the load-shedding policy treats
/// every cause identically. Only the SDK transport (feature-gated) and tests
/// construct these.
#[cfg_attr(not(feature = "backend-dragonfly-proxy"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryableCause {
    /// The request timed out.
    Timeout,
    /// The local dfdaemon could not be reached.
    Connect,
    /// The proxy or the backend behind it answered HTTP 5xx.
    ServerError,
    /// The response body failed mid-stream after a successful start.
    Stream,
    /// Any other SDK transport error.
    Other,
}

impl RetryableCause {
    fn as_str(self) -> &'static str {
        match self {
            RetryableCause::Timeout => "timeout",
            RetryableCause::Connect => "connect",
            RetryableCause::ServerError => "server_error",
            RetryableCause::Stream => "stream",
            RetryableCause::Other => "other",
        }
    }
}

/// Classification of a failed Dragonfly read, driving the load-shedding
/// policy in [`dragonfly_action`]. Only the SDK transport (feature-gated) and
/// tests construct these.
#[cfg_attr(not(feature = "backend-dragonfly-proxy"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DragonflyFailure {
    /// The Dragonfly proxy answered HTTP 429.
    RateLimited,
    /// The Dragonfly proxy answered HTTP 403.
    Forbidden,
    /// A transient failure the policy may retry.
    Retryable(RetryableCause),
}

impl DragonflyFailure {
    fn as_str(self) -> &'static str {
        match self {
            DragonflyFailure::RateLimited => "rate_limited",
            DragonflyFailure::Forbidden => "forbidden",
            DragonflyFailure::Retryable(cause) => cause.as_str(),
        }
    }

    /// The metrics label class of this failure.
    fn metrics_class(self) -> nydus_telemetry::metrics::DragonflyErrorClass {
        use nydus_telemetry::metrics::DragonflyErrorClass;
        match self {
            DragonflyFailure::RateLimited => DragonflyErrorClass::RateLimited,
            DragonflyFailure::Forbidden => DragonflyErrorClass::Forbidden,
            DragonflyFailure::Retryable(RetryableCause::Timeout) => DragonflyErrorClass::Timeout,
            DragonflyFailure::Retryable(RetryableCause::Connect) => DragonflyErrorClass::Connect,
            DragonflyFailure::Retryable(RetryableCause::ServerError) => {
                DragonflyErrorClass::ServerError
            }
            DragonflyFailure::Retryable(RetryableCause::Stream) => DragonflyErrorClass::Stream,
            DragonflyFailure::Retryable(RetryableCause::Other) => DragonflyErrorClass::Other,
        }
    }
}

/// A classified error from the Dragonfly transport.
#[derive(Debug)]
struct DragonflyError {
    failure: DragonflyFailure,
    message: String,
}

impl std::fmt::Display for DragonflyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dragonfly {}: {}", self.failure.as_str(), self.message)
    }
}

impl DragonflyError {
    /// Fold a policy-terminal Dragonfly failure into the error the caller
    /// sees. A rate-limited prefetch carries the [`crate::throttled_error`]
    /// marker so the storage layer can distinguish "throttled — reschedule
    /// later" from an ordinary failure.
    fn into_registry_error(self, kind: ReadKind) -> RegistryError {
        match self.failure {
            DragonflyFailure::RateLimited => match kind {
                ReadKind::Prefetch => RegistryError::Io(crate::throttled_error(self.message)),
                ReadKind::OnDemand => RegistryError::TooManyRequests(self.message),
            },
            DragonflyFailure::Forbidden => RegistryError::Forbidden(self.message),
            DragonflyFailure::Retryable(cause) => RegistryError::Io(io::Error::other(format!(
                "dragonfly {}: {}",
                cause.as_str(),
                self.message
            ))),
        }
    }
}

/// The transport seam for Dragonfly reads: the SDK client in production,
/// scripted fakes in tests. Unconditional (not feature-gated) so the policy
/// loop and its tests compile without the `backend-dragonfly-proxy` feature.
trait DragonflyTransport: Send + Sync {
    /// Issue a blob `GET` through Dragonfly.
    fn get(
        &self,
        url: &str,
        headers: HeaderMap,
        kind: ReadKind,
    ) -> Result<Response, DragonflyError>;
}

/// Per-read-kind Dragonfly retry budgets, from the `registry.dragonfly`
/// configuration.
#[derive(Debug, Clone, Copy)]
struct DragonflyPolicy {
    /// Retries for a retryable prefetch failure before the read fails.
    prefetch_max_retries: u32,
    /// Retries for a retryable on-demand failure before falling back.
    ondemand_max_retries: u32,
}

impl Default for DragonflyPolicy {
    fn default() -> Self {
        Self {
            prefetch_max_retries: 10,
            ondemand_max_retries: 3,
        }
    }
}

impl DragonflyPolicy {
    /// The per-read-kind budgets from the `registry.dragonfly` configuration,
    /// or the defaults when no Dragonfly section is configured.
    fn from_config(config: Option<&DragonflyConfig>) -> Self {
        config
            .map(|dragonfly_config| DragonflyPolicy {
                prefetch_max_retries: dragonfly_config.prefetch_max_retries,
                ondemand_max_retries: dragonfly_config.ondemand_max_retries,
            })
            .unwrap_or_default()
    }
}

/// The `[min, max]` window for the random delay before a Dragonfly prefetch
/// retry. Prefetch retries are paced with this jitter so a burst of failing
/// prefetch reads does not hammer a struggling Dragonfly proxy in lockstep;
/// latency-sensitive on-demand retries are never delayed.
const PREFETCH_RETRY_DELAY_MIN: Duration = Duration::from_millis(100);
const PREFETCH_RETRY_DELAY_MAX: Duration = Duration::from_secs(1);

/// A random delay inside the prefetch retry window, seeded from OS entropy
/// via `RandomState` so no `rand` dependency is needed (same technique as the
/// prefetch rescheduler in `nydus-storage`).
fn prefetch_retry_delay() -> Duration {
    use std::hash::{BuildHasher, Hasher};
    let seed = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    let span = PREFETCH_RETRY_DELAY_MAX - PREFETCH_RETRY_DELAY_MIN;
    // The 900ms span is far below `u64::MAX` nanoseconds, so the cast is safe.
    let span_nanos = span.as_nanos() as u64;
    PREFETCH_RETRY_DELAY_MIN + Duration::from_nanos(seed % (span_nanos + 1))
}

/// What the load-shedding policy decides after one failed Dragonfly attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DragonflyAction {
    /// Retry the read through Dragonfly.
    Retry,
    /// Give up on Dragonfly and fall back to the throttled origin path.
    Fallback,
    /// Fail the read without touching the origin.
    Fail,
}

/// Decide what to do after a failed Dragonfly attempt. `attempts` counts the
/// Dragonfly attempts made so far, including the one that just failed.
///
/// The policy: `Forbidden` (403) is terminal for both read kinds. A
/// rate-limited (429) prefetch fails immediately — the caller reschedules it —
/// while a rate-limited on-demand read falls back to the origin without
/// retrying Dragonfly. Retryable failures (timeout, connect, 5xx, other) are
/// retried up to the read kind's budget; when the budget is exhausted a
/// prefetch fails and an on-demand read falls back. Prefetch reads never fall
/// back, so a Dragonfly outage degrades prefetch instead of flooding the
/// origin.
fn dragonfly_action(
    policy: DragonflyPolicy,
    kind: ReadKind,
    failure: DragonflyFailure,
    attempts: u32,
) -> DragonflyAction {
    match failure {
        DragonflyFailure::Forbidden => DragonflyAction::Fail,
        DragonflyFailure::RateLimited => match kind {
            ReadKind::Prefetch => DragonflyAction::Fail,
            ReadKind::OnDemand => DragonflyAction::Fallback,
        },
        DragonflyFailure::Retryable(_) => {
            let budget = match kind {
                ReadKind::Prefetch => policy.prefetch_max_retries,
                ReadKind::OnDemand => policy.ondemand_max_retries,
            };
            if attempts <= budget {
                DragonflyAction::Retry
            } else {
                match kind {
                    ReadKind::Prefetch => DragonflyAction::Fail,
                    ReadKind::OnDemand => DragonflyAction::Fallback,
                }
            }
        }
    }
}

/// Shapes origin requests issued as Dragonfly fallbacks to one request per
/// interval (1 QPS by default), per registry backend. Slots are handed out
/// FIFO under a mutex; the wait happens outside the lock so a sleeping waiter
/// never blocks the next caller from claiming its own later slot.
struct FallbackLimiter {
    /// The minimum spacing between two fallback requests; zero disables the
    /// throttle.
    interval: Duration,
    /// The earliest instant the next fallback request may start.
    next_slot: Mutex<Instant>,
}

impl FallbackLimiter {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            next_slot: Mutex::new(Instant::now()),
        }
    }

    /// Block until this caller's slot arrives, returning how long it waited.
    fn acquire(&self) -> Duration {
        if self.interval.is_zero() {
            return Duration::ZERO;
        }
        let now = Instant::now();
        let slot = {
            let mut next = self.next_slot.lock().unwrap();
            let slot = (*next).max(now);
            *next = slot + self.interval;
            slot
        };
        let wait = slot.saturating_duration_since(now);
        if !wait.is_zero() {
            std::thread::sleep(wait);
        }
        wait
    }
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

    /// Drain the streaming body into memory, returning an equivalent response
    /// backed by the buffered bytes. Pre-sizes the buffer from
    /// `content-length` when present.
    fn buffered(mut self) -> io::Result<Response> {
        let capacity = self
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        let body = runtime().block_on(async {
            let mut body = Vec::with_capacity(capacity);
            self.reader.read_to_end(&mut body).await?;
            io::Result::Ok(body)
        })?;
        Ok(Response {
            status: self.status,
            headers: self.headers,
            reader: Box::new(std::io::Cursor::new(body)),
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
    /// is rejected); kept unconditional so the policy loop and its tests
    /// compile without the feature.
    dragonfly: Option<Box<dyn DragonflyTransport>>,
    /// Per-read-kind retry budgets of the Dragonfly load-shedding policy.
    dragonfly_policy: DragonflyPolicy,
    /// Shapes origin requests issued as Dragonfly fallbacks.
    fallback_limiter: FallbackLimiter,
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
        let dragonfly: Option<Box<dyn DragonflyTransport>> = match &config.dragonfly {
            Some(dragonfly_config) => Some(Box::new(Dragonfly::new(
                dragonfly_config,
                config.http.timeout,
            )?)),
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

        let dragonfly_policy = DragonflyPolicy::from_config(config.dragonfly.as_ref());
        let fallback_limiter = FallbackLimiter::new(
            config
                .dragonfly
                .as_ref()
                .map(|dragonfly_config| dragonfly_config.fallback_interval)
                .unwrap_or(Duration::ZERO),
        );

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
            dragonfly_policy,
            fallback_limiter,
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
    /// configured, driven by the load-shedding policy (see
    /// [`dragonfly_action`]): retryable failures are retried up to the read
    /// kind's budget, on-demand reads then fall back to the origin through
    /// the fallback throttle, and prefetch reads fail without touching the
    /// origin. Everything else — and requests with `allow_dragonfly` false
    /// (auth token fetches) — goes directly to the origin, where the HTTP
    /// client's retry middleware retries transient failures.
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
                return self.request_via_dragonfly(dragonfly.as_ref(), url, headers, context);
            }
        }

        self.request_http(method, url, headers, context)
    }

    /// Drive a blob `GET` through Dragonfly under the load-shedding policy,
    /// retrying, failing, or falling back to the throttled origin path as
    /// [`dragonfly_action`] dictates. Prefetch retries wait a random
    /// [`PREFETCH_RETRY_DELAY_MIN`]–[`PREFETCH_RETRY_DELAY_MAX`] delay first;
    /// on-demand retries go immediately. Every failed attempt is recorded to
    /// the per-class Dragonfly error metrics.
    fn request_via_dragonfly(
        &self,
        dragonfly: &dyn DragonflyTransport,
        url: &str,
        headers: HeaderMap,
        context: ReadContext,
    ) -> RegistryResult<Response> {
        let mut attempts = 0u32;
        let err = loop {
            attempts += 1;
            let err = match self.request_dragonfly(dragonfly, url, headers.clone(), context) {
                Ok(response) => return Ok(response),
                Err(err) => err,
            };
            nydus_telemetry::metrics::record_dragonfly_error(
                err.failure.metrics_class(),
                context.kind,
            );

            match dragonfly_action(self.dragonfly_policy, context.kind, err.failure, attempts) {
                DragonflyAction::Retry => {
                    tracing::warn!(
                        "dragonfly request failed (attempt {attempts}), retrying: {err}"
                    );
                    if context.kind == ReadKind::Prefetch {
                        std::thread::sleep(prefetch_retry_delay());
                    }
                }
                DragonflyAction::Fallback => {
                    tracing::warn!(
                        "dragonfly request failed after {attempts} attempt(s), \
                         falling back to the origin: {err}"
                    );
                    return self.fallback_request_http(Method::GET, url, headers, context);
                }
                DragonflyAction::Fail => break err,
            }
        };

        tracing::warn!("dragonfly request failed terminally after {attempts} attempt(s): {err}");
        Err(err.into_registry_error(context.kind))
    }

    /// Issue an origin request as a Dragonfly fallback. Retries are not left
    /// to the HTTP client's retry middleware — its backoff would run under a
    /// single fallback-throttle permit — but performed explicitly here: each
    /// origin attempt (the first plus up to `http.max_retries` retries of
    /// transient failures) waits for its own fallback-throttle slot, so actual
    /// origin requests never exceed one per `fallback_interval`.
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

        let mut attempts = 0u32;
        let result = loop {
            attempts += 1;
            let waited = self.fallback_limiter.acquire();
            nydus_telemetry::metrics::record_fallback_throttle_wait(waited);

            let result = self.request_http_once(method.clone(), url, headers.clone(), context);
            // Mirror the retry middleware's transient classification: retry
            // transport errors and retryable statuses, pass everything else on.
            let transient = match &result {
                Ok(response) => {
                    response.status.is_server_error()
                        || response.status == StatusCode::REQUEST_TIMEOUT
                        || response.status == StatusCode::TOO_MANY_REQUESTS
                }
                Err(_) => true,
            };
            if !transient || attempts > self.http.max_retries() {
                break result;
            }
            tracing::warn!(
                "fallback origin request failed transiently (attempt {attempts}), \
                 retrying through the fallback throttle"
            );
        };
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
        let start = Instant::now();
        let result = runtime().block_on(async {
            self.http
                .client()
                .request(method.clone(), url)
                .headers(headers.clone())
                .send()
                .await
                .map_err(io::Error::other)
        });
        self.finish_http_request(method, url, headers, context, start, result)
    }

    /// Send exactly one request attempt to the origin (no retry middleware)
    /// and log its completion.
    fn request_http_once(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        context: ReadContext,
    ) -> RegistryResult<Response> {
        let start = Instant::now();
        let result = runtime().block_on(async {
            self.http
                .raw_client()
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

    /// Send a single blob `GET` attempt through the Dragonfly transport and
    /// log its completion. The body is drained into memory here, before the
    /// attempt counts as a success: the caller consumes the response only
    /// after the policy loop has returned, so a mid-stream dfdaemon/backend
    /// failure surfaced later would bypass the Dragonfly error metrics,
    /// retries, and fallback entirely. Buffering also means no bytes are ever
    /// exposed from an attempt that is later retried.
    fn request_dragonfly(
        &self,
        dragonfly: &dyn DragonflyTransport,
        url: &str,
        headers: HeaderMap,
        context: ReadContext,
    ) -> Result<Response, DragonflyError> {
        let start = Instant::now();
        let result = dragonfly
            .get(url, headers.clone(), context.kind)
            .and_then(|response| {
                response.buffered().map_err(|err| DragonflyError {
                    failure: DragonflyFailure::Retryable(RetryableCause::Stream),
                    message: format!("response body failed mid-stream: {err}"),
                })
            });
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
    /// transient failures inside the HTTP client's retry middleware;
    /// Dragonfly reads are governed by the load-shedding policy in
    /// [`Registry::request_via_dragonfly`].
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
            match self.request(Method::GET, &redirect, headers, context, true) {
                Ok(response) => {
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
                // Dragonfly reports an expired signed link as a terminal 403
                // error rather than a 403 response. The failure stays terminal
                // for this attempt, but the stale URL must not be retried
                // forever: drop it and fall through to re-resolve.
                Err(RegistryError::Forbidden(_)) => self.remove_redirect_url(&hex),
                Err(err) => return Err(err),
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
    fn policy_matrix_matches_the_load_shedding_table() {
        use DragonflyAction::*;
        use DragonflyFailure::*;
        use ReadKind::*;

        let policy = DragonflyPolicy::default();
        let retryable = Retryable(RetryableCause::Timeout);

        // (kind, failure, attempts) -> action, one row per cell of the table.
        let cases = [
            // Proxy 429: prefetch fails at once, ondemand falls back at once.
            (Prefetch, RateLimited, 1, Fail),
            (OnDemand, RateLimited, 1, Fallback),
            // Proxy 403: terminal for both kinds.
            (Prefetch, Forbidden, 1, Fail),
            (OnDemand, Forbidden, 1, Fail),
            // Retryable (timeout / connect / 5xx): prefetch retries ten
            // times — 11 attempts total — then fails without fallback.
            (Prefetch, retryable, 1, Retry),
            (Prefetch, retryable, 10, Retry),
            (Prefetch, retryable, 11, Fail),
            // Ondemand retries three times — 4 attempts total — then falls back.
            (OnDemand, retryable, 1, Retry),
            (OnDemand, retryable, 2, Retry),
            (OnDemand, retryable, 3, Retry),
            (OnDemand, retryable, 4, Fallback),
            // The failure class, not the attempt count, decides for 429/403:
            // a class switch deep into a retryable budget is still terminal
            // (or an immediate fallback) at that attempt.
            (Prefetch, RateLimited, 2, Fail),
            (OnDemand, RateLimited, 4, Fallback),
            (Prefetch, Forbidden, 2, Fail),
            (OnDemand, Forbidden, 4, Fail),
        ];
        for (kind, failure, attempts, want) in cases {
            assert_eq!(
                dragonfly_action(policy, kind, failure, attempts),
                want,
                "kind={kind:?} failure={failure:?} attempts={attempts}"
            );
        }

        // Every retryable cause maps to the same decisions.
        for cause in [
            RetryableCause::Timeout,
            RetryableCause::Connect,
            RetryableCause::ServerError,
            RetryableCause::Stream,
            RetryableCause::Other,
        ] {
            assert_eq!(
                dragonfly_action(policy, Prefetch, Retryable(cause), 11),
                Fail
            );
            assert_eq!(
                dragonfly_action(policy, OnDemand, Retryable(cause), 4),
                Fallback
            );
        }
    }

    #[test]
    fn prefetch_retry_delay_stays_inside_the_window() {
        for _ in 0..64 {
            let delay = prefetch_retry_delay();
            assert!(
                (PREFETCH_RETRY_DELAY_MIN..=PREFETCH_RETRY_DELAY_MAX).contains(&delay),
                "delay {delay:?} outside the window"
            );
        }
    }

    #[test]
    fn custom_retry_budgets_are_honored() {
        use DragonflyAction::*;
        use DragonflyFailure::*;
        use ReadKind::*;

        let policy = DragonflyPolicy {
            prefetch_max_retries: 0,
            ondemand_max_retries: 5,
        };
        let retryable = Retryable(RetryableCause::Timeout);

        // A zero prefetch budget makes the first retryable failure terminal.
        assert_eq!(dragonfly_action(policy, Prefetch, retryable, 1), Fail);

        // Ondemand retries through the enlarged budget, then falls back.
        for attempts in 1..=5 {
            assert_eq!(
                dragonfly_action(policy, OnDemand, retryable, attempts),
                Retry,
                "attempts={attempts}"
            );
        }
        assert_eq!(dragonfly_action(policy, OnDemand, retryable, 6), Fallback);
    }

    #[test]
    fn policy_budgets_come_from_the_dragonfly_config() {
        let dragonfly: DragonflyConfig = serde_yaml::from_str(
            "scheduler_endpoint: http://127.0.0.1:65000\n\
             ondemand_max_retries: 5\n\
             prefetch_max_retries: 0\n",
        )
        .unwrap();
        let policy = DragonflyPolicy::from_config(Some(&dragonfly));
        assert_eq!(policy.prefetch_max_retries, 0);
        assert_eq!(policy.ondemand_max_retries, 5);

        // No dragonfly section: the documented defaults.
        let defaults = DragonflyPolicy::from_config(None);
        assert_eq!(defaults.prefetch_max_retries, 10);
        assert_eq!(defaults.ondemand_max_retries, 3);
    }

    #[test]
    fn terminal_rate_limited_prefetch_carries_the_throttled_marker() {
        let err = DragonflyError {
            failure: DragonflyFailure::RateLimited,
            message: "proxy answered 429".to_string(),
        };
        let io_err: io::Error = err.into_registry_error(ReadKind::Prefetch).into();
        assert!(crate::is_backend_throttled(&io_err));

        let err = DragonflyError {
            failure: DragonflyFailure::Forbidden,
            message: "denied".to_string(),
        };
        let io_err: io::Error = err.into_registry_error(ReadKind::Prefetch).into();
        assert!(!crate::is_backend_throttled(&io_err));
        assert!(io_err.to_string().contains("forbidden"));
    }

    #[test]
    fn registry_error_to_io_error_preserves_dragonfly_messages() {
        let too_many_requests: io::Error =
            RegistryError::TooManyRequests("proxy answered 429".to_string()).into();
        assert!(
            too_many_requests.to_string().contains("too many requests"),
            "unexpected error: {too_many_requests}"
        );
        assert!(
            too_many_requests.to_string().contains("429"),
            "unexpected error: {too_many_requests}"
        );

        let forbidden: io::Error =
            RegistryError::Forbidden("proxy answered 403".to_string()).into();
        assert!(
            forbidden.to_string().contains("forbidden"),
            "unexpected error: {forbidden}"
        );
        assert!(
            forbidden.to_string().contains("403"),
            "unexpected error: {forbidden}"
        );

        let inner = io::Error::new(io::ErrorKind::TimedOut, "timed out");
        let passthrough: io::Error = RegistryError::Io(inner).into();
        assert_eq!(passthrough.kind(), io::ErrorKind::TimedOut);
        assert!(passthrough.to_string().contains("timed out"));
    }

    #[test]
    fn fallback_limiter_spaces_permits_by_the_interval() {
        let interval = Duration::from_millis(40);
        let limiter = FallbackLimiter::new(interval);

        // Idle limiter grants (nearly) immediately.
        let start = Instant::now();
        limiter.acquire();
        assert!(start.elapsed() < interval);

        // Consecutive permits are spaced at least an interval apart.
        limiter.acquire();
        assert!(start.elapsed() >= interval);

        // A zero interval disables the throttle.
        let unthrottled = FallbackLimiter::new(Duration::ZERO);
        let start = Instant::now();
        for _ in 0..3 {
            assert_eq!(unthrottled.acquire(), Duration::ZERO);
        }
        assert!(start.elapsed() < Duration::from_millis(20));
    }

    /// A scripted Dragonfly transport: pops one scripted outcome per `get`,
    /// counting the calls. `Ok(body)` produces a `200` response serving the
    /// bytes; `Err(failure)` produces a classified error.
    struct ScriptedTransport {
        script: Mutex<std::collections::VecDeque<Result<Vec<u8>, DragonflyFailure>>>,
        calls: std::sync::atomic::AtomicU32,
    }

    impl ScriptedTransport {
        fn new(
            script: impl IntoIterator<Item = Result<Vec<u8>, DragonflyFailure>>,
        ) -> ScriptedTransport {
            ScriptedTransport {
                script: Mutex::new(script.into_iter().collect()),
                calls: std::sync::atomic::AtomicU32::new(0),
            }
        }

        fn calls(&self) -> u32 {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl DragonflyTransport for ScriptedTransport {
        fn get(
            &self,
            _url: &str,
            _headers: HeaderMap,
            _kind: ReadKind,
        ) -> Result<Response, DragonflyError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let outcome = self
                .script
                .lock()
                .unwrap()
                .pop_front()
                .expect("transport called more times than scripted");
            match outcome {
                Ok(body) => Ok(Response {
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                    reader: Box::new(std::io::Cursor::new(body)),
                }),
                Err(failure) => Err(DragonflyError {
                    failure,
                    message: "scripted failure".to_string(),
                }),
            }
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
    /// transport and a configurable fallback throttle.
    fn scripted_registry(
        origin: &OriginStub,
        transport: Arc<ScriptedTransport>,
        fallback_interval: Duration,
    ) -> Registry {
        scripted_registry_at(origin.addr, transport, fallback_interval, 3)
    }

    /// A registry pointed at `addr` as its origin with `origin_max_retries`
    /// HTTP retries, a scripted Dragonfly transport, and a configurable
    /// fallback throttle.
    fn scripted_registry_at(
        addr: std::net::SocketAddr,
        transport: Arc<ScriptedTransport>,
        fallback_interval: Duration,
        origin_max_retries: u32,
    ) -> Registry {
        let config: RegistryConfig = serde_yaml::from_str(&format!(
            "addr: http://{addr}\nrepository: library/ubuntu\nhttp:\n  max_retries: {origin_max_retries}\n",
        ))
        .unwrap();
        let mut registry = Registry::new(config).unwrap();
        registry.dragonfly = Some(Box::new(SharedTransport(transport)));
        registry.fallback_limiter = FallbackLimiter::new(fallback_interval);
        registry.target = nydus_telemetry::metrics::BackendTarget::Proxy;
        registry
    }

    /// Lets a test keep a handle on its [`ScriptedTransport`] after boxing it
    /// into the registry.
    struct SharedTransport(Arc<ScriptedTransport>);

    impl DragonflyTransport for SharedTransport {
        fn get(
            &self,
            url: &str,
            headers: HeaderMap,
            kind: ReadKind,
        ) -> Result<Response, DragonflyError> {
            self.0.get(url, headers, kind)
        }
    }

    /// A body that serves `data` and then fails instead of reaching EOF.
    struct MidStreamFailingBody {
        data: Vec<u8>,
        pos: usize,
    }

    impl AsyncRead for MidStreamFailingBody {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            if self.pos < self.data.len() {
                let n = buf.remaining().min(self.data.len() - self.pos);
                let pos = self.pos;
                buf.put_slice(&self.data[pos..pos + n]);
                self.pos = pos + n;
                std::task::Poll::Ready(Ok(()))
            } else {
                std::task::Poll::Ready(Err(io::Error::other("connection reset mid-stream")))
            }
        }
    }

    /// A transport handing out pre-built responses in order, counting calls.
    struct SequencedTransport {
        responses: Mutex<std::collections::VecDeque<Response>>,
        calls: Arc<std::sync::atomic::AtomicU32>,
    }

    impl SequencedTransport {
        fn new(
            responses: impl IntoIterator<Item = Response>,
        ) -> (SequencedTransport, Arc<std::sync::atomic::AtomicU32>) {
            let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
            let transport = SequencedTransport {
                responses: Mutex::new(responses.into_iter().collect()),
                calls: calls.clone(),
            };
            (transport, calls)
        }
    }

    impl DragonflyTransport for SequencedTransport {
        fn get(
            &self,
            _url: &str,
            _headers: HeaderMap,
            _kind: ReadKind,
        ) -> Result<Response, DragonflyError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("transport called more times than scripted"))
        }
    }

    fn ok_response(reader: Box<dyn AsyncRead + Send + Unpin>) -> Response {
        Response {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            reader,
        }
    }

    const TEST_BLOB_ID: [u8; SHA256_DIGEST_SIZE] = [7u8; SHA256_DIGEST_SIZE];

    fn retryable() -> DragonflyFailure {
        DragonflyFailure::Retryable(RetryableCause::Connect)
    }

    #[test]
    fn ondemand_read_retries_dragonfly_then_falls_back_to_origin() {
        let body = b"0123456789".to_vec();
        let origin = OriginStub::serve(body.clone());
        // 4 Dragonfly attempts (1 + 3 retries) all fail retryably.
        let transport = Arc::new(ScriptedTransport::new(vec![
            Err(retryable()),
            Err(retryable()),
            Err(retryable()),
            Err(retryable()),
        ]));
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
        assert_eq!(transport.calls(), 4);
        assert_eq!(origin.hits(), 1);
    }

    #[test]
    fn fallback_reads_are_attributed_to_the_origin() {
        let body = b"0123456789".to_vec();
        let origin = OriginStub::serve(body.clone());
        let transport = Arc::new(ScriptedTransport::new(vec![Err(
            DragonflyFailure::RateLimited,
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
    fn prefetch_read_fails_without_origin_fallback() {
        let origin = OriginStub::serve(b"unused".to_vec());
        // A 1-retry budget keeps the test fast (the default is 10, each
        // prefetch retry sleeps a 100ms–1s jitter): 2 Dragonfly attempts
        // (1 + 1 retry), then the read must fail.
        let transport = Arc::new(ScriptedTransport::new(vec![
            Err(retryable()),
            Err(retryable()),
        ]));
        let mut registry = scripted_registry(&origin, transport.clone(), Duration::ZERO);
        registry.dragonfly_policy = DragonflyPolicy {
            prefetch_max_retries: 1,
            ..DragonflyPolicy::default()
        };

        let mut dst = vec![0u8; 4];
        let err = registry
            .try_read(
                &TEST_BLOB_ID,
                0,
                &mut dst,
                ReadContext::raw(ReadKind::Prefetch),
            )
            .unwrap_err();

        assert!(err.to_string().contains("dragonfly"));
        assert_eq!(transport.calls(), 2);
        assert_eq!(origin.hits(), 0);
    }

    #[test]
    fn rate_limited_prefetch_fails_at_once_with_the_throttled_marker() {
        let origin = OriginStub::serve(b"unused".to_vec());
        let transport = Arc::new(ScriptedTransport::new(vec![Err(
            DragonflyFailure::RateLimited,
        )]));
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

        assert!(crate::is_backend_throttled(&err));
        assert_eq!(transport.calls(), 1);
        assert_eq!(origin.hits(), 0);
    }

    #[test]
    fn forbidden_is_terminal_for_ondemand_reads() {
        let origin = OriginStub::serve(b"unused".to_vec());
        let transport = Arc::new(ScriptedTransport::new(vec![Err(
            DragonflyFailure::Forbidden,
        )]));
        let registry = scripted_registry(&origin, transport.clone(), Duration::ZERO);

        let mut dst = vec![0u8; 4];
        let err = registry
            .try_read(
                &TEST_BLOB_ID,
                0,
                &mut dst,
                ReadContext::raw(ReadKind::OnDemand),
            )
            .unwrap_err();

        assert!(matches!(err, RegistryError::Forbidden(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(origin.hits(), 0);
    }

    #[test]
    fn forbidden_is_terminal_for_prefetch_reads() {
        let origin = OriginStub::serve(b"unused".to_vec());
        let transport = Arc::new(ScriptedTransport::new(vec![Err(
            DragonflyFailure::Forbidden,
        )]));
        let registry = scripted_registry(&origin, transport.clone(), Duration::ZERO);

        let mut dst = vec![0u8; 4];
        let err = registry
            .try_read(
                &TEST_BLOB_ID,
                0,
                &mut dst,
                ReadContext::raw(ReadKind::Prefetch),
            )
            .unwrap_err();

        assert!(matches!(err, RegistryError::Forbidden(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(origin.hits(), 0);
    }

    #[test]
    fn retryable_read_succeeds_on_a_dragonfly_retry() {
        for kind in [ReadKind::OnDemand, ReadKind::Prefetch] {
            let body = b"retried".to_vec();
            let origin = OriginStub::serve(b"unused".to_vec());
            // Attempt 1 fails retryably; the retry succeeds on Dragonfly, so
            // the origin is never touched.
            let transport = Arc::new(ScriptedTransport::new(vec![
                Err(retryable()),
                Ok(body.clone()),
            ]));
            let registry = scripted_registry(&origin, transport.clone(), Duration::ZERO);

            let start = Instant::now();
            let mut dst = vec![0u8; body.len()];
            registry
                .try_read(&TEST_BLOB_ID, 0, &mut dst, ReadContext::raw(kind))
                .unwrap();
            let elapsed = start.elapsed();

            assert_eq!(dst, body, "kind={kind:?}");
            assert_eq!(transport.calls(), 2, "kind={kind:?}");
            assert_eq!(origin.hits(), 0, "kind={kind:?}");
            // Only the prefetch retry is paced by the jitter window;
            // on-demand retries go immediately.
            match kind {
                ReadKind::Prefetch => assert!(
                    elapsed >= PREFETCH_RETRY_DELAY_MIN,
                    "prefetch retry skipped the jitter delay: {elapsed:?}"
                ),
                ReadKind::OnDemand => assert!(
                    elapsed < PREFETCH_RETRY_DELAY_MIN,
                    "on-demand retry must not be delayed: {elapsed:?}"
                ),
            }
        }
    }

    #[test]
    fn rate_limit_after_a_retryable_failure_falls_back_at_once() {
        let body = b"0123456789".to_vec();
        let origin = OriginStub::serve(body.clone());
        // Attempt 1 is retryable; attempt 2 answers 429, which falls back
        // immediately instead of burning the remaining retryable budget.
        let transport = Arc::new(ScriptedTransport::new(vec![
            Err(retryable()),
            Err(DragonflyFailure::RateLimited),
        ]));
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
        assert_eq!(transport.calls(), 2);
        assert_eq!(origin.hits(), 1);
    }

    #[test]
    fn rate_limit_after_a_retryable_prefetch_fails_with_the_throttled_marker() {
        let origin = OriginStub::serve(b"unused".to_vec());
        // Attempt 1 is retryable; the 429 on attempt 2 is terminal for
        // prefetch and carries the throttled marker for the rescheduler.
        let transport = Arc::new(ScriptedTransport::new(vec![
            Err(retryable()),
            Err(DragonflyFailure::RateLimited),
        ]));
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

        assert!(crate::is_backend_throttled(&err));
        assert_eq!(transport.calls(), 2);
        assert_eq!(origin.hits(), 0);
    }

    #[test]
    fn fallback_origin_failure_surfaces_as_an_io_error() {
        // Nothing listens on the origin address, so the fallback's connect is
        // refused; zero origin retries keep the failure immediate.
        let transport = Arc::new(ScriptedTransport::new(vec![Err(
            DragonflyFailure::RateLimited,
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
        let transport = Arc::new(ScriptedTransport::new(vec![Err(
            DragonflyFailure::RateLimited,
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
    fn mid_stream_body_failure_is_retried_by_the_policy() {
        let body = b"whole body".to_vec();
        let origin = OriginStub::serve(b"unused".to_vec());
        // Attempt 1 starts streaming and dies mid-body; the policy must see
        // it as a retryable failure and retry, never touching the origin.
        let (transport, calls) = SequencedTransport::new(vec![
            ok_response(Box::new(MidStreamFailingBody {
                data: body[..4].to_vec(),
                pos: 0,
            })),
            ok_response(Box::new(std::io::Cursor::new(body.clone()))),
        ]);
        let mut registry = scripted_registry(
            &origin,
            Arc::new(ScriptedTransport::new(vec![])),
            Duration::ZERO,
        );
        registry.dragonfly = Some(Box::new(transport));

        let stream_errors_before = nydus_telemetry::metrics::dragonfly_error_total(
            nydus_telemetry::metrics::DragonflyErrorClass::Stream,
            ReadKind::OnDemand,
        );
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
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(origin.hits(), 0);
        assert!(
            nydus_telemetry::metrics::dragonfly_error_total(
                nydus_telemetry::metrics::DragonflyErrorClass::Stream,
                ReadKind::OnDemand,
            ) > stream_errors_before
        );
    }

    #[test]
    fn mid_stream_body_failure_exhausts_the_budget_then_falls_back() {
        let body = b"0123456789".to_vec();
        let origin = OriginStub::serve(body.clone());
        // Every Dragonfly attempt dies mid-body; the on-demand budget
        // (1 + 3 retries) drains, then the read falls back to the origin.
        let (transport, calls) = SequencedTransport::new((0..4).map(|_| {
            ok_response(Box::new(MidStreamFailingBody {
                data: b"par".to_vec(),
                pos: 0,
            }))
        }));
        let mut registry = scripted_registry(
            &origin,
            Arc::new(ScriptedTransport::new(vec![])),
            Duration::ZERO,
        );
        registry.dragonfly = Some(Box::new(transport));

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
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert_eq!(origin.hits(), 1);
    }

    #[test]
    fn consecutive_fallbacks_are_throttled() {
        let body = b"abcd".to_vec();
        let origin = OriginStub::serve(body.clone());
        // Two reads, each rate-limited once, each falling back to the origin.
        let transport = Arc::new(ScriptedTransport::new(vec![
            Err(DragonflyFailure::RateLimited),
            Err(DragonflyFailure::RateLimited),
        ]));
        let interval = Duration::from_millis(80);
        let registry = scripted_registry(&origin, transport.clone(), interval);

        let start = Instant::now();
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
        // The second fallback had to wait for the next interval slot.
        assert!(start.elapsed() >= interval);
    }

    #[test]
    fn cached_redirect_reads_ride_dragonfly() {
        let body = b"redirected".to_vec();
        let origin = OriginStub::serve(b"unused".to_vec());
        let transport = Arc::new(ScriptedTransport::new(vec![Ok(body.clone())]));
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
        // The cached signed URL fails with a Dragonfly 403 (expired link);
        // the read evicts it and re-resolves through the blob URL, which
        // succeeds on Dragonfly.
        let transport = Arc::new(ScriptedTransport::new(vec![
            Err(DragonflyFailure::Forbidden),
            Ok(body.clone()),
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

    #[test]
    fn fallback_retries_are_throttled_per_attempt() {
        // Every fallback attempt answers a retryable 500, so the read burns
        // its full origin budget (1 + 1 retry); each attempt must wait for
        // its own throttle slot.
        let origin = OriginStub::serve_with_status("500 Internal Server Error", b"boom".to_vec());
        let transport = Arc::new(ScriptedTransport::new(vec![Err(
            DragonflyFailure::RateLimited,
        )]));
        let interval = Duration::from_millis(80);
        let registry = scripted_registry_at(origin.addr, transport.clone(), interval, 1);

        let start = Instant::now();
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
        // The retry had to wait for the next interval slot.
        assert!(start.elapsed() >= interval);
    }
}
