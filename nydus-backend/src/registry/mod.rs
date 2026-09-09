//! The OCI registry backend.
//!
//! A blob is addressed by its full-blob digest, the digest the merged
//! bootstrap's device slots carry and the on-disk blob metadata is named by,
//! and served in byte ranges. Blob metadata normally comes from the cache
//! directory, the backend recovering it from the blob's trailing footer only
//! when the cache has none.
//!
//! ```text
//!                             Registry
//!                                │
//!            ┌───────────────────┼───────────────────┐
//!          Auth            RedirectCache           policy
//!    handshake, token     signed 3xx URLs    settle a Dragonfly answer
//!                                │
//!                      ┌─────────┴─────────┐
//!                    Http               Dragonfly
//!               direct origin      seed peers, own retries
//!                      │
//!             Http (back to source)
//!          rate limited, on-demand fallback
//! ```
//!
//! [`Registry`] owns the registry-specific logic, the transports spend their
//! own retries and hand back a settled [`Response`]. A blob `GET` rides
//! Dragonfly when it is configured and [`policy::decide`] settles the answer:
//! serve it, defer a prefetch read to the storage layer's reschedule, or fall
//! an on-demand read back to the origin through the rate-limited client.
//! `HEAD` requests and token fetches always go straight to the origin.
//!
//! Every read runs as a task on the backend runtime and the calling thread
//! waits on its join handle, so the body flows from hyper or tonic to the read
//! inside the worker pool and the caller is woken once, when the bytes are
//! ready to copy out.

mod auth;
#[cfg(feature = "backend-dragonfly")]
mod dragonfly;
mod http;
mod policy;
mod redirect;
mod response;

use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Instant;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, RANGE, WWW_AUTHENTICATE};
use reqwest::{Method, StatusCode};
use tokio::runtime::Runtime;
use tracing::warn;
use url::Url;

use nydus_config::RegistryConfig;
use nydus_format::blob::{BlobFooter, BlobMetadata, NYDUS_BLOB_FOOTER_SIZE};
use nydus_format::utils::{hex_string, SHA256_DIGEST_SIZE};
use nydus_telemetry::metrics::{
    collect_read_backend_failure_metrics, collect_read_backend_finished_metrics,
};

use crate::{Backend, BlobBackend, Protocol, ReadKind};

use self::auth::Auth;
#[cfg(feature = "backend-dragonfly")]
use self::dragonfly::Dragonfly;
use self::http::{Http, RateLimit};
use self::policy::Action;
use self::redirect::RedirectCache;
use self::response::{fill_exact, status_error, Response};

/// The runtime bridging the synchronous [`BlobBackend`] trait to the
/// asynchronous transports.
static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .thread_name("nydus-backend")
        .enable_all()
        .build()
        .expect("failed to build backend tokio runtime")
});

/// Run `future` as a task on the runtime and wait for it. The whole request
/// rides the worker pool, hyper and tonic handing it body chunks on the same
/// worker, and the calling thread is woken once when the task settles.
fn run<F>(future: F) -> io::Result<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    RUNTIME
        .block_on(RUNTIME.spawn(future))
        .map_err(io::Error::other)
}

/// An error of the registry backend. Private to the crate, it folds into an
/// [`io::Error`] at the [`BlobBackend`] boundary.
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

/// The transport a blob `GET` rides on: the origin registry over HTTP, or the
/// Dragonfly seed peers. One call spends the transport's own retries and hands
/// back a settled answer, a Dragonfly body already buffered so a mid-stream
/// failure surfaces here rather than while the caller consumes it.
#[async_trait]
trait BlobTransport: Send + Sync {
    async fn get(&self, url: &str, headers: HeaderMap, kind: ReadKind) -> RegistryResult<Response>;
}

/// Split a registry `addr` such as `http://127.0.0.1:5000` into its scheme
/// and `host[:port]` authority.
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

/// A blob backend over an OCI registry: the synchronous [`BlobBackend`] face
/// of [`Inner`], which does the asynchronous work on the runtime.
///
/// ```text
/// read_range_into(dst)                         runtime worker
///   │ spawn(get_blob into an owned buffer) ──▶ get_blob ◀── body chunks ── hyper / tonic
///   │ block_on(join handle)                        │
///   ◀──────────── one wake ───────────────────────┘
///   └─ copy into dst, note who served it
/// ```
pub(crate) struct Registry {
    inner: Arc<Inner>,
    /// Whether a read has succeeded, so later reads skip [`Self::first_read`].
    first_read_done: AtomicBool,
    /// Serializes reads until the first one succeeds, so a cold-start burst
    /// performs one auth handshake and reuses its token instead of one per
    /// read.
    first_read: Mutex<()>,
}

/// The registry client every read shares, behind an [`Arc`] so a read can run
/// on the runtime while its caller waits.
///
/// ```text
/// get_blob(range, kind)
///   │
///   ├─ cached redirect ──▶ send(GET redirect) ──────────────────────┐
///   │                       401/403 evicts it and falls through      │
///   └─ blob URL ──▶ authorized_request(GET) ─┬─ 3xx ──▶ send(GET location), cache it
///                                            └─ 2xx ──────────────────┐
///                                                                     ▼
///                                                                fill_exact
///
/// send(method, url)
///   ├─ GET, Dragonfly configured ──▶ dragonfly.get ──▶ policy::decide
///   │                                   Serve ──▶ answer
///   │                                   Fallback ──▶ back_to_source.get (on-demand)
///   │                                   Defer ──▶ Err(PrefetchDeferred) (prefetch)
///   └─ otherwise ──▶ http.request
/// ```
struct Inner {
    /// The scheme of the configured `addr`, `http` or `https`.
    scheme: &'static str,
    /// The registry `host[:port]` authority.
    host: String,
    /// The image repository, such as `library/ubuntu`.
    repository: String,
    /// The credentials and the cached `Authorization` they produced.
    auth: Auth,
    /// The signed URLs blob `GET`s were redirected to, by blob hex digest.
    redirects: RedirectCache,
    /// The direct client to the origin.
    http: Http,
    /// The origin client an on-demand read falls back to when Dragonfly
    /// cannot serve it, every attempt claiming a rate limit slot first.
    back_to_source: Http,
    /// The Dragonfly transport when configured, always `None` without the
    /// `backend-dragonfly` feature since the config is rejected.
    dragonfly: Option<Box<dyn BlobTransport>>,
    /// How reads are fetched when nothing else is known, the `protocol` label
    /// of a failed read: the Dragonfly SDK when configured, otherwise HTTP.
    protocol: Protocol,
}

impl Registry {
    /// Build a registry backend from its configuration.
    pub(crate) fn new(config: RegistryConfig) -> io::Result<Self> {
        let (scheme, host) = parse_registry_addr(&config.addr)?;
        let http = Http::builder(&config.http).build()?;
        let rate_limit = RateLimit::new(
            config
                .dragonfly
                .as_ref()
                .map(|dragonfly| dragonfly.back_to_source.request_rate_limit)
                .unwrap_or(0),
        );
        let back_to_source = Http::builder(&config.http).rate_limit(rate_limit).build()?;

        let dragonfly: Option<Box<dyn BlobTransport>> = match &config.dragonfly {
            #[cfg(feature = "backend-dragonfly")]
            Some(dragonfly) => Some(Box::new(Dragonfly::new(dragonfly)?)),
            #[cfg(not(feature = "backend-dragonfly"))]
            Some(dragonfly) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "dragonfly.scheduler_endpoint is set ({}) but this build lacks \
                         the `backend-dragonfly` feature",
                        dragonfly.scheduler_endpoint
                    ),
                ))
            }
            None => None,
        };

        Ok(Self::from_parts(
            scheme,
            host,
            config.repository,
            config.auth,
            http,
            back_to_source,
            dragonfly,
        ))
    }

    /// Assemble a registry backend from its parts. `basic_auth` is the
    /// `base64(user:pass)` of the config, sent verbatim after `Basic `.
    fn from_parts(
        scheme: &'static str,
        host: String,
        repository: String,
        basic_auth: Option<String>,
        http: Http,
        back_to_source: Http,
        dragonfly: Option<Box<dyn BlobTransport>>,
    ) -> Self {
        let protocol = if dragonfly.is_some() {
            Protocol::DragonflySdk
        } else {
            Protocol::Http
        };
        Registry {
            inner: Arc::new(Inner {
                scheme,
                host,
                repository,
                auth: Auth::new(basic_auth),
                redirects: RedirectCache::new(),
                http,
                back_to_source,
                dragonfly,
                protocol,
            }),
            first_read_done: AtomicBool::new(false),
            first_read: Mutex::new(()),
        }
    }
}

impl Inner {
    /// The URL of the blob with hex digest `hex`.
    fn blob_url(&self, hex: &str) -> String {
        format!(
            "{}://{}/v2/{}/blobs/sha256:{}",
            self.scheme, self.host, self.repository, hex
        )
    }

    /// Send a request. A `GET` rides Dragonfly when it is configured and
    /// [`policy::decide`] settles the answer, everything else goes straight to
    /// the origin.
    async fn send(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        kind: ReadKind,
    ) -> RegistryResult<Response> {
        let dragonfly = match (&self.dragonfly, &method) {
            (Some(dragonfly), &Method::GET) => dragonfly,
            _ => return self.http.request(method, url, headers, kind).await,
        };

        let outcome = dragonfly.get(url, headers.clone(), kind).await;
        match policy::decide(kind, outcome).await {
            Action::Serve(response) => Ok(response),
            Action::Fallback(err) => {
                warn!("dragonfly request failed, falling back to the origin: {err}");
                let start = Instant::now();
                match self.back_to_source.get(url, headers, kind).await {
                    Ok(mut response) => {
                        response.protocol = Protocol::DragonflyHttp;
                        Ok(response)
                    }
                    Err(err) => {
                        collect_read_backend_failure_metrics(
                            kind,
                            Backend::Registry,
                            Some(Protocol::DragonflyHttp),
                            start.elapsed(),
                        );
                        Err(err)
                    }
                }
            }
            Action::Defer(err) => {
                warn!("dragonfly request failed: {err}");
                Err(err)
            }
        }
    }

    /// Send a request, answering a `401` with the auth handshake.
    ///
    /// ```text
    /// send with cached Authorization ──▶ not 401 ──▶ answer
    ///   │ 401
    ///   ▼
    /// resend without Authorization when one was sent, to get a fresh challenge
    ///   │
    ///   ▼
    /// WWW-Authenticate ──▶ Auth::obtain ──▶ resend with it ──▶ 2xx/3xx caches it
    /// ```
    async fn authorized_request(
        &self,
        method: Method,
        url: &str,
        mut headers: HeaderMap,
        kind: ReadKind,
    ) -> RegistryResult<Response> {
        let cached = self.auth.current();
        if !cached.is_empty() {
            headers.insert(AUTHORIZATION, auth::header_value(&cached)?);
        }

        let response = self
            .send(method.clone(), url, headers.clone(), kind)
            .await?;
        if response.status != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }

        let challenge_response = if headers.remove(AUTHORIZATION).is_some() {
            self.send(method.clone(), url, headers.clone(), kind)
                .await?
        } else {
            response
        };

        let challenge = challenge_response
            .headers
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .and_then(Auth::parse_challenge);
        let Some(challenge) = challenge else {
            return Ok(challenge_response);
        };

        let authorization = self.auth.obtain(&self.http, challenge).await?;
        headers.insert(AUTHORIZATION, auth::header_value(&authorization)?);
        let response = self.send(method, url, headers, kind).await?;
        if response.status.is_success() || response.status.is_redirection() {
            self.auth.set(authorization);
        }
        Ok(response)
    }

    /// Fill `dst` with the blob bytes from `offset`, through the cached
    /// redirect when there is one and otherwise through the blob URL, caching
    /// the redirect it answers with. Returns the protocol that served the bytes.
    async fn get_blob(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        dst: &mut [u8],
        kind: ReadKind,
    ) -> RegistryResult<Protocol> {
        let hex = hex_string(blob_id);
        let end = offset + dst.len() as u64 - 1;
        let range: HeaderValue = format!("bytes={offset}-{end}").parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(RANGE, range);

        if let Some(redirect) = self.redirects.get(&hex) {
            let response = self
                .send(Method::GET, &redirect, headers.clone(), kind)
                .await?;
            match response.status {
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => self.redirects.remove(&hex),
                status if status.is_success() => return fill_exact(response, dst).await,
                _ => return Err(status_error(response).await),
            }
        }

        let url = self.blob_url(&hex);
        let response = self
            .authorized_request(Method::GET, &url, headers.clone(), kind)
            .await?;
        if response.status.is_redirection() {
            let location = response.location()?;
            let redirected = self.send(Method::GET, &location, headers, kind).await?;
            if !redirected.status.is_success() {
                return Err(status_error(redirected).await);
            }
            self.redirects.insert(&hex, location);
            fill_exact(redirected, dst).await
        } else if response.status.is_success() {
            fill_exact(response, dst).await
        } else {
            Err(status_error(response).await)
        }
    }

    /// The size of a blob, from a `HEAD` request following one redirect.
    async fn stat_blob(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        kind: ReadKind,
    ) -> RegistryResult<u64> {
        let url = self.blob_url(&hex_string(blob_id));
        let response = self
            .authorized_request(Method::HEAD, &url, HeaderMap::new(), kind)
            .await?;

        let response = if response.status.is_redirection() {
            let location = response.location()?;
            let redirected = self
                .send(Method::HEAD, &location, HeaderMap::new(), kind)
                .await?;
            if !redirected.status.is_success() {
                return Err(status_error(redirected).await);
            }
            redirected
        } else if response.status.is_success() {
            response
        } else {
            return Err(status_error(response).await);
        };

        response.content_length()
    }

    /// Recover a blob's metadata from its trailing footer: `HEAD` for the
    /// size, read the footer, then read the blob metadata region it points at.
    async fn get_blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        kind: ReadKind,
    ) -> RegistryResult<BlobMetadata> {
        let size = self.stat_blob(blob_id, kind).await?;
        let footer_offset = BlobFooter::offset_from_size(size)
            .map_err(|err| RegistryError::Io(io::Error::other(err)))?;

        let mut footer_bytes = [0u8; NYDUS_BLOB_FOOTER_SIZE];
        self.get_blob(blob_id, footer_offset, &mut footer_bytes, kind)
            .await?;
        let footer = BlobFooter::from_bytes(&footer_bytes)
            .map_err(|err| RegistryError::Io(io::Error::other(err)))?;

        let blob_metadata_size = usize::try_from(footer.blob_metadata_size()).map_err(|_| {
            RegistryError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "blob meta size exceeds usize",
            ))
        })?;
        let mut blob_metadata_bytes = vec![0u8; blob_metadata_size];
        self.get_blob(
            blob_id,
            footer.blob_metadata_offset(),
            &mut blob_metadata_bytes,
            kind,
        )
        .await?;

        BlobMetadata::from_bytes(&blob_metadata_bytes, false)
            .map_err(|err| RegistryError::Io(io::Error::other(err)))
    }
}

impl BlobBackend for Registry {
    fn backend(&self) -> Backend {
        Backend::Registry
    }

    fn protocol(&self) -> Option<Protocol> {
        Some(self.inner.protocol)
    }

    fn blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        kind: ReadKind,
    ) -> io::Result<BlobMetadata> {
        let inner = self.inner.clone();
        let blob_id = *blob_id;
        Ok(run(async move {
            inner.get_blob_metadata(&blob_id, kind).await
        })??)
    }

    /// Reads are serialized until the first one succeeds, so a cold-start
    /// burst waits for one auth handshake and reuses its token.
    fn read_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        dst: &mut [u8],
        kind: ReadKind,
    ) -> io::Result<()> {
        if dst.is_empty() {
            return Ok(());
        }
        let _first = (!self.first_read_done.load(Ordering::Acquire))
            .then(|| self.first_read.lock().unwrap());

        let start = Instant::now();
        let inner = self.inner.clone();
        let blob_id = *blob_id;
        let len = dst.len();
        let result = run(async move {
            let mut buf = vec![0u8; len];
            let protocol = inner.get_blob(&blob_id, offset, &mut buf, kind).await?;
            Ok::<_, RegistryError>((buf, protocol))
        })
        .and_then(|result| Ok(result?));

        match result {
            Ok((buf, protocol)) => {
                collect_read_backend_finished_metrics(
                    kind,
                    Backend::Registry,
                    Some(protocol),
                    len as u64,
                    start.elapsed(),
                );
                dst.copy_from_slice(&buf);
                self.first_read_done.store(true, Ordering::Release);
                Ok(())
            }
            Err(err) => {
                collect_read_backend_failure_metrics(
                    kind,
                    Backend::Registry,
                    Some(self.inner.protocol),
                    start.elapsed(),
                );
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::net::{SocketAddr, TcpListener};
    use std::sync::atomic::AtomicU32;
    use std::thread;
    use std::time::{Duration, Instant};

    use nydus_telemetry::metrics;

    const TEST_BLOB_ID: [u8; SHA256_DIGEST_SIZE] = [7u8; SHA256_DIGEST_SIZE];

    #[async_trait]
    impl<T: BlobTransport> BlobTransport for Arc<T> {
        async fn get(
            &self,
            url: &str,
            headers: HeaderMap,
            kind: ReadKind,
        ) -> RegistryResult<Response> {
            (**self).get(url, headers, kind).await
        }
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

    /// A Dragonfly transport popping one scripted outcome per `get`, counting
    /// the calls.
    struct ScriptedTransport {
        script: Mutex<VecDeque<Scripted>>,
        calls: AtomicU32,
    }

    impl ScriptedTransport {
        fn new(script: impl IntoIterator<Item = Scripted>) -> Arc<ScriptedTransport> {
            Arc::new(ScriptedTransport {
                script: Mutex::new(script.into_iter().collect()),
                calls: AtomicU32::new(0),
            })
        }

        fn calls(&self) -> u32 {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl BlobTransport for ScriptedTransport {
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
                    protocol: Protocol::DragonflySdk,
                }),
                Scripted::Status(status, headers) => Ok(Response {
                    status,
                    headers,
                    reader: Box::new(std::io::Cursor::new(Vec::new())),
                    protocol: Protocol::DragonflySdk,
                }),
                Scripted::Transport => Err(RegistryError::Io(io::Error::other("scripted failure"))),
            }
        }
    }

    /// A Dragonfly transport answering `401` with a basic challenge until the
    /// request carries `Authorization`, holding its first answer for `delay`
    /// so a second reader piles up behind it. Counts the challenges issued.
    struct AuthGate {
        delay: Duration,
        first: AtomicBool,
        challenges: AtomicU32,
    }

    impl AuthGate {
        fn new(delay: Duration) -> Arc<AuthGate> {
            Arc::new(AuthGate {
                delay,
                first: AtomicBool::new(true),
                challenges: AtomicU32::new(0),
            })
        }

        fn challenges(&self) -> u32 {
            self.challenges.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl BlobTransport for AuthGate {
        async fn get(
            &self,
            _url: &str,
            headers: HeaderMap,
            _kind: ReadKind,
        ) -> RegistryResult<Response> {
            if self.first.swap(false, Ordering::SeqCst) {
                tokio::time::sleep(self.delay).await;
            }
            if headers.contains_key(AUTHORIZATION) {
                return Ok(Response {
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                    reader: Box::new(std::io::Cursor::new(b"ok".to_vec())),
                    protocol: Protocol::DragonflySdk,
                });
            }
            self.challenges.fetch_add(1, Ordering::SeqCst);
            let mut challenge = HeaderMap::new();
            challenge.insert(
                WWW_AUTHENTICATE,
                r#"Basic realm="registry""#.parse().unwrap(),
            );
            Ok(Response {
                status: StatusCode::UNAUTHORIZED,
                headers: challenge,
                reader: Box::new(std::io::Cursor::new(Vec::new())),
                protocol: Protocol::DragonflySdk,
            })
        }
    }

    /// A minimal origin on a loopback listener answering every request with
    /// `status` and `body`, counting the requests served.
    struct OriginStub {
        addr: SocketAddr,
        hits: Arc<AtomicU32>,
    }

    impl OriginStub {
        fn serve(body: Vec<u8>) -> OriginStub {
            OriginStub::serve_with_status("206 Partial Content", body)
        }

        fn serve_with_status(status: &'static str, body: Vec<u8>) -> OriginStub {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let hits = Arc::new(AtomicU32::new(0));
            let hits_in_thread = hits.clone();
            thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { break };
                    let body = body.clone();
                    let hits = hits_in_thread.clone();
                    thread::spawn(move || {
                        use std::io::{Read, Write};
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
    fn dead_addr() -> SocketAddr {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    /// A registry over the config `yaml` with `transport` as its Dragonfly
    /// and a back-to-source rate limit of one slot per `interval`, zero
    /// disabling it.
    fn scripted_registry_from(
        yaml: &str,
        transport: impl BlobTransport + 'static,
        interval: Duration,
    ) -> Registry {
        let config: RegistryConfig = serde_yaml::from_str(yaml).unwrap();
        let (scheme, host) = parse_registry_addr(&config.addr).unwrap();
        let http = Http::builder(&config.http).build().unwrap();
        let back_to_source = Http::builder(&config.http)
            .rate_limit(RateLimit::with_interval(1, interval))
            .build()
            .unwrap();
        Registry::from_parts(
            scheme,
            host,
            config.repository,
            config.auth,
            http,
            back_to_source,
            Some(Box::new(transport)),
        )
    }

    /// A registry whose origin is `addr` with `origin_max_retries` HTTP
    /// retries, `transport` as its Dragonfly, and a back-to-source rate limit
    /// of one slot per `interval`, zero disabling it.
    fn scripted_registry_at(
        addr: SocketAddr,
        transport: impl BlobTransport + 'static,
        interval: Duration,
        origin_max_retries: u32,
    ) -> Registry {
        scripted_registry_from(
            &format!(
                "addr: http://{addr}\nrepository: library/ubuntu\nhttp:\n  max_retries: {origin_max_retries}\n",
            ),
            transport,
            interval,
        )
    }

    /// A registry whose origin is `origin`, with the default HTTP retries.
    fn scripted_registry(
        origin: &OriginStub,
        transport: impl BlobTransport + 'static,
        interval: Duration,
    ) -> Registry {
        scripted_registry_at(origin.addr, transport, interval, 3)
    }

    /// Read the test blob from offset zero into `dst`, keeping the registry
    /// error and the side that served it.
    fn read(registry: &Registry, kind: ReadKind, dst: &mut [u8]) -> RegistryResult<Protocol> {
        RUNTIME.block_on(registry.inner.get_blob(&TEST_BLOB_ID, 0, dst, kind))
    }

    #[test]
    fn builds_blob_url() {
        let config: RegistryConfig = serde_yaml::from_str(
            "addr: https://registry.example.com\nrepository: library/ubuntu\n",
        )
        .unwrap();
        let registry = Registry::new(config).unwrap();
        assert_eq!(
            registry.inner.blob_url("abc123"),
            "https://registry.example.com/v2/library/ubuntu/blobs/sha256:abc123"
        );
    }

    #[test]
    fn parses_registry_addr() {
        let test_cases = vec![
            ("http://127.0.0.1:5000", Some(("http", "127.0.0.1:5000"))),
            (
                "https://registry-1.docker.io",
                Some(("https", "registry-1.docker.io")),
            ),
            (
                "https://registry.example.com/",
                Some(("https", "registry.example.com")),
            ),
            ("registry.example.com", None),
            ("ftp://registry.example.com", None),
            ("https://registry.example.com/v2", None),
        ];
        for (addr, expected) in test_cases {
            let parsed = parse_registry_addr(addr).ok();
            assert_eq!(
                parsed
                    .as_ref()
                    .map(|(scheme, host)| (*scheme, host.as_str())),
                expected,
                "addr={addr}"
            );
        }
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
        assert_eq!(registry.inner.host, "registry.example.com");
        assert_eq!(registry.inner.scheme, "https");
        assert!(registry.inner.dragonfly.is_none());
        assert_eq!(registry.inner.protocol, Protocol::Http);
    }

    #[cfg(not(feature = "backend-dragonfly"))]
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
        assert!(err.to_string().contains("backend-dragonfly"));
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

    #[test]
    fn ondemand_transport_failure_falls_back_to_origin() {
        let body = b"0123456789".to_vec();
        let origin = OriginStub::serve(body.clone());
        let transport = ScriptedTransport::new(vec![Scripted::Transport]);
        let registry = scripted_registry(&origin, transport.clone(), Duration::ZERO);

        let mut dst = vec![0u8; body.len()];
        let protocol = read(&registry, ReadKind::OnDemand, &mut dst).unwrap();

        assert_eq!(protocol, Protocol::DragonflyHttp);
        assert_eq!(dst, body);
        assert_eq!(transport.calls(), 1);
        assert_eq!(origin.hits(), 1);
    }

    #[test]
    fn back_to_source_reads_are_counted_as_such() {
        let body = b"0123456789".to_vec();
        let origin = OriginStub::serve(body.clone());
        let transport = ScriptedTransport::new(vec![status(StatusCode::TOO_MANY_REQUESTS)]);
        let registry = scripted_registry(&origin, transport, Duration::ZERO);

        let back_to_source_before = metrics::READ_BACKEND_COUNT
            .with_label_values(&["ondemand", "registry", "dragonfly-http"])
            .get();
        let mut dst = vec![0u8; body.len()];
        registry
            .read_range_into(&TEST_BLOB_ID, 0, &mut dst, ReadKind::OnDemand)
            .unwrap();

        assert_eq!(dst, body);
        assert_eq!(origin.hits(), 1);
        assert!(
            metrics::READ_BACKEND_COUNT
                .with_label_values(&["ondemand", "registry", "dragonfly-http"])
                .get()
                > back_to_source_before
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
            let transport = ScriptedTransport::new(vec![outcome]);
            let registry = scripted_registry(&origin, transport.clone(), Duration::ZERO);

            let mut dst = vec![0u8; 4];
            let err: io::Error = read(&registry, ReadKind::Prefetch, &mut dst)
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
            let transport = ScriptedTransport::new(vec![outcome]);
            let registry = scripted_registry(&origin, transport.clone(), Duration::ZERO);

            let mut dst = vec![0u8; body.len()];
            read(&registry, ReadKind::OnDemand, &mut dst).unwrap();

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
                let transport = ScriptedTransport::new(vec![status(terminal)]);
                let registry = scripted_registry(&origin, transport.clone(), Duration::ZERO);

                let mut dst = vec![0u8; 4];
                let err = read(&registry, kind, &mut dst).unwrap_err();

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
            let transport = ScriptedTransport::new(vec![
                Scripted::Status(StatusCode::UNAUTHORIZED, challenge),
                Scripted::Body(body.clone()),
            ]);
            let registry = scripted_registry_from(
                &format!(
                    "addr: http://{}\nrepository: library/ubuntu\nauth: YWxpY2U6c2VjcmV0\n",
                    origin.addr
                ),
                transport.clone(),
                Duration::ZERO,
            );

            let mut dst = vec![0u8; body.len()];
            read(&registry, kind, &mut dst).unwrap();

            assert_eq!(dst, body, "kind={kind:?}");
            assert_eq!(transport.calls(), 2, "kind={kind:?}");
            assert_eq!(origin.hits(), 0, "kind={kind:?}");
            assert_eq!(registry.inner.auth.current(), "Basic YWxpY2U6c2VjcmV0");
        }
    }

    #[test]
    fn blob_metadata_reads_carry_the_read_kind() {
        let test_cases = vec![
            (ReadKind::Prefetch, true, 1),
            (ReadKind::OnDemand, false, 2),
        ];

        for (kind, deferred, origin_hits) in test_cases {
            let origin = OriginStub::serve(vec![0u8; 2 * NYDUS_BLOB_FOOTER_SIZE]);
            let transport = ScriptedTransport::new(vec![status(StatusCode::TOO_MANY_REQUESTS)]);
            let registry = scripted_registry(&origin, transport.clone(), Duration::ZERO);

            let err = registry.blob_metadata(&TEST_BLOB_ID, kind).unwrap_err();

            assert_eq!(
                err.kind() == io::ErrorKind::QuotaExceeded,
                deferred,
                "kind={kind:?}: {err}"
            );
            assert_eq!(transport.calls(), 1, "kind={kind:?}");
            assert_eq!(origin.hits(), origin_hits, "kind={kind:?}");
        }
    }

    #[test]
    fn concurrent_first_reads_share_one_auth_handshake() {
        let gate = AuthGate::new(Duration::from_millis(100));
        let registry = Arc::new(scripted_registry_from(
            &format!(
                "addr: http://{}\nrepository: library/ubuntu\nauth: YWxpY2U6c2VjcmV0\n",
                dead_addr()
            ),
            gate.clone(),
            Duration::ZERO,
        ));

        let readers: Vec<_> = (0..2)
            .map(|_| {
                let registry = registry.clone();
                thread::spawn(move || {
                    let mut dst = [0u8; 2];
                    registry
                        .read_range_into(&TEST_BLOB_ID, 0, &mut dst, ReadKind::OnDemand)
                        .unwrap();
                    dst
                })
            })
            .collect();
        for reader in readers {
            assert_eq!(&reader.join().unwrap(), b"ok");
        }

        assert_eq!(gate.challenges(), 1);
        assert!(registry.first_read_done.load(Ordering::Acquire));
    }

    #[test]
    fn fallback_origin_failure_surfaces_as_an_io_error() {
        let transport = ScriptedTransport::new(vec![status(StatusCode::TOO_MANY_REQUESTS)]);
        let registry = scripted_registry_at(dead_addr(), transport.clone(), Duration::ZERO, 0);

        let errors_before = metrics::READ_BACKEND_FAILURE_COUNT
            .with_label_values(&["ondemand", "registry", "dragonfly-http"])
            .get();
        let mut dst = vec![0u8; 4];
        let err = read(&registry, ReadKind::OnDemand, &mut dst).unwrap_err();

        assert!(matches!(err, RegistryError::Io(_)), "unexpected: {err:?}");
        assert_eq!(transport.calls(), 1);
        assert!(
            metrics::READ_BACKEND_FAILURE_COUNT
                .with_label_values(&["ondemand", "registry", "dragonfly-http"])
                .get()
                > errors_before
        );
    }

    #[test]
    fn fallback_gives_the_origin_its_http_retry_budget() {
        let origin = OriginStub::serve_with_status("500 Internal Server Error", b"boom".to_vec());
        let transport = ScriptedTransport::new(vec![status(StatusCode::TOO_MANY_REQUESTS)]);
        let registry = scripted_registry_at(origin.addr, transport.clone(), Duration::ZERO, 1);

        let mut dst = vec![0u8; 4];
        let err = read(&registry, ReadKind::OnDemand, &mut dst).unwrap_err();

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
        let origin = OriginStub::serve_with_status("500 Internal Server Error", b"boom".to_vec());
        let transport = ScriptedTransport::new(vec![status(StatusCode::TOO_MANY_REQUESTS)]);
        let interval = Duration::from_millis(80);
        let start = Instant::now();
        let registry = scripted_registry_at(origin.addr, transport.clone(), interval, 1);

        let mut dst = vec![0u8; 4];
        let err = read(&registry, ReadKind::OnDemand, &mut dst).unwrap_err();

        assert!(
            matches!(
                err,
                RegistryError::UnexpectedStatus(StatusCode::INTERNAL_SERVER_ERROR, _)
            ),
            "unexpected: {err:?}"
        );
        assert_eq!(origin.hits(), 2);
        assert!(start.elapsed() >= interval);
    }

    #[test]
    fn consecutive_fallbacks_are_throttled() {
        let body = b"abcd".to_vec();
        let origin = OriginStub::serve(body.clone());
        let transport = ScriptedTransport::new(vec![
            status(StatusCode::TOO_MANY_REQUESTS),
            status(StatusCode::TOO_MANY_REQUESTS),
        ]);
        let interval = Duration::from_millis(80);
        let start = Instant::now();
        let registry = scripted_registry(&origin, transport.clone(), interval);

        let mut dst = vec![0u8; body.len()];
        for _ in 0..2 {
            read(&registry, ReadKind::OnDemand, &mut dst).unwrap();
            assert_eq!(dst, body);
        }

        assert_eq!(origin.hits(), 2);
        assert!(start.elapsed() >= interval);
    }

    #[test]
    fn cached_redirect_reads_ride_dragonfly() {
        let body = b"redirected".to_vec();
        let origin = OriginStub::serve(b"unused".to_vec());
        let transport = ScriptedTransport::new(vec![Scripted::Body(body.clone())]);
        let registry = scripted_registry(&origin, transport.clone(), Duration::ZERO);
        let hex = hex_string(&TEST_BLOB_ID);
        registry
            .inner
            .redirects
            .insert(&hex, "http://cdn.example.com/signed".to_string());

        let mut dst = vec![0u8; body.len()];
        let protocol = read(&registry, ReadKind::OnDemand, &mut dst).unwrap();

        assert_eq!(protocol, Protocol::DragonflySdk);
        assert_eq!(dst, body);
        assert_eq!(transport.calls(), 1);
        assert_eq!(origin.hits(), 0);
    }

    #[test]
    fn forbidden_cached_redirect_is_evicted_and_re_resolved() {
        let body = b"fresh".to_vec();
        let origin = OriginStub::serve(b"unused".to_vec());
        let transport = ScriptedTransport::new(vec![
            status(StatusCode::FORBIDDEN),
            Scripted::Body(body.clone()),
        ]);
        let registry = scripted_registry(&origin, transport.clone(), Duration::ZERO);
        let hex = hex_string(&TEST_BLOB_ID);
        registry
            .inner
            .redirects
            .insert(&hex, "http://cdn.example.com/expired".to_string());

        let mut dst = vec![0u8; body.len()];
        read(&registry, ReadKind::OnDemand, &mut dst).unwrap();

        assert_eq!(dst, body);
        assert_eq!(transport.calls(), 2);
        assert!(registry.inner.redirects.get(&hex).is_none());
    }
}
