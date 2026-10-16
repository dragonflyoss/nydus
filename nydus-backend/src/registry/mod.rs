//! The OCI registry backend.
//!
//! A blob is addressed by its full-blob digest, the digest the merged
//! bootstrap's device slots carry and the on-disk blob metadata is named by,
//! and served in byte ranges. Blob metadata normally comes from the cache
//! directory, the backend recovering it from the blob's trailing footer only
//! when the cache has none.
//!
//! ```text
//!                      Registry
//!                         │
//!            ┌────────────┴────────────┐
//!       Authorizer               RedirectCache
//!    challenge, token           signed 3xx URLs
//!                         │
//!              ┌──────────┴──────────┐
//!            Http                Dragonfly
//!       direct origin,       seed peers, own retries,
//!       own retries,         on-demand back to source,
//!       prefetch deferred    prefetch deferred
//! ```
//!
//! [`Registry`] owns the registry-specific logic, the transports spend their
//! own retries and fallbacks and hand back a settled [`Response`]. A blob
//! `GET` rides Dragonfly when it is configured; `HEAD` requests and token
//! fetches always go straight to the origin.
//!
//! Every read runs as a task on the runtime of its kind ([`rt`]) and the
//! calling thread waits on its join handle, so the body flows from hyper or
//! tonic to the read inside the worker pool, the connection is opened in the
//! runtime's network namespace, and the caller is woken once, when the bytes
//! are ready to copy out.

mod auth;
#[cfg(feature = "dragonfly")]
mod dragonfly;
mod http;
mod netns;
mod redirect;
mod response;
mod rt;

use std::io;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, RANGE, WWW_AUTHENTICATE};
use reqwest::{Method, StatusCode};
use url::Url;

use nydus_config::RegistryConfig;
use nydus_format::blob::{BlobFooter, BlobMetadata};
use nydus_format::utils::SHA256_DIGEST_SIZE;
use nydus_telemetry::metrics::{
    collect_read_backend_failure_metrics, collect_read_backend_finished_metrics,
};

use crate::{Backend, BackendKind, Protocol, ReadKind};

use self::auth::{Authorizer, Challenge};
#[cfg(feature = "dragonfly")]
use self::dragonfly::Dragonfly;
use self::http::Http;
pub use self::netns::{Netns, NetnsId};
use self::redirect::RedirectCache;
use self::response::Response;
pub use self::rt::Runtime;

/// The transport a blob `GET` rides on: the origin registry over HTTP, or the
/// Dragonfly seed peers.
///
/// One call spends the transport's own retries and hands back a settled
/// answer, a Dragonfly body already buffered so a mid-stream failure surfaces
/// here rather than while the caller consumes it.
#[async_trait]
trait Transport: Send + Sync {
    /// Sends a `HEAD`.
    async fn head(&self, url: &str, headers: HeaderMap) -> io::Result<Response>;

    /// Sends the `GET` of an on-demand read, which a FUSE reader waits on.
    async fn get(&self, url: &str, headers: HeaderMap) -> io::Result<Response>;

    /// Sends the `GET` of a background prefetch read, deferring a transient
    /// failure the transport's retries did not cure as an
    /// [`io::ErrorKind::QuotaExceeded`] for the storage layer to reschedule.
    async fn prefetch(&self, url: &str, headers: HeaderMap) -> io::Result<Response>;
}

/// A blob backend over an OCI registry: the synchronous [`Backend`] face
/// of a [`Client`], which does the asynchronous work on the runtime.
///
/// ```text
/// read_range_into(buf)                      runtime worker
///   │ spawn(get_blob, read its bytes) ──▶ get_blob ◀── body chunks ── hyper / tonic
///   │ block_on(join handle)                     │
///   ◀──────────── one wake ────────────────────┘
///   └─ copy into buf, note who served it
/// ```
pub(crate) struct Registry {
    /// The registry client, shared with the task of each read.
    client: Arc<Client>,

    /// The runtimes every read runs on, one per read kind.
    runtime: Arc<Runtime>,
}

/// The client of one repository on one registry, behind an [`Arc`] so a read
/// can run on the runtime while its caller waits.
///
/// ```text
/// get_blob(range, kind)
///   │
///   ├─ cached redirect ──▶ send(GET redirect) ──────────────────────┐
///   │                       401/403 evicts it and falls through      │
///   └─ blob URL ──▶ authorized_request(GET) ─┬─ 3xx ──▶ send(GET location), cache it
///                                            └─ 2xx ──────────────────┐
///                                                                     ▼
///                                                                  bytes
///
/// send(method, url)
///   ├─ HEAD ──▶ transport.head
///   ├─ on-demand GET ──▶ transport.get
///   └─ prefetch GET ──▶ transport.prefetch     transport: Dragonfly when configured, else Http
/// ```
struct Client {
    /// The registry origin, `scheme://host[:port]/`.
    addr: Url,

    /// The image repository, such as `library/ubuntu`.
    repository: String,

    /// The credentials and the `Authorization` the last challenge produced.
    authorizer: Authorizer,

    /// The signed URLs blob `GET`s were redirected to, by blob hex digest.
    redirects: RedirectCache,

    /// The direct client to the origin.
    http: Http,

    /// The Dragonfly transport when configured, always `None` without the
    /// `dragonfly` feature since the config is rejected.
    dragonfly: Option<Box<dyn Transport>>,
}

/// Implements the registry backend construction.
impl Registry {
    /// Creates a registry backend from its configuration, running on `runtime`.
    pub(crate) fn new(config: RegistryConfig, runtime: Arc<Runtime>) -> io::Result<Self> {
        let addr = Self::parse_addr(&config.addr)?;
        let http = Http::new(&config.http, None)?;

        // Reject a Dragonfly configuration this build cannot honour.
        #[cfg(not(feature = "dragonfly"))]
        if let Some(dragonfly) = &config.dragonfly {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "dragonfly.scheduler_endpoint is set ({}) but this build lacks \
                     the `dragonfly` feature",
                    dragonfly.scheduler_endpoint
                ),
            ));
        }

        // Connect the Dragonfly transport when configured.
        #[cfg(feature = "dragonfly")]
        let dragonfly: Option<Box<dyn Transport>> = match config.dragonfly {
            Some(dragonfly) => Some(Box::new(Dragonfly::new(
                dragonfly,
                &config.http,
                http.clone(),
                &runtime,
            )?)),
            None => None,
        };
        #[cfg(not(feature = "dragonfly"))]
        let dragonfly: Option<Box<dyn Transport>> = None;

        Ok(Self {
            client: Arc::new(Client {
                addr,
                repository: config.repository,
                authorizer: Authorizer::new(config.auth.as_deref())?,
                redirects: RedirectCache::new(),
                http,
                dragonfly,
            }),
            runtime,
        })
    }

    /// Parses a registry `addr` such as `http://127.0.0.1:5000` into its
    /// origin, rejecting a scheme other than `http` or `https` and any path,
    /// query or fragment.
    fn parse_addr(addr: &str) -> io::Result<Url> {
        let invalid = |reason: &str| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid registry addr {addr}: {reason}"),
            )
        };
        let url = Url::parse(addr).map_err(|err| invalid(&err.to_string()))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(invalid(&format!("unsupported scheme `{}`", url.scheme())));
        }
        if url.host_str().is_none() {
            return Err(invalid("missing host"));
        }
        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            return Err(invalid("must not carry a path, query, or fragment"));
        }

        Ok(url)
    }
}

/// Implements the registry requests.
impl Client {
    /// Returns how reads are fetched when nothing else is known, the
    /// `protocol` label of a failed read: Dragonfly when configured,
    /// otherwise HTTP.
    fn protocol(&self) -> Protocol {
        if self.dragonfly.is_some() {
            Protocol::Dragonfly
        } else {
            Protocol::Http
        }
    }

    /// Returns the URL of the blob with hex digest `hex`.
    fn blob_url(&self, hex: &str) -> String {
        format!("{}v2/{}/blobs/sha256:{hex}", self.addr, self.repository)
    }

    /// Sends `method` for `url` through Dragonfly when it is configured,
    /// otherwise straight to the origin, a `GET` as the read of `kind`.
    async fn send(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        kind: ReadKind,
    ) -> io::Result<Response> {
        let transport: &dyn Transport = match &self.dragonfly {
            Some(dragonfly) => dragonfly.as_ref(),
            None => &self.http,
        };
        match (method, kind) {
            (Method::HEAD, _) => transport.head(url, headers).await,
            (_, ReadKind::OnDemand) => transport.get(url, headers).await,
            (_, ReadKind::Prefetch) => transport.prefetch(url, headers).await,
        }
    }

    /// Sends a request, answering a `401` with the auth handshake.
    ///
    /// ```text
    /// send with cached Authorization ──▶ not 401 ──▶ answer
    ///   │ 401
    ///   ▼
    /// resend without Authorization when one was sent, to get a fresh challenge
    ///   │
    ///   ▼
    /// WWW-Authenticate ──▶ Authorizer::authenticate ──▶ resend authorized
    /// ```
    async fn authorized_request(
        &self,
        method: Method,
        url: &str,
        mut headers: HeaderMap,
        kind: ReadKind,
    ) -> io::Result<Response> {
        // Send with the cached Authorization, when one is still valid.
        self.authorizer.authorize(&mut headers);
        let response = self
            .send(method.clone(), url, headers.clone(), kind)
            .await?;
        if response.status != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }

        // Forget the refused Authorization and resend without it to get a
        // fresh challenge.
        let challenge_response = match headers.remove(AUTHORIZATION) {
            Some(stale) => {
                self.authorizer.invalidate(&stale);
                self.send(method.clone(), url, headers.clone(), kind)
                    .await?
            }
            None => response,
        };

        // Answer the challenge and resend authorized.
        let challenge = challenge_response
            .headers
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<Challenge>().ok());
        let Some(challenge) = challenge else {
            return Ok(challenge_response);
        };

        self.authorizer.authenticate(&self.http, challenge).await?;
        self.authorizer.authorize(&mut headers);
        self.send(method, url, headers, kind).await
    }

    /// Sends the `GET` for `len` blob bytes from `offset` and returns the
    /// successful response, its body still to be read.
    ///
    /// The read goes through the cached redirect when there is one and
    /// otherwise through the blob URL, caching the redirect it answers with.
    async fn get_blob(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        len: usize,
        kind: ReadKind,
    ) -> io::Result<Response> {
        let hex = hex::encode(blob_id);
        let end = offset + len as u64 - 1;
        let range: HeaderValue = format!("bytes={offset}-{end}").parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(RANGE, range);

        match self.get_through_redirect(&hex, &headers, kind).await? {
            Some(response) => Ok(response),
            None => self.get_through_blob_url(&hex, headers, kind).await,
        }
    }

    /// Sends the blob `GET` through the redirect cached for `hex`, `None`
    /// when none is cached or the link answered `401` or `403`, which evicts
    /// it so the read falls through to the blob URL.
    async fn get_through_redirect(
        &self,
        hex: &str,
        headers: &HeaderMap,
        kind: ReadKind,
    ) -> io::Result<Option<Response>> {
        let Some(redirect) = self.redirects.get(hex) else {
            return Ok(None);
        };

        let response = self
            .send(Method::GET, &redirect, headers.clone(), kind)
            .await?;
        match response.status {
            status if status.is_success() => Ok(Some(response)),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                self.redirects.remove(hex);
                Ok(None)
            }
            _ => Err(response.into_io_error().await),
        }
    }

    /// Sends the blob `GET` through the blob URL of `hex`, following the
    /// redirect it answers with and caching it for the reads that follow.
    async fn get_through_blob_url(
        &self,
        hex: &str,
        headers: HeaderMap,
        kind: ReadKind,
    ) -> io::Result<Response> {
        let url = self.blob_url(hex);
        let response = self
            .authorized_request(Method::GET, &url, headers.clone(), kind)
            .await?;
        if response.status.is_success() {
            return Ok(response);
        }
        if !response.status.is_redirection() {
            return Err(response.into_io_error().await);
        }

        let location = response.location()?;
        let redirected = self.send(Method::GET, &location, headers, kind).await?;
        if !redirected.status.is_success() {
            return Err(redirected.into_io_error().await);
        }

        self.redirects.insert(hex, location);
        Ok(redirected)
    }

    /// Returns the size of a blob, from a `HEAD` request following one redirect.
    async fn stat_blob(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        kind: ReadKind,
    ) -> io::Result<u64> {
        let url = self.blob_url(&hex::encode(blob_id));
        let response = self
            .authorized_request(Method::HEAD, &url, HeaderMap::new(), kind)
            .await?;
        if response.status.is_success() {
            return response.content_length();
        }
        if !response.status.is_redirection() {
            return Err(response.into_io_error().await);
        }

        let redirected = self
            .send(Method::HEAD, &response.location()?, HeaderMap::new(), kind)
            .await?;
        if !redirected.status.is_success() {
            return Err(redirected.into_io_error().await);
        }

        redirected.content_length()
    }

    /// Recovers a blob's metadata from its trailing footer: `HEAD` for the
    /// size, read the footer, then read the blob metadata region it points at.
    async fn get_blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        kind: ReadKind,
    ) -> io::Result<BlobMetadata> {
        let size = self.stat_blob(blob_id, kind).await?;
        let footer_offset =
            BlobFooter::calculate_offset_by_blob_size(size).map_err(io::Error::other)?;

        let footer_bytes = self
            .get_blob(blob_id, footer_offset, BlobFooter::SIZE, kind)
            .await?
            .bytes(BlobFooter::SIZE)
            .await?;
        let footer_bytes = footer_bytes.as_ref().try_into().map_err(io::Error::other)?;
        let footer = BlobFooter::from_bytes(footer_bytes).map_err(io::Error::other)?;
        footer
            .validate_layout(footer_offset)
            .map_err(io::Error::other)?;
        if footer.is_raw_device() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native EROFS layers are not served from a registry; mount them through the kernel",
            ));
        }

        let blob_metadata_size = usize::try_from(footer.blob_metadata_size()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "blob meta size exceeds usize")
        })?;
        let blob_metadata_bytes = self
            .get_blob(
                blob_id,
                footer.blob_metadata_offset(),
                blob_metadata_size,
                kind,
            )
            .await?
            .bytes(blob_metadata_size)
            .await?;

        BlobMetadata::from_bytes(blob_metadata_bytes.into()).map_err(io::Error::other)
    }
}

/// Implements the blob backend over the registry.
impl Backend for Registry {
    /// Returns [`BackendKind::Registry`].
    fn kind(&self) -> BackendKind {
        BackendKind::Registry
    }

    /// Returns the configured transport: Dragonfly when configured, otherwise
    /// HTTP.
    fn protocol(&self) -> Option<Protocol> {
        Some(self.client.protocol())
    }

    /// Recovers the blob's metadata from the registry on the runtime.
    fn blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        kind: ReadKind,
    ) -> io::Result<BlobMetadata> {
        let client = self.client.clone();
        let blob_id = *blob_id;
        self.runtime.block_on_worker(kind, async move {
            client.get_blob_metadata(&blob_id, kind).await
        })
    }

    /// Fills `buf` with the blob bytes from `offset` on the runtime, recording
    /// the read's metrics.
    fn read_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        buf: &mut [u8],
        kind: ReadKind,
    ) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        // Read the bytes on a thread of the kind's runtime.
        let start = Instant::now();
        let client = self.client.clone();
        let blob_id = *blob_id;
        let len = buf.len();
        let result = self.runtime.block_on_worker(kind, async move {
            let response = client.get_blob(&blob_id, offset, len, kind).await?;
            let protocol = response.protocol;
            Ok((response.bytes(len).await?, protocol))
        });

        // Record the metrics and copy the bytes out.
        match result {
            Ok((bytes, protocol)) => {
                collect_read_backend_finished_metrics(
                    kind,
                    BackendKind::Registry,
                    Some(protocol),
                    len as u64,
                    start.elapsed(),
                );
                buf.copy_from_slice(&bytes);
                Ok(())
            }
            Err(err) => {
                collect_read_backend_failure_metrics(
                    kind,
                    BackendKind::Registry,
                    Some(self.client.protocol()),
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
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;

    use bytes::Bytes;

    use nydus_config::HttpConfig;

    use super::response::Body;

    const TEST_BLOB_ID: [u8; SHA256_DIGEST_SIZE] = [7u8; SHA256_DIGEST_SIZE];

    fn test_runtime() -> Arc<Runtime> {
        let http = HttpConfig::default();
        Arc::new(Runtime::new(http.worker_threads, http.max_blocking_threads, None).unwrap())
    }

    #[async_trait]
    impl<T: Transport> Transport for Arc<T> {
        async fn head(&self, url: &str, headers: HeaderMap) -> io::Result<Response> {
            (**self).head(url, headers).await
        }

        async fn get(&self, url: &str, headers: HeaderMap) -> io::Result<Response> {
            (**self).get(url, headers).await
        }

        async fn prefetch(&self, url: &str, headers: HeaderMap) -> io::Result<Response> {
            (**self).prefetch(url, headers).await
        }
    }

    enum Scripted {
        Body(Vec<u8>),
        Status(StatusCode, HeaderMap),
    }

    fn status(status: StatusCode) -> Scripted {
        Scripted::Status(status, HeaderMap::new())
    }

    struct ScriptedTransport {
        script: Mutex<VecDeque<Scripted>>,
        calls: AtomicU32,
        http: Http,
    }

    impl ScriptedTransport {
        fn new(script: impl IntoIterator<Item = Scripted>) -> Arc<ScriptedTransport> {
            Arc::new(ScriptedTransport {
                script: Mutex::new(script.into_iter().collect()),
                calls: AtomicU32::new(0),
                http: Http::new(&HttpConfig::default(), None).unwrap(),
            })
        }

        fn calls(&self) -> u32 {
            self.calls.load(Ordering::SeqCst)
        }

        fn play(&self) -> io::Result<Response> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let scripted = self
                .script
                .lock()
                .unwrap()
                .pop_front()
                .expect("transport called more times than scripted");
            match scripted {
                Scripted::Body(body) => Ok(Response {
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                    body: Body::Bytes(body.into()),
                    protocol: Protocol::Dragonfly,
                }),
                Scripted::Status(status, headers) => Ok(Response {
                    status,
                    headers,
                    body: Body::Bytes(Bytes::new()),
                    protocol: Protocol::Dragonfly,
                }),
            }
        }
    }

    #[async_trait]
    impl Transport for ScriptedTransport {
        async fn head(&self, url: &str, headers: HeaderMap) -> io::Result<Response> {
            self.http.head(url, headers).await
        }

        async fn get(&self, _url: &str, _headers: HeaderMap) -> io::Result<Response> {
            self.play()
        }

        async fn prefetch(&self, _url: &str, _headers: HeaderMap) -> io::Result<Response> {
            self.play()
        }
    }

    struct AuthGate {
        delay: Duration,
        first: AtomicBool,
        challenges: AtomicU32,
        http: Http,
    }

    impl AuthGate {
        fn new(delay: Duration) -> Arc<AuthGate> {
            Arc::new(AuthGate {
                delay,
                first: AtomicBool::new(true),
                challenges: AtomicU32::new(0),
                http: Http::new(&HttpConfig::default(), None).unwrap(),
            })
        }

        fn challenges(&self) -> u32 {
            self.challenges.load(Ordering::SeqCst)
        }

        async fn answer(&self, headers: HeaderMap) -> io::Result<Response> {
            if self.first.swap(false, Ordering::SeqCst) {
                tokio::time::sleep(self.delay).await;
            }
            if headers.contains_key(AUTHORIZATION) {
                return Ok(Response {
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                    body: Body::Bytes(Bytes::from_static(b"ok")),
                    protocol: Protocol::Dragonfly,
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
                body: Body::Bytes(Bytes::new()),
                protocol: Protocol::Dragonfly,
            })
        }
    }

    #[async_trait]
    impl Transport for AuthGate {
        async fn head(&self, url: &str, headers: HeaderMap) -> io::Result<Response> {
            self.http.head(url, headers).await
        }

        async fn get(&self, _url: &str, headers: HeaderMap) -> io::Result<Response> {
            self.answer(headers).await
        }

        async fn prefetch(&self, _url: &str, headers: HeaderMap) -> io::Result<Response> {
            self.answer(headers).await
        }
    }

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

    fn dead_addr() -> SocketAddr {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    fn scripted_registry_from(yaml: &str, transport: impl Transport + 'static) -> Registry {
        let config: RegistryConfig = serde_yaml::from_str(yaml).unwrap();
        Registry {
            client: Arc::new(Client {
                addr: Registry::parse_addr(&config.addr).unwrap(),
                repository: config.repository,
                authorizer: Authorizer::new(config.auth.as_deref()).unwrap(),
                redirects: RedirectCache::new(),
                http: Http::new(&config.http, None).unwrap(),
                dragonfly: Some(Box::new(transport)),
            }),
            runtime: test_runtime(),
        }
    }

    fn scripted_registry(origin: &OriginStub, transport: impl Transport + 'static) -> Registry {
        scripted_registry_from(
            &format!("addr: http://{}\nrepository: library/ubuntu\n", origin.addr),
            transport,
        )
    }

    fn read(registry: &Registry, kind: ReadKind, buf: &mut [u8]) -> io::Result<Protocol> {
        registry.runtime.tokio(kind).block_on(async {
            let response = registry
                .client
                .get_blob(&TEST_BLOB_ID, 0, buf.len(), kind)
                .await?;
            let protocol = response.protocol;
            buf.copy_from_slice(&response.bytes(buf.len()).await?);
            Ok(protocol)
        })
    }

    #[test]
    fn blob_url_names_the_blob_under_the_repository() {
        let config: RegistryConfig = serde_yaml::from_str(
            "addr: https://registry.example.com\nrepository: library/ubuntu\n",
        )
        .unwrap();
        let registry = Registry::new(config, test_runtime()).unwrap();
        assert_eq!(
            registry.client.blob_url("abc123"),
            "https://registry.example.com/v2/library/ubuntu/blobs/sha256:abc123"
        );
    }

    #[test]
    fn parse_addr_accepts_a_bare_http_origin() {
        let test_cases = vec![
            ("http://127.0.0.1:5000", Some("http://127.0.0.1:5000/")),
            (
                "https://registry-1.docker.io",
                Some("https://registry-1.docker.io/"),
            ),
            (
                "https://registry.example.com/",
                Some("https://registry.example.com/"),
            ),
            ("registry.example.com", None),
            ("ftp://registry.example.com", None),
            ("https://registry.example.com/v2", None),
            ("https://registry.example.com/?x=1", None),
        ];

        for (addr, expected) in test_cases {
            assert_eq!(
                Registry::parse_addr(addr).ok().as_ref().map(Url::as_str),
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
        let registry = Registry::new(config, test_runtime()).unwrap();
        assert_eq!(
            registry.client.addr.as_str(),
            "https://registry.example.com/"
        );
        assert!(registry.client.dragonfly.is_none());
        assert_eq!(registry.client.protocol(), Protocol::Http);
    }

    #[cfg(not(feature = "dragonfly"))]
    #[test]
    fn new_rejects_dragonfly_endpoint_without_the_feature() {
        let yaml = "
addr: https://registry.example.com
repository: library/ubuntu
dragonfly:
  scheduler_endpoint: http://127.0.0.1:65000
";
        let config: RegistryConfig = serde_yaml::from_str(yaml).unwrap();
        let err = Registry::new(config, test_runtime()).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("dragonfly"));
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
                let registry = scripted_registry(&origin, transport.clone());

                let mut buf = vec![0u8; 4];
                let err = read(&registry, kind, &mut buf).unwrap_err();

                assert!(
                    err.to_string().contains(terminal.as_str()),
                    "kind={kind:?} status={terminal}: {err}"
                );
                assert_eq!(transport.calls(), 1, "kind={kind:?} status={terminal}");
                assert_eq!(origin.hits(), 0, "kind={kind:?} status={terminal}");
            }
        }
    }

    #[test]
    fn origin_transient_failures_defer_prefetch_and_fail_ondemand() {
        let test_cases = vec![
            (ReadKind::Prefetch, io::ErrorKind::QuotaExceeded),
            (ReadKind::OnDemand, io::ErrorKind::Other),
        ];

        for (kind, expected) in test_cases {
            let origin = OriginStub::serve_with_status("503 Service Unavailable", b"busy".to_vec());
            let config: RegistryConfig = serde_yaml::from_str(&format!(
                "addr: http://{}\nrepository: library/ubuntu\nhttp:\n  max_retries: 0\n",
                origin.addr
            ))
            .unwrap();
            let registry = Registry::new(config, test_runtime()).unwrap();

            let mut buf = vec![0u8; 4];
            let err = read(&registry, kind, &mut buf).unwrap_err();

            assert_eq!(err.kind(), expected, "kind={kind:?}: {err}");
            assert!(err.to_string().contains("503"), "kind={kind:?}: {err}");
            assert_eq!(origin.hits(), 1, "kind={kind:?}");
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
            );

            let mut buf = vec![0u8; body.len()];
            read(&registry, kind, &mut buf).unwrap();

            assert_eq!(buf, body, "kind={kind:?}");
            assert_eq!(transport.calls(), 2, "kind={kind:?}");
            assert_eq!(origin.hits(), 0, "kind={kind:?}");
            let mut authorized = HeaderMap::new();
            registry.client.authorizer.authorize(&mut authorized);
            assert_eq!(authorized[AUTHORIZATION], "Basic YWxpY2U6c2VjcmV0");
        }
    }

    #[test]
    fn blob_metadata_stats_at_the_origin_and_reads_through_the_transport() {
        for kind in [ReadKind::OnDemand, ReadKind::Prefetch] {
            let origin = OriginStub::serve(vec![0u8; 2 * BlobFooter::SIZE]);
            let transport = ScriptedTransport::new(vec![status(StatusCode::NOT_FOUND)]);
            let registry = scripted_registry(&origin, transport.clone());

            let err = registry.blob_metadata(&TEST_BLOB_ID, kind).unwrap_err();

            assert!(err.to_string().contains("404"), "kind={kind:?}: {err}");
            assert_eq!(origin.hits(), 1, "kind={kind:?}");
            assert_eq!(transport.calls(), 1, "kind={kind:?}");
        }
    }

    #[test]
    fn concurrent_reads_each_complete_the_auth_handshake() {
        let gate = AuthGate::new(Duration::from_millis(100));
        let registry = Arc::new(scripted_registry_from(
            &format!(
                "addr: http://{}\nrepository: library/ubuntu\nauth: YWxpY2U6c2VjcmV0\n",
                dead_addr()
            ),
            gate.clone(),
        ));

        let readers: Vec<_> = (0..2)
            .map(|_| {
                let registry = registry.clone();
                thread::spawn(move || {
                    let mut buf = [0u8; 2];
                    registry
                        .read_range_into(&TEST_BLOB_ID, 0, &mut buf, ReadKind::OnDemand)
                        .unwrap();
                    buf
                })
            })
            .collect();
        for reader in readers {
            assert_eq!(&reader.join().unwrap(), b"ok");
        }

        assert_eq!(gate.challenges(), 2);
    }

    #[test]
    fn cached_redirect_reads_ride_dragonfly() {
        let body = b"redirected".to_vec();
        let origin = OriginStub::serve(b"unused".to_vec());
        let transport = ScriptedTransport::new(vec![Scripted::Body(body.clone())]);
        let registry = scripted_registry(&origin, transport.clone());
        let hex = hex::encode(TEST_BLOB_ID);
        registry
            .client
            .redirects
            .insert(&hex, "http://cdn.example.com/signed".to_string());

        let mut buf = vec![0u8; body.len()];
        let protocol = read(&registry, ReadKind::OnDemand, &mut buf).unwrap();

        assert_eq!(protocol, Protocol::Dragonfly);
        assert_eq!(buf, body);
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
        let registry = scripted_registry(&origin, transport.clone());
        let hex = hex::encode(TEST_BLOB_ID);
        registry
            .client
            .redirects
            .insert(&hex, "http://cdn.example.com/expired".to_string());

        let mut buf = vec![0u8; body.len()];
        read(&registry, ReadKind::OnDemand, &mut buf).unwrap();

        assert_eq!(buf, body);
        assert_eq!(transport.calls(), 2);
        assert!(registry.client.redirects.get(&hex).is_none());
    }
}
