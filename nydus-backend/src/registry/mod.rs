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
//!       prefetch retried     prefetch retried once,
//!       once, hours later    hours later
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

use std::future::Future;
use std::io;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use reqwest::header::{HeaderMap, AUTHORIZATION, RANGE, WWW_AUTHENTICATE};
use reqwest::StatusCode;
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

/// The window of the random delay before a prefetch read the transport's
/// own retries did not cure is sent once more. Hours long so a registry or
/// Dragonfly outage or rate limit has time to clear, random so a fleet of
/// instances does not retry in lockstep.
const PREFETCH_RETRY_DELAY: RangeInclusive<Duration> =
    Duration::from_secs(6 * 60 * 60)..=Duration::from_secs(12 * 60 * 60);

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

    /// Sends the `GET` of a background prefetch read, sending it once more
    /// after a random [`PREFETCH_RETRY_DELAY`] when the transport's own
    /// retries did not cure a `429`, `5xx` or `408`; a transport failure
    /// fails the read at once.
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
/// get_blob(range) / prefetch_blob(range)         transport: Dragonfly when
///   │                                            configured, else Http
///   ├─ cached redirect ──▶ GET redirect ───────────────────────────────┐
///   │                       401/403 evicts it and falls through        │
///   └─ blob URL ──▶ execute(GET) ─┬─ 3xx ──▶ GET location, cache it    │
///                                 └─ 2xx ─────────────────────────────┐
///                                                                     ▼
///                                                                  bytes
///
/// stat_blob ──▶ execute(transport.head), following one redirect
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
        let http = Http::new(&config.http, None)?;

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
                addr: config.addr,
                repository: config.repository,
                authorizer: Authorizer::new(config.auth.as_deref())?,
                redirects: RedirectCache::new(),
                http,
                dragonfly,
            }),
            runtime,
        })
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

    /// Returns the URL of the blob with hex digest `hex`, the distribution
    /// API path appended to the registry address, a path of its own kept as
    /// the prefix.
    fn blob_url(&self, hex: &str) -> String {
        format!(
            "{}/v2/{}/blobs/sha256:{hex}",
            self.addr.as_str().trim_end_matches('/'),
            self.repository
        )
    }

    /// Returns the transport a blob `GET` rides: Dragonfly when it is
    /// configured, otherwise the origin.
    fn transport(&self) -> &dyn Transport {
        match &self.dragonfly {
            Some(dragonfly) => dragonfly.as_ref(),
            None => &self.http,
        }
    }

    /// Executes `request` with `headers` carrying the cached Authorization,
    /// answering a `401` with the auth handshake and executing it again.
    ///
    /// ```text
    /// request with cached Authorization ──▶ not 401 ──▶ answer
    ///   │ 401
    ///   ▼
    /// request again without Authorization when one was sent, for a fresh challenge
    ///   │
    ///   ▼
    /// WWW-Authenticate ──▶ Authorizer::authenticate ──▶ request again authorized
    /// ```
    async fn execute<F, Fut>(&self, mut headers: HeaderMap, request: F) -> io::Result<Response>
    where
        F: Fn(HeaderMap) -> Fut,
        Fut: Future<Output = io::Result<Response>>,
    {
        // Request with the cached Authorization, when one is still valid.
        self.authorizer.authorize(&mut headers);
        let response = request(headers.clone()).await?;
        if response.status != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }

        // Forget the refused Authorization and request again without it to
        // get a fresh challenge.
        let challenge_response = match headers.remove(AUTHORIZATION) {
            Some(stale) => {
                self.authorizer.invalidate(&stale);
                request(headers.clone()).await?
            }
            None => response,
        };

        // Answer the challenge and request again authorized.
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
        request(headers).await
    }

    /// Fetches `length` blob bytes from `offset` for an on-demand read and
    /// returns the successful response, its body still to be read.
    ///
    /// The read goes through the cached redirect when there is one, a `401`
    /// or `403` evicting it, and otherwise through the blob URL, caching the
    /// redirect it answers with.
    async fn get_blob(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        length: usize,
    ) -> io::Result<Response> {
        let hex = hex::encode(blob_id);
        let end = offset + length as u64 - 1;
        let mut headers = HeaderMap::new();
        headers.insert(RANGE, format!("bytes={offset}-{end}").parse().unwrap());
        let transport = self.transport();

        // Read through the cached redirect, a refusal evicting it.
        if let Some(redirect) = self.redirects.get(&hex) {
            let response = transport.get(&redirect, headers.clone()).await?;
            match response.status {
                status if status.is_success() => return Ok(response),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => self.redirects.remove(&hex),
                _ => return Err(response.into_io_error().await),
            }
        }

        // Read through the blob URL, following and caching its redirect.
        let url = self.blob_url(&hex);
        let response = self
            .execute(headers.clone(), |headers| transport.get(&url, headers))
            .await?;
        if response.status.is_success() {
            return Ok(response);
        }
        if !response.status.is_redirection() {
            return Err(response.into_io_error().await);
        }

        let location = response.location()?;
        let redirected = transport.get(&location, headers).await?;
        if !redirected.status.is_success() {
            return Err(redirected.into_io_error().await);
        }

        self.redirects.insert(&hex, location);
        Ok(redirected)
    }

    /// Fetches `length` blob bytes from `offset` for a prefetch read and
    /// returns the successful response, its body still to be read.
    ///
    /// The read goes through the cached redirect when there is one, a `401`
    /// or `403` evicting it, and otherwise through the blob URL, caching the
    /// redirect it answers with.
    async fn prefetch_blob(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        length: usize,
    ) -> io::Result<Response> {
        let hex = hex::encode(blob_id);
        let end = offset + length as u64 - 1;
        let mut headers = HeaderMap::new();
        headers.insert(RANGE, format!("bytes={offset}-{end}").parse().unwrap());
        let transport = self.transport();

        // Read through the cached redirect, a refusal evicting it.
        if let Some(redirect) = self.redirects.get(&hex) {
            let response = transport.prefetch(&redirect, headers.clone()).await?;
            match response.status {
                status if status.is_success() => return Ok(response),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => self.redirects.remove(&hex),
                _ => return Err(response.into_io_error().await),
            }
        }

        // Read through the blob URL, following and caching its redirect.
        let url = self.blob_url(&hex);
        let response = self
            .execute(headers.clone(), |headers| transport.prefetch(&url, headers))
            .await?;
        if response.status.is_success() {
            return Ok(response);
        }
        if !response.status.is_redirection() {
            return Err(response.into_io_error().await);
        }

        let location = response.location()?;
        let redirected = transport.prefetch(&location, headers).await?;
        if !redirected.status.is_success() {
            return Err(redirected.into_io_error().await);
        }

        self.redirects.insert(&hex, location);
        Ok(redirected)
    }

    /// Returns the size of a blob, from a `HEAD` request following one redirect.
    async fn stat_blob(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<u64> {
        let url = self.blob_url(&hex::encode(blob_id));
        let transport = self.transport();
        let response = self
            .execute(HeaderMap::new(), |headers| transport.head(&url, headers))
            .await?;
        if response.status.is_success() {
            return response.content_length();
        }
        if !response.status.is_redirection() {
            return Err(response.into_io_error().await);
        }

        let redirected = transport
            .head(&response.location()?, HeaderMap::new())
            .await?;
        if !redirected.status.is_success() {
            return Err(redirected.into_io_error().await);
        }

        redirected.content_length()
    }

    /// Recovers a blob's metadata from its trailing footer for an on-demand
    /// read: `HEAD` for the size, read the footer, then read the blob
    /// metadata region it points at.
    async fn get_blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<BlobMetadata> {
        let size = self.stat_blob(blob_id).await?;
        let footer_offset =
            BlobFooter::calculate_offset_by_blob_size(size).map_err(io::Error::other)?;

        let footer_bytes = self
            .get_blob(blob_id, footer_offset, BlobFooter::SIZE)
            .await?
            .bytes(BlobFooter::SIZE)
            .await?;
        let footer =
            BlobFooter::from_bytes(footer_bytes.as_ref().try_into().map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
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
            .get_blob(blob_id, footer.blob_metadata_offset(), blob_metadata_size)
            .await?
            .bytes(blob_metadata_size)
            .await?;

        BlobMetadata::from_bytes(blob_metadata_bytes.into()).map_err(io::Error::other)
    }

    /// Recovers a blob's metadata from its trailing footer for a prefetch
    /// read: `HEAD` for the size, read the footer, then read the blob
    /// metadata region it points at.
    async fn prefetch_blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<BlobMetadata> {
        let size = self.stat_blob(blob_id).await?;
        let footer_offset =
            BlobFooter::calculate_offset_by_blob_size(size).map_err(io::Error::other)?;

        let footer_bytes = self
            .prefetch_blob(blob_id, footer_offset, BlobFooter::SIZE)
            .await?
            .bytes(BlobFooter::SIZE)
            .await?;
        let footer =
            BlobFooter::from_bytes(footer_bytes.as_ref().try_into().map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
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
            .prefetch_blob(blob_id, footer.blob_metadata_offset(), blob_metadata_size)
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

    /// Recovers the blob's metadata from the registry on the on-demand
    /// runtime.
    fn read_blob_metadata(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<BlobMetadata> {
        let client = self.client.clone();
        let blob_id = *blob_id;
        self.runtime
            .block_on_worker(ReadKind::OnDemand, async move {
                client.get_blob_metadata(&blob_id).await
            })
    }

    /// Recovers the blob's metadata from the registry on the prefetch
    /// runtime.
    fn prefetch_blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<BlobMetadata> {
        let client = self.client.clone();
        let blob_id = *blob_id;
        self.runtime
            .block_on_worker(ReadKind::Prefetch, async move {
                client.prefetch_blob_metadata(&blob_id).await
            })
    }

    /// Fills `buf` with the blob bytes from `offset` on the on-demand
    /// runtime, recording the read's metrics.
    fn read_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        buf: &mut [u8],
    ) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        // Read the bytes on a thread of the on-demand runtime.
        let start = Instant::now();
        let client = self.client.clone();
        let blob_id = *blob_id;
        let length = buf.len();
        let result = self
            .runtime
            .block_on_worker(ReadKind::OnDemand, async move {
                let response = client.get_blob(&blob_id, offset, length).await?;
                let protocol = response.protocol;
                Ok((response.bytes(length).await?, protocol))
            });

        // Record the metrics and copy the bytes out.
        match result {
            Ok((bytes, protocol)) => {
                collect_read_backend_finished_metrics(
                    ReadKind::OnDemand,
                    BackendKind::Registry,
                    Some(protocol),
                    length as u64,
                    start.elapsed(),
                );
                buf.copy_from_slice(&bytes);
                Ok(())
            }
            Err(err) => {
                collect_read_backend_failure_metrics(
                    ReadKind::OnDemand,
                    BackendKind::Registry,
                    Some(self.client.protocol()),
                    start.elapsed(),
                );
                Err(err)
            }
        }
    }

    /// Fills `buf` with the blob bytes from `offset` on the prefetch runtime,
    /// recording the read's metrics.
    fn prefetch_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        buf: &mut [u8],
    ) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        // Read the bytes on a thread of the prefetch runtime.
        let start = Instant::now();
        let client = self.client.clone();
        let blob_id = *blob_id;
        let length = buf.len();
        let result = self
            .runtime
            .block_on_worker(ReadKind::Prefetch, async move {
                let response = client.prefetch_blob(&blob_id, offset, length).await?;
                let protocol = response.protocol;
                Ok((response.bytes(length).await?, protocol))
            });

        // Record the metrics and copy the bytes out.
        match result {
            Ok((bytes, protocol)) => {
                collect_read_backend_finished_metrics(
                    ReadKind::Prefetch,
                    BackendKind::Registry,
                    Some(protocol),
                    length as u64,
                    start.elapsed(),
                );
                buf.copy_from_slice(&bytes);
                Ok(())
            }
            Err(err) => {
                collect_read_backend_failure_metrics(
                    ReadKind::Prefetch,
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
                addr: config.addr,
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
            let client = &registry.client;
            let response = match kind {
                ReadKind::OnDemand => client.get_blob(&TEST_BLOB_ID, 0, buf.len()).await?,
                ReadKind::Prefetch => client.prefetch_blob(&TEST_BLOB_ID, 0, buf.len()).await?,
            };
            let protocol = response.protocol;
            buf.copy_from_slice(&response.bytes(buf.len()).await?);
            Ok(protocol)
        })
    }

    #[test]
    fn blob_url_appends_the_api_path_to_the_registry_addr() {
        let test_cases = vec![
            (
                "https://registry.example.com",
                "https://registry.example.com/v2/library/ubuntu/blobs/sha256:abc123",
            ),
            (
                "http://127.0.0.1:5000/",
                "http://127.0.0.1:5000/v2/library/ubuntu/blobs/sha256:abc123",
            ),
            (
                "https://registry.example.com/mirror",
                "https://registry.example.com/mirror/v2/library/ubuntu/blobs/sha256:abc123",
            ),
            (
                "https://registry.example.com/mirror/",
                "https://registry.example.com/mirror/v2/library/ubuntu/blobs/sha256:abc123",
            ),
        ];

        for (addr, expected) in test_cases {
            let config: RegistryConfig =
                serde_yaml::from_str(&format!("addr: {addr}\nrepository: library/ubuntu\n"))
                    .unwrap();
            let registry = Registry::new(config, test_runtime()).unwrap();
            assert_eq!(registry.client.blob_url("abc123"), expected, "addr={addr}");
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
    fn origin_transient_failure_fails_an_ondemand_read_at_once() {
        let origin = OriginStub::serve_with_status("503 Service Unavailable", b"busy".to_vec());
        let config: RegistryConfig = serde_yaml::from_str(&format!(
            "addr: http://{}\nrepository: library/ubuntu\nhttp:\n  max_retries: 0\n",
            origin.addr
        ))
        .unwrap();
        let registry = Registry::new(config, test_runtime()).unwrap();

        let mut buf = vec![0u8; 4];
        let err = read(&registry, ReadKind::OnDemand, &mut buf).unwrap_err();

        assert!(err.to_string().contains("503"), "{err}");
        assert_eq!(origin.hits(), 1);
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
    fn read_blob_metadata_stats_at_the_origin_and_reads_through_the_transport() {
        for kind in [ReadKind::OnDemand, ReadKind::Prefetch] {
            let origin = OriginStub::serve(vec![0u8; 2 * BlobFooter::SIZE]);
            let transport = ScriptedTransport::new(vec![status(StatusCode::NOT_FOUND)]);
            let registry = scripted_registry(&origin, transport.clone());

            let err = match kind {
                ReadKind::OnDemand => registry.read_blob_metadata(&TEST_BLOB_ID),
                ReadKind::Prefetch => registry.prefetch_blob_metadata(&TEST_BLOB_ID),
            }
            .unwrap_err();

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
                        .read_range_into(&TEST_BLOB_ID, 0, &mut buf)
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
