//! The OCI registry backend: blobs addressed by their full blob digest and
//! served in byte ranges, over the origin or the Dragonfly seed peers.

mod auth;
#[cfg(feature = "dragonfly")]
mod dragonfly;
mod http;
mod range;
mod redirect;
mod response;
mod rt;

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, AUTHORIZATION, RANGE, WWW_AUTHENTICATE};
use reqwest::StatusCode;
use url::Url;

use nydus_config::{PrefetchConfig, RegistryConfig};
use nydus_format::blob::{BlobFooter, BlobMetadata};
use nydus_format::utils::SHA256_DIGEST_SIZE;
use nydus_telemetry::metrics::Metrics;

use crate::{Backend, Netns, ReadKind, Source};

use self::auth::{Authorizer, Challenge};
#[cfg(feature = "dragonfly")]
use self::dragonfly::Dragonfly;
use self::http::Http;
use self::range::GetRange;
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
    /// Sends the `GET` of an on-demand read, which a FUSE reader waits on.
    async fn get(&self, url: &str, headers: HeaderMap) -> io::Result<Response>;

    /// Sends the `GET` of a background prefetch read, once more after the
    /// configured prefetch retry interval when it answered `429`, `5xx` or
    /// `408`; a transport failure fails the read at once.
    async fn prefetch(&self, url: &str, headers: HeaderMap) -> io::Result<Response>;

    /// Waits until the transport is ready to send, returning the error that
    /// failed it.
    async fn ready(&self) -> io::Result<()> {
        Ok(())
    }
}

/// A blob backend over an OCI registry: the synchronous [`Backend`] face of
/// a [`Client`], which does the asynchronous work on the runtime.
///
/// Every read runs as a task on the runtime and the calling thread waits on
/// its join handle, so the body flows into the read inside the worker pool,
/// the connection is opened in the runtime's network namespace, and the
/// caller is woken once, when the bytes are ready to copy out.
///
/// ```text
/// Registry
///   ├─ Runtime            the tokio runtime of every read
///   ├─ Metrics            the metrics of the image, every read recorded
///   └─ Client
///        ├─ Authorizer    the challenge and the token that answers it
///        ├─ RedirectCache the signed URLs blob GETs were redirected to
///        ├─ Http          the origin: token fetches, and blob GETs without Dragonfly
///        └─ Dragonfly     the seed peers for blob GETs when configured, with a
///                         rate-limited Http of its own back to the origin
/// ```
pub(crate) struct Registry {
    /// The registry client, shared with the task of each read.
    client: Arc<Client>,

    /// The runtime every read runs on.
    runtime: Arc<Runtime>,

    /// The metrics of the image the backend serves.
    metrics: Arc<Metrics>,
}

/// The client of one repository on one registry, behind an [`Arc`] so a read
/// can run on the runtime while its caller waits.
///
/// The life of a blob's reads against a registry with bearer auth that
/// redirects blob `GET`s to a CDN, every `GET` riding Dragonfly when it is
/// configured and the origin otherwise, the token fetch the origin always:
///
/// ```text
/// the first read, read_range(blob_id, range)
///   1. redirect cache ───────────────────────────────────────────▶ miss
///   2. GET blob URL, no token kept ────────────────────────────────▶ 401 WWW-Authenticate
///   3. fetch a token from the challenge's realm, keep it until it expires
///   4. GET blob URL again, with the token ─────────────────────────▶ 307 Location
///   5. GET the location, the signed CDN URL ───────────────────────▶ 206 bytes
///   6. cache the location for the blob, 10 minutes
///
/// the reads that follow
///   1. redirect cache ──▶ hit ──▶ GET the cached location ─────────▶ 206 bytes
///                                  └─ 401 / 403, the link expired ──▶ evicted, step 4
///
/// a read once the token expired, or the registry refuses it
///   4. GET blob URL ──▶ 401 ──▶ the token is forgotten ────────────▶ step 2
///
/// any other status ends the read as an error, a 2xx at any GET as the bytes
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
    /// Creates a registry backend from its configuration, recording into
    /// `metrics` and running on a runtime of its own, every thread of it
    /// entering `netns` when one is given, its prefetch reads retried after
    /// the interval the `prefetch` section sets.
    ///
    /// Every origin request goes through the `http` section: the blob
    /// `GET`s and auth token fetches of a plain registry, and the auth token
    /// fetches and rate-limited fallback reads of a Dragonfly one.
    pub(crate) fn new(
        config: RegistryConfig,
        prefetch: &PrefetchConfig,
        netns: Option<Netns>,
        metrics: Arc<Metrics>,
    ) -> io::Result<Self> {
        let runtime = Arc::new(Runtime::new(netns)?);
        let http = Http::new(
            config.http.request_timeout,
            config.http.max_retries,
            config.http.proxy.as_ref(),
            &config.http.tls,
            prefetch.retry_interval,
            None,
            if config.http.proxy.is_some() {
                Source::Proxy
            } else {
                Source::Origin
            },
        )?;

        #[cfg(feature = "dragonfly")]
        let dragonfly: Option<Box<dyn Transport>> = match config.dragonfly {
            Some(dragonfly) => Some(Box::new(Dragonfly::new(
                dragonfly,
                &config.http,
                prefetch.retry_interval,
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
            metrics,
        })
    }
}

/// Implements the registry requests.
impl Client {
    /// Returns where reads are fetched from when nothing else is known, the
    /// `source` label of a failed read: the seed peers when Dragonfly is
    /// configured, otherwise wherever the HTTP client reaches.
    fn source(&self) -> Source {
        if self.dragonfly.is_some() {
            Source::Dragonfly
        } else {
            self.http.source()
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

    /// Executes `request` with `headers` carrying the kept token, answering
    /// a `401` with the auth handshake and executing it again.
    ///
    /// ```text
    /// request with the kept token, none when it expired
    ///   ├─ not 401 ────────────────────────────────────────────────────────▶ answer
    ///   └─ 401 ─▶ sent with a token? it is forgotten, request again without
    ///              ├─ no WWW-Authenticate ─────────────────────────────────▶ answer
    ///              └─ WWW-Authenticate ─▶ fetch a token, keep it ─▶ request again ─▶ answer
    /// ```
    async fn execute<F, Fut>(&self, mut headers: HeaderMap, request: F) -> io::Result<Response>
    where
        F: Fn(HeaderMap) -> Fut,
        Fut: Future<Output = io::Result<Response>>,
    {
        self.authorizer.authorize(&mut headers);
        let response = request(headers.clone()).await?;
        if response.status != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }

        let challenge_response = match headers.remove(AUTHORIZATION) {
            Some(stale) => {
                self.authorizer.invalidate(&stale);
                request(headers.clone()).await?
            }
            None => response,
        };

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

    /// Fetches the `range` of a blob for an on-demand read and returns the
    /// response carrying exactly that range, its body still to be read.
    ///
    /// The read goes through the cached redirect when there is one, a `401`
    /// or `403` evicting it, and otherwise through the blob URL, caching the
    /// redirect it answers with.
    async fn read_range(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        range: &GetRange,
    ) -> io::Result<Response> {
        let hex = hex::encode(blob_id);
        let mut headers = HeaderMap::new();
        headers.insert(RANGE, range.to_string().parse().map_err(io::Error::other)?);
        let transport = self.transport();
        if let Some(redirect) = self.redirects.get(&hex) {
            let response = transport.get(&redirect, headers.clone()).await?;
            match response.status {
                status if status.is_success() => {
                    response.validate_range(range)?;
                    return Ok(response);
                }
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => self.redirects.remove(&hex),
                _ => return Err(response.into_io_error().await),
            }
        }

        let url = self.blob_url(&hex);
        let response = self
            .execute(headers.clone(), |headers| transport.get(&url, headers))
            .await?;
        if response.status.is_success() {
            response.validate_range(range)?;
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
        redirected.validate_range(range)?;

        self.redirects.insert(&hex, location);
        Ok(redirected)
    }

    /// Fetches the `range` of a blob for a prefetch read and returns the
    /// response carrying exactly that range, its body still to be read.
    ///
    /// The read goes through the cached redirect when there is one, a `401`
    /// or `403` evicting it, and otherwise through the blob URL, caching the
    /// redirect it answers with.
    async fn prefetch_range(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        range: &GetRange,
    ) -> io::Result<Response> {
        let hex = hex::encode(blob_id);
        let mut headers = HeaderMap::new();
        headers.insert(RANGE, range.to_string().parse().map_err(io::Error::other)?);
        let transport = self.transport();
        if let Some(redirect) = self.redirects.get(&hex) {
            let response = transport.prefetch(&redirect, headers.clone()).await?;
            match response.status {
                status if status.is_success() => {
                    response.validate_range(range)?;
                    return Ok(response);
                }
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => self.redirects.remove(&hex),
                _ => return Err(response.into_io_error().await),
            }
        }

        let url = self.blob_url(&hex);
        let response = self
            .execute(headers.clone(), |headers| transport.prefetch(&url, headers))
            .await?;
        if response.status.is_success() {
            response.validate_range(range)?;
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
        redirected.validate_range(range)?;

        self.redirects.insert(&hex, location);
        Ok(redirected)
    }

    /// Recovers a blob's metadata for an on-demand read: a suffix range
    /// fetches the footer, the blob's fixed-size tail, its `Content-Range`
    /// telling the blob's size, and the footer points at the metadata region.
    async fn read_blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<BlobMetadata> {
        let response = self
            .read_range(blob_id, &GetRange::Suffix(BlobFooter::SIZE as u64))
            .await?;
        let footer_offset =
            BlobFooter::calculate_offset_by_blob_size(response.content_range()?.complete_length)
                .map_err(io::Error::other)?;
        let footer_bytes = response.bytes(BlobFooter::SIZE).await?;
        let footer =
            BlobFooter::from_bytes(footer_bytes.as_ref().try_into().map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
        footer
            .validate_layout(footer_offset)
            .map_err(io::Error::other)?;

        let blob_metadata_size = usize::try_from(footer.blob_metadata_size()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "blob meta size exceeds usize")
        })?;
        let blob_metadata_end = footer.offset().map_err(io::Error::other)?.saturating_sub(1);
        let blob_metadata_bytes = self
            .read_range(
                blob_id,
                &GetRange::Bounded(footer.blob_metadata_offset()..=blob_metadata_end),
            )
            .await?
            .bytes(blob_metadata_size)
            .await?;

        BlobMetadata::from_bytes(blob_metadata_bytes.into()).map_err(io::Error::other)
    }

    /// Recovers a blob's metadata for a prefetch read: a suffix range
    /// fetches the footer, the blob's fixed-size tail, its `Content-Range`
    /// telling the blob's size, and the footer points at the metadata region.
    async fn prefetch_blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<BlobMetadata> {
        let response = self
            .prefetch_range(blob_id, &GetRange::Suffix(BlobFooter::SIZE as u64))
            .await?;
        let footer_offset =
            BlobFooter::calculate_offset_by_blob_size(response.content_range()?.complete_length)
                .map_err(io::Error::other)?;
        let footer_bytes = response.bytes(BlobFooter::SIZE).await?;
        let footer =
            BlobFooter::from_bytes(footer_bytes.as_ref().try_into().map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
        footer
            .validate_layout(footer_offset)
            .map_err(io::Error::other)?;

        let blob_metadata_size = usize::try_from(footer.blob_metadata_size()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "blob meta size exceeds usize")
        })?;
        let blob_metadata_end = footer.offset().map_err(io::Error::other)?.saturating_sub(1);
        let blob_metadata_bytes = self
            .prefetch_range(
                blob_id,
                &GetRange::Bounded(footer.blob_metadata_offset()..=blob_metadata_end),
            )
            .await?
            .bytes(blob_metadata_size)
            .await?;

        BlobMetadata::from_bytes(blob_metadata_bytes.into()).map_err(io::Error::other)
    }
}

/// Implements the blob backend over the registry.
impl Backend for Registry {
    /// Returns the metrics of the image.
    fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// Waits until the transport is ready, the Dragonfly seed peer clients
    /// connecting to the scheduler in the background.
    fn ready(&self) -> io::Result<()> {
        let client = self.client.clone();
        self.runtime
            .block_on_worker(async move { client.transport().ready().await })
    }

    /// Recovers the blob's metadata from the registry for an on-demand read.
    fn read_blob_metadata(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<BlobMetadata> {
        let client = self.client.clone();
        let blob_id = *blob_id;
        self.runtime
            .block_on_worker(async move { client.read_blob_metadata(&blob_id).await })
    }

    /// Recovers the blob's metadata from the registry for a prefetch read.
    fn prefetch_blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<BlobMetadata> {
        let client = self.client.clone();
        let blob_id = *blob_id;
        self.runtime
            .block_on_worker(async move { client.prefetch_blob_metadata(&blob_id).await })
    }

    /// Fills `buf` with the blob bytes from `offset` for an on-demand read,
    /// recording the read's metrics.
    fn read_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        buf: &mut [u8],
    ) -> io::Result<()> {
        let start = Instant::now();
        let client = self.client.clone();
        let blob_id = *blob_id;
        let length = buf.len();
        let result = self.runtime.block_on_worker(async move {
            let range = GetRange::Bounded(offset..=(offset + length as u64).saturating_sub(1));
            let response = client.read_range(&blob_id, &range).await?;
            let source = response.source;
            Ok((response.bytes(length).await?, source))
        });

        match result {
            Ok((bytes, source)) => {
                self.metrics.backend.collect_read_finished_metrics(
                    ReadKind::Ondemand,
                    source,
                    length as u64,
                    start.elapsed(),
                );
                buf.copy_from_slice(&bytes);
                Ok(())
            }
            Err(err) => {
                self.metrics
                    .backend
                    .collect_read_failure_metrics(ReadKind::Ondemand, self.client.source());
                Err(err)
            }
        }
    }

    /// Fills `buf` with the blob bytes from `offset` for a prefetch read,
    /// recording the read's metrics.
    fn prefetch_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        buf: &mut [u8],
    ) -> io::Result<()> {
        let start = Instant::now();
        let client = self.client.clone();
        let blob_id = *blob_id;
        let length = buf.len();
        let result = self.runtime.block_on_worker(async move {
            let range = GetRange::Bounded(offset..=(offset + length as u64).saturating_sub(1));
            let response = client.prefetch_range(&blob_id, &range).await?;
            let source = response.source;
            Ok((response.bytes(length).await?, source))
        });

        match result {
            Ok((bytes, source)) => {
                self.metrics.backend.collect_read_finished_metrics(
                    ReadKind::Prefetch,
                    source,
                    length as u64,
                    start.elapsed(),
                );
                buf.copy_from_slice(&bytes);
                Ok(())
            }
            Err(err) => {
                self.metrics
                    .backend
                    .collect_read_failure_metrics(ReadKind::Prefetch, self.client.source());
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::range::ContentRange;
    use super::response::Body;
    use super::*;
    use bytes::Bytes;
    use nydus_config::HttpConfig;
    use nydus_test_utils::blob::FullBlob;
    use nydus_test_utils::metadata::single_chunk_group;
    use reqwest::header::LOCATION;
    use std::collections::VecDeque;
    use std::fs;
    use std::net::{SocketAddr, TcpListener};
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;
    use tempfile::tempdir;

    const TEST_BLOB_ID: [u8; SHA256_DIGEST_SIZE] = [7u8; SHA256_DIGEST_SIZE];

    #[async_trait]
    impl<T: Transport> Transport for Arc<T> {
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
                    status: StatusCode::PARTIAL_CONTENT,
                    headers: HeaderMap::new(),
                    body: Body::Bytes(body.into()),
                    source: Source::Dragonfly,
                }),
                Scripted::Status(status, headers) => Ok(Response {
                    status,
                    headers,
                    body: Body::Bytes(Bytes::new()),
                    source: Source::Dragonfly,
                }),
            }
        }
    }

    #[async_trait]
    impl Transport for ScriptedTransport {
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

        async fn answer(&self, headers: HeaderMap) -> io::Result<Response> {
            if self.first.swap(false, Ordering::SeqCst) {
                tokio::time::sleep(self.delay).await;
            }
            if headers.contains_key(AUTHORIZATION) {
                return Ok(Response {
                    status: StatusCode::PARTIAL_CONTENT,
                    headers: HeaderMap::new(),
                    body: Body::Bytes(Bytes::from_static(b"ok")),
                    source: Source::Dragonfly,
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
                source: Source::Dragonfly,
            })
        }
    }

    #[async_trait]
    impl Transport for AuthGate {
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
        fn serve(status: &'static str, body: Vec<u8>) -> OriginStub {
            OriginStub::serve_on(TcpListener::bind("127.0.0.1:0").unwrap(), status, body)
        }

        fn serve_on(listener: TcpListener, status: &'static str, body: Vec<u8>) -> OriginStub {
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
                        let request = String::from_utf8_lossy(&buf);
                        let _ = stream.write_all(&OriginStub::respond(status, &request, &body));
                    });
                }
            });
            OriginStub { addr, hits }
        }

        fn respond(status: &str, request: &str, blob: &[u8]) -> Vec<u8> {
            let range = request
                .lines()
                .find_map(|line| line.strip_prefix("range: "))
                .filter(|_| status.starts_with("206"))
                .map(|value| {
                    value
                        .parse::<GetRange>()
                        .unwrap()
                        .to_range(blob.len() as u64)
                });
            let (content_range, body) = match range {
                Some(range) => (
                    format!(
                        "Content-Range: {}\r\n",
                        ContentRange {
                            range: range.clone(),
                            complete_length: blob.len() as u64,
                        }
                    ),
                    &blob[*range.start() as usize..=*range.end() as usize],
                ),
                None => (String::new(), blob),
            };

            let mut response = format!(
                "HTTP/1.1 {status}\r\n{content_range}Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            response.extend_from_slice(body);
            response
        }

        fn hits(&self) -> u32 {
            self.hits.load(Ordering::SeqCst)
        }
    }

    fn scripted_registry(
        addr: SocketAddr,
        auth: Option<&str>,
        transport: impl Transport + 'static,
    ) -> Registry {
        let http = HttpConfig::default();
        Registry {
            client: Arc::new(Client {
                addr: format!("http://{addr}").parse().unwrap(),
                repository: "library/ubuntu".to_string(),
                authorizer: Authorizer::new(auth).unwrap(),
                redirects: RedirectCache::new(),
                http: Http::new(
                    http.request_timeout,
                    http.max_retries,
                    None,
                    &http.tls,
                    PrefetchConfig::default().retry_interval,
                    None,
                    Source::Origin,
                )
                .unwrap(),
                dragonfly: Some(Box::new(transport)),
            }),
            runtime: Arc::new(Runtime::new(None).unwrap()),
            metrics: Arc::new(Metrics::new()),
        }
    }

    fn origin_registry(addr: SocketAddr, netns: Option<Netns>) -> Registry {
        let config: RegistryConfig = serde_yaml::from_str(&format!(
            "addr: http://{addr}\nrepository: library/ubuntu\n"
        ))
        .unwrap();
        Registry::new(
            config,
            &PrefetchConfig::default(),
            netns,
            Arc::new(Metrics::new()),
        )
        .unwrap()
    }

    fn read(registry: &Registry, kind: ReadKind, buf: &mut [u8]) -> io::Result<Source> {
        registry.runtime.tokio().block_on(async {
            let client = &registry.client;
            let range = GetRange::Bounded(0..=buf.len() as u64 - 1);
            let response = match kind {
                ReadKind::Ondemand => client.read_range(&TEST_BLOB_ID, &range).await?,
                ReadKind::Prefetch => client.prefetch_range(&TEST_BLOB_ID, &range).await?,
            };
            let source = response.source;
            buf.copy_from_slice(&response.bytes(buf.len()).await?);
            Ok(source)
        })
    }

    #[test]
    fn blob_metadata_and_ranges_are_read_from_the_origin_for_both_read_kinds() {
        let dir = tempdir().unwrap();
        let payload = vec![0x9au8; 4096];
        let blob_metadata = single_chunk_group(&payload);
        let full_blob_id = FullBlob::new(&payload)
            .with_blob_metadata(&blob_metadata)
            .save_in(dir.path());
        let blob = fs::read(dir.path().join(hex::encode(full_blob_id))).unwrap();
        let origin = OriginStub::serve("206 Partial Content", blob);
        let registry = origin_registry(origin.addr, None);

        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let blob_metadata = match kind {
                ReadKind::Ondemand => registry.read_blob_metadata(&full_blob_id),
                ReadKind::Prefetch => registry.prefetch_blob_metadata(&full_blob_id),
            }
            .unwrap();
            let mut data = vec![0u8; 16];
            match kind {
                ReadKind::Ondemand => registry.read_range_into(&full_blob_id, 17, &mut data),
                ReadKind::Prefetch => registry.prefetch_range_into(&full_blob_id, 17, &mut data),
            }
            .unwrap();

            assert_eq!(blob_metadata.chunk_group_count(), 1, "kind={kind:?}");
            assert_eq!(data, payload[17..33], "kind={kind:?}");
        }
        assert_eq!(origin.hits(), 6);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, CAP_NET_ADMIN and iproute2 to create a netns"]
    fn reads_reach_the_origin_only_inside_the_configured_netns() {
        let (netns, listener) = thread::spawn(|| {
            // SAFETY: unshare only affects this scratch thread, which exits
            // right after; the descriptor keeps the namespace.
            assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
            assert!(std::process::Command::new("ip")
                .args(["link", "set", "lo", "up"])
                .status()
                .unwrap()
                .success());
            let file = fs::File::open("/proc/thread-self/ns/net").unwrap();
            (
                Netns::new(file.into()).unwrap(),
                TcpListener::bind("127.0.0.1:0").unwrap(),
            )
        })
        .join()
        .unwrap();
        let origin = OriginStub::serve_on(listener, "206 Partial Content", b"abcd".to_vec());
        let escaped = TcpListener::bind(origin.addr).unwrap();
        escaped.set_nonblocking(true).unwrap();
        let registry = origin_registry(origin.addr, Some(netns));

        let mut buf = [0u8; 4];
        registry
            .read_range_into(&TEST_BLOB_ID, 0, &mut buf)
            .unwrap();
        registry
            .prefetch_range_into(&TEST_BLOB_ID, 0, &mut buf)
            .unwrap();

        assert_eq!(&buf, b"abcd");
        assert_eq!(origin.hits(), 2);
        assert_eq!(
            escaped.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn whole_blob_answers_from_the_origin_are_rejected_for_both_read_kinds() {
        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let origin = OriginStub::serve("200 OK", (0..64).collect());
            let registry = origin_registry(origin.addr, None);

            let mut buf = vec![0u8; 4];
            let err = read(&registry, kind, &mut buf).unwrap_err();

            assert_eq!(
                err.kind(),
                io::ErrorKind::InvalidData,
                "kind={kind:?}: {err}"
            );
            assert_eq!(origin.hits(), 1, "kind={kind:?}");
        }
    }

    #[test]
    fn whole_blob_answers_from_dragonfly_are_rejected_for_both_read_kinds() {
        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let origin = OriginStub::serve("206 Partial Content", b"unused".to_vec());
            let transport =
                ScriptedTransport::new(vec![Scripted::Status(StatusCode::OK, HeaderMap::new())]);
            let registry = scripted_registry(origin.addr, None, transport.clone());

            let mut buf = vec![0u8; 4];
            let err = read(&registry, kind, &mut buf).unwrap_err();

            assert_eq!(
                err.kind(),
                io::ErrorKind::InvalidData,
                "kind={kind:?}: {err}"
            );
            assert_eq!(transport.calls(), 1, "kind={kind:?}");
            assert_eq!(origin.hits(), 0, "kind={kind:?}");
        }
    }

    #[test]
    fn whole_blob_redirected_answers_are_rejected_and_not_cached() {
        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let origin = OriginStub::serve("206 Partial Content", b"unused".to_vec());
            let mut redirect = HeaderMap::new();
            redirect.insert(LOCATION, "http://cdn.example.com/signed".parse().unwrap());
            let transport = ScriptedTransport::new(vec![
                Scripted::Status(StatusCode::TEMPORARY_REDIRECT, redirect),
                Scripted::Status(StatusCode::OK, HeaderMap::new()),
            ]);
            let registry = scripted_registry(origin.addr, None, transport.clone());

            let mut buf = vec![0u8; 4];
            let err = read(&registry, kind, &mut buf).unwrap_err();

            assert_eq!(
                err.kind(),
                io::ErrorKind::InvalidData,
                "kind={kind:?}: {err}"
            );
            assert_eq!(transport.calls(), 2, "kind={kind:?}");
            assert!(
                registry
                    .client
                    .redirects
                    .get(&hex::encode(TEST_BLOB_ID))
                    .is_none(),
                "kind={kind:?}"
            );
        }
    }

    #[test]
    fn whole_blob_cached_redirect_answers_are_rejected() {
        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let origin = OriginStub::serve("206 Partial Content", b"unused".to_vec());
            let transport =
                ScriptedTransport::new(vec![Scripted::Status(StatusCode::OK, HeaderMap::new())]);
            let registry = scripted_registry(origin.addr, None, transport.clone());
            registry.client.redirects.insert(
                &hex::encode(TEST_BLOB_ID),
                "http://cdn.example.com/signed".to_string(),
            );

            let mut buf = vec![0u8; 4];
            let err = read(&registry, kind, &mut buf).unwrap_err();

            assert_eq!(
                err.kind(),
                io::ErrorKind::InvalidData,
                "kind={kind:?}: {err}"
            );
            assert_eq!(transport.calls(), 1, "kind={kind:?}");
        }
    }

    #[cfg(feature = "dragonfly")]
    #[test]
    fn unreachable_scheduler_fails_ready_while_ondemand_reads_fall_back() {
        let scheduler = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let origin = OriginStub::serve("206 Partial Content", b"abcd".to_vec());
        let config: RegistryConfig = serde_yaml::from_str(&format!(
            "addr: http://{}\nrepository: library/ubuntu\ndragonfly:\n  scheduler_endpoint: http://{scheduler}\n",
            origin.addr
        ))
        .unwrap();
        let registry = Registry::new(
            config,
            &PrefetchConfig::default(),
            None,
            Arc::new(Metrics::new()),
        )
        .unwrap();

        let mut buf = [0u8; 4];
        registry
            .read_range_into(&TEST_BLOB_ID, 0, &mut buf)
            .unwrap();

        assert!(registry.ready().is_err());
        assert_eq!(&buf, b"abcd");
        assert!(registry
            .prefetch_range_into(&TEST_BLOB_ID, 0, &mut buf)
            .is_err());
        assert_eq!(origin.hits(), 1);
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
            let registry = Registry::new(
                config,
                &PrefetchConfig::default(),
                None,
                Arc::new(Metrics::new()),
            )
            .unwrap();
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
        let registry = Registry::new(
            config,
            &PrefetchConfig::default(),
            None,
            Arc::new(Metrics::new()),
        )
        .unwrap();
        assert_eq!(
            registry.client.addr.as_str(),
            "https://registry.example.com/"
        );
        assert!(registry.client.dragonfly.is_none());
        assert_eq!(registry.client.source(), Source::Origin);
    }

    #[test]
    fn definitive_answers_are_terminal_for_both_read_kinds() {
        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            for terminal in [
                StatusCode::FORBIDDEN,
                StatusCode::NOT_FOUND,
                StatusCode::UNPROCESSABLE_ENTITY,
            ] {
                let origin = OriginStub::serve("206 Partial Content", b"unused".to_vec());
                let transport =
                    ScriptedTransport::new(vec![Scripted::Status(terminal, HeaderMap::new())]);
                let registry = scripted_registry(origin.addr, None, transport.clone());

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
        let origin = OriginStub::serve("503 Service Unavailable", b"busy".to_vec());
        let config: RegistryConfig = serde_yaml::from_str(&format!(
            "addr: http://{}\nrepository: library/ubuntu\nhttp:\n  max_retries: 0\n",
            origin.addr
        ))
        .unwrap();
        let registry = Registry::new(
            config,
            &PrefetchConfig::default(),
            None,
            Arc::new(Metrics::new()),
        )
        .unwrap();

        let mut buf = vec![0u8; 4];
        let err = read(&registry, ReadKind::Ondemand, &mut buf).unwrap_err();

        assert!(err.to_string().contains("503"), "{err}");
        assert_eq!(origin.hits(), 1);
    }

    #[test]
    fn unauthorized_answer_triggers_the_auth_handshake() {
        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let body = b"authorized".to_vec();
            let origin = OriginStub::serve("206 Partial Content", b"unused".to_vec());
            let mut challenge = HeaderMap::new();
            challenge.insert(
                WWW_AUTHENTICATE,
                r#"Basic realm="registry""#.parse().unwrap(),
            );
            let transport = ScriptedTransport::new(vec![
                Scripted::Status(StatusCode::UNAUTHORIZED, challenge),
                Scripted::Body(body.clone()),
            ]);
            let registry =
                scripted_registry(origin.addr, Some("YWxpY2U6c2VjcmV0"), transport.clone());

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
    fn read_blob_metadata_fetches_the_footer_through_the_transport() {
        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let origin = OriginStub::serve("206 Partial Content", b"unused".to_vec());
            let transport = ScriptedTransport::new(vec![Scripted::Status(
                StatusCode::NOT_FOUND,
                HeaderMap::new(),
            )]);
            let registry = scripted_registry(origin.addr, None, transport.clone());

            let err = match kind {
                ReadKind::Ondemand => registry.read_blob_metadata(&TEST_BLOB_ID),
                ReadKind::Prefetch => registry.prefetch_blob_metadata(&TEST_BLOB_ID),
            }
            .unwrap_err();

            assert!(err.to_string().contains("404"), "kind={kind:?}: {err}");
            assert_eq!(origin.hits(), 0, "kind={kind:?}");
            assert_eq!(transport.calls(), 1, "kind={kind:?}");
        }
    }

    #[test]
    fn concurrent_reads_each_complete_the_auth_handshake() {
        let gate = AuthGate::new(Duration::from_millis(100));
        let dead_addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let registry = Arc::new(scripted_registry(
            dead_addr,
            Some("YWxpY2U6c2VjcmV0"),
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
        let origin = OriginStub::serve("206 Partial Content", b"unused".to_vec());
        let transport = ScriptedTransport::new(vec![Scripted::Body(body.clone())]);
        let registry = scripted_registry(origin.addr, None, transport.clone());
        let hex = hex::encode(TEST_BLOB_ID);
        registry
            .client
            .redirects
            .insert(&hex, "http://cdn.example.com/signed".to_string());

        let mut buf = vec![0u8; body.len()];
        let source = read(&registry, ReadKind::Ondemand, &mut buf).unwrap();

        assert_eq!(source, Source::Dragonfly);
        assert_eq!(buf, body);
        assert_eq!(transport.calls(), 1);
        assert_eq!(origin.hits(), 0);
    }

    #[test]
    fn forbidden_cached_redirect_is_evicted_and_re_resolved() {
        let body = b"fresh".to_vec();
        let origin = OriginStub::serve("206 Partial Content", b"unused".to_vec());
        let transport = ScriptedTransport::new(vec![
            Scripted::Status(StatusCode::FORBIDDEN, HeaderMap::new()),
            Scripted::Body(body.clone()),
        ]);
        let registry = scripted_registry(origin.addr, None, transport.clone());
        let hex = hex::encode(TEST_BLOB_ID);
        registry
            .client
            .redirects
            .insert(&hex, "http://cdn.example.com/expired".to_string());

        let mut buf = vec![0u8; body.len()];
        read(&registry, ReadKind::Ondemand, &mut buf).unwrap();

        assert_eq!(buf, body);
        assert_eq!(transport.calls(), 2);
        assert!(registry.client.redirects.get(&hex).is_none());
    }
}
