//! The OCI registry backend: blobs addressed by their full blob digest and
//! served in byte ranges, over the origin or the Dragonfly seed peers.

mod auth;
#[cfg(feature = "dragonfly")]
mod dragonfly;
mod http;
mod range;
mod reader;
mod redirect;
mod response;
mod rt;

use std::future::Future;
use std::io::{self, BufRead};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use futures::{TryFutureExt, TryStreamExt};
use reqwest::header::{HeaderMap, AUTHORIZATION, RANGE, WWW_AUTHENTICATE};
use reqwest::StatusCode;
use tracing::debug;
use url::Url;

use nydus_config::{BackendConfig, Config, RedactedString};
use nydus_format::blob::{BlobFooter, BlobMetadata};
use nydus_format::utils::SHA256_DIGEST_SIZE;
use nydus_telemetry::metrics::Metrics;

use crate::{Backend, Netns, ReadKind, Source};

use self::auth::{Authorizer, Challenge};
#[cfg(feature = "dragonfly")]
use self::dragonfly::Dragonfly;
use self::http::Http;
use self::range::Range;
use self::reader::StreamReader;
use self::redirect::RedirectCache;
use self::response::Response;
pub use self::rt::Runtime;

/// The transport of blob `GET`s, the origin or the Dragonfly seed peers, each
/// call returning after the transport's own retries.
#[async_trait]
trait Transport: Send + Sync {
    /// Sends the `GET` of an on-demand read, which a FUSE reader waits on.
    async fn get(&self, url: &str, headers: HeaderMap) -> io::Result<Response>;

    /// Sends the `GET` of a prefetch read, once more after the retry interval
    /// on a `429`, `5xx` or `408`.
    async fn prefetch(&self, url: &str, headers: HeaderMap) -> io::Result<Response>;
}

/// The blob backend over an OCI registry, running the reads of [`Client`] on
/// [`Runtime`] and streaming each range to a [`StreamReader`].
///
/// ```text
/// Registry
///   ├─ Runtime              the tokio runtime of every read
///   ├─ Metrics              the metrics of the image
///   └─ Client
///        ├─ Authorizer      the challenge and the token that answers it
///        ├─ RedirectCache   the signed URLs blob GETs were redirected to
///        ├─ Http            the origin, token fetches included
///        └─ Dragonfly       the seed peers, with a rate-limited Http back to the origin
/// ```
pub(crate) struct Registry {
    /// The registry client, shared with the task of each read.
    client: Arc<Client>,

    /// The runtime every read runs on.
    runtime: Arc<Runtime>,

    /// The metrics of the image the backend serves.
    metrics: Arc<Metrics>,
}

/// The client of one repository on one registry.
///
/// The reads of a blob from a registry with bearer auth that redirects blob
/// `GET`s to a CDN:
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
/// the first read with a `registry_token` in the config, kept as the token
///   1. redirect cache ───────────────────────────────────────────▶ miss, step 4
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

    /// The credentials and the `Authorization` kept from the config or the
    /// last challenge.
    authorizer: Authorizer,

    /// The signed URLs blob `GET`s were redirected to, by blob hex digest.
    redirects: RedirectCache,

    /// The direct client to the origin.
    http: Http,

    /// The Dragonfly transport when configured.
    dragonfly: Option<Box<dyn Transport>>,
}

/// Implements the registry backend construction.
impl Registry {
    /// Creates a registry backend from the `backend` section of `config`.
    pub(crate) fn new(
        config: &Config,
        netns: Option<Netns>,
        metrics: Arc<Metrics>,
    ) -> io::Result<Self> {
        let BackendConfig::Registry(registry) = &config.backend else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "backend is not a registry",
            ));
        };

        let runtime = Arc::new(Runtime::new(netns)?);
        let http = Http::new(
            registry.http.request_timeout,
            registry.http.max_retries,
            registry.http.proxy.as_ref(),
            &registry.http.tls,
            config.prefetch.retry_interval,
            None,
        )?;

        let dragonfly: Option<Box<dyn Transport>> = match &registry.dragonfly {
            #[cfg(feature = "dragonfly")]
            Some(_) => Some(Box::new(Dragonfly::new(config, &runtime)?)),
            _ => None,
        };

        Ok(Self {
            client: Arc::new(Client {
                addr: registry.addr.clone(),
                repository: registry.repository.clone(),
                authorizer: Authorizer::new(
                    registry.auth.as_ref().map(RedactedString::expose),
                    registry.registry_token.as_ref().map(RedactedString::expose),
                )?,
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
    /// Returns the `source` label of the reads.
    fn source(&self) -> Source {
        if self.dragonfly.is_some() {
            Source::Dragonfly
        } else {
            Source::Http
        }
    }

    /// Returns the URL of blob `hex`, `<addr>/v2/<repository>/blobs/sha256:<hex>`.
    fn blob_url(&self, hex: &str) -> String {
        format!(
            "{}/v2/{}/blobs/sha256:{hex}",
            self.addr.as_str().trim_end_matches('/'),
            self.repository
        )
    }

    /// Returns the transport of blob `GET`s, Dragonfly when configured.
    fn transport(&self) -> &dyn Transport {
        match &self.dragonfly {
            Some(dragonfly) => dragonfly.as_ref(),
            None => &self.http,
        }
    }

    /// Executes `request` with the kept token, answering a `401` with the auth
    /// handshake.
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

    /// Fetches the `range` of a blob for an on-demand read, through the cached
    /// redirect when there is one.
    async fn read_range(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        range: &Range,
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

    /// Fetches the `range` of a blob for a prefetch read, through the cached
    /// redirect when there is one.
    async fn prefetch_range(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        range: &Range,
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

    /// Reads a blob's metadata for an on-demand read.
    ///
    /// ```text
    /// GET bytes=-<footer size> ──▶ footer, Content-Range: bytes .../<blob size>
    /// GET bytes=<blob meta range in the footer> ──▶ blob meta
    /// ```
    async fn read_blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<BlobMetadata> {
        let response = self
            .read_range(blob_id, &Range::Suffix(BlobFooter::SIZE as u64))
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
                &Range::Bounded(footer.blob_metadata_offset()..=blob_metadata_end),
            )
            .await?
            .bytes(blob_metadata_size)
            .await?;

        BlobMetadata::from_bytes(blob_metadata_bytes.into()).map_err(io::Error::other)
    }

    /// Reads a blob's metadata for a prefetch read, like
    /// [`Client::read_blob_metadata`].
    async fn prefetch_blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<BlobMetadata> {
        let response = self
            .prefetch_range(blob_id, &Range::Suffix(BlobFooter::SIZE as u64))
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
                &Range::Bounded(footer.blob_metadata_offset()..=blob_metadata_end),
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

    /// Reads the blob's metadata for an on-demand read.
    fn read_blob_metadata(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<BlobMetadata> {
        let client = self.client.clone();
        let blob_id = *blob_id;
        self.runtime
            .block_on_worker(async move { client.read_blob_metadata(&blob_id).await })
    }

    /// Reads the blob's metadata for a prefetch read.
    fn prefetch_blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<BlobMetadata> {
        let client = self.client.clone();
        let blob_id = *blob_id;
        self.runtime
            .block_on_worker(async move { client.prefetch_blob_metadata(&blob_id).await })
    }

    /// Reads `len` blob bytes from `offset` for an on-demand read, streaming.
    fn read(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        len: usize,
    ) -> io::Result<Box<dyn BufRead + Send>> {
        let now = Instant::now();
        let end = offset.checked_add(len as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob range offset overflow")
        })?;
        let range = Range::try_from(offset..end)?;

        let client = self.client.clone();
        let blob_id = *blob_id;
        let response = self
            .runtime
            .block_on_worker(async move { client.read_range(&blob_id, &range).await })
            .inspect_err(|_| {
                self.metrics
                    .backend
                    .collect_read_failure_metrics(ReadKind::Ondemand, self.client.source())
            })?;

        let source = self.client.source();
        let metrics = self.metrics.clone();
        let (tx, reader) = StreamReader::channel();
        self.runtime.spawn(async move {
            // Stream the range until it ends or the reader is dropped.
            let result = tokio::select! {
                result = response.bytes_stream(len).try_for_each(|chunk| {
                    tx.send(Ok(chunk)).map_err(|_| io::ErrorKind::BrokenPipe.into())
                }) => result,
                _ = tx.closed() => Err(io::ErrorKind::BrokenPipe.into()),
            };

            match result {
                Ok(()) => metrics.backend.collect_read_finished_metrics(
                    ReadKind::Ondemand,
                    source,
                    len as u64,
                    now.elapsed(),
                ),
                Err(err) => {
                    metrics
                        .backend
                        .collect_read_failure_metrics(ReadKind::Ondemand, source);
                    if tx.send(Err(err)).await.is_err() {
                        debug!("range reader dropped before its read ended");
                    }
                }
            }
        });

        Ok(Box::new(reader))
    }

    /// Reads `len` blob bytes from `offset` for a prefetch read, streaming.
    fn prefetch(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        len: usize,
    ) -> io::Result<Box<dyn BufRead + Send>> {
        let now = Instant::now();
        let end = offset.checked_add(len as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "blob range offset overflow")
        })?;
        let range = Range::try_from(offset..end)?;

        let client = self.client.clone();
        let blob_id = *blob_id;
        let response = self
            .runtime
            .block_on_worker(async move { client.prefetch_range(&blob_id, &range).await })
            .inspect_err(|_| {
                self.metrics
                    .backend
                    .collect_read_failure_metrics(ReadKind::Prefetch, self.client.source())
            })?;

        let source = self.client.source();
        let metrics = self.metrics.clone();
        let (tx, reader) = StreamReader::channel();
        self.runtime.spawn(async move {
            // Stream the range until it ends or the reader is dropped.
            let result = tokio::select! {
                result = response.bytes_stream(len).try_for_each(|chunk| {
                    tx.send(Ok(chunk)).map_err(|_| io::ErrorKind::BrokenPipe.into())
                }) => result,
                _ = tx.closed() => Err(io::ErrorKind::BrokenPipe.into()),
            };

            match result {
                Ok(()) => metrics.backend.collect_read_finished_metrics(
                    ReadKind::Prefetch,
                    source,
                    len as u64,
                    now.elapsed(),
                ),
                Err(err) => {
                    metrics
                        .backend
                        .collect_read_failure_metrics(ReadKind::Prefetch, source);
                    if tx.send(Err(err)).await.is_err() {
                        debug!("range reader dropped before its read ended");
                    }
                }
            }
        });

        Ok(Box::new(reader))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::range::ContentRange;
    use super::*;
    use bytes::Bytes;
    use futures::stream::{self, StreamExt};
    use nydus_config::{HttpConfig, PrefetchConfig};
    use nydus_test_utils::blob::FullBlob;
    use nydus_test_utils::metadata::single_chunk_group;
    use reqwest::header::{CONTENT_RANGE, LOCATION};
    use std::collections::VecDeque;
    use std::fs;
    use std::io::Read;
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
        headers: Mutex<Vec<HeaderMap>>,
    }

    impl ScriptedTransport {
        fn new(script: impl IntoIterator<Item = Scripted>) -> Arc<ScriptedTransport> {
            Arc::new(ScriptedTransport {
                script: Mutex::new(script.into_iter().collect()),
                calls: AtomicU32::new(0),
                headers: Mutex::new(Vec::new()),
            })
        }

        fn calls(&self) -> u32 {
            self.calls.load(Ordering::SeqCst)
        }

        fn headers(&self) -> Vec<HeaderMap> {
            self.headers.lock().unwrap().clone()
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
                Scripted::Body(body) => {
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        CONTENT_RANGE,
                        ContentRange {
                            range: 0..=body.len() as u64 - 1,
                            complete_length: body.len() as u64,
                        }
                        .to_string()
                        .parse()
                        .unwrap(),
                    );
                    Ok(Response {
                        status: StatusCode::PARTIAL_CONTENT,
                        headers,
                        body: stream::iter([Ok(Bytes::from(body))]).boxed(),
                    })
                }
                Scripted::Status(status, headers) => Ok(Response {
                    status,
                    headers,
                    body: stream::empty().boxed(),
                }),
            }
        }
    }

    #[async_trait]
    impl Transport for ScriptedTransport {
        async fn get(&self, _url: &str, headers: HeaderMap) -> io::Result<Response> {
            self.headers.lock().unwrap().push(headers);
            self.play()
        }

        async fn prefetch(&self, _url: &str, headers: HeaderMap) -> io::Result<Response> {
            self.headers.lock().unwrap().push(headers);
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
                let mut headers = HeaderMap::new();
                headers.insert(CONTENT_RANGE, "bytes 0-1/2".parse().unwrap());
                return Ok(Response {
                    status: StatusCode::PARTIAL_CONTENT,
                    headers,
                    body: stream::iter([Ok(Bytes::from_static(b"ok"))]).boxed(),
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
                body: stream::empty().boxed(),
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
        requests: Arc<Mutex<Vec<String>>>,
    }

    impl OriginStub {
        fn serve(statuses: &'static [&'static str], body: Vec<u8>) -> OriginStub {
            OriginStub::serve_on(TcpListener::bind("127.0.0.1:0").unwrap(), statuses, body)
        }

        fn serve_on(
            listener: TcpListener,
            statuses: &'static [&'static str],
            body: Vec<u8>,
        ) -> OriginStub {
            let addr = listener.local_addr().unwrap();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let requests_in_thread = requests.clone();
            thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { break };
                    let body = body.clone();
                    let requests = requests_in_thread.clone();
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
                        let request = String::from_utf8_lossy(&buf).into_owned();
                        let status = {
                            let mut requests = requests.lock().unwrap();
                            requests.push(request.clone());
                            statuses[(requests.len() - 1).min(statuses.len() - 1)]
                        };
                        let _ = stream.write_all(&OriginStub::respond(status, &request, &body));
                    });
                }
            });
            OriginStub { addr, requests }
        }

        fn respond(status: &str, request: &str, blob: &[u8]) -> Vec<u8> {
            let range = request
                .lines()
                .find_map(|line| line.strip_prefix("range: "))
                .filter(|_| status.starts_with("206"))
                .map(|value| {
                    value
                        .parse::<Range>()
                        .unwrap()
                        .satisfiable_range(blob.len() as u64)
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
            if status.ends_with("Truncated") {
                response.extend_from_slice(&body[..body.len() / 2]);
            } else {
                response.extend_from_slice(body);
            }
            response
        }

        fn hits(&self) -> u32 {
            self.requests.lock().unwrap().len() as u32
        }

        fn ranges(&self) -> Vec<String> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .filter_map(|request| {
                    request
                        .lines()
                        .find_map(|line| line.strip_prefix("range: "))
                        .map(str::to_string)
                })
                .collect()
        }
    }

    fn scripted_registry(
        addr: SocketAddr,
        auth: Option<&str>,
        registry_token: Option<&str>,
        transport: impl Transport + 'static,
    ) -> Registry {
        let http = HttpConfig::default();
        Registry {
            client: Arc::new(Client {
                addr: format!("http://{addr}").parse().unwrap(),
                repository: "library/ubuntu".to_string(),
                authorizer: Authorizer::new(auth, registry_token).unwrap(),
                redirects: RedirectCache::new(),
                http: Http::new(
                    http.request_timeout,
                    http.max_retries,
                    None,
                    &http.tls,
                    PrefetchConfig::default().retry_interval,
                    None,
                )
                .unwrap(),
                dragonfly: Some(Box::new(transport)),
            }),
            runtime: Arc::new(Runtime::new(None).unwrap()),
            metrics: Arc::new(Metrics::new()),
        }
    }

    fn origin_registry(addr: SocketAddr, netns: Option<Netns>) -> Registry {
        let config: Config = serde_yaml::from_str(&format!(
            "backend:\n  type: registry\n  config:\n    addr: http://{addr}\n    repository: library/ubuntu\n"
        ))
        .unwrap();
        Registry::new(&config, netns, Arc::new(Metrics::new())).unwrap()
    }

    fn read(registry: &Registry, kind: ReadKind, buf: &mut [u8]) -> io::Result<()> {
        registry.runtime.tokio().block_on(async {
            let client = &registry.client;
            let range = Range::Bounded(0..=buf.len() as u64 - 1);
            let response = match kind {
                ReadKind::Ondemand => client.read_range(&TEST_BLOB_ID, &range).await?,
                ReadKind::Prefetch => client.prefetch_range(&TEST_BLOB_ID, &range).await?,
            };
            buf.copy_from_slice(&response.bytes(buf.len()).await?);
            Ok(())
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
        let origin = OriginStub::serve(&["206 Partial Content"], blob);
        let registry = origin_registry(origin.addr, None);

        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let blob_metadata = match kind {
                ReadKind::Ondemand => registry.read_blob_metadata(&full_blob_id),
                ReadKind::Prefetch => registry.prefetch_blob_metadata(&full_blob_id),
            }
            .unwrap();
            let mut data = vec![0u8; 16];
            match kind {
                ReadKind::Ondemand => registry.read(&full_blob_id, 17, data.len()),
                ReadKind::Prefetch => registry.prefetch(&full_blob_id, 17, data.len()),
            }
            .unwrap()
            .read_exact(&mut data)
            .unwrap();

            assert_eq!(blob_metadata.chunk_group_count(), 1);
            assert_eq!(data, payload[17..33]);
        }
        assert_eq!(origin.hits(), 6);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, CAP_NET_ADMIN and iproute2 to create a netns"]
    fn reads_reach_the_origin_only_inside_the_configured_netns() {
        let escaped = TcpListener::bind("127.0.0.1:0").unwrap();
        escaped.set_nonblocking(true).unwrap();
        let port = escaped.local_addr().unwrap().port();
        let (netns, listener) = thread::spawn(move || {
            // SAFETY: unshare only affects this short-lived thread.
            assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
            assert!(std::process::Command::new("ip")
                .args(["link", "set", "lo", "up"])
                .status()
                .unwrap()
                .success());
            let file = fs::File::open("/proc/thread-self/ns/net").unwrap();
            (
                Netns::new(file.into()).unwrap(),
                TcpListener::bind(("127.0.0.1", port)).unwrap(),
            )
        })
        .join()
        .unwrap();
        let dir = tempdir().unwrap();
        let payload = vec![0x9au8; 4096];
        let blob_metadata = single_chunk_group(&payload);
        let full_blob_id = FullBlob::new(&payload)
            .with_blob_metadata(&blob_metadata)
            .save_in(dir.path());
        let blob = fs::read(dir.path().join(hex::encode(full_blob_id))).unwrap();
        let origin = OriginStub::serve_on(listener, &["206 Partial Content"], blob);
        let registry = origin_registry(origin.addr, Some(netns));

        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let blob_metadata = match kind {
                ReadKind::Ondemand => registry.read_blob_metadata(&full_blob_id),
                ReadKind::Prefetch => registry.prefetch_blob_metadata(&full_blob_id),
            }
            .unwrap();
            let mut data = vec![0u8; 16];
            match kind {
                ReadKind::Ondemand => registry.read(&full_blob_id, 17, data.len()),
                ReadKind::Prefetch => registry.prefetch(&full_blob_id, 17, data.len()),
            }
            .unwrap()
            .read_exact(&mut data)
            .unwrap();

            assert_eq!(blob_metadata.chunk_group_count(), 1);
            assert_eq!(data, payload[17..33]);
        }
        assert_eq!(origin.hits(), 6);
        assert_eq!(
            escaped.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn read_and_prefetch_reject_an_empty_or_overflowing_range() {
        let test_cases = vec![(0, 0), (u64::MAX, 2)];

        for (offset, len) in test_cases {
            let origin = OriginStub::serve(&["206 Partial Content"], b"abcd".to_vec());
            let registry = origin_registry(origin.addr, None);

            let read = registry.read(&TEST_BLOB_ID, offset, len);
            let prefetch = registry.prefetch(&TEST_BLOB_ID, offset, len);

            assert_eq!(read.err().unwrap().kind(), io::ErrorKind::InvalidInput);
            assert_eq!(prefetch.err().unwrap().kind(), io::ErrorKind::InvalidInput);
            assert_eq!(origin.hits(), 0);
        }
    }

    #[test]
    fn origin_body_that_breaks_off_fails_both_read_kinds() {
        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let origin = OriginStub::serve(&["206 Truncated"], b"abcd".to_vec());
            let registry = origin_registry(origin.addr, None);

            let mut buf = [0u8; 4];
            let result = match kind {
                ReadKind::Ondemand => registry.read(&TEST_BLOB_ID, 0, buf.len()),
                ReadKind::Prefetch => registry.prefetch(&TEST_BLOB_ID, 0, buf.len()),
            }
            .and_then(|mut reader| reader.read_exact(&mut buf));

            assert!(result.is_err());
            assert_eq!(origin.ranges(), ["bytes=0-3"]);
        }
    }

    #[cfg(feature = "dragonfly")]
    #[test]
    fn seed_peer_body_that_breaks_off_is_resumed_through_the_seed_peers() {
        let test_cases: Vec<(&'static [&'static str], fn(io::Result<Vec<u8>>))> = vec![
            (&["206 Truncated", "206 Partial Content"], |result| {
                assert_eq!(result.unwrap(), b"abcd")
            }),
            (&["206 Truncated"], |result| assert!(result.is_err())),
        ];

        for (statuses, expect) in test_cases {
            let runtime_dir = tempdir().unwrap();
            let seed_peer = OriginStub::serve(statuses, b"abcd".to_vec());
            let origin = OriginStub::serve(&["206 Partial Content"], b"abcd".to_vec());
            let cache_dir = runtime_dir.path().join("dragonfly");
            fs::create_dir(&cache_dir).unwrap();
            fs::write(
                cache_dir.join("e87f700bacfeed52.v1.json"),
                serde_json::json!({
                    "scheduler_endpoint": "http://127.0.0.1:1/",
                    "next_refresh_at": humantime_serde::re::humantime::format_rfc3339(
                        std::time::SystemTime::now() + Duration::from_secs(60)
                    )
                    .to_string(),
                    "seed_peers": [{
                        "id": "seed-peer-0",
                        "name": "seed-peer-0",
                        "hostname": "seed-peer-0",
                        "ip": "127.0.0.1",
                        "port": 1,
                        "proxy_port": seed_peer.addr.port(),
                        "healthy": true,
                    }],
                })
                .to_string(),
            )
            .unwrap();
            let config: Config = serde_yaml::from_str(&format!(
                "runtime_dir: {}\nbackend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n    dragonfly:\n      scheduler_endpoint: http://127.0.0.1:1\n      max_retries: 1\n",
                runtime_dir.path().display(),
                origin.addr
            ))
            .unwrap();
            let registry = Registry::new(&config, None, Arc::new(Metrics::new())).unwrap();

            let result = registry.read(&TEST_BLOB_ID, 0, 4).and_then(|mut reader| {
                let mut data = Vec::new();
                reader.read_to_end(&mut data).map(|_| data)
            });

            expect(result);
            assert_eq!(seed_peer.ranges(), ["bytes=0-3", "bytes=2-3"]);
            assert_eq!(origin.hits(), 0);
        }
    }

    #[test]
    fn read_records_its_metrics_once_whether_its_reader_finishes_or_drops() {
        let test_cases: Vec<(fn(Box<dyn BufRead + Send>), f64)> = vec![
            (
                |mut reader| {
                    let mut data = Vec::new();
                    reader.read_to_end(&mut data).unwrap();
                    assert_eq!(data.len(), 1 << 20);
                },
                0.0,
            ),
            (drop, 1.0),
        ];

        for (consume, failures) in test_cases {
            let origin = OriginStub::serve(&["206 Partial Content"], vec![7u8; 1 << 20]);
            let registry = origin_registry(origin.addr, None);
            let counter = |name: &str| -> f64 {
                registry
                    .metrics
                    .registry()
                    .gather()
                    .iter()
                    .filter(|family| family.get_name() == name)
                    .flat_map(|family| family.get_metric())
                    .map(|metric| metric.get_counter().get_value())
                    .sum()
            };

            consume(registry.read(&TEST_BLOB_ID, 0, 1 << 20).unwrap());
            let now = Instant::now();
            while counter("nydus_backend_read_total") + counter("nydus_backend_read_failure_total")
                < 1.0 + failures
                && now.elapsed() < Duration::from_secs(5)
            {
                thread::sleep(Duration::from_millis(10));
            }

            assert_eq!(counter("nydus_backend_read_total"), 1.0);
            assert_eq!(counter("nydus_backend_read_failure_total"), failures);
        }
    }

    #[test]
    fn dropping_the_reader_ends_a_read_whose_body_stalls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            use std::io::Write;
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            stream
                .write_all(
                    b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-3/4\r\nContent-Length: 4\r\n\r\nab",
                )
                .unwrap();
            let _ = stream.read(&mut byte);
        });
        let config: Config = serde_yaml::from_str(&format!(
            "backend:\n  type: registry\n  config:\n    addr: http://{addr}\n    repository: library/ubuntu\n    http:\n      request_timeout: 60s\n"
        ))
        .unwrap();
        let registry = Registry::new(&config, None, Arc::new(Metrics::new())).unwrap();
        let counter = |name: &str| -> f64 {
            registry
                .metrics
                .registry()
                .gather()
                .iter()
                .filter(|family| family.get_name() == name)
                .flat_map(|family| family.get_metric())
                .map(|metric| metric.get_counter().get_value())
                .sum()
        };

        let mut reader = registry.read(&TEST_BLOB_ID, 0, 4).unwrap();
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).unwrap();
        drop(reader);
        let now = Instant::now();
        while counter("nydus_backend_read_failure_total") < 1.0
            && now.elapsed() < Duration::from_secs(5)
        {
            thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(&buf, b"ab");
        assert_eq!(counter("nydus_backend_read_failure_total"), 1.0);
    }

    #[test]
    fn whole_blob_answers_from_the_origin_are_rejected_for_both_read_kinds() {
        let origin = OriginStub::serve(&["200 OK"], (0..64).collect());
        let registry = origin_registry(origin.addr, None);

        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let err = match kind {
                ReadKind::Ondemand => registry.read(&TEST_BLOB_ID, 16, 4),
                ReadKind::Prefetch => registry.prefetch(&TEST_BLOB_ID, 16, 4),
            }
            .err()
            .unwrap();

            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }
        assert_eq!(origin.hits(), 2);
    }

    #[test]
    fn whole_blob_answers_from_dragonfly_are_rejected_for_both_read_kinds() {
        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let origin = OriginStub::serve(&["206 Partial Content"], b"unused".to_vec());
            let transport =
                ScriptedTransport::new(vec![Scripted::Status(StatusCode::OK, HeaderMap::new())]);
            let registry = scripted_registry(origin.addr, None, None, transport.clone());

            let mut buf = vec![0u8; 4];
            let err = read(&registry, kind, &mut buf).unwrap_err();

            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(transport.calls(), 1);
            assert_eq!(origin.hits(), 0);
        }
    }

    #[test]
    fn whole_blob_redirected_answers_are_rejected_and_not_cached() {
        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let origin = OriginStub::serve(&["206 Partial Content"], b"unused".to_vec());
            let mut redirect = HeaderMap::new();
            redirect.insert(LOCATION, "http://cdn.example.com/signed".parse().unwrap());
            let transport = ScriptedTransport::new(vec![
                Scripted::Status(StatusCode::TEMPORARY_REDIRECT, redirect),
                Scripted::Status(StatusCode::OK, HeaderMap::new()),
            ]);
            let registry = scripted_registry(origin.addr, None, None, transport.clone());

            let mut buf = vec![0u8; 4];
            let err = read(&registry, kind, &mut buf).unwrap_err();

            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(transport.calls(), 2);
            assert!(registry
                .client
                .redirects
                .get(&hex::encode(TEST_BLOB_ID))
                .is_none());
        }
    }

    #[test]
    fn whole_blob_cached_redirect_answers_are_rejected() {
        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let origin = OriginStub::serve(&["206 Partial Content"], b"unused".to_vec());
            let transport =
                ScriptedTransport::new(vec![Scripted::Status(StatusCode::OK, HeaderMap::new())]);
            let registry = scripted_registry(origin.addr, None, None, transport.clone());
            registry.client.redirects.insert(
                &hex::encode(TEST_BLOB_ID),
                "http://cdn.example.com/signed".to_string(),
            );

            let mut buf = vec![0u8; 4];
            let err = read(&registry, kind, &mut buf).unwrap_err();

            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(transport.calls(), 1);
        }
    }

    #[cfg(feature = "dragonfly")]
    #[test]
    fn unreachable_scheduler_falls_back_to_the_origin_only_for_ondemand_reads() {
        let runtime_dir = tempdir().unwrap();
        let origin = OriginStub::serve(&["206 Partial Content"], b"abcd".to_vec());
        let config: Config = serde_yaml::from_str(&format!(
            "runtime_dir: {}\nbackend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n    dragonfly:\n      scheduler_endpoint: http://127.0.0.1:1\nprefetch:\n  request_timeout: 100ms\n",
            runtime_dir.path().display(),
            origin.addr
        ))
        .unwrap();
        let registry = Registry::new(&config, None, Arc::new(Metrics::new())).unwrap();

        let mut buf = [0u8; 4];
        read(&registry, ReadKind::Ondemand, &mut buf).unwrap();
        let prefetch = read(&registry, ReadKind::Prefetch, &mut [0u8; 4]);

        assert_eq!(&buf, b"abcd");
        assert_eq!(prefetch.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(origin.hits(), 1);
    }

    #[cfg(feature = "dragonfly")]
    #[test]
    fn fallback_reads_are_counted_under_the_dragonfly_source() {
        let runtime_dir = tempdir().unwrap();
        let origin = OriginStub::serve(&["206 Partial Content"], b"abcd".to_vec());
        let config: Config = serde_yaml::from_str(&format!(
            "runtime_dir: {}\nbackend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n    dragonfly:\n      scheduler_endpoint: http://127.0.0.1:1\n",
            runtime_dir.path().display(),
            origin.addr
        ))
        .unwrap();
        let registry = Registry::new(&config, None, Arc::new(Metrics::new())).unwrap();
        let sources = || -> Vec<String> {
            registry
                .metrics
                .registry()
                .gather()
                .iter()
                .filter(|family| family.get_name() == "nydus_backend_read_total")
                .flat_map(|family| family.get_metric())
                .flat_map(|metric| metric.get_label())
                .filter(|label| label.get_name() == "source")
                .map(|label| label.get_value().to_string())
                .collect()
        };

        let mut buf = [0u8; 4];
        registry
            .read(&TEST_BLOB_ID, 0, buf.len())
            .unwrap()
            .read_exact(&mut buf)
            .unwrap();
        let now = Instant::now();
        while sources().is_empty() && now.elapsed() < Duration::from_secs(5) {
            thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(&buf, b"abcd");
        assert_eq!(origin.hits(), 1);
        assert_eq!(sources(), ["dragonfly"]);
    }

    #[cfg(feature = "dragonfly")]
    #[test]
    fn ondemand_reads_fall_back_within_the_request_timeout_while_the_scheduler_hangs() {
        let runtime_dir = tempdir().unwrap();
        let scheduler = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = OriginStub::serve(&["206 Partial Content"], b"abcd".to_vec());
        let config: Config = serde_yaml::from_str(&format!(
            "runtime_dir: {}\nbackend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n    dragonfly:\n      scheduler_endpoint: http://{}\n      request_timeout: 100ms\n",
            runtime_dir.path().display(),
            origin.addr,
            scheduler.local_addr().unwrap()
        ))
        .unwrap();
        let registry = Registry::new(&config, None, Arc::new(Metrics::new())).unwrap();

        let now = Instant::now();
        let mut buf = [0u8; 4];
        read(&registry, ReadKind::Ondemand, &mut buf).unwrap();

        assert_eq!(&buf, b"abcd");
        assert_eq!(origin.hits(), 1);
        assert!(now.elapsed() < Duration::from_secs(2));
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
            let config: Config = serde_yaml::from_str(&format!(
                "backend:\n  type: registry\n  config:\n    addr: {addr}\n    repository: library/ubuntu\n"
            ))
            .unwrap();
            let registry = Registry::new(&config, None, Arc::new(Metrics::new())).unwrap();
            assert_eq!(registry.client.blob_url("abc123"), expected);
        }
    }

    #[test]
    fn new_builds_from_config() {
        let yaml = "
backend:
  type: registry
  config:
    addr: https://registry.example.com
    repository: library/ubuntu
    auth: YWxpY2U6c2VjcmV0
    registry_token: xyz
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let registry = Registry::new(&config, None, Arc::new(Metrics::new())).unwrap();
        assert_eq!(
            registry.client.addr.as_str(),
            "https://registry.example.com/"
        );
        let mut headers = HeaderMap::new();
        registry.client.authorizer.authorize(&mut headers);
        assert_eq!(headers[AUTHORIZATION], "Bearer xyz");
        assert!(registry.client.dragonfly.is_none());
        assert_eq!(registry.client.source(), Source::Http);
    }

    #[test]
    fn definitive_answers_are_terminal_for_both_read_kinds() {
        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            for terminal in [
                StatusCode::FORBIDDEN,
                StatusCode::NOT_FOUND,
                StatusCode::UNPROCESSABLE_ENTITY,
            ] {
                let origin = OriginStub::serve(&["206 Partial Content"], b"unused".to_vec());
                let transport =
                    ScriptedTransport::new(vec![Scripted::Status(terminal, HeaderMap::new())]);
                let registry = scripted_registry(origin.addr, None, None, transport.clone());

                let mut buf = vec![0u8; 4];
                let err = read(&registry, kind, &mut buf).unwrap_err();

                assert!(err.to_string().contains(terminal.as_str()));
                assert_eq!(transport.calls(), 1);
                assert_eq!(origin.hits(), 0);
            }
        }
    }

    #[test]
    fn origin_transient_failure_fails_an_ondemand_read_at_once() {
        let origin = OriginStub::serve(&["503 Service Unavailable"], b"busy".to_vec());
        let config: Config = serde_yaml::from_str(&format!(
            "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n    http:\n      max_retries: 0\n",
            origin.addr
        ))
        .unwrap();
        let registry = Registry::new(&config, None, Arc::new(Metrics::new())).unwrap();

        let mut buf = vec![0u8; 4];
        let err = read(&registry, ReadKind::Ondemand, &mut buf).unwrap_err();

        assert!(err.to_string().contains("503"));
        assert_eq!(origin.hits(), 1);
    }

    #[test]
    fn origin_transient_failure_retries_a_prefetch_read_once() {
        let test_cases: Vec<(&'static [&'static str], fn(io::Result<()>, [u8; 4]))> = vec![
            (
                &["503 Service Unavailable", "206 Partial Content"],
                |result, buf| {
                    result.unwrap();
                    assert_eq!(&buf, b"abcd");
                },
            ),
            (&["503 Service Unavailable"], |result, _| {
                assert!(result.unwrap_err().to_string().contains("503"));
            }),
        ];

        for (statuses, expect) in test_cases {
            let origin = OriginStub::serve(statuses, b"abcd".to_vec());
            let config: Config = serde_yaml::from_str(&format!(
                "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n    http:\n      max_retries: 0\nprefetch:\n  retry_interval: 10ms\n",
                origin.addr
            ))
            .unwrap();
            let registry = Registry::new(&config, None, Arc::new(Metrics::new())).unwrap();

            let mut buf = [0u8; 4];
            let result = registry
                .prefetch(&TEST_BLOB_ID, 0, buf.len())
                .and_then(|mut reader| reader.read_exact(&mut buf));

            expect(result, buf);
            assert_eq!(origin.ranges(), ["bytes=0-3", "bytes=0-3"]);
        }
    }

    #[test]
    fn unauthorized_answer_triggers_the_auth_handshake() {
        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let body = b"authorized".to_vec();
            let origin = OriginStub::serve(&["206 Partial Content"], b"unused".to_vec());
            let mut challenge = HeaderMap::new();
            challenge.insert(
                WWW_AUTHENTICATE,
                r#"Basic realm="registry""#.parse().unwrap(),
            );
            let transport = ScriptedTransport::new(vec![
                Scripted::Status(StatusCode::UNAUTHORIZED, challenge),
                Scripted::Body(body.clone()),
            ]);
            let registry = scripted_registry(
                origin.addr,
                Some("YWxpY2U6c2VjcmV0"),
                None,
                transport.clone(),
            );

            let mut buf = vec![0u8; body.len()];
            read(&registry, kind, &mut buf).unwrap();

            assert_eq!(buf, body);
            assert_eq!(transport.calls(), 2);
            assert_eq!(origin.hits(), 0);
            let mut authorized = HeaderMap::new();
            registry.client.authorizer.authorize(&mut authorized);
            assert_eq!(authorized[AUTHORIZATION], "Basic YWxpY2U6c2VjcmV0");
        }
    }

    #[test]
    fn configured_bearer_token_skips_the_auth_handshake() {
        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let body = b"authorized".to_vec();
            let origin = OriginStub::serve(&["206 Partial Content"], b"unused".to_vec());
            let transport = ScriptedTransport::new(vec![Scripted::Body(body.clone())]);
            let registry = scripted_registry(
                origin.addr,
                Some("YWxpY2U6c2VjcmV0"),
                Some("xyz"),
                transport.clone(),
            );

            let mut buf = vec![0u8; body.len()];
            read(&registry, kind, &mut buf).unwrap();

            assert_eq!(buf, body);
            assert_eq!(origin.hits(), 0);
            let headers = transport.headers();
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0][AUTHORIZATION], "Bearer xyz");
        }
    }

    #[test]
    fn refused_configured_bearer_token_is_replaced_through_the_auth_handshake() {
        let test_cases: Vec<(fn(SocketAddr) -> String, &str, u32)> = vec![
            (
                |_| r#"Basic realm="registry""#.to_string(),
                "Basic YWxpY2U6c2VjcmV0",
                0,
            ),
            (
                |addr| format!(r#"Bearer realm="http://{addr}/token",service="registry""#),
                "Bearer abc",
                1,
            ),
        ];

        for (challenge, expected, fetches) in test_cases {
            for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
                let body = b"authorized".to_vec();
                let origin =
                    OriginStub::serve(&["200 OK"], br#"{"token":"abc","expires_in":300}"#.to_vec());
                let mut unauthorized = HeaderMap::new();
                unauthorized.insert(WWW_AUTHENTICATE, challenge(origin.addr).parse().unwrap());
                let transport = ScriptedTransport::new(vec![
                    Scripted::Status(StatusCode::UNAUTHORIZED, unauthorized.clone()),
                    Scripted::Status(StatusCode::UNAUTHORIZED, unauthorized),
                    Scripted::Body(body.clone()),
                ]);
                let registry = scripted_registry(
                    origin.addr,
                    Some("YWxpY2U6c2VjcmV0"),
                    Some("xyz"),
                    transport.clone(),
                );

                let mut buf = vec![0u8; body.len()];
                read(&registry, kind, &mut buf).unwrap();

                assert_eq!(buf, body);
                assert_eq!(origin.hits(), fetches);
                let headers = transport.headers();
                assert_eq!(headers.len(), 3);
                assert_eq!(headers[0][AUTHORIZATION], "Bearer xyz");
                assert_eq!(headers[1].get(AUTHORIZATION), None);
                assert_eq!(headers[2][AUTHORIZATION], expected);
            }
        }
    }

    #[test]
    fn read_blob_metadata_fetches_the_footer_through_the_transport() {
        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let origin = OriginStub::serve(&["206 Partial Content"], b"unused".to_vec());
            let transport = ScriptedTransport::new(vec![Scripted::Status(
                StatusCode::NOT_FOUND,
                HeaderMap::new(),
            )]);
            let registry = scripted_registry(origin.addr, None, None, transport.clone());

            let err = match kind {
                ReadKind::Ondemand => registry.read_blob_metadata(&TEST_BLOB_ID),
                ReadKind::Prefetch => registry.prefetch_blob_metadata(&TEST_BLOB_ID),
            }
            .unwrap_err();

            assert!(err.to_string().contains("404"));
            assert_eq!(origin.hits(), 0);
            assert_eq!(transport.calls(), 1);
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
            None,
            gate.clone(),
        ));

        let readers: Vec<_> = (0..2)
            .map(|_| {
                let registry = registry.clone();
                thread::spawn(move || {
                    let mut buf = [0u8; 2];
                    registry
                        .read(&TEST_BLOB_ID, 0, buf.len())
                        .unwrap()
                        .read_exact(&mut buf)
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
        let origin = OriginStub::serve(&["206 Partial Content"], b"unused".to_vec());
        let transport = ScriptedTransport::new(vec![Scripted::Body(body.clone())]);
        let registry = scripted_registry(origin.addr, None, None, transport.clone());
        let hex = hex::encode(TEST_BLOB_ID);
        registry
            .client
            .redirects
            .insert(&hex, "http://cdn.example.com/signed".to_string());

        let mut buf = vec![0u8; body.len()];
        read(&registry, ReadKind::Ondemand, &mut buf).unwrap();

        assert_eq!(buf, body);
        assert_eq!(transport.calls(), 1);
        assert_eq!(origin.hits(), 0);
    }

    #[test]
    fn forbidden_cached_redirect_is_evicted_and_re_resolved() {
        let body = b"fresh".to_vec();
        let origin = OriginStub::serve(&["206 Partial Content"], b"unused".to_vec());
        let transport = ScriptedTransport::new(vec![
            Scripted::Status(StatusCode::FORBIDDEN, HeaderMap::new()),
            Scripted::Body(body.clone()),
        ]);
        let registry = scripted_registry(origin.addr, None, None, transport.clone());
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
