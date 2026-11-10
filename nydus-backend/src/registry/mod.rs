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
use bytes::Bytes;
use futures::StreamExt;
use reqwest::header::{HeaderMap, AUTHORIZATION, RANGE, WWW_AUTHENTICATE};
use reqwest::StatusCode;
use tokio::sync::mpsc;
use tracing::warn;
use url::Url;

use nydus_config::{BackendConfig, Config};
use nydus_format::blob::{BlobFooter, BlobMetadata};
use nydus_format::utils::SHA256_DIGEST_SIZE;
use nydus_telemetry::metrics::Metrics;

use crate::{Backend, Netns, ReadKind, Source};

use self::auth::{Authorizer, Challenge};
#[cfg(feature = "dragonfly")]
use self::dragonfly::Dragonfly;
use self::http::Http;
use self::range::Range;
use self::redirect::RedirectCache;
use self::response::Response;
pub use self::rt::Runtime;

/// Pieces of a streamed range the network may run ahead of the reader by:
/// the bound on the bytes a range read holds between the two.
const STREAM_PIECES: usize = 8;

/// Times a range read whose body broke off is sent again for the bytes still
/// missing.
const BODY_RESUMES: u32 = 2;

/// The transport of blob `GET`s, the origin or the Dragonfly seed peers, each
/// call returning after the transport's own retries, the body still
/// streaming: a body that breaks off is resumed by [`Client::stream_range`].
#[async_trait]
trait Transport: Send + Sync {
    /// Sends the `GET` of an on-demand read, which a FUSE reader waits on.
    async fn get(&self, url: &str, headers: HeaderMap) -> io::Result<Response>;

    /// Sends the `GET` of a prefetch read, once more after the retry interval
    /// on a `429`, `5xx` or `408`.
    async fn prefetch(&self, url: &str, headers: HeaderMap) -> io::Result<Response>;
}

/// The blob backend over an OCI registry, running the reads of [`Client`] on
/// [`Runtime`] while the caller waits.
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
            if registry.http.proxy.is_some() {
                Source::Proxy
            } else {
                Source::Origin
            },
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
                authorizer: Authorizer::new(registry.auth.as_deref())?,
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
    /// Returns the `source` label of a failed read: Dragonfly when configured,
    /// otherwise the origin client's.
    fn source(&self) -> Source {
        if self.dragonfly.is_some() {
            Source::Dragonfly
        } else {
            self.http.source()
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

    /// Streams `len` bytes of a blob from `offset` for a `kind` read into
    /// `pieces`, piece by piece as they arrive, and returns where they came
    /// from. A body that breaks off is asked for again from the first byte
    /// still missing, at most [`BODY_RESUMES`] times; a reader that hangs up
    /// ends the read early.
    async fn stream_range(
        &self,
        blob_id: [u8; SHA256_DIGEST_SIZE],
        offset: u64,
        len: u64,
        kind: ReadKind,
        pieces: mpsc::Sender<Bytes>,
    ) -> io::Result<Source> {
        let end = offset + len;
        let mut pos = offset;
        let mut resumes = 0;
        loop {
            let range = Range::Bounded(pos..=end - 1);
            let response = match kind {
                ReadKind::Ondemand => self.read_range(&blob_id, &range).await?,
                ReadKind::Prefetch => self.prefetch_range(&blob_id, &range).await?,
            };
            let source = response.source;
            let mut body = response.into_stream();
            let broke = loop {
                match body.next().await {
                    Some(Ok(piece)) => {
                        if piece.len() as u64 > end - pos {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("registry returned more than the {len} bytes asked for"),
                            ));
                        }
                        pos += piece.len() as u64;
                        if !piece.is_empty() && pieces.send(piece).await.is_err() {
                            return Ok(source);
                        }
                    }
                    Some(Err(err)) => break err,
                    None if pos == end => return Ok(source),
                    None => {
                        break io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!(
                                "early eof: registry returned {} of {len} bytes",
                                pos - offset
                            ),
                        )
                    }
                }
            };
            if pos == end {
                return Ok(source);
            }
            if resumes == BODY_RESUMES {
                return Err(broke);
            }
            resumes += 1;
            warn!(
                "blob {} body broke off at byte {pos} of {offset}..{end}, asking for the rest: {broke}",
                hex::encode(blob_id)
            );
        }
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

    /// Fills `buf` with the blob bytes from `offset` for an on-demand read.
    fn read_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        buf: &mut [u8],
    ) -> io::Result<()> {
        self.read_into(blob_id, offset, buf, ReadKind::Ondemand)
    }

    /// Fills `buf` with the blob bytes from `offset` for a prefetch read.
    fn prefetch_range_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        buf: &mut [u8],
    ) -> io::Result<()> {
        self.read_into(blob_id, offset, buf, ReadKind::Prefetch)
    }

    /// Streams the range into `sink` as the body arrives, the network
    /// running at most [`STREAM_PIECES`] pieces ahead, and records the read's
    /// metrics; a `sink` error stops the read and is not the backend's.
    fn read_range_with(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        len: u64,
        kind: ReadKind,
        sink: &mut dyn FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        if len == 0 {
            return Ok(());
        }
        if offset.checked_add(len).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "blob range offset overflow",
            ));
        }

        let start = Instant::now();
        let (pieces, mut received) = mpsc::channel(STREAM_PIECES);
        let client = self.client.clone();
        let blob_id = *blob_id;
        let task = self.runtime.start(async move {
            client
                .stream_range(blob_id, offset, len, kind, pieces)
                .await
        });

        let mut streamed = 0u64;
        while let Some(piece) = received.blocking_recv() {
            streamed += piece.len() as u64;
            if let Err(err) = sink(&piece) {
                task.abort();
                return Err(err);
            }
        }

        match self.runtime.wait(task) {
            Ok(source) if streamed == len => {
                self.metrics.backend.collect_read_finished_metrics(
                    kind,
                    source,
                    len,
                    start.elapsed(),
                );
                Ok(())
            }
            result => {
                self.metrics
                    .backend
                    .collect_read_failure_metrics(kind, self.client.source());
                Err(result.err().unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("registry returned {streamed} of {len} bytes"),
                    )
                }))
            }
        }
    }
}

/// Implements the buffered reads over the streamed one.
impl Registry {
    /// Fills `buf` with the blob bytes from `offset` for a `kind` read.
    fn read_into(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        offset: u64,
        buf: &mut [u8],
        kind: ReadKind,
    ) -> io::Result<()> {
        let mut filled = 0;
        self.read_range_with(blob_id, offset, buf.len() as u64, kind, &mut |piece| {
            buf[filled..filled + piece.len()].copy_from_slice(piece);
            filled += piece.len();
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::range::ContentRange;
    use super::response::Body;
    use super::*;
    use nydus_config::{HttpConfig, PrefetchConfig};
    use nydus_test_utils::blob::FullBlob;
    use nydus_test_utils::metadata::single_chunk_group;
    use reqwest::header::{CONTENT_RANGE, LOCATION};
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
                        body: Body::streamed(body),
                        source: Source::Dragonfly,
                    })
                }
                Scripted::Status(status, headers) => Ok(Response {
                    status,
                    headers,
                    body: Body::streamed(Vec::new()),
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
                let mut headers = HeaderMap::new();
                headers.insert(CONTENT_RANGE, "bytes 0-1/2".parse().unwrap());
                return Ok(Response {
                    status: StatusCode::PARTIAL_CONTENT,
                    headers,
                    body: Body::streamed(b"ok".to_vec()),
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
                body: Body::streamed(Vec::new()),
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
            response.extend_from_slice(body);
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

    /// A transport serving the bytes `0..` of a 256-byte blob, each answer to
    /// the requested range breaking off after `cut` bytes while cuts are left.
    struct BreakingTransport {
        cuts: Mutex<VecDeque<usize>>,
        ranges: Mutex<Vec<String>>,
    }

    impl BreakingTransport {
        fn new(cuts: impl IntoIterator<Item = usize>) -> Arc<BreakingTransport> {
            Arc::new(BreakingTransport {
                cuts: Mutex::new(cuts.into_iter().collect()),
                ranges: Mutex::new(Vec::new()),
            })
        }

        fn ranges(&self) -> Vec<String> {
            self.ranges.lock().unwrap().clone()
        }

        fn answer(&self, headers: &HeaderMap) -> io::Result<Response> {
            let range = headers[RANGE].to_str().unwrap().to_string();
            self.ranges.lock().unwrap().push(range.clone());
            let Range::Bounded(bounds) = range.parse::<Range>().unwrap() else {
                unreachable!("streamed reads ask for bounded ranges");
            };
            let bytes: Vec<u8> = (*bounds.start() as u8..=*bounds.end() as u8).collect();
            let mut pieces: Vec<io::Result<Bytes>> = bytes
                .chunks(2)
                .map(|piece| Ok(Bytes::copy_from_slice(piece)))
                .collect();
            if let Some(cut) = self.cuts.lock().unwrap().pop_front() {
                pieces.truncate(cut / 2);
                pieces.push(Err(io::Error::new(io::ErrorKind::ConnectionReset, "reset")));
            }
            let mut headers = HeaderMap::new();
            headers.insert(
                CONTENT_RANGE,
                format!("bytes {}-{}/256", bounds.start(), bounds.end())
                    .parse()
                    .unwrap(),
            );
            Ok(Response {
                status: StatusCode::PARTIAL_CONTENT,
                headers,
                body: Body::Stream(futures::stream::iter(pieces).boxed()),
                source: Source::Dragonfly,
            })
        }
    }

    #[async_trait]
    impl Transport for Arc<BreakingTransport> {
        async fn get(&self, _url: &str, headers: HeaderMap) -> io::Result<Response> {
            self.answer(&headers)
        }

        async fn prefetch(&self, _url: &str, headers: HeaderMap) -> io::Result<Response> {
            self.answer(&headers)
        }
    }

    /// The backend reads and bytes `registry` recorded for `kind`.
    fn backend_reads(registry: &Registry, kind: ReadKind) -> (u64, u64) {
        let sum = |name: &str| -> u64 {
            registry
                .metrics
                .registry()
                .gather()
                .iter()
                .filter(|family| family.get_name() == name)
                .flat_map(|family| family.get_metric())
                .filter(|metric| {
                    metric.get_label().iter().any(|label| {
                        label.get_name() == "type" && label.get_value() == kind.to_string()
                    })
                })
                .map(|metric| metric.get_counter().get_value() as u64)
                .sum()
        };
        (
            sum("nydus_backend_read_total"),
            sum("nydus_backend_read_bytes_total"),
        )
    }

    #[test]
    fn a_broken_body_is_resumed_from_the_first_missing_byte() {
        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let transport = BreakingTransport::new([4, 2]);
            let registry =
                scripted_registry("127.0.0.1:9".parse().unwrap(), None, transport.clone());
            let mut pieces = Vec::new();
            registry
                .read_range_with(&TEST_BLOB_ID, 16, 12, kind, &mut |piece| {
                    pieces.push(piece.to_vec());
                    Ok(())
                })
                .unwrap();

            assert_eq!(pieces.concat(), (16..28).collect::<Vec<u8>>(), "{kind:?}");
            assert_eq!(
                transport.ranges(),
                ["bytes=16-27", "bytes=20-27", "bytes=22-27"],
                "{kind:?}"
            );
            assert_eq!(backend_reads(&registry, kind), (1, 12), "{kind:?}");
        }
    }

    #[test]
    fn a_body_breaking_off_past_the_resumes_fails_the_read() {
        let transport = BreakingTransport::new([2, 2, 2]);
        let registry = scripted_registry("127.0.0.1:9".parse().unwrap(), None, transport.clone());
        let mut buf = [0u8; 8];

        let err = registry
            .read_range_into(&TEST_BLOB_ID, 0, &mut buf)
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(transport.ranges().len(), 1 + BODY_RESUMES as usize);
    }

    #[test]
    fn a_failing_sink_stops_the_read_with_its_error() {
        let transport = BreakingTransport::new([]);
        let registry = scripted_registry("127.0.0.1:9".parse().unwrap(), None, transport);
        let mut calls = 0;

        let err = registry
            .read_range_with(&TEST_BLOB_ID, 0, 16, ReadKind::Ondemand, &mut |_| {
                calls += 1;
                Err(io::Error::new(io::ErrorKind::InvalidData, "bad group"))
            })
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(calls, 1);
    }

    fn origin_registry(addr: SocketAddr, netns: Option<Netns>) -> Registry {
        let config: Config = serde_yaml::from_str(&format!(
            "backend:\n  type: registry\n  config:\n    addr: http://{addr}\n    repository: library/ubuntu\n"
        ))
        .unwrap();
        Registry::new(&config, netns, Arc::new(Metrics::new())).unwrap()
    }

    fn read(registry: &Registry, kind: ReadKind, buf: &mut [u8]) -> io::Result<Source> {
        registry.runtime.tokio().block_on(async {
            let client = &registry.client;
            let range = Range::Bounded(0..=buf.len() as u64 - 1);
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
                ReadKind::Ondemand => registry.read_range_into(&full_blob_id, 17, &mut data),
                ReadKind::Prefetch => registry.prefetch_range_into(&full_blob_id, 17, &mut data),
            }
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
                ReadKind::Ondemand => registry.read_range_into(&full_blob_id, 17, &mut data),
                ReadKind::Prefetch => registry.prefetch_range_into(&full_blob_id, 17, &mut data),
            }
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
    fn whole_blob_answers_from_the_origin_are_rejected_for_both_read_kinds() {
        let origin = OriginStub::serve(&["200 OK"], (0..64).collect());
        let registry = origin_registry(origin.addr, None);

        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let mut buf = [0u8; 4];
            let err = match kind {
                ReadKind::Ondemand => registry.read_range_into(&TEST_BLOB_ID, 16, &mut buf),
                ReadKind::Prefetch => registry.prefetch_range_into(&TEST_BLOB_ID, 16, &mut buf),
            }
            .unwrap_err();

            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(buf, [0u8; 4]);
        }
        assert_eq!(origin.hits(), 2);
    }

    #[test]
    fn whole_blob_answers_from_dragonfly_are_rejected_for_both_read_kinds() {
        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let origin = OriginStub::serve(&["206 Partial Content"], b"unused".to_vec());
            let transport =
                ScriptedTransport::new(vec![Scripted::Status(StatusCode::OK, HeaderMap::new())]);
            let registry = scripted_registry(origin.addr, None, transport.clone());

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
            let registry = scripted_registry(origin.addr, None, transport.clone());

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
            let registry = scripted_registry(origin.addr, None, transport.clone());
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
        let ondemand = read(&registry, ReadKind::Ondemand, &mut buf).unwrap();
        let prefetch = read(&registry, ReadKind::Prefetch, &mut [0u8; 4]);

        assert_eq!(ondemand, Source::Fallback);
        assert_eq!(&buf, b"abcd");
        assert_eq!(prefetch.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(origin.hits(), 1);
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

        let start = Instant::now();
        let mut buf = [0u8; 4];
        let ondemand = read(&registry, ReadKind::Ondemand, &mut buf).unwrap();

        assert_eq!(ondemand, Source::Fallback);
        assert_eq!(&buf, b"abcd");
        assert!(start.elapsed() < Duration::from_secs(2));
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
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let registry = Registry::new(&config, None, Arc::new(Metrics::new())).unwrap();
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
                let origin = OriginStub::serve(&["206 Partial Content"], b"unused".to_vec());
                let transport =
                    ScriptedTransport::new(vec![Scripted::Status(terminal, HeaderMap::new())]);
                let registry = scripted_registry(origin.addr, None, transport.clone());

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
            let result = registry.prefetch_range_into(&TEST_BLOB_ID, 0, &mut buf);

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
            let registry =
                scripted_registry(origin.addr, Some("YWxpY2U6c2VjcmV0"), transport.clone());

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
    fn read_blob_metadata_fetches_the_footer_through_the_transport() {
        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let origin = OriginStub::serve(&["206 Partial Content"], b"unused".to_vec());
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
        let origin = OriginStub::serve(&["206 Partial Content"], b"unused".to_vec());
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
        let origin = OriginStub::serve(&["206 Partial Content"], b"unused".to_vec());
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
