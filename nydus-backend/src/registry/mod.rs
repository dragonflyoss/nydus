//! The OCI registry backend: blobs addressed by their full blob digest and
//! served in byte ranges, over the origin, a proxy or the Dragonfly seed
//! peers.
//!
//! ```text
//! mod.rs       Registry    the blob backend: runs the reads on the runtime, streams them, counts them
//! client.rs    Client      the registry protocol: the blob URL, the auth handshake, the redirects
//! transport/   Transport   how one `GET` is sent: the origin, a proxy, the seed peers, the fallback
//! ```

mod auth;
mod client;
mod range;
mod reader;
mod redirect;
mod response;
mod rt;
mod transport;

use std::io::{self, BufRead};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{TryFutureExt, TryStreamExt};
use tracing::debug;

use nydus_config::{Config, RedactedString, RegistryConfig};
use nydus_format::blob::{BlobFooter, BlobMetadata};
use nydus_format::utils::SHA256_DIGEST_SIZE;
use nydus_telemetry::metrics::Metrics;

use crate::{Backend, Netns, ReadKind, Source};

use self::auth::Authorizer;
use self::client::Client;
use self::range::Range;
use self::reader::StreamReader;
use self::redirect::RedirectCache;
pub use self::rt::Runtime;
#[cfg(feature = "dragonfly")]
use self::transport::Dragonfly;
use self::transport::{Fetcher, Http, RateLimit, Transport};

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
///        ├─ Transport       the transport of token fetches, never Dragonfly
///        │    ├─ http.proxy ──▶ Fallback: the proxy, then the origin
///        │    └─ otherwise ───▶ Direct: the origin
///        └─ Transport       the transport of blob GETs, by the configuration
///             ├─ dragonfly ───▶ Fallback: the seed peers, then the origin
///             ├─ http.proxy ──▶ Fallback: the proxy, then the origin
///             └─ neither ─────▶ Direct: the origin
/// ```
pub(crate) struct Registry {
    /// The registry client, shared with the task of each read.
    client: Arc<Client>,

    /// The runtime every read runs on.
    runtime: Arc<Runtime>,

    /// The metrics of the image the backend serves.
    metrics: Arc<Metrics>,
}

/// Implements the registry backend construction.
impl Registry {
    /// Creates the registry backend `registry` configures.
    pub(crate) fn new(
        config: &Config,
        registry: &RegistryConfig,
        netns: Option<Netns>,
        metrics: Arc<Metrics>,
    ) -> io::Result<Self> {
        let runtime = Arc::new(Runtime::new(netns)?);

        // Read through Dragonfly when configured, else through the proxy when
        // configured, both falling back to the origin, else from the origin.
        let (auth_transport, transport): (Transport, Transport) =
            match (&registry.dragonfly, &registry.http.proxy) {
                #[cfg(feature = "dragonfly")]
                (Some(dragonfly), _) => {
                    let http_client = Http::new(
                        registry.http.request_timeout,
                        registry.http.request_read_timeout,
                        registry.http.max_retries,
                        None,
                        &registry.http.tls,
                        None,
                    )?;

                    let fallback_http_client = Http::new(
                        registry.fallback.request_timeout,
                        registry.fallback.request_read_timeout,
                        registry.fallback.max_retries,
                        None,
                        &registry.http.tls,
                        Some(RateLimit::new(
                            registry.fallback.rate_limit,
                            Duration::from_secs(1),
                        )),
                    )?;

                    let dragonfly = Dragonfly::new(config, dragonfly, &runtime)?;
                    let auth_transport = Transport::Direct {
                        fetcher: Box::new(http_client),
                    };
                    let transport = Transport::Fallback {
                        fetcher: Box::new(dragonfly),
                        fallback_http_client,
                    };
                    (auth_transport, transport)
                }
                (None, Some(proxy)) => {
                    let http_client = Http::new(
                        registry.http.request_timeout,
                        registry.http.request_read_timeout,
                        registry.http.max_retries,
                        Some(proxy),
                        &registry.http.tls,
                        None,
                    )?;

                    let fallback_http_client = Http::new(
                        registry.fallback.request_timeout,
                        registry.fallback.request_read_timeout,
                        registry.fallback.max_retries,
                        None,
                        &registry.http.tls,
                        Some(RateLimit::new(
                            registry.fallback.rate_limit,
                            Duration::from_secs(1),
                        )),
                    )?;

                    let auth_transport = Transport::Fallback {
                        fetcher: Box::new(http_client.clone()),
                        fallback_http_client: fallback_http_client.clone(),
                    };
                    let transport = Transport::Fallback {
                        fetcher: Box::new(http_client),
                        fallback_http_client,
                    };
                    (auth_transport, transport)
                }
                _ => {
                    let http_client = Http::new(
                        registry.http.request_timeout,
                        registry.http.request_read_timeout,
                        registry.http.max_retries,
                        None,
                        &registry.http.tls,
                        None,
                    )?;

                    let auth_transport = Transport::Direct {
                        fetcher: Box::new(http_client.clone()),
                    };
                    let transport = Transport::Direct {
                        fetcher: Box::new(http_client),
                    };
                    (auth_transport, transport)
                }
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
                prefetch_retry_interval: config.prefetch.retry_interval
                    ..=config.prefetch.retry_interval.saturating_mul(2),
                auth_transport,
                transport,
            }),
            runtime,
            metrics,
        })
    }
}

/// Implements the blob backend over the registry.
impl Backend for Registry {
    /// Returns the metrics of the image.
    fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// Reads the blob's metadata for an on-demand read.
    ///
    /// ```text
    /// GET bytes=-<footer size> ──▶ footer, Content-Range: bytes .../<blob size>
    /// GET bytes=<blob meta range in the footer> ──▶ blob meta
    /// ```
    fn get_blob_metadata(&self, blob_id: &[u8; SHA256_DIGEST_SIZE]) -> io::Result<BlobMetadata> {
        let client = self.client.clone();
        let blob_id = *blob_id;
        self.runtime.block_on_worker(async move {
            let response = client
                .get(&blob_id, &Range::Suffix(BlobFooter::SIZE as u64))
                .await?;
            if !response.status.is_success() {
                return Err(response.into_io_error().await);
            }

            let footer_offset = BlobFooter::calculate_offset_by_blob_size(
                response.content_range()?.complete_length,
            )
            .map_err(io::Error::other)?;

            let footer_bytes = response.bytes(BlobFooter::SIZE).await?;
            let footer =
                BlobFooter::from_bytes(footer_bytes.as_ref().try_into().map_err(io::Error::other)?)
                    .map_err(io::Error::other)?;
            footer
                .validate_layout(footer_offset)
                .map_err(io::Error::other)?;

            let blob_metadata_size =
                usize::try_from(footer.blob_metadata_size()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "blob meta size exceeds usize")
                })?;
            let blob_metadata_end = footer.offset().map_err(io::Error::other)?.saturating_sub(1);
            let response = client
                .get(
                    &blob_id,
                    &Range::Bounded(footer.blob_metadata_offset()..=blob_metadata_end),
                )
                .await?;
            if !response.status.is_success() {
                return Err(response.into_io_error().await);
            }

            let blob_metadata_bytes = response.bytes(blob_metadata_size).await?;
            BlobMetadata::from_bytes(blob_metadata_bytes.into()).map_err(io::Error::other)
        })
    }

    /// Reads the blob's metadata for a prefetch read, like
    /// [`Registry::get_blob_metadata`].
    fn prefetch_blob_metadata(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
    ) -> io::Result<BlobMetadata> {
        let client = self.client.clone();
        let blob_id = *blob_id;
        self.runtime.block_on_worker(async move {
            let response = client
                .prefetch(&blob_id, &Range::Suffix(BlobFooter::SIZE as u64))
                .await?;
            let footer_offset = BlobFooter::calculate_offset_by_blob_size(
                response.content_range()?.complete_length,
            )
            .map_err(io::Error::other)?;

            let footer_bytes = response.bytes(BlobFooter::SIZE).await?;
            let footer =
                BlobFooter::from_bytes(footer_bytes.as_ref().try_into().map_err(io::Error::other)?)
                    .map_err(io::Error::other)?;
            footer
                .validate_layout(footer_offset)
                .map_err(io::Error::other)?;

            let blob_metadata_size =
                usize::try_from(footer.blob_metadata_size()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "blob meta size exceeds usize")
                })?;
            let blob_metadata_end = footer.offset().map_err(io::Error::other)?.saturating_sub(1);
            let blob_metadata_bytes = client
                .prefetch(
                    &blob_id,
                    &Range::Bounded(footer.blob_metadata_offset()..=blob_metadata_end),
                )
                .await?
                .bytes(blob_metadata_size)
                .await?;

            BlobMetadata::from_bytes(blob_metadata_bytes.into()).map_err(io::Error::other)
        })
    }

    /// Reads `len` blob bytes from `offset` for an on-demand read, streaming.
    fn get(
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
            .block_on_worker(async move { client.get(&blob_id, &range).await })
            .inspect_err(|_| {
                self.metrics.backend.collect_read_failure_metrics(
                    ReadKind::Ondemand,
                    self.client.transport.source(),
                )
            })?;

        // Fail on an answer that is not the range.
        if !response.status.is_success() {
            let source = if response.fallback.load(Ordering::Relaxed) {
                Source::Fallback
            } else {
                self.client.transport.source()
            };

            self.metrics
                .backend
                .collect_read_failure_metrics(ReadKind::Ondemand, source);
            return self
                .runtime
                .block_on_worker(async move { Err(response.into_io_error().await) });
        }

        let source = self.client.transport.source();
        let fallback = response.fallback.clone();
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

            let source = if fallback.load(Ordering::Relaxed) {
                Source::Fallback
            } else {
                source
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
            .block_on_worker(async move { client.prefetch(&blob_id, &range).await })
            .inspect_err(|_| {
                self.metrics.backend.collect_read_failure_metrics(
                    ReadKind::Prefetch,
                    self.client.transport.source(),
                )
            })?;

        let source = self.client.transport.source();
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
    use super::response::Response;
    use super::*;
    use async_trait::async_trait;
    use bytes::Bytes;
    use futures::stream::{self, StreamExt};
    use nydus_config::BackendConfig;
    use nydus_test_utils::blob::FullBlob;
    use nydus_test_utils::metadata::single_chunk_group;
    use reqwest::header::{HeaderMap, AUTHORIZATION, CONTENT_RANGE, LOCATION, WWW_AUTHENTICATE};
    use reqwest::StatusCode;
    use std::collections::VecDeque;
    use std::fs;
    use std::io::Read;
    use std::net::{SocketAddr, TcpListener};
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;
    use tempfile::tempdir;
    use url::Url;

    const TEST_BLOB_ID: [u8; SHA256_DIGEST_SIZE] = [7u8; SHA256_DIGEST_SIZE];

    #[async_trait]
    impl<T: Fetcher> Fetcher for Arc<T> {
        async fn get(&self, url: &Url, headers: HeaderMap) -> io::Result<Response> {
            (**self).get(url, headers).await
        }

        async fn prefetch(&self, url: &Url, headers: HeaderMap) -> io::Result<Response> {
            (**self).prefetch(url, headers).await
        }

        fn source(&self) -> Source {
            (**self).source()
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
                        fallback: Arc::default(),
                    })
                }
                Scripted::Status(status, headers) => Ok(Response {
                    status,
                    headers,
                    body: stream::empty().boxed(),
                    fallback: Arc::default(),
                }),
            }
        }
    }

    #[async_trait]
    impl Fetcher for ScriptedTransport {
        async fn get(&self, _url: &Url, headers: HeaderMap) -> io::Result<Response> {
            self.headers.lock().unwrap().push(headers);
            self.play()
        }

        async fn prefetch(&self, _url: &Url, headers: HeaderMap) -> io::Result<Response> {
            self.headers.lock().unwrap().push(headers);
            self.play()
        }

        fn source(&self) -> Source {
            Source::Dragonfly
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
                    fallback: Arc::default(),
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
                fallback: Arc::default(),
            })
        }
    }

    #[async_trait]
    impl Fetcher for AuthGate {
        async fn get(&self, _url: &Url, headers: HeaderMap) -> io::Result<Response> {
            self.answer(headers).await
        }

        async fn prefetch(&self, _url: &Url, headers: HeaderMap) -> io::Result<Response> {
            self.answer(headers).await
        }

        fn source(&self) -> Source {
            Source::Dragonfly
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

            let host = request
                .lines()
                .find_map(|line| line.strip_prefix("host: "))
                .unwrap_or_default();
            let header = match status {
                "307 Temporary Redirect" => format!("Location: http://{host}/redirected\r\n"),
                "401 Unauthorized" => "WWW-Authenticate: Basic realm=\"registry\"\r\n".to_string(),
                "401 Bearer" => {
                    format!("WWW-Authenticate: Bearer realm=\"http://{host}/token\"\r\n")
                }
                _ => String::new(),
            };

            let mut response = format!(
                "HTTP/1.1 {status}\r\n{content_range}{header}Content-Length: {}\r\nConnection: close\r\n\r\n",
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
        let config: Config = serde_yaml::from_str(&format!(
            "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n",
            origin.addr
        ))
        .unwrap();
        let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();

        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let blob_metadata = match kind {
                ReadKind::Ondemand => registry.get_blob_metadata(&full_blob_id),
                ReadKind::Prefetch => registry.prefetch_blob_metadata(&full_blob_id),
            }
            .unwrap();
            let mut data = vec![0u8; 16];
            match kind {
                ReadKind::Ondemand => registry.get(&full_blob_id, 17, data.len()),
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
        let config: Config = serde_yaml::from_str(&format!(
            "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n",
            origin.addr
        ))
        .unwrap();
        let registry = <dyn Backend>::new(&config, Some(netns), Arc::new(Metrics::new())).unwrap();

        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let blob_metadata = match kind {
                ReadKind::Ondemand => registry.get_blob_metadata(&full_blob_id),
                ReadKind::Prefetch => registry.prefetch_blob_metadata(&full_blob_id),
            }
            .unwrap();
            let mut data = vec![0u8; 16];
            match kind {
                ReadKind::Ondemand => registry.get(&full_blob_id, 17, data.len()),
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
            let config: Config = serde_yaml::from_str(&format!(
                "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n",
                origin.addr
            ))
            .unwrap();
            let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();

            let read = registry.get(&TEST_BLOB_ID, offset, len);
            let prefetch = registry.prefetch(&TEST_BLOB_ID, offset, len);

            assert_eq!(read.err().unwrap().kind(), io::ErrorKind::InvalidInput);
            assert_eq!(prefetch.err().unwrap().kind(), io::ErrorKind::InvalidInput);
            assert_eq!(origin.hits(), 0);
        }
    }

    #[test]
    fn origin_read_times_out_a_slow_reader_by_the_request_timeout_only() {
        let test_cases: Vec<(&str, fn(io::Result<usize>))> = vec![
            ("request_read_timeout: 1s", |result| {
                assert_eq!(result.unwrap(), (32 << 20) - 1)
            }),
            ("request_timeout: 1s", |result| assert!(result.is_err())),
        ];

        for (timeout, expect) in test_cases {
            let blob = vec![7u8; 32 << 20];
            let origin = OriginStub::serve(&["206 Partial Content"], blob.clone());
            let config: Config = serde_yaml::from_str(&format!(
                "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n    http:\n      {timeout}\n",
                origin.addr
            ))
            .unwrap();
            let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();

            let mut reader = registry.get(&TEST_BLOB_ID, 0, blob.len()).unwrap();
            let mut head = [0u8; 1];
            reader.read_exact(&mut head).unwrap();
            thread::sleep(Duration::from_millis(1500));
            let mut tail = Vec::new();
            expect(reader.read_to_end(&mut tail));
        }
    }

    #[test]
    fn origin_read_times_out_once_the_origin_stalls() {
        let test_cases: Vec<&'static [u8]> = vec![
            b"",
            b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-3/4\r\nContent-Length: 4\r\n\r\nab",
        ];

        for answer in test_cases {
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
                stream.write_all(answer).unwrap();
                let _ = stream.read(&mut byte);
            });
            let config: Config = serde_yaml::from_str(&format!(
                "backend:\n  type: registry\n  config:\n    addr: http://{addr}\n    repository: library/ubuntu\n    http:\n      request_read_timeout: 1s\n      max_retries: 0\n"
            ))
            .unwrap();
            let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();

            let mut buf = [0u8; 4];
            let now = Instant::now();
            let result = registry
                .get(&TEST_BLOB_ID, 0, buf.len())
                .and_then(|mut reader| reader.read_exact(&mut buf));

            assert!(result.is_err());
            assert!(now.elapsed() >= Duration::from_secs(1));
        }
    }

    #[test]
    fn origin_body_that_breaks_off_fails_both_read_kinds() {
        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let origin = OriginStub::serve(&["206 Truncated"], b"abcd".to_vec());
            let config: Config = serde_yaml::from_str(&format!(
                "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n",
                origin.addr
            ))
            .unwrap();
            let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();

            let mut buf = [0u8; 4];
            let result = match kind {
                ReadKind::Ondemand => registry.get(&TEST_BLOB_ID, 0, buf.len()),
                ReadKind::Prefetch => registry.prefetch(&TEST_BLOB_ID, 0, buf.len()),
            }
            .and_then(|mut reader| reader.read_exact(&mut buf));

            assert!(result.is_err());
            assert_eq!(origin.ranges(), ["bytes=0-3"]);
        }
    }

    #[cfg(feature = "dragonfly")]
    #[test]
    fn seed_peer_read_times_out_a_slow_reader_by_the_request_timeout_only() {
        let test_cases = vec![("request_read_timeout: 1s", 1), ("request_timeout: 1s", 2)];

        for (timeout, seed_peer_hits) in test_cases {
            let blob = vec![7u8; 32 << 20];
            let runtime_dir = tempdir().unwrap();
            let seed_peer = OriginStub::serve(&["206 Partial Content"], blob.clone());
            let origin = OriginStub::serve(&["206 Partial Content"], blob.clone());
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
                "runtime_dir: {}\nbackend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n    dragonfly:\n      scheduler_endpoint: http://127.0.0.1:1\n      {timeout}\n      max_retries: 1\n",
                runtime_dir.path().display(),
                origin.addr
            ))
            .unwrap();
            let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();

            let mut reader = registry.get(&TEST_BLOB_ID, 0, blob.len()).unwrap();
            let mut head = [0u8; 1];
            reader.read_exact(&mut head).unwrap();
            thread::sleep(Duration::from_millis(1500));
            let mut tail = Vec::new();
            reader.read_to_end(&mut tail).unwrap();

            assert_eq!(tail.len(), blob.len() - 1);
            assert_eq!(seed_peer.hits(), seed_peer_hits);
        }
    }

    #[cfg(feature = "dragonfly")]
    #[test]
    fn seed_peer_that_stalls_falls_back_to_the_origin_after_the_request_read_timeout() {
        let test_cases: Vec<&'static [u8]> = vec![
            b"",
            b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-3/4\r\nContent-Length: 4\r\n\r\nab",
        ];

        for answer in test_cases {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let seed_peer_port = listener.local_addr().unwrap().port();
            thread::spawn(move || {
                use std::io::Write;
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                stream.write_all(answer).unwrap();
                let _ = stream.read(&mut byte);
            });
            let runtime_dir = tempdir().unwrap();
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
                        "proxy_port": seed_peer_port,
                        "healthy": true,
                    }],
                })
                .to_string(),
            )
            .unwrap();
            let config: Config = serde_yaml::from_str(&format!(
                "runtime_dir: {}\nbackend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n    dragonfly:\n      scheduler_endpoint: http://127.0.0.1:1\n      request_read_timeout: 1s\n      max_retries: 0\n",
                runtime_dir.path().display(),
                origin.addr
            ))
            .unwrap();
            let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();

            let now = Instant::now();
            let mut data = Vec::new();
            registry
                .get(&TEST_BLOB_ID, 0, 4)
                .unwrap()
                .read_to_end(&mut data)
                .unwrap();

            assert_eq!(data, b"abcd");
            assert_eq!(origin.hits(), 1);
            assert!(now.elapsed() >= Duration::from_secs(1));
            assert!(now.elapsed() < Duration::from_secs(10));
        }
    }

    #[cfg(feature = "dragonfly")]
    #[test]
    fn ondemand_read_is_counted_under_the_source_that_served_it() {
        let test_cases: Vec<(
            &'static [&'static str],
            &'static [&'static str],
            &str,
            Option<Vec<u8>>,
            u32,
        )> = vec![
            (
                &["206 Partial Content"],
                &["206 Partial Content"],
                "dragonfly",
                Some(b"abcd".to_vec()),
                0,
            ),
            (
                &["503 Service Unavailable"],
                &["206 Partial Content"],
                "fallback",
                Some(b"abcd".to_vec()),
                1,
            ),
            (
                &["206 Truncated"],
                &["206 Partial Content"],
                "fallback",
                Some(b"abcd".to_vec()),
                1,
            ),
            (
                &["404 Not Found"],
                &["206 Partial Content"],
                "dragonfly",
                None,
                0,
            ),
            (
                &["503 Service Unavailable"],
                &["503 Service Unavailable"],
                "fallback",
                None,
                1,
            ),
            (
                &["206 Truncated"],
                &["503 Service Unavailable"],
                "fallback",
                None,
                1,
            ),
        ];

        for (seed_peer_statuses, origin_statuses, source, expected, origin_hits) in test_cases {
            let runtime_dir = tempdir().unwrap();
            let seed_peer = OriginStub::serve(seed_peer_statuses, b"abcd".to_vec());
            let origin = OriginStub::serve(origin_statuses, b"abcd".to_vec());
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
                "runtime_dir: {}\nbackend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n    dragonfly:\n      scheduler_endpoint: http://127.0.0.1:1\n      max_retries: 0\n",
                runtime_dir.path().display(),
                origin.addr
            ))
            .unwrap();
            let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();
            let reads = || -> f64 {
                registry
                    .metrics()
                    .registry()
                    .gather()
                    .iter()
                    .filter(|family| family.get_name() == "nydus_backend_read_total")
                    .flat_map(|family| family.get_metric())
                    .filter(|metric| {
                        metric.get_label().iter().any(|label| {
                            label.get_name() == "source" && label.get_value() == source
                        })
                    })
                    .map(|metric| metric.get_counter().get_value())
                    .sum()
            };

            let mut data = Vec::new();
            let result = registry
                .get(&TEST_BLOB_ID, 0, 4)
                .and_then(|mut reader| reader.read_to_end(&mut data));
            let now = Instant::now();
            while reads() < 1.0 && now.elapsed() < Duration::from_secs(5) {
                thread::sleep(Duration::from_millis(10));
            }

            assert_eq!(result.ok().map(|_| data), expected);
            assert_eq!(reads(), 1.0);
            assert_eq!(origin.hits(), origin_hits);
        }
    }

    #[cfg(feature = "dragonfly")]
    #[test]
    fn seed_peer_body_that_breaks_off_is_resumed_through_the_seed_peers_then_the_origin() {
        let test_cases: Vec<(
            ReadKind,
            &'static [&'static str],
            &'static [&'static str],
            fn(io::Result<Vec<u8>>),
            Vec<&str>,
            Vec<&str>,
        )> = vec![
            (
                ReadKind::Ondemand,
                &["206 Truncated", "206 Partial Content"],
                &["206 Partial Content"],
                |result| assert_eq!(result.unwrap(), b"abcd"),
                vec!["bytes=0-3", "bytes=2-3"],
                vec![],
            ),
            (
                ReadKind::Ondemand,
                &["206 Truncated"],
                &["206 Partial Content"],
                |result| assert_eq!(result.unwrap(), b"abcd"),
                vec!["bytes=0-3", "bytes=2-3"],
                vec!["bytes=3-3"],
            ),
            (
                ReadKind::Ondemand,
                &["206 Truncated"],
                &["307 Temporary Redirect", "206 Partial Content"],
                |result| assert_eq!(result.unwrap(), b"abcd"),
                vec!["bytes=0-3", "bytes=2-3"],
                vec!["bytes=3-3", "bytes=3-3"],
            ),
            (
                ReadKind::Ondemand,
                &["206 Truncated"],
                &["401 Unauthorized", "206 Partial Content"],
                |result| assert_eq!(result.unwrap(), b"abcd"),
                vec!["bytes=0-3", "bytes=2-3"],
                vec!["bytes=3-3", "bytes=3-3"],
            ),
            (
                ReadKind::Ondemand,
                &["206 Truncated"],
                &["206 Truncated"],
                |result| assert!(result.is_err()),
                vec!["bytes=0-3", "bytes=2-3"],
                vec!["bytes=3-3"],
            ),
            (
                ReadKind::Ondemand,
                &["503 Service Unavailable"],
                &["206 Truncated"],
                |result| assert!(result.is_err()),
                vec!["bytes=0-3", "bytes=0-3"],
                vec!["bytes=0-3"],
            ),
            (
                ReadKind::Prefetch,
                &["206 Truncated"],
                &["206 Partial Content"],
                |result| assert!(result.is_err()),
                vec!["bytes=0-3"],
                vec![],
            ),
        ];

        for (kind, seed_peer_statuses, origin_statuses, expect, seed_peer_ranges, origin_ranges) in
            test_cases
        {
            let runtime_dir = tempdir().unwrap();
            let seed_peer = OriginStub::serve(seed_peer_statuses, b"abcd".to_vec());
            let origin = OriginStub::serve(origin_statuses, b"abcd".to_vec());
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
                "runtime_dir: {}\nbackend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n    auth: dXNlcjpwYXNz\n    dragonfly:\n      scheduler_endpoint: http://127.0.0.1:1\n      max_retries: 1\n",
                runtime_dir.path().display(),
                origin.addr
            ))
            .unwrap();
            let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();

            let result = match kind {
                ReadKind::Ondemand => registry.get(&TEST_BLOB_ID, 0, 4),
                ReadKind::Prefetch => registry.prefetch(&TEST_BLOB_ID, 0, 4),
            }
            .and_then(|mut reader| {
                let mut data = Vec::new();
                reader.read_to_end(&mut data).map(|_| data)
            });

            expect(result);
            assert_eq!(seed_peer.ranges(), seed_peer_ranges);
            assert_eq!(origin.ranges(), origin_ranges);
            assert_eq!(origin.hits() as usize, origin_ranges.len());
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
            let config: Config = serde_yaml::from_str(&format!(
                "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n",
                origin.addr
            ))
            .unwrap();
            let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();
            let counter = |name: &str| -> f64 {
                registry
                    .metrics()
                    .registry()
                    .gather()
                    .iter()
                    .filter(|family| family.get_name() == name)
                    .flat_map(|family| family.get_metric())
                    .map(|metric| metric.get_counter().get_value())
                    .sum()
            };

            consume(registry.get(&TEST_BLOB_ID, 0, 1 << 20).unwrap());
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
            "backend:\n  type: registry\n  config:\n    addr: http://{addr}\n    repository: library/ubuntu\n    http:\n      request_timeout: 60s\n      request_read_timeout: 60s\n"
        ))
        .unwrap();
        let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();
        let counter = |name: &str| -> f64 {
            registry
                .metrics()
                .registry()
                .gather()
                .iter()
                .filter(|family| family.get_name() == name)
                .flat_map(|family| family.get_metric())
                .map(|metric| metric.get_counter().get_value())
                .sum()
        };

        let mut reader = registry.get(&TEST_BLOB_ID, 0, 4).unwrap();
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
        let config: Config = serde_yaml::from_str(&format!(
            "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n",
            origin.addr
        ))
        .unwrap();
        let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();

        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let err = match kind {
                ReadKind::Ondemand => registry.get(&TEST_BLOB_ID, 16, 4),
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
            let config: Config = serde_yaml::from_str(&format!(
                "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\nprefetch:\n  retry_interval: 1ms\n",
                origin.addr
            ))
            .unwrap();
            let BackendConfig::Registry(registry_config) = &config.backend else {
                unreachable!()
            };
            let mut registry =
                Registry::new(&config, registry_config, None, Arc::new(Metrics::new())).unwrap();
            Arc::get_mut(&mut registry.client).unwrap().transport = Transport::Direct {
                fetcher: Box::new(transport.clone()),
            };

            let mut buf = vec![0u8; 4];
            let err = match kind {
                ReadKind::Ondemand => registry.get(&TEST_BLOB_ID, 0, buf.len()),
                ReadKind::Prefetch => registry.prefetch(&TEST_BLOB_ID, 0, buf.len()),
            }
            .and_then(|mut reader| reader.read_exact(&mut buf))
            .unwrap_err();

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
            let config: Config = serde_yaml::from_str(&format!(
                "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\nprefetch:\n  retry_interval: 1ms\n",
                origin.addr
            ))
            .unwrap();
            let BackendConfig::Registry(registry_config) = &config.backend else {
                unreachable!()
            };
            let mut registry =
                Registry::new(&config, registry_config, None, Arc::new(Metrics::new())).unwrap();
            Arc::get_mut(&mut registry.client).unwrap().transport = Transport::Direct {
                fetcher: Box::new(transport.clone()),
            };

            let mut buf = vec![0u8; 4];
            let err = match kind {
                ReadKind::Ondemand => registry.get(&TEST_BLOB_ID, 0, buf.len()),
                ReadKind::Prefetch => registry.prefetch(&TEST_BLOB_ID, 0, buf.len()),
            }
            .and_then(|mut reader| reader.read_exact(&mut buf))
            .unwrap_err();

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
            let config: Config = serde_yaml::from_str(&format!(
                "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\nprefetch:\n  retry_interval: 1ms\n",
                origin.addr
            ))
            .unwrap();
            let BackendConfig::Registry(registry_config) = &config.backend else {
                unreachable!()
            };
            let mut registry =
                Registry::new(&config, registry_config, None, Arc::new(Metrics::new())).unwrap();
            Arc::get_mut(&mut registry.client).unwrap().transport = Transport::Direct {
                fetcher: Box::new(transport.clone()),
            };
            registry.client.redirects.insert(
                &hex::encode(TEST_BLOB_ID),
                "http://cdn.example.com/signed".parse().unwrap(),
            );

            let mut buf = vec![0u8; 4];
            let err = match kind {
                ReadKind::Ondemand => registry.get(&TEST_BLOB_ID, 0, buf.len()),
                ReadKind::Prefetch => registry.prefetch(&TEST_BLOB_ID, 0, buf.len()),
            }
            .and_then(|mut reader| reader.read_exact(&mut buf))
            .unwrap_err();

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
        let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();

        let mut buf = [0u8; 4];
        registry
            .get(&TEST_BLOB_ID, 0, buf.len())
            .and_then(|mut reader| reader.read_exact(&mut buf))
            .unwrap();
        let prefetch = registry
            .prefetch(&TEST_BLOB_ID, 0, 4)
            .and_then(|mut reader| reader.read_exact(&mut [0u8; 4]));

        assert_eq!(&buf, b"abcd");
        assert_eq!(prefetch.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(origin.hits(), 1);
    }

    #[cfg(feature = "dragonfly")]
    #[test]
    fn ondemand_read_without_a_seed_peer_falls_back_to_the_origin_bypassing_the_proxy() {
        for proxied in [false, true] {
            let runtime_dir = tempdir().unwrap();
            let origin = OriginStub::serve(&["206 Partial Content"], b"abcd".to_vec());
            let proxy = OriginStub::serve(&["206 Partial Content"], b"abcd".to_vec());
            let http = if proxied {
                format!(
                    "    http:\n      proxy:\n        addr: http://{}\n",
                    proxy.addr
                )
            } else {
                String::new()
            };
            let config: Config = serde_yaml::from_str(&format!(
                "runtime_dir: {}\nbackend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n{http}    dragonfly:\n      scheduler_endpoint: http://127.0.0.1:1\n",
                runtime_dir.path().display(),
                origin.addr
            ))
            .unwrap();
            let BackendConfig::Registry(registry_config) = &config.backend else {
                unreachable!()
            };
            let registry =
                Registry::new(&config, registry_config, None, Arc::new(Metrics::new())).unwrap();
            let sources = || -> Vec<String> {
                registry
                    .metrics()
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
                .get(&TEST_BLOB_ID, 0, buf.len())
                .unwrap()
                .read_exact(&mut buf)
                .unwrap();
            let now = Instant::now();
            while sources().is_empty() && now.elapsed() < Duration::from_secs(5) {
                thread::sleep(Duration::from_millis(10));
            }

            assert_eq!(&buf, b"abcd");
            assert_eq!(origin.hits(), 1);
            assert_eq!(proxy.hits(), 0);
            assert_eq!(sources(), ["fallback"]);
            assert_eq!(registry.client.auth_transport.source(), Source::Http);
        }
    }

    #[cfg(feature = "dragonfly")]
    #[test]
    fn ondemand_reads_fall_back_within_the_request_read_timeout_while_the_scheduler_hangs() {
        let runtime_dir = tempdir().unwrap();
        let scheduler = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = OriginStub::serve(&["206 Partial Content"], b"abcd".to_vec());
        let config: Config = serde_yaml::from_str(&format!(
            "runtime_dir: {}\nbackend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n    dragonfly:\n      scheduler_endpoint: http://{}\n      request_read_timeout: 100ms\n",
            runtime_dir.path().display(),
            origin.addr,
            scheduler.local_addr().unwrap()
        ))
        .unwrap();
        let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();

        let now = Instant::now();
        let mut buf = [0u8; 4];
        registry
            .get(&TEST_BLOB_ID, 0, buf.len())
            .and_then(|mut reader| reader.read_exact(&mut buf))
            .unwrap();

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
            let BackendConfig::Registry(registry_config) = &config.backend else {
                unreachable!()
            };
            let registry =
                Registry::new(&config, registry_config, None, Arc::new(Metrics::new())).unwrap();
            assert_eq!(
                registry.client.blob_url("abc123").unwrap().as_str(),
                expected
            );
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
        let BackendConfig::Registry(registry_config) = &config.backend else {
            unreachable!()
        };
        let registry =
            Registry::new(&config, registry_config, None, Arc::new(Metrics::new())).unwrap();
        assert_eq!(
            registry.client.addr.as_str(),
            "https://registry.example.com/"
        );
        let mut headers = HeaderMap::new();
        registry.client.authorizer.authorize(&mut headers);
        assert_eq!(headers[AUTHORIZATION], "Bearer xyz");
        assert_eq!(registry.client.transport.source(), Source::Http);
    }

    #[test]
    fn proxied_read_is_counted_under_the_source_that_served_it() {
        let test_cases: Vec<(
            &'static [&'static str],
            &'static [&'static str],
            &str,
            Option<Vec<u8>>,
            u32,
        )> = vec![
            (
                &["206 Partial Content"],
                &["206 Partial Content"],
                "http_proxy",
                Some(b"abcd".to_vec()),
                0,
            ),
            (
                &["503 Service Unavailable"],
                &["206 Partial Content"],
                "fallback",
                Some(b"abcd".to_vec()),
                1,
            ),
            (
                &["206 Truncated"],
                &["206 Partial Content"],
                "fallback",
                Some(b"abcd".to_vec()),
                1,
            ),
            (
                &["404 Not Found"],
                &["206 Partial Content"],
                "http_proxy",
                None,
                0,
            ),
            (
                &["503 Service Unavailable"],
                &["503 Service Unavailable"],
                "fallback",
                None,
                1,
            ),
            (
                &["206 Truncated"],
                &["503 Service Unavailable"],
                "fallback",
                None,
                1,
            ),
            (
                &["503 Service Unavailable"],
                &["200 OK"],
                "fallback",
                None,
                1,
            ),
        ];

        for (proxy_statuses, origin_statuses, source, expected, origin_hits) in test_cases {
            let proxy = OriginStub::serve(proxy_statuses, b"abcd".to_vec());
            let origin = OriginStub::serve(origin_statuses, b"abcd".to_vec());
            let config: Config = serde_yaml::from_str(&format!(
                "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n    http:\n      max_retries: 0\n      proxy:\n        addr: http://{}\n",
                origin.addr, proxy.addr
            ))
            .unwrap();
            let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();
            let reads = || -> f64 {
                registry
                    .metrics()
                    .registry()
                    .gather()
                    .iter()
                    .filter(|family| family.get_name() == "nydus_backend_read_total")
                    .flat_map(|family| family.get_metric())
                    .filter(|metric| {
                        metric.get_label().iter().any(|label| {
                            label.get_name() == "source" && label.get_value() == source
                        })
                    })
                    .map(|metric| metric.get_counter().get_value())
                    .sum()
            };

            let mut data = Vec::new();
            let result = registry
                .get(&TEST_BLOB_ID, 0, 4)
                .and_then(|mut reader| reader.read_to_end(&mut data));
            let now = Instant::now();
            while reads() < 1.0 && now.elapsed() < Duration::from_secs(5) {
                thread::sleep(Duration::from_millis(10));
            }

            assert_eq!(result.ok().map(|_| data), expected);
            assert_eq!(reads(), 1.0);
            assert_eq!(proxy.hits(), 1);
            assert_eq!(origin.hits(), origin_hits);
        }
    }

    #[test]
    fn proxied_read_is_counted_under_the_fallback_source_when_the_origin_is_unreachable() {
        let proxy = OriginStub::serve(&["503 Service Unavailable"], b"abcd".to_vec());
        let config: Config = serde_yaml::from_str(&format!(
            "backend:\n  type: registry\n  config:\n    addr: http://127.0.0.1:1\n    repository: library/ubuntu\n    http:\n      max_retries: 0\n      proxy:\n        addr: http://{}\n",
            proxy.addr
        ))
        .unwrap();
        let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();
        let failures = || -> Vec<String> {
            registry
                .metrics()
                .registry()
                .gather()
                .iter()
                .filter(|family| family.get_name() == "nydus_backend_read_failure_total")
                .flat_map(|family| family.get_metric())
                .flat_map(|metric| metric.get_label())
                .filter(|label| label.get_name() == "source")
                .map(|label| label.get_value().to_string())
                .collect()
        };

        let err = registry.get(&TEST_BLOB_ID, 0, 4).err().unwrap();

        assert!(err.to_string().contains("502 Bad Gateway"));
        assert_eq!(proxy.hits(), 1);
        assert_eq!(failures(), ["fallback"]);
    }

    #[test]
    fn proxied_read_fetches_the_token_from_the_origin_while_the_proxy_is_unreachable() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        drop(proxy);
        let token = br#"{"token":"abc"}"#.to_vec();
        let origin = OriginStub::serve(
            &["401 Bearer", "200 OK", "206 Partial Content"],
            token.clone(),
        );
        let config: Config = serde_yaml::from_str(&format!(
            "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n    http:\n      proxy:\n        addr: http://{proxy_addr}\n    fallback:\n      rate_limit: 100\n",
            origin.addr
        ))
        .unwrap();
        let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();

        let mut buf = [0u8; 4];
        registry
            .get(&TEST_BLOB_ID, 0, buf.len())
            .unwrap()
            .read_exact(&mut buf)
            .unwrap();

        assert_eq!(buf, token[..4]);
        assert_eq!(origin.hits(), 3);
        assert!(origin.requests.lock().unwrap()[2].contains("authorization: Bearer abc"));
    }

    #[test]
    fn new_names_the_source_after_the_http_proxy() {
        let test_cases = vec![
            ("", Source::Http),
            (
                "    http:\n      proxy:\n        addr: http://127.0.0.1:65001\n",
                Source::HttpProxy,
            ),
        ];

        for (http, source) in test_cases {
            let config: Config = serde_yaml::from_str(&format!(
                "backend:\n  type: registry\n  config:\n    addr: http://127.0.0.1:5000\n    repository: library/ubuntu\n{http}"
            ))
            .unwrap();
            let BackendConfig::Registry(registry_config) = &config.backend else {
                unreachable!()
            };
            let registry =
                Registry::new(&config, registry_config, None, Arc::new(Metrics::new())).unwrap();
            assert_eq!(registry.client.transport.source(), source);
        }
    }

    #[cfg(feature = "dragonfly")]
    #[test]
    fn new_names_the_source_after_dragonfly_with_or_without_the_http_proxy() {
        let test_cases = vec![
            "",
            "    http:\n      proxy:\n        addr: http://127.0.0.1:65001\n",
        ];

        for http in test_cases {
            let runtime_dir = tempdir().unwrap();
            let config: Config = serde_yaml::from_str(&format!(
                "runtime_dir: {}\nbackend:\n  type: registry\n  config:\n    addr: http://127.0.0.1:5000\n    repository: library/ubuntu\n{http}    dragonfly:\n      scheduler_endpoint: http://127.0.0.1:1\n",
                runtime_dir.path().display()
            ))
            .unwrap();
            let BackendConfig::Registry(registry_config) = &config.backend else {
                unreachable!()
            };
            let registry =
                Registry::new(&config, registry_config, None, Arc::new(Metrics::new())).unwrap();

            assert_eq!(registry.client.transport.source(), Source::Dragonfly);
            assert!(runtime_dir.path().join("dragonfly").is_dir());
        }
    }

    #[cfg(feature = "dragonfly")]
    #[test]
    fn new_fails_when_the_dragonfly_transport_cannot_be_built() {
        let test_cases: Vec<(fn(&std::path::Path) -> (std::path::PathBuf, String), &str)> = vec![
            (
                |dir| {
                    fs::write(dir.join("runtime"), b"").unwrap();
                    (dir.join("runtime"), String::new())
                },
                "failed to create dragonfly runtime directory",
            ),
            (
                |dir| {
                    (
                        dir.to_path_buf(),
                        format!(
                            "    http:\n      tls:\n        ca_cert: {}\n",
                            dir.join("missing.pem").display()
                        ),
                    )
                },
                "failed to read CA cert",
            ),
        ];

        for (prepare, expected) in test_cases {
            let dir = tempdir().unwrap();
            let (runtime_dir, http) = prepare(dir.path());
            let config: Config = serde_yaml::from_str(&format!(
                "runtime_dir: {}\nbackend:\n  type: registry\n  config:\n    addr: http://127.0.0.1:5000\n    repository: library/ubuntu\n{http}    dragonfly:\n      scheduler_endpoint: http://127.0.0.1:1\n",
                runtime_dir.display()
            ))
            .unwrap();
            let BackendConfig::Registry(registry) = &config.backend else {
                panic!("expected a registry backend, got {:?}", config.backend);
            };

            let err = Registry::new(&config, registry, None, Arc::new(Metrics::new()))
                .err()
                .unwrap();

            assert!(err.to_string().contains(expected), "{err}");
        }
    }

    #[cfg(feature = "dragonfly")]
    #[test]
    fn dragonfly_fallback_retries_by_the_fallback_max_retries_not_the_http_max_retries() {
        let test_cases = vec![(2, 0, 1), (0, 1, 2)];

        for (http_max_retries, fallback_max_retries, origin_hits) in test_cases {
            let runtime_dir = tempdir().unwrap();
            let origin = OriginStub::serve(&["503 Service Unavailable"], b"abcd".to_vec());
            let config: Config = serde_yaml::from_str(&format!(
                "runtime_dir: {}\nbackend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n    http:\n      max_retries: {http_max_retries}\n    fallback:\n      max_retries: {fallback_max_retries}\n    dragonfly:\n      scheduler_endpoint: http://127.0.0.1:1\n",
                runtime_dir.path().display(),
                origin.addr
            ))
            .unwrap();
            let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();

            let err = registry
                .get(&TEST_BLOB_ID, 0, 4)
                .and_then(|mut reader| reader.read_exact(&mut [0u8; 4]))
                .unwrap_err();

            assert!(err.to_string().contains("503"));
            assert_eq!(origin.hits(), origin_hits);
        }
    }

    #[cfg(feature = "dragonfly")]
    #[test]
    fn dragonfly_fallback_reads_wait_for_a_slot_of_the_fallback_rate_limit() {
        let test_cases: Vec<(u64, fn(Duration) -> bool)> = vec![
            (1, |elapsed| elapsed >= Duration::from_secs(1)),
            (100, |elapsed| elapsed < Duration::from_secs(1)),
        ];

        for (rate_limit, expected) in test_cases {
            let runtime_dir = tempdir().unwrap();
            let origin = OriginStub::serve(&["206 Partial Content"], b"abcd".to_vec());
            let config: Config = serde_yaml::from_str(&format!(
                "runtime_dir: {}\nbackend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n    fallback:\n      rate_limit: {rate_limit}\n    dragonfly:\n      scheduler_endpoint: http://127.0.0.1:1\n",
                runtime_dir.path().display(),
                origin.addr
            ))
            .unwrap();

            let now = Instant::now();
            let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();
            for _ in 0..2 {
                let mut buf = [0u8; 4];
                registry
                    .get(&TEST_BLOB_ID, 0, buf.len())
                    .and_then(|mut reader| reader.read_exact(&mut buf))
                    .unwrap();
                assert_eq!(&buf, b"abcd");
            }

            assert!(expected(now.elapsed()), "{:?}", now.elapsed());
            assert_eq!(origin.hits(), 2);
        }
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
                let config: Config = serde_yaml::from_str(&format!(
                    "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\nprefetch:\n  retry_interval: 1ms\n",
                    origin.addr
                ))
                .unwrap();
                let BackendConfig::Registry(registry_config) = &config.backend else {
                    unreachable!()
                };
                let mut registry =
                    Registry::new(&config, registry_config, None, Arc::new(Metrics::new()))
                        .unwrap();
                Arc::get_mut(&mut registry.client).unwrap().transport = Transport::Direct {
                    fetcher: Box::new(transport.clone()),
                };

                let mut buf = vec![0u8; 4];
                let err = match kind {
                    ReadKind::Ondemand => registry.get(&TEST_BLOB_ID, 0, buf.len()),
                    ReadKind::Prefetch => registry.prefetch(&TEST_BLOB_ID, 0, buf.len()),
                }
                .and_then(|mut reader| reader.read_exact(&mut buf))
                .unwrap_err();

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
        let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();

        let mut buf = vec![0u8; 4];
        let err = registry
            .get(&TEST_BLOB_ID, 0, buf.len())
            .and_then(|mut reader| reader.read_exact(&mut buf))
            .unwrap_err();

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
            let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();

            let mut buf = [0u8; 4];
            let result = registry
                .prefetch(&TEST_BLOB_ID, 0, buf.len())
                .and_then(|mut reader| reader.read_exact(&mut buf));

            expect(result, buf);
            assert_eq!(origin.ranges(), ["bytes=0-3", "bytes=0-3"]);
        }
    }

    #[test]
    fn origin_transport_failure_fails_a_prefetch_read_at_once() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let config: Config = serde_yaml::from_str(&format!(
            "backend:\n  type: registry\n  config:\n    addr: http://{addr}\n    repository: library/ubuntu\n    http:\n      max_retries: 0\nprefetch:\n  retry_interval: 2s\n"
        ))
        .unwrap();
        let registry = <dyn Backend>::new(&config, None, Arc::new(Metrics::new())).unwrap();

        let now = Instant::now();
        let mut buf = [0u8; 4];
        let result = registry
            .prefetch(&TEST_BLOB_ID, 0, buf.len())
            .and_then(|mut reader| reader.read_exact(&mut buf));

        assert!(result.is_err());
        assert!(now.elapsed() < Duration::from_secs(2));
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
            let config: Config = serde_yaml::from_str(&format!(
                "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n    auth: YWxpY2U6c2VjcmV0\nprefetch:\n  retry_interval: 1ms\n",
                origin.addr
            ))
            .unwrap();
            let BackendConfig::Registry(registry_config) = &config.backend else {
                unreachable!()
            };
            let mut registry =
                Registry::new(&config, registry_config, None, Arc::new(Metrics::new())).unwrap();
            Arc::get_mut(&mut registry.client).unwrap().transport = Transport::Direct {
                fetcher: Box::new(transport.clone()),
            };

            let mut buf = vec![0u8; body.len()];
            match kind {
                ReadKind::Ondemand => registry.get(&TEST_BLOB_ID, 0, buf.len()),
                ReadKind::Prefetch => registry.prefetch(&TEST_BLOB_ID, 0, buf.len()),
            }
            .and_then(|mut reader| reader.read_exact(&mut buf))
            .unwrap();

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
            let config: Config = serde_yaml::from_str(&format!(
                "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n    auth: YWxpY2U6c2VjcmV0\n    registry_token: xyz\nprefetch:\n  retry_interval: 1ms\n",
                origin.addr
            ))
            .unwrap();
            let BackendConfig::Registry(registry_config) = &config.backend else {
                unreachable!()
            };
            let mut registry =
                Registry::new(&config, registry_config, None, Arc::new(Metrics::new())).unwrap();
            Arc::get_mut(&mut registry.client).unwrap().transport = Transport::Direct {
                fetcher: Box::new(transport.clone()),
            };

            let mut buf = vec![0u8; body.len()];
            match kind {
                ReadKind::Ondemand => registry.get(&TEST_BLOB_ID, 0, buf.len()),
                ReadKind::Prefetch => registry.prefetch(&TEST_BLOB_ID, 0, buf.len()),
            }
            .and_then(|mut reader| reader.read_exact(&mut buf))
            .unwrap();

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
                let config: Config = serde_yaml::from_str(&format!(
                    "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\n    auth: YWxpY2U6c2VjcmV0\n    registry_token: xyz\nprefetch:\n  retry_interval: 1ms\n",
                    origin.addr
                ))
                .unwrap();
                let BackendConfig::Registry(registry_config) = &config.backend else {
                    unreachable!()
                };
                let mut registry =
                    Registry::new(&config, registry_config, None, Arc::new(Metrics::new()))
                        .unwrap();
                Arc::get_mut(&mut registry.client).unwrap().transport = Transport::Direct {
                    fetcher: Box::new(transport.clone()),
                };

                let mut buf = vec![0u8; body.len()];
                match kind {
                    ReadKind::Ondemand => registry.get(&TEST_BLOB_ID, 0, buf.len()),
                    ReadKind::Prefetch => registry.prefetch(&TEST_BLOB_ID, 0, buf.len()),
                }
                .and_then(|mut reader| reader.read_exact(&mut buf))
                .unwrap();

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
    fn get_blob_metadata_fetches_the_footer_through_the_transport() {
        for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
            let origin = OriginStub::serve(&["206 Partial Content"], b"unused".to_vec());
            let transport = ScriptedTransport::new(vec![Scripted::Status(
                StatusCode::NOT_FOUND,
                HeaderMap::new(),
            )]);
            let config: Config = serde_yaml::from_str(&format!(
                "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\nprefetch:\n  retry_interval: 1ms\n",
                origin.addr
            ))
            .unwrap();
            let BackendConfig::Registry(registry_config) = &config.backend else {
                unreachable!()
            };
            let mut registry =
                Registry::new(&config, registry_config, None, Arc::new(Metrics::new())).unwrap();
            Arc::get_mut(&mut registry.client).unwrap().transport = Transport::Direct {
                fetcher: Box::new(transport.clone()),
            };

            let err = match kind {
                ReadKind::Ondemand => registry.get_blob_metadata(&TEST_BLOB_ID),
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
        let config: Config = serde_yaml::from_str(&format!(
            "backend:\n  type: registry\n  config:\n    addr: http://{dead_addr}\n    repository: library/ubuntu\n    auth: YWxpY2U6c2VjcmV0\nprefetch:\n  retry_interval: 1ms\n"
        ))
        .unwrap();
        let BackendConfig::Registry(registry_config) = &config.backend else {
            unreachable!()
        };
        let mut registry =
            Registry::new(&config, registry_config, None, Arc::new(Metrics::new())).unwrap();
        Arc::get_mut(&mut registry.client).unwrap().transport = Transport::Direct {
            fetcher: Box::new(gate.clone()),
        };
        let registry = Arc::new(registry);

        let readers: Vec<_> = (0..2)
            .map(|_| {
                let registry = registry.clone();
                thread::spawn(move || {
                    let mut buf = [0u8; 2];
                    registry
                        .get(&TEST_BLOB_ID, 0, buf.len())
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
        let config: Config = serde_yaml::from_str(&format!(
            "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\nprefetch:\n  retry_interval: 1ms\n",
            origin.addr
        ))
        .unwrap();
        let BackendConfig::Registry(registry_config) = &config.backend else {
            unreachable!()
        };
        let mut registry =
            Registry::new(&config, registry_config, None, Arc::new(Metrics::new())).unwrap();
        Arc::get_mut(&mut registry.client).unwrap().transport = Transport::Direct {
            fetcher: Box::new(transport.clone()),
        };
        let hex = hex::encode(TEST_BLOB_ID);
        registry
            .client
            .redirects
            .insert(&hex, "http://cdn.example.com/signed".parse().unwrap());

        let mut buf = vec![0u8; body.len()];
        registry
            .get(&TEST_BLOB_ID, 0, buf.len())
            .and_then(|mut reader| reader.read_exact(&mut buf))
            .unwrap();

        assert_eq!(buf, body);
        assert_eq!(transport.calls(), 1);
        assert_eq!(origin.hits(), 0);
    }

    #[test]
    fn rejected_cached_redirect_is_evicted_and_re_resolved() {
        let test_cases = vec![
            (StatusCode::UNAUTHORIZED, true, false),
            (StatusCode::FORBIDDEN, true, false),
            (StatusCode::BAD_REQUEST, true, false),
            (StatusCode::NOT_FOUND, true, false),
            (StatusCode::GONE, true, false),
            (StatusCode::REQUEST_TIMEOUT, false, true),
            (StatusCode::RANGE_NOT_SATISFIABLE, false, false),
            (StatusCode::TOO_MANY_REQUESTS, false, true),
            (StatusCode::INTERNAL_SERVER_ERROR, false, true),
        ];

        for (status, evicted, transient) in test_cases {
            for kind in [ReadKind::Ondemand, ReadKind::Prefetch] {
                let body = b"fresh".to_vec();
                let origin = OriginStub::serve(&["206 Partial Content"], b"unused".to_vec());
                let mut script = vec![Scripted::Status(status, HeaderMap::new())];
                if evicted {
                    script.push(Scripted::Body(body.clone()));
                }
                if transient && matches!(kind, ReadKind::Prefetch) {
                    script.push(Scripted::Status(status, HeaderMap::new()));
                }
                let calls = script.len() as u32;
                let transport = ScriptedTransport::new(script);
                let config: Config = serde_yaml::from_str(&format!(
                    "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\nprefetch:\n  retry_interval: 1ms\n",
                    origin.addr
                ))
                .unwrap();
                let BackendConfig::Registry(registry_config) = &config.backend else {
                    unreachable!()
                };
                let mut registry =
                    Registry::new(&config, registry_config, None, Arc::new(Metrics::new()))
                        .unwrap();
                Arc::get_mut(&mut registry.client).unwrap().transport = Transport::Direct {
                    fetcher: Box::new(transport.clone()),
                };
                let hex = hex::encode(TEST_BLOB_ID);
                registry
                    .client
                    .redirects
                    .insert(&hex, "http://cdn.example.com/expired".parse().unwrap());

                let mut buf = vec![0u8; body.len()];
                let result = match kind {
                    ReadKind::Ondemand => registry.get(&TEST_BLOB_ID, 0, buf.len()),
                    ReadKind::Prefetch => registry.prefetch(&TEST_BLOB_ID, 0, buf.len()),
                }
                .and_then(|mut reader| reader.read_exact(&mut buf));

                assert_eq!(result.is_ok(), evicted);
                assert_eq!(transport.calls(), calls);
                assert_eq!(registry.client.redirects.get(&hex).is_none(), evicted);
            }
        }
    }

    #[test]
    fn prefetch_resolves_the_redirect_again_when_the_read_is_sent_once_more() {
        let body = b"fresh".to_vec();
        let test_cases: Vec<(ReadKind, Vec<(StatusCode, Option<&str>)>, Option<&str>)> = vec![
            (
                ReadKind::Prefetch,
                vec![
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        Some("http://cdn.example.com/busy"),
                    ),
                    (StatusCode::SERVICE_UNAVAILABLE, None),
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        Some("http://cdn.example.com/fresh"),
                    ),
                    (StatusCode::PARTIAL_CONTENT, None),
                ],
                Some("http://cdn.example.com/fresh"),
            ),
            (
                ReadKind::Prefetch,
                vec![
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        Some("http://cdn.example.com/busy"),
                    ),
                    (StatusCode::SERVICE_UNAVAILABLE, None),
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        Some("http://cdn.example.com/busy"),
                    ),
                    (StatusCode::SERVICE_UNAVAILABLE, None),
                ],
                None,
            ),
            (
                ReadKind::Prefetch,
                vec![
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        Some("http://cdn.example.com/rejected"),
                    ),
                    (StatusCode::FORBIDDEN, None),
                ],
                None,
            ),
            (
                ReadKind::Ondemand,
                vec![
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        Some("http://cdn.example.com/busy"),
                    ),
                    (StatusCode::SERVICE_UNAVAILABLE, None),
                ],
                None,
            ),
        ];

        for (kind, answers, link) in test_cases {
            let origin = OriginStub::serve(&["206 Partial Content"], b"unused".to_vec());
            let transport = ScriptedTransport::new(answers.iter().map(|(status, location)| {
                if *status == StatusCode::PARTIAL_CONTENT {
                    return Scripted::Body(body.clone());
                }

                Scripted::Status(
                    *status,
                    location
                        .iter()
                        .map(|location| (LOCATION, location.parse().unwrap()))
                        .collect(),
                )
            }));
            let config: Config = serde_yaml::from_str(&format!(
                "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: library/ubuntu\nprefetch:\n  retry_interval: 1ms\n",
                origin.addr
            ))
            .unwrap();
            let BackendConfig::Registry(registry_config) = &config.backend else {
                unreachable!()
            };
            let mut registry =
                Registry::new(&config, registry_config, None, Arc::new(Metrics::new())).unwrap();
            Arc::get_mut(&mut registry.client).unwrap().transport = Transport::Direct {
                fetcher: Box::new(transport.clone()),
            };

            let mut buf = vec![0u8; body.len()];
            let result = match kind {
                ReadKind::Ondemand => registry.get(&TEST_BLOB_ID, 0, buf.len()),
                ReadKind::Prefetch => registry.prefetch(&TEST_BLOB_ID, 0, buf.len()),
            }
            .and_then(|mut reader| reader.read_exact(&mut buf));

            assert_eq!(result.is_ok(), link.is_some());
            assert_eq!(transport.calls(), answers.len() as u32);
            assert_eq!(
                registry
                    .client
                    .redirects
                    .get(&hex::encode(TEST_BLOB_ID))
                    .as_ref()
                    .map(Url::as_str),
                link
            );
            if link.is_some() {
                assert_eq!(buf, body);
            }
        }
    }
}
