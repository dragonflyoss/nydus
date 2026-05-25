// Copyright 2022 Ant Group. All rights reserved.
// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Base module used to implement object storage backend drivers (such as oss, s3, etc.).

use std::fmt;
use std::fmt::Debug;
use std::io::{Error, Read, Result};
use std::marker::Send;
use std::sync::Arc;

use reqwest::header::{HeaderMap, CONTENT_LENGTH};
use reqwest::Method;

use nydus_utils::metrics::BackendMetrics;

use super::request::{self, is_success_status};
use super::{BackendContext, BackendError, BackendResult, BlobBackend, BlobReader};

/// Error codes related to object storage backend.
#[derive(Debug)]
pub enum ObjectStorageError {
    Auth(Error),
    ConstructHeader(String),
    Transport(std::io::Error),
    Response(String),
}

impl fmt::Display for ObjectStorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectStorageError::Auth(e) => write!(f, "failed to generate auth info, {}", e),
            ObjectStorageError::ConstructHeader(e) => {
                write!(f, "failed to generate HTTP header, {}", e)
            }
            ObjectStorageError::Transport(e) => write!(f, "network communication error, {}", e),
            ObjectStorageError::Response(s) => write!(f, "network communication error, {}", s),
        }
    }
}

impl From<ObjectStorageError> for BackendError {
    fn from(err: ObjectStorageError) -> Self {
        BackendError::ObjectStorage(err)
    }
}

pub trait ObjectStorageState: Send + Sync + Debug {
    // `url` builds the resource path and full url for the object.
    fn url(&self, object_key: &str, query: &[&str]) -> (String, String);

    // `sign` signs the request with the access key and secret key.
    fn sign(
        &self,
        verb: Method,
        headers: &mut HeaderMap,
        canonicalized_resource: &str,
        full_resource_url: &str,
    ) -> Result<()>;

    fn retry_limit(&self) -> u8;
}

struct ObjectStorageReader<T>
where
    T: ObjectStorageState,
{
    blob_id: String,
    request: Arc<request::Request>,
    state: Arc<T>,
    metrics: Arc<BackendMetrics>,
}

impl<T> BlobReader for ObjectStorageReader<T>
where
    T: ObjectStorageState,
{
    fn blob_size(&self) -> BackendResult<u64> {
        let (resource, url) = self.state.url(&self.blob_id, &[]);
        let mut headers = HeaderMap::new();

        self.state
            .sign(Method::HEAD, &mut headers, resource.as_str(), url.as_str())
            .map_err(ObjectStorageError::Auth)?;

        let mut ctx = BackendContext::default();
        let resp = self
            .request
            .call::<&[u8]>(
                Method::HEAD,
                url.as_str(),
                None,
                None,
                &mut headers,
                true,
                &mut ctx,
                false,
            )
            .map_err(BackendError::Request)?;
        let content_length = resp
            .headers()
            .get(CONTENT_LENGTH)
            .ok_or_else(|| ObjectStorageError::Response("invalid content length".to_string()))?;

        Ok(content_length
            .to_str()
            .map_err(|err| {
                ObjectStorageError::Response(format!("invalid content length: {:?}", err))
            })?
            .parse::<u64>()
            .map_err(|err| {
                ObjectStorageError::Response(format!("invalid content length: {:?}", err))
            })?)
    }

    fn try_read(&self, buf: &mut [u8], offset: u64) -> BackendResult<usize> {
        self.try_read_ctx(buf, offset, None)
    }

    fn try_read_ctx(
        &self,
        buf: &mut [u8],
        offset: u64,
        ctx: Option<&mut BackendContext>,
    ) -> BackendResult<usize> {
        let mut default_ctx = BackendContext::default();
        let ctx = ctx.unwrap_or(&mut default_ctx);

        let query = &[];
        let (resource, url) = self.state.url(&self.blob_id, query);
        let mut headers = HeaderMap::new();
        let end_at = offset + buf.len() as u64 - 1;
        let range = format!("bytes={}-{}", offset, end_at);

        headers.insert(
            "Range",
            range
                .as_str()
                .parse()
                .map_err(|e| ObjectStorageError::ConstructHeader(format!("{}", e)))?,
        );
        self.state
            .sign(Method::GET, &mut headers, resource.as_str(), url.as_str())
            .map_err(ObjectStorageError::Auth)?;

        let resp = self
            .request
            .call::<&[u8]>(
                Method::GET,
                url.as_str(),
                None,
                None,
                &mut headers,
                true,
                ctx,
                false,
            )
            .map_err(BackendError::Request)?;
        Ok(resp
            .copy_to(buf)
            .map_err(|e| ObjectStorageError::Transport(std::io::Error::other(e)))
            .map(|size| size as usize)?)
    }

    /// Start a streaming read from the blob at the given offset.
    ///
    /// When `offset` is 0, no Range header is sent so that Dragonfly dfdaemon
    /// downloads and caches the entire blob. When `offset > 0`, an open-ended
    /// Range header (`bytes=offset-`) is used.
    fn try_stream_read(
        &self,
        offset: u64,
        ctx: Option<&mut BackendContext>,
    ) -> BackendResult<Box<dyn Read + Send>> {
        let mut default_ctx = BackendContext::default();
        let ctx = ctx.unwrap_or(&mut default_ctx);

        let query = &[];
        let (resource, url) = self.state.url(&self.blob_id, query);
        let mut headers = HeaderMap::new();

        // Only add Range header if offset > 0 (open-ended range to stream from offset).
        // When offset == 0: NO Range header — dfdaemon downloads full blob and caches it.
        if offset > 0 {
            let range = format!("bytes={}-", offset);
            headers.insert(
                "Range",
                range
                    .as_str()
                    .parse()
                    .map_err(|e| ObjectStorageError::ConstructHeader(format!("{}", e)))?,
            );
        }

        self.state
            .sign(Method::GET, &mut headers, resource.as_str(), url.as_str())
            .map_err(ObjectStorageError::Auth)?;

        let resp = self
            .request
            .call::<&[u8]>(
                Method::GET,
                url.as_str(),
                None,
                None,
                &mut headers,
                true,
                ctx,
                false,
            )
            .map_err(BackendError::Request)?;

        let status = resp.status();
        if !is_success_status(status) {
            return Err(BackendError::ObjectStorage(ObjectStorageError::Response(
                format!("stream_read failed, status: {}", status),
            )));
        }

        Ok(resp.reader())
    }

    fn metrics(&self) -> &BackendMetrics {
        &self.metrics
    }

    fn retry_limit(&self) -> u8 {
        self.state.retry_limit()
    }
}

#[derive(Debug)]
pub struct ObjectStorage<T>
where
    T: ObjectStorageState,
{
    request: Arc<request::Request>,
    state: Arc<T>,
    metrics: Option<Arc<BackendMetrics>>,
    #[allow(unused)]
    id: Option<String>,
}

impl<T> ObjectStorage<T>
where
    T: ObjectStorageState,
{
    pub(crate) fn new_object_storage(
        request: Arc<request::Request>,
        state: Arc<T>,
        metrics: Option<Arc<BackendMetrics>>,
        id: Option<String>,
    ) -> Self {
        ObjectStorage {
            request,
            state,
            metrics,
            id,
        }
    }
}

impl<T: 'static> BlobBackend for ObjectStorage<T>
where
    T: ObjectStorageState,
{
    fn shutdown(&self) {
        self.request.shutdown();
    }

    fn metrics(&self) -> &BackendMetrics {
        // `metrics()` is only used for nydusd, which will always provide valid `blob_id`, thus
        // `self.metrics` has valid value.
        self.metrics.as_ref().unwrap()
    }

    fn get_reader(&self, blob_id: &str) -> BackendResult<Arc<dyn BlobReader>> {
        if let Some(metrics) = self.metrics.as_ref() {
            Ok(Arc::new(ObjectStorageReader {
                blob_id: blob_id.to_string(),
                state: self.state.clone(),
                request: self.request.clone(),
                metrics: metrics.clone(),
            }))
        } else {
            Err(BackendError::Unsupported(
                "no metrics object available for OssReader".to_string(),
            ))
        }
    }
}

impl<T> Drop for ObjectStorage<T>
where
    T: ObjectStorageState,
{
    fn drop(&mut self) {
        if let Some(metrics) = self.metrics.as_ref() {
            metrics.release().unwrap_or_else(|e| error!("{:?}", e));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error as IoError, Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use nydus_api::ProxyConfig;
    use nydus_utils::metrics::BackendMetrics;

    use crate::backend::connection::{Connection, ConnectionConfig};

    const OBJECT_STORAGE_TEST_CONTENT: &[u8] = b"object-storage-response-body";

    fn make_io_error(msg: &str) -> IoError {
        IoError::other(msg)
    }

    // ── Minimal mock for ObjectStorageState ────────────────────────────────

    #[derive(Debug)]
    struct MockState {
        retry: u8,
        base_url: String,
        sign_error: Option<String>,
        signed_methods: Arc<Mutex<Vec<Method>>>,
    }

    impl MockState {
        fn new(retry: u8) -> Self {
            MockState {
                retry,
                base_url: "http://test.example.com".to_string(),
                sign_error: None,
                signed_methods: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn with_base_url(retry: u8, base_url: String) -> Self {
            let mut state = Self::new(retry);
            state.base_url = base_url;
            state
        }

        fn with_sign_error(retry: u8, msg: &str) -> Self {
            let mut state = Self::new(retry);
            state.sign_error = Some(msg.to_string());
            state
        }
    }

    impl ObjectStorageState for MockState {
        fn url(&self, object_key: &str, _query: &[&str]) -> (String, String) {
            let resource = format!("/test-bucket/{}", object_key);
            let url = format!("{}/{}", self.base_url.trim_end_matches('/'), object_key);
            (resource, url)
        }

        fn sign(
            &self,
            verb: Method,
            _headers: &mut HeaderMap,
            _canonicalized_resource: &str,
            _full_resource_url: &str,
        ) -> std::io::Result<()> {
            self.signed_methods.lock().unwrap().push(verb);
            if let Some(msg) = self.sign_error.as_ref() {
                return Err(IoError::other(msg.clone()));
            }
            Ok(())
        }

        fn retry_limit(&self) -> u8 {
            self.retry
        }
    }

    fn make_request() -> Arc<request::Request> {
        let config = ConnectionConfig::default();
        let connection = Connection::new(&config).unwrap();
        request::Request::new(
            connection,
            ProxyConfig::default(),
            false,
            "test-object-storage",
        )
    }

    fn parse_range(request: &str) -> Option<String> {
        request.lines().find_map(|line| {
            let line = line.trim();
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("range") {
                Some(value.trim().to_string())
            } else {
                None
            }
        })
    }

    fn read_http_request(stream: &mut std::net::TcpStream) -> String {
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    request.extend_from_slice(&buf[..n]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(e) => panic!("failed to read mock request: {}", e),
            }
        }

        String::from_utf8_lossy(&request).into_owned()
    }

    fn start_object_storage_server(
        include_content_length: bool,
    ) -> (String, Arc<AtomicBool>, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let seen_ranges = Arc::new(Mutex::new(Vec::new()));
        let shutdown_clone = shutdown.clone();
        let seen_ranges_clone = seen_ranges.clone();

        thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            while !shutdown_clone.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let request = read_http_request(&mut stream);
                        let response = if request.starts_with("HEAD ") {
                            if include_content_length {
                                format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    OBJECT_STORAGE_TEST_CONTENT.len()
                                )
                            } else {
                                "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_string()
                            }
                        } else if let Some(range) = parse_range(&request) {
                            seen_ranges_clone.lock().unwrap().push(range.clone());
                            let range = range.trim_start_matches("bytes=");
                            let (start, end) = range.split_once('-').unwrap();
                            let start: usize = start.parse().unwrap();
                            if end.is_empty() {
                                // Open-ended range: bytes=N-
                                let body = &OBJECT_STORAGE_TEST_CONTENT[start..];
                                format!(
                                    "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    body.len(),
                                    String::from_utf8_lossy(body)
                                )
                            } else {
                                let end: usize = end.parse().unwrap();
                                let body = &OBJECT_STORAGE_TEST_CONTENT[start..=end];
                                format!(
                                    "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    body.len(),
                                    String::from_utf8_lossy(body)
                                )
                            }
                        } else {
                            // No Range header — return full body
                            seen_ranges_clone.lock().unwrap().push("none".to_string());
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                OBJECT_STORAGE_TEST_CONTENT.len(),
                                String::from_utf8_lossy(OBJECT_STORAGE_TEST_CONTENT)
                            )
                        };

                        stream.write_all(response.as_bytes()).unwrap();
                        stream.flush().unwrap();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });

        thread::sleep(Duration::from_millis(50));

        (format!("http://{}", addr), shutdown, seen_ranges)
    }

    // ── ObjectStorageError display/debug/conversion tests ─────────────────

    #[test]
    fn test_object_storage_error_auth_display() {
        let err = ObjectStorageError::Auth(make_io_error("auth failed"));
        let msg = format!("{}", err);
        assert!(msg.contains("failed to generate auth info"));
        assert!(msg.contains("auth failed"));
    }

    #[test]
    fn test_object_storage_error_construct_header_display() {
        let err = ObjectStorageError::ConstructHeader("bad header".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("failed to generate HTTP header"));
        assert!(msg.contains("bad header"));
    }

    #[test]
    fn test_object_storage_error_response_display() {
        let err = ObjectStorageError::Response("server error 500".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("network communication error"));
        assert!(msg.contains("server error 500"));
    }

    #[test]
    fn test_object_storage_error_transport_display() {
        let err = ObjectStorageError::Transport(make_io_error("network timeout"));
        let msg = format!("{}", err);
        assert!(msg.contains("network communication error"));
        assert!(msg.contains("network timeout"));
    }

    #[test]
    fn test_object_storage_error_auth_debug() {
        let err = ObjectStorageError::Auth(make_io_error("test"));
        let dbg = format!("{:?}", err);
        assert!(dbg.contains("Auth"));
    }

    #[test]
    fn test_object_storage_error_into_backend_error() {
        let err = ObjectStorageError::Response("test".to_string());
        let backend_err: BackendError = err.into();
        assert!(matches!(backend_err, BackendError::ObjectStorage(_)));
    }

    // ── ObjectStorage construction and lifecycle ───────────────────────────

    #[test]
    fn test_new_object_storage_metrics_and_shutdown() {
        let metrics = BackendMetrics::new("obj-storage-lifecycle", "oss");
        let storage = ObjectStorage::new_object_storage(
            make_request(),
            Arc::new(MockState::new(5)),
            Some(metrics),
            Some("lifecycle-id".to_string()),
        );

        // metrics() must return the same object on repeated calls
        let m1 = storage.metrics() as *const BackendMetrics;
        let m2 = storage.metrics() as *const BackendMetrics;
        assert_eq!(
            m1, m2,
            "metrics() must return the same BackendMetrics instance"
        );

        // shutdown() must not panic
        storage.shutdown();
    }

    #[test]
    fn test_get_reader_with_metrics_returns_ok() {
        let metrics = BackendMetrics::new("obj-storage-get-reader-ok", "oss");
        let storage = ObjectStorage::new_object_storage(
            make_request(),
            Arc::new(MockState::new(3)),
            Some(metrics),
            Some("get-reader-ok-id".to_string()),
        );

        let result = storage.get_reader("test-blob-abc");
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_reader_without_metrics_returns_error() {
        let storage: ObjectStorage<MockState> = ObjectStorage::new_object_storage(
            make_request(),
            Arc::new(MockState::new(3)),
            None,
            None,
        );

        let result = storage.get_reader("any-blob");
        assert!(matches!(result, Err(BackendError::Unsupported(_))));
    }

    // ── ObjectStorageReader behaviour ─────────────────────────────────────

    #[test]
    fn test_reader_retry_limit() {
        let metrics = BackendMetrics::new("obj-storage-retry-limit", "oss");
        let storage = ObjectStorage::new_object_storage(
            make_request(),
            Arc::new(MockState::new(5)),
            Some(metrics),
            Some("retry-limit-id".to_string()),
        );

        let reader = storage.get_reader("blob-retry").unwrap();
        assert_eq!(reader.retry_limit(), 5);
    }

    #[test]
    fn test_reader_metrics_same_as_storage() {
        let metrics = BackendMetrics::new("obj-storage-reader-metrics", "oss");
        let storage = ObjectStorage::new_object_storage(
            make_request(),
            Arc::new(MockState::new(2)),
            Some(metrics),
            Some("reader-metrics-id".to_string()),
        );

        let reader = storage.get_reader("blob-metrics").unwrap();
        // The reader must expose the same BackendMetrics instance as the storage backend.
        assert!(std::ptr::eq(reader.metrics(), storage.metrics()));
    }

    #[test]
    fn test_reader_blob_size_uses_head_request() {
        let (base_url, shutdown, _seen_ranges) = start_object_storage_server(true);
        let state = Arc::new(MockState::with_base_url(4, base_url));
        let signed_methods = state.signed_methods.clone();
        let metrics = BackendMetrics::new("obj-storage-blob-size", "oss");
        let storage = ObjectStorage::new_object_storage(make_request(), state, Some(metrics), None);
        let reader = storage.get_reader("blob-head").unwrap();

        let size = reader.blob_size().unwrap();

        shutdown.store(true, Ordering::Relaxed);
        assert_eq!(size, OBJECT_STORAGE_TEST_CONTENT.len() as u64);
        assert_eq!(signed_methods.lock().unwrap().as_slice(), &[Method::HEAD]);
    }

    #[test]
    fn test_reader_blob_size_requires_content_length() {
        let (base_url, shutdown, _seen_ranges) = start_object_storage_server(false);
        let metrics = BackendMetrics::new("obj-storage-missing-length", "oss");
        let storage = ObjectStorage::new_object_storage(
            make_request(),
            Arc::new(MockState::with_base_url(2, base_url)),
            Some(metrics),
            None,
        );
        let reader = storage.get_reader("blob-missing-length").unwrap();

        let result = reader.blob_size();

        shutdown.store(true, Ordering::Relaxed);
        assert!(matches!(
            result,
            Err(BackendError::ObjectStorage(ObjectStorageError::Response(msg)))
                if msg == "invalid content length"
        ));
    }

    #[test]
    fn test_reader_try_read_ctx_reads_requested_range() {
        let (base_url, shutdown, seen_ranges) = start_object_storage_server(true);
        let state = Arc::new(MockState::with_base_url(3, base_url));
        let signed_methods = state.signed_methods.clone();
        let metrics = BackendMetrics::new("obj-storage-range-read", "oss");
        let storage = ObjectStorage::new_object_storage(make_request(), state, Some(metrics), None);
        let reader = storage.get_reader("blob-read").unwrap();
        let mut buf = vec![0u8; 6];
        let mut ctx = BackendContext::default();

        let size = reader.try_read_ctx(&mut buf, 2, Some(&mut ctx)).unwrap();

        shutdown.store(true, Ordering::Relaxed);
        assert_eq!(size, 6);
        assert_eq!(&buf, b"ject-s");
        assert_eq!(seen_ranges.lock().unwrap().as_slice(), &["bytes=2-7"]);
        assert_eq!(signed_methods.lock().unwrap().as_slice(), &[Method::GET]);
    }

    #[test]
    fn test_reader_propagates_sign_errors() {
        let metrics = BackendMetrics::new("obj-storage-sign-error", "oss");
        let storage = ObjectStorage::new_object_storage(
            make_request(),
            Arc::new(MockState::with_sign_error(1, "sign failed")),
            Some(metrics),
            None,
        );
        let reader = storage.get_reader("blob-sign-error").unwrap();

        let result = reader.blob_size();

        assert!(matches!(
            result,
            Err(BackendError::ObjectStorage(ObjectStorageError::Auth(err)))
                if err.to_string().contains("sign failed")
        ));
    }

    #[test]
    fn test_stream_read_offset_zero_no_range_header() {
        let (base_url, shutdown, seen_ranges) = start_object_storage_server(true);
        let state = Arc::new(MockState::with_base_url(3, base_url));
        let metrics = BackendMetrics::new("obj-storage-stream-zero", "oss");
        let storage = ObjectStorage::new_object_storage(make_request(), state, Some(metrics), None);
        let reader = storage.get_reader("blob-stream-zero").unwrap();
        let mut ctx = BackendContext::default();

        let mut stream = reader.try_stream_read(0, Some(&mut ctx)).unwrap();
        let mut body = Vec::new();
        stream.read_to_end(&mut body).unwrap();

        shutdown.store(true, Ordering::Relaxed);
        assert_eq!(body, OBJECT_STORAGE_TEST_CONTENT);
        // offset==0 means no Range header was sent
        assert_eq!(seen_ranges.lock().unwrap().as_slice(), &["none"]);
    }

    #[test]
    fn test_stream_read_offset_nonzero_open_range() {
        let (base_url, shutdown, seen_ranges) = start_object_storage_server(true);
        let state = Arc::new(MockState::with_base_url(3, base_url));
        let metrics = BackendMetrics::new("obj-storage-stream-offset", "oss");
        let storage = ObjectStorage::new_object_storage(make_request(), state, Some(metrics), None);
        let reader = storage.get_reader("blob-stream-offset").unwrap();
        let mut ctx = BackendContext::default();

        let mut stream = reader.try_stream_read(7, Some(&mut ctx)).unwrap();
        let mut body = Vec::new();
        stream.read_to_end(&mut body).unwrap();

        shutdown.store(true, Ordering::Relaxed);
        assert_eq!(body, &OBJECT_STORAGE_TEST_CONTENT[7..]);
        assert_eq!(seen_ranges.lock().unwrap().as_slice(), &["bytes=7-"]);
    }
}
