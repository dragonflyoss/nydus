// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Storage backends to read blob data from Registry, OSS, disk, file system etc.
//!
//! There are several types of storage backend drivers implemented:
//! - [Registry](registry/struct.Registry.html): backend driver to access blobs on container image
//!   registry.
//! - [Oss](oss/struct.Oss.html): backend driver to access blobs on Oss(Object Storage System).
//! - [LocalFs](localfs/struct.LocalFs.html): backend driver to access blobs on local file system.
//!   The [LocalFs](localfs/struct.LocalFs.html) storage backend supports backend level data
//!   prefetching, which is to load data into page cache.
//! - [LocalDisk](localdisk/struct.LocalDisk.html): backend driver to access blobs on local disk.

use std::fmt;
use std::io::Read;
use std::thread::sleep;
use std::{sync::Arc, time::Duration};

use fuse_backend_rs::file_buf::FileVolatileSlice;
use nydus_utils::metrics::BackendMetrics;

use crate::utils::{alloc_buf, copyv};
use crate::StorageError;

#[cfg(any(
    feature = "backend-oss",
    feature = "backend-registry",
    feature = "backend-s3",
    feature = "backend-http-proxy",
))]
pub mod connection;
#[cfg(feature = "backend-http-proxy")]
pub mod http_proxy;
#[cfg(feature = "backend-localdisk")]
pub mod localdisk;
#[cfg(feature = "backend-localfs")]
pub mod localfs;
#[cfg(any(feature = "backend-oss", feature = "backend-s3"))]
pub mod object_storage;
#[cfg(feature = "backend-oss")]
pub mod oss;
#[cfg(feature = "backend-registry")]
pub mod registry;
#[cfg(feature = "backend-s3")]
pub mod s3;

#[cfg(feature = "backend-hickory-dns")]
pub mod hickory;
pub mod pauser;
#[cfg(any(
    feature = "backend-oss",
    feature = "backend-registry",
    feature = "backend-s3",
    feature = "backend-http-proxy",
))]
pub mod proxy;
#[cfg(feature = "backend-qps-limit")]
pub mod qps;
#[cfg(any(
    feature = "backend-oss",
    feature = "backend-registry",
    feature = "backend-s3",
    feature = "backend-http-proxy",
))]
pub mod request;
#[cfg(feature = "backend-oss")]
pub mod url_encoding;

/// Source of a backend read request, used for retry policy decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RequestSource {
    /// On-demand read triggered by user I/O.
    #[default]
    OnDemand,
    /// Background prefetch read.
    Prefetch,
}

impl fmt::Display for RequestSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestSource::OnDemand => write!(f, "ondemand"),
            RequestSource::Prefetch => write!(f, "prefetch"),
        }
    }
}

/// Per-request context for proxy-aware backend operations.
///
/// Tracks request source (on-demand vs prefetch), proxy routing state,
/// and error information across retry attempts.
#[derive(Debug, Clone, Default)]
pub struct BackendContext {
    /// Whether this request is on-demand or prefetch.
    pub request_source: RequestSource,
    /// Set to true to bypass the proxy and request directly from source.
    pub disable_proxy: bool,
    /// Set to true to disable Dragonfly SDK mode and fall back to HTTP proxy.
    pub disable_proxy_sdk: bool,
    /// Whether the current attempt is using Dragonfly SDK.
    pub using_proxy_sdk: bool,
    /// Error message from the last failed attempt.
    pub error: Option<String>,
}

#[cfg(feature = "backend-qps-limit")]
lazy_static::lazy_static! {
    /// Global QPS limiter for source backend fallback, limited to 1 QPS.
    pub static ref BACKEND_QPS_LIMITER: self::qps::QpsLimiter = self::qps::QpsLimiter::new(1.0);
    /// Global pauser for backend requests, allows pausing all requests.
    pub static ref BACKEND_PAUSER: self::pauser::Pauser = self::pauser::Pauser::new();
}

/// Error codes related to storage backend operations.
#[derive(Debug)]
pub enum BackendError {
    /// Unsupported operation.
    Unsupported(String),
    /// Failed to copy data from/into blob.
    CopyData(StorageError),
    #[cfg(feature = "backend-localdisk")]
    /// Error from LocalDisk storage backend.
    LocalDisk(self::localdisk::LocalDiskError),
    #[cfg(feature = "backend-registry")]
    /// Error from Registry storage backend.
    Registry(self::registry::RegistryError),
    #[cfg(feature = "backend-localfs")]
    /// Error from LocalFs storage backend.
    LocalFs(self::localfs::LocalFsError),
    #[cfg(any(feature = "backend-oss", feature = "backend-s3"))]
    /// Error from object storage backend.
    ObjectStorage(self::object_storage::ObjectStorageError),
    #[cfg(feature = "backend-http-proxy")]
    /// Error from local http proxy backend.
    HttpProxy(self::http_proxy::HttpProxyError),
    #[cfg(any(
        feature = "backend-oss",
        feature = "backend-registry",
        feature = "backend-s3",
        feature = "backend-http-proxy",
    ))]
    /// Error from the request routing layer.
    Request(self::request::RequestError),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendError::Unsupported(s) => write!(f, "{}", s),
            BackendError::CopyData(e) => write!(f, "failed to copy data, {}", e),
            #[cfg(feature = "backend-registry")]
            BackendError::Registry(e) => write!(f, "{:?}", e),
            #[cfg(feature = "backend-localfs")]
            BackendError::LocalFs(e) => write!(f, "{}", e),
            #[cfg(any(feature = "backend-oss", feature = "backend-s3"))]
            BackendError::ObjectStorage(e) => write!(f, "{}", e),
            #[cfg(feature = "backend-localdisk")]
            BackendError::LocalDisk(e) => write!(f, "{:?}", e),
            #[cfg(feature = "backend-http-proxy")]
            BackendError::HttpProxy(e) => write!(f, "{}", e),
            #[cfg(any(
                feature = "backend-oss",
                feature = "backend-registry",
                feature = "backend-s3",
                feature = "backend-http-proxy",
            ))]
            BackendError::Request(e) => write!(f, "request error: {:?}", e),
        }
    }
}

/// Specialized `Result` for storage backends.
pub type BackendResult<T> = std::result::Result<T, BackendError>;

impl BackendError {
    /// Returns true if this error represents a proxy-forbidden (403) response.
    pub fn is_proxy_forbidden(&self) -> bool {
        #[cfg(all(
            feature = "backend-dragonfly-proxy",
            any(
                feature = "backend-oss",
                feature = "backend-registry",
                feature = "backend-s3",
                feature = "backend-http-proxy"
            )
        ))]
        if let BackendError::Request(self::request::RequestError::Proxy(
            self::proxy::ProxyError::Forbidden(_),
        )) = self
        {
            return true;
        }
        false
    }

    /// Returns true if this error represents a proxy rate-limit (429) response.
    pub fn is_proxy_limited(&self) -> bool {
        #[cfg(all(
            feature = "backend-dragonfly-proxy",
            any(
                feature = "backend-oss",
                feature = "backend-registry",
                feature = "backend-s3",
                feature = "backend-http-proxy"
            )
        ))]
        if let BackendError::Request(self::request::RequestError::Proxy(
            self::proxy::ProxyError::TooManyRequests(_),
        )) = self
        {
            return true;
        }
        false
    }

    /// Returns true if this is a proxy SDK internal error.
    pub fn is_proxy_sdk_internal(&self) -> bool {
        #[cfg(all(
            feature = "backend-dragonfly-proxy",
            any(
                feature = "backend-oss",
                feature = "backend-registry",
                feature = "backend-s3",
                feature = "backend-http-proxy"
            )
        ))]
        if let BackendError::Request(self::request::RequestError::Proxy(
            self::proxy::ProxyError::Internal(_),
        )) = self
        {
            return true;
        }
        false
    }
}

#[cfg(feature = "backend-qps-limit")]
fn random_duration(min_millis: u64, max_millis: u64) -> Duration {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    Duration::from_millis(rng.gen_range(min_millis..=max_millis))
}

/// Proxy-aware retry loop for backend read operations.
///
/// Retry policy:
/// - On-demand requests get 3 retries, prefetch gets 1
/// - Proxy-forbidden (403): return immediately, no retry
/// - Proxy rate-limited (429) + prefetch: return immediately
/// - Proxy rate-limited + on-demand: disable proxy, apply QPS limiter, retry via source
/// - SDK internal error: disable SDK, retry via HTTP proxy
/// - Last retry: disable proxy and apply QPS limiter for source fallback
/// - Prefetch retries: random sleep 100ms-1s between attempts
pub fn retry_op<T, F>(
    metrics: &BackendMetrics,
    context: &mut BackendContext,
    data_len: usize,
    mut op: F,
) -> BackendResult<T>
where
    F: FnMut(&mut BackendContext) -> BackendResult<T>,
{
    let is_prefetch = context.request_source == RequestSource::Prefetch;
    let mut retry_count: u32 = if is_prefetch { 1 } else { 3 };

    loop {
        context.using_proxy_sdk = false;
        let begin_time = metrics.begin();
        let ret = op(context);

        match ret {
            Ok(val) => {
                context.error = None;
                metrics.end(&begin_time, data_len, false);
                return Ok(val);
            }
            Err(err) => {
                context.error = Some(format!("{:?}", err));
                metrics.end(&begin_time, data_len, true);

                let proxy_forbidden = err.is_proxy_forbidden();
                if proxy_forbidden {
                    warn!("proxy blocked the request");
                }

                let proxy_limited = err.is_proxy_limited();
                if proxy_limited {
                    warn!("proxy rate limited the request");
                }

                let proxy_sdk_internal = err.is_proxy_sdk_internal();
                if proxy_sdk_internal {
                    warn!("proxy SDK internal error, fallback to proxy mode");
                    context.disable_proxy_sdk = true;
                }

                // SDK retries internally, reduce retry count
                if context.using_proxy_sdk && !proxy_sdk_internal {
                    if is_prefetch {
                        retry_count = 0;
                    } else if retry_count > 1 {
                        retry_count = 1;
                    }
                }

                // Do not retry for:
                // 1. No remaining retry count
                // 2. Proxy forbidden
                // 3. Proxy limited + prefetch
                if retry_count > 0 && !proxy_forbidden && !(proxy_limited && is_prefetch) {
                    retry_count -= 1;

                    // Last retry or rate-limited on-demand: disable proxy, use QPS limiter
                    if (retry_count == 0 || proxy_limited) && !is_prefetch {
                        warn!(
                            "retry via source backend with QPS limiter, remains: {}",
                            retry_count
                        );
                        context.disable_proxy = true;
                        #[cfg(feature = "backend-qps-limit")]
                        {
                            let limited = BACKEND_QPS_LIMITER.acquire();
                            if limited {
                                warn!("source backend request rate-limited by QPS limiter");
                            }
                        }
                    } else {
                        context.disable_proxy = false;
                        if is_prefetch {
                            #[cfg(feature = "backend-qps-limit")]
                            {
                                let duration = random_duration(100, 1000);
                                warn!(
                                    "retry prefetch, remains: {}, sleep: {:?}",
                                    retry_count, duration
                                );
                                sleep(duration);
                            }
                            #[cfg(not(feature = "backend-qps-limit"))]
                            {
                                warn!("retry prefetch, remains: {}", retry_count);
                                sleep(Duration::from_millis(500));
                            }
                        } else {
                            warn!("retry via proxy, remains: {}", retry_count);
                        }
                    }
                } else {
                    break Err(err);
                }
            }
        }
    }
}

pub trait BlobReader: Send + Sync {
    /// Get size of the blob file.
    fn blob_size(&self) -> BackendResult<u64>;

    /// Try to read a range of data from the blob file into the provided buffer.
    ///
    /// Try to read data of range [offset, offset + buf.len()) from the blob file, and returns:
    /// - bytes of data read, which may be smaller than buf.len()
    /// - error code if error happens
    fn try_read(&self, buf: &mut [u8], offset: u64) -> BackendResult<usize>;

    /// Try to read a range of data from the blob file with optional context.
    ///
    /// The context carries proxy routing state for retry decisions.
    /// Default implementation ignores the context and delegates to `try_read`.
    fn try_read_ctx(
        &self,
        buf: &mut [u8],
        offset: u64,
        _ctx: Option<&mut BackendContext>,
    ) -> BackendResult<usize> {
        self.try_read(buf, offset)
    }

    /// Whether `read()` should enforce that the backend returns exactly the
    /// requested number of bytes. Remote backends return `true` (default) so
    /// that short reads are retried as transient errors. Local backends
    /// override this to return `false`, since short reads at EOF are expected.
    fn expect_exact_read(&self) -> bool {
        true
    }

    /// Read a range of data from the blob file into the provided buffer.
    ///
    /// For remote backends, a short read is treated as a transient error and
    /// retried. For local backends (`expect_exact_read() == false`), a short
    /// read is returned as-is.
    ///
    /// It will try `BlobBackend::retry_limit()` times at most and return the first successfully
    /// read data.
    fn read(&self, buf: &mut [u8], offset: u64) -> BackendResult<usize> {
        let mut ctx = BackendContext::default();
        let buf_len = buf.len();
        let strict = self.expect_exact_read();
        retry_op(self.metrics(), &mut ctx, buf_len, |ctx| {
            let size = self.try_read_ctx(buf, offset, Some(ctx))?;
            if strict && size != buf_len {
                return Err(BackendError::CopyData(StorageError::CacheIndex(
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("expected {} bytes, got {}", buf_len, size),
                    ),
                )));
            }
            Ok(size)
        })
    }

    /// Read as much as possible data into buffer.
    fn read_all(&self, buf: &mut [u8], offset: u64) -> BackendResult<usize> {
        let mut off = 0usize;
        let mut left = buf.len();

        while left > 0 {
            let mut ctx = BackendContext::default();
            let current_off = off;
            let cnt = retry_op(self.metrics(), &mut ctx, left, |ctx| {
                self.try_read_ctx(
                    &mut buf[current_off..],
                    offset + current_off as u64,
                    Some(ctx),
                )
            })?;
            if cnt == 0 {
                break;
            }
            off += cnt;
            left -= cnt;
        }

        Ok(off)
    }

    /// Read a range of data from the blob file into the provided buffers.
    ///
    /// Read data of range [offset, offset + max_size) from the blob file, and returns:
    /// - bytes of data read, which may be smaller than max_size
    /// - error code if error happens
    ///
    /// It will try `BlobBackend::retry_limit()` times at most and return the first successfully
    /// read data.
    fn readv(
        &self,
        bufs: &[FileVolatileSlice],
        offset: u64,
        max_size: usize,
    ) -> BackendResult<usize> {
        if bufs.len() == 1 && max_size >= bufs[0].len() {
            let buf = unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), bufs[0].len()) };
            self.read(buf, offset)
        } else {
            // Use std::alloc to avoid zeroing the allocated buffer.
            let size = bufs.iter().fold(0usize, move |size, s| size + s.len());
            let size = std::cmp::min(size, max_size);
            let mut data = alloc_buf(size);

            let result = self.read(&mut data, offset)?;
            copyv(&[&data], bufs, 0, result, 0, 0)
                .map(|r| r.0)
                .map_err(BackendError::CopyData)
        }
    }

    /// Get metrics object.
    fn metrics(&self) -> &BackendMetrics;

    /// Get maximum number of times to retry when encountering IO errors.
    fn retry_limit(&self) -> u8 {
        0
    }
}

/// Trait to access blob files on backend storages, such as OSS, registry, local fs etc.
pub trait BlobBackend: Send + Sync {
    /// Destroy the `BlobBackend` storage object.
    fn shutdown(&self);

    /// Get metrics object.
    fn metrics(&self) -> &BackendMetrics;

    /// Get a blob reader object to access blob `blob_id`.
    fn get_reader(&self, blob_id: &str) -> BackendResult<Arc<dyn BlobReader>>;
}

/// A buffered reader for `BlobReader` object.
pub struct BlobBufReader {
    buf: Vec<u8>,
    pos: usize,
    len: usize,
    start: u64,
    size: u64,
    reader: Arc<dyn BlobReader>,
}

impl BlobBufReader {
    /// Create a new instance of `BlobBufReader`.
    pub fn new(buf_size: usize, reader: Arc<dyn BlobReader>, start: u64, size: u64) -> Self {
        Self {
            buf: alloc_buf(buf_size),
            pos: 0,
            len: 0,
            start,
            size,
            reader,
        }
    }
}

impl Read for BlobBufReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut sz = self.len;
        if sz == 0 && self.size == 0 {
            // No more data.
            return Ok(0);
        }

        // Refill the buffer.
        if sz == 0 && self.size > 0 {
            let cnt = std::cmp::min(self.buf.len() as u64, self.size) as usize;
            let ret = self
                .reader
                .read(&mut self.buf[..cnt], self.start)
                .map_err(|e| eio!(format!("failed to read data from backend, {:?}", e)))?;
            self.start += ret as u64;
            self.size -= ret as u64;
            self.pos = 0;
            self.len = ret;
            sz = ret;
        }
        if self.size != 0 && sz == 0 {
            return Err(eio!("unexpected EOF when reading data from backend"));
        }

        let sz = std::cmp::min(sz, buf.len());
        buf[..sz].copy_from_slice(&self.buf[self.pos..self.pos + sz]);
        self.pos += sz;
        self.len -= sz;

        Ok(sz)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    // Mock BlobReader for testing
    struct MockBlobReader {
        data: Vec<u8>,
        metrics: Arc<BackendMetrics>,
    }

    impl MockBlobReader {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                metrics: BackendMetrics::new("mock", "mock-instance"),
            }
        }
    }

    impl BlobReader for MockBlobReader {
        fn blob_size(&self) -> BackendResult<u64> {
            Ok(self.data.len() as u64)
        }

        fn try_read(&self, buf: &mut [u8], offset: u64) -> BackendResult<usize> {
            let offset = offset as usize;
            if offset >= self.data.len() {
                return Ok(0);
            }
            let len = std::cmp::min(buf.len(), self.data.len() - offset);
            buf[..len].copy_from_slice(&self.data[offset..offset + len]);
            Ok(len)
        }

        fn metrics(&self) -> &BackendMetrics {
            &self.metrics
        }

        fn retry_limit(&self) -> u8 {
            3
        }
    }

    #[test]
    fn test_backend_error_display() {
        let err = BackendError::Unsupported("test operation".to_string());
        assert_eq!(format!("{}", err), "test operation");

        let err = BackendError::CopyData(StorageError::Unsupported);
        assert!(format!("{}", err).contains("failed to copy data"));
    }

    #[test]
    fn test_blob_reader_try_read() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let reader = MockBlobReader::new(data);

        let mut buf = vec![0u8; 4];
        let sz = reader.try_read(&mut buf, 0).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(buf, vec![1, 2, 3, 4]);

        let sz = reader.try_read(&mut buf, 4).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(buf, vec![5, 6, 7, 8]);
    }

    #[test]
    fn test_blob_reader_read() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let reader = MockBlobReader::new(data);

        let mut buf = vec![0u8; 4];
        let sz = reader.read(&mut buf, 2).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(buf, vec![3, 4, 5, 6]);
    }

    #[test]
    fn test_blob_reader_read_all() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let reader = MockBlobReader::new(data);

        let mut buf = vec![0u8; 10];
        let sz = reader.read_all(&mut buf, 0).unwrap();
        assert_eq!(sz, 8);
        assert_eq!(&buf[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_blob_reader_blob_size() {
        let data = vec![1, 2, 3, 4, 5];
        let reader = MockBlobReader::new(data);
        assert_eq!(reader.blob_size().unwrap(), 5);
    }

    #[test]
    fn test_blob_reader_retry_limit() {
        let reader = MockBlobReader::new(vec![]);
        assert_eq!(reader.retry_limit(), 3);
    }

    #[test]
    fn test_blob_buf_reader_read() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let reader = Arc::new(MockBlobReader::new(data));
        let mut buf_reader = BlobBufReader::new(4, reader, 0, 10);

        let mut buf = vec![0u8; 3];
        let sz = buf_reader.read(&mut buf).unwrap();
        assert_eq!(sz, 3);
        assert_eq!(buf, vec![1, 2, 3]);

        let sz = buf_reader.read(&mut buf).unwrap();
        assert_eq!(sz, 1);
        assert_eq!(&buf[..1], &[4]);
    }

    #[test]
    fn test_blob_buf_reader_read_eof() {
        let data = vec![1, 2, 3, 4];
        let reader = Arc::new(MockBlobReader::new(data));
        let mut buf_reader = BlobBufReader::new(8, reader, 0, 4);

        let mut buf = vec![0u8; 10];
        let sz = buf_reader.read(&mut buf).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(&buf[..4], &[1, 2, 3, 4]);

        let sz = buf_reader.read(&mut buf).unwrap();
        assert_eq!(sz, 0);
    }

    #[test]
    fn test_blob_buf_reader_multiple_refills() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let reader = Arc::new(MockBlobReader::new(data));
        let mut buf_reader = BlobBufReader::new(3, reader, 0, 8);

        let mut buf = vec![0u8; 2];

        // First read
        let sz = buf_reader.read(&mut buf).unwrap();
        assert_eq!(sz, 2);
        assert_eq!(buf, vec![1, 2]);

        // Second read (still from buffer)
        let sz = buf_reader.read(&mut buf).unwrap();
        assert_eq!(sz, 1);
        assert_eq!(&buf[..1], &[3]);

        // Third read (refill needed)
        let sz = buf_reader.read(&mut buf).unwrap();
        assert_eq!(sz, 2);
        assert_eq!(buf, vec![4, 5]);
    }

    #[test]
    fn test_blob_buf_reader_with_offset() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let reader = Arc::new(MockBlobReader::new(data));
        let mut buf_reader = BlobBufReader::new(4, reader, 3, 5);

        let mut buf = vec![0u8; 10];
        let sz = buf_reader.read(&mut buf).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(&buf[..4], &[4, 5, 6, 7]);
    }

    #[test]
    fn test_backend_context_default() {
        let ctx = BackendContext::default();
        assert!(matches!(ctx.request_source, RequestSource::OnDemand));
        assert!(!ctx.disable_proxy);
        assert!(!ctx.disable_proxy_sdk);
        assert!(!ctx.using_proxy_sdk);
        assert!(ctx.error.is_none());
    }

    #[test]
    fn test_request_source_display() {
        assert_eq!(format!("{}", RequestSource::OnDemand), "ondemand");
        assert_eq!(format!("{}", RequestSource::Prefetch), "prefetch");
    }

    #[test]
    fn test_backend_error_is_proxy_forbidden() {
        let err = BackendError::Unsupported("test".to_string());
        assert!(!err.is_proxy_forbidden());
        assert!(!err.is_proxy_limited());
        assert!(!err.is_proxy_sdk_internal());
    }

    #[test]
    fn test_retry_op_success_on_first_try() {
        let metrics = BackendMetrics::new("test-retry-success", "test");
        let mut ctx = BackendContext::default();

        let result = retry_op(&metrics, &mut ctx, 1024, |_ctx| Ok(42usize));

        assert_eq!(result.unwrap(), 42);
        assert!(ctx.error.is_none());
    }

    #[test]
    fn test_retry_op_retries_on_failure() {
        let metrics = BackendMetrics::new("test-retry-fail", "test");
        let mut ctx = BackendContext::default();

        let mut attempt = 0;
        let result = retry_op(&metrics, &mut ctx, 1024, |_ctx| {
            attempt += 1;
            if attempt < 3 {
                Err(BackendError::Unsupported(format!("attempt {}", attempt)))
            } else {
                Ok(99usize)
            }
        });

        assert_eq!(result.unwrap(), 99);
        assert_eq!(attempt, 3);
    }

    #[test]
    fn test_retry_op_prefetch_fewer_retries() {
        let metrics = BackendMetrics::new("test-retry-prefetch", "test");
        let mut ctx = BackendContext {
            request_source: RequestSource::Prefetch,
            ..Default::default()
        };

        let mut attempt = 0;
        let result: BackendResult<usize> = retry_op(&metrics, &mut ctx, 1024, |_ctx| {
            attempt += 1;
            Err(BackendError::Unsupported(format!("attempt {}", attempt)))
        });

        assert!(result.is_err());
        // Prefetch gets 1 retry (initial attempt + 1 retry = 2 attempts max)
        assert!(attempt <= 2);
    }

    #[test]
    fn test_blob_reader_try_read_ctx_default() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let reader = MockBlobReader::new(data);

        let mut buf = vec![0u8; 4];
        // With None context, should delegate to try_read
        let sz = reader.try_read_ctx(&mut buf, 0, None).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(buf, vec![1, 2, 3, 4]);

        // With Some context, should also work (default impl ignores context)
        let mut ctx = BackendContext::default();
        let sz = reader.try_read_ctx(&mut buf, 4, Some(&mut ctx)).unwrap();
        assert_eq!(sz, 4);
        assert_eq!(buf, vec![5, 6, 7, 8]);
    }
}
