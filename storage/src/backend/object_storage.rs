// Copyright 2022 Ant Group. All rights reserved.
// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Base module used to implement object storage backend drivers (such as oss, s3, etc.).

use std::fmt;
use std::fmt::Debug;
use std::io::{Error, Result};
use std::marker::Send;
use std::sync::Arc;

use reqwest::header::{HeaderMap, CONTENT_LENGTH};
use reqwest::Method;

use nydus_utils::metrics::BackendMetrics;

use super::request;
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
    use std::io::Error as IoError;

    use nydus_api::ProxyConfig;
    use nydus_utils::metrics::BackendMetrics;

    use crate::backend::connection::{Connection, ConnectionConfig};

    fn make_io_error(msg: &str) -> IoError {
        IoError::other(msg)
    }

    // ── Minimal mock for ObjectStorageState ────────────────────────────────

    #[derive(Debug)]
    struct MockState {
        retry: u8,
    }

    impl MockState {
        fn new(retry: u8) -> Self {
            MockState { retry }
        }
    }

    impl ObjectStorageState for MockState {
        fn url(&self, object_key: &str, _query: &[&str]) -> (String, String) {
            let resource = format!("/test-bucket/{}", object_key);
            let url = format!("http://test.example.com{}", resource);
            (resource, url)
        }

        fn sign(
            &self,
            _verb: Method,
            _headers: &mut HeaderMap,
            _canonicalized_resource: &str,
            _full_resource_url: &str,
        ) -> std::io::Result<()> {
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
}
