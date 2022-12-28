// Copyright 2022 Ant Group. All rights reserved.
// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Base module used to implement object storage backend drivers (such as oss, s3, etc.).

use std::fmt::Debug;
use std::io::{Error, Result};
use std::marker::Send;
use std::sync::Arc;

use reqwest::header::{HeaderMap, CONTENT_LENGTH};
use reqwest::{Method, StatusCode};

use nydus_utils::metrics::BackendMetrics;

use super::connection::{Connection, ConnectionError};
use super::{BackendError, BackendResult, BlobBackend, BlobReader};

/// Error codes related to object storage backend.
#[derive(Debug)]
pub enum ObjectStorageError {
    Common(String),
    Auth(Error),
    Url(String),
    Request(ConnectionError),
    ConstructHeader(String),
    Transport(reqwest::Error),
    Response(String),
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
    connection: Arc<Connection>,
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

        let resp = self
            .connection
            .call::<&[u8]>(Method::HEAD, url.as_str(), None, None, &mut headers, false)
            .map_err(ObjectStorageError::Request)?;
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

    fn try_read(&self, mut buf: &mut [u8], offset: u64) -> BackendResult<usize> {
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

        // Safe because the the call() is a synchronous operation.
        let mut resp = self
            .connection
            .call::<&[u8]>(Method::GET, url.as_str(), None, None, &mut headers, false)
            .map_err(ObjectStorageError::Request)?;

        let status = resp.status();

        if status == StatusCode::PARTIAL_CONTENT || status == StatusCode::OK {
            // TODO: Support multiple range request
            resp.copy_to(&mut buf)
                .map_err(|e| BackendError::ObjectStorage(ObjectStorageError::Transport(e)))
                .map(|size| size as usize)
        } else {
            Err(BackendError::ObjectStorage(ObjectStorageError::Common(
                format!("Unrecognized status code {} response {:?}", status, resp),
            )))
        }
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
    connection: Arc<Connection>,
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
        connection: Arc<Connection>,
        state: Arc<T>,
        metrics: Option<Arc<BackendMetrics>>,
        id: Option<String>,
    ) -> Self {
        ObjectStorage {
            connection,
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
        self.connection.shutdown();
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
                connection: self.connection.clone(),
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
