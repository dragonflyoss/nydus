// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
use std::io::{Error, Result};
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use hmac::{Hmac, Mac, NewMac};
use reqwest::header::CONTENT_LENGTH;
use reqwest::{Method, StatusCode};
use sha1::Sha1;

use crate::storage::backend::request::{HeaderMap, Progress, ReqBody, Request, RequestError};
use crate::storage::backend::{default_http_scheme, BackendError, BackendResult};
use crate::storage::backend::{BlobBackend, BlobBackendUploader, CommonConfig};

use nydus_utils::{einval, metrics::BackendMetrics};

const HEADER_DATE: &str = "Date";
const HEADER_AUTHORIZATION: &str = "Authorization";

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug)]
pub enum OssError {
    Auth(Error),
    Url(String),
    Request(RequestError),
    ConstructHeader(String),
    Transport(reqwest::Error),
    Response(String),
}

type OssResult<T> = std::result::Result<T, OssError>;

impl From<OssError> for BackendError {
    fn from(error: OssError) -> Self {
        BackendError::Oss(error)
    }
}

#[derive(Debug)]
pub struct OSS {
    request: Arc<Request>,
    access_key_id: String,
    access_key_secret: String,
    scheme: String,
    object_prefix: String,
    endpoint: String,
    bucket_name: String,
    force_upload: bool,
    retry_limit: u8,
    metrics: Option<Arc<BackendMetrics>>,
    id: Option<String>,
}

#[derive(Clone, Deserialize)]
struct OssConfig {
    endpoint: String,
    access_key_id: String,
    access_key_secret: String,
    bucket_name: String,
    #[serde(default = "default_http_scheme")]
    scheme: String,
    /// Prefix object_prefix to OSS object key, for exmaple the
    /// simulation of subdirectory:
    /// object_key: sha256:xxx, object_prefix: nydus/
    /// object_key with object_prefix: nydus/sha256:xxx
    #[serde(default)]
    object_prefix: String,
}

impl OSS {
    /// generate oss request signature
    fn sign(
        &self,
        verb: Method,
        mut headers: HeaderMap,
        canonicalized_resource: &str,
    ) -> Result<HeaderMap> {
        let content_md5 = "";
        let content_type = "";
        let mut canonicalized_oss_headers = vec![];

        let date = httpdate::fmt_http_date(SystemTime::now());

        let mut data = vec![
            verb.as_str(),
            content_md5,
            content_type,
            date.as_str(),
            // canonicalized_oss_headers,
            canonicalized_resource,
        ];
        for (name, value) in &headers {
            let name = name.as_str();
            let value = value.to_str().map_err(|e| einval!(e))?;
            if name.starts_with("x-oss-") {
                let header = format!("{}:{}", name.to_lowercase(), value);
                canonicalized_oss_headers.push(header);
            }
        }
        let canonicalized_oss_headers = canonicalized_oss_headers.join("\n");
        if !canonicalized_oss_headers.is_empty() {
            data.insert(4, canonicalized_oss_headers.as_str());
        }
        let data = data.join("\n");
        let mut mac =
            HmacSha1::new_varkey(self.access_key_secret.as_bytes()).map_err(|e| einval!(e))?;
        mac.update(data.as_bytes());
        let signature = base64::encode(&mac.finalize().into_bytes());

        let authorization = format!("OSS {}:{}", self.access_key_id, signature);

        headers.insert(HEADER_DATE, date.as_str().parse().map_err(|e| einval!(e))?);
        headers.insert(
            HEADER_AUTHORIZATION,
            authorization.as_str().parse().map_err(|e| einval!(e))?,
        );

        Ok(headers)
    }

    fn resource(&self, object_key: &str, query_str: &str) -> String {
        format!("/{}/{}{}", self.bucket_name, object_key, query_str)
    }

    fn url(&self, object_key: &str, query: &[&str]) -> (String, String) {
        let object_key = &format!("{}{}", self.object_prefix, object_key);

        let url = format!(
            "{}://{}.{}/{}",
            self.scheme, self.bucket_name, self.endpoint, object_key
        );

        if query.is_empty() {
            (self.resource(object_key, ""), url)
        } else {
            let query_str = format!("?{}", query.join("&"));
            let resource = self.resource(object_key, &query_str);
            let url = format!("{}{}", url.as_str(), &query_str);
            (resource, url)
        }
    }

    #[allow(dead_code)]
    fn create_bucket(&self) -> OssResult<()> {
        let query = &[];
        let (resource, url) = self.url("", query);
        let headers = self
            .sign(Method::PUT, HeaderMap::new(), resource.as_str())
            .map_err(OssError::Auth)?;

        // Safe because the the call() is a synchronous operation.
        self.request
            .call::<&[u8]>(Method::PUT, url.as_str(), None, headers, true)
            .map_err(OssError::Request)?;

        Ok(())
    }

    fn blob_exists(&self, blob_id: &str) -> OssResult<bool> {
        let (resource, url) = self.url(blob_id, &[]);
        let headers = HeaderMap::new();
        let headers = self
            .sign(Method::HEAD, headers, resource.as_str())
            .map_err(OssError::Auth)?;

        let resp = self
            .request
            .call::<&[u8]>(Method::HEAD, url.as_str(), None, headers, false)
            .map_err(OssError::Request)?;

        if resp.status() == StatusCode::OK {
            return Ok(true);
        }

        Ok(false)
    }
}

pub fn new(config: serde_json::value::Value, id: Option<&str>) -> Result<OSS> {
    let common_config: CommonConfig =
        serde_json::from_value(config.clone()).map_err(|e| einval!(e))?;
    let force_upload = common_config.force_upload;
    let retry_limit = common_config.retry_limit;
    let request = Request::new(common_config)?;

    let config: OssConfig = serde_json::from_value(config).map_err(|e| einval!(e))?;

    Ok(OSS {
        scheme: config.scheme,
        object_prefix: config.object_prefix,
        endpoint: config.endpoint,
        access_key_id: config.access_key_id,
        access_key_secret: config.access_key_secret,
        bucket_name: config.bucket_name,
        request,
        force_upload,
        retry_limit,
        metrics: id.map(|i| BackendMetrics::new(i, "oss")),
        id: id.map(|i| i.to_string()),
    })
}

impl BlobBackend for OSS {
    #[inline]
    fn retry_limit(&self) -> u8 {
        self.retry_limit
    }

    fn metrics(&self) -> &BackendMetrics {
        // Safe because nydusd must have backend attached with id, only image builder can no id
        // but use backend instance to upload blob.
        self.metrics.as_ref().unwrap()
    }

    fn release(&self) {
        self.metrics()
            .release()
            .unwrap_or_else(|e| error!("{:?}", e))
    }

    fn prefetch_blob(
        &self,
        _blob_id: &str,
        _blob_readahead_offset: u32,
        _blob_readahead_size: u32,
    ) -> BackendResult<()> {
        Err(BackendError::Unsupported(
            "Oss backend does not support prefetch as per on-disk blob entries".to_string(),
        ))
    }

    fn blob_size(&self, blob_id: &str) -> BackendResult<u64> {
        let (resource, url) = self.url(blob_id, &[]);
        let headers = HeaderMap::new();
        let headers = self
            .sign(Method::HEAD, headers, resource.as_str())
            .map_err(OssError::Auth)?;

        let resp = self
            .request
            .call::<&[u8]>(Method::HEAD, url.as_str(), None, headers, true)
            .map_err(OssError::Request)?;

        let content_length = resp
            .headers()
            .get(CONTENT_LENGTH)
            .ok_or_else(|| OssError::Response("invalid content length".to_string()))?;

        Ok(content_length
            .to_str()
            .map_err(|err| OssError::Response(format!("invalid content length: {:?}", err)))?
            .parse::<u64>()
            .map_err(|err| OssError::Response(format!("invalid content length: {:?}", err)))?)
    }

    /// read ranged data from oss object
    fn try_read(&self, blob_id: &str, mut buf: &mut [u8], offset: u64) -> BackendResult<usize> {
        let query = &[];
        let (resource, url) = self.url(blob_id, query);

        let mut headers = HeaderMap::new();
        let end_at = offset + buf.len() as u64 - 1;
        let range = format!("bytes={}-{}", offset, end_at);
        headers.insert(
            "Range",
            range
                .as_str()
                .parse()
                .map_err(|e| OssError::ConstructHeader(format!("{}", e)))?,
        );
        let headers = self
            .sign(Method::GET, headers, resource.as_str())
            .map_err(OssError::Auth)?;

        // Safe because the the call() is a synchronous operation.
        let mut resp = self
            .request
            .call::<&[u8]>(Method::GET, url.as_str(), None, headers, true)
            .map_err(OssError::Request)?;

        Ok(resp
            .copy_to(&mut buf)
            .map_err(OssError::Transport)
            .map(|size| size as usize)?)
    }

    /// append data to oss object
    fn write(&self, blob_id: &str, buf: &[u8], offset: u64) -> BackendResult<usize> {
        let position = format!("position={}", offset);
        let query = &["append", position.as_str()];
        let (resource, url) = self.url(blob_id, query);
        let headers = self
            .sign(Method::POST, HeaderMap::new(), resource.as_str())
            .map_err(OssError::Auth)?;

        // Safe because the the call() is a synchronous operation.
        self.request
            .call::<&[u8]>(Method::POST, url.as_str(), None, headers, true)
            .map_err(OssError::Request)?;

        Ok(buf.len())
    }
}

impl BlobBackendUploader for OSS {
    fn upload(
        &self,
        blob_id: &str,
        blob_path: &Path,
        callback: fn((usize, usize)),
    ) -> Result<usize> {
        if !self.force_upload && self.blob_exists(blob_id).map_err(|e| einval!(e))? {
            return Ok(0);
        }

        let query = &[];
        let (resource, url) = self.url(blob_id, query);
        let headers = self.sign(Method::PUT, HeaderMap::new(), resource.as_str())?;

        let blob_file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(blob_path)
            .map_err(|e| {
                error!("oss blob upload: open failed {:?}", e);
                e
            })?;
        let size = blob_file.metadata()?.len() as usize;

        let body = Progress::new(blob_file, size, callback);

        self.request
            .call(
                Method::PUT,
                url.as_str(),
                Some(ReqBody::Read(body, size)),
                headers,
                true,
            )
            .map_err(|e| einval!(e))?;

        Ok(size as usize)
    }
}
