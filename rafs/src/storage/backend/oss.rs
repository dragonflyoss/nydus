// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
use std::io::Result;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use hmac::{Hmac, Mac, NewMac};
use reqwest::{Method, StatusCode};
use sha1::Sha1;
use url::Url;

use crate::storage::backend::default_http_scheme;
use crate::storage::backend::request::{HeaderMap, Progress, ReqBody, Request};
use crate::storage::backend::{BlobBackend, BlobBackendUploader, CommonConfig};

use nydus_utils::{einval, epipe};

const HEADER_DATE: &str = "Date";
const HEADER_AUTHORIZATION: &str = "Authorization";

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug)]
pub struct OSS {
    request: Arc<Request>,
    access_key_id: String,
    access_key_secret: String,
    scheme: String,
    endpoint: String,
    bucket_name: String,
    force_upload: bool,
    retry_limit: u8,
}

#[derive(Clone, Deserialize)]
struct OssConfig {
    endpoint: String,
    access_key_id: String,
    access_key_secret: String,
    bucket_name: String,
    #[serde(default = "default_http_scheme")]
    scheme: String,
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
        if canonicalized_oss_headers != "" {
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
        if self.bucket_name != "" {
            format!("/{}/{}{}", self.bucket_name, object_key, query_str)
        } else {
            format!("/{}{}", object_key, query_str)
        }
    }

    fn url(&self, object_key: &str, query: &[&str]) -> Result<(String, String)> {
        let url = if self.bucket_name != "" {
            format!("{}://{}.{}", self.scheme, self.bucket_name, self.endpoint)
        } else {
            format!("{}://{}", self.scheme, self.endpoint)
        };
        let mut url = Url::parse(url.as_str()).map_err(|e| einval!(e))?;

        url.path_segments_mut()
            .map_err(|e| einval!(e))?
            .push(object_key);

        if query.is_empty() {
            Ok((self.resource(object_key, ""), url.to_string()))
        } else {
            let query_str = format!("?{}", query.join("&"));
            let resource = self.resource(object_key, &query_str);
            let url = format!("{}{}", url.as_str(), &query_str);

            Ok((resource, url))
        }
    }

    #[allow(dead_code)]
    fn create_bucket(&self) -> Result<()> {
        let query = &[];
        let (resource, url) = self.url("", query)?;
        let headers = self.sign(Method::PUT, HeaderMap::new(), resource.as_str())?;

        // Safe because the the call() is a synchronous operation.
        self.request
            .call::<&[u8]>(Method::PUT, url.as_str(), None, headers, true)?;

        Ok(())
    }

    fn blob_exists(&self, blob_id: &str) -> Result<bool> {
        let (resource, url) = self.url(blob_id, &[])?;
        let headers = HeaderMap::new();
        let headers = self.sign(Method::HEAD, headers, resource.as_str())?;

        let resp = self
            .request
            .call::<&[u8]>(Method::HEAD, url.as_str(), None, headers, false)?;

        if resp.status() == StatusCode::OK {
            return Ok(true);
        }

        Ok(false)
    }
}

pub fn new(config: serde_json::value::Value) -> Result<OSS> {
    let common_config: CommonConfig =
        serde_json::from_value(config.clone()).map_err(|e| einval!(e))?;
    let force_upload = common_config.force_upload;
    let retry_limit = common_config.retry_limit;
    let request = Request::new(common_config)?;

    let config: OssConfig = serde_json::from_value(config).map_err(|e| einval!(e))?;

    Ok(OSS {
        scheme: config.scheme,
        endpoint: config.endpoint,
        access_key_id: config.access_key_id,
        access_key_secret: config.access_key_secret,
        bucket_name: config.bucket_name,
        request,
        force_upload,
        retry_limit,
    })
}

impl BlobBackend for OSS {
    #[inline]
    fn retry_limit(&self) -> u8 {
        self.retry_limit
    }

    /// read ranged data from oss object
    fn try_read(&self, blob_id: &str, mut buf: &mut [u8], offset: u64) -> Result<usize> {
        let query = &[];
        let (resource, url) = self.url(blob_id, query)?;

        let mut headers = HeaderMap::new();
        let end_at = offset + buf.len() as u64 - 1;
        let range = format!("bytes={}-{}", offset, end_at);
        headers.insert("Range", range.as_str().parse().map_err(|e| einval!(e))?);
        let headers = self.sign(Method::GET, headers, resource.as_str())?;

        // Safe because the the call() is a synchronous operation.
        let mut resp = self
            .request
            .call::<&[u8]>(Method::GET, url.as_str(), None, headers, true)
            .map_err(|e| epipe!(format!("oss req failed {:?}", e)))?;

        resp.copy_to(&mut buf)
            .map_err(|err| epipe!(format!("oss read failed {:?}", err)))
            .map(|size| size as usize)
    }

    /// append data to oss object
    fn write(&self, blob_id: &str, buf: &[u8], offset: u64) -> Result<usize> {
        let position = format!("position={}", offset);
        let query = &["append", position.as_str()];
        let (resource, url) = self.url(blob_id, query)?;
        let headers = self.sign(Method::POST, HeaderMap::new(), resource.as_str())?;

        // Safe because the the call() is a synchronous operation.
        self.request
            .call::<&[u8]>(Method::POST, url.as_str(), None, headers, true)?;

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
        if !self.force_upload && self.blob_exists(blob_id)? {
            return Ok(0);
        }

        let query = &[];
        let (resource, url) = self.url(blob_id, query)?;
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

        self.request.call(
            Method::PUT,
            url.as_str(),
            Some(ReqBody::Read(body, size)),
            headers,
            true,
        )?;

        Ok(size as usize)
    }
}
