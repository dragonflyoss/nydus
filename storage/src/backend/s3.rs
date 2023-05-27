// Copyright 2022 Ant Group. All rights reserved.
// Copyright (C) 2022 Alibaba Cloud. All rights reserved.

// SPDX-License-Identifier: Apache-2.0

// ! Storage backend driver to access blobs on s3.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Result;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use http::Uri;
use nydus_api::S3Config;
use nydus_utils::metrics::BackendMetrics;
use reqwest::header::HeaderMap;
use reqwest::Method;
use sha2::{Digest, Sha256};
use time::{format_description, OffsetDateTime};

use crate::backend::connection::{Connection, ConnectionConfig};
use crate::backend::object_storage::{ObjectStorage, ObjectStorageState};

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const HEADER_HOST: &str = "Host";
const HEADER_AWZ_DATE: &str = "x-amz-date";
const HEADER_AWZ_CONTENT_SHA256: &str = "x-amz-content-sha256";
const S3_DEFAULT_ENDPOINT: &str = "s3.amazonaws.com";

#[derive(Debug)]
pub struct S3State {
    region: String,
    access_key_id: String,
    access_key_secret: String,
    scheme: String,
    object_prefix: String,
    endpoint: String,
    bucket_name: String,
    retry_limit: u8,
}

/// Storage backend to access data stored in S3.
pub type S3 = ObjectStorage<S3State>;

impl S3 {
    /// Create a new S3 storage backend.
    pub fn new(s3_config: &S3Config, id: Option<&str>) -> Result<S3> {
        let con_config: ConnectionConfig = s3_config.clone().into();
        let retry_limit = con_config.retry_limit;
        let connection = Connection::new(&con_config)?;
        let final_endpoint = if s3_config.endpoint.is_empty() {
            S3_DEFAULT_ENDPOINT.to_string()
        } else {
            s3_config.endpoint.clone()
        };

        let state = Arc::new(S3State {
            region: s3_config.region.clone(),
            scheme: s3_config.scheme.clone(),
            object_prefix: s3_config.object_prefix.clone(),
            endpoint: final_endpoint,
            access_key_id: s3_config.access_key_id.clone(),
            access_key_secret: s3_config.access_key_secret.clone(),
            bucket_name: s3_config.bucket_name.clone(),
            retry_limit,
        });
        let metrics = id.map(|i| BackendMetrics::new(i, "oss"));

        Ok(ObjectStorage::new_object_storage(
            connection,
            state,
            metrics,
            id.map(|i| i.to_string()),
        ))
    }
}

impl S3State {
    // modified based on https://github.com/minio/minio-rs/blob/5fea81d68d381fd2a4c27e4d259f7012de08ab77/src/s3/utils.rs#L155-L200
    // under apache 2.0 license
    fn get_canonical_headers(&self, map: &HeaderMap) -> (String, String) {
        let mut btmap: BTreeMap<String, String> = BTreeMap::new();

        for (k, values) in map.iter() {
            let key = k.as_str().to_lowercase();
            if "authorization" == key || "user-agent" == key {
                continue;
            }
            btmap.insert(key.clone(), values.to_str().unwrap().to_string());
        }

        let mut signed_headers = String::new();
        let mut canonical_headers = String::new();
        let mut add_delim = false;
        for (key, value) in &btmap {
            if add_delim {
                signed_headers.push(';');
                canonical_headers.push('\n');
            }

            signed_headers.push_str(key);

            canonical_headers.push_str(key);
            canonical_headers.push(':');
            canonical_headers.push_str(value);

            add_delim = true;
        }

        (signed_headers, canonical_headers)
    }

    // modified based on https://github.com/minio/minio-rs/blob/5fea81d68d381fd2a4c27e4d259f7012de08ab77/src/s3/signer.rs#L44-L64
    // under apache 2.0 license
    fn get_canonical_request_hash(
        &self,
        method: &Method,
        uri: &str,
        query_string: &str,
        headers: &str,
        signed_headers: &str,
        content_sha256: &str,
    ) -> String {
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n\n{}\n{}",
            method, uri, query_string, headers, signed_headers, content_sha256
        );
        return sha256_hash(canonical_request.as_bytes());
    }

    // modified based on https://github.com/minio/minio-rs/blob/5fea81d68d381fd2a4c27e4d259f7012de08ab77/src/s3/signer.rs#L75-88
    // under apache 2.0 license
    pub fn get_signing_key(&self, date: &OffsetDateTime) -> Vec<u8> {
        let mut key: Vec<u8> = b"AWS4".to_vec();
        key.extend(self.access_key_secret.as_bytes());

        let date_key = hmac_hash(key.as_slice(), to_signer_date(date).as_bytes());
        let date_region_key = hmac_hash(date_key.as_slice(), self.region.as_bytes());
        let date_region_service_key = hmac_hash(date_region_key.as_slice(), "s3".as_bytes());
        return hmac_hash(date_region_service_key.as_slice(), b"aws4_request");
    }
}

impl ObjectStorageState for S3State {
    fn url(&self, obj_key: &str, query_str: &[&str]) -> (String, String) {
        let query_str = if query_str.is_empty() {
            "".to_string()
        } else {
            format!("?{}", query_str.join("&"))
        };
        let resource = format!(
            "/{}/{}{}{}",
            self.bucket_name, self.object_prefix, obj_key, query_str
        );
        let url = format!("{}://{}{}", self.scheme, self.endpoint, resource,);
        (resource, url)
    }

    // modified based on https://github.com/minio/minio-rs/blob/5fea81d68d381fd2a4c27e4d259f7012de08ab77/src/s3/signer.rs#L106-L135
    // under apache 2.0 license
    /// generate s3 request signature
    fn sign(
        &self,
        verb: Method,
        headers: &mut HeaderMap,
        _: &str,
        full_resource_url: &str,
    ) -> Result<()> {
        let date = OffsetDateTime::now_utc();
        let content_sha256 = EMPTY_SHA256;
        let parsed_uri = full_resource_url
            .to_string()
            .parse::<Uri>()
            .map_err(|e| einval!(e))?;
        let uri_path = parsed_uri.path();
        let query = parsed_uri.query().unwrap_or("");
        let host = parsed_uri.host().unwrap_or(self.endpoint.as_str());

        headers.insert(HEADER_HOST, host.parse().map_err(|e| einval!(e))?);
        headers.insert(
            HEADER_AWZ_DATE,
            to_awz_date(&date).parse().map_err(|e| einval!(e))?,
        );
        headers.insert(
            HEADER_AWZ_CONTENT_SHA256,
            EMPTY_SHA256.parse().map_err(|e| einval!(e))?,
        );
        let scope = format!(
            "{}/{}/{}/aws4_request",
            to_signer_date(&date),
            self.region,
            "s3",
        );
        let (signed_headers, canonical_headers) = self.get_canonical_headers(headers);
        let canonical_request_hash = self.get_canonical_request_hash(
            &verb,
            uri_path,
            query,
            &canonical_headers,
            &signed_headers,
            content_sha256,
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            to_awz_date(&date),
            scope,
            canonical_request_hash
        );
        let signing_key = self.get_signing_key(&date);
        let signature = hmac_hash_hex(signing_key.as_slice(), string_to_sign.as_bytes());
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key_id, scope, signed_headers, signature
        );
        headers.insert(
            "Authorization",
            authorization.parse().map_err(|e| einval!(e))?,
        );

        Ok(())
    }

    fn retry_limit(&self) -> u8 {
        self.retry_limit
    }
}

// modified based on https://github.com/minio/minio-rs/blob/5fea81d68d381fd2a4c27e4d259f7012de08ab77/src/s3/utils.rs#L52-L56
// under apache 2.0 license
fn sha256_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// modified based on https://github.com/minio/minio-rs/blob/5fea81d68d381fd2a4c27e4d259f7012de08ab77/src/s3/signer.rs#L25-L29
// under apache 2.0 license
fn hmac_hash(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hasher = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    hasher.update(data);
    hasher.finalize().into_bytes().to_vec()
}

// modified based on https://github.com/minio/minio-rs/blob/5fea81d68d381fd2a4c27e4d259f7012de08ab77/src/s3/signer.rs#L31-L33
// under apache 2.0 license
fn hmac_hash_hex(key: &[u8], data: &[u8]) -> String {
    hex::encode(hmac_hash(key, data))
}

// modified based on https://github.com/minio/minio-rs/blob/5fea81d68d381fd2a4c27e4d259f7012de08ab77/src/s3/utils.rs#L66-L68
// under apache 2.0 license
fn to_signer_date(date: &OffsetDateTime) -> String {
    let format = format_description::parse("[year][month][day]").unwrap();
    date.format(&format).unwrap()
}

// modified based on https://github.com/minio/minio-rs/blob/5fea81d68d381fd2a4c27e4d259f7012de08ab77/src/s3/utils.rs#L70-L72
// under apache 2.0 license
fn to_awz_date(date: &OffsetDateTime) -> String {
    let format = format_description::parse("[year][month][day]T[hour][minute][second]Z").unwrap();
    date.format(&format).unwrap()
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, Method};
    use nydus_api::S3Config;

    use crate::backend::object_storage::ObjectStorageState;
    use crate::backend::s3::S3State;
    use crate::backend::BlobBackend;

    use super::S3;

    fn get_test_s3_state() -> (S3State, String, String) {
        let state = S3State {
            region: "us-east-1".to_string(),
            access_key_id: "test-key".to_string(),
            access_key_secret: "test-key-secret".to_string(),
            scheme: "http".to_string(),
            object_prefix: "test-prefix-".to_string(),
            endpoint: "localhost:9000".to_string(),
            bucket_name: "test-bucket".to_string(),
            retry_limit: 6,
        };
        let (resource, url) = state.url("test-object", &["a=b", "c=d"]);
        (state, resource, url)
    }

    #[test]
    fn test_s3_new() {
        let config_str = r#"{
            "endpoint": "https://test.com",
            "region": "us-east-1",
            "access_key_id": "test",
            "access_key_secret": "test",
            "bucket_name": "antsys-nydus",
            "object_prefix":"nydus_v2/",
            "retry_limit": 6
        }"#;
        let config: S3Config = serde_json::from_str(config_str).unwrap();
        let s3 = S3::new(&config, Some("test-image")).unwrap();

        s3.metrics();

        let reader = s3.get_reader("test").unwrap();
        assert_eq!(reader.retry_limit(), 6);

        s3.shutdown();
    }

    #[test]
    fn test_s3_state_url() {
        let (_, resource, url) = get_test_s3_state();
        assert_eq!(resource, "/test-bucket/test-prefix-test-object?a=b&c=d");
        assert_eq!(
            url,
            "http://localhost:9000/test-bucket/test-prefix-test-object?a=b&c=d"
        );
    }

    #[test]
    fn test_s3_state_sign() {
        let (state, resource, url) = get_test_s3_state();
        println!("{}", url);
        let mut headers = HeaderMap::new();
        headers.append("Range", "bytes=5242900-".parse().unwrap());
        let result = state.sign(Method::GET, &mut headers, &resource, &url);
        assert!(result.is_ok());

        use regex::Regex;
        let re = Regex::new(r"^AWS4-HMAC-SHA256 Credential=test-key/[0-9]{8}/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=[A-Fa-f0-9]{64}$").unwrap();
        let authorization = headers.get("Authorization").unwrap();
        assert!(re.is_match(authorization.to_str().unwrap()));
    }
}
