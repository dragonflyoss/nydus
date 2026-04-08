// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Storage backend driver to access blobs on Oss(Object Storage System).
use std::io::Result;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use hmac::{Hmac, Mac};
use reqwest::header::HeaderMap;
use reqwest::Method;
use sha1::Sha1;

use nydus_api::OssConfig;
use nydus_utils::metrics::BackendMetrics;

use crate::backend::connection::{Connection, ConnectionConfig};
use crate::backend::object_storage::{ObjectStorage, ObjectStorageState};
use crate::backend::request;

const HEADER_DATE: &str = "Date";
const HEADER_AUTHORIZATION: &str = "Authorization";

type HmacSha1 = Hmac<Sha1>;

// `OssState` is almost identical to `OssConfig`, but let's keep them separated.
#[derive(Debug)]
pub struct OssState {
    access_key_id: String,
    access_key_secret: String,
    scheme: String,
    object_prefix: String,
    endpoint: String,
    bucket_name: String,
    retry_limit: u8,
}

impl OssState {
    fn resource(&self, object_key: &str, query_str: &str) -> String {
        format!("/{}/{}{}", self.bucket_name, object_key, query_str)
    }

    /// Generate a pre-signed URL query string for OSS access.
    #[allow(dead_code)]
    fn sign_by_url(&self, method: Method, resource: &str) -> Result<String> {
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| einval!(e))?
            .as_secs()
            + 3600;
        let string_to_sign = format!("{}\n\n\n{}\n{}", method.as_str(), expiry, resource);
        let hmac = HmacSha1::new_from_slice(self.access_key_secret.as_bytes())
            .map_err(|e| einval!(e))?
            .chain_update(string_to_sign.as_bytes())
            .finalize()
            .into_bytes();
        let signature = base64::engine::general_purpose::STANDARD.encode(hmac);
        Ok(format!(
            "OSSAccessKeyId={}&Expires={}&Signature={}",
            self.access_key_id,
            expiry,
            super::url_encoding::encode(&signature)
        ))
    }
}

impl ObjectStorageState for OssState {
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

    /// generate oss request signature
    fn sign(
        &self,
        verb: Method,
        headers: &mut HeaderMap,
        canonicalized_resource: &str,
        _: &str,
    ) -> Result<()> {
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

        for (name, value) in headers.iter() {
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
        let hmac = HmacSha1::new_from_slice(self.access_key_secret.as_bytes())
            .map_err(|e| einval!(e))?
            .chain_update(data.as_bytes())
            .finalize()
            .into_bytes();
        let signature = base64::engine::general_purpose::STANDARD.encode(hmac);

        let authorization = format!("OSS {}:{}", self.access_key_id, signature);

        headers.insert(HEADER_DATE, date.as_str().parse().map_err(|e| einval!(e))?);
        headers.insert(
            HEADER_AUTHORIZATION,
            authorization.as_str().parse().map_err(|e| einval!(e))?,
        );

        Ok(())
    }

    fn retry_limit(&self) -> u8 {
        self.retry_limit
    }
}

/// Storage backend to access data stored in OSS.
pub type Oss = ObjectStorage<OssState>;

impl Oss {
    /// Create a new OSS storage backend.
    pub fn new(oss_config: &OssConfig, id: Option<&str>) -> Result<Oss> {
        let con_config: ConnectionConfig = oss_config.clone().into();
        let retry_limit = con_config.retry_limit;
        let proxy_config = con_config.proxy.clone();
        let connection = Connection::new(&con_config)?;
        let request = request::Request::new(connection, proxy_config, false);
        let state = Arc::new(OssState {
            scheme: oss_config.scheme.clone(),
            object_prefix: oss_config.object_prefix.clone(),
            endpoint: oss_config.endpoint.clone(),
            access_key_id: oss_config.access_key_id.clone(),
            access_key_secret: oss_config.access_key_secret.clone(),
            bucket_name: oss_config.bucket_name.clone(),
            retry_limit,
        });
        let metrics = id.map(|i| BackendMetrics::new(i, "oss"));

        Ok(ObjectStorage::new_object_storage(
            request,
            state,
            metrics,
            id.map(|i| i.to_string()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::backend::BlobBackend;

    use super::*;

    #[test]
    fn test_oss_state() {
        let state = OssState {
            access_key_id: "key".to_string(),
            access_key_secret: "secret".to_string(),
            scheme: "https".to_string(),
            object_prefix: "nydus".to_string(),
            endpoint: "oss".to_string(),
            bucket_name: "images".to_string(),
            retry_limit: 5,
        };

        assert_eq!(
            state.resource("obj_key", "?idontcare"),
            "/images/obj_key?idontcare"
        );

        let (resource, url) = state.url("obj_key", &["idontcare", "second"]);
        assert_eq!(resource, "/images/nydusobj_key?idontcare&second");
        assert_eq!(url, "https://images.oss/nydusobj_key?idontcare&second");

        let mut headers = HeaderMap::new();
        state
            .sign(Method::HEAD, &mut headers, resource.as_str(), "")
            .unwrap();
        let signature = headers.get(HEADER_AUTHORIZATION).unwrap();
        assert!(signature.to_str().unwrap().contains("OSS key:"));
    }

    #[test]
    fn test_oss_new() {
        let json_str = "{\"access_key_id\":\"key\",\"access_key_secret\":\"secret\",\"bucket_name\":\"images\",\"endpoint\":\"/oss\",\"object_prefix\":\"nydus\",\"scheme\":\"\",\"proxy\":{\"url\":\"\",\"ping_url\":\"\",\"fallback\":true,\"check_interval\":5},\"timeout\":5,\"connect_timeout\":5,\"retry_limit\":5}";
        let config: OssConfig = serde_json::from_str(json_str).unwrap();
        let oss = Oss::new(&config, Some("test-image")).unwrap();

        oss.metrics();

        let reader = oss.get_reader("test").unwrap();
        assert_eq!(reader.retry_limit(), 5);

        oss.shutdown();
    }

    #[test]
    fn test_oss_new_no_id() {
        let json_str = "{\"access_key_id\":\"key\",\"access_key_secret\":\"secret\",\"bucket_name\":\"images\",\"endpoint\":\"/oss\",\"object_prefix\":\"\",\"scheme\":\"https\",\"proxy\":{\"url\":\"\",\"ping_url\":\"\",\"fallback\":true,\"check_interval\":5},\"timeout\":5,\"connect_timeout\":5,\"retry_limit\":3}";
        let config: OssConfig = serde_json::from_str(json_str).unwrap();
        // Passing None as id means no metrics object — get_reader would fail, so just verify construction succeeds
        let oss = Oss::new(&config, None).unwrap();
        // shutdown should still work
        oss.shutdown();
    }

    #[test]
    fn test_oss_url_empty_query() {
        let state = OssState {
            access_key_id: "key".to_string(),
            access_key_secret: "secret".to_string(),
            scheme: "https".to_string(),
            object_prefix: "prefix/".to_string(),
            endpoint: "oss-cn-hangzhou.aliyuncs.com".to_string(),
            bucket_name: "mybucket".to_string(),
            retry_limit: 1,
        };

        // Empty query slice takes the first branch
        let (resource, url) = state.url("myobj", &[]);
        assert_eq!(resource, "/mybucket/prefix/myobj");
        assert_eq!(
            url,
            "https://mybucket.oss-cn-hangzhou.aliyuncs.com/prefix/myobj"
        );
    }

    #[test]
    fn test_oss_sign_with_oss_headers() {
        let state = OssState {
            access_key_id: "ak".to_string(),
            access_key_secret: "sk".to_string(),
            scheme: "https".to_string(),
            object_prefix: "".to_string(),
            endpoint: "oss.example.com".to_string(),
            bucket_name: "bucket".to_string(),
            retry_limit: 0,
        };

        let mut headers = HeaderMap::new();
        // Add an x-oss-* header to exercise the canonicalized_oss_headers branch
        headers.insert(
            reqwest::header::HeaderName::from_static("x-oss-meta-author"),
            reqwest::header::HeaderValue::from_static("test"),
        );
        state
            .sign(Method::GET, &mut headers, "/bucket/someobj", "")
            .unwrap();

        let auth = headers.get(HEADER_AUTHORIZATION).unwrap();
        assert!(auth.to_str().unwrap().starts_with("OSS ak:"));
    }

    #[test]
    fn test_sign_by_url() {
        let state = OssState {
            access_key_id: "test-key-id".to_string(),
            access_key_secret: "test-key-secret".to_string(),
            scheme: "https".to_string(),
            object_prefix: "".to_string(),
            endpoint: "oss.example.com".to_string(),
            bucket_name: "test-bucket".to_string(),
            retry_limit: 1,
        };
        let result = state.sign_by_url(Method::GET, "/test-bucket/myobject");
        assert!(result.is_ok());
        let query = result.unwrap();
        assert!(query.contains("OSSAccessKeyId=test-key-id"));
        assert!(query.contains("Expires="));
        assert!(query.contains("Signature="));
    }

    #[test]
    fn test_oss_url_preserves_path_separators() {
        let state = OssState {
            access_key_id: "key".to_string(),
            access_key_secret: "secret".to_string(),
            scheme: "https".to_string(),
            object_prefix: "prefix/".to_string(),
            endpoint: "oss.example.com".to_string(),
            bucket_name: "mybucket".to_string(),
            retry_limit: 1,
        };
        let (resource, url) = state.url("subdir/file.tar.gz", &[]);
        // Both resource and URL preserve path separators
        assert_eq!(resource, "/mybucket/prefix/subdir/file.tar.gz");
        assert_eq!(
            url,
            "https://mybucket.oss.example.com/prefix/subdir/file.tar.gz"
        );
    }
}
