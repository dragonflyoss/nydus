// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Storage backend driver to access blobs on Oss(Object Storage System).
use std::io::Result;
use std::sync::Arc;
use std::time::SystemTime;

use base64::Engine;
use hmac::{Hmac, Mac};
use reqwest::header::HeaderMap;
use reqwest::Method;
use sha1::Sha1;

use nydus_api::OssConfig;
use nydus_utils::metrics::BackendMetrics;

use crate::backend::connection::{Connection, ConnectionConfig};
use crate::backend::object_storage::{ObjectStorage, ObjectStorageState};

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
        let signature = base64::engine::general_purpose::STANDARD.encode(&hmac);

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
        let connection = Connection::new(&con_config)?;
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
            connection,
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
}
