// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Result;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{header, Method, Request, Uri as HyperUri};
use hyper_util::client::legacy::Client;
use hyperlocal::{UnixClientExt, UnixConnector, Uri};

use serde_json::{self, Value};

pub struct NydusdClient {
    sock_path: PathBuf,
}

impl NydusdClient {
    pub fn new(sock: &str) -> Self {
        Self {
            sock_path: sock.to_string().into(),
        }
    }

    fn build_uri(&self, path: &str, query: Option<Vec<(&str, &str)>>) -> HyperUri {
        let mut endpoint = format!("/api/{}", path);

        if let Some(q) = query {
            let mut params = String::new();
            for p in q {
                params.push_str(&format!("{}={}", p.0, p.1))
            }

            endpoint.push_str(&format!("?{}", params));
        }

        Uri::new(&self.sock_path, endpoint.as_str()).into()
    }

    pub async fn get(&self, path: &str) -> Result<Value> {
        let client: Client<UnixConnector, Full<Bytes>> = Client::unix();
        let uri = self.build_uri(path, None);
        let response = client.get(uri).await?;
        let sc = response.status().as_u16();
        let buf = response.into_body().collect().await?.to_bytes();
        let b = serde_json::from_slice(&buf).map_err(|e| anyhow!("deserialize: {}", e))?;

        if sc >= 400 {
            bail!("Request failed. {:?}", b);
        }

        Ok(b)
    }

    pub async fn put(&self, path: &str, data: Option<String>) -> Result<()> {
        let client: Client<UnixConnector, Full<Bytes>> = Client::unix();
        let uri = self.build_uri(path, None);
        let body = if let Some(d) = data {
            Full::new(Bytes::from(d))
        } else {
            Full::new(Bytes::new())
        };

        let req = Request::builder()
            .method(Method::PUT)
            .header(header::USER_AGENT, "nydusctl")
            .uri(uri)
            .body(body)?;
        let response = client.request(req).await?;
        let sc = response.status().as_u16();
        let buf = response.into_body().collect().await?.to_bytes();

        if sc >= 400 {
            let b: serde_json::Value =
                serde_json::from_slice(&buf).map_err(|e| anyhow!("deserialize: {}", e))?;
            bail!("Request failed. {:?}", b);
        }

        Ok(())
    }

    pub async fn post(
        &self,
        path: &str,
        data: Option<String>,
        query: Option<Vec<(&str, &str)>>,
    ) -> Result<()> {
        let client: Client<UnixConnector, Full<Bytes>> = Client::unix();
        let uri = self.build_uri(path, query);
        let body = if let Some(d) = data {
            Full::new(Bytes::from(d))
        } else {
            Full::new(Bytes::new())
        };

        let req = Request::builder()
            .method(Method::POST)
            .header(header::USER_AGENT, "nydusctl")
            .uri(uri)
            .body(body)?;
        let response = client.request(req).await?;
        let sc = response.status().as_u16();
        let buf = response.into_body().collect().await?.to_bytes();

        if sc >= 400 {
            let b: serde_json::Value =
                serde_json::from_slice(&buf).map_err(|e| anyhow!("deserialize: {}", e))?;
            bail!("Request failed. {:?}", b);
        }

        Ok(())
    }

    pub async fn delete(
        &self,
        path: &str,
        data: Option<String>,
        query: Option<Vec<(&str, &str)>>,
    ) -> Result<()> {
        let client: Client<UnixConnector, Full<Bytes>> = Client::unix();
        let uri = self.build_uri(path, query);
        let body = if let Some(d) = data {
            Full::new(Bytes::from(d))
        } else {
            Full::new(Bytes::new())
        };

        let req = Request::builder()
            .method(Method::DELETE)
            .header(header::USER_AGENT, "nydusctl")
            .uri(uri)
            .body(body)?;
        let response = client.request(req).await?;
        let sc = response.status().as_u16();
        let buf = response.into_body().collect().await?.to_bytes();

        if sc >= 400 {
            let b: serde_json::Value =
                serde_json::from_slice(&buf).map_err(|e| anyhow!("deserialize: {}", e))?;
            bail!("Request failed. {:?}", b);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_client() {
        let client = NydusdClient::new("/tmp/nydus.sock");
        assert_eq!(client.sock_path, PathBuf::from("/tmp/nydus.sock"));

        let client = NydusdClient::new("/var/run/nydusd.sock");
        assert_eq!(client.sock_path, PathBuf::from("/var/run/nydusd.sock"));
    }

    #[test]
    fn test_build_uri_without_query() {
        let client = NydusdClient::new("/tmp/nydus.sock");

        let uri = client.build_uri("v1/daemon", None);
        let uri_str = uri.to_string();
        // The URI should contain the path
        assert!(uri_str.contains("/api/v1/daemon"));
    }

    #[test]
    fn test_build_uri_with_query() {
        let client = NydusdClient::new("/tmp/nydus.sock");

        let query = vec![("key1", "value1")];
        let uri = client.build_uri("v1/daemon", Some(query));
        let uri_str = uri.to_string();
        assert!(uri_str.contains("/api/v1/daemon"));
        assert!(uri_str.contains("key1=value1"));
    }

    #[test]
    fn test_build_uri_with_multiple_query_params() {
        let client = NydusdClient::new("/tmp/nydus.sock");

        let query = vec![("key1", "value1"), ("key2", "value2")];
        let uri = client.build_uri("v2/blobs", Some(query));
        let uri_str = uri.to_string();
        assert!(uri_str.contains("/api/v2/blobs"));
        assert!(uri_str.contains("key1=value1"));
        assert!(uri_str.contains("key2=value2"));
    }

    #[test]
    fn test_build_uri_various_paths() {
        let client = NydusdClient::new("/tmp/nydus.sock");

        // Test different API paths
        let paths = vec![
            "v1/daemon",
            "v1/metrics/files",
            "v2/blobs/sha256:abc123",
            "v1/mount",
        ];

        for path in paths {
            let uri = client.build_uri(path, None);
            let uri_str = uri.to_string();
            assert!(
                uri_str.contains(&format!("/api/{}", path)),
                "URI should contain /api/{}, got {}",
                path,
                uri_str
            );
        }
    }
}
