// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Result;
use hyper::{header, Body, Client, Method, Request, Uri as HyperUri};
use hyperlocal::{UnixClientExt, Uri};
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
        let mut endpoint = format!("/api/v1/{}", path);

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
        let client = Client::unix();
        let uri = self.build_uri(path, None);
        let response = client.get(uri).await?;
        let sc = response.status().as_u16();
        let buf = hyper::body::to_bytes(response).await?;
        let b = serde_json::from_slice(&buf).map_err(|e| anyhow!("deserialize: {}", e))?;

        if sc >= 400 {
            bail!("Request failed. {:?}", b);
        }

        Ok(b)
    }

    pub async fn put(&self, path: &str, data: Option<String>) -> Result<()> {
        let client = Client::unix();
        let uri = self.build_uri(path, None);
        let (body, _) = if let Some(d) = data {
            let l = d.len();
            (d.into(), l)
        } else {
            (Body::empty(), 0)
        };

        let req = Request::builder()
            .method(Method::PUT)
            .header(header::USER_AGENT, "nydusctl")
            .uri(uri)
            .body(body)?;
        let response = client.request(req).await?;
        let sc = response.status().as_u16();
        let buf = hyper::body::to_bytes(response).await?;

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
        let client = Client::unix();
        let uri = self.build_uri(path, query);
        let (body, _) = if let Some(d) = data {
            let l = d.len();
            (d.into(), l)
        } else {
            (Body::empty(), 0)
        };

        let req = Request::builder()
            .method(Method::POST)
            .header(header::USER_AGENT, "nydusctl")
            .uri(uri)
            .body(body)?;
        let response = client.request(req).await?;
        let sc = response.status().as_u16();
        let buf = hyper::body::to_bytes(response).await?;

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
        let client = Client::unix();
        let uri = self.build_uri(path, query);
        let (body, _) = if let Some(d) = data {
            let l = d.len();
            (d.into(), l)
        } else {
            (Body::empty(), 0)
        };

        let req = Request::builder()
            .method(Method::DELETE)
            .header(header::USER_AGENT, "nydusctl")
            .uri(uri)
            .body(body)?;
        let response = client.request(req).await?;
        let sc = response.status().as_u16();
        let buf = hyper::body::to_bytes(response).await?;

        if sc >= 400 {
            let b: serde_json::Value =
                serde_json::from_slice(&buf).map_err(|e| anyhow!("deserialize: {}", e))?;
            bail!("Request failed. {:?}", b);
        }

        Ok(())
    }
}
