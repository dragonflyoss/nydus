// Copyright 2023 Ant Group. All rights reserved.

// SPDX-License-Identifier: Apache-2.0

// ! Storage backend driver to access the blobs through a http proxy.

use http::{HeaderMap, HeaderValue, Method, Request};
use hyper::Client as HyperClient;
use hyper::{body, Body, Response};
use hyperlocal::Uri as HyperLocalUri;
use hyperlocal::{UnixClientExt, UnixConnector};
use nydus_api::HttpProxyConfig;
use nydus_utils::metrics::BackendMetrics;
use reqwest;
use tokio::runtime::Runtime;

use super::connection::{Connection, ConnectionConfig, ConnectionError};
use super::{BackendError, BackendResult, BlobBackend, BlobReader};
use std::path::Path;
use std::{
    fmt,
    io::{Error, Result},
    num::ParseIntError,
    str::{self},
    sync::Arc,
};

const HYPER_LOCAL_CLIENT_RUNTIME_THREAD_NUM: usize = 1;

#[derive(Debug)]
pub enum HttpProxyError {
    /// Failed to parse string to integer.
    ParseStringToInteger(ParseIntError),
    ParseContentLengthFromHeader(http::header::ToStrError),
    /// Failed to get response from the local http server.
    LocalRequest(hyper::Error),
    /// Failed to get response from the remote http server.
    RemoteRequest(ConnectionError),
    /// Failed to build the tokio runtime.
    BuildTokioRuntime(Error),
    /// Failed to build local http request.
    BuildHttpRequest(http::Error),
    /// Failed to read the response body.
    ReadResponseBody(hyper::Error),
    /// Failed to transport the remote response body.
    Transport(reqwest::Error),
    /// Failed to copy the buffer.
    CopyBuffer(Error),
    /// Invalid path.
    InvalidPath,
    /// Failed to build request header.
    ConstructHeader(String),
}

impl fmt::Display for HttpProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpProxyError::ParseStringToInteger(e) => {
                write!(f, "failed to parse string to integer, {}", e)
            }
            HttpProxyError::ParseContentLengthFromHeader(e) => {
                write!(f, "failed to parse content length from header, {}", e)
            }
            HttpProxyError::LocalRequest(e) => write!(f, "failed to get response, {}", e),
            HttpProxyError::RemoteRequest(e) => write!(f, "failed to get response, {}", e),
            HttpProxyError::BuildTokioRuntime(e) => {
                write!(f, "failed to build tokio runtime, {}", e)
            }
            HttpProxyError::BuildHttpRequest(e) => {
                write!(f, "failed to build http request, {}", e)
            }
            HttpProxyError::Transport(e) => {
                write!(f, "failed to transport remote response body, {}", e)
            }
            HttpProxyError::ReadResponseBody(e) => {
                write!(f, "failed to read response body, {}", e)
            }
            HttpProxyError::CopyBuffer(e) => write!(f, "failed to copy buffer, {}", e),
            HttpProxyError::InvalidPath => write!(f, "invalid path"),
            HttpProxyError::ConstructHeader(e) => {
                write!(f, "failed to construct request header, {}", e)
            }
        }
    }
}

impl From<HttpProxyError> for BackendError {
    fn from(error: HttpProxyError) -> Self {
        BackendError::HttpProxy(error)
    }
}

/// A storage backend driver to access blobs through a http proxy server.
/// The http proxy server may be local (using unix socket) or be remote (using `http://` or `https://`).
///
/// `HttpProxy` uses two API endpoints to access the blobs:
/// - `HEAD /path/to/blob` to get the blob size
/// - `GET /path/to/blob` to read the blob
///
/// The http proxy server should respect [the `Range` header](https://www.rfc-editor.org/rfc/rfc9110.html#name-range) to support range reading.
pub struct HttpProxy {
    addr: String,
    path: String,
    client: Client,
    metrics: Option<Arc<BackendMetrics>>,
}

/// HttpProxyReader is a BlobReader to implement the HttpProxy backend driver.
pub struct HttpProxyReader {
    client: Client,
    uri: Uri,
    metrics: Arc<BackendMetrics>,
}

#[derive(Clone)]
struct LocalClient {
    client: Arc<HyperClient<UnixConnector>>,
    runtime: Arc<Runtime>,
}

#[derive(Clone)]
enum Client {
    Local(LocalClient),
    Remote(Arc<Connection>),
}

enum Uri {
    Local(Arc<hyper::Uri>),
    Remote(String),
}

fn range_str_for_header(offset: u64, len: Option<usize>) -> String {
    match len {
        Some(len) => format!("bytes={}-{}", offset, offset + len as u64 - 1),
        None => format!("bytes={}-", offset),
    }
}

fn build_tokio_runtime(name: &str, thread_num: usize) -> Result<Runtime> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_name(name)
        .worker_threads(thread_num)
        .enable_all()
        .build()?;
    Ok(runtime)
}

impl LocalClient {
    async fn do_req(
        &self,
        uri: Arc<hyper::Uri>,
        only_head: bool,
        offset: u64,
        len: Option<usize>,
    ) -> BackendResult<Response<Body>> {
        let method = if only_head { Method::HEAD } else { Method::GET };
        let req = Request::builder()
            .method(method)
            .uri(uri.as_ref())
            .header(http::header::RANGE, range_str_for_header(offset, len))
            .body(Body::default())
            .map_err(HttpProxyError::BuildHttpRequest)?;
        let resp = self
            .client
            .request(req)
            .await
            .map_err(HttpProxyError::LocalRequest)?;
        Ok(resp)
    }

    fn get_headers(&self, uri: Arc<hyper::Uri>) -> BackendResult<HeaderMap<HeaderValue>> {
        let headers = self
            .runtime
            .block_on(self.do_req(uri, true, 0, None))?
            .headers()
            .to_owned();
        Ok(headers)
    }

    fn try_read(&self, uri: Arc<hyper::Uri>, offset: u64, len: usize) -> BackendResult<Vec<u8>> {
        self.runtime.block_on(async {
            let resp = self.do_req(uri, false, offset, Some(len)).await;
            match resp {
                Ok(resp) => body::to_bytes(resp)
                    .await
                    .map_err(|e| HttpProxyError::ReadResponseBody(e).into())
                    .map(|bytes| bytes.to_vec()),
                Err(e) => Err(e),
            }
        })
    }
}

impl BlobReader for HttpProxyReader {
    fn blob_size(&self) -> super::BackendResult<u64> {
        let headers = match &self.client {
            Client::Local(client) => {
                let uri = match self.uri {
                    Uri::Local(ref uri) => uri.clone(),
                    Uri::Remote(_) => unreachable!(),
                };
                client.get_headers(uri)
            }
            Client::Remote(connection) => {
                let uri = match self.uri {
                    Uri::Local(_) => unreachable!(),
                    Uri::Remote(ref uri) => uri.clone(),
                };
                connection
                    .call::<&[u8]>(
                        Method::HEAD,
                        uri.as_str(),
                        None,
                        None,
                        &mut HeaderMap::new(),
                        true,
                    )
                    .map(|resp| resp.headers().to_owned())
                    .map_err(|e| HttpProxyError::RemoteRequest(e).into())
            }
        };
        let content_length = headers?[http::header::CONTENT_LENGTH]
            .to_str()
            .map_err(HttpProxyError::ParseContentLengthFromHeader)?
            .parse::<u64>()
            .map_err(HttpProxyError::ParseStringToInteger)?;
        Ok(content_length)
    }

    fn try_read(&self, mut buf: &mut [u8], offset: u64) -> BackendResult<usize> {
        match &self.client {
            Client::Local(client) => {
                let uri = match self.uri {
                    Uri::Local(ref uri) => uri.clone(),
                    Uri::Remote(_) => unreachable!(),
                };
                let content = client.try_read(uri, offset, buf.len())?;
                let copied_size = std::io::copy(&mut content.as_slice(), &mut buf)
                    .map_err(HttpProxyError::CopyBuffer)?;
                Ok(copied_size as usize)
            }
            Client::Remote(connection) => {
                let uri = match self.uri {
                    Uri::Local(_) => unreachable!(),
                    Uri::Remote(ref uri) => uri.clone(),
                };
                let mut headers = HeaderMap::new();
                let range = range_str_for_header(offset, Some(buf.len()));
                headers.insert(
                    http::header::RANGE,
                    range
                        .as_str()
                        .parse()
                        .map_err(|e| HttpProxyError::ConstructHeader(format!("{}", e)))?,
                );
                let mut resp = connection
                    .call::<&[u8]>(Method::GET, uri.as_str(), None, None, &mut headers, true)
                    .map_err(HttpProxyError::RemoteRequest)?;

                Ok(resp
                    .copy_to(&mut buf)
                    .map_err(HttpProxyError::Transport)
                    .map(|size| size as usize)?)
            }
        }
    }

    fn metrics(&self) -> &nydus_utils::metrics::BackendMetrics {
        &self.metrics
    }
}

impl HttpProxy {
    pub fn new(config: &HttpProxyConfig, id: Option<&str>) -> Result<HttpProxy> {
        let client = if config.addr.starts_with("http://") || config.addr.starts_with("https://") {
            let conn_cfg: ConnectionConfig = config.clone().into();
            let conn = Connection::new(&conn_cfg)?;
            Client::Remote(conn)
        } else {
            let client = HyperClient::unix();
            let runtime = build_tokio_runtime("http-proxy", HYPER_LOCAL_CLIENT_RUNTIME_THREAD_NUM)?;
            let local_client = LocalClient {
                client: Arc::new(client),
                runtime: Arc::new(runtime),
            };
            Client::Local(local_client)
        };
        Ok(HttpProxy {
            addr: config.addr.to_string(),
            path: config.path.to_string(),
            client,
            metrics: id.map(|i| BackendMetrics::new(i, "http-proxy")),
        })
    }
}

impl BlobBackend for HttpProxy {
    fn shutdown(&self) {
        match &self.client {
            Client::Local(_) => {
                // do nothing
            }
            Client::Remote(remote_client) => {
                remote_client.shutdown();
            }
        }
    }

    fn metrics(&self) -> &nydus_utils::metrics::BackendMetrics {
        // `metrics()` is only used for nydusd, which will always provide valid `blob_id`, thus
        // `self.metrics` has valid value.
        self.metrics.as_ref().unwrap()
    }

    fn get_reader(
        &self,
        blob_id: &str,
    ) -> super::BackendResult<std::sync::Arc<dyn super::BlobReader>> {
        let path = Path::new(&self.path).join(blob_id);
        let path = path.to_str().ok_or(HttpProxyError::InvalidPath)?;
        let uri = match &self.client {
            Client::Local(_) => {
                let uri: Arc<hyper::Uri> =
                    Arc::new(HyperLocalUri::new(self.addr.clone(), "/").into());
                Uri::Local(uri)
            }
            Client::Remote(_) => {
                let uri = format!("{}{}", self.addr, path);
                Uri::Remote(uri)
            }
        };
        let reader = Arc::new(HttpProxyReader {
            client: self.client.clone(),
            uri,
            metrics: self.metrics.as_ref().unwrap().clone(),
        });
        Ok(reader)
    }
}

impl Drop for HttpProxy {
    fn drop(&mut self) {
        self.shutdown();
        if let Some(metrics) = self.metrics.as_ref() {
            metrics.release().unwrap_or_else(|e| error!("{:?}", e));
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        backend::{http_proxy::HttpProxy, BlobBackend},
        utils::alloc_buf,
    };

    use http::{status, Request};
    use hyper::{
        service::{make_service_fn, service_fn},
        Body, Response, Server,
    };
    use hyperlocal::UnixServerExt;
    use nydus_api::HttpProxyConfig;
    use std::{
        cmp,
        fs::{self},
        net::{IpAddr, Ipv4Addr, SocketAddr},
        path::Path,
        thread,
        time::Duration,
    };

    use super::build_tokio_runtime;

    const CONTENT: &str = "some content for test";
    const SOCKET_PATH: &str = "/tmp/nydus-test-local-http-proxy.sock";

    fn parse_range_header(range_str: &str) -> (u64, Option<u64>) {
        let range_str = range_str.trim_start_matches("bytes=");
        let range: Vec<&str> = range_str.split('-').collect();
        let start = range[0].parse::<u64>().unwrap();
        let end = match range[1] {
            "" => None,
            _ => Some(cmp::min(
                range[1].parse::<u64>().unwrap(),
                (CONTENT.len() - 1) as u64,
            )),
        };
        (start, end)
    }

    async fn server_handler(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        return match *req.method() {
            hyper::Method::HEAD => Ok::<_, hyper::Error>(
                Response::builder()
                    .status(200)
                    .header(http::header::CONTENT_LENGTH, CONTENT.len())
                    .body(Body::empty())
                    .unwrap(),
            ),
            hyper::Method::GET => {
                let range = req.headers()[http::header::RANGE].to_str().unwrap();
                println!("range: {}", range);
                let (start, end) = parse_range_header(range);
                let length = match end {
                    Some(e) => e - start + 1,
                    None => CONTENT.len() as u64,
                };
                println!("start: {}, end: {:?}, length: {}", start, end, length);
                let end = match end {
                    Some(e) => e,
                    None => (CONTENT.len() - 1) as u64,
                };
                let content = CONTENT.as_bytes()[start as usize..(end + 1) as usize].to_vec();
                Ok::<_, hyper::Error>(
                    Response::builder()
                        .status(200)
                        .header(http::header::CONTENT_LENGTH, length)
                        .body(Body::from(content))
                        .unwrap(),
                )
            }
            _ => Ok::<_, hyper::Error>(
                Response::builder()
                    .status(status::StatusCode::METHOD_NOT_ALLOWED)
                    .body(Body::empty())
                    .unwrap(),
            ),
        };
    }

    #[test]
    fn test_head_and_get() {
        thread::spawn(|| {
            let rt = build_tokio_runtime("test-local-http-proxy-server", 1).unwrap();
            rt.block_on(async {
                println!("\nstarting local http proxy server......");
                let path = Path::new(SOCKET_PATH);
                if path.exists() {
                    fs::remove_file(path).unwrap();
                }
                Server::bind_unix(path)
                    .unwrap()
                    .serve(make_service_fn(|_| async {
                        Ok::<_, hyper::Error>(service_fn(server_handler))
                    }))
                    .await
                    .unwrap();
            });
        });

        thread::spawn(|| {
            let rt = build_tokio_runtime("test-remote-http-proxy-server", 1).unwrap();
            rt.block_on(async {
                println!("\nstarting remote http proxy server......");
                Server::bind(&SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    9977,
                ))
                .serve(make_service_fn(|_| async {
                    Ok::<_, hyper::Error>(service_fn(server_handler))
                }))
                .await
                .unwrap();
            });
        });

        // wait for server to start
        thread::sleep(Duration::from_secs(5));

        // start the client and test
        let test_list: Vec<(String, String)> = vec![
            (
                format!(
                    "{{\"addr\":\"{}\",\"path\":\"/namespace/<repo>/blobs\"}}",
                    SOCKET_PATH,
                ),
                "test-local-http-proxy".to_string(),
            ),
            (
                "{\"addr\":\"http://127.0.0.1:9977\",\"path\":\"/namespace/<repo>/blobs\"}"
                    .to_string(),
                "test-remote-http-proxy".to_string(),
            ),
        ];
        for test_case in test_list.iter() {
            let config: HttpProxyConfig = serde_json::from_str(test_case.0.as_str()).unwrap();
            let backend = HttpProxy::new(&config, Some(test_case.1.as_str())).unwrap();
            let reader = backend.get_reader("blob_id").unwrap();

            println!();
            println!("testing blob_size()......");
            let blob_size = reader
                .blob_size()
                .map_err(|e| {
                    println!("blob_size() failed: {}", e);
                    e
                })
                .unwrap();
            assert_eq!(blob_size, CONTENT.len() as u64);

            println!();
            println!("testing read() range......");
            let mut buf = alloc_buf(3);
            let size = reader
                .try_read(&mut buf, 0)
                .map_err(|e| {
                    println!("read() range failed: {}", e);
                    e
                })
                .unwrap();
            assert_eq!(size, 3);
            assert_eq!(buf, CONTENT.as_bytes()[0..3]);

            println!();
            println!("testing read() full......");
            let mut buf = alloc_buf(80);
            let size = reader
                .try_read(&mut buf, 0)
                .map_err(|e| {
                    println!("read() range failed: {}", e);
                    e
                })
                .unwrap();
            assert_eq!(size, CONTENT.len() as usize);
            assert_eq!(&buf[0..CONTENT.len()], CONTENT.as_bytes());
        }
    }
}
