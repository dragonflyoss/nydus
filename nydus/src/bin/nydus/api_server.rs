//! The HTTP server behind `--apiserver`: an image's metrics and ondemand record
//! over a Unix socket.
//!
//! It serves `GET /metrics`, the Prometheus text exposition of the
//! [`Metrics`] it was started with, and `GET /trace`, the chunk group
//! ondemand record `nydus optimize` reads, and answers `404` to everything
//! else. It runs on a current-thread Tokio runtime of its own in a background
//! thread, so it stays independent of the backend's runtime and of any cargo
//! feature, and is torn down with its socket on [`ApiServer::stop`].

use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus::{Encoder, TextEncoder};
use tokio::net::UnixListener;
use tokio::runtime::Builder;
use tokio::sync::Notify;
use tracing::{error, info, warn};

use nydus::error::{Context, Result};
use nydus::parse_unix_address;
use nydus_core::{Metrics, OndemandRecorder};

/// A running HTTP server of one image's metrics and ondemand record, bound to a
/// Unix socket until stopped.
pub struct ApiServer {
    /// The socket the server listens on, unlinked on stop.
    socket_path: PathBuf,

    /// Woken once to stop the accept loop.
    shutdown: Arc<Notify>,

    /// The thread the server runs on, joined on stop.
    handle: Option<JoinHandle<()>>,
}

/// Implements the API server.
impl ApiServer {
    /// Starts serving `metrics` and the ondemand record at `address`, which must be
    /// `unix:///path/to.sock`, creating the socket's directory and replacing
    /// a stale socket a previous run left behind.
    pub fn start(
        address: &str,
        metrics: Arc<Metrics>,
        ondemand: Arc<OndemandRecorder>,
    ) -> Result<Self> {
        let socket_path = parse_unix_address(address)?;

        if let Some(parent) = socket_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create api socket directory {}", parent.display())
                })?;
            }
        }
        if socket_path.exists() {
            std::fs::remove_file(&socket_path).with_context(|| {
                format!(
                    "failed to remove stale api socket {}",
                    socket_path.display()
                )
            })?;
        }

        let runtime = Builder::new_current_thread()
            .enable_io()
            .build()
            .context("failed to build apiserver runtime")?;

        // Bind synchronously so start() fails fast on a bad path or permissions.
        let listener = {
            let _guard = runtime.enter();
            UnixListener::bind(&socket_path)
                .with_context(|| format!("failed to bind api socket: {}", socket_path.display()))?
        };

        let shutdown = Arc::new(Notify::new());
        let shutdown_for_thread = shutdown.clone();
        let handle = std::thread::Builder::new()
            .name("nydus_apiserver".to_string())
            .spawn(move || {
                runtime.block_on(serve(listener, shutdown_for_thread, metrics, ondemand));
            })
            .context("failed to spawn apiserver thread")?;

        info!(
            "metrics apiserver listening on unix://{}",
            socket_path.display()
        );
        Ok(Self {
            socket_path,
            shutdown,
            handle: Some(handle),
        })
    }

    /// Stops the server, joins its thread and unlinks the socket.
    pub fn stop(mut self) {
        self.shutdown.notify_waiters();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Accepts connections until `shutdown` is woken, answering each on a task of
/// its own.
async fn serve(
    listener: UnixListener,
    shutdown: Arc<Notify>,
    metrics: Arc<Metrics>,
    ondemand: Arc<OndemandRecorder>,
) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _addr)) => {
                    let io = TokioIo::new(stream);
                    let metrics = metrics.clone();
                    let ondemand = ondemand.clone();
                    tokio::task::spawn(async move {
                        if let Err(err) = http1::Builder::new()
                            .serve_connection(
                                io,
                                service_fn(move |req| {
                                    handle_request(req, metrics.clone(), ondemand.clone())
                                }),
                            )
                            .await
                        {
                            warn!("apiserver connection error: {err}");
                        }
                    });
                }
                Err(err) => error!("apiserver accept error: {err}"),
            },
        }
    }
}

/// Answers one request: the metrics, the ondemand record, or `404`.
async fn handle_request(
    req: Request<Incoming>,
    metrics: Arc<Metrics>,
    ondemand: Arc<OndemandRecorder>,
) -> std::result::Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let response = if req.method() == Method::GET && req.uri().path() == "/metrics" {
        let mut body = Vec::new();
        if let Err(err) = TextEncoder::new().encode(&metrics.registry().gather(), &mut body) {
            error!("failed to encode metrics: {err}");
        }
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/plain; version=0.0.4")
            .body(Full::new(Bytes::from(body)))
            .expect("valid metrics response")
    } else if req.method() == Method::GET && req.uri().path() == "/trace" {
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(ondemand.encode_json())))
            .expect("valid ondemand response")
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from_static(b"not found\n")))
            .expect("valid 404 response")
    };
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use tempfile::tempdir;

    fn get(socket_path: &Path, path: &str) -> String {
        let mut stream = UnixStream::connect(socket_path).unwrap();
        stream
            .write_all(format!("GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n").as_bytes())
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    fn serves_the_metrics_and_ondemand_record_it_was_started_with() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("run").join("api.sock");
        let metrics = Arc::new(Metrics::new());
        let ondemand = Arc::new(OndemandRecorder::default());
        metrics.storage.collect_prefetch_task_finished_metrics();
        ondemand.record_chunk_group_access(1, 4);
        let server = ApiServer::start(
            &format!("unix://{}", socket_path.display()),
            metrics,
            ondemand,
        )
        .unwrap();

        let test_cases = vec![
            ("/metrics", " 200 ", "nydus_storage_prefetch_task_total 1"),
            (
                "/trace",
                " 200 ",
                r#"{"blob_index":1,"chunk_group_index":4}"#,
            ),
            ("/other", " 404 ", "not found"),
        ];

        for (path, status, body) in test_cases {
            let response = get(&socket_path, path);
            assert!(response.contains(status), "{path}: {response}");
            assert!(response.contains(body), "{path}: {response}");
        }

        server.stop();
        assert!(!socket_path.exists());
    }

    #[test]
    fn start_replaces_a_stale_socket() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("api.sock");
        std::fs::write(&socket_path, b"stale").unwrap();
        let server = ApiServer::start(
            &format!("unix://{}", socket_path.display()),
            Arc::new(Metrics::new()),
            Arc::new(OndemandRecorder::default()),
        )
        .unwrap();
        assert!(get(&socket_path, "/metrics").contains(" 200 "));
        server.stop();
    }
}
