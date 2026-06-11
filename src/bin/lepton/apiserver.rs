//! Lightweight HTTP server exposing Prometheus metrics over a Unix socket.
//!
//! The server is intentionally tiny: it serves `GET /metrics` (the Prometheus
//! text exposition produced by [`lepton::metrics`]) and returns `404` for
//! everything else. It runs on its own current-thread Tokio runtime in a
//! background thread so it stays independent of the backend's runtime and of
//! any cargo feature, and is shut down cleanly when the mount exits.

use anyhow::{anyhow, bail, Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::UnixListener;
use tokio::runtime::Builder;
use tokio::sync::Notify;
use tracing::{error, info, warn};

/// A running metrics HTTP server bound to a Unix socket.
pub struct ApiServer {
    socket_path: PathBuf,
    shutdown: Arc<Notify>,
    handle: Option<JoinHandle<()>>,
}

impl ApiServer {
    /// Start serving metrics at `address`, which must be `unix:///path/to.sock`.
    pub fn start(address: &str) -> Result<Self> {
        let socket_path = parse_unix_address(address)?;

        if let Some(parent) = socket_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create api socket directory {}", parent.display())
                })?;
            }
        }
        // Remove a stale socket left behind by a previous run.
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
                .with_context(|| format!("failed to bind api socket {}", socket_path.display()))?
        };

        let shutdown = Arc::new(Notify::new());
        let shutdown_for_thread = shutdown.clone();
        let handle = std::thread::Builder::new()
            .name("lepton_apiserver".to_string())
            .spawn(move || {
                runtime.block_on(serve(listener, shutdown_for_thread));
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

    /// Stop the server, join its thread, and unlink the socket.
    pub fn stop(mut self) {
        self.shutdown.notify_waiters();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

async fn serve(listener: UnixListener, shutdown: Arc<Notify>) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _addr)) => {
                    let io = TokioIo::new(stream);
                    tokio::task::spawn(async move {
                        if let Err(err) = http1::Builder::new()
                            .serve_connection(io, service_fn(handle_request))
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

async fn handle_request(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let response = if req.method() == Method::GET && req.uri().path() == "/metrics" {
        let body = lepton::metrics::encode_text();
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/plain; version=0.0.4")
            .body(Full::new(Bytes::from(body)))
            .expect("valid metrics response")
    } else if req.method() == Method::GET && req.uri().path() == "/trace" {
        let body = lepton::metrics::trace::encode_json();
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .expect("valid trace response")
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from_static(b"not found\n")))
            .expect("valid 404 response")
    };
    Ok(response)
}

pub(crate) fn parse_unix_address(address: &str) -> Result<PathBuf> {
    let path = address
        .strip_prefix("unix://")
        .ok_or_else(|| anyhow!("apiserver address must start with unix:// (got {address})"))?;
    if path.is_empty() {
        bail!("apiserver unix socket path is empty");
    }
    Ok(PathBuf::from(path))
}
