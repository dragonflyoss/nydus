//! Lightweight HTTP server exposing Prometheus metrics over a Unix socket.
//!
//! The server is intentionally tiny: it serves `GET /metrics` (the Prometheus
//! text exposition produced by [`nydus_telemetry::metrics`]) and returns `404` for
//! everything else. It runs on its own current-thread Tokio runtime in a
//! background thread so it stays independent of the backend's runtime and of
//! any cargo feature, and is shut down cleanly when the mount exits.

use nydus::error::{Context, Result};
use nydus::parse_unix_address;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use nydus_telemetry::metrics::ImageMetrics;
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
    pub fn start(address: &str, metrics: Arc<ImageMetrics>) -> Result<Self> {
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
                .with_context(|| format!("failed to bind api socket: {}", socket_path.display()))?
        };

        let shutdown = Arc::new(Notify::new());
        let shutdown_for_thread = shutdown.clone();
        let handle = std::thread::Builder::new()
            .name("nydus_apiserver".to_string())
            .spawn(move || {
                runtime.block_on(serve(listener, shutdown_for_thread, metrics));
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

async fn serve(listener: UnixListener, shutdown: Arc<Notify>, metrics: Arc<ImageMetrics>) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _addr)) => {
                    let io = TokioIo::new(stream);
                    let metrics = metrics.clone();
                    tokio::task::spawn(async move {
                        if let Err(err) = http1::Builder::new()
                            .serve_connection(
                                io,
                                service_fn(move |request| {
                                    handle_request(request, metrics.clone())
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

async fn handle_request<B>(
    req: Request<B>,
    metrics: Arc<ImageMetrics>,
) -> std::result::Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let response = if req.method() == Method::GET && req.uri().path() == "/metrics" {
        let body = metrics.encode_text();
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/plain; version=0.0.4")
            .body(Full::new(Bytes::from(body)))
            .expect("valid metrics response")
    } else if req.method() == Method::GET && req.uri().path() == "/trace" {
        let body = nydus_storage::access_trace::encode_json();
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

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use nydus_telemetry::metrics::{BackendTarget, ReadKind};
    use std::time::Duration;

    async fn metrics_body(metrics: Arc<ImageMetrics>) -> String {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/metrics")
            .body(())
            .unwrap();
        let response = handle_request(request, metrics).await.unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn metrics_endpoint_uses_the_selected_image_registry() {
        let first = Arc::new(ImageMetrics::new());
        let second = Arc::new(ImageMetrics::new());
        first.record_backend_read(
            BackendTarget::Origin,
            ReadKind::OnDemand,
            4096,
            Duration::from_millis(1),
            false,
        );

        let first_body = metrics_body(first).await;
        let second_body = metrics_body(second).await;
        assert!(first_body.contains("backend_origin_read_count 1\n"));
        assert!(second_body.contains("backend_origin_read_count 0\n"));
    }
}
