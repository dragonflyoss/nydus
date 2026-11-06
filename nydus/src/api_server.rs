//! The HTTP server behind `--apiserver`: an image's metrics and ondemand record
//! over a Unix socket, the registry backend's credentials, plus optional Unix
//! control-protocol upgrades.

use std::io;
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Body, Bytes, Incoming};
use hyper::header::{
    HeaderValue, ALLOW, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING, UPGRADE,
};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use nydus_backend::Backend;
use nydus_core::{Metrics, OndemandRecorder};
use prometheus::{Encoder, TextEncoder};
use serde::Deserialize;
use tokio::net::{UnixListener, UnixStream};
use tokio::runtime::Builder;
use tokio::sync::{watch, Semaphore};
use tracing::{error, info, warn};

use crate::error::{Context, Error, Result};
use crate::parse_unix_address;

/// The endpoint and upgrade token of a frontend's control protocol.
#[derive(Clone, Copy, Debug)]
pub struct ControlProtocol {
    pub path: &'static str,
    pub token: &'static str,
}

/// The bound for reading request headers and completing an upgrade.
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// The route that replaces the registry backend's basic credentials.
const BACKEND_AUTH_PATH: &str = "/api/v1/backend/auth";

/// The largest body [`BACKEND_AUTH_PATH`] reads.
const BACKEND_AUTH_BODY_LIMIT: usize = 64 * 1024;

/// The body of `PUT` [`BACKEND_AUTH_PATH`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendAuthRequest {
    /// The registry credentials, `base64(user:pass)`.
    auth: String,
}

/// Serves one upgraded control connection with its read-ahead bytes and
/// returns whether the server should stop accepting.
pub(crate) type ControlHandler = Arc<dyn Fn(StdUnixStream, Vec<u8>) -> Result<bool> + Send + Sync>;

#[derive(Clone)]
pub(crate) struct ControlEndpoint {
    pub protocol: ControlProtocol,
    pub handler: ControlHandler,
}

/// The state every connection serves its requests with, cloned per
/// connection like hyper's `examples/state.rs`.
#[derive(Clone)]
struct ApiState {
    /// The control protocol upgrades are handed to, `None` without upgrades.
    control: Option<ControlEndpoint>,

    /// The metrics `GET /metrics` encodes.
    metrics: Arc<Metrics>,

    /// The ondemand record `GET /trace` encodes.
    ondemand: Arc<OndemandRecorder>,

    /// The backend [`BACKEND_AUTH_PATH`] replaces the credentials of.
    backend: Option<Arc<dyn Backend>>,

    /// The permit one control connection holds at a time.
    admission: Arc<Semaphore>,

    /// The flag a control handoff raises to stop accepting.
    shutdown: watch::Sender<bool>,
}

/// An HTTP listener, optionally owning its socket pathname.
pub struct ApiServer {
    shutdown: watch::Sender<bool>,
    handle: Option<JoinHandle<()>>,
    socket_path: Option<PathBuf>,
}

impl ApiServer {
    /// Starts an endpoint without control upgrades, `backend` answering
    /// [`BACKEND_AUTH_PATH`] when given. FUSE uses its ownership-aware
    /// listener instead of this pathname takeover policy.
    pub fn start(
        address: &str,
        metrics: Arc<Metrics>,
        ondemand: Arc<OndemandRecorder>,
        backend: Option<Arc<dyn Backend>>,
    ) -> Result<Self> {
        let path = parse_unix_address(address)?;
        if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create api directory {}", parent.display()))?;
        }
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("failed to remove stale api socket {}", path.display()))?;
        }
        let listener = StdUnixListener::bind(&path)
            .with_context(|| format!("failed to bind api socket {}", path.display()))?;
        let mut server = Self::from_listener(listener, None, metrics, ondemand, backend)
            .inspect_err(|_| remove_socket(&path))?;
        info!("apiserver listening on unix://{}", path.display());
        server.socket_path = Some(path);
        Ok(server)
    }

    /// Serves `listener` on a dedicated thread, upgrading control connections to `control`.
    pub(crate) fn from_listener(
        listener: StdUnixListener,
        control: Option<ControlEndpoint>,
        metrics: Arc<Metrics>,
        ondemand: Arc<OndemandRecorder>,
        backend: Option<Arc<dyn Backend>>,
    ) -> Result<Self> {
        listener.set_nonblocking(true)?;
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to build apiserver runtime")?;
        let listener = {
            let _guard = runtime.enter();
            UnixListener::from_std(listener)?
        };
        let (shutdown, receiver) = watch::channel(false);
        let sender = shutdown.clone();
        let handle = std::thread::Builder::new()
            .name("nydus_apiserver".to_string())
            .spawn(move || {
                runtime.block_on(serve(
                    listener,
                    control,
                    metrics,
                    ondemand,
                    backend.clone(),
                    sender,
                    receiver,
                ));
                // A registry backend owns a runtime, which panics when its
                // last reference drops inside this one.
                drop(runtime);
                drop(backend);
            })
            .context("failed to spawn apiserver thread")?;
        Ok(Self {
            shutdown,
            handle: Some(handle),
            socket_path: None,
        })
    }

    /// Stops serving and removes only a pathname created by [`Self::start`].
    pub fn stop(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        self.shutdown.send_replace(true);
        if let Some(handle) = self.handle.take() {
            if handle.join().is_err() {
                error!("apiserver thread panicked");
            }
        }
        if let Some(path) = self.socket_path.take() {
            remove_socket(&path);
        }
    }
}

impl Drop for ApiServer {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

pub(crate) fn remove_socket(path: &Path) {
    if let Err(err) = std::fs::remove_file(path) {
        if err.kind() != io::ErrorKind::NotFound {
            warn!("failed to remove api socket {}: {}", path.display(), err);
        }
    }
}

async fn serve(
    listener: UnixListener,
    control: Option<ControlEndpoint>,
    metrics: Arc<Metrics>,
    ondemand: Arc<OndemandRecorder>,
    backend: Option<Arc<dyn Backend>>,
    shutdown: watch::Sender<bool>,
    mut stopped: watch::Receiver<bool>,
) {
    let state = ApiState {
        control,
        metrics,
        ondemand,
        backend,
        admission: Arc::new(Semaphore::new(1)),
        shutdown,
    };
    loop {
        if *stopped.borrow() {
            break;
        }
        tokio::select! {
            _ = stopped.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let authorized = match stream.peer_cred() {
                        // SAFETY: geteuid takes no pointers and cannot fail.
                        Ok(peer) => peer.uid() == unsafe { libc::geteuid() },
                        Err(err) => {
                            warn!("failed to authenticate api peer: {err}");
                            false
                        }
                    };
                    let state = state.clone();
                    tokio::spawn(async move {
                        let handler =
                            service_fn(move |req| handle_request(req, state.clone(), authorized));
                        if let Err(err) = http1::Builder::new()
                            .timer(TokioTimer::new())
                            .header_read_timeout(HTTP_TIMEOUT)
                            .max_buf_size(16 * 1024)
                            .serve_connection(TokioIo::new(stream), handler)
                            .with_upgrades()
                            .await
                        {
                            warn!("apiserver connection error: {err}");
                        }
                    });
                }
                Err(err) => error!("apiserver accept error: {err}"),
            }
        }
    }
}

fn response(status: StatusCode, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(body.into()));
    *response.status_mut() = status;
    response
}

/// Returns a `status` answer whose JSON body carries `message`.
fn json_error(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let mut reply = response(
        status,
        serde_json::json!({ "message": message }).to_string(),
    );
    reply
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    reply
}

/// Checks both HTTP upgrade headers against the selected protocol.
pub(crate) fn is_control_upgrade<'a>(
    headers: impl Iterator<Item = (&'a str, &'a [u8])>,
    expected: &str,
) -> bool {
    let (mut connection, mut protocol) = (false, false);
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("connection") {
            connection |= std::str::from_utf8(value).is_ok_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            });
        } else if name.eq_ignore_ascii_case("upgrade") {
            protocol |= value.eq_ignore_ascii_case(expected.as_bytes());
        }
    }
    connection && protocol
}

async fn handle_request(
    mut req: Request<Incoming>,
    state: ApiState,
    authorized: bool,
) -> std::result::Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let ApiState {
        control,
        metrics,
        ondemand,
        backend,
        admission,
        shutdown,
    } = state;
    if let Some(control) = control
        .filter(|control| req.method() == Method::GET && req.uri().path() == control.protocol.path)
    {
        if !authorized {
            return Ok(response(
                StatusCode::FORBIDDEN,
                "control peer uid mismatch\n",
            ));
        }
        if req.version() != hyper::Version::HTTP_11
            || !is_control_upgrade(
                req.headers()
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_bytes())),
                control.protocol.token,
            )
        {
            let mut reply = response(StatusCode::UPGRADE_REQUIRED, "control upgrade required\n");
            reply
                .headers_mut()
                .insert(UPGRADE, HeaderValue::from_static(control.protocol.token));
            return Ok(reply);
        }
        if req.headers().contains_key(TRANSFER_ENCODING)
            || req
                .headers()
                .get(CONTENT_LENGTH)
                .is_some_and(|length| length.as_bytes() != b"0")
        {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                "control request has a body\n",
            ));
        }
        let permit = match tokio::time::timeout(HTTP_TIMEOUT, admission.acquire_owned()).await {
            Ok(Ok(permit)) if !*shutdown.borrow() => permit,
            _ => {
                return Ok(response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "control is busy\n",
                ))
            }
        };
        let upgraded = hyper::upgrade::on(&mut req);
        let protocol = control.protocol;
        tokio::spawn(async move {
            let _permit = permit;
            match run_control(upgraded, control.handler).await {
                Ok(true) => {
                    shutdown.send_replace(true);
                }
                Ok(false) => {}
                Err(err) => warn!("control connection failed: {}", err.report()),
            }
        });
        let mut reply = response(StatusCode::SWITCHING_PROTOCOLS, Bytes::new());
        reply
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        reply
            .headers_mut()
            .insert(UPGRADE, HeaderValue::from_static(protocol.token));
        return Ok(reply);
    }
    if req.uri().path() == BACKEND_AUTH_PATH {
        if req.method() != Method::PUT {
            let mut reply = json_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
            reply
                .headers_mut()
                .insert(ALLOW, HeaderValue::from_static("PUT"));
            return Ok(reply);
        }
        return Ok(put_backend_auth(req.into_body(), backend, authorized).await);
    }
    let (body, content_type) = match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let mut body = Vec::new();
            if let Err(err) = TextEncoder::new().encode(&metrics.registry().gather(), &mut body) {
                error!("failed to encode metrics: {err}");
            }
            (body, "text/plain; version=0.0.4")
        }
        (&Method::GET, "/trace") => (ondemand.encode_json().into_bytes(), "application/json"),
        _ => return Ok(response(StatusCode::NOT_FOUND, "not found\n")),
    };
    let mut reply = response(StatusCode::OK, body);
    reply
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    Ok(reply)
}

/// Answers `PUT` [`BACKEND_AUTH_PATH`]: replaces the basic credentials of the
/// registry `backend` with the `auth` of a JSON `body` of at most
/// [`BACKEND_AUTH_BODY_LIMIT`] bytes, read within [`HTTP_TIMEOUT`].
///
/// Only a peer with the daemon's UID is `authorized`. Error messages are
/// fixed, so they never echo the credentials whatever the backend reports.
async fn put_backend_auth<B>(
    body: B,
    backend: Option<Arc<dyn Backend>>,
    authorized: bool,
) -> Response<Full<Bytes>>
where
    B: Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if !authorized {
        return json_error(StatusCode::FORBIDDEN, "peer uid mismatch");
    }

    let body = Limited::new(body, BACKEND_AUTH_BODY_LIMIT).collect();
    let body = match tokio::time::timeout(HTTP_TIMEOUT, body).await {
        Ok(Ok(body)) => body.to_bytes(),
        Ok(Err(err)) if err.is::<LengthLimitError>() => {
            return json_error(StatusCode::PAYLOAD_TOO_LARGE, "body exceeds 64 KiB")
        }
        Ok(Err(err)) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                &format!("failed to read body: {err}"),
            )
        }
        Err(_) => return json_error(StatusCode::REQUEST_TIMEOUT, "body read timed out"),
    };
    let Ok(request) = serde_json::from_slice::<BackendAuthRequest>(&body) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            r#"body must be {"auth": "<base64 user:pass>"}"#,
        );
    };

    let Some(backend) = backend else {
        return json_error(StatusCode::NOT_FOUND, "no registry backend");
    };
    match backend.set_auth(&request.auth) {
        Ok(()) => {
            info!("replaced the registry backend credentials");
            response(StatusCode::NO_CONTENT, Bytes::new())
        }
        Err(err) => match err.kind() {
            io::ErrorKind::Unsupported => json_error(StatusCode::NOT_FOUND, "no registry backend"),
            io::ErrorKind::InvalidInput => {
                json_error(StatusCode::BAD_REQUEST, "auth is not base64 of user:pass")
            }
            kind => {
                error!("failed to replace the registry backend credentials: {kind}");
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to replace the credentials",
                )
            }
        },
    }
}

/// Waits for the upgrade, then runs `handler` on the raw stream off the runtime.
async fn run_control(upgrade: hyper::upgrade::OnUpgrade, handler: ControlHandler) -> Result<bool> {
    let upgraded = tokio::time::timeout(HTTP_TIMEOUT, upgrade)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP upgrade timed out"))?
        .map_err(|err| Error::Protocol(format!("HTTP upgrade failed: {err}")))?;
    let parts = upgraded
        .downcast::<TokioIo<UnixStream>>()
        .map_err(|_| Error::Protocol("HTTP upgrade did not return a Unix stream".into()))?;
    let stream = parts.io.into_inner().into_std()?;
    stream.set_nonblocking(false)?;
    tokio::task::spawn_blocking(move || handler(stream, parts.read_buf.to_vec()))
        .await
        .map_err(|err| Error::Runtime(format!("control task failed: {err}")))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_protocol_matching_ignores_ascii_case() {
        for (protocol, accepted) in [
            ("nydus-fuse-control/1", true),
            ("Nydus-Fuse-Control/1", true),
            ("NYDUS-FUSE-CONTROL/1", true),
            ("nydus-fuse-control/2", false),
            ("other-control/1", false),
        ] {
            let headers = [
                ("Connection", b"Upgrade".as_slice()),
                ("Upgrade", protocol.as_bytes()),
            ];
            assert_eq!(
                is_control_upgrade(headers.into_iter(), "nydus-fuse-control/1"),
                accepted,
                "{protocol}"
            );
        }
    }

    fn get(socket_path: &Path, path: &str) -> String {
        use std::io::{Read, Write};
        let mut stream = StdUnixStream::connect(socket_path).unwrap();
        stream
            .write_all(format!("GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n").as_bytes())
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    fn serves_the_metrics_and_ondemand_record_it_was_started_with() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("run").join("api.sock");
        let metrics = Arc::new(Metrics::new());
        let ondemand = Arc::new(OndemandRecorder::default());
        metrics.storage.collect_prefetch_task_finished_metrics();
        ondemand.record_chunk_group_access(1, 4);
        let server = ApiServer::start(
            &format!("unix://{}", socket_path.display()),
            metrics,
            ondemand,
            None,
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
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("api.sock");
        std::fs::write(&socket_path, b"stale").unwrap();
        let server = ApiServer::start(
            &format!("unix://{}", socket_path.display()),
            Arc::new(Metrics::new()),
            Arc::new(OndemandRecorder::default()),
            None,
        )
        .unwrap();
        assert!(get(&socket_path, "/metrics").contains(" 200 "));
        server.stop();
    }

    fn registry() -> Arc<dyn Backend> {
        let config = serde_json::from_str(
            r#"{"type":"registry","config":{"addr":"http://127.0.0.1:5000","repository":"a/b"}}"#,
        )
        .unwrap();
        <dyn Backend>::new(&config, &Default::default(), None, Arc::new(Metrics::new())).unwrap()
    }

    struct Refusing(io::ErrorKind, Arc<Metrics>);

    impl Backend for Refusing {
        fn metrics(&self) -> &Arc<Metrics> {
            &self.1
        }

        fn read_blob_metadata(
            &self,
            _blob_id: &[u8; 32],
        ) -> io::Result<nydus_format::blob::BlobMetadata> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn read_range_into(
            &self,
            _blob_id: &[u8; 32],
            _offset: u64,
            _buf: &mut [u8],
        ) -> io::Result<()> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn set_auth(&self, auth: &str) -> io::Result<()> {
            Err(io::Error::new(self.0, auth.to_string()))
        }
    }

    #[test]
    fn put_backend_auth_answers_by_peer_body_and_backend() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let registry = registry();
        let local: Arc<dyn Backend> = Arc::new(nydus_backend::Local::new(
            dir.path().to_path_buf(),
            Arc::new(Metrics::new()),
        ));
        let refusing =
            |kind| -> Arc<dyn Backend> { Arc::new(Refusing(kind, Arc::new(Metrics::new()))) };
        let auth = r#"{"auth":"Ym9iOmh1bnRlcjI="}"#.to_string();
        let test_cases = vec![
            (
                true,
                Some(registry.clone()),
                auth.clone(),
                StatusCode::NO_CONTENT,
            ),
            (
                false,
                Some(registry.clone()),
                auth.clone(),
                StatusCode::FORBIDDEN,
            ),
            (
                true,
                Some(registry.clone()),
                r#"{"auth":"Ym9i"}"#.to_string(),
                StatusCode::BAD_REQUEST,
            ),
            (
                true,
                Some(registry.clone()),
                r#"{"auth":"Ym9iOmh1bnRlcjI=","user":"bob"}"#.to_string(),
                StatusCode::BAD_REQUEST,
            ),
            (
                true,
                Some(registry.clone()),
                r#""Ym9iOmh1bnRlcjI=""#.to_string(),
                StatusCode::BAD_REQUEST,
            ),
            (
                true,
                Some(registry.clone()),
                format!(r#"{{"auth":"{}"}}"#, "A".repeat(BACKEND_AUTH_BODY_LIMIT)),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                true,
                Some(refusing(io::ErrorKind::InvalidInput)),
                auth.clone(),
                StatusCode::BAD_REQUEST,
            ),
            (
                true,
                Some(refusing(io::ErrorKind::Other)),
                auth.clone(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (true, Some(local), auth.clone(), StatusCode::NOT_FOUND),
            (true, None, auth, StatusCode::NOT_FOUND),
        ];

        for (authorized, backend, body, status) in test_cases {
            let reply = runtime.block_on(put_backend_auth(
                Full::new(Bytes::from(body.clone())),
                backend,
                authorized,
            ));
            assert_eq!(reply.status(), status, "{body:.64}");
            let reply = runtime
                .block_on(reply.into_body().collect())
                .unwrap()
                .to_bytes();
            assert!(
                !String::from_utf8_lossy(&reply).contains("Ym9i"),
                "{body:.64}"
            );
            if status != StatusCode::NO_CONTENT {
                let reply: serde_json::Value = serde_json::from_slice(&reply).unwrap();
                assert!(reply["message"].is_string(), "{body:.64}");
            }
        }
    }

    #[test]
    fn serves_backend_auth_on_put_only() {
        use std::io::{Read, Write};
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("api.sock");
        let server = ApiServer::start(
            &format!("unix://{}", socket_path.display()),
            Arc::new(Metrics::new()),
            Arc::new(OndemandRecorder::default()),
            Some(registry()),
        )
        .unwrap();
        let test_cases = vec![
            ("PUT", " 204 "),
            ("GET", " 405 "),
            ("POST", " 405 "),
            ("DELETE", " 405 "),
        ];

        for (method, status) in test_cases {
            let body = r#"{"auth":"Ym9iOmh1bnRlcjI="}"#;
            let mut stream = StdUnixStream::connect(&socket_path).unwrap();
            write!(
                stream,
                "{method} {BACKEND_AUTH_PATH} HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            assert!(response.contains(status), "{method}: {response}");
            let allowed = status == " 405 ";
            assert_eq!(
                response.to_ascii_lowercase().contains("\r\nallow: put\r\n"),
                allowed,
                "{method}: {response}"
            );
            assert_eq!(
                response.contains(r#"{"message":"method not allowed"}"#),
                allowed,
                "{method}: {response}"
            );
        }

        server.stop();
    }
}
