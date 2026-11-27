//! The HTTP server behind `--apiserver`: an image's metrics and ondemand record
//! over a Unix socket, the daemon's description, the registry backend's
//! credentials, plus optional Unix control-protocol upgrades.

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
use nydus_config::GIT_COMMIT_SHORT_HASH;
use nydus_core::{Metrics, OndemandRecorder};
use prometheus::{Encoder, TextEncoder};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
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

/// The wait after a failed accept before the next one.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The route that describes the daemon: its build, its process and the
/// optional calls it serves.
const DAEMON_PATH: &str = "/api/v1/daemon";

/// The route that replaces the basic credentials of the registry backend.
const BACKEND_AUTH_BASIC_PATH: &str = "/api/v1/backend/auth/basic";

/// The route that replaces the bearer token of the registry backend.
const BACKEND_AUTH_BEARER_PATH: &str = "/api/v1/backend/auth/bearer";

/// The largest body a route replacing a credential reads.
const CREDENTIAL_BODY_LIMIT: usize = 64 * 1024;

/// A credential of the registry backend that the `PUT` of its route replaces.
///
/// ```text
/// PUT /api/v1/backend/auth/basic   {"username", "password"} ─▶ Backend::set_basic_auth
/// PUT /api/v1/backend/auth/bearer  {"token"}                ─▶ Backend::set_bearer_auth
/// ```
trait Credential: DeserializeOwned {
    /// The message telling the body the route takes.
    const BODY: &'static str;

    /// The message of a credential that is rejected.
    const INVALID: &'static str;

    /// Replaces the credential of `backend`.
    fn set(&self, backend: &dyn Backend) -> io::Result<()>;
}

/// The body of `PUT` [`BACKEND_AUTH_BASIC_PATH`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendAuthBasicRequest {
    /// The user name.
    username: String,

    /// The password.
    password: String,
}

/// Implements the credential [`BACKEND_AUTH_BASIC_PATH`] replaces.
impl Credential for BackendAuthBasicRequest {
    const BODY: &'static str =
        r#"body must be {"username": "<username>", "password": "<password>"}"#;

    const INVALID: &'static str = "username holds a colon";

    fn set(&self, backend: &dyn Backend) -> io::Result<()> {
        backend.set_basic_auth(&self.username, &self.password)
    }
}

/// The body of `PUT` [`BACKEND_AUTH_BEARER_PATH`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendAuthBearerRequest {
    /// The bearer token.
    token: String,
}

/// Implements the credential [`BACKEND_AUTH_BEARER_PATH`] replaces.
impl Credential for BackendAuthBearerRequest {
    const BODY: &'static str = r#"body must be {"token": "<bearer token>"}"#;

    const INVALID: &'static str = "token is not a bearer token";

    fn set(&self, backend: &dyn Backend) -> io::Result<()> {
        backend.set_bearer_auth(&self.token)
    }
}

/// An optional call of the API, listed by [`DAEMON_PATH`] when this daemon
/// serves it.
///
/// A client gates the call on its capability, not on the daemon's version,
/// and ignores the capabilities it does not know, the way a CSI driver's
/// capabilities and a containerd plugin's are read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Capability {
    /// [`BACKEND_AUTH_BASIC_PATH`] replaces the registry backend's basic
    /// credentials.
    BackendAuthBasic,

    /// [`BACKEND_AUTH_BEARER_PATH`] replaces the registry backend's bearer
    /// token.
    BackendAuthBearer,
}

/// The body `GET` [`DAEMON_PATH`] answers with. Fields are only ever added,
/// so a client ignores the ones it does not know.
#[derive(Debug, Serialize)]
struct DaemonInfo {
    /// The version of the build.
    version: &'static str,

    /// The git commit of the build.
    git_commit: &'static str,

    /// The process ID of the daemon.
    pid: u32,

    /// The optional calls this daemon serves.
    capabilities: Vec<Capability>,
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

    /// The backend [`BACKEND_AUTH_BASIC_PATH`] and
    /// [`BACKEND_AUTH_BEARER_PATH`] replace the credentials of.
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
    /// Starts an endpoint without control upgrades, `backend` answering the
    /// `/api/v1/backend/auth` routes when given.
    /// FUSE uses its ownership-aware
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
                Err(err) => {
                    // Back off before accepting again, a failure such as EMFILE lasts.
                    error!("apiserver accept error: {err}");
                    tokio::select! {
                        _ = stopped.changed() => break,
                        _ = tokio::time::sleep(ACCEPT_BACKOFF) => {}
                    }
                }
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
    if req.uri().path() == DAEMON_PATH {
        if req.method() != Method::GET {
            let mut reply = json_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
            reply
                .headers_mut()
                .insert(ALLOW, HeaderValue::from_static("GET"));
            return Ok(reply);
        }
        return Ok(get_daemon(backend.as_deref()));
    }
    let basic = req.uri().path() == BACKEND_AUTH_BASIC_PATH;
    if basic || req.uri().path() == BACKEND_AUTH_BEARER_PATH {
        if req.method() != Method::PUT {
            let mut reply = json_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
            reply
                .headers_mut()
                .insert(ALLOW, HeaderValue::from_static("PUT"));
            return Ok(reply);
        }
        let body = req.into_body();
        return Ok(if basic {
            put_backend_credential::<BackendAuthBasicRequest, _>(body, backend, authorized).await
        } else {
            put_backend_credential::<BackendAuthBearerRequest, _>(body, backend, authorized).await
        });
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

/// Answers `GET` [`DAEMON_PATH`]: the build and the process of this daemon and
/// its capabilities, the calls that replace a credential when it has a
/// backend.
fn get_daemon(backend: Option<&dyn Backend>) -> Response<Full<Bytes>> {
    let info = DaemonInfo {
        version: env!("CARGO_PKG_VERSION"),
        git_commit: GIT_COMMIT_SHORT_HASH,
        pid: std::process::id(),
        capabilities: backend
            .map(|_| vec![Capability::BackendAuthBasic, Capability::BackendAuthBearer])
            .unwrap_or_default(),
    };
    match serde_json::to_vec(&info) {
        Ok(body) => {
            let mut reply = response(StatusCode::OK, body);
            reply
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            reply
        }
        Err(err) => {
            error!("failed to encode the daemon info: {err}");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to encode the daemon info",
            )
        }
    }
}

/// Answers the `PUT` that replaces the credential `C` of `backend` with the
/// one a JSON `body` carries. Error messages are fixed, so none echoes the
/// credential.
///
/// ```text
/// peer of another UID ───────────────────▶ 403
/// body over CREDENTIAL_BODY_LIMIT ───────▶ 413
/// body later than HTTP_TIMEOUT ──────────▶ 408
/// body that is not `C` ──────────────────▶ 400
/// no backend, or one without credentials ▶ 404
/// credential the backend rejects ────────▶ 400
/// credential replaced ───────────────────▶ 204
/// ```
async fn put_backend_credential<C, B>(
    body: B,
    backend: Option<Arc<dyn Backend>>,
    authorized: bool,
) -> Response<Full<Bytes>>
where
    C: Credential,
    B: Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if !authorized {
        return json_error(StatusCode::FORBIDDEN, "peer uid mismatch");
    }

    let body = Limited::new(body, CREDENTIAL_BODY_LIMIT).collect();
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
    let Ok(credential) = serde_json::from_slice::<C>(&body) else {
        return json_error(StatusCode::BAD_REQUEST, C::BODY);
    };

    let Some(backend) = backend else {
        return json_error(StatusCode::NOT_FOUND, "no registry backend");
    };
    match credential.set(backend.as_ref()) {
        Ok(()) => {
            info!("replaced the registry backend credentials");
            response(StatusCode::NO_CONTENT, Bytes::new())
        }
        Err(err) => match err.kind() {
            io::ErrorKind::Unsupported => json_error(StatusCode::NOT_FOUND, "no registry backend"),
            io::ErrorKind::InvalidInput => json_error(StatusCode::BAD_REQUEST, C::INVALID),
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
        let config: nydus_config::Config = serde_yaml::from_str(
            "backend:\n  type: registry\n  config:\n    addr: http://127.0.0.1:5000\n    repository: a/b\n",
        )
        .unwrap();
        <dyn Backend>::new(&config, Arc::new(Metrics::new()), None).unwrap()
    }

    struct Refusing(io::ErrorKind, Arc<Metrics>);

    impl Backend for Refusing {
        fn metrics(&self) -> &Arc<Metrics> {
            &self.1
        }

        fn get_blob_metadata(
            &self,
            _blob_id: &[u8; 32],
        ) -> io::Result<nydus_format::blob::BlobMetadata> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn get(
            &self,
            _blob_id: &[u8; 32],
            _offset: u64,
            _len: usize,
        ) -> io::Result<Box<dyn io::BufRead + Send>> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn set_basic_auth(&self, _username: &str, password: &str) -> io::Result<()> {
            Err(io::Error::new(self.0, password.to_string()))
        }

        fn set_bearer_auth(&self, token: &str) -> io::Result<()> {
            Err(io::Error::new(self.0, token.to_string()))
        }
    }

    type PutCase = (bool, Option<Arc<dyn Backend>>, String, StatusCode);

    fn assert_put<C: Credential>(test_cases: Vec<PutCase>) {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        for (authorized, backend, body, status) in test_cases {
            let reply = runtime.block_on(put_backend_credential::<C, _>(
                Full::new(Bytes::from(body.clone())),
                backend,
                authorized,
            ));
            assert_eq!(reply.status(), status, "{body:.64}");
            let reply = runtime
                .block_on(reply.into_body().collect())
                .unwrap()
                .to_bytes();
            let reply = String::from_utf8_lossy(&reply);
            assert!(
                ["Ym9i", "hunter2", "s3cr3t"]
                    .iter()
                    .all(|secret| !reply.contains(secret)),
                "{body:.64}"
            );
            if status != StatusCode::NO_CONTENT {
                let reply: serde_json::Value = serde_json::from_str(&reply).unwrap();
                assert!(reply["message"].is_string(), "{body:.64}");
            }
        }
    }

    fn refusing(kind: io::ErrorKind) -> Arc<dyn Backend> {
        Arc::new(Refusing(kind, Arc::new(Metrics::new())))
    }

    fn local(dir: &Path) -> Arc<dyn Backend> {
        Arc::new(nydus_backend::Local::new(
            dir.to_path_buf(),
            Arc::new(Metrics::new()),
        ))
    }

    #[test]
    fn put_backend_auth_basic_answers_by_peer_body_and_backend() {
        let dir = tempfile::tempdir().unwrap();
        let registry = registry();
        let basic = r#"{"username":"bob","password":"hunter2"}"#.to_string();
        assert_put::<BackendAuthBasicRequest>(vec![
            (
                true,
                Some(registry.clone()),
                basic.clone(),
                StatusCode::NO_CONTENT,
            ),
            (
                true,
                Some(registry.clone()),
                r#"{"username":"bob","password":""}"#.to_string(),
                StatusCode::NO_CONTENT,
            ),
            (
                false,
                Some(registry.clone()),
                basic.clone(),
                StatusCode::FORBIDDEN,
            ),
            (
                true,
                Some(registry.clone()),
                r#"{"username":"bo:b","password":"hunter2"}"#.to_string(),
                StatusCode::BAD_REQUEST,
            ),
            (
                true,
                Some(registry.clone()),
                r#"{"username":"bob"}"#.to_string(),
                StatusCode::BAD_REQUEST,
            ),
            (
                true,
                Some(registry.clone()),
                r#"{"username":"bob","password":"hunter2","token":"s3cr3t"}"#.to_string(),
                StatusCode::BAD_REQUEST,
            ),
            (
                true,
                Some(registry.clone()),
                r#"{"auth":"Ym9iOmh1bnRlcjI="}"#.to_string(),
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
                format!(
                    r#"{{"username":"bob","password":"{}"}}"#,
                    "A".repeat(CREDENTIAL_BODY_LIMIT)
                ),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                true,
                Some(refusing(io::ErrorKind::InvalidInput)),
                basic.clone(),
                StatusCode::BAD_REQUEST,
            ),
            (
                true,
                Some(refusing(io::ErrorKind::Other)),
                basic.clone(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                true,
                Some(local(dir.path())),
                basic.clone(),
                StatusCode::NOT_FOUND,
            ),
            (true, None, basic, StatusCode::NOT_FOUND),
        ]);
    }

    #[test]
    fn put_backend_auth_bearer_answers_by_peer_body_and_backend() {
        let dir = tempfile::tempdir().unwrap();
        let registry = registry();
        let bearer = r#"{"token":"s3cr3t"}"#.to_string();
        assert_put::<BackendAuthBearerRequest>(vec![
            (
                true,
                Some(registry.clone()),
                bearer.clone(),
                StatusCode::NO_CONTENT,
            ),
            (
                false,
                Some(registry.clone()),
                bearer.clone(),
                StatusCode::FORBIDDEN,
            ),
            (
                true,
                Some(registry.clone()),
                r#"{"token":""}"#.to_string(),
                StatusCode::BAD_REQUEST,
            ),
            (
                true,
                Some(registry.clone()),
                r#"{"token":"s3cr3t","username":"bob"}"#.to_string(),
                StatusCode::BAD_REQUEST,
            ),
            (
                true,
                Some(registry.clone()),
                r#"{"registry_token":"s3cr3t"}"#.to_string(),
                StatusCode::BAD_REQUEST,
            ),
            (
                true,
                Some(registry.clone()),
                format!(r#"{{"token":"{}"}}"#, "A".repeat(CREDENTIAL_BODY_LIMIT)),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                true,
                Some(refusing(io::ErrorKind::InvalidInput)),
                bearer.clone(),
                StatusCode::BAD_REQUEST,
            ),
            (
                true,
                Some(refusing(io::ErrorKind::Other)),
                bearer.clone(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                true,
                Some(local(dir.path())),
                bearer.clone(),
                StatusCode::NOT_FOUND,
            ),
            (true, None, bearer, StatusCode::NOT_FOUND),
        ]);
    }

    #[test]
    fn serves_the_daemon_info_with_the_capabilities_of_its_backend() {
        let test_cases: Vec<(Option<Arc<dyn Backend>>, &str)> = vec![
            (None, r#""capabilities":[]"#),
            (
                Some(registry()),
                r#""capabilities":["backend_auth_basic","backend_auth_bearer"]"#,
            ),
        ];

        for (backend, capabilities) in test_cases {
            let dir = tempfile::tempdir().unwrap();
            let socket_path = dir.path().join("api.sock");
            let server = ApiServer::start(
                &format!("unix://{}", socket_path.display()),
                Arc::new(Metrics::new()),
                Arc::new(OndemandRecorder::default()),
                backend,
            )
            .unwrap();
            let response = get(&socket_path, DAEMON_PATH);
            assert!(response.contains(" 200 "), "{response}");
            assert!(
                response
                    .to_ascii_lowercase()
                    .contains("\r\ncontent-type: application/json\r\n"),
                "{response}"
            );
            assert!(
                response.contains(&format!(
                    r#"{{"version":"{}","git_commit":"{}","pid":{},"#,
                    env!("CARGO_PKG_VERSION"),
                    GIT_COMMIT_SHORT_HASH,
                    std::process::id()
                )),
                "{response}"
            );
            assert!(response.contains(capabilities), "{response}");
            server.stop();
        }
    }

    #[test]
    fn serves_the_daemon_info_on_get_only() {
        use std::io::{Read, Write};
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("api.sock");
        let server = ApiServer::start(
            &format!("unix://{}", socket_path.display()),
            Arc::new(Metrics::new()),
            Arc::new(OndemandRecorder::default()),
            None,
        )
        .unwrap();
        let test_cases = vec![
            ("GET", " 200 "),
            ("PUT", " 405 "),
            ("POST", " 405 "),
            ("DELETE", " 405 "),
        ];

        for (method, status) in test_cases {
            let mut stream = StdUnixStream::connect(&socket_path).unwrap();
            write!(
                stream,
                "{method} {DAEMON_PATH} HTTP/1.0\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
            )
            .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            assert!(response.contains(status), "{method}: {response}");
            assert_eq!(
                response.to_ascii_lowercase().contains("\r\nallow: get\r\n"),
                status == " 405 ",
                "{method}: {response}"
            );
        }

        server.stop();
    }

    #[test]
    fn serves_the_backend_credentials_on_put_only() {
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
        let basic = (
            BACKEND_AUTH_BASIC_PATH,
            r#"{"username":"bob","password":"hunter2"}"#,
        );
        let bearer = (BACKEND_AUTH_BEARER_PATH, r#"{"token":"xyz"}"#);
        let test_cases = vec![
            (basic, "PUT", " 204 "),
            (basic, "GET", " 405 "),
            (basic, "POST", " 405 "),
            (basic, "DELETE", " 405 "),
            (bearer, "PUT", " 204 "),
            (bearer, "GET", " 405 "),
            (bearer, "POST", " 405 "),
            (bearer, "DELETE", " 405 "),
        ];

        for ((path, body), method, status) in test_cases {
            let mut stream = StdUnixStream::connect(&socket_path).unwrap();
            write!(
                stream,
                "{method} {path} HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            assert!(response.contains(status), "{method} {path}: {response}");
            let allowed = status == " 405 ";
            assert_eq!(
                response.to_ascii_lowercase().contains("\r\nallow: put\r\n"),
                allowed,
                "{method} {path}: {response}"
            );
            assert_eq!(
                response.contains(r#"{"message":"method not allowed"}"#),
                allowed,
                "{method} {path}: {response}"
            );
        }

        server.stop();
    }
}
