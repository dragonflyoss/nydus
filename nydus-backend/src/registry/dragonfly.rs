//! The Dragonfly SDK transport, feature `backend-dragonfly`.
//!
//! A blob `GET` rides the Dragonfly client SDK to the seed peers named by the
//! scheduler, every other request going straight to the origin. The SDK owns
//! the retries: an on-demand read retries a transient failure, a `429`
//! included, on the next seed peer up to the configured budget, while a
//! prefetch read never retries, the storage layer rescheduling a failed
//! prefetch hours later instead. The body streams from the seed peer, so a
//! read holds no more than the bytes it asked for. An answer the SDK reports
//! as an error but that carries an HTTP status is handed back as a
//! [`Response`], so [`policy`](super::policy) classifies it by status like an
//! origin answer.

use std::io;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::TryStreamExt;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::StatusCode;
use tokio_util::io::StreamReader;
use tracing::debug;

use dragonfly_api::common::v2::Priority;
use dragonfly_client_request::errors::{BackendError, DfdaemonError, Error, ProxyError};
use dragonfly_client_request::{GetRequest, Proxy, Request as _};

use nydus_config::DragonflyConfig;

use super::response::Response;
use super::rt::Runtime;
use super::Transport;
use crate::{Protocol, ReadKind};

/// The Dragonfly SDK transport, one client per read kind so each kind keeps
/// its own retry budget.
pub(crate) struct Dragonfly {
    /// The client serving on-demand reads, retrying at once because a FUSE
    /// reader is waiting, a `429` included since another seed peer may not be
    /// rate limited.
    ondemand: Proxy,

    /// The client serving prefetch reads, never retrying: a failed prefetch
    /// is rescheduled hours later instead.
    prefetch: Proxy,

    /// The timeout of each attempt of a request.
    request_timeout: Duration,
}

/// Implements the Dragonfly transport.
impl Dragonfly {
    /// Creates the transport, each client connecting to the configured
    /// scheduler on the runtime of its read kind.
    ///
    /// Only the on-demand client retries, `max_retries` times across seed
    /// peers.
    pub(crate) fn new(config: DragonflyConfig, runtime: &Runtime) -> io::Result<Self> {
        Ok(Self {
            ondemand: Self::client(
                runtime,
                ReadKind::OnDemand,
                config.scheduler_endpoint.clone(),
                config.max_retries as u8,
            )?,
            prefetch: Self::client(runtime, ReadKind::Prefetch, config.scheduler_endpoint, 0)?,
            request_timeout: config.request_timeout,
        })
    }

    /// Creates the client of reads of `kind`, connected to the scheduler at
    /// `scheduler_endpoint` on that kind's runtime so it is reached from the
    /// runtime's netns, retrying a request `max_retries` times across seed
    /// peers.
    fn client(
        runtime: &Runtime,
        kind: ReadKind,
        scheduler_endpoint: String,
        max_retries: u8,
    ) -> io::Result<Proxy> {
        runtime
            .block_on_worker(kind, async move {
                Proxy::builder()
                    .scheduler_endpoint(scheduler_endpoint)
                    .max_retries(max_retries)
                    .build()
                    .await
            })?
            .map_err(|err| io::Error::other(format!("failed to build dragonfly client: {err}")))
    }
}

/// Implements the blob transport over the Dragonfly SDK.
#[async_trait]
impl Transport for Dragonfly {
    /// Fetches `url` through the client of the read kind at its scheduling
    /// priority, the SDK adding the P2P and priority headers itself, and
    /// logs the outcome.
    ///
    /// An on-demand read a FUSE reader waits on goes at `Level6`, the SDK's
    /// default, a background prefetch at `Level3` so a first download lets a
    /// normal peer go back to source ahead of it. The body streams from the
    /// seed peer; the SDK retries a transient failure before it starts, a
    /// peer failing mid-body fails the read. A proxy, backend or dfdaemon
    /// error carrying an HTTP status is an answer, rebuilt as a [`Response`]
    /// with its status, headers and message, so a `429`, `403` or a dfdaemon
    /// `422` reaches the policy the same way an origin answer does; anything
    /// else is a transport failure.
    async fn get(&self, url: &str, headers: HeaderMap, kind: ReadKind) -> io::Result<Response> {
        let (client, priority) = match kind {
            ReadKind::OnDemand => (&self.ondemand, Priority::Level6),
            ReadKind::Prefetch => (&self.prefetch, Priority::Level3),
        };
        let request = GetRequest {
            url: url.to_string(),
            header: headers,
            priority: Some(priority as i32),
            timeout: self.request_timeout,
            ..Default::default()
        };

        let start = Instant::now();
        let result = match client.get(&request).await {
            Ok(response) => Ok(Response {
                status: response.status_code.unwrap_or(StatusCode::OK),
                headers: response.header,
                body: Box::new(StreamReader::new(
                    response
                        .body
                        .unwrap_or_else(|| Box::new(futures::stream::empty()))
                        .map_err(io::Error::other),
                )),
                protocol: Protocol::Dragonfly,
            }),
            Err(Error::ProxyError(ProxyError {
                status_code: Some(status),
                header,
                message,
            }))
            | Err(Error::BackendError(BackendError {
                status_code: Some(status),
                header,
                message,
            }))
            | Err(Error::DfdaemonError(DfdaemonError {
                status_code: Some(status),
                header,
                message,
            })) => Ok(Response {
                status,
                headers: header
                    .into_iter()
                    .filter_map(|(name, value)| {
                        Some((
                            HeaderName::from_bytes(name.as_bytes()).ok()?,
                            HeaderValue::from_str(&value).ok()?,
                        ))
                    })
                    .collect(),
                body: Box::new(io::Cursor::new(message.unwrap_or_default())),
                protocol: Protocol::Dragonfly,
            }),
            Err(Error::RequestTimeout(message)) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("dragonfly request timed out: {message}"),
            )),
            Err(err) => Err(io::Error::other(format!("dragonfly error: {err}"))),
        };

        match &result {
            Ok(response) => debug!(
                "GET {url} ({kind}) through dragonfly returned {} in {:?}",
                response.status,
                start.elapsed()
            ),
            Err(err) => debug!(
                "GET {url} ({kind}) through dragonfly failed in {:?}: {err}",
                start.elapsed()
            ),
        }
        result
    }
}
