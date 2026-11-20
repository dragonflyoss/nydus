//! The client of one repository on one registry: the blob URL, the auth
//! handshake and the redirects of a blob `GET`.

use std::future::Future;
use std::io;
use std::ops::RangeInclusive;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use reqwest::header::{HeaderMap, AUTHORIZATION, RANGE, WWW_AUTHENTICATE};
use reqwest::StatusCode;
use tracing::warn;
use url::Url;

use nydus_format::utils::SHA256_DIGEST_SIZE;

use super::auth::{Authorizer, Challenge};
use super::range::Range;
use super::redirect::RedirectCache;
use super::response::Response;
use super::transport::{Fetcher, Transport};

/// The client of one repository on one registry.
///
/// The reads of a blob from a registry with bearer auth that redirects blob
/// `GET`s to a CDN:
///
/// ```text
/// the first read, get(blob_id, range)
///   1. redirect cache ───────────────────────────────────────────▶ miss
///   2. GET blob URL, no token kept ────────────────────────────────▶ 401 WWW-Authenticate
///   3. fetch a token from the challenge's realm, keep it until it expires
///   4. GET blob URL again, with the token ─────────────────────────▶ 307 Location
///   5. GET the location, the signed CDN URL ───────────────────────▶ 206 bytes
///   6. cache the location for the blob, 10 minutes
///
/// the first read with a `registry_token` in the config, kept as the token
///   1. redirect cache ───────────────────────────────────────────▶ miss, step 4
///
/// the reads that follow
///   1. redirect cache ──▶ hit ──▶ GET the cached location ─────────▶ 206 bytes
///                                  └─ rejected, the link expired ───▶ evicted, step 4
///
/// a read once the token expired, or the registry refuses it
///   4. GET blob URL ──▶ 401 ──▶ the token is forgotten ────────────▶ step 2
///
/// a prefetch read answered with a `429`, `5xx` or `408`
///   sent once more after the retry interval, from step 1
///
/// a read through the proxy or Dragonfly whose body breaks off, see
/// [`Response::resumable`]
///   the same steps from the origin, for the bytes left
///
/// any other status ends the read as an error, a 2xx at any GET as the bytes
/// ```
pub(crate) struct Client {
    /// The registry origin, `scheme://host[:port]/`.
    pub(crate) addr: Url,

    /// The image repository, such as `library/ubuntu`.
    pub(crate) repository: String,

    /// The credentials and the `Authorization` kept from the config or the
    /// last challenge.
    pub(crate) authorizer: Authorizer,

    /// The signed URLs blob `GET`s were redirected to, by blob hex digest.
    pub(crate) redirects: RedirectCache,

    /// The random wait before a prefetch read is sent once more.
    pub(crate) prefetch_retry_interval: RangeInclusive<Duration>,

    /// The transport of token fetches, never Dragonfly: `http.proxy` when
    /// configured, falling back to the origin, or the origin.
    pub(crate) auth_transport: Transport,

    /// The transport of blob `GET`s: the Dragonfly seed peers or `http.proxy`
    /// when configured, falling back to the origin, or the origin.
    pub(crate) transport: Transport,
}

/// Implements the registry requests.
impl Client {
    /// Returns the URL of blob `hex`, `<addr>/v2/<repository>/blobs/sha256:<hex>`.
    pub(crate) fn blob_url(&self, hex: &str) -> io::Result<Url> {
        Url::parse(&format!(
            "{}/v2/{}/blobs/sha256:{hex}",
            self.addr.as_str().trim_end_matches('/'),
            self.repository
        ))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
    }

    /// Executes `request` with the kept token, answering a `401` with the auth
    /// handshake.
    ///
    /// ```text
    /// request with the kept token, none when it expired
    ///   ├─ not 401 ────────────────────────────────────────────────────────▶ answer
    ///   └─ 401 ─▶ sent with a token? it is forgotten, request again without
    ///              ├─ no WWW-Authenticate ─────────────────────────────────▶ answer
    ///              └─ WWW-Authenticate ─▶ fetch a token, keep it ─▶ request again ─▶ answer
    /// ```
    async fn execute<F, Fut>(&self, mut headers: HeaderMap, request: F) -> io::Result<Response>
    where
        F: Fn(HeaderMap) -> Fut,
        Fut: Future<Output = io::Result<Response>>,
    {
        self.authorizer.authorize(&mut headers);
        let response = request(headers.clone()).await?;
        if response.status != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }

        let challenge_response = match headers.remove(AUTHORIZATION) {
            Some(stale) => {
                self.authorizer.invalidate(&stale);
                request(headers.clone()).await?
            }
            None => response,
        };

        let challenge = challenge_response
            .headers
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<Challenge>().ok());
        let Some(challenge) = challenge else {
            return Ok(challenge_response);
        };

        let authorization = self
            .authorizer
            .authenticate(&self.auth_transport, challenge)
            .await?;
        headers.insert(AUTHORIZATION, authorization);
        request(headers).await
    }

    /// Fetches the `range` of a blob for an on-demand read, its body resumed
    /// through the fallback of the transport when it breaks off. An answer
    /// that is not the range is handed back as is.
    pub(crate) async fn get(
        self: &Arc<Self>,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        range: &Range,
    ) -> io::Result<Response> {
        let response = self.get_from(&self.transport, blob_id, range).await?;
        if response.fallback.load(Ordering::Relaxed)
            || !response.status.is_success()
            || matches!(self.transport, Transport::Direct { .. })
        {
            return Ok(response);
        }

        let client = self.clone();
        let blob_id = *blob_id;
        let fallback = response.fallback.clone();
        response.resumable(move |err, range| async move {
            let fallback_http_client = client.transport.fallback(err)?;
            fallback.store(true, Ordering::Relaxed);

            let response = client
                .get_from(fallback_http_client, &blob_id, &range)
                .await?;
            if !response.status.is_success() {
                return Err(response.into_io_error().await);
            }

            Ok(response)
        })
    }

    /// Fetches the `range` of a blob from `fetcher`, through the cached
    /// redirect when there is one. An answer that is not the range is handed
    /// back as is.
    async fn get_from(
        &self,
        fetcher: &impl Fetcher,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        range: &Range,
    ) -> io::Result<Response> {
        let hex = hex::encode(blob_id);
        let mut headers = HeaderMap::new();
        headers.insert(RANGE, range.to_string().parse().map_err(io::Error::other)?);
        if let Some(redirect) = self.redirects.get(&hex) {
            let response = fetcher.get(&redirect, headers.clone()).await?;
            match response.status {
                status if status.is_success() => {
                    response.validate_range(range)?;
                    return Ok(response);
                }
                _ if response.is_redirect_expired() => self.redirects.remove(&hex),
                _ => return Ok(response),
            }
        }

        let url = self.blob_url(&hex)?;
        let response = self
            .execute(headers.clone(), |headers| fetcher.get(&url, headers))
            .await?;

        if response.status.is_success() {
            response.validate_range(range)?;
            return Ok(response);
        }

        if !response.status.is_redirection() {
            return Ok(response);
        }

        let location = response.location(&url)?;
        let redirected = fetcher.get(&location, headers).await?;
        if !redirected.status.is_success() {
            return Ok(redirected);
        }

        redirected.validate_range(range)?;
        self.redirects.insert(&hex, location);
        Ok(redirected)
    }

    /// Fetches the `range` of a blob for a prefetch read, through the cached
    /// redirect when there is one, once more on a `429`, `5xx` or `408`.
    pub(crate) async fn prefetch(
        &self,
        blob_id: &[u8; SHA256_DIGEST_SIZE],
        range: &Range,
    ) -> io::Result<Response> {
        let hex = hex::encode(blob_id);
        let mut headers = HeaderMap::new();
        headers.insert(RANGE, range.to_string().parse().map_err(io::Error::other)?);
        let transport = &self.transport;
        let url = self.blob_url(&hex)?;
        let mut retried = false;
        loop {
            // Fetch through the cached redirect, evicting one that expired.
            let cached = match self.redirects.get(&hex) {
                Some(redirect) => {
                    let response = transport.prefetch(&redirect, headers.clone()).await?;
                    if response.is_redirect_expired() {
                        self.redirects.remove(&hex);
                        None
                    } else {
                        Some(response)
                    }
                }
                None => None,
            };

            // Resolve the redirect at the registry without a cached one.
            let (response, location) = match cached {
                Some(response) => (response, None),
                None => {
                    let response = self
                        .execute(headers.clone(), |headers| transport.prefetch(&url, headers))
                        .await?;
                    if response.status.is_redirection() {
                        let location = response.location(&url)?;
                        let redirected = transport.prefetch(&location, headers.clone()).await?;
                        (redirected, Some(location))
                    } else {
                        (response, None)
                    }
                }
            };

            if response.status.is_success() {
                response.validate_range(range)?;
                if let Some(location) = location {
                    self.redirects.insert(&hex, location);
                }

                return Ok(response);
            }

            if !response.is_transient() || retried {
                return Err(response.into_io_error().await);
            }

            // Retry once after a random interval, resolving the redirect again.
            let err = response.into_io_error().await;
            let delay = rand::rng().random_range(self.prefetch_retry_interval.clone());
            warn!(
                "{} request failed, retrying in {delay:?}: {err}",
                transport.source()
            );
            tokio::time::sleep(delay).await;
            retried = true;
        }
    }
}
