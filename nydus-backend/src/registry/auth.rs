//! Registry authentication: the cached `Authorization` header and the
//! `WWW-Authenticate` handshake that refreshes it.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::Method;
use serde::Deserialize;
use url::Url;

use super::http::Http;
use super::response::status_error;
use super::{RegistryError, RegistryResult};
use crate::ReadKind;

/// The `client_id` nydus reports to a registry token server.
const CLIENT_ID: &str = "nydus-registry-client";

/// How long a bearer token lives when the token server does not say.
const DEFAULT_TOKEN_EXPIRATION: u64 = 10 * 60;

/// How many seconds before expiry a cached token is already treated as
/// expired, so a request never leaves with a token about to lapse.
const TOKEN_REFRESH_MARGIN: u64 = 20;

/// The credentials of one registry: the configured basic credentials and the
/// `Authorization` value the last handshake produced.
pub(crate) struct Auth {
    /// `base64(user:pass)` from the config, sent verbatim after `Basic `.
    basic: Option<String>,
    /// The cached `Authorization` value, `Bearer ...` or `Basic ...`, empty
    /// when no handshake succeeded yet.
    cached: RwLock<String>,
    /// The epoch second the cached bearer token expires at, `None` for basic.
    token_expires_at: ArcSwapOption<u64>,
}

/// The challenge a registry sends in `WWW-Authenticate`.
pub(crate) enum AuthChallenge {
    Basic,
    Bearer {
        realm: String,
        service: String,
        scope: String,
    },
}

/// The body a token server answers with, either field naming the token.
#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default)]
    token: String,
    #[serde(default)]
    access_token: String,
    #[serde(default = "default_token_expiration")]
    expires_in: u64,
}

fn default_token_expiration() -> u64 {
    DEFAULT_TOKEN_EXPIRATION
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse a credential into an `Authorization` header value. Tokens come from
/// the remote token server and basic credentials from the config, so bytes an
/// HTTP header cannot carry surface as an auth error instead of a panic.
pub(crate) fn header_value(value: &str) -> RegistryResult<HeaderValue> {
    value.parse().map_err(|_| {
        RegistryError::Unauthorized(
            "credentials contain bytes that are invalid in an HTTP header".to_string(),
        )
    })
}

impl Auth {
    /// Create the credentials of a registry from its optional basic
    /// credentials.
    pub(crate) fn new(basic: Option<String>) -> Self {
        Self {
            basic,
            cached: RwLock::new(String::new()),
            token_expires_at: ArcSwapOption::from(None),
        }
    }

    /// The cached `Authorization` value, empty when none is cached or the
    /// bearer token is within [`TOKEN_REFRESH_MARGIN`] of expiring.
    pub(crate) fn current(&self) -> String {
        if let Some(expires_at) = self.token_expires_at.load().as_deref().copied() {
            if now_secs() + TOKEN_REFRESH_MARGIN >= expires_at {
                self.clear();
                return String::new();
            }
        }
        self.cached.read().unwrap().clone()
    }

    /// Cache `value` as the `Authorization` to send from now on.
    pub(crate) fn set(&self, value: String) {
        *self.cached.write().unwrap() = value;
    }

    /// Forget the cached `Authorization` and its expiry.
    pub(crate) fn clear(&self) {
        self.cached.write().unwrap().clear();
        self.token_expires_at.store(None);
    }

    /// Parse a `WWW-Authenticate` value, `None` for a scheme nydus cannot
    /// answer.
    pub(crate) fn parse_challenge(value: &str) -> Option<AuthChallenge> {
        let (scheme, rest) = value.split_once(' ')?;
        match scheme.trim() {
            "Basic" => Some(AuthChallenge::Basic),
            "Bearer" => {
                let mut params = HashMap::new();
                for pair in rest.split(',') {
                    if let Some((k, v)) = pair.trim().split_once('=') {
                        params.insert(k.trim(), v.trim().trim_matches('"'));
                    }
                }
                Some(AuthChallenge::Bearer {
                    realm: (*params.get("realm")?).to_string(),
                    service: params.get("service").copied().unwrap_or("").to_string(),
                    scope: params.get("scope").copied().unwrap_or("").to_string(),
                })
            }
            _ => None,
        }
    }

    /// Answer `challenge` with an `Authorization` value: the basic
    /// credentials, or a bearer token fetched from the realm through `http`.
    pub(crate) async fn obtain(
        &self,
        http: &Http,
        challenge: AuthChallenge,
    ) -> RegistryResult<String> {
        match challenge {
            AuthChallenge::Basic => {
                let basic = self.basic.as_ref().ok_or_else(|| {
                    RegistryError::Unauthorized(
                        "registry requires basic-auth credentials".to_string(),
                    )
                })?;
                Ok(format!("Basic {basic}"))
            }
            AuthChallenge::Bearer {
                realm,
                service,
                scope,
            } => {
                let token = self.fetch_token(http, &realm, &service, &scope).await?;
                Ok(format!("Bearer {token}"))
            }
        }
    }

    /// Fetch a bearer token from the realm, always straight from the token
    /// server and never through Dragonfly, and remember when it expires.
    async fn fetch_token(
        &self,
        http: &Http,
        realm: &str,
        service: &str,
        scope: &str,
    ) -> RegistryResult<String> {
        let mut url = Url::parse(realm)
            .map_err(|err| RegistryError::InvalidUrl(format!("{realm}: {err}")))?;
        {
            let mut query = url.query_pairs_mut();
            if !service.is_empty() {
                query.append_pair("service", service);
            }
            if !scope.is_empty() {
                query.append_pair("scope", scope);
            }
            query.append_pair("client_id", CLIENT_ID);
        }

        let mut headers = HeaderMap::new();
        if let Some(basic) = &self.basic {
            headers.insert(AUTHORIZATION, header_value(&format!("Basic {basic}"))?);
        }

        let response = http
            .request(Method::GET, url.as_str(), headers, ReadKind::OnDemand)
            .await?;
        if !response.status.is_success() {
            return Err(status_error(response).await);
        }

        let body = response.text().await.map_err(RegistryError::Io)?;
        let mut token: TokenResponse = serde_json::from_str(&body).map_err(|err| {
            RegistryError::UnexpectedResponse(format!("invalid token response: {err}"))
        })?;
        if token.token.is_empty() {
            token.token = token.access_token.clone();
        }
        if token.token.is_empty() {
            return Err(RegistryError::UnexpectedResponse(
                "empty token from registry".to_string(),
            ));
        }

        self.token_expires_at
            .store(Some(Arc::new(now_secs() + token.expires_in)));
        Ok(token.token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bearer_challenge() {
        let header = r#"Bearer realm="https://auth.example.com/token",service="example.com",scope="repository:library/ubuntu:pull""#;
        match Auth::parse_challenge(header).unwrap() {
            AuthChallenge::Bearer {
                realm,
                service,
                scope,
            } => {
                assert_eq!(realm, "https://auth.example.com/token");
                assert_eq!(service, "example.com");
                assert_eq!(scope, "repository:library/ubuntu:pull");
            }
            _ => panic!("expected bearer challenge"),
        }
    }

    #[test]
    fn parses_basic_challenge() {
        assert!(matches!(
            Auth::parse_challenge(r#"Basic realm="registry""#).unwrap(),
            AuthChallenge::Basic
        ));
        assert!(Auth::parse_challenge(r#"Digest realm="registry""#).is_none());
    }

    #[test]
    fn expired_token_is_cleared() {
        let auth = Auth::new(None);
        auth.set("Bearer xyz".to_string());
        auth.token_expires_at.store(Some(Arc::new(now_secs())));
        assert_eq!(auth.current(), "");
        assert!(auth.cached.read().unwrap().is_empty());
    }

    #[test]
    fn a_fresh_token_is_served_from_the_cache() {
        let auth = Auth::new(None);
        auth.set("Bearer xyz".to_string());
        auth.token_expires_at
            .store(Some(Arc::new(now_secs() + 3600)));
        assert_eq!(auth.current(), "Bearer xyz");
    }

    #[test]
    fn header_value_rejects_bytes_a_header_cannot_carry() {
        assert!(header_value("Bearer ok").is_ok());
        assert!(matches!(
            header_value("Bearer bad\nvalue"),
            Err(RegistryError::Unauthorized(_))
        ));
    }
}
