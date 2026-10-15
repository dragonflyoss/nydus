//! Registry authentication: the `WWW-Authenticate` challenge a registry
//! answers an unauthenticated request with, and the credential that answers
//! it, kept until it nears expiry.

use std::str::FromStr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

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
const DEFAULT_TOKEN_EXPIRATION: Duration = Duration::from_secs(10 * 60);

/// How long before its expiry a token is treated as expired, so a request in
/// flight never arrives with a token that has just lapsed.
const TOKEN_EXPIRY_LEEWAY: Duration = Duration::from_secs(20);

/// The challenge a registry sends in `WWW-Authenticate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Challenge {
    /// `Basic realm="..."`, answered with the configured credentials.
    Basic,

    /// `Bearer realm="...",service="...",scope="..."`, answered with a token
    /// fetched from `realm`.
    Bearer {
        /// The token server URL.
        realm: String,
        /// The service the token is for, empty when the registry names none.
        service: String,
        /// The access the token grants, empty when the registry names none.
        scope: String,
    },
}

impl FromStr for Challenge {
    type Err = RegistryError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let unsupported =
            || RegistryError::Unauthorized(format!("unsupported auth challenge: {value}"));
        let (scheme, params) = value.split_once(' ').unwrap_or((value, ""));
        let param = |name: &str| {
            params
                .split(',')
                .filter_map(|pair| pair.trim().split_once('='))
                .find(|(key, _)| key.trim() == name)
                .map(|(_, value)| value.trim().trim_matches('"').to_string())
        };
        match scheme.trim() {
            "Basic" => Ok(Self::Basic),
            "Bearer" => Ok(Self::Bearer {
                realm: param("realm").ok_or_else(unsupported)?,
                service: param("service").unwrap_or_default(),
                scope: param("scope").unwrap_or_default(),
            }),
            _ => Err(unsupported()),
        }
    }
}

/// A credential that answers a challenge, held as the `Authorization` it is
/// sent as. The header value is marked sensitive so request logs redact it.
#[derive(Debug, Clone)]
enum Credential {
    /// The configured basic credentials, which never expire.
    Basic(HeaderValue),

    /// A bearer token from the token server and when it expires.
    Bearer {
        /// The `Bearer ...` header value.
        authorization: HeaderValue,
        /// When the token server said the token expires.
        expires_at: Instant,
    },
}

impl Credential {
    /// The basic credentials `encoded`, the config's `base64(user:pass)`.
    fn basic(encoded: &str) -> RegistryResult<Self> {
        Ok(Self::Basic(Self::authorization_for(&format!(
            "Basic {encoded}"
        ))?))
    }

    /// A bearer `token` that expires `expires_in` from now.
    fn bearer(token: &str, expires_in: Duration) -> RegistryResult<Self> {
        Ok(Self::Bearer {
            authorization: Self::authorization_for(&format!("Bearer {token}"))?,
            expires_at: Instant::now() + expires_in,
        })
    }

    /// Parse a credential into an `Authorization` value. Tokens come from the
    /// token server and basic credentials from the config, so bytes a header
    /// cannot carry surface as an auth error instead of a panic.
    fn authorization_for(value: &str) -> RegistryResult<HeaderValue> {
        let mut authorization: HeaderValue = value.parse().map_err(|_| {
            RegistryError::Unauthorized(
                "credentials contain bytes that are invalid in an HTTP header".to_string(),
            )
        })?;
        authorization.set_sensitive(true);
        Ok(authorization)
    }

    /// The `Authorization` header value this credential is sent as.
    fn authorization(&self) -> &HeaderValue {
        match self {
            Self::Basic(authorization) | Self::Bearer { authorization, .. } => authorization,
        }
    }

    /// Whether the credential is still good to send: basic credentials
    /// always, a bearer token until it is within the leeway of expiring.
    fn is_fresh(&self) -> bool {
        match self {
            Self::Basic(_) => true,
            Self::Bearer { expires_at, .. } => Instant::now() + TOKEN_EXPIRY_LEEWAY < *expires_at,
        }
    }
}

/// The body a token server answers with, either field naming the token.
#[derive(Deserialize)]
struct TokenResponse {
    /// The token, as the distribution spec names it.
    #[serde(default)]
    token: String,
    /// The token, as OAuth2 names it.
    #[serde(default)]
    access_token: String,
    /// The token's lifetime in seconds, when the server says.
    expires_in: Option<u64>,
}

impl TokenResponse {
    /// The bearer credential this response carries.
    fn into_credential(self) -> RegistryResult<Credential> {
        let token = if self.token.is_empty() {
            self.access_token
        } else {
            self.token
        };
        if token.is_empty() {
            return Err(RegistryError::UnexpectedResponse(
                "empty token from registry".to_string(),
            ));
        }
        let expires_in = self
            .expires_in
            .map_or(DEFAULT_TOKEN_EXPIRATION, Duration::from_secs);
        Credential::bearer(&token, expires_in)
    }
}

/// The authentication state of one registry: the configured basic
/// credentials and the credential the last challenge produced.
pub(crate) struct Auth {
    /// The configured credentials, `None` for an anonymous registry.
    basic: Option<Credential>,
    /// The credential the last challenge produced, kept until it expires.
    credential: RwLock<Option<Credential>>,
}

impl Auth {
    /// The authentication state of a registry whose config carries `basic`,
    /// its `base64(user:pass)`, validated here so a bad value fails when the
    /// backend is built rather than on the first read.
    pub(crate) fn new(basic: Option<&str>) -> RegistryResult<Self> {
        Ok(Self {
            basic: basic.map(Credential::basic).transpose()?,
            credential: RwLock::new(None),
        })
    }

    /// The `Authorization` to send, `None` until a challenge has been
    /// answered or once the last token is about to expire.
    pub(crate) fn current(&self) -> Option<HeaderValue> {
        self.credential
            .read()
            .unwrap()
            .as_ref()
            .filter(|credential| credential.is_fresh())
            .map(|credential| credential.authorization().clone())
    }

    /// Answer `challenge` with an `Authorization` and keep the credential for
    /// the requests that follow: the configured basic credentials, or a
    /// bearer token fetched from the realm through `http`.
    pub(crate) async fn answer(
        &self,
        http: &Http,
        challenge: Challenge,
    ) -> RegistryResult<HeaderValue> {
        let credential = match challenge {
            Challenge::Basic => self.basic.clone().ok_or_else(|| {
                RegistryError::Unauthorized("registry requires basic-auth credentials".to_string())
            })?,
            Challenge::Bearer {
                realm,
                service,
                scope,
            } => self.fetch_token(http, &realm, &service, &scope).await?,
        };
        let authorization = credential.authorization().clone();
        *self.credential.write().unwrap() = Some(credential);
        Ok(authorization)
    }

    /// Fetch a bearer token from the realm, always straight from the token
    /// server and never through Dragonfly, with the basic credentials when
    /// the config has them.
    async fn fetch_token(
        &self,
        http: &Http,
        realm: &str,
        service: &str,
        scope: &str,
    ) -> RegistryResult<Credential> {
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
            headers.insert(AUTHORIZATION, basic.authorization().clone());
        }

        let response = http
            .request(Method::GET, url.as_str(), headers, ReadKind::OnDemand)
            .await?;
        if !response.status.is_success() {
            return Err(status_error(response).await);
        }

        let body = response.text().await.map_err(RegistryError::Io)?;
        serde_json::from_str::<TokenResponse>(&body)
            .map_err(|err| {
                RegistryError::UnexpectedResponse(format!("invalid token response: {err}"))
            })?
            .into_credential()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::*;
    use nydus_config::HttpConfig;

    #[test]
    fn challenge_parses_the_scheme_and_its_parameters() {
        let test_cases: Vec<(&str, fn(RegistryResult<Challenge>))> = vec![
            (
                r#"Bearer realm="https://auth.example.com/token",service="example.com",scope="repository:library/ubuntu:pull""#,
                |challenge| {
                    assert_eq!(
                        challenge.unwrap(),
                        Challenge::Bearer {
                            realm: "https://auth.example.com/token".to_string(),
                            service: "example.com".to_string(),
                            scope: "repository:library/ubuntu:pull".to_string(),
                        }
                    );
                },
            ),
            (
                r#"Bearer realm="https://auth.example.com/token""#,
                |challenge| {
                    assert_eq!(
                        challenge.unwrap(),
                        Challenge::Bearer {
                            realm: "https://auth.example.com/token".to_string(),
                            service: String::new(),
                            scope: String::new(),
                        }
                    );
                },
            ),
            (r#"Basic realm="registry""#, |challenge| {
                assert_eq!(challenge.unwrap(), Challenge::Basic);
            }),
            ("Basic", |challenge| {
                assert_eq!(challenge.unwrap(), Challenge::Basic);
            }),
            (r#"Bearer service="example.com""#, |challenge| {
                assert!(matches!(challenge, Err(RegistryError::Unauthorized(_))));
            }),
            (r#"Digest realm="registry""#, |challenge| {
                assert!(matches!(challenge, Err(RegistryError::Unauthorized(_))));
            }),
        ];

        for (header, assert_fn) in test_cases {
            assert_fn(header.parse());
        }
    }

    #[test]
    fn credentials_reject_bytes_a_header_cannot_carry() {
        let test_cases = vec![("YWxpY2U6c2VjcmV0", true), ("bad\nvalue", false)];

        for (encoded, ok) in test_cases {
            assert_eq!(Credential::basic(encoded).is_ok(), ok, "{encoded:?}");
            assert_eq!(Auth::new(Some(encoded)).is_ok(), ok, "{encoded:?}");
        }
    }

    #[test]
    fn credentials_are_sensitive_in_logs() {
        let credential = Credential::basic("YWxpY2U6c2VjcmV0").unwrap();
        assert!(credential.authorization().is_sensitive());
        assert_eq!(format!("{credential:?}"), "Basic(Sensitive)");
    }

    #[test]
    fn current_serves_a_credential_until_it_nears_expiry() {
        let test_cases = vec![
            (
                Credential::basic("YWxpY2U6c2VjcmV0").unwrap(),
                Some("Basic YWxpY2U6c2VjcmV0"),
            ),
            (
                Credential::bearer("xyz", Duration::from_secs(3600)).unwrap(),
                Some("Bearer xyz"),
            ),
            (
                Credential::bearer("xyz", TOKEN_EXPIRY_LEEWAY).unwrap(),
                None,
            ),
            (Credential::bearer("xyz", Duration::ZERO).unwrap(), None),
        ];

        for (credential, expected) in test_cases {
            let auth = Auth::new(None).unwrap();
            assert_eq!(auth.current(), None);
            *auth.credential.write().unwrap() = Some(credential.clone());
            assert_eq!(
                auth.current().as_ref().map(|value| value.to_str().unwrap()),
                expected,
                "{credential:?}"
            );
        }
    }

    #[tokio::test]
    async fn answer_uses_the_configured_basic_credentials() {
        let http = Http::builder(&HttpConfig::default()).build().unwrap();
        let test_cases: Vec<(
            Option<&str>,
            fn(RegistryResult<HeaderValue>, Option<HeaderValue>),
        )> = vec![
            (Some("YWxpY2U6c2VjcmV0"), |answer, current| {
                assert_eq!(answer.unwrap(), "Basic YWxpY2U6c2VjcmV0");
                assert_eq!(current.unwrap(), "Basic YWxpY2U6c2VjcmV0");
            }),
            (None, |answer, current| {
                assert!(matches!(answer, Err(RegistryError::Unauthorized(_))));
                assert_eq!(current, None);
            }),
        ];

        for (basic, assert_fn) in test_cases {
            let auth = Auth::new(basic).unwrap();
            let answer = auth.answer(&http, Challenge::Basic).await;
            assert_fn(answer, auth.current());
        }
    }

    #[test]
    fn token_responses_name_the_token_either_way() {
        let test_cases: Vec<(&str, fn(RegistryResult<Credential>))> = vec![
            (r#"{"token":"abc","expires_in":300}"#, |credential| {
                let credential = credential.unwrap();
                assert_eq!(credential.authorization(), "Bearer abc");
                assert!(credential.is_fresh());
            }),
            (r#"{"access_token":"abc"}"#, |credential| {
                let credential = credential.unwrap();
                assert_eq!(credential.authorization(), "Bearer abc");
                assert!(credential.is_fresh());
            }),
            (r#"{"token":"abc","expires_in":1}"#, |credential| {
                assert!(!credential.unwrap().is_fresh());
            }),
            (r#"{"token":"","access_token":""}"#, |credential| {
                assert!(matches!(
                    credential,
                    Err(RegistryError::UnexpectedResponse(_))
                ));
            }),
        ];

        for (body, assert_fn) in test_cases {
            let response: TokenResponse = serde_json::from_str(body).unwrap();
            assert_fn(response.into_credential());
        }
    }
}
