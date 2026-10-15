//! Registry authentication: the `WWW-Authenticate` challenge and the header that answers it.

use std::str::FromStr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use http_auth::ChallengeParser;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::Method;
use serde::Deserialize;
use url::Url;

use super::http::Http;
use super::response::status_error;
use super::{RegistryError, RegistryResult};
use crate::ReadKind;

/// The lifetime of a bearer token when the token server does not say.
const DEFAULT_TOKEN_EXPIRATION: Duration = Duration::from_secs(10 * 60);

/// The margin before its expiry within which a token counts as expired, so a
/// request in flight never arrives with one that has just lapsed.
const TOKEN_EXPIRY_LEEWAY: Duration = Duration::from_secs(20);

/// The challenge a registry sends in `WWW-Authenticate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Challenge {
    /// A `Basic realm="..."` challenge, answered with the configured credentials.
    Basic,

    /// A `Bearer realm="...",service="...",scope="..."` challenge, answered
    /// with a token fetched from `realm`.
    Bearer {
        /// The token server URL.
        realm: String,

        /// The service the token is for, empty when the registry names none.
        service: String,

        /// The access the token grants, empty when the registry names none.
        scope: String,
    },
}

/// Implements parsing from a `WWW-Authenticate` value.
impl FromStr for Challenge {
    type Err = RegistryError;

    /// Parses the challenge list in `value` and picks the one to answer: a
    /// `Bearer` when there is one, since a token server also serves anonymous
    /// pulls, otherwise a `Basic`.
    ///
    /// Rejects a malformed list, one with neither scheme, and a `Bearer`
    /// without a realm.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut has_basic = false;
        for challenge in ChallengeParser::new(value) {
            let challenge = challenge.map_err(|err| {
                RegistryError::Unauthorized(format!("invalid auth challenge: {err}"))
            })?;

            // Answer a bearer challenge as soon as one appears.
            if challenge.scheme.eq_ignore_ascii_case("Bearer") {
                let mut realm = None;
                let mut service = String::new();
                let mut scope = String::new();
                for (key, param) in &challenge.params {
                    if key.eq_ignore_ascii_case("realm") {
                        realm = Some(param.to_unescaped());
                    } else if key.eq_ignore_ascii_case("service") {
                        service = param.to_unescaped();
                    } else if key.eq_ignore_ascii_case("scope") {
                        scope = param.to_unescaped();
                    }
                }

                let Some(realm) = realm else {
                    return Err(RegistryError::Unauthorized(format!(
                        "bearer challenge without realm: {value}"
                    )));
                };

                return Ok(Self::Bearer {
                    realm,
                    service,
                    scope,
                });
            }

            if challenge.scheme.eq_ignore_ascii_case("Basic") {
                has_basic = true;
            }
        }

        // Fall back to a basic challenge when the list carried one.
        if has_basic {
            return Ok(Self::Basic);
        }

        Err(RegistryError::Unauthorized(format!(
            "unsupported auth challenge: {value}"
        )))
    }
}

/// The header value that answers a challenge, marked sensitive so request
/// logs redact it.
#[derive(Debug, Clone)]
enum Authorization {
    /// The configured basic credentials, which never expire.
    Basic(HeaderValue),

    /// A bearer token from the token server, when it was fetched and how long
    /// it lives.
    Bearer {
        /// The `Bearer ...` header value.
        value: HeaderValue,

        /// The instant the token was fetched.
        created_at: Instant,

        /// The lifetime the token server gave the token.
        expires_in: Duration,
    },
}

/// Implements the authorization header value.
impl Authorization {
    /// Creates the basic authorization for `encoded`, the config's
    /// `base64(user:pass)`.
    fn basic(encoded: &str) -> RegistryResult<Self> {
        Ok(Self::Basic(Self::header_value(&format!(
            "Basic {encoded}"
        ))?))
    }

    /// Creates a bearer authorization for `token` that expires `expires_in`
    /// from now.
    fn bearer(token: &str, expires_in: Duration) -> RegistryResult<Self> {
        Ok(Self::Bearer {
            value: Self::header_value(&format!("Bearer {token}"))?,
            created_at: Instant::now(),
            expires_in,
        })
    }

    /// Parses `value` into a sensitive header value.
    ///
    /// Tokens come from the token server and basic credentials from the
    /// config, so bytes a header cannot carry surface as an auth error
    /// instead of a panic.
    fn header_value(value: &str) -> RegistryResult<HeaderValue> {
        let mut value: HeaderValue = value.parse().map_err(|_| {
            RegistryError::Unauthorized(
                "credentials contain bytes that are invalid in an HTTP header".to_string(),
            )
        })?;

        value.set_sensitive(true);
        Ok(value)
    }

    /// Returns the header value to send.
    fn value(&self) -> &HeaderValue {
        match self {
            Self::Basic(value) | Self::Bearer { value, .. } => value,
        }
    }

    /// Returns whether the authorization is still good to send: basic
    /// credentials always, a bearer token until it is within the leeway of
    /// expiring.
    fn is_valid(&self) -> bool {
        match self {
            Self::Basic(_) => true,
            Self::Bearer {
                created_at,
                expires_in,
                ..
            } => created_at.elapsed() + TOKEN_EXPIRY_LEEWAY < *expires_in,
        }
    }
}

/// The body a token server answers [`Authorizer::fetch_token`] with, either
/// field naming the token.
#[derive(Deserialize)]
struct FetchTokenResponse {
    /// The token, as the distribution spec names it.
    #[serde(default)]
    token: String,

    /// The token, as OAuth2 names it.
    #[serde(default)]
    access_token: String,

    /// The token's lifetime in seconds, when the server says.
    expires_in: Option<u64>,
}

/// Implements the token fetch response.
impl FetchTokenResponse {
    /// Converts the response into the bearer [Authorization] it carries.
    fn into_authorization(self) -> RegistryResult<Authorization> {
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

        Authorization::bearer(
            &token,
            self.expires_in
                .map_or(DEFAULT_TOKEN_EXPIRATION, Duration::from_secs),
        )
    }
}

/// The authentication state of one registry: the configured basic
/// credentials and the answer to the last challenge.
pub(crate) struct Authorizer {
    /// The configured credentials, `None` for an anonymous registry.
    basic: Option<Authorization>,

    /// The answer to the last challenge, kept until it expires.
    authorization: RwLock<Option<Authorization>>,
}

/// Implements the registry authorizer.
impl Authorizer {
    /// Creates an authorizer for a registry whose config carries `basic`, its
    /// `base64(user:pass)`.
    ///
    /// The credentials are validated here so a bad value fails when the
    /// backend is built rather than on the first read.
    pub(crate) fn new(basic: Option<&str>) -> RegistryResult<Self> {
        Ok(Self {
            basic: basic.map(Authorization::basic).transpose()?,
            authorization: RwLock::new(None),
        })
    }

    /// Adds the `Authorization` header to `headers` when a challenge has been
    /// answered and the answer has not expired.
    pub(crate) fn authorize(&self, headers: &mut HeaderMap) {
        if let Some(value) = self
            .authorization
            .read()
            .unwrap()
            .as_ref()
            .filter(|authorization| authorization.is_valid())
            .map(|authorization| authorization.value().clone())
        {
            headers.insert(AUTHORIZATION, value);
        }
    }

    /// Answers `challenge` and keeps the answer for the requests that follow:
    /// the configured basic credentials, or a bearer token fetched from the
    /// realm through `http`.
    pub(crate) async fn authenticate(
        &self,
        http: &Http,
        challenge: Challenge,
    ) -> RegistryResult<()> {
        let authorization = match challenge {
            Challenge::Basic => self.basic.clone().ok_or_else(|| {
                RegistryError::Unauthorized("registry requires basic-auth credentials".to_string())
            })?,
            Challenge::Bearer {
                realm,
                service,
                scope,
            } => self.fetch_token(http, &realm, &service, &scope).await?,
        };

        *self.authorization.write().unwrap() = Some(authorization);
        Ok(())
    }

    /// Fetches a bearer token from the realm, with the basic credentials when
    /// the config has them.
    ///
    /// The request goes straight to the token server through `http`, never
    /// through Dragonfly.
    async fn fetch_token(
        &self,
        http: &Http,
        realm: &str,
        service: &str,
        scope: &str,
    ) -> RegistryResult<Authorization> {
        // Build the token URL from the realm and the challenge's parameters.
        let mut url = Url::parse(realm)
            .map_err(|err| RegistryError::InvalidUrl(format!("{realm}: {err}")))?;
        url.query_pairs_mut().extend_pairs(
            [("service", service), ("scope", scope)]
                .into_iter()
                .filter(|(_, value)| !value.is_empty()),
        );

        // Present the configured credentials to the token server.
        let mut headers = HeaderMap::new();
        if let Some(basic) = &self.basic {
            headers.insert(AUTHORIZATION, basic.value().clone());
        }

        // Request the token from the realm.
        let response = http
            .request(Method::GET, url.as_str(), headers, ReadKind::OnDemand)
            .await?;
        if !response.status.is_success() {
            return Err(status_error(response).await);
        }

        // Parse the token out of the body.
        let body = response.text().await.map_err(RegistryError::Io)?;
        let token: FetchTokenResponse = serde_json::from_str(&body).map_err(|err| {
            RegistryError::UnexpectedResponse(format!("invalid token response: {err}"))
        })?;

        token.into_authorization()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::*;
    use nydus_config::HttpConfig;

    #[test]
    fn from_str_picks_the_challenge_to_answer() {
        let test_cases: Vec<(&str, fn(RegistryResult<Challenge>))> = vec![
            (
                r#"Bearer realm="https://auth.example.com/token",service="example.com",scope="repository:library/ubuntu:pull,push""#,
                |challenge| {
                    assert_eq!(
                        challenge.unwrap(),
                        Challenge::Bearer {
                            realm: "https://auth.example.com/token".to_string(),
                            service: "example.com".to_string(),
                            scope: "repository:library/ubuntu:pull,push".to_string(),
                        }
                    );
                },
            ),
            (
                r#"bearer realm="https://auth.example.com/token""#,
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
            (
                r#"Basic realm="registry", Bearer realm="https://auth.example.com/token""#,
                |challenge| {
                    assert!(matches!(challenge.unwrap(), Challenge::Bearer { .. }));
                },
            ),
            (r#"Basic realm="registry""#, |challenge| {
                assert_eq!(challenge.unwrap(), Challenge::Basic);
            }),
            ("Basic", |challenge| {
                assert_eq!(challenge.unwrap(), Challenge::Basic);
            }),
            (
                r#"Digest realm="registry", Basic realm="registry""#,
                |challenge| {
                    assert_eq!(challenge.unwrap(), Challenge::Basic);
                },
            ),
            (r#"Bearer service="example.com""#, |challenge| {
                assert!(matches!(challenge, Err(RegistryError::Unauthorized(_))));
            }),
            (r#"Bearer realm="unterminated"#, |challenge| {
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
    fn new_rejects_credentials_a_header_cannot_carry() {
        let test_cases = vec![("YWxpY2U6c2VjcmV0", true), ("bad\nvalue", false)];

        for (basic, ok) in test_cases {
            assert_eq!(Authorizer::new(Some(basic)).is_ok(), ok);
        }
    }

    #[test]
    fn basic_marks_the_header_value_sensitive() {
        let authorization = Authorization::basic("YWxpY2U6c2VjcmV0").unwrap();
        assert!(authorization.value().is_sensitive());
        assert_eq!(format!("{authorization:?}"), "Basic(Sensitive)");
    }

    #[test]
    fn authorize_adds_the_header_until_the_token_nears_expiry() {
        let test_cases = vec![
            (
                Authorization::basic("YWxpY2U6c2VjcmV0").unwrap(),
                Some("Basic YWxpY2U6c2VjcmV0"),
            ),
            (
                Authorization::bearer("xyz", Duration::from_secs(3600)).unwrap(),
                Some("Bearer xyz"),
            ),
            (
                Authorization::bearer("xyz", TOKEN_EXPIRY_LEEWAY).unwrap(),
                None,
            ),
            (Authorization::bearer("xyz", Duration::ZERO).unwrap(), None),
        ];

        for (authorization, expected) in test_cases {
            let authorizer = Authorizer::new(None).unwrap();
            let mut headers = HeaderMap::new();
            authorizer.authorize(&mut headers);
            assert_eq!(headers.get(AUTHORIZATION), None);

            *authorizer.authorization.write().unwrap() = Some(authorization);
            authorizer.authorize(&mut headers);
            assert_eq!(
                headers.get(AUTHORIZATION),
                expected.map(HeaderValue::from_static).as_ref()
            );
        }
    }

    #[tokio::test]
    async fn authenticate_answers_a_basic_challenge_from_the_config() {
        let http = Http::builder(&HttpConfig::default()).build().unwrap();
        let test_cases: Vec<(Option<&str>, fn(RegistryResult<()>, Option<HeaderValue>))> = vec![
            (Some("YWxpY2U6c2VjcmV0"), |result, header| {
                assert!(result.is_ok());
                assert_eq!(header.unwrap(), "Basic YWxpY2U6c2VjcmV0");
            }),
            (None, |result, header| {
                assert!(matches!(result, Err(RegistryError::Unauthorized(_))));
                assert_eq!(header, None);
            }),
        ];

        for (basic, assert_fn) in test_cases {
            let authorizer = Authorizer::new(basic).unwrap();
            let result = authorizer.authenticate(&http, Challenge::Basic).await;
            let mut headers = HeaderMap::new();
            authorizer.authorize(&mut headers);
            assert_fn(result, headers.get(AUTHORIZATION).cloned());
        }
    }

    #[test]
    fn into_authorization_accepts_either_token_field() {
        let test_cases: Vec<(&str, fn(RegistryResult<Authorization>))> = vec![
            (r#"{"token":"abc","expires_in":300}"#, |authorization| {
                let authorization = authorization.unwrap();
                assert_eq!(authorization.value(), "Bearer abc");
                assert!(authorization.is_valid());
            }),
            (r#"{"access_token":"abc"}"#, |authorization| {
                let authorization = authorization.unwrap();
                assert_eq!(authorization.value(), "Bearer abc");
                assert!(authorization.is_valid());
            }),
            (r#"{"token":"abc","expires_in":1}"#, |authorization| {
                assert!(!authorization.unwrap().is_valid());
            }),
            (r#"{"token":"","access_token":""}"#, |authorization| {
                assert!(matches!(
                    authorization,
                    Err(RegistryError::UnexpectedResponse(_))
                ));
            }),
        ];

        for (body, assert_fn) in test_cases {
            let response: FetchTokenResponse = serde_json::from_str(body).unwrap();
            assert_fn(response.into_authorization());
        }
    }
}
