//! Registry authentication: the `WWW-Authenticate` challenge and the header
//! that answers it.

use std::io;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_auth::ChallengeParser;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde::Deserialize;
use url::Url;

use super::transport::Fetcher;

/// The margin before expiry within which a token counts as expired.
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
    type Err = io::Error;

    /// Parses the challenges in `value`, preferring `Bearer` over `Basic`.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut has_basic = false;
        for challenge in ChallengeParser::new(value) {
            let challenge = challenge
                .map_err(|err| io::Error::other(format!("invalid auth challenge: {err}")))?;

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
                    return Err(io::Error::other(format!(
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

        Err(io::Error::other(format!(
            "unsupported auth challenge: {value}"
        )))
    }
}

/// The header value that authorizes a request, the configured bearer token
/// or the answer to a challenge, marked sensitive so request logs redact it.
#[derive(Debug, Clone)]
enum Authorization {
    /// The configured basic credentials, which never expire.
    Basic(HeaderValue),

    /// A bearer token, the configured one or one from the token server.
    Bearer {
        /// The `Bearer ...` header value.
        value: HeaderValue,

        /// The instant the token was configured or fetched.
        created_at: Instant,

        /// The lifetime of the token, `None` when it does not expire.
        expires_in: Option<Duration>,
    },
}

/// Implements the authorization header value.
impl Authorization {
    /// Creates the basic authorization for `encoded`, the config's
    /// `base64(user:pass)`, or `InvalidInput` when it is not one.
    fn basic(encoded: &str) -> io::Result<Self> {
        if !STANDARD
            .decode(encoded)
            .is_ok_and(|decoded| decoded.contains(&b':'))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "auth is not base64 of user:pass",
            ));
        }

        Ok(Self::Basic(Self::header_value(&format!(
            "Basic {encoded}"
        ))?))
    }

    /// Creates a bearer authorization for `token` that expires `expires_in`
    /// from now, `None` keeping it until a `401` invalidates it, or
    /// `InvalidInput` when `token` is empty.
    fn bearer(token: &str, expires_in: Option<Duration>) -> io::Result<Self> {
        if token.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "registry bearer token is empty",
            ));
        }

        Ok(Self::Bearer {
            value: Self::header_value(&format!("Bearer {token}"))?,
            created_at: Instant::now(),
            expires_in,
        })
    }

    /// Parses `value` into a sensitive header value, or `InvalidInput` when a
    /// header cannot carry it.
    fn header_value(value: &str) -> io::Result<HeaderValue> {
        let mut value: HeaderValue = value.parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "credentials contain bytes that are invalid in an HTTP header",
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

    /// Returns whether the authorization answers a challenge. A bearer token
    /// given to the daemon does not, and is the only one that never expires.
    fn is_answer(&self) -> bool {
        !matches!(
            self,
            Self::Bearer {
                expires_in: None,
                ..
            }
        )
    }

    /// Returns whether the authorization is still valid, a bearer token until
    /// the leeway before it expires, at most half its lifetime.
    fn is_valid(&self) -> bool {
        match self {
            Self::Basic(_) => true,
            Self::Bearer {
                created_at,
                expires_in,
                ..
            } => expires_in.is_none_or(|expires_in| {
                let leeway = TOKEN_EXPIRY_LEEWAY.min(expires_in / 2);
                created_at.elapsed() + leeway < expires_in
            }),
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
    fn into_authorization(self) -> io::Result<Authorization> {
        let token = if self.token.is_empty() {
            self.access_token
        } else {
            self.token
        };

        if token.is_empty() {
            return Err(io::Error::other(
                "empty token from token server".to_string(),
            ));
        }

        if self.expires_in == Some(0) {
            return Err(io::Error::other(
                "invalid expires_in 0 from token server".to_string(),
            ));
        }

        Authorization::bearer(&token, self.expires_in.map(Duration::from_secs))
    }
}

/// The authentication state of one registry: the basic credentials and the
/// authorization requests are sent with. No error echoes a credential.
///
/// ```text
/// basic          ◀─ new, set_basic
/// authorization  ◀─ new, set_bearer, the answer to a challenge
///
/// request ─▶ authorize: send `authorization` ───────────────────▶ 2xx
///             └─ 401 ─▶ invalidate: forget it
///                     ─▶ authenticate: answer the challenge, keep and send the answer
///                          Basic  ─▶ `basic`
///                          Bearer ─▶ a token fetched with `basic`, until it expires
///
/// set_basic   forgets a kept answer, keeps a bearer token given to the daemon
/// set_bearer  replaces `authorization`, keeps `basic`
/// either, during a handshake ─▶ the challenge is answered again
/// ```
pub(crate) struct Authorizer {
    /// The configured basic credentials, `None` when the config has no `auth`,
    /// replaced by [`Authorizer::set_basic`].
    basic: RwLock<Option<Authorization>>,

    /// The authorization requests are sent with: the configured bearer token
    /// at first, then the answer to the last challenge, kept until it expires,
    /// a `401` invalidates it or [`Authorizer::set_bearer`] replaces it.
    authorization: RwLock<Option<Authorization>>,

    /// The number of times a credential was replaced, bumped under the lock
    /// of `authorization`, so a handshake that began before keeps nothing.
    generation: AtomicU64,

    /// The lock one handshake holds while it answers a challenge, so a burst
    /// of challenged requests fetches one token and the rest reuse it.
    handshake: tokio::sync::Mutex<()>,
}

/// Implements the registry authorizer.
impl Authorizer {
    /// Creates an authorizer with the `base64(user:pass)` credentials `basic`
    /// and the bearer token `bearer`, both validated here. `bearer` is sent
    /// before any challenge, `basic` answers the challenge once a `401`
    /// invalidates it.
    pub(crate) fn new(basic: Option<&str>, bearer: Option<&str>) -> io::Result<Self> {
        Ok(Self {
            basic: RwLock::new(basic.map(Authorization::basic).transpose()?),
            authorization: RwLock::new(
                bearer
                    .map(|token| Authorization::bearer(token, None))
                    .transpose()?,
            ),
            generation: AtomicU64::new(0),
            handshake: tokio::sync::Mutex::new(()),
        })
    }

    /// Replaces the basic credentials with `username` and `password` and
    /// forgets a kept answer, so the next challenge is answered with them.
    ///
    /// A `username` holding a colon is `InvalidInput`: the colon ends the
    /// user name of basic credentials, refer to
    /// <https://www.rfc-editor.org/rfc/rfc7617#section-2>.
    pub(crate) fn set_basic(&self, username: &str, password: &str) -> io::Result<()> {
        if username.contains(':') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "username holds a colon",
            ));
        }

        let basic = Authorization::basic(&STANDARD.encode(format!("{username}:{password}")))?;

        // The same credentials replace nothing, so a push that repeats them
        // costs the daemon no token.
        {
            let mut current = self.basic.write().unwrap();
            if current
                .as_ref()
                .is_some_and(|current| current.value() == basic.value())
            {
                return Ok(());
            }

            *current = Some(basic);
        }

        let mut kept = self.authorization.write().unwrap();
        self.generation.fetch_add(1, Ordering::SeqCst);
        if kept.as_ref().is_some_and(Authorization::is_answer) {
            *kept = None;
        }

        Ok(())
    }

    /// Replaces the kept authorization with the bearer token `token`, sent
    /// with the requests that follow until a `401` invalidates it.
    ///
    /// An empty `token`, or one a header cannot carry, is `InvalidInput`.
    pub(crate) fn set_bearer(&self, token: &str) -> io::Result<()> {
        let bearer = Authorization::bearer(token, None)?;
        let mut kept = self.authorization.write().unwrap();
        self.generation.fetch_add(1, Ordering::SeqCst);
        *kept = Some(bearer);
        Ok(())
    }

    /// Adds the `Authorization` header to `headers` when the configured bearer
    /// token or the answer to a challenge is kept and still valid.
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

    /// Forgets the kept answer when it is still `stale`, the one a request was
    /// refused with.
    pub(crate) fn invalidate(&self, stale: &HeaderValue) {
        let mut authorization = self.authorization.write().unwrap();
        if authorization
            .as_ref()
            .is_some_and(|current| current.value() == stale)
        {
            *authorization = None;
        }
    }

    /// Answers `challenge` with the basic credentials or a bearer token fetched
    /// through `fetcher`, one handshake at a time, and returns the header
    /// value to send.
    ///
    /// A challenge whose answer a replaced credential outdated meanwhile is
    /// answered again, so the request is never sent without one.
    pub(crate) async fn authenticate(
        &self,
        fetcher: &impl Fetcher,
        challenge: Challenge,
    ) -> io::Result<HeaderValue> {
        let _handshake = self.handshake.lock().await;
        loop {
            // Check and load under the lock the setters bump and replace
            // under, so a replacement lands wholly before or after.
            let generation = {
                let kept = self.authorization.read().unwrap();
                if let Some(valid) = kept.as_ref().filter(|kept| kept.is_valid()) {
                    return Ok(valid.value().clone());
                }

                self.generation.load(Ordering::SeqCst)
            };

            let authorization = match &challenge {
                Challenge::Basic => self.basic.read().unwrap().clone().ok_or_else(|| {
                    io::Error::other("registry requires basic-auth credentials".to_string())
                })?,
                Challenge::Bearer {
                    realm,
                    service,
                    scope,
                } => self.fetch_token(fetcher, realm, service, scope).await?,
            };

            let mut kept = self.authorization.write().unwrap();
            if self.generation.load(Ordering::SeqCst) == generation {
                let value = authorization.value().clone();
                *kept = Some(authorization);
                return Ok(value);
            }
        }
    }

    /// Fetches a bearer token from `realm` through `fetcher`, never Dragonfly,
    /// with the basic credentials when configured.
    async fn fetch_token(
        &self,
        fetcher: &impl Fetcher,
        realm: &str,
        service: &str,
        scope: &str,
    ) -> io::Result<Authorization> {
        let mut url = Url::parse(realm)
            .map_err(|err| io::Error::other(format!("invalid realm {realm}: {err}")))?;
        url.query_pairs_mut().extend_pairs(
            [("service", service), ("scope", scope)]
                .into_iter()
                .filter(|(_, value)| !value.is_empty()),
        );

        let mut headers = HeaderMap::new();
        if let Some(basic) = self.basic.read().unwrap().as_ref() {
            headers.insert(AUTHORIZATION, basic.value().clone());
        }

        let response = fetcher.get(&url, headers).await?;
        if !response.status.is_success() {
            return Err(response.into_io_error().await);
        }

        let body = response.text().await?;
        let token: FetchTokenResponse = serde_json::from_str(&body).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid token response: {err}"),
            )
        })?;

        token.into_authorization()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::*;
    use crate::registry::transport::Http;
    use nydus_config::TlsConfig;

    #[test]
    fn from_str_picks_the_challenge_to_answer() {
        let test_cases: Vec<(&str, fn(io::Result<Challenge>))> = vec![
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
                assert!(challenge.is_err());
            }),
            (r#"Bearer realm="unterminated"#, |challenge| {
                assert!(challenge.is_err());
            }),
            (r#"Digest realm="registry""#, |challenge| {
                assert!(challenge.is_err());
            }),
        ];

        for (header, assert_fn) in test_cases {
            assert_fn(header.parse());
        }
    }

    #[test]
    fn new_rejects_credentials_a_header_cannot_carry() {
        let test_cases = vec![
            (Some("YWxpY2U6c2VjcmV0"), None, true),
            (Some("bad\nvalue"), None, false),
            (None, Some("xyz"), true),
            (None, Some("bad\nvalue"), false),
        ];

        for (basic, bearer, ok) in test_cases {
            assert_eq!(Authorizer::new(basic, bearer).is_ok(), ok);
        }
    }

    #[test]
    fn new_rejects_an_empty_bearer_token() {
        let test_cases = vec!["", "   "];

        for bearer in test_cases {
            assert!(Authorizer::new(None, Some(bearer)).is_err());
        }
    }

    #[test]
    fn new_rejects_malformed_credentials() {
        let test_cases = vec![
            (Some("Ym9i"), None),
            (Some("Ym9iOmh1bnRlcjI"), None),
            (Some("bob:hunter2"), None),
            (Some(""), None),
            (None, Some("")),
            (None, Some(" ")),
            (None, Some("a\nb")),
        ];

        for (basic, bearer) in test_cases {
            assert_eq!(
                Authorizer::new(basic, bearer).err().map(|err| err.kind()),
                Some(io::ErrorKind::InvalidInput),
                "{basic:?} {bearer:?}"
            );
        }
    }

    #[test]
    fn new_keeps_rejected_credentials_out_of_the_error() {
        let test_cases = vec![(Some("secret\nvalue"), None), (None, Some("secret\nvalue"))];

        for (basic, bearer) in test_cases {
            let err = Authorizer::new(basic, bearer).err().unwrap();
            assert!(!err.to_string().contains("secret"), "{err}");
        }
    }

    #[test]
    fn new_keeps_the_configured_bearer_token_until_it_is_invalidated() {
        let authorizer = Authorizer::new(Some("YWxpY2U6c2VjcmV0"), Some("xyz")).unwrap();
        let mut headers = HeaderMap::new();
        authorizer.authorize(&mut headers);
        assert_eq!(headers[AUTHORIZATION], "Bearer xyz");
        assert!(headers[AUTHORIZATION].is_sensitive());

        authorizer.invalidate(&HeaderValue::from_static("Bearer xyz"));
        let mut headers = HeaderMap::new();
        authorizer.authorize(&mut headers);
        assert_eq!(headers.get(AUTHORIZATION), None);
    }

    #[test]
    fn basic_marks_the_header_value_sensitive() {
        let authorization = Authorization::basic("YWxpY2U6c2VjcmV0").unwrap();
        assert!(authorization.value().is_sensitive());
        assert_eq!(format!("{authorization:?}"), "Basic(Sensitive)");
    }

    #[test]
    fn authorize_adds_the_header_until_the_token_nears_expiry() {
        let bearer = |expires_in: u64, age: u64| Authorization::Bearer {
            value: HeaderValue::from_static("Bearer xyz"),
            created_at: Instant::now() - Duration::from_secs(age),
            expires_in: Some(Duration::from_secs(expires_in)),
        };
        let test_cases = vec![
            (
                Authorization::basic("YWxpY2U6c2VjcmV0").unwrap(),
                Some("Basic YWxpY2U6c2VjcmV0"),
            ),
            (
                Authorization::bearer("xyz", None).unwrap(),
                Some("Bearer xyz"),
            ),
            (bearer(3600, 0), Some("Bearer xyz")),
            (bearer(40, 19), Some("Bearer xyz")),
            (bearer(40, 21), None),
            (bearer(30, 14), Some("Bearer xyz")),
            (bearer(30, 16), None),
            (bearer(21, 9), Some("Bearer xyz")),
            (bearer(21, 11), None),
            (bearer(20, 9), Some("Bearer xyz")),
            (bearer(20, 11), None),
            (bearer(1, 0), Some("Bearer xyz")),
            (bearer(0, 0), None),
        ];

        for (authorization, expected) in test_cases {
            let authorizer = Authorizer::new(None, None).unwrap();
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
        let http_client = Http::new(
            Duration::from_secs(5),
            Duration::from_secs(5),
            3,
            None,
            &TlsConfig::default(),
            None,
        )
        .unwrap();
        let test_cases: Vec<(
            Option<&str>,
            fn(io::Result<HeaderValue>, Option<HeaderValue>),
        )> = vec![
            (Some("YWxpY2U6c2VjcmV0"), |result, header| {
                assert!(result.is_ok());
                assert_eq!(header.unwrap(), "Basic YWxpY2U6c2VjcmV0");
            }),
            (None, |result, header| {
                assert!(result.is_err());
                assert_eq!(header, None);
            }),
        ];

        for (basic, assert_fn) in test_cases {
            let authorizer = Authorizer::new(basic, None).unwrap();
            let result = authorizer
                .authenticate(&http_client, Challenge::Basic)
                .await;
            let mut headers = HeaderMap::new();
            authorizer.authorize(&mut headers);
            assert_fn(result, headers.get(AUTHORIZATION).cloned());
        }
    }

    #[tokio::test]
    async fn authenticate_fetches_one_token_for_a_burst_of_challenges() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let realm = format!("http://{}/token", listener.local_addr().unwrap());
        let fetches = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let served = fetches.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let served = served.clone();
                std::thread::spawn(move || {
                    use std::io::{Read, Write};
                    let mut request = Vec::new();
                    let mut byte = [0u8; 1];
                    while !request.ends_with(b"\r\n\r\n") {
                        match stream.read(&mut byte) {
                            Ok(1) => request.push(byte[0]),
                            _ => return,
                        }
                    }
                    served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(50));
                    let body = r#"{"token":"abc","expires_in":300}"#;
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                });
            }
        });
        let http_client = Http::new(
            Duration::from_secs(5),
            Duration::from_secs(5),
            3,
            None,
            &TlsConfig::default(),
            None,
        )
        .unwrap();
        let authorizer = Authorizer::new(None, None).unwrap();
        let challenge = || Challenge::Bearer {
            realm: realm.clone(),
            service: String::new(),
            scope: String::new(),
        };

        let (first, second) = tokio::join!(
            authorizer.authenticate(&http_client, challenge()),
            authorizer.authenticate(&http_client, challenge())
        );

        assert!(first.is_ok());
        assert!(second.is_ok());
        assert_eq!(fetches.load(std::sync::atomic::Ordering::SeqCst), 1);
        let mut headers = HeaderMap::new();
        authorizer.authorize(&mut headers);
        assert_eq!(headers[AUTHORIZATION], "Bearer abc");
    }

    #[test]
    fn set_basic_replaces_the_credentials_and_drops_the_kept_answer() {
        let fetched = Some(Duration::from_secs(3600));
        let test_cases = vec![
            (
                ("bob", "hunter2"),
                fetched,
                None,
                None,
                "Basic Ym9iOmh1bnRlcjI=",
            ),
            (("bob", ""), fetched, None, None, "Basic Ym9iOg=="),
            (("bob", "pa:ss"), fetched, None, None, "Basic Ym9iOnBhOnNz"),
            (
                ("alice", "secret"),
                fetched,
                None,
                Some("Bearer xyz"),
                "Basic YWxpY2U6c2VjcmV0",
            ),
            (
                ("bob", "hunter2"),
                None,
                None,
                Some("Bearer xyz"),
                "Basic Ym9iOmh1bnRlcjI=",
            ),
            (
                ("bo:b", "hunter2"),
                fetched,
                Some(io::ErrorKind::InvalidInput),
                Some("Bearer xyz"),
                "Basic YWxpY2U6c2VjcmV0",
            ),
        ];

        for ((username, password), expires_in, err, header, basic) in test_cases {
            let authorizer = Authorizer::new(Some("YWxpY2U6c2VjcmV0"), None).unwrap();
            *authorizer.authorization.write().unwrap() =
                Some(Authorization::bearer("xyz", expires_in).unwrap());

            assert_eq!(
                authorizer
                    .set_basic(username, password)
                    .err()
                    .map(|err| err.kind()),
                err,
                "{username}"
            );
            let mut headers = HeaderMap::new();
            authorizer.authorize(&mut headers);
            assert_eq!(
                headers.get(AUTHORIZATION),
                header.map(HeaderValue::from_static).as_ref(),
                "{username}"
            );
            assert_eq!(
                authorizer.basic.read().unwrap().as_ref().unwrap().value(),
                basic,
                "{username}"
            );
        }
    }

    #[test]
    fn set_bearer_replaces_the_kept_authorization_and_keeps_the_basic_credentials() {
        let invalid = Some(io::ErrorKind::InvalidInput);
        let test_cases = vec![
            ("abc", None, "Bearer abc"),
            ("", invalid, "Bearer xyz"),
            (" ", invalid, "Bearer xyz"),
            ("a\nb", invalid, "Bearer xyz"),
        ];

        for (token, err, header) in test_cases {
            let authorizer = Authorizer::new(Some("YWxpY2U6c2VjcmV0"), None).unwrap();
            *authorizer.authorization.write().unwrap() =
                Some(Authorization::bearer("xyz", Some(Duration::from_secs(3600))).unwrap());

            assert_eq!(
                authorizer.set_bearer(token).err().map(|err| err.kind()),
                err,
                "{token:?}"
            );
            let mut headers = HeaderMap::new();
            authorizer.authorize(&mut headers);
            assert_eq!(headers[AUTHORIZATION], header, "{token:?}");
            assert_eq!(
                authorizer.basic.read().unwrap().as_ref().unwrap().value(),
                "Basic YWxpY2U6c2VjcmV0",
                "{token:?}"
            );
        }
    }

    #[tokio::test]
    async fn authenticate_answers_a_basic_challenge_with_the_replaced_credentials() {
        let http_client = Http::new(
            Duration::from_secs(5),
            Duration::from_secs(5),
            3,
            None,
            &TlsConfig::default(),
            None,
        )
        .unwrap();
        let test_cases = vec![
            (None, "Basic Ym9iOmh1bnRlcjI="),
            (Some("YWxpY2U6c2VjcmV0"), "Basic Ym9iOmh1bnRlcjI="),
        ];

        for (basic, expected) in test_cases {
            let authorizer = Authorizer::new(basic, None).unwrap();
            authorizer.set_basic("bob", "hunter2").unwrap();
            authorizer
                .authenticate(&http_client, Challenge::Basic)
                .await
                .unwrap();
            let mut headers = HeaderMap::new();
            authorizer.authorize(&mut headers);
            assert_eq!(headers[AUTHORIZATION], expected);
        }
    }

    #[tokio::test]
    async fn authenticate_answers_again_when_a_credential_is_replaced_meanwhile() {
        let http_client = Http::new(
            Duration::from_secs(5),
            Duration::from_secs(5),
            3,
            None,
            &TlsConfig::default(),
            None,
        )
        .unwrap();
        let test_cases: Vec<(fn(&Authorizer) -> io::Result<()>, &str, Vec<&str>)> = vec![
            (|_| Ok(()), "Bearer abc", vec!["Basic YWxpY2U6c2VjcmV0"]),
            (
                |authorizer| authorizer.set_basic("bob", "hunter2"),
                "Bearer def",
                vec!["Basic YWxpY2U6c2VjcmV0", "Basic Ym9iOmh1bnRlcjI="],
            ),
            (
                |authorizer| authorizer.set_bearer("given"),
                "Bearer given",
                vec!["Basic YWxpY2U6c2VjcmV0"],
            ),
        ];

        for (replace, expected, fetches) in test_cases {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let realm = format!("http://{}/token", listener.local_addr().unwrap());
            let fetched = std::sync::Arc::new(tokio::sync::Notify::new());
            let (release, released) = std::sync::mpsc::channel::<()>();
            let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let (notify, recorded, count) = (fetched.clone(), requests.clone(), fetches.len());
            std::thread::spawn(move || {
                use std::io::{Read, Write};
                for (i, token) in ["abc", "def"].into_iter().take(count).enumerate() {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut request = Vec::new();
                    let mut byte = [0u8; 1];
                    while !request.ends_with(b"\r\n\r\n") {
                        stream.read_exact(&mut byte).unwrap();
                        request.push(byte[0]);
                    }
                    recorded
                        .lock()
                        .unwrap()
                        .push(String::from_utf8(request).unwrap());
                    if i == 0 {
                        notify.notify_one();
                        released.recv().unwrap();
                    }
                    let body = format!(r#"{{"token":"{token}","expires_in":300}}"#);
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .unwrap();
                }
            });
            let authorizer = Authorizer::new(Some("YWxpY2U6c2VjcmV0"), None).unwrap();
            let challenge = Challenge::Bearer {
                realm,
                service: String::new(),
                scope: String::new(),
            };

            let (sent, ()) =
                tokio::join!(authorizer.authenticate(&http_client, challenge), async {
                    fetched.notified().await;
                    replace(&authorizer).unwrap();
                    release.send(()).unwrap();
                });

            assert_eq!(sent.unwrap(), expected);
            let mut headers = HeaderMap::new();
            authorizer.authorize(&mut headers);
            assert_eq!(headers[AUTHORIZATION], expected);
            let sent_with: Vec<String> = requests
                .lock()
                .unwrap()
                .iter()
                .map(|request| {
                    request
                        .lines()
                        .find_map(|line| {
                            line.split_once(": ")
                                .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                                .map(|(_, value)| value.to_string())
                        })
                        .unwrap()
                })
                .collect();
            assert_eq!(sent_with, fetches, "{expected}");
        }
    }

    #[test]
    fn invalidate_forgets_only_the_answer_a_request_was_refused_with() {
        let authorizer = Authorizer::new(None, None).unwrap();
        *authorizer.authorization.write().unwrap() =
            Some(Authorization::bearer("fresh", Some(Duration::from_secs(3600))).unwrap());

        authorizer.invalidate(&HeaderValue::from_static("Bearer stale"));
        let mut headers = HeaderMap::new();
        authorizer.authorize(&mut headers);
        assert_eq!(headers[AUTHORIZATION], "Bearer fresh");

        authorizer.invalidate(&HeaderValue::from_static("Bearer fresh"));
        let mut headers = HeaderMap::new();
        authorizer.authorize(&mut headers);
        assert_eq!(headers.get(AUTHORIZATION), None);
    }

    #[test]
    fn into_authorization_accepts_either_token_field() {
        let test_cases: Vec<(&str, fn(io::Result<Authorization>))> = vec![
            (r#"{"token":"abc","expires_in":300}"#, |authorization| {
                let authorization = authorization.unwrap();
                assert_eq!(authorization.value(), "Bearer abc");
                assert!(matches!(
                    authorization,
                    Authorization::Bearer { expires_in: Some(expires_in), .. }
                        if expires_in == Duration::from_secs(300)
                ));
            }),
            (r#"{"access_token":"abc"}"#, |authorization| {
                let authorization = authorization.unwrap();
                assert_eq!(authorization.value(), "Bearer abc");
                assert!(matches!(
                    authorization,
                    Authorization::Bearer {
                        expires_in: None,
                        ..
                    }
                ));
            }),
            (r#"{"token":"abc","expires_in":1}"#, |authorization| {
                assert!(authorization.unwrap().is_valid());
            }),
            (r#"{"token":"abc","expires_in":0}"#, |authorization| {
                assert!(authorization.is_err());
            }),
            (r#"{"token":"","access_token":""}"#, |authorization| {
                assert!(authorization.is_err());
            }),
        ];

        for (body, assert_fn) in test_cases {
            let response: FetchTokenResponse = serde_json::from_str(body).unwrap();
            assert_fn(response.into_authorization());
        }
    }
}
