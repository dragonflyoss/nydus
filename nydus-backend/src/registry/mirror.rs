//! Registry mirror URL rewriting and validated, mirror-only headers.

use std::io;

use nydus_config::MirrorConfig;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use url::Url;

pub(super) struct Mirror {
    host: Url,
    pub headers: HeaderMap,
    pub auth_through: bool,
}

impl Mirror {
    pub fn new(config: &MirrorConfig) -> io::Result<Self> {
        let invalid = |message| io::Error::new(io::ErrorKind::InvalidInput, message);
        let host = Url::parse(&config.host).map_err(|_| invalid("invalid mirror URL"))?;
        if !matches!(host.scheme(), "http" | "https")
            || host.host_str().is_none()
            || !host.username().is_empty()
            || host.password().is_some()
            || host.path() != "/"
            || host.query().is_some()
            || host.fragment().is_some()
        {
            return Err(invalid(
                "mirror host must be an HTTP(S) origin without credentials, path, query or fragment",
            ));
        }
        let mut headers = HeaderMap::new();
        for (name, value) in &config.headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| invalid("invalid mirror header name"))?;
            if matches!(
                name.as_str(),
                "host"
                    | "authorization"
                    | "proxy-authorization"
                    | "range"
                    | "content-length"
                    | "transfer-encoding"
                    | "connection"
            ) {
                return Err(invalid("mirror headers cannot override routing, authentication, range or framing headers"));
            }
            let value =
                HeaderValue::from_str(value).map_err(|_| invalid("invalid mirror header value"))?;
            headers.insert(name, value);
        }
        Ok(Self {
            host,
            headers,
            auth_through: config.auth_through,
        })
    }

    pub fn url(&self, origin: &str) -> io::Result<Url> {
        let invalid = |_| io::Error::new(io::ErrorKind::InvalidInput, "invalid mirror request URL");
        let mut url = Url::parse(origin).map_err(io::Error::other)?;
        url.set_scheme(self.host.scheme()).map_err(invalid)?;
        url.set_host(self.host.host_str())
            .map_err(io::Error::other)?;
        url.set_port(self.host.port()).map_err(invalid)?;
        Ok(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Registry;
    use crate::{BlobBackend, ReadContext, ReadKind};
    use nydus_config::RegistryConfig;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    struct Server {
        url: String,
        requests: Arc<Mutex<Vec<String>>>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl Server {
        fn new(handler: impl Fn(&str, &str) -> String + Send + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let (captured, stopped, base) = (requests.clone(), stop.clone(), url.clone());
            let thread = thread::spawn(move || {
                while !stopped.load(Ordering::Relaxed) {
                    let (mut stream, _) = match listener.accept() {
                        Ok(connection) => connection,
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                            continue;
                        }
                        Err(err) => panic!("accept: {err}"),
                    };
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut byte = [0];
                    while !request.ends_with(b"\r\n\r\n") {
                        if stream.read(&mut byte).unwrap_or(0) == 0 {
                            break;
                        }
                        request.push(byte[0]);
                    }
                    let request = String::from_utf8(request).unwrap();
                    captured.lock().unwrap().push(request.clone());
                    let _ = stream.write_all(handler(&request, &base).as_bytes());
                }
            });
            Self {
                url,
                requests,
                stop,
                thread: Some(thread),
            }
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            self.thread.take().unwrap().join().unwrap();
        }
    }

    fn response(status: &str, headers: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn registry(origin: &str, mirrors: &[(&str, bool)]) -> Registry {
        let config = serde_json::json!({
            "addr": origin,
            "repository": "library/test",
            "auth": "dXNlcjpwYXNz",
            "http": {"timeout": "2s", "max_retries": 0},
            "mirrors": mirrors.iter().map(|(host, auth_through)| serde_json::json!({
                "host": host,
                "auth_through": auth_through,
                "headers": {"X-Dragonfly-Registry": origin},
            })).collect::<Vec<_>>(),
        });
        Registry::new(serde_json::from_value(config).unwrap()).unwrap()
    }

    fn read(registry: &Registry) {
        let mut bytes = [0; 4];
        registry
            .read_range_into(
                &[0; 32],
                7,
                &mut bytes,
                ReadContext::raw(ReadKind::OnDemand),
            )
            .unwrap();
        assert_eq!(&bytes, b"data");
    }

    #[test]
    fn https_origin_uses_plain_http_mirror_with_range_and_auth() {
        let mirror = Server::new(|_, _| response("206 Partial Content", "", "data"));
        // An unreachable HTTPS origin makes an accidental direct request or
        // CONNECT fail, without requiring a real registry or TLS certificates.
        let registry = registry("https://registry.invalid", &[(&mirror.url, false)]);
        registry.set_auth("Bearer cached-token".into());
        read(&registry);
        let requests = mirror.requests();
        assert_eq!(requests.len(), 1);
        let request = requests[0].to_ascii_lowercase();
        assert!(request.starts_with("get /v2/library/test/blobs/sha256:"));
        assert!(request.contains("\r\nrange: bytes=7-10\r\n"));
        assert!(request.contains("\r\nauthorization: bearer cached-token\r\n"));
        assert!(request.contains("\r\nx-dragonfly-registry: https://registry.invalid\r\n"));
        assert!(!request.contains("connect "));
    }

    #[test]
    fn authentication_uses_origin_then_mirror_and_reuses_token() {
        for (auth_through, stale_token) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let origin = Server::new(|request, base| {
                if request.starts_with("GET /token?") {
                    assert!(request.contains("authorization: Basic dXNlcjpwYXNz\r\n"));
                    response("200 OK", "", r#"{"token":"fresh-token","expires_in":3600}"#)
                } else if request.contains("authorization: Bearer fresh-token\r\n") {
                    response("206 Partial Content", "", "data")
                } else {
                    response(
                        "401 Unauthorized",
                        &format!(
                            "WWW-Authenticate: Bearer realm=\"{base}/token\",service=\"test\"\r\n"
                        ),
                        "",
                    )
                }
            });
            let origin_url = origin.url.clone();
            let mirror = Server::new(move |request, _| {
                if request.contains("authorization: Bearer fresh-token\r\n") {
                    response("206 Partial Content", "", "data")
                } else {
                    response("401 Unauthorized", &format!("WWW-Authenticate: Bearer realm=\"{origin_url}/token\",service=\"test\"\r\n"), "")
                }
            });
            let registry = registry(&origin.url, &[(&mirror.url, auth_through)]);
            if stale_token {
                registry.set_auth("Bearer stale-token".into());
            }
            read(&registry);
            read(&registry);
            let origin_requests = origin.requests();
            assert_eq!(
                origin_requests.len(),
                if auth_through {
                    1
                } else if stale_token {
                    4
                } else {
                    2
                }
            );
            assert_eq!(
                mirror.requests().len(),
                if auth_through {
                    3 + usize::from(stale_token)
                } else {
                    2
                }
            );
            assert!(origin_requests
                .iter()
                .all(|r| !r.to_ascii_lowercase().contains("x-dragonfly-registry")));
        }
    }

    #[test]
    fn mirror_failures_try_next_mirror_then_origin_without_mirror_headers() {
        for status in [
            "401 Unauthorized",
            "403 Forbidden",
            "404 Not Found",
            "429 Too Many Requests",
            "503 Service Unavailable",
        ] {
            let failed = Server::new(move |_, _| response(status, "", ""));
            let next = Server::new(|_, _| response("206 Partial Content", "", "data"));
            let origin = Server::new(|_, _| response("206 Partial Content", "", "data"));
            let registry = registry(&origin.url, &[(&failed.url, false), (&next.url, false)]);
            registry.set_auth("Bearer cached-token".into());
            read(&registry);
            assert_eq!(failed.requests().len(), 1);
            assert_eq!(next.requests().len(), 1);
            assert!(origin.requests().is_empty());

            let registry = self::registry(&origin.url, &[(&failed.url, false)]);
            registry.set_auth("Bearer cached-token".into());
            read(&registry);
            let requests = origin.requests();
            assert_eq!(requests.len(), 1);
            assert!(!requests[0]
                .to_ascii_lowercase()
                .contains("x-dragonfly-registry"));
            assert!(requests[0].contains("authorization: Bearer cached-token\r\n"));
            assert!(requests[0].contains("range: bytes=7-10\r\n"));
        }
    }

    #[test]
    fn connection_failure_falls_back_to_origin() {
        let unused = TcpListener::bind("127.0.0.1:0").unwrap();
        let mirror = format!("http://{}", unused.local_addr().unwrap());
        drop(unused);
        let origin = Server::new(|_, _| response("206 Partial Content", "", "data"));
        read(&registry(&origin.url, &[(&mirror, true)]));
        assert_eq!(origin.requests().len(), 1);
    }

    #[test]
    fn incomplete_body_restarts_the_full_range_at_the_next_source() {
        for declared_length in [2, 4] {
            for next_is_mirror in [false, true] {
                let broken = Server::new(move |_, _| {
                    format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Length: {declared_length}\r\nConnection: close\r\n\r\nxx"
                )
                });
                let healthy = Server::new(|_, _| response("206 Partial Content", "", "data"));
                let mirrors = if next_is_mirror {
                    vec![(broken.url.as_str(), true), (healthy.url.as_str(), true)]
                } else {
                    vec![(broken.url.as_str(), true)]
                };
                let registry = registry(&healthy.url, &mirrors);
                registry.set_auth("Bearer cached-token".into());
                read(&registry);
                assert_eq!(broken.requests().len(), 1);
                let requests = healthy.requests();
                assert_eq!(requests.len(), 1);
                assert!(requests[0].contains("range: bytes=7-10\r\n"));
                assert!(requests[0].contains("authorization: Bearer cached-token\r\n"));
                assert_eq!(
                    requests[0].contains("x-dragonfly-registry:"),
                    next_is_mirror
                );
            }
        }
    }

    #[test]
    fn authentication_failure_is_bounded_and_tries_the_next_source() {
        for failure in [
            "persistent-401",
            "no-challenge",
            "no-credentials",
            "token-error",
            "invalid-token",
        ] {
            for next_is_mirror in [false, true] {
                let token = Server::new(move |_, _| {
                    if failure == "token-error" {
                        response("503 Service Unavailable", "", "")
                    } else {
                        response("200 OK", "", "not-json")
                    }
                });
                let token_url = token.url.clone();
                let denied = Server::new(move |_, _| {
                    let challenge = match failure {
                        "no-challenge" => String::new(),
                        "token-error" | "invalid-token" => {
                            format!("WWW-Authenticate: Bearer realm=\"{token_url}/token\"\r\n")
                        }
                        _ => "WWW-Authenticate: Basic realm=\"registry\"\r\n".into(),
                    };
                    response("401 Unauthorized", &challenge, "")
                });
                let healthy = Server::new(|_, _| response("206 Partial Content", "", "data"));
                let mirrors = if next_is_mirror {
                    vec![(denied.url.as_str(), true), (healthy.url.as_str(), true)]
                } else {
                    vec![(denied.url.as_str(), true)]
                };
                let mut registry = registry(&healthy.url, &mirrors);
                if failure == "no-credentials" {
                    registry.basic_auth = None;
                }
                read(&registry);
                assert_eq!(
                    denied.requests().len(),
                    if failure == "persistent-401" { 2 } else { 1 }
                );
                assert_eq!(healthy.requests().len(), 1);
                assert_eq!(
                    token.requests().len(),
                    usize::from(matches!(failure, "token-error" | "invalid-token"))
                );
                assert!(registry.current_auth().is_empty());
                assert!(registry.token_expires_at.load().is_none());
            }
        }
    }

    #[test]
    fn failed_authenticated_body_does_not_publish_token_or_expiry() {
        let token = Server::new(|_, _| {
            response("200 OK", "", r#"{"token":"mirror-token","expires_in":600}"#)
        });
        let token_url = token.url.clone();
        let broken = Server::new(move |request, _| {
            if request.contains("authorization: Bearer mirror-token\r\n") {
                response("206 Partial Content", "", "xx")
            } else {
                response(
                    "401 Unauthorized",
                    &format!("WWW-Authenticate: Bearer realm=\"{token_url}/token\"\r\n"),
                    "",
                )
            }
        });
        let origin = Server::new(|_, _| response("206 Partial Content", "", "data"));
        let registry = registry(&origin.url, &[(&broken.url, true)]);
        registry.set_auth("Bearer origin-token".into());
        let expiry = crate::registry::now_secs() + 3600;
        registry.token_expires_at.store(Some(Arc::new(expiry)));
        read(&registry);
        assert_eq!(registry.current_auth(), "Bearer origin-token");
        assert_eq!(**registry.token_expires_at.load().as_ref().unwrap(), expiry);
        assert_eq!(broken.requests().len(), 3);
        assert_eq!(token.requests().len(), 1);
        let requests = origin.requests();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains("authorization: Bearer origin-token\r\n"));
        assert!(!requests[0].contains("x-dragonfly-registry:"));
    }

    #[test]
    fn all_sources_failing_returns_an_error_without_restarting_the_list() {
        let denied = Server::new(|_, _| {
            response(
                "401 Unauthorized",
                "WWW-Authenticate: Basic realm=\"registry\"\r\n",
                "",
            )
        });
        let broken = Server::new(|_, _| response("206 Partial Content", "", "xx"));
        let origin = Server::new(|_, _| response("404 Not Found", "", "missing"));
        let registry = registry(&origin.url, &[(&denied.url, true), (&broken.url, true)]);
        let err = registry
            .read_range_into(
                &[0; 32],
                7,
                &mut [0; 4],
                ReadContext::raw(ReadKind::OnDemand),
            )
            .unwrap_err();
        assert!(err.to_string().contains("404"));
        assert_eq!(denied.requests().len(), 2);
        assert_eq!(broken.requests().len(), 1);
        assert_eq!(origin.requests().len(), 1);
    }

    #[test]
    fn failed_redirect_body_is_not_cached_and_falls_back() {
        let destination = Server::new(|_, _| response("206 Partial Content", "", "xx"));
        let location = format!("Location: {}/signed-blob\r\n", destination.url);
        let mirror = Server::new(move |_, _| response("307 Temporary Redirect", &location, ""));
        let origin = Server::new(|_, _| response("206 Partial Content", "", "data"));
        let registry = registry(&origin.url, &[(&mirror.url, true)]);
        read(&registry);
        read(&registry);
        assert_eq!(mirror.requests().len(), 2);
        assert_eq!(destination.requests().len(), 2);
        assert_eq!(origin.requests().len(), 2);
        assert!(registry.redirect_url(&"00".repeat(32)).is_none());
    }

    #[test]
    fn redirect_and_cached_redirect_do_not_receive_mirror_headers_or_auth() {
        let destination = Server::new(|_, _| response("206 Partial Content", "", "data"));
        let location = format!(
            "Location: {}/signed-blob?signature=test\r\n",
            destination.url
        );
        let mirror = Server::new(move |_, _| response("307 Temporary Redirect", &location, ""));
        let registry = registry("https://registry.invalid", &[(&mirror.url, false)]);
        registry.set_auth("Bearer cached-token".into());
        read(&registry);
        read(&registry);
        assert_eq!(mirror.requests().len(), 1);
        let requests = destination.requests();
        assert_eq!(requests.len(), 2);
        for request in requests {
            let request = request.to_ascii_lowercase();
            assert!(request.starts_with("get /signed-blob?signature=test "));
            assert!(request.contains("range: bytes=7-10\r\n"));
            assert!(!request.contains("authorization:"));
            assert!(!request.contains("x-dragonfly-registry:"));
        }
    }

    #[test]
    fn head_uses_mirror_for_blob_size() {
        let mirror = Server::new(|_, _| response("200 OK", "", "data"));
        let registry = registry("https://registry.invalid", &[(&mirror.url, true)]);
        assert_eq!(registry.fetch_blob_size(&[0; 32]).unwrap(), 4);
        assert!(mirror.requests()[0].starts_with("HEAD /v2/"));
    }

    #[test]
    fn head_without_a_valid_size_falls_back() {
        let mirror = Server::new(|_, _| "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".into());
        let origin = Server::new(|_, _| response("200 OK", "", "data"));
        let registry = registry(&origin.url, &[(&mirror.url, true)]);
        assert_eq!(registry.fetch_blob_size(&[0; 32]).unwrap(), 4);
        assert_eq!(mirror.requests().len(), 1);
        assert_eq!(origin.requests().len(), 1);
    }

    #[test]
    fn validates_mirror_configuration_before_requests() {
        for host in [
            "ftp://example.com",
            "http://user:password@example.com",
            "http://example.com/v2",
            "http://example.com/?query",
            "http://example.com/#fragment",
        ] {
            let config: MirrorConfig =
                serde_json::from_value(serde_json::json!({"host": host})).unwrap();
            assert!(Mirror::new(&config).is_err(), "{host}");
        }
        for (name, value) in [
            ("Authorization", "token"),
            ("Range", "bytes=0-1"),
            ("Host", "other"),
            ("Content-Length", "10"),
            ("invalid name", "value"),
            ("X-Test", "bad\r\nvalue"),
        ] {
            let config: MirrorConfig = serde_json::from_value(
                serde_json::json!({"host": "http://localhost:65001", "headers": {name: value}}),
            )
            .unwrap();
            assert!(Mirror::new(&config).is_err(), "{name}");
        }
        for extra in [
            serde_json::json!({"http": {"proxy": {"addr": "http://localhost:65001"}}}),
            serde_json::json!({"dragonfly": {"scheduler_endpoint": "http://localhost:8002"}}),
        ] {
            let mut config = serde_json::json!({"addr": "https://registry.invalid", "repository": "test", "mirrors": [{"host": "http://localhost:65001"}]});
            config
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let config: RegistryConfig = serde_json::from_value(config).unwrap();
            let err = Registry::new(config).err().unwrap();
            assert!(err.to_string().contains("cannot be combined"));
        }
    }

    #[test]
    fn rewriting_preserves_encoded_path_and_query() {
        let config: MirrorConfig =
            serde_json::from_value(serde_json::json!({"host": "http://[::1]:65001"})).unwrap();
        let mirror = Mirror::new(&config).unwrap();
        assert_eq!(
            mirror
                .url("https://registry.example:8443/v2/a%2Fb/blobs/sha256:123?ns=test")
                .unwrap()
                .as_str(),
            "http://[::1]:65001/v2/a%2Fb/blobs/sha256:123?ns=test"
        );
    }
}
