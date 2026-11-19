//! The reqwest middleware of the HTTP client: the rate limit, the circuit
//! breaker and the query redaction.

use std::io;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use http::Extensions;
use leaky_bucket::RateLimiter;
use reqwest::Request;
use reqwest_middleware::{Middleware, Next};

/// A fair leaky bucket of one slot per attempt, inside the retry middleware.
pub(crate) struct RateLimit {
    /// The request rate limiter.
    limiter: RateLimiter,
}

/// Implements the rate limit.
impl RateLimit {
    /// Creates a limit of `request_rate_limit` requests per `interval`, both
    /// at least one.
    pub(crate) fn new(request_rate_limit: u64, interval: Duration) -> Self {
        Self {
            limiter: RateLimiter::builder()
                .initial(request_rate_limit as usize)
                .refill(request_rate_limit as usize)
                .max(request_rate_limit as usize)
                .interval(interval)
                .fair(true)
                .build(),
        }
    }
}

/// Implements the rate limit as a reqwest middleware.
#[async_trait]
impl Middleware for RateLimit {
    /// Claims a slot, then runs the request.
    async fn handle(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        self.limiter.acquire_one().await;
        next.run(req, extensions).await
    }
}

/// The states of a circuit breaker.
enum CircuitBreakerState {
    /// The requests go through.
    Closed,

    /// The requests are rejected until the instant.
    Open(Instant),

    /// One request went through on trial, the others are rejected until the
    /// instant.
    HalfOpen(Instant),
}

/// The circuit breaker of a proxy, inside the retry middleware. A request that
/// fails to connect opens it, and the requests are then rejected, with no
/// retry, until one goes through on trial after the open wait.
///
/// ```text
/// Closed ───▶ request ──▶ connects ─────────────────────▶ Closed
///               └─ fails to connect ────────────────────▶ Open
/// Open ─────▶ request ──▶ rejected until the open wait passed
///               └─ after it, on trial ──────────────────▶ HalfOpen
/// HalfOpen ─▶ the trial ──▶ connects ───────────────────▶ Closed
///               │           └─ fails to connect ────────▶ Open
///               └─ the other requests ──▶ rejected
/// ```
pub(crate) struct CircuitBreaker {
    /// The address of the proxy.
    addr: String,

    /// The state of the breaker.
    state: Mutex<CircuitBreakerState>,
}

/// Implements the circuit breaker.
impl CircuitBreaker {
    /// The default wait in the open state before a request goes through on
    /// trial.
    const DEFAULT_OPEN_WAIT: Duration = Duration::from_secs(5);

    /// Creates a closed breaker of the proxy at `addr`.
    pub(crate) fn new(addr: &str) -> Self {
        Self {
            addr: addr.to_string(),
            state: Mutex::new(CircuitBreakerState::Closed),
        }
    }

    /// Returns whether a request is permitted, letting one through on trial
    /// once the open wait has passed.
    fn is_call_permitted(&self) -> bool {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();
        match *state {
            CircuitBreakerState::Closed => true,
            CircuitBreakerState::Open(until) | CircuitBreakerState::HalfOpen(until)
                if now < until =>
            {
                false
            }
            CircuitBreakerState::Open(_) | CircuitBreakerState::HalfOpen(_) => {
                *state = CircuitBreakerState::HalfOpen(now + Self::DEFAULT_OPEN_WAIT);
                true
            }
        }
    }

    /// Closes the breaker after the request on trial connected.
    fn on_success(&self) {
        let mut state = self.state.lock().unwrap();
        if let CircuitBreakerState::HalfOpen(_) = *state {
            *state = CircuitBreakerState::Closed;
        }
    }

    /// Opens the breaker after a request failed to connect.
    fn on_error(&self) {
        let mut state = self.state.lock().unwrap();
        if let CircuitBreakerState::Closed | CircuitBreakerState::HalfOpen(_) = *state {
            *state = CircuitBreakerState::Open(Instant::now() + Self::DEFAULT_OPEN_WAIT);
        }
    }
}

/// Implements the circuit breaker as a reqwest middleware.
#[async_trait]
impl Middleware for CircuitBreaker {
    /// Runs the request when the breaker permits it.
    async fn handle(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        if !self.is_call_permitted() {
            return Err(reqwest_middleware::Error::middleware(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("circuit breaker of proxy {} is open", self.addr),
            )));
        }

        // Hand a connection failure back as a middleware error, which the
        // retry middleware does not send again.
        match next.run(req, extensions).await {
            Err(reqwest_middleware::Error::Reqwest(err)) if err.is_connect() => {
                self.on_error();
                Err(reqwest_middleware::Error::middleware(io::Error::new(
                    io::ErrorKind::NotConnected,
                    format!("failed to connect to proxy {}: {err}", self.addr),
                )))
            }
            result => {
                self.on_success();
                result
            }
        }
    }
}

/// The redaction of the query, which signs a redirect URL, from the error of
/// a failed request, inside every other middleware.
pub(crate) struct RedactQuery;

/// Implements the query redaction as a reqwest middleware.
#[async_trait]
impl Middleware for RedactQuery {
    /// Runs the request, dropping the query from the URL its error names.
    async fn handle(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        next.run(req, extensions).await.map_err(|mut err| {
            if let Some(url) = err.url_mut() {
                url.set_query(None);
            }

            err
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Client;
    use reqwest_middleware::ClientBuilder;
    use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};
    use std::net::TcpListener;
    use std::sync::Arc;

    #[cfg(feature = "dragonfly")]
    #[test]
    fn new_fills_a_fair_bucket_to_the_limit() {
        let limit = RateLimit::new(10, Duration::from_millis(100));
        assert_eq!(limit.limiter.max(), 10);
        assert_eq!(limit.limiter.refill(), 10);
        assert_eq!(limit.limiter.balance(), 10);
        assert_eq!(limit.limiter.interval(), Duration::from_millis(100));
        assert!(limit.limiter.is_fair());
    }

    #[tokio::test]
    async fn circuit_breaker_rejects_requests_until_the_one_on_trial_connects() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let url = format!("http://{addr}/");
        let circuit_breaker = Arc::new(CircuitBreaker::new(&url));
        let client = ClientBuilder::new(Client::new())
            .with(RetryTransientMiddleware::new_with_policy(
                ExponentialBackoff::builder().build_with_max_retries(3),
            ))
            .with_arc(circuit_breaker.clone())
            .build();
        let rejected = format!("circuit breaker of proxy {url} is open");

        let err = client.get(&url).send().await.unwrap_err();
        assert!(err
            .to_string()
            .starts_with(&format!("failed to connect to proxy {url}: ")));
        let err = client.get(&url).send().await.unwrap_err();
        assert_eq!(err.to_string(), rejected);

        let listener = TcpListener::bind(addr).unwrap();
        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let mut requests = 0;
            for stream in listener.incoming().take(2) {
                let mut stream = stream.unwrap();
                let mut buf = [0u8; 1024];
                while !buf.windows(4).any(|window| window == b"\r\n\r\n") {
                    if stream.read(&mut buf).unwrap() == 0 {
                        break;
                    }
                }
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .unwrap();
                requests += 1;
            }
            requests
        });

        let err = client.get(&url).send().await.unwrap_err();
        assert_eq!(err.to_string(), rejected);

        *circuit_breaker.state.lock().unwrap() = CircuitBreakerState::Open(Instant::now());
        assert!(client.get(&url).send().await.unwrap().status().is_success());
        assert!(client.get(&url).send().await.unwrap().status().is_success());
        assert_eq!(server.join().unwrap(), 2);
    }

    #[tokio::test]
    async fn redact_query_drops_the_query_from_the_url_an_error_names() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/blob", listener.local_addr().unwrap());
        drop(listener);
        let test_cases = vec![(0, false), (1, false), (0, true)];

        for (max_retries, proxied) in test_cases {
            let mut client =
                ClientBuilder::new(Client::new()).with(RetryTransientMiddleware::new_with_policy(
                    ExponentialBackoff::builder()
                        .retry_bounds(Duration::from_millis(1), Duration::from_millis(1))
                        .build_with_max_retries(max_retries),
                ));
            if proxied {
                client = client.with(CircuitBreaker::new(&url));
            }
            let client = client.with(RedactQuery).build();

            let err = client
                .get(format!("{url}?sig=secret"))
                .send()
                .await
                .unwrap_err();
            let chain = format!("{err:?}");
            assert!(chain.contains(&url));
            assert!(!chain.contains("secret"));
        }
    }
}
