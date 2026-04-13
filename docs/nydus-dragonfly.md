# Dragonfly P2P Proxy Integration

This document describes the design and implementation of nydus's integration
with [Dragonfly](https://d7y.io/) for P2P-accelerated container image
distribution.

## Overview

Nydus supports routing storage backend requests through Dragonfly's dfdaemon
to enable peer-to-peer data distribution. This reduces bandwidth pressure on
source registries and improves pull performance in large-scale deployments.

Two proxy modes are supported:

- **HTTP proxy mode** -- Requests are routed through dfdaemon's HTTP proxy
  endpoint. dfdaemon transparently intercepts the request and serves data from
  P2P peers when available, falling back to the source registry otherwise.

- **SDK proxy mode** -- Requests are made directly through the Dragonfly client
  SDK (`dragonfly-client-util`), which communicates with a Dragonfly scheduler
  for P2P task coordination. This provides tighter integration with Dragonfly's
  scheduling and priority system.

Both modes support configurable fallback to direct registry access.

## Architecture

```
                BlobReader (registry, oss, s3, http-proxy)
                      |
                      | try_read_ctx(buf, offset, context)
                      v
                retry_op() -- proxy-aware retry orchestration
                      |
           +----------+----------+
           |          |          |
      HTTP Direct  HTTP Proxy  Dragonfly SDK
           |          |          |
      Registry    dfdaemon    Scheduler
                      |          |
                      +----+-----+
                           |
                     P2P Peer Network
```

### Component Roles

- **`request.rs`** -- Unified request dispatcher. Routes each call to one of
  three paths (HTTP direct, HTTP proxy, SDK) based on configuration and runtime
  context. Produces a `Response` enum that abstracts over `reqwest::Response`
  and Dragonfly's `GetResponse`.

- **`proxy.rs`** -- Dragonfly SDK client wrapper. Manages a static registry of
  `ProxySDKClient` instances keyed by scheduler endpoint. Maps Dragonfly error
  types to typed `ProxyError` variants.

- **`mod.rs` / `retry_op()`** -- Retry orchestration with proxy-aware fallback
  logic. Classifies errors by source (proxy vs registry) and applies different
  retry strategies accordingly.

- **`connection.rs`** -- HTTP connection management with proxy health checking.
  Handles scheme replacement (HTTPS to HTTP) and background health monitoring
  via ping URL.

## Configuration

Proxy behavior is configured through the `ProxyConfig` struct in the backend
configuration JSON:

```json
{
  "device": {
    "backend": {
      "type": "registry",
      "config": {
        "host": "ghcr.io",
        "repo": "example/image",
        "proxy": {
          "url": "http://127.0.0.1:4001",
          "ping_url": "http://127.0.0.1:4001",
          "fallback": true,
          "check_interval": 5,
          "use_http": false,
          "check_pause_elapsed": 300,
          "dragonfly_scheduler_endpoint": "http://127.0.0.1:8002"
        }
      }
    }
  }
}
```

### Configuration Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | `""` | dfdaemon proxy URL. Empty disables proxy. |
| `ping_url` | string | `""` | Health check endpoint. |
| `fallback` | bool | `true` | Fall back to direct access on proxy failure. |
| `check_interval` | u64 | `5` | Health check interval in seconds. |
| `use_http` | bool | `false` | Replace HTTPS with HTTP for proxy requests. |
| `check_pause_elapsed` | u64 | `300` | Pause health checks after this many seconds of inactivity. |
| `dragonfly_scheduler_endpoint` | string | `""` | Dragonfly scheduler URL. Non-empty enables SDK mode. |

### Mode Selection

The proxy mode is determined by configuration:

- **No proxy**: `url` is empty -- all requests go directly to the source.
- **HTTP proxy mode**: `url` is set, `dragonfly_scheduler_endpoint` is empty.
- **SDK proxy mode**: Both `url` and `dragonfly_scheduler_endpoint` are set.
  SDK is the primary path; HTTP proxy is the fallback when SDK encounters
  internal errors.

Dynamic configuration hot-reload is supported. Changes to
`dragonfly_scheduler_endpoint` take effect on the next request via
`nydus_utils::config::get_changed()`.

## Request Routing

`Request::call()` implements the routing decision:

```
call(method, url, query, data, headers, catch_status, context, temp_disable_proxy)
  |
  |-- Is proxy disabled (temp_disable_proxy, context.disable_proxy, or empty url)?
  |     YES --> HTTP Direct (Connection::call without proxy)
  |
  |-- Is SDK endpoint configured and not disabled?
  |     YES --> Is this a GET request?
  |               YES --> Dragonfly SDK path
  |               NO  --> Error ("only GET method is supported with Dragonfly SDK proxy")
  |
  |-- HTTP Proxy path (with Dragonfly headers injected)
```

Note: Non-GET requests with SDK configured return an error rather than falling
through to the HTTP proxy. This error is treated as a generic failure by
`retry_op()`, which will exhaust its retry budget before the last-retry
fallback sends the request directly to the registry.

### Dragonfly Request Headers

When routing through the HTTP proxy path, nydus injects Dragonfly-specific
headers to control P2P behavior:

| Header | Values | Purpose |
|--------|--------|---------|
| `X-Dragonfly-Priority` | `3` (prefetch), `6` (on-demand) | Scheduling priority. Higher = more urgent. |
| `X-Dragonfly-Use-P2P` | `"true"` | Enable P2P distribution for this request. |
| `X-Dragonfly-Prefetch` | `"true"` / `"false"` | Controls whether P2P prefetch is enabled for this backend. Static per-configuration, not per-request. |

The SDK path does not use these headers. Instead, priority is passed as a
function parameter to the SDK client's `request()` method.

Additional headers defined but used by Dragonfly internally:

| Header | Purpose |
|--------|---------|
| `X-Dragonfly-Output-Path` | Local output path hint. |
| `X-Dragonfly-Piece-Length` | Piece length for chunked transfer. |
| `X-Dragonfly-Force-Hard-Link` | Force hard-link for cached data. |
| `X-Dragonfly-Content-For-Calculating-Task-ID` | Content hash for task deduplication. |

### Request Priority

Nydus maps its internal `RequestSource` to Dragonfly priority levels:

- **Prefetch** (background reads for startup optimization): priority 3 (lower
  urgency). Dragonfly can schedule these with more aggressive P2P, tolerating
  higher latency.
- **On-demand** (user-triggered reads): priority 6 (higher urgency). Dragonfly
  prioritizes speed and cache locality.

### Response Abstraction

The `Response` enum unifies HTTP and SDK responses:

```rust
pub enum Response {
    HTTP(reqwest::blocking::Response),
    ProxySDK(GetResponse),
}
```

Methods on `Response`:

- `status()` -- Returns HTTP status code. SDK responses use
  `status_code.unwrap_or(502 Bad Gateway)`.
- `headers()` -- Returns response headers. SDK responses return an empty map
  if no headers are present.
- `reader()` -- Returns `Box<dyn Read + Send>`. SDK async readers are wrapped
  with `SyncAdapter` that blocks on the proxy runtime.
- `text()` -- Reads entire body as string.
- `copy_to(buf)` -- Copies body into a buffer.

## Error Handling

### Non-Standard Error Signaling

Dragonfly uses non-standard error signaling that requires special handling in
the retry layer. The same logical errors (rate limiting, forbidden, internal)
arrive through different mechanisms depending on the proxy mode.

**HTTP proxy path**: dfdaemon returns standard HTTP status codes (429, 403, 5xx)
but marks them with an `X-Dragonfly-Error-Type: proxy` response header to
distinguish proxy-originated errors from errors forwarded from the upstream
registry. Without this header, a 429 from the proxy would be indistinguishable
from a 429 from the registry, leading to incorrect retry behavior.

`request.rs` inspects this header after every HTTP proxy response and converts
matching responses into typed errors:

```
Response with X-Dragonfly-Error-Type: proxy
  +-- 429 --> RequestError::Proxy(ProxyError::TooManyRequests)
  +-- 403 --> RequestError::Proxy(ProxyError::Forbidden)
  +-- other -> RequestError::Common (logged, not retried as proxy error)
```

**SDK path**: The Dragonfly client SDK returns its own error types that do not
use HTTP semantics. `proxy.rs` maps these to the same `ProxyError` variants:

```
dragonfly_client_util::Error
  +-- ProxyError { status_code: 429 } --> ProxyError::TooManyRequests
  +-- ProxyError { status_code: 403 } --> ProxyError::Forbidden
  +-- DfdaemonError                   --> ProxyError::Common
  +-- RequestTimeout                  --> ProxyError::Common
  +-- InvalidArgument                 --> ProxyError::Common
  +-- Internal                        --> ProxyError::Internal
  +-- BackendError (catch_status=true)  --> ProxyError::Common
  +-- BackendError (catch_status=false) --> Response with error status code
```

### ProxyError Variants

```rust
pub enum ProxyError {
    Common(String),          // Generic proxy/network errors
    Internal(String),        // SDK internal errors (triggers SDK -> HTTP fallback)
    TooManyRequests(String), // Rate limiting (429)
    Forbidden(String),       // Access denied (403)
}
```

### Error Classification in retry_op()

`BackendError` provides three classification methods that `retry_op()` uses to
determine the retry strategy:

- `is_proxy_forbidden()` -- Detects `ProxyError::Forbidden`. The proxy has
  denied the request (e.g., authentication failure, access policy). Retrying
  will not help.

- `is_proxy_limited()` -- Detects `ProxyError::TooManyRequests`. The proxy is
  rate-limiting requests. The correct response depends on request source: for
  on-demand reads, bypass the proxy and go direct with QPS limiting; for
  prefetch reads, give up immediately to avoid adding load.

- `is_proxy_sdk_internal()` -- Detects `ProxyError::Internal`. The SDK itself
  has failed (not the upstream). Disable the SDK and fall back to the HTTP proxy
  path for subsequent retries.

## Retry Strategy

`retry_op()` orchestrates retries with proxy-aware fallback. The retry budget
and behavior differ based on the request source:

| | On-Demand | Prefetch |
|---|-----------|----------|
| Retry budget | 3 retries | 1 retry |
| After SDK non-internal error | Budget reduced to 1 | Budget reduced to 0 (no retry) |
| On 403 (forbidden) | Immediate return, no retry | Immediate return, no retry |
| On 429 (rate limit) | Disable proxy, apply QPS limiter, retry direct | Immediate return, no retry |
| On SDK internal | Disable SDK, retry via HTTP proxy | Disable SDK, retry via HTTP proxy |
| Last retry | Disable proxy, apply QPS limiter | Random sleep 100ms-1s between attempts |

**SDK retry budget reduction**: When the SDK path fails with a non-internal
error (e.g., upstream 500 relayed through the SDK), the retry budget is
reduced. The SDK client is configured with `max_retries(0)` (retries disabled
at the SDK level), so nydus manages all retry logic. The budget reduction
prevents excessive retries through an expensive SDK call path. For on-demand
requests, the budget drops to at most 1 remaining retry. For prefetch
requests, the budget drops to 0 (immediate failure).

### Retry Flow

```
retry_op(metrics, context, data_len, op)
  |
  for each attempt:
  |
  |-- metrics.begin()
  |
  |-- Execute op(context)
  |     |
  |     +-- Success: clear error, metrics.end(ok), return Ok
  |     |
  |     +-- Error: metrics.end(err)
  |           |
  |           +-- 403 Forbidden? --> break (no retry, return error)
  |           |
  |           +-- 429 Rate Limited?
  |           |     +-- Prefetch:  break (no retry)
  |           |     +-- OnDemand:  disable_proxy=true, acquire QPS token
  |           |
  |           +-- SDK Internal?
  |           |     +-- disable_proxy_sdk=true (next attempt uses HTTP proxy)
  |           |
  |           +-- SDK non-internal error?
  |           |     +-- Prefetch:  retry_count=0 (no more retries)
  |           |     +-- OnDemand:  retry_count=min(retry_count, 1)
  |           |
  |           +-- Last attempt + OnDemand?
  |           |     +-- disable_proxy=true, acquire QPS token
  |           |
  |           +-- (else) Prefetch? sleep random 100ms-1s
  |           |
  |           +-- Continue loop
  |
  return last error
```

Note: The "last attempt + OnDemand" and "prefetch sleep" branches are mutually
exclusive. Prefetch requests on their last retry only sleep -- they never enter
the proxy-disable + QPS acquire path because that branch requires `!is_prefetch`.

### QPS Limiting on Fallback

When the proxy is bypassed (due to rate limiting or final retry), `retry_op()`
acquires a token from the global `BACKEND_QPS_LIMITER` (default: 1 QPS) before
issuing the direct request. This prevents a thundering herd against the source
registry when the proxy is under pressure.

The `BACKEND_QPS_LIMITER` is a token-bucket rate limiter with capacity equal to
the configured QPS. It refills at the configured rate and blocks callers when
empty via a condvar.

## Proxy Health Checking

The HTTP proxy path includes background health monitoring:

1. A background thread periodically GETs `ping_url` at `check_interval`.
2. If the proxy is unhealthy and `fallback=true`, requests go directly to
   the source.
3. If the proxy is unhealthy and `fallback=false`, requests fail with an error.
4. Health checks are paused after `check_pause_elapsed` seconds of inactivity
   to avoid unnecessary network traffic.

### Per-Request Fallback

Independently of the health check thread, `Connection::call()` also performs
per-request fallback when `fallback=true`: if a proxy request returns a 5xx
status code or a connection error, the request is silently retried against the
origin server. This means `retry_op()` never sees proxy 5xx errors when
fallback is enabled -- they are masked by the connection layer.

When `fallback=false`, proxy 5xx responses and connection errors are returned
as-is, allowing `retry_op()` to handle them.

The SDK path does not use health checking -- errors are detected per-request
and trigger fallback to the HTTP proxy path.

## Feature Flags

| Feature | Deps | Purpose |
|---------|------|---------|
| `backend-dragonfly-proxy` | `dragonfly-client-util` | Dragonfly SDK integration. x86_64/aarch64 only (ring crate limitation). |
| `backend-hickory-dns` | `hickory-resolver`, `once_cell`, `reqwest` | DNS resolution with caching and singleflight deduplication. |
| `backend-qps-limit` | `rand` | QPS rate limiter for source fallback protection. |

When `backend-dragonfly-proxy` is not enabled, all SDK-related code paths are
compiled out. The HTTP proxy path and retry logic remain functional without it.

## SDK Runtime

The Dragonfly SDK uses async APIs. Since nydus storage backends are synchronous,
a dedicated tokio runtime bridges the gap:

- A 10-thread multi-threaded runtime (`nydus-backend-proxy-runtime`) is created
  once per process.
- `ProxySDKClient::request()` blocks on this runtime to execute async SDK calls.
- `SyncAdapter<R>` wraps async readers as sync `Read` implementors using
  `runtime.block_on()` for each read call.
- SDK clients are cached per scheduler endpoint in a static
  `RwLock<HashMap<String, Arc<ProxySDKClient>>>`.

## Example Configurations

### HTTP Proxy with Fallback

Routes through dfdaemon's HTTP proxy. Falls back to direct registry access if
the proxy is unhealthy.

```json
{
  "proxy": {
    "url": "http://127.0.0.1:4001",
    "ping_url": "http://127.0.0.1:4001",
    "fallback": true,
    "check_interval": 5,
    "use_http": false
  }
}
```

### HTTP Proxy Strict (No Fallback)

Proxy must be available. Requests fail if the proxy is unhealthy.

```json
{
  "proxy": {
    "url": "http://127.0.0.1:4001",
    "ping_url": "http://127.0.0.1:4001",
    "fallback": false,
    "check_interval": 5,
    "use_http": false
  }
}
```

### SDK Proxy with Fallback

Uses Dragonfly SDK for P2P scheduling. Falls back to HTTP proxy on SDK errors,
then to direct access if the proxy is also unhealthy.

```json
{
  "proxy": {
    "url": "http://127.0.0.1:4001",
    "ping_url": "http://127.0.0.1:4001",
    "fallback": true,
    "check_interval": 5,
    "use_http": false,
    "dragonfly_scheduler_endpoint": "http://127.0.0.1:8002"
  }
}
```

### SDK Proxy Strict (No Fallback)

SDK and proxy must be available. No fallback to direct registry access.

```json
{
  "proxy": {
    "url": "http://127.0.0.1:4001",
    "ping_url": "http://127.0.0.1:4001",
    "fallback": false,
    "check_interval": 5,
    "use_http": false,
    "dragonfly_scheduler_endpoint": "http://127.0.0.1:8002"
  }
}
```

## Dragonfly Deployment

A typical Dragonfly deployment alongside nydus consists of:

- **Manager** -- Orchestrates the Dragonfly cluster. Backed by MySQL and Redis.
- **Scheduler** -- Coordinates P2P task distribution. Connects to the manager
  for cluster state.
- **dfdaemon** (seed peer) -- Local proxy that serves data from P2P peers or
  the source registry. Exposes HTTP proxy (port 4001) and gRPC upload (port
  4000) endpoints.

See `misc/dragonfly/` for example configuration files for each component.
