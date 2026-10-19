# nydus-backend

Data-plane blob backends for
[Nydus](https://github.com/dragonflyoss/nydus): local directory and OCI
registry, with optional Dragonfly SDK P2P reads.

Every API here returns `io::Result` so the OS errno survives to the service
edges; this crate does not depend on the control-plane error type.
Backend-private errors (registry auth, Dragonfly classification) are matched
for retry decisions internally and fold into `io::Error` at the trait
boundary.

## Features

| Feature | Description |
| --- | --- |
| `backend-registry` | Container image registry backend (OCI distribution). |
| `backend-dragonfly-proxy` | Dragonfly P2P SDK proxy support for the registry backend. |

All features are disabled by default, keeping the dependency footprint
minimal (local backend only).

## Registry mirrors

The registry backend can read blobs through HTTP(S) mirrors without the
Dragonfly SDK. For example, to use a local Dragonfly registry mirror:

```yaml
backend:
  type: registry
  config:
    addr: https://registry.example.com
    repository: library/example
    mirrors:
      - host: http://127.0.0.1:65001
        headers:
          X-Dragonfly-Registry: https://registry.example.com
```

The mirror must have registry mirror support enabled. Nydus sends blob GET
and HEAD requests directly to its configured address, preserving the path,
query, Range and registry Authorization headers. An HTTP mirror for an HTTPS
registry does not use CONNECT or require TLS interception.

Mirrors are tried in order, then the original registry on transport errors,
authentication failures, unsuccessful HTTP responses or incomplete range
reads. Each attempt must finish the requested read before it succeeds;
partial reads restart the full range at the next source. They share `http.timeout`,
`http.max_retries` and `http.tls`. Do not combine `mirrors` with `http.proxy`
or `dragonfly`; these select different routing mechanisms.

By default, requests without cached credentials go to the original registry
to complete authentication first. Set `auth_through: true` on a mirror to
also send unauthenticated blob requests through it, including for anonymous
registries; a mirror's 401 response then enters the normal auth handshake.
Token endpoint requests always bypass mirrors. Mirror headers cannot
override Host, Authorization, Proxy-Authorization, Range, Content-Length,
Transfer-Encoding or Connection, and are never sent to the origin or to
redirect destinations. Blob redirects retain the existing behavior: follow
the redirect without registry credentials and cache the resolved URL.

## License

Apache-2.0. This crate is part of the
[Nydus](https://github.com/dragonflyoss/nydus) project.
