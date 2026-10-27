# nydus-backend

Data-plane blob backends for
[Nydus](https://github.com/dragonflyoss/nydus): local directory and OCI
registry, with optional Dragonfly SDK P2P reads.

Every API here returns `io::Result` so the OS errno survives to the service
edges; this crate does not depend on the control-plane error type. Registry
auth and Dragonfly failures are `io::Error`s too; a prefetch read the origin
or Dragonfly answered with a `429`, `5xx` or `408` is sent once more after a
random interval of `prefetch.retry_interval` to twice that, 6 to 12 hours by
default, before it fails.

## Features

| Feature | Description |
| --- | --- |
| `registry` | Container image registry backend (OCI distribution). |
| `dragonfly` | Dragonfly P2P reads for the registry backend. |

All features are disabled by default, keeping the dependency footprint
minimal (local backend only).

## Registry TLS

The registry HTTP client explicitly selects Rustls, as declared by this crate's
features. Another workspace dependency enabling reqwest's `default-tls` must not
silently switch it to native TLS or add native TLS initialization to each image.
Certificate verification remains enabled by default; private CA certificates
are supplied through `tls.ca_cert`.

The HTTPS regression test covers rejection without a trusted CA, acceptance with
the configured CA, and rejection with a different CA. Run it with both TLS
implementations enabled to exercise Cargo feature unification:

```sh
cargo test -p nydus-backend --features registry,reqwest/default-tls --lib
```

## License

Apache-2.0. This crate is part of the
[Nydus](https://github.com/dragonflyoss/nydus) project.
