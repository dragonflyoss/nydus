# nydus-backend

Data-plane blob backends for
[Nydus](https://github.com/dragonflyoss/nydus): local directory and OCI
registry, with optional Dragonfly SDK P2P reads, plus the blob prefetch that
drives them and reschedules the blobs a backend could not serve.

Every API here returns `io::Result` so the OS errno survives to the service
edges; this crate does not depend on the control-plane error type. Registry
auth and Dragonfly failures are `io::Error`s too; a prefetch read the origin
or Dragonfly could not serve is an `io::ErrorKind::QuotaExceeded`, the one
kind the prefetcher acts on.

## Features

| Feature | Description |
| --- | --- |
| `registry` | Container image registry backend (OCI distribution). |
| `dragonfly` | Dragonfly P2P reads for the registry backend. |

All features are disabled by default, keeping the dependency footprint
minimal (local backend only).

## License

Apache-2.0. This crate is part of the
[Nydus](https://github.com/dragonflyoss/nydus) project.
