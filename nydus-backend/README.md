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

## License

Apache-2.0. This crate is part of the
[Nydus](https://github.com/dragonflyoss/nydus) project.
