# nydus-backend

Data-plane blob backends for
[Nydus](https://github.com/dragonflyoss/nydus): local directory and OCI
registry, with optional Dragonfly SDK P2P reads.

Every API here returns `io::Result` so the OS errno survives to the service
edges; this crate does not depend on the control-plane error type. Registry
auth and Dragonfly failures are `io::Error`s too; a prefetch read the origin
or Dragonfly could not serve is sent once more after a random delay of hours
before it fails.

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
