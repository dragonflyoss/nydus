# nydus-telemetry

Telemetry for [Nydus](https://github.com/dragonflyoss/nydus), following the
observability pillars:

- `metrics`: independent Prometheus registries for opened images, plus a
  process-wide compatibility registry for legacy constructors.
- `logging` (feature `logging`): `tracing`-subscriber installation (stdout +
  rolling files + panic hook). Only binaries enable this — libraries emit
  through the `tracing` facade and never install subscribers.

This crate is a dependency leaf: it does not depend on other nydus crates, so
every layer (data plane and control plane alike) can record metrics.

`NydusCore::metrics()` returns the registry for one image. The free
`metrics::snapshot()` and `metrics::encode_text()` functions expose only the
compatibility registry; they do not aggregate the registries of all opened
images.

## Features

| Feature | Description |
| --- | --- |
| `logging` | `tracing`-subscriber installation for binaries. |

All features are disabled by default.

## License

Apache-2.0. This crate is part of the
[Nydus](https://github.com/dragonflyoss/nydus) project.
