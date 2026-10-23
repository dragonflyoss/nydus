# nydus-telemetry

Telemetry for [Nydus](https://github.com/dragonflyoss/nydus), following the
observability pillars:

- `metrics`: the Prometheus metrics of an image, `Metrics`, one instance per
  opened image.
- `logging` (feature `logging`): `tracing`-subscriber installation (stdout +
  rolling files + panic hook). Only binaries enable this — libraries emit
  through the `tracing` facade and never install subscribers.

This crate depends on no nydus crate but `nydus-config`, for the metric
namespace, so every layer (data plane and control plane alike) can record
metrics. It re-exports `prometheus`, so a crate that registers a collector
of its own or encodes a registry reaches it through this one.

## Features

| Feature | Description |
| --- | --- |
| `logging` | `tracing`-subscriber installation for binaries. |

All features are disabled by default.

## License

Apache-2.0. This crate is part of the
[Nydus](https://github.com/dragonflyoss/nydus) project.
