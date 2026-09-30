# nydus-telemetry

Process-wide telemetry for [Nydus](https://github.com/dragonflyoss/nydus),
following the observability pillars:

- `metrics`: the process-wide Prometheus registry and every metric the daemon
  exports.
- `logging` (feature `logging`): `tracing`-subscriber installation (stdout +
  rolling files + panic hook). Only binaries enable this — libraries emit
  through the `tracing` facade and never install subscribers.

This crate is a dependency leaf: it does not depend on other nydus crates, so
every layer (data plane and control plane alike) can record metrics.

## Features

| Feature | Description |
| --- | --- |
| `logging` | `tracing`-subscriber installation for binaries. |

All features are disabled by default.

## License

Apache-2.0. This crate is part of the
[Nydus](https://github.com/dragonflyoss/nydus) project.
