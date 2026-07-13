# nydus-accessor

Runtime accessor APIs for EROFS-based Nydus images.

This crate provides the host-side building blocks used to serve Nydus images
at runtime:

- `metadata`: EROFS on-disk metadata parsing (superblock, inodes, blob
  metadata and footers).
- `storage`: on-demand blob cache, storage backends (`local`, and `registry`
  behind the `backend-registry` feature) and background prefetching.
- `fs`: an EROFS image reader (`ErofsReader`).
- `accessor`: the high-level `NydusAccessor` entry point exposing the device
  table and block-aligned `fetch` APIs for microVM virtio-pmem use cases.

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
