# nydus-core

The [Nydus](https://github.com/dragonflyoss/nydus) image core: EROFS reading,
path resolution and incremental image writing over the data-plane crates,
plus the `NydusCore`/`Blobs` runtime entry points the services drive.

Every view this crate assembles from the data plane
(`nydus-storage`/`nydus-backend`) exists to let a kernel or FUSE mount the
image:

- the file-tree reader (`reader` + `entry`) behind FUSE and image
  inspection;
- the flattened device views (`NydusCore` / `Blobs`) that NBD / ublk /
  fanotify / userfaultfd hand to the kernel EROFS driver;
- the incremental writer (`NydusCore::writer`) that stages full-file and
  byte-range updates over a parent image and commits a merged bootstrap plus
  an upper data blob.

For microVM virtio-pmem use cases, `NydusCore` exposes the device table
needed to wire up pmem devices backed by the host-side cache data files, and
a `Blobs::fetch` entry point that guarantees a block-aligned range is decoded
and resident before the guest touches it. A core reaches a registry from the
network namespace it is given (`NydusCore::new(bootstrap, config, netns)`)
and records into `Metrics` and an `OndemandRecord` of its own (`core.metrics()`,
`core.ondemand_record()`), so one process can serve several sandboxes without
mixing their namespaces, counters or ondemand records; an embedder gathers the values
from `core.metrics().registry()`.

The low-level `build` modules are shared with the `nydus` crate so the regular
builder and incremental writer use the same chunk encoding, inode layout and
bootstrap rendering implementation. Applications should use
`NydusCore::writer` or `IncrementalWriter` instead of those helpers directly.

## License

Apache-2.0. This crate is part of the
[Nydus](https://github.com/dragonflyoss/nydus) project.
