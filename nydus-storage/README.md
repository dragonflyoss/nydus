# nydus-storage

Local data plane for [Nydus](https://github.com/dragonflyoss/nydus) images:
sparse blob caches, block group-level fill tracking, background prefetch and
on-demand access tracing.

- `cache`: sparse local blob caches over the dense decoded block address
  space.
- `block_group_map`: group-level fill tracking for cached blobs.
- `prefetch`: background prefetch scheduling.
- `access_trace`: on-demand access tracing.

Every API here returns `io::Result` so the OS errno survives to the service
edges; this crate does not depend on the control-plane error type. Remote
reads come through the `nydus-backend` crate; the assembly that wires
configs, bootstraps and caches together lives above, in `nydus-core`.

## License

Apache-2.0. This crate is part of the
[Nydus](https://github.com/dragonflyoss/nydus) project.
