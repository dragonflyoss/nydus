# nydus-storage

Local data plane for [Nydus](https://github.com/dragonflyoss/nydus) images:
sparse blob caches, chunk group-level fill tracking, background prefetch and
on-demand access tracing.

- `cache`: the blob caches, one `BlobCache` per blob behind one
  `BlobCaches` set per image, over the dense decoded block address space.
  `local/` is the sparse cache file in the storage directory shared across
  processes, with its `.group.map` sidecar and `pwritev` gather; `diskless`
  decodes in memory alone without a storage directory; `raw_device` reads a
  native `erofs-*` layer as-is from the backend; `decode` turns a fetched
  window into a verified chunk group.
- `prefetch`: the blob-level prefetch after a mount.
- `access_trace`: the on-demand access trace `nydus optimize` builds an
  ondemand blob from.

Every API here returns `io::Result` so the OS errno survives to the service
edges; this crate does not depend on the control-plane error type. The
on-disk formats and their codec come from `nydus-format`, remote reads
through `nydus-backend`, and the caches and the prefetcher take their
`storage` and `prefetch` sections from `nydus-config`; the assembly that
wires configs, bootstraps and caches together lives above, in `nydus-core`.

## License

Apache-2.0. This crate is part of the
[Nydus](https://github.com/dragonflyoss/nydus) project.
