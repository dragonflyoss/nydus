# nydus-storage

Local data plane for [Nydus](https://github.com/dragonflyoss/nydus) images:
sparse blob caches, chunk group-level fill tracking and on-demand access
recording.

- `lib.rs`: the `BlobCache` trait, one per blob over the dense decoded
  block address space, and the `BlobCaches` set of an image.
- `local/`: the sparse cache file in the storage directory shared across
  processes, with its `.group.map` sidecar (`ChunkGroupMap`), the notifier
  the readers of one in-flight fill wait on (`ChunkGroupNotifier`) and the
  `pwritev` writer of a chunk group (`ChunkGroupWriter`);
  `BlobCaches::prefetch_blob` streams one blob into it,
  deduplicated across processes, while which blobs and when is decided
  above, by `nydus-core`'s prefetcher.
- `diskless`: decodes in memory alone without a storage directory.
- `raw_device`: reads a native `erofs-*` layer as-is from the backend.
- `buffer`, `decoder`: the fetch buffers and the `ChunkGroupDecoder` that
  decodes and verifies a blob's chunk groups, shared by the caches and by
  `nydus optimize`.
- `ondemand_record`: the chunk groups a workload's on-demand reads touched,
  which `nydus optimize` turns into an ondemand blob.

Every API here returns `io::Result` so the OS errno survives to the service
edges; this crate does not depend on the control-plane error type. The
on-disk formats and their codec come from `nydus-format`, remote reads
through `nydus-backend`, the caches and the prefetcher take their `storage`
and `prefetch` sections from `nydus-config` and record into the `Metrics` of
`nydus-telemetry`; the assembly that
wires configs, bootstraps and caches together lives above, in `nydus-core`.

## License

Apache-2.0. This crate is part of the
[Nydus](https://github.com/dragonflyoss/nydus) project.
