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
and resident before the guest touches it.

For a flattened-device fault handler, `fetch_flat_ranges(offset, len)` returns
only the requested bytes. `fetch_flat_group_ranges(offset, len)` also returns
the rest of each chunk group touched by that request, so the caller can batch
mappings of data that the fetch already made ready. It uses the opened blobs'
in-memory metadata, leaves unrelated blobs unopened, and preserves on-demand
access tracing. Groups warmed only by read-ahead or prefetch are excluded.
Bootstrap, gaps, and raw devices keep exact-range behavior.

Group boundaries need not be host-page aligned. Fetch the full faulting host
page, then clip returned extents to the mapping window and complete host pages
with aligned backing offsets. Pages spanning different backing files need a
copy fallback. Never round an extent outward into cold bytes.

The low-level `build` modules are shared with the `nydus` crate so the regular
builder and incremental writer use the same chunk encoding, inode layout and
bootstrap rendering implementation. Applications should use
`NydusCore::writer` or `IncrementalWriter` instead of those helpers directly.

## License

Apache-2.0. This crate is part of the
[Nydus](https://github.com/dragonflyoss/nydus) project.
