# nydus-core

The [Nydus](https://github.com/dragonflyoss/nydus) image reader: EROFS
reading and path resolution over the data-plane crates, plus the
`NydusCore`/`Blobs` runtime entry points the services drive.

Every view this crate assembles from the data plane
(`nydus-storage`/`nydus-backend`) exists to let a kernel or FUSE mount the
image:

- the file-tree reader (`reader` + `entry`) behind FUSE and image
  inspection;
- the flattened device views (`NydusCore` / `Blobs`) that NBD / ublk /
  fanotify / userfaultfd hand to the kernel EROFS driver.

For microVM virtio-pmem use cases, `NydusCore` exposes the device table
needed to wire up pmem devices backed by the host-side cache data files, and
a `Blobs::fetch` entry point that guarantees a block-aligned range is decoded
and resident before the guest touches it.

## License

Apache-2.0. This crate is part of the
[Nydus](https://github.com/dragonflyoss/nydus) project.
