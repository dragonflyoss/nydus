# Nydus ublk Block Device Target

## Status

This document describes the `nydus ublk` target: how a Nydus image is exposed
as a read-only `/dev/ublkbN` block device, how the kernel EROFS driver mounts
it, and the operational constraints of running the daemon.

The target is feature-gated behind the `ublk` Cargo feature and requires Linux
6.0 or newer with the `ublk_drv` module loaded.

## Overview

`nydus ublk` serves the flattened image address space through
[ublk](https://docs.kernel.org/block/ublk.html), the kernel's userspace block
driver. The daemon registers a block device with the driver, receives I/O
descriptors over `io_uring`, and answers them from the bootstrap file and the
decoded blob cache files.

```text
mount -t erofs /dev/ublkbN /mnt
      |
      v
kernel EROFS driver
      |
      | block read (LBA, length)
      v
ublk_drv  --- io_uring ---> nydus ublk queue thread
                                     |
                            resolve flattened ranges
                                     |
                     +---------------+---------------+
                     |               |               |
                bootstrap       blob cache       /dev/zero
                  file            files          (holes)
                                     |
                            cache miss: fetch,
                            decode and validate
                            from the backend
```

Because the device is a plain block device, everything above it is stock
kernel code: EROFS metadata reads, page cache, and readahead all work without
a userspace round trip per file operation. This is the block-level counterpart
to `nydus fuse` (userspace filesystem), `nydus uffd` (microVM virtio-pmem), and
`nydus fanotify` (native EROFS multi-device mount).

## Flattened Device Layout

The device exposes exactly the layout the EROFS device table already describes,
so no translation layer is needed between the block device and the filesystem:

```text
device offset 0
    |
    v
+-----------+------+--------+------+--------+------+-----+
| bootstrap | hole | blob 0 | hole | blob 1 | hole | ... |
+-----------+------+--------+------+--------+------+-----+
```

Layout rules:

- The bootstrap starts at device offset `0` and occupies its file size. The
  EROFS superblock therefore sits where the kernel expects it.
- Every non-redirect blob starts at the `mapped_offset` recorded by its EROFS
  device slot. Blob order in the table is not used to infer offsets.
- Blob length is the decoded cache file size (`blocks * 4096`).
- Gaps between mapped parts are holes served from `/dev/zero`.
- Redirect ("ondemand") blobs produced by `nydus optimize` are excluded: no
  chunk index points at them, and they only feed the phase-0 prefetch.
- The device size is the maximum part end rounded up to the logical block
  size.

This is the same layout `nydus uffd` serves, so the two targets share the
`NydusCore` range-resolution path.

## Device Parameters

| Parameter | Value | Rationale |
| --- | --- | --- |
| Logical block size | 4096 | Matches `EROFS_BLOCK_SIZE`, so every request covers whole EROFS blocks |
| Physical block size | 4096 | Same as logical; no read-modify-write exists on a read-only device |
| Minimum / optimal I/O size | 4096 | Reported through `UBLK_PARAM_TYPE_BASIC` |
| Attributes | `UBLK_ATTR_READ_ONLY` | Write, discard and zero-out requests are rejected |
| Queues | one per host CPU, capped at 4 | See [Queues and concurrency](#queues-and-concurrency) |
| Queue depth | 128 | Per queue |
| I/O buffer size | 512 KiB | Upper bound on a single request payload |

Supported operations are `READ` and `FLUSH` (a no-op that succeeds). Every
other operation returns `-EOPNOTSUPP`.

## Queues and Concurrency

Each ublk queue is served by one dedicated thread that processes its I/O
descriptors synchronously: resolve ranges, copy or fetch, complete. A single
queue therefore serializes all block I/O for the whole device, which becomes
the bottleneck as soon as more than one reader is active.

The default is one queue per host CPU, capped at `MAX_DEFAULT_QUEUES` (4).
`--queues` overrides it. The cap exists because each queue thread is a busy
`io_uring` waiter: more queues than concurrent readers costs threads without
adding throughput.

blk-mq maps a submitting CPU to a queue, so a single-threaded sequential
reader still uses exactly one queue thread. Parallelism comes from multiple
readers, not from splitting one reader's stream.

## Read Path

A block read is served in three steps:

1. **Resolve.** `NydusCore::fetch_flat_ranges` maps the requested device
   range onto a list of `(fd, offset, length)` ranges over the bootstrap file,
   the blob cache files, and `/dev/zero`. Ranges backed by a blob are fetched,
   decoded and CRC-validated before the descriptor is handed back, so a cache
   miss is resolved inline.
2. **Copy.** Each range is copied into the request buffer out of a
   `MAP_SHARED`/`PROT_READ` mapping of its backing file. Mappings are created
   on first use and kept for the life of the device. A range that reaches past
   a mapping (a file that grew after it was mapped) falls back to `pread`.
3. **Zero-fill.** Bytes not covered by any range — holes between blobs, the
   tail past the end of the image, and unwritten regions — are zeroed, which is
   what a block device with sparse backing returns.

The blob layout is resolved once and memoised, so the per-I/O cost is the copy
plus one `io_uring` completion.

### Why mmap instead of pread

Serving a request with `pread` costs a syscall plus a `copy_to_user` of the
whole payload. On a warm cache a queue thread is CPU bound, and a profile is
dominated by that copy: `__arch_copy_to_user` alone accounts for ~27% of the
thread's CPU. Copying out of a shared mapping of the same page cache costs
about half as much per 4 KiB (464 ns vs 977 ns measured on the benchmark host),
which translates directly into IOPS.

The mappings are safe to hold because the backing files never shrink: the
bootstrap is opened read-only, and a blob cache file is sized to the blob's
dense address space when it is prepared. There is no `SIGBUS` window.

## Startup and Shutdown

Blobs are prepared while the device is being built, before the device path is
printed. That means:

- A backend that cannot serve a blob meta fails the daemon at startup instead
  of surfacing later as an opaque `mount` failure.
- The announcement is truthful: once `/dev/ublkbN` is printed, the device can
  serve I/O without a multi-second stall on the first read.

The daemon prints the device path to stdout as a single line so callers can
script against it. Structured logs go to the log directory (and to stdout when
`--console` is set), so consumers should match the `/dev/ublkb` prefix rather
than assuming the path is the first line.

On `SIGTERM`, `SIGINT` or `SIGHUP` the daemon stops the queues and deletes the
device. **Unmount before stopping the daemon**: the kernel cannot delete a
device that is still mounted, so killing the daemon first leaks the device
until it is removed manually.

> [!WARNING]
> The daemon must not run in the same mount namespace as the process that
> mounts the device. Deleting the device on shutdown blocks on the mount, and
> the mount cannot be released without the daemon, so the two deadlock. Either
> unmount first, or run the daemon in its own mount namespace.

## Usage

```bash
cargo build --release --features cli,ublk --bin nydus

sudo modprobe ublk_drv

sudo nydus ublk \
  --bootstrap /var/lib/nydus/image/image.boot \
  --config /etc/nydus/config.yaml
# prints e.g. /dev/ublkb0

sudo mount -t erofs -o ro /dev/ublkb0 /mnt/nydus
```

Teardown:

```bash
sudo umount /mnt/nydus
sudo pkill -f 'nydus ublk'
```

Options:

- `--bootstrap` selects the EROFS bootstrap used as device metadata. Its blob
  table drives the flattened layout, so multi-blob images work without extra
  configuration.
- `--config` selects the regular Nydus backend, cache, and prefetch
  configuration. See [Storage config](nydus.md#storage-config).
- `--dev-id` requests a specific device id; `-1` (the default) lets the driver
  allocate one.
- `--queues` sets the queue count (default: host CPU count, capped at 4).
- `--depth` sets the per-queue depth (default 128).
- `--io-buf-bytes` sets the per-request buffer size (default 512 KiB).
- `--unprivileged` creates the device with `UBLK_F_UNPRIVILEGED_DEV`.
- `--log-level`, `--log-dir`, and `--log-max-files` control logging.

## Prefetch

`prefetch.scope` in the storage config works as it does for the other
targets, but it is not a default win for this one. The prefetch worker
competes with on-demand reads for the same disk and CPU, and on a
storage-bound host a full-image cold read was measured slower with prefetch
on than off. Enable it only when the node has spare I/O bandwidth, or use
`nydus optimize` so the warmup is a single ordered stream instead of a
scattered one.

## Comparison with the Other Mount Paths

| | `nydus ublk` | `nydus fuse` | `nydus fanotify` | `nydus uffd` |
| --- | --- | --- | --- | --- |
| Kernel interface | block device | FUSE | EROFS multi-device + fanotify | userfaultfd |
| Filesystem | kernel EROFS | userspace | kernel EROFS | guest EROFS |
| Per-file-op round trip | no | yes | no | no |
| Kernel requirement | 6.0 (`ublk_drv`) | any | 6.15 | 5.x + virtio-pmem |
| Writable | no (stack overlayfs) | no | no | no |
| Typical use | host mount, snapshotter rootfs | development, portability | host mount on new kernels | microVM guests |

`ublk` and `fanotify` both deliver a native EROFS mount. `fanotify` mounts the
bootstrap locally and marks each blob cache file as a separate EROFS device;
`ublk` presents one flat device and needs no per-file event hook, at the cost
of routing every block read through a userspace queue thread.

## Testing

```bash
# Rust unit tests for range assembly and zero-filling.
cargo test --features cli,ublk -p nydus ublk

# End-to-end: build an image, serve it, mount it with the kernel EROFS driver,
# and compare the tree against a FUSE mount of the same image.
# Requires root and Linux 6.0+ with ublk_drv; skips itself otherwise.
make test-ublk
```

## Constraints

- Read-only. A writable container rootfs needs `overlayfs` on top.
- Requires `CAP_SYS_ADMIN` to create the device unless `--unprivileged` is
  used, and always requires it to mount.
- One device per daemon process.
- User recovery (`UBLK_F_USER_RECOVERY`) is not implemented: if the daemon
  dies, in-flight and subsequent I/O to the device fails.
- No `dm-verity` integration; integrity comes from the per-block-group CRC32C
  validation on the fetch path.
