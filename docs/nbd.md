# Nydus NBD Service

## Status

This document describes the current NBD service: how a flattened nydus image
is exposed as a read-only block device through the Linux Network Block Device
driver, the kernel socket protocol the daemon serves, the netlink session setup,
and the mount lifecycle.

See the [documentation index](../README.md#documentation) and
[kernel/format requirements](nydus.md#kernel-compatibility-and-format-limits).
The NBD wire protocol is unchanged by chunk-table `.blob.meta` v1. This
flattened EROFS layout requires flatdev support (Linux 6.4+).

The service uses the classic NBD kernel transport: a Unix socket pair per
connection, configured through the kernel's NBD generic-netlink family. There is no TCP listener
and no NBD newstyle negotiation; the daemon is the only peer the kernel talks
to.

## Overview

The NBD service supports hosts that mount EROFS directly from a block device.
The daemon attaches `/dev/nbdX`, programs its geometry from the flattened
image, and serves the kernel's read requests from the bootstrap and decoded
blob cache files, fetching missing blob ranges on demand.

Chunk-based payloads are dense on the backend and scattered into padded plain
cache blocks. Native `erofs-*` layers carry no blob meta and are not served on demand by this frontend; they are mounted through the kernel from a block device or a local store. NBD is a block-copy transport, not guest DAX.

```text
EROFS mount of /dev/nbdX
      |
      v
kernel nbd driver -- 28-byte read request --> nydus nbd worker
                                                    |
                                           fetch/decode ranges
                                                    |
                                                    v
                                             local cache files
                                                    |
                                          pread + zero-fill holes
                                                    |
kernel nbd driver <-- 16-byte reply + data --------+
      |
      v
page cache serves repeat reads
```

Repeat reads are served by the page cache above the device. Reads that reach
the daemon again after page-cache eviction pread cache-resident ranges locally
without touching the backend.

This is the block-device counterpart to `nydus fanotify` (native EROFS mount
plus pre-content hooks) and `nydus uffd` (microVM virtio-pmem). It works on
kernels without `FAN_CLASS_PRE_CONTENT` (Linux < 6.15); it only needs the
`nbd` module and EROFS support.

## Flattened Device Layout

The device content is the core's flattened view, identical to the UFFD
service's layout (see [Nydus UFFD Service and Wire Protocol](uffd.md)):

```text
device offset 0
    |
    v
+-----------+------+--------+------+--------+------+-----+
| bootstrap | hole | blob 0 | hole | blob 1 | hole | ... |
+-----------+------+--------+------+--------+------+-----+
```

- The bootstrap starts at offset `0` and is served byte-for-byte, device
  table included.
- Every blob (the "ondemand" blob of an optimized image included) starts at
  the `mapped_offset` recorded by its EROFS device slot; its length is the
  decoded cache file size.
- Gaps outside mapped blobs are zero-filled. Cold ranges must be fetched and
  validated before replying; a fetch failure returns an error, not zero data.
- The device size is the flattened image size; it is a multiple of the 4096-
  byte EROFS block size.

Because the bootstrap keeps its device table and the mount passes no
`device=` options, the kernel enables EROFS "flatdev" mode: each chunk
address is resolved by adding its device slot's mapped block address,
which is exactly the layout above. The device table must not be zeroed:
without it the kernel masks chunk `device_id`s to `0` and misreads
blob-relative addresses as flat offsets.

## Wire Protocol

The daemon serves the kernel NBD socket protocol. All integer fields are
big-endian. Each request is a fixed 28-byte header (read requests carry no
payload):

| Offset | Size | Type | Field | Meaning |
|---:|---:|---|---|---|
| 0 | 4 | `u32` | `magic` | Always `0x25609513` |
| 4 | 4 | `u32` | `type` | Command type |
| 8 | 8 | `u64` | `handle` | Opaque request id, echoed in the reply |
| 16 | 8 | `u64` | `offset` | Byte offset in the device |
| 24 | 4 | `u32` | `len` | Byte length |

Each reply is a fixed 16-byte header, followed by `len` data bytes when the
reply is a successful read:

| Offset | Size | Type | Field | Meaning |
|---:|---:|---|---|---|
| 0 | 4 | `u32` | `magic` | Always `0x67446698` |
| 4 | 4 | `u32` | `error` | `0` ok, `5` (EIO), `22` (EINVAL) |
| 8 | 8 | `u64` | `handle` | Echoed from the request |

Command handling:

| Type | Name | Handling |
|---:|---|---|
| `0` | `NBD_CMD_READ` | Validate, fill, reply with header + data |
| `1` | `NBD_CMD_WRITE` | Never legitimate (read-only device); the session is dropped rather than replied to, because the unconsumed payload would desync the stream |
| `2` | `NBD_CMD_DISC` | Session teardown; no reply, the worker exits |
| other | flush/trim/... | Reply `EINVAL` (no payload to drain) |

A request whose magic does not match is treated as a desynced stream and
drops the session; there is no way to resync a byte stream to header
boundaries, and a reply would carry a fabricated handle the kernel cannot
match.

Read validation, in order:

1. `len` above the 4 MiB cap: reply `EINVAL`. The block layer's default
   `max_sectors` keeps real requests far below this; the cap only rejects a
   pathological length before it drives a huge allocation. Raising
   `/sys/block/nbdX/queue/max_sectors_kb` past 4096 would need this cap
   raised too.
2. `offset` or `len` not 4096-aligned: reply `EINVAL`. The advertised block
   size makes aligned requests the only well-formed ones.
3. Fetch + read failure (backend error, range past the device end): reply
   `EIO`.

Successful read replies are always full-length; logical holes and padding
are zero-filled, while source data is fetched before completion. The reply header and data payload are written with one
`writev`.

## Device Setup and Session

`NbdSession` starts one worker per connection, each on its own socket pair,
then resolves the `nbd` generic-netlink family and sends
`NBD_CMD_CONNECT` with the device index, capacity, 4096-byte block size,
request timeout, `HAS_FLAGS | READ_ONLY | CAN_MULTI_CONN`, and all socket
descriptors. The kernel rejects an occupied device instead of clearing its
existing session.

The read-only flag makes the kernel reject writes at the block layer, so
`NBD_CMD_WRITE` never arrives from a healthy kernel.

CONNECT commits the device geometry before returning, so no blocking
`NBD_DO_IT` thread or capacity polling is needed before mounting. The kernel
retains the session configuration independently of the daemon.

## Service Lifecycle

Each worker thread reads requests off the user end of its socket pair and
replies serially; concurrency comes from running multiple workers. A worker
keeps a reuse buffer that grows to the largest request seen, so the
steady-state read path performs no allocation.

When `--mountpoint` is given, the daemon mounts the device as EROFS
(`MS_RDONLY | MS_NODEV | MS_NOSUID`, no `device=` options) once the capacity
is committed, and owns the unmount. Without `--mountpoint` only the device is
attached and the caller mounts it.

Termination signals trigger the ordered shutdown:

1. The first signal unmounts the mountpoint **before** tearing down the NBD
   session — the unmount's own reads still need a live device, and clearing
   the socket first would leave a live mount backed by a dead device. `EBUSY`
   is retried for a bounded window (40 x 250 ms); "not mounted"
   (EINVAL/ENOENT) stops the retries immediately.
2. Issue `NBD_CMD_DISCONNECT`, then stop and join any remaining workers. The
   kernel closes the connections and completes outstanding I/O without waiting
   for a daemon acknowledgement.
3. A second signal forces immediate exit.

A kernel `NBD_CMD_DISC` request also triggers normal unmount and cleanup.
Losing one connection retires only its worker while other workers continue
serving. If all workers exit or a worker reports a fatal failure, the daemon
reports the failure and tears the session down; this standalone path does not
yet support recovery of a retained session.

## Running the Service

Build the CLI with both feature gates:

```bash
cargo build --release --features cli,nbd --bin nydus
```

Start the service:

```bash
sudo nydus nbd \
  --bootstrap /var/lib/nydus/image/image.boot \
  --config /etc/nydus/config.yaml \
  --device /dev/nbd0 \
  --mountpoint /mnt/erofs
```

Options:

- `--bootstrap` is the EROFS bootstrap served at the head of the device.
- `--config` is the regular Nydus storage configuration (backend, cache,
  prefetch).
- `--device` is the NBD device node to attach. A busy device is refused.
- `--mountpoint` optionally mounts the device as EROFS and unmounts it on
  shutdown.
- `--threads` sets the worker count; default is the available CPU count
  capped at 16. Every worker is an independent kernel connection.
- `--timeout` (seconds, default 60, nonzero) is handed to `NBD_ATTR_TIMEOUT`:
  how long the kernel waits for one reply before retiring that connection and
  retrying the request. Size it above the worst-case cold fetch of a
  single read from the backend, registry latency included.
- `--log-level`, `--log-dir`, and `--log-max-files` control service logging.

## Requirements

- Root (`CAP_SYS_ADMIN`): NBD netlink configuration and `mount(2)`.
- The `nbd` kernel module (`modprobe nbd`) and a free `/dev/nbdX`.
- Kernel EROFS support for the mount path. No fanotify pre-content support is
  needed, so any distribution kernel with `nbd` and `erofs` works.

## Constraints

- The device is read-only; writes are rejected by the kernel block layer.
- Wire integers are big-endian (NBD protocol), unlike the little-endian UFFD
  socket protocol.
- Requests must be 4096-aligned in offset and length; the advertised block
  size guarantees this for kernel-issued requests.
- One daemon owns one `/dev/nbdX`; attaching to a busy device is refused.
- Requests on one connection are served serially; parallelism scales with
  `--threads`.
- If the daemon dies without a clean shutdown, reads on the mount fail after
  the kernel's request timeout; the mount must then be unmounted manually
  (`umount -l` as a last resort). Use a netlink-capable `nbd-client -d /dev/nbdN`
  to disconnect the retained device before starting a fresh daemon.

## Verification

`make e2e-experimental` runs the end-to-end suite
(`tests/e2e/experimental/nbd`): the filesystem contract shared by every
mount mode, plus demand-paging cache-growth bounds, concurrency and cache
persistence across restarts, against an in-process registry. It requires
root, the `nbd` module, and EROFS support. Protocol framing and netlink
encodings are covered by unit tests (`cargo test -p nydus --features cli,nbd
--lib nbd`).
