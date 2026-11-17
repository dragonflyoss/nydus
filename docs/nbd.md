# Nydus NBD Service

## Status

This document describes the current NBD service: how a flattened nydus image
is exposed as a read-only block device through the Linux Network Block Device
driver, the kernel socket protocol, netlink session setup, and automatic
hot upgrade and crash recovery.

See the [documentation index](../README.md#documentation) and
[kernel/format requirements](nydus.md#kernel-compatibility-and-format-limits).
The NBD wire protocol is unchanged by chunk-table `.blob.meta` v1. This
flattened EROFS layout requires flatdev support (Linux 6.4+).

The service uses a Unix socket pair per connection, configured through the
kernel's NBD generic-netlink family. There is no TCP listener
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
kernels without `FAN_CLASS_PRE_CONTENT` (Linux < 6.15); it needs NBD netlink
sessions with backend identity (Linux 5.14+) and EROFS flatdev support
(Linux 6.4+).

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
| `1` | `NBD_CMD_WRITE` | Never legitimate (read-only device); the connection is closed rather than replied to, because the unconsumed payload would desync the stream, and the daemon stops |
| `2` | `NBD_CMD_DISC` | Session teardown; no reply, the worker exits |
| other | flush/trim/... | Reply `EINVAL` (no payload to drain) |

A request whose magic does not match is treated as a desynced stream: the
connection is closed and the daemon stops, keeping the kernel session for a
replacement (see [Service Lifecycle](#service-lifecycle)). There is no way to
resync a byte stream to header boundaries, and a reply would carry a
fabricated handle the kernel cannot match.

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

`nbd::upgrade` implements the shared `continuity::startup::Frontend` and
`continuity::handoff::SessionControl` contracts. Startup inspects
`/sys/block/nbdN/{size,backend}` without opening or reading a stalled block
device, then selects:

| State | Action |
| --- | --- |
| Neither a kernel session nor a live lifetime owner | Create a fresh session with `NBD_CMD_CONNECT` |
| Matching live API peer | Take over its connections through the control socket |
| Retained kernel session, no live owner, valid ownership record and, with `--mountpoint`, its filesystem still mounted there | Reattach with `NBD_CMD_RECONFIGURE` automatically, with or without API |
| Live owner without usable API, missing/mismatched record or different kernel identity | Fail without replacing or disconnecting the existing session |

Fresh CONNECT supplies the 4096-byte block size, flattened capacity,
`HAS_FLAGS | READ_ONLY | CAN_MULTI_CONN`, timeouts, backend identity and one
socket per worker. It commits geometry before returning; no `NBD_DO_IT`
thread or capacity polling is needed. The kernel retains the device and
connection references independently of the daemon.

The read-only flag makes the kernel reject writes at the block layer, so
`NBD_CMD_WRITE` never arrives from a healthy kernel.

### Ownership and recovery identity

Every launch uses `<runtime_dir>/nbd/<effective_uid>/<hash>.lock` and `.owner`,
where `runtime_dir` comes from `--config` (`/run/nydus` by default) and `hash`
is SHA-256 of `/dev/nbdN`. Device-node aliases must resolve to
that same kernel device. The lock roles are the same as
[shared continuity](upgrade.md#ownership-state); keep both
inodes across generations, independently of API configuration.

The record stores `"version": 1`, the device, the image metadata digest,
mountpoint, Session UUID, capacity, connection count and timeouts. Missing or
unsupported versions are rejected without negotiation. The backend identifier
registered with the kernel is derived from the record,
`nydus:<image_digest>:<session_uuid>`. Both the record and kernel identity must
match before adoption. The image identity is content-based, not its bootstrap
pathname.

Workers retain the lifetime lock through release and cleanup. Connection
counts and timeouts are inherited from the record even if a successor's flags
differ, so crash recovery does not depend on the control plane remembering
the original `--threads`. Only the check before a handoff reads the record
without its lifetime lock; the predecessor then sends its own copy with the
connections, and the kernel itself rejects a reconfigure whose backend identity
differs from the session's.

### Hot upgrade and failover

With `--apiserver`, `/metrics`, `/trace`, and `/nbd/handoff` share one HTTP
Unix socket. Control uses `Upgrade: nydus-nbd-control/1`, authenticated INFO,
and the shared `Transfer` handoff mode. No mode-selection flag is needed:
launching another binary with the same device, image and mountpoint initiates
the handoff.

The predecessor hands its connections over instead of closing them. Each worker
stops between two requests, waits until the reads it dispatched are answered,
and parks; the predecessor then sends a duplicate of every connection, with its
ownership record, over the control socket. The kernel keeps queueing requests
on a parked connection, so whoever reads it next continues both the request and
the reply stream: no request loses its reply, no kernel slot is retired, and no
netlink command is involved. The successor holds the connections without
reading them until the predecessor has released ownership and its workers have
exited, then serves the requests queued meanwhile.

Until the successor reports ready the handoff is reversible: on any failure the
predecessor resumes serving the same connections, and the successor exits
without closing them. Parking waits for the reads in flight for at most half of
`--timeout`, and never longer than the 30-second handoff timeout; if they do
not finish in time, the handoff is refused and can be retried. It is also
refused while no connection is alive. Requests wait in the kernel while the
connections are parked, normally for well under a second. A request held
longer than `--timeout` is retried by the kernel, which closes the connection
it timed out on; the new daemon reattaches that connection (see
[Service Lifecycle](#service-lifecycle)).

After a crash no daemon is left to pass the connections on, so a restart
attaches fresh connections to the kernel-retained session with
`NBD_CMD_RECONFIGURE`. It replaces only dead slots, never disconnecting the
device or moving the mount. The kernel silently ignores sockets for slots that
are not dead yet, so Nydus drops its kernel-end copies and checks which
connections closed. Accepted connections serve at once; only the ignored ones
are retried. The repair of a connection lost while serving offers replacements
the same way from a helper thread. Inflight requests may wait for the original
request timeout before being retried; new I/O waits up to
`--dead-conn-timeout`. Recovery must finish within the kernel's I/O budgets to
avoid errors. A failed adoption preserves the device and record for a retry. No
external Holder is required.

One kernel race affects these reattachments. A slot retired by a failed send, a
request timeout or a crash is marked dead again by its exiting kernel receiver:
Linux `recv_work` does this without checking which socket the slot now holds,
so it can close a replacement attached in between. No process can observe that
receiver, so the daemon does not rely on it exiting first; it reattaches lost
connections instead (see [Service Lifecycle](#service-lifecycle)).

## Service Lifecycle

Each connection has one worker thread that reads requests off the user end of
its socket pair and dispatches reads to a fetch pool shared by all connections
(`--fetch-concurrency` threads). A cold read waiting on the backend therefore
does not hold up the requests queued behind it on the same connection, which
matters when one CPU issues most I/O and the kernel maps it to one connection.
Replies are written whole under a per-connection lock in completion order; the
kernel matches them to requests by handle. Pool threads keep a reuse buffer
that grows to the largest request seen. A reply that cannot be written closes
its connection, and the kernel retries the requests it had sent on it. Only a
handoff waits for the reads a connection dispatched, for a bounded time, before
it parks the connection; any other exit closes the connection at once.

When `--mountpoint` is given, the daemon mounts the device as EROFS
(`MS_RDONLY | MS_NODEV | MS_NOSUID`, no `device=` options) once the capacity
is committed, and owns the unmount. Without `--mountpoint` only the device is
attached and the caller mounts it.

Termination signals trigger the ordered shutdown:

1. The first signal unmounts the mountpoint **before** tearing down the NBD
   session — the unmount's own reads still need a live device, and clearing
   the socket first would leave a live mount backed by a dead device. `EBUSY`
   is retried for a bounded window (40 x 250 ms); "not mounted"
   (EINVAL/ENOENT) stops the retries immediately. If the filesystem stays in
   use, the daemon keeps the session instead of disconnecting it under the
   mount: it stops its workers and exits with an error, and a restart with the
   same device, image and mountpoint recovers the session as after a crash.
2. Issue `NBD_CMD_DISCONNECT`, then stop and join any remaining workers. The
   kernel closes the connections and completes outstanding I/O; it does not
   wait for a daemon acknowledgement. Device teardown requires the recorded
   kernel backend identity; a predecessor that released its session never
   disconnects its successor.
3. A second signal forces immediate exit. A session not disconnected by then
   stays connected as after a crash; restart the daemon to recover it if its
   filesystem is still mounted. If the signal arrived after the unmount, the
   session cannot be recovered; discard it as below.

This ordered shutdown applies only to a daemon that is serving. A signal that
arrives while the daemon is still starting cancels the startup at its next safe
boundary and never tears down a session it takes over or recovers; only a
session it has just created is disconnected again. Until the successor reports
ready the predecessor keeps or resumes serving, and once the predecessor has
released, the session stays connected and mounted for the next daemon to
recover, as after a crash.
To roll back an upgrade that already began, hand the session over again to the
previous version.

An unexpected transport disconnect retires only the affected worker; other
workers keep serving, and the kernel retries unfinished requests. While serving,
the daemon reattaches each lost connection with a fresh socket through
`NBD_CMD_RECONFIGURE`, retrying while the kernel has not yet released the slot.
This covers request timeouts and a retired kernel receiver closing the socket
that replaced it; each receiver exits once, so repeated losses converge.
Reattachment pauses during a handoff and stops once teardown begins. Each repair
sends `NBD_CMD_RECONFIGURE` from a helper thread, because the kernel runs a
netlink command inside the sending call and can block it on a lock that no
socket timeout interrupts; the daemon keeps serving and answering signals and
handoffs meanwhile, and logs a warning once the call exceeds 10 seconds. A
failed repair, whether the kernel rejects the replacement or the sockets cannot
be created, keeps the remaining connections serving and is retried every 5
seconds. If a worker reports a fatal failure, the daemon stops its remaining
workers and reports an error, preserving the device, mount and ownership record
for a replacement daemon. This is distinct from an explicit termination signal,
which tears the session down. A received kernel `NBD_CMD_DISC` request also
triggers normal unmount and cleanup, not recovery. Lifetime ownership remains
held until the workers have stopped.

Restart `nydus nbd` with the same device, image and mountpoint to recover a
retained session; with `--mountpoint`, its filesystem must still be mounted
there. To discard it instead, unmount its filesystem and use a netlink-capable
`nbd-client -d /dev/nbdN` before starting fresh.

A disconnected session cannot be recovered. While a filesystem is still mounted
on its device, as when a caller mounted the device itself without
`--mountpoint`, the kernel keeps reporting the session; the daemon marks its ownership
record on disconnect, and a restart refuses to start until that filesystem is
unmounted.

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
  --mountpoint /mnt/erofs \
  --apiserver unix:///run/nydus/nbd0.sock
```

Options:

- `--bootstrap` is the EROFS bootstrap served at the head of the device.
- `--config` is the regular Nydus storage configuration (backend, cache,
  prefetch).
- `--device` identifies the NBD device to create or continue. Unrelated sessions
  are refused; matching sessions use the automatic startup rules above.
- `--mountpoint` optionally mounts the device as EROFS and unmounts it on
  shutdown. A fresh session needs an existing directory that nothing is mounted
  on, named without symlinks or `..`; a takeover or recovery needs the same
  path as the session it continues.
- `--threads` sets the connection count, 1 to 16; default is the available CPU
  count capped at 16. Every connection is a kernel blk-mq hardware queue, and
  a hot upgrade passes them all in one message.
- `--fetch-concurrency` bounds the reads served at once across all connections;
  default max(ncpu, 64). Like the fanotify option, it sizes a thread pool. Each
  pool thread keeps a buffer as large as the largest read it served, so a busy
  daemon holds up to this many read buffers; lower it to bound the memory of
  many devices on one host.
- `--timeout` (seconds, default 60, nonzero) is handed to `NBD_ATTR_TIMEOUT`:
  how long the kernel waits for one reply before retrying the request on
  another connection. Size it above the worst-case cold fetch of a single read
  from the backend, registry latency included.
- `--dead-conn-timeout` (seconds, default 60) lets the kernel queue I/O while
  all connections are dead, as until a crashed daemon is restarted. Once it
  expires, I/O fails with `EIO` until a daemon reattaches. Size it above the
  time your supervisor needs to restart a crashed daemon. A hot upgrade keeps
  every connection and does not depend on it.
- `--apiserver` optionally enables metrics, trace and direct hot upgrade. The
  socket path must be absolute, without symlinks or `..`, and outside the
  mountpoint; a successor finds its predecessor only at the same path.
  Omit it for automatic crash recovery without a listener. There are no
  `--upgrade`, `--recover`, `--control-socket` or `--supervisor-socket` options.
- `--log-level`, `--log-dir`, and `--log-max-files` control service logging.

## Requirements

- Root (`CAP_SYS_ADMIN`): NBD netlink configuration and `mount(2)`.
- The `nbd` kernel module (`modprobe nbd`); a fresh session needs a free
  `/dev/nbdX`, while a handoff or recovery continues its recorded device.
- NBD netlink support with the backend-identifier attribute and sysfs identity
  (Linux 5.14+), and EROFS flatdev support (Linux 6.4+) for the mount path.
  No fanotify pre-content support is needed.

## Constraints

- The device is read-only; writes are rejected by the kernel block layer.
- Wire integers are big-endian (NBD protocol), unlike the little-endian UFFD
  socket protocol.
- Requests must be 4096-aligned in offset and length; the advertised block
  size guarantees this for kernel-issued requests.
- One daemon owns one `/dev/nbdX`; a handoff cannot bypass lifetime ownership.
- Concurrency is bounded by `--fetch-concurrency` and the kernel queue depth
  (128 per connection), not by the connection count.
- Recovery does not undo I/O errors already returned after the kernel's
  timeouts. It restores future I/O on the same device and mount.
- This path cannot adopt an old ioctl-configured NBD device or an old
  prototype using pathname-based backend identity. Stop and detach it before
  the first launch with this version.

## Verification

`make e2e-experimental` runs the end-to-end suite
(`tests/e2e/experimental/nbd`): the filesystem contract shared by every mount
mode, plus demand-paging cache-growth bounds, concurrency and cache persistence
across restarts, against an in-process registry. It requires root, the `nbd`
module, and EROFS support. Protocol framing, netlink encoding, connection
handoff and record matching are covered by unit tests (`cargo test -p nydus
--features cli,nbd --lib nbd`).

The same suite covers continuity (`upgrade_test.go`), which `make
e2e-nbd-continuity` runs alone: four upgrades under concurrent cache-evicting
I/O and one while 64 readers keep every connection busy, bounding every
read's stall well below the request timeout, cold reads through held handles
and a pre-handoff mapping, an unchanged mount object (the device, its
connections and the mount stay), repeated failover,
corrupted-record rejection and retry, concurrent recovery, API-free recovery,
clean final shutdown, and a shutdown that could not unmount keeping the session
for a restart to recover.
