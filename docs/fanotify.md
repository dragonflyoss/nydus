# Nydus Fanotify Pre-Content Service

## Status

This document describes the current `nydus fanotify` daemon, which serves a
real kernel EROFS mount on demand through fanotify pre-content hooks.
Requires Linux 6.15+.

## Overview

The daemon serves a **multi-device** EROFS image. The bootstrap is a real local
EROFS file that is mounted directly; each data blob is a separate EROFS
`device=` backed by the accessor's per-blob sparse cache file. The daemon marks
each blob cache file `FAN_PRE_ACCESS`. Mount, `ls`, and `stat` read the local
bootstrap and never involve fanotify; only cold blob-**data** reads fault.

```text
nydus fanotify  --marks each blob cache file-->  FAN_CLASS_PRE_CONTENT group

guest process: cat /mnt/erofs/big.bin
      |
      v
kernel EROFS driver (bootstrap mounted directly; big.bin data is on device N)
      |
      | reads blob device N's backing cache file at [offset, +count)
      v
backing cache file (sparse hole; pages not present)
      |
      | pre-content event {fd -> cache file, RANGE{offset, count}} -- BLOCKS reader
      v
nydus fanotify
      |
      | fstat(fd) -> (dev, ino) -> blob device
      | BlobAccessor::fetch(id, offset, count):
      |   backend fetch + decode + CRC validate
      |   write decoded data to the blob's cache file
      v
write(fan_fd, {fd, FAN_ALLOW}); close(fd)
      |
      v
kernel resumes the blocked read -> EROFS returns bytes
```

The kernel EROFS driver is unmodified. The filled cache file *is* the file the
kernel reads, so no separate copy step is needed. A marked file faults on
**every** read (a pre-content mark also disables readahead on it), so repeat
reads of a filled range still generate events — but the groupmap fast path
answers them immediately with no backend I/O.

## Multi-Device Model

The daemon enumerates blob devices from the bootstrap via
`BlobAccessor::entries()`, which also creates and sizes each blob's sparse cache
file so the device files exist before mount.

Layout rules:

- The **bootstrap** is a local EROFS file, mounted directly as the mount source.
  It is never marked and never served through fanotify.
- Each **blob** is one EROFS `device=` slot, in device-table order. Its backing
  file is the accessor's decoded cache file (`BlobInfo::cache_path`), sized to
  the blob's decoded length.
- Device slots keep their original 1-based index, including **redirect** slots,
  so the EROFS `device=` index is never renumbered. A read routed to a redirect
  slot is an invariant violation and is denied.
- A blob device is identified at fault time by the event fd's `(st_dev, st_ino)`,
  taken from the same descriptor that was confirmed to be a regular file of the
  expected size at startup (closes the path-stat/mark/open race).

## Event ABI

The parser mirrors `<linux/fanotify.h>`: a fixed `fanotify_event_metadata`
header optionally followed by info records. For a pre-content read the kernel
appends a `FAN_EVENT_INFO_TYPE_RANGE` (type `6`) record carrying the
`{offset, count}` the reader is about to access.

The RANGE record trails its info header with `{ __u32 pad; __u64 offset;
__u64 count; }`, so `offset` sits 8 bytes and `count` 16 bytes past the record
start. `FAN_PRE_ACCESS` is `0x0010_0000`; the metadata version is `3`.

The parser is pure byte handling with no syscalls (unit-tested). It walks each
event in a `read(2)` batch with checked arithmetic and reports — rather than
silently dropping — a malformed event. Errors are split by whether the event's
length was already validated: a **semantic** error (missing/zero/duplicate
RANGE, malformed info record — the next event's boundary is known) denies just
that event and keeps parsing the batch, so one odd event cannot take the daemon
down; a **structural** error (truncated header, bad version, bogus `event_len`
— the boundary is untrustworthy) stops the batch fail-closed. A queue-overflow
marker (`fd == FAN_NOFD`) carries no fd or range and is fatal.

## Event Processing

The daemon runs one event loop on a dedicated thread, driven by `epoll` over the
fanotify fd, a completion-wakeup `eventfd`, and a stop pipe. For each event it
decides a response purely from the parsed event, then admits the fetch:

1. **Decide.** A non-`FAN_PRE_ACCESS` mask, or a missing/zero RANGE record, is a
   `FAN_DENY` (without an offset the fetch cannot be bounded).
2. **Resolve device.** `fstat` the event fd for `(dev, ino)` and look up the
   blob device. An unknown device, or a redirect slot, is denied.
3. **Align.** The RANGE is aligned outward to 4 KiB EROFS blocks and clamped to
   the device size (the accessor requires block-aligned arguments). The device
   size is the fetch bound; there is no per-event byte cap.
4. **Fast path.** If the authoritative groupmap already covers the aligned range,
   the event is allowed immediately with no backend I/O.
5. **Coalesce or admit.** If an identical `(blob, aligned range)` fetch is
   already in flight, the event attaches to it and is answered by that one
   fetch's completion — no duplicate work. Otherwise it takes a slot in an
   unbounded pending table. Admission never fails; concurrency is bounded by the
   fetch thread pool (`--fetch-concurrency`), which queues tasks (backpressure)
   rather than denying.
6. **Fetch.** `BlobAccessor::fetch(id, offset, count)` runs on a fetch worker
   thread; it decodes, CRC-validates, dedups (idempotent, group-granular) and
   writes the blob's cache file in place. The work is wrapped in `catch_unwind`.
7. **Respond.** On completion the event is answered `FAN_ALLOW` on success, or
   `FAN_DENY` on a backend/range failure or a worker panic. A fetch in flight
   when shutdown denies its event still completes and may warm the cache, but
   as a late completion can no longer change the already-sent response. Bounded
   fetch time comes from the backend's HTTP timeout + bounded retries, not a
   per-event deadline; a registry `timeout: 0` (which would disable the HTTP
   timeout and leave fetches unbounded) is rejected at startup in this mode.

Duplicate work is removed at two layers. The event loop coalesces events sharing
an identical `(blob, aligned range)` key, so a burst of readers faulting the same
range dispatches a single fetch. Below that, the accessor de-duplicates at
blob-meta-group granularity (single-flight), so faults for different ranges in
the same group also join one fetch. Distinct groups fetch concurrently up to the
fetch thread pool size (`max(ncpu, 64)`); a saturated pool queues tasks rather
than denying reads.

### Response protocol

Each event fd is owned exactly once. A decision is selected once, the response
(`fanotify_response{fd, FAN_ALLOW|FAN_DENY}`) is written to the fanotify fd, and
only then is the fd closed — the kernel keys the response by fd, and each
intercepted access dups a fresh fd that must be closed or it leaks. `EINTR` is
retried; `EAGAIN` yields and retries (the fanotify fd is non-blocking). If a
permission object is dropped undecided it makes a best-effort `FAN_DENY` before
closing, so a reader is never left blocked.

### Deny reasons

| Reason | Cause |
|---|---|
| `InvalidRange` | missing/zero/out-of-device/overflow range, or non-pre-access mask |
| `UnknownDevice` | event fd's `(dev, ino)` matched no known blob device |
| `RedirectRead` | a read targeted a redirect slot the guest must not read |
| `BackendFailure` | backend fetch, decode, CRC, or cache write failed |

Overload is **not** a deny reason: admission is unbounded (the pending table
never fills) and a saturated fetch pool queues tasks, so a burst of cold reads
waits rather than failing with `EPERM`. The per-event denies above fire only on
malformed or unmappable events, never on load.

A queue-overflow event is handled as fatal (fail-closed): a lost permission
event cannot be answered safely. The group keeps a **bounded** kernel queue
(no `FAN_UNLIMITED_QUEUE`) so the overflow safety valve stays intact and
memory growth is bounded. The kernel default (16384 queued events) is large
enough for most workloads. Sustained overload (readers arriving faster than
the backend can drain) eventually overflows and stops the daemon fail-closed;
a large queue just raises that threshold.

Admission is unbounded — the pending table never fills. Concurrency is
bounded by `--fetch-concurrency` (the fetch thread pool): a busy pool queues
tasks, so readers wait rather than seeing `EPERM` (backpressure). To keep the
unbounded admission from exhausting file descriptors — each in-flight cold read
pins a dup'd event fd — the daemon raises its `RLIMIT_NOFILE` soft limit to the
hard limit at startup.

Per-event denies (`InvalidRange`, `UnknownDevice`, `RedirectRead`,
`BackendFailure`) surface as `EPERM` to the offending `read()`. Most
applications do not retry `EPERM`, but these only fire on a malformed event or
a backend failure, not on overload — admission is unbounded and the fetch pool
backpressures readers rather than denying them.

## Service Lifecycle

1. **Setup.** Raise the `RLIMIT_NOFILE` soft limit to the hard limit (each
   in-flight cold read pins a dup'd event fd and admission is unbounded). Build
   the accessor, enumerate and prepare blob devices, create the
   `FAN_CLASS_PRE_CONTENT` group, and `FAN_MARK_ADD` `FAN_PRE_ACCESS` on each
   blob cache file — skipping any blob already fully cached. The group fd is
   held unregistered.
2. **Run.** On a dedicated thread, register the group fd with `epoll` (alongside
   a completion `eventfd` and the stop pipe) and signal readiness once the
   event loop is polling.
3. **Mount.** After the event loop is ready, mount the bootstrap file-backed with each
   blob cache file as a `device=` option (`mount -t erofs <bootstrap> -o
   ro,device=<cache>...`, `MS_RDONLY|MS_NODEV|MS_NOSUID`). Because the bootstrap
   is local, mount and metadata succeed without any fanotify traffic.
4. **Serve.** Handle events until a termination signal.
5. **Shutdown.** A termination signal (`SIGTERM`/`SIGINT`/`SIGQUIT`/`SIGHUP`)
   wakes the event loop through the stop pipe; a **second** signal forces an
   immediate `exit` rather than requiring `SIGKILL`. On exit — whether a clean
   stop **or a fatal error** — the event loop denies every outstanding event
   (`deny_undecided`), drains in-flight completions, and drains the kernel queue
   (`drain_kernel_queue`), so no reader stays blocked and the mount goes
   quiescent. It then **returns the group fd to the caller in both cases**, and
   the caller unmounts **before** dropping the fd, retrying the unmount for a
   bounded window and deny-draining newly queued events between attempts (a
   reader racing the shutdown gets `EPERM` instead of blocking the unmount).
   The kernel's
   `fanotify_release()` is fail-open: it answers any still-queued permission
   events with `FAN_ALLOW`. Unmounting first ensures those ALLOWs cannot reach a
   live mount and read zero pages off the sparse cache (silent corruption —
   see [Known Limitations](#known-limitations)); returning the fd even on the
   fatal path is what preserves this ordering when the event loop thread aborts.

## Running the Service

Build the CLI with both feature gates:

```bash
cargo build --release --features cli,fanotify --bin nydus
```

Start the service (requires root for `FAN_CLASS_PRE_CONTENT` and `mount`):

```bash
sudo nydus fanotify \
  --bootstrap /var/lib/nydus/image/image.boot \
  --config /etc/nydus/config.yaml \
  --mountpoint /mnt/erofs
```

Options:

- `--bootstrap` is the EROFS bootstrap, mounted directly as the primary device.
- `--config` is the regular Nydus storage configuration. It selects the blob
  backend, local cache directory (where the marked cache files live), and
  prefetch settings.
- `--mountpoint` is the EROFS mount target (required). The daemon owns the mount
  lifecycle: it mounts after the group is ready and unmounts on shutdown, which
  is what lets shutdown unmount before the fail-open fd drop.
- `--fetch-concurrency` bounds how many blob fetches may run concurrently
  (default `max(ncpu, 64)`). A busy pool queues tasks — backpressure —
  rather than denying reads.
- `--log-level`, `--log-dir`, `--log-max-files`, `--console` control logging.

Example registry configuration:

```yaml
backend:
  type: registry
  config:
    host: 127.0.0.1:5000
    repo: nydus/example
    insecure: true
cache:
  type: local
  config:
    dir: /var/lib/nydus/cache
prefetch:
  enable: false
```

The fanotify feature is optional and does not affect default library or builtin
accessor builds unless explicitly enabled.

## Requirements

- **Kernel ≥ 6.15** for `FAN_PRE_ACCESS`; **6.15** for `FAN_EVENT_INFO_TYPE_RANGE`
  (precise range fills — the daemon requires a RANGE record and denies events
  without one).
- **Config:** `CONFIG_FANOTIFY=y`, `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`,
  `CONFIG_EROFS_FS=y`, and `CONFIG_EROFS_FS_BACKED_BY_FILE=y` (file-backed EROFS
  mount, kernel ≥ 6.12) — the daemon mounts a regular file, not a block device.
- **Privileges:** `CAP_SYS_ADMIN` (root) for both `fanotify_init` with the
  pre-content class and for `mount`.
- **Backing filesystem:** the cache files must live on a filesystem whose page
  cache the pre-content hook covers (ext4/xfs, verified). A **loop device** does
  not work — its backing-file reads bypass the VFS pre-content hook; mount the
  regular file file-backed instead.

## Constraints

- The blob-meta group (build-time `--compress-size`, default 4 MiB) is the fetch and
  cache-population unit, so one fault warms every chunk in the enclosing group.
  There is no runtime read-ahead knob; the tuning dial is the build-time group
  size.
- A burst of concurrent faults is bounded by the fetch pool
  (`--fetch-concurrency`, default `max(ncpu, 64)`): a saturated pool queues
  fetches (the reader waits) rather than denying — no application-visible
  EPERM.
- Fills persist in the on-disk cache file and its groupmap. A daemon restart
  re-serves already-fetched groups with no backend traffic. A cold restart must
  remove all per-blob artifacts (`*.blob.data`, `*.blob.meta`, `*.groupmap`,
  `*.prefetch.lock`) together; a stale groupmap against a wiped data file makes
  the fast path allow reads of unfilled holes.

## Known Limitations

- **Permission events are fail-open — silent zeros on crash.** This is the
  biggest gap. When the daemon exits, gracefully or not, `fanotify_release()`
  answers every still-queued permission event with `FAN_ALLOW`. If the mount is
  still up — the daemon was killed before it could unmount, or panicked — those
  ALLOWs, and any subsequent reads that reach the now-unmarked sparse cache
  files, hit holes and return zero pages. There is no way for the container to
  distinguish "file content is legitimately zero" from "daemon crashed and data
  was never fetched" — silent data corruption.

  The fail-open behavior is fundamental to the VFS notification subsystem:
  closing the last fd of a notification group must release kernel resources, and
  the safest thing to do with in-flight events in that case is to allow them
  rather than wedge every blocked reader indefinitely. There is no flag to opt into fail-close.

  **Mitigation.** The daemon owns the mount lifecycle and unmounts *before*
  dropping the group fd on every exit path (including fatal errors), so the
  ALLOWs from fd drop cannot reach a live mount (see [Service Lifecycle](#service-lifecycle)).
  A supervisor that unmounts on stop covers the `kill -9` / panic case the
  daemon cannot self-cover. If readers hold files open past the unmount retry
  window, the final fd drop still fail-opens and unfilled ranges read as zeros —
  stop readers before stopping the daemon.

  **Upstream fix proposed.** Ibrahim Jirdeh (Meta) posted a patch series
  ([v3, April 2026](https://lore.kernel.org/linux-fsdevel/20260416194844.3874004-1-ibrahimjirdeh@meta.com/))
  adding two pieces:
  - `FAN_RESTARTABLE_EVENTS` — an opt-in `fanotify_init` flag that makes the
    group **fail-close**: on fd drop, pending permission events are *not*
    auto-allowed; they stay queued. This is the missing flag the current API
    has no equivalent of.
  - `FAN_IOC_OPEN_QUEUE_FD` — an ioctl that opens a "queue fd" onto the
    (possibly crashed) group, letting a new daemon drain those queued events
    and respond to them normally.

  Together they replace the current "silent zeros on crash" with
  "blocked-until-recovered": readers stay blocked rather than reading holes,
  and a restarting daemon picks up the pending events through the queue fd. If
  no daemon ever recovers them, those readers stay wedged (the safe-failure
  counterpart to today's silent corruption). Until this API lands, fail-open
  is unavoidable.

## Verification

`make test-fanotify` runs the end-to-end suite
([`tests/integration/fanotify_test.go`](../tests/integration/fanotify_test.go),
cases C0–C12). It builds a nydus image, pushes it to a throwaway local
`registry:2`, exports the bootstrap, starts the daemon against the registry
backend, and asserts correctness (byte-exact partial and full reads,
demand-paged cache growth), robustness (concurrent readers, warm re-read fast
path, restart persistence, graceful unmount), and — via an `strace` case —
that the daemon reads pre-content events, writes responses, and pwrites the
cache, i.e. that it is on the read path. It preflight-checks the kernel
version, privileges, and required binaries, and skips loudly on an unsupported
host. `make test-fanotify-perf` runs the fanotify vs FUSE comparison
([`tests/integration/fanotify_perf_test.go`](../tests/integration/fanotify_perf_test.go)).

Sources: dragonflyoss/nydus#1826; erofs-utils `lib/backends/fanotify.c` and
`mount/main.c` (`erofsmount_fanotify`); LWN "fanotify: add pre-content hooks".
