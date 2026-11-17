# Hot upgrade and crash recovery

Nydus can replace the daemon that serves a mounted image without replacing the
kernel mount or device. The control plane launches and monitors daemons; Nydus
selects the startup path and coordinates ownership.

The coordination is frontend-independent. This document describes it once, and
then what each frontend that uses it adds:

| Frontend | Hot upgrade | After a daemon crash |
| --- | --- | --- |
| [FUSE](#fuse) | The predecessor passes its FUSE connection | The mount is abandoned and must be cleaned up before a fresh start |
| [NBD](#nbd) | The predecessor passes its kernel connections | The kernel keeps the session, and a restart reattaches to it |

## Usage

| Launch | HTTP API | Hot upgrade |
| --- | --- | --- |
| Without `--apiserver` | No | No |
| With `--apiserver` | Metrics, trace, control | Yes |

```sh
# Mount with hot-upgrade control enabled.
nydus fuse --bootstrap boot.img --blob-dir blobs/ --mountpoint /mnt/img \
  --apiserver unix:///run/nydus/image.sock

# Attach a device with hot-upgrade control enabled.
nydus nbd --bootstrap boot.img --config config.yaml --device /dev/nbd0 \
  --mountpoint /mnt/img --apiserver unix:///run/nydus/nbd0.sock
```

Start a successor with the same image, effective UID, API path and resource:
the mountpoint for FUSE, the device and mountpoint for NBD. No `--upgrade` or
`--takeover` flag is needed. Crash recovery, where a frontend has it, needs no
API.

The API socket must use an absolute path outside the resolved mountpoint, with
no `..` or symlink components. A missing socket file or parent directory is
allowed.

### Automatic startup

Nydus acquires the startup lock and inspects the state of its resource, the
mount or the device, before probing a configured API for direct handoff. If
direct handoff is unavailable, it rechecks that state and acquires lifetime
ownership before considering a fresh start:

| State | Action |
| --- | --- |
| A matching live predecessor completes handoff | Adopt its session |
| Resource absent, lifetime lock free | Start fresh |
| Resource present, no live owner | Recover it where the kernel kept it usable (NBD); otherwise reject startup (FUSE) |
| Live owner without a usable control endpoint, identity mismatch, or a resource Nydus did not create | Reject startup |

Explicit protocol rejection and authentication failures are errors, not evidence
that a predecessor is absent. Missing control endpoints and timeouts do not
permit bypassing a held ownership lock.

Inspection never accesses the resource itself, which may block when the
previous daemon has crashed: FUSE reads `/proc/self/mountinfo`, NBD reads sysfs.

### Ownership state

Every launch uses the same coordination paths under the config's
`runtime_dir` (`/run/nydus` by default, or without `--config`), whether or not
an API is configured, so the old and the new daemon must share it:

```text
<runtime_dir>/<frontend>/<effective_uid>/<hash>.lock
<runtime_dir>/<frontend>/<effective_uid>/<hash>.owner
frontend = fuse | nbd
hash     = lowercase hex SHA256 of the resource name: the resolved absolute
           mountpoint for FUSE, /dev/nbdN for NBD (UTF-8 bytes)
```

Missing parent directories are created at startup. The UID directory and state
files are created with modes `0700` and `0600`, respectively, subject to umask.
An existing UID directory must belong to the effective UID, must not be a symlink,
and must have no group or other access. The owner record must be a regular file.

| File | Purpose |
| --- | --- |
| `.lock` | Serializes discovery through API publication; concurrent starters may fail and retry |
| `.owner` | Holds the lifetime `flock` and the frontend's record of the session |

Both locks remain in use without an API. Workers and teardown retain the owner
guard independently of API availability. Handoff releases it only after workers
are parked and the rights to serve and tear down the resource are released.
Acquiring the lock alone does not authorize adoption: a record matching the
resource and image is also required, and so is live handoff unless the frontend
can recover a session without its owner.

Owner-lock acquisition waits up to five seconds, except after the point of no return
in a handoff, where it waits until acquired or cancelled. Never unlink or recreate either file
to bypass a live owner. Handoff reads and validates the existing record before
HANDOFF_BEGIN, without the lifetime lock and without rewriting it; the startup
lock excludes a concurrent fresh startup. A missing or mismatched record fails
startup while the predecessor keeps serving.

## Hot upgrade

```text
successor                         predecessor
    |------ HTTP Upgrade / INFO ------>|
    |------ HANDOFF_BEGIN ------------>|
    |                           pause at request boundaries
    |<----- metadata + descriptors ----|
    | adopt with workers parked        |
    |------ READY -------------------->|
    |                           release; remove API socket
    |<----- COMMITTED -----------------|
    | acquire owner lock               | exit
    | resume; publish API              |
```

Dispatched requests finish before parking; new requests queue in the kernel on
the connections being passed. Open files remain usable.

Local adoption failure before READY half-closes the control connection's write
side and waits for ABORT, allowing the predecessor to resume without waiting for
successor exit. If ABORT cannot be delivered and successor exit cannot be
confirmed, the predecessor releases the session rather than risk concurrent readers.

| Interrupted handoff | Successor action |
| --- | --- |
| Connection, HTTP upgrade, or INFO interrupted | Recheck lifetime ownership and the resource; treat an existing resource as [without a predecessor](#automatic-startup) |
| HANDOFF_BEGIN attempted, no complete transfer | Stand down |
| Complete transfer received | Prepare the successor using that transfer |
| READY write incomplete, predecessor exit confirmed | Continue the prepared handoff after acquiring ownership |
| READY sent, ABORT received | Stand down without touching the resource |
| READY sent, COMMITTED received | Acquire the owner lock, then activate the adopted session |
| READY sent, verdict missing or ambiguous | Stay parked, terminate the predecessor through pidfd, and confirm exit before activation |

A complete transfer is sent only after the predecessor parks its workers at
request boundaries. The successor may finish that already-prepared handoff after
confirmed predecessor exit. Direct handoff requires pidfd process control.

Discovery has a five-second budget. Handoff preparation, transfer, and READY have
a separate 30-second budget; verdict and exit waits are five seconds each.
An ambiguous verdict and the owner wait after it have no overall deadline, but
can be cancelled. A timeout never grants the rights to serve or tear down the
resource, and released ownership cannot be reclaimed.

## Session transfer

A transfer is one frame of metadata followed by descriptors. The coordinator
carries both without interpreting them; the frontend defines and validates
them:

| Frontend | Metadata | Descriptors |
| --- | --- | --- |
| FUSE | [`SessionTransferMetadata`](#fuse-session-transfer) | One: the live FUSE connection |
| NBD | The [ownership record](nbd.md#ownership-and-recovery-identity) of the session | One per live kernel connection |

## Optional unified API endpoint

With `--apiserver`, a frontend publishes one `0600` Unix socket for `/metrics`,
`/trace`, and control. No API listener is created without the option. Each
frontend has its own control path and protocol token:

| Frontend | Path | Token |
| --- | --- | --- |
| FUSE | `/fuse/handoff` | `nydus-fuse-control/1` |
| NBD | `/nbd/handoff` | `nydus-nbd-control/1` |

Control starts with, for FUSE:

```http
GET /fuse/handoff HTTP/1.1
Host: localhost
Connection: Upgrade
Upgrade: nydus-fuse-control/1

HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: nydus-fuse-control/1
```

After `101`, the connection carries framed JSON and descriptors. HTTP read-ahead
is preserved. Both peers authenticate the same effective UID through `SO_PEERCRED`;
declared PIDs must match the authenticated PID. INFO is required on the same
connection before HANDOFF_BEGIN. Its `info` object is the identity of the
frontend; this is FUSE's:

```text
request:  {"type":"info"}
response: {"type":"info","info":{"pid":1234,"version":"...",
          "mountpoint":"...","image_digest":"..."},"session_id":null}
```

Control frames have a four-byte little-endian length and a 1-byte to 4-MiB JSON
payload. The descriptors of a transfer travel in one `SCM_RIGHTS` record with
byte tag `F`; rejected descriptors are closed. TCP, HTTP/2, and proxies are
unsupported.

One control conversation is admitted at a time; another waits up to five seconds
before receiving HTTP `503`. Metrics and trace remain concurrent. Publication
only replaces an existing socket after a refused connection; a timeout is not
proof that a socket is stale.

The predecessor removes its socket before COMMITTED, and later teardown does
not unlink the successor's socket. No listener descriptor is transferred, so
HTTP clients must tolerate a brief reconnect.

## Readiness and shutdown

Workers are active before a configured API is published. Publication failure is
handled according to the startup path:

| Path | API publication failure |
| --- | --- |
| Fresh | Stop workers and tear down the fresh mount or session |
| Hot upgrade | Warn and continue serving without API or further direct upgrades |

The control plane must observe readiness and health.
INFO verifies daemon identity and control
responsiveness, not filesystem I/O health. Without an API there is no explicit
readiness signal. Process existence alone is insufficient.

The first termination signal requests cancellation at a safe startup boundary
or normal teardown while serving. A bounded protocol operation may finish before
cancellation is observed. A second signal forces immediate exit, including during
startup. Cancellation never authorizes ownership or worker activation.

### Cleanup

Changing API paths does not bypass lifetime ownership.

Normal shutdown tears down only the recorded mount or session while the daemon
owns it. A daemon that released its session never tears it down. What a crash
leaves behind depends on the frontend; see [FUSE](#fuse) and [NBD](#nbd).
Preserve the lock-file inodes.

Socket and coordination paths must remain under the control plane's management.

## FUSE

The supplied mountpoint path must not contain `..` components. Symlink targets
may contain `..`. Symlink aliases are resolved to an absolute path before deriving
ownership and session identity, so different symlinks to the same mountpoint share
the startup and lifetime locks. Fresh mounts require an existing directory. The
control plane must keep the resolved mountpoint and its parent directories stable
during startup.

Mountpoint resolution requires traversable parent directories and may block
if an ancestor filesystem is unresponsive.

The owner record stores `version`, `mountpoint`, `image_digest`, and
`mount_dev`. The image digest is computed only when `--apiserver` is configured;
otherwise the owner record stores `image_digest: null`. Live handoff requires a
present, matching image digest in both identities and the owner record; transfer
metadata always carries a SHA-256 digest.

FUSE has no crash recovery. After a crash, confirm the old readers have exited
and clean up the abandoned mount before starting fresh.

### FUSE session transfer

```text
SessionTransferMetadata {
    version = 1      // JSON format version, also used by the .owner record
    mountpoint
    image_digest     // SHA-256 hex
    fuse_session_state {
        proto_major, proto_minor
        negotiated_init_flags, kernel_init_flags
    }
}
fd[0] = live read-write FUSE connection
```

Before adoption, both transfer metadata and the ownership record are checked for
`"version": 1`. This is distinct from the daemon software version in INFO and the
kernel FUSE protocol version; no version negotiation is performed.
Each transfer carries exactly one connection descriptor. Nydus
validates the mountpoint, image digest, negotiated INIT state and FUSE connection
before adoption.

## NBD

NBD uses the coordination above for hot upgrade, and adds crash recovery that
needs neither an API nor a live predecessor: the kernel keeps the session of a
daemon that exited, and a restart with the same device, image and mountpoint
attaches fresh connections to it.

- A session is identified by a UUID that the kernel holds as its backend
  identity and the owner record stores with the device, the image digest, the
  mountpoint, the capacity, the connection count and the timeouts. A successor
  inherits the count and the timeouts.
- A termination signal tears the session down, except that a mounted
  filesystem that stays busy keeps it for a restart to recover.

See [NBD continuity](nbd.md#hot-upgrade-and-failover) for the session identity,
what the kernel does with requests while no daemon serves, and how connections
are reattached.

## Frontend integration

The handoff and ownership logic lives in the frontend-independent
`continuity` module; `fuse::upgrade` adds FUSE identity, mount inspection,
resource validation and worker control, and `nbd::upgrade` adds connection
handoff, netlink reattachment and kernel session validation. The adapter
contracts and the design rules are documented in
`nydus/src/continuity/mod.rs`.

## Verification

Real-FUSE E2E covers upgrade, rollback, lifetime-owner exclusion and
operation without an API. Run it in a root/FUSE-capable environment:

```sh
make e2e-fuse-continuity
```

To exercise hot upgrade from a different predecessor binary that implements the
same control protocol:

```sh
NYDUS_E2E_FUSE_PREDECESSOR=/absolute/path/to/nydus-before make e2e-fuse-continuity
```

NBD E2E covers upgrade and crash recovery under I/O; see
[NBD verification](nbd.md#verification). It needs root and the `nbd` module:

```sh
make e2e-nbd-continuity
```
