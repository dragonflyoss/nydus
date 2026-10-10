# FUSE hot upgrade

FUSE supports hot upgrade without replacing the kernel mount. The control plane
launches and monitors daemons; Nydus selects the startup path and coordinates
ownership.

## Usage

| Launch | HTTP API | Hot upgrade |
| --- | --- | --- |
| Without `--apiserver` | No | No |
| With `--apiserver` | Metrics, trace, control | Yes |

```sh
# Mount with hot-upgrade control enabled.
nydus fuse --bootstrap boot.img --blob-dir blobs/ --mountpoint /mnt/img \
  --apiserver unix:///run/nydus/image.sock
```

Start a successor with the same mountpoint, image, effective UID, and API path.
No `--upgrade` or `--takeover` flag is needed.

Mountpoints are normalized absolute paths without `..`; fresh mounts also require
an existing directory at its canonical path. The API socket must use an absolute
path outside the mountpoint, with no `..` or symlink components. A missing socket
file or parent directory is allowed.

### Automatic startup

Nydus serializes startup and tries direct handoff first when an API is configured.
If direct handoff is unavailable, it checks mount state and lifetime ownership
before considering a fresh mount:

| State | Action |
| --- | --- |
| A matching live predecessor completes handoff | Adopt its session |
| Mount absent, lifetime lock free | Mount fresh |
| Live owner without a usable control endpoint, abandoned mount, identity mismatch, or non-FUSE mount | Reject startup |

Explicit protocol rejection and authentication failures are errors, not evidence
that a predecessor is absent. Missing control endpoints and timeouts do not
permit bypassing a held ownership lock.

Mount inspection reads `/proc/self/mountinfo` rather than accessing the mounted
path, which may block when the previous daemon has crashed.

### Mount-scoped ownership state

Every launch uses the same coordination paths, whether or not an API is configured:

```text
/tmp/nydus-fuse-<effective_uid>/<mount_hash>.lock
/tmp/nydus-fuse-<effective_uid>/<mount_hash>.owner
mount_hash = lowercase hex SHA256(normalized absolute mountpoint UTF-8 bytes)
```

New directories and files are created with modes `0700` and `0600`, respectively,
subject to umask. An existing directory must belong to the effective UID, must not
be a symlink, and must have no group or other access. The owner record must be a
regular file. Preserve owner-only access and exclude active state from temporary
directory cleanup.

| File | Purpose |
| --- | --- |
| `.lock` | Serializes discovery through API publication; concurrent starters may fail and retry |
| `.owner` | Holds the lifetime `flock` and records `version`, `mountpoint`, `image_digest`, and `mount_dev` |

Workers and teardown retain the owner guard independently of API availability.
Handoff releases it only after workers are parked and read/unmount rights are
released. Acquiring the lock alone does not authorize adoption: live handoff and
a record matching the mount and image are also required.

Owner-lock acquisition waits up to five seconds, except after the point of no return
in a handoff, where it waits until acquired or cancelled. Never unlink or recreate either file
to bypass a live owner. Handoff reads and validates the existing record before
HANDOFF_BEGIN, without the lifetime lock and without rewriting it; this is safe
because the startup lock excludes fresh startup, the only writer. A missing or
mismatched record fails startup while the predecessor keeps serving.

## Hot upgrade

```text
successor                         predecessor
    |------ HTTP Upgrade / INFO ------>|
    |------ HANDOFF_BEGIN ------------>|
    |                           pause at request boundaries
    |<----- metadata + connection FD --|
    | adopt with workers parked        |
    |------ READY -------------------->|
    |                           release; remove API socket
    |<----- COMMITTED -----------------|
    | acquire owner lock               | exit
    | resume; publish API              |
```

Dispatched requests finish before parking; new requests queue on the existing
connection. Open file handles and directory cookies remain usable.

Local adoption failure before READY half-closes the control connection's write
side and waits for ABORT, allowing the predecessor to resume without waiting for
successor exit. If ABORT cannot be delivered and successor exit cannot be
confirmed, the predecessor releases the session rather than risk concurrent readers.

| Interrupted handoff | Successor action |
| --- | --- |
| Connection, HTTP upgrade, or INFO interrupted | Recheck lifetime ownership and mount state; reject an existing mount without handoff |
| HANDOFF_BEGIN attempted, no complete transfer | Stand down |
| Complete transfer received | Prepare the successor using that transfer |
| READY write incomplete, predecessor exit confirmed | Continue the prepared handoff after acquiring ownership |
| READY sent, ABORT received | Stand down without unmounting |
| READY sent, COMMITTED received | Acquire the owner lock, then activate the adopted session |
| READY sent, verdict missing or ambiguous | Stay parked, terminate the predecessor through pidfd, and confirm exit before activation |

A complete transfer is sent only after the predecessor parks its workers at
request boundaries. The successor may finish that already-prepared handoff after
confirmed predecessor exit. Direct handoff requires pidfd process control.

Discovery has a five-second budget. Handoff preparation, transfer, and READY have
a separate 30-second budget; verdict and exit waits are five seconds each.
An ambiguous verdict and the owner wait after it have no overall deadline, but
can be cancelled. A timeout never
grants read or unmount rights, and released ownership cannot be reclaimed.

## Session transfer

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

## Optional unified API endpoint

With `--apiserver`, FUSE publishes one `0600` Unix socket for `/metrics`, `/trace`,
and control. No API listener is created without the option. Control starts with:

```http
GET /fuse/control HTTP/1.1
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
connection before HANDOFF_BEGIN:

```text
request:  {"type":"info"}
response: {"type":"info","info":{"pid":1234,"version":"...",
          "mountpoint":"...","image_digest":"..."},"session_id":null}
```

Control frames have a four-byte little-endian length and a 1-byte to 4-MiB JSON
payload. The FUSE connection descriptor travels in one `SCM_RIGHTS` record with
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
| Fresh | Stop workers and unmount |
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

Normal shutdown unmounts only the recorded device while the daemon owns it.
A daemon that released its session never unmounts. After a crash, confirm the
old readers have exited and clean up the abandoned mount before starting fresh.
Preserve the lock-file inodes.

Socket and coordination paths must remain under the control plane's management.

## Frontend integration

The handoff and ownership logic lives in the frontend-independent
`continuity` module; `fuse::upgrade` adds FUSE identity, mount inspection,
resource validation and worker control. The adapter contracts and the design
rules are documented in `nydus/src/continuity/mod.rs`.

## Verification

Real-FUSE E2E covers upgrade, rollback, lifetime-owner exclusion and
operation without an API. Run it in a root/FUSE-capable environment:

```sh
make test-fuse-continuity
```

To exercise hot upgrade from a different predecessor binary that implements the
same control protocol:

```sh
make test-fuse-continuity FUSE_CONTINUITY_PREDECESSOR=/absolute/path/to/nydus-before
```
