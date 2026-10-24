# FUSE hot upgrade and crash failover

FUSE supports hot upgrade and opt-in crash failover without replacing the kernel
mount. The control plane launches and monitors daemons; Nydus selects the startup
path and coordinates ownership.

Crash failover requires an external **holder**, run by the control plane, that
retains the session's FUSE devices and, where needed, its inflight journal across
daemon restarts. Its wire protocol is specified under
[Holder transport](#holder-transport).

## Usage

| Fresh launch | HTTP API | Hot upgrade | Crash failover |
| --- | --- | --- | --- |
| Neither option | No | No | No |
| `--apiserver` | Metrics, trace, control | Yes | No |
| `--supervisor-socket` | No | No | Yes |
| Both options | Metrics, trace, control | Yes | Yes |

```sh
# Standalone session with hot upgrade.
nydus fuse --bootstrap boot.img --blob-dir blobs/ --mountpoint /mnt/img \
  --apiserver unix:///run/nydus/image.sock

# Protected session; the holder must already be listening.
nydus fuse --bootstrap boot.img --blob-dir blobs/ --mountpoint /mnt/img \
  --apiserver unix:///run/nydus/image.sock \
  --supervisor-socket unix:///run/nydus/supervisor/image.sock
```

Start a successor with the same mountpoint, image, effective UID, and API path.
No `--upgrade` or `--takeover` flag is needed. Hot upgrade inherits the existing
session's protection without contacting the holder. Supplying a holder on an
upgrade does not protect a standalone session; that requires a fresh mount. A
successor of a protected session without `--supervisor-socket` is refused before
handoff, so a later crash can be recovered and a clean shutdown can release the
retention.

The supplied mountpoint path must not contain `..` components. Symlink targets
may contain `..`. Symlink aliases are resolved to an absolute path before deriving
ownership and session identity, so different symlinks to the same mountpoint share
the startup and lifetime locks. Fresh mounts require an existing directory. The
control plane must keep the resolved mountpoint and its parent directories stable
during startup. The API socket must use an absolute path outside the resolved
mountpoint, with no `..` or symlink components; a holder socket follows the same
rules and must differ from the API socket. Missing socket files or parent
directories are allowed.

### Automatic startup

Nydus acquires the startup lock and inspects mount state before probing a
configured API for direct handoff. If direct handoff is unavailable, it rechecks
mount state and acquires lifetime ownership before considering recovery or a
fresh mount:

| State | Action |
| --- | --- |
| A matching live predecessor completes handoff | Adopt its session |
| Protected mount, free owner lock, matching record and holder transfer | Recover the existing session |
| Mount absent, lifetime lock free, no holder configured, no protected session recorded | Mount fresh without failover protection |
| Mount absent, lifetime lock free, configured holder explicitly replies `empty` | Mount fresh with failover protection |
| Live owner without a usable control endpoint, abandoned standalone mount, protected mount whose holder has nothing, identity mismatch, non-FUSE mount, or retained transfer without a mount | Reject startup |

Explicit protocol rejection and authentication failures are errors, not evidence
that a predecessor is absent. Missing control endpoints and timeouts do not
permit bypassing a held ownership lock. Holder errors, disconnects, malformed
replies, and unreachable sockets never mean `empty`. A recorded protected session
requires a holder check even after its mount is gone.

Mount inspection reads `/proc/self/mountinfo` rather than accessing the mounted
path, which may block when the previous daemon has crashed.
Mountpoint resolution still requires traversable parent directories and may block
if an ancestor filesystem is unresponsive.

### Mount-scoped ownership state

Every launch uses the same coordination paths, regardless of API or holder options:

```text
/run/nydus/fuse/<effective_uid>/<mount_hash>.lock
/run/nydus/fuse/<effective_uid>/<mount_hash>.owner
mount_hash = lowercase hex SHA256(resolved absolute mountpoint UTF-8 bytes)
```

Missing parent directories are created at startup. The UID directory and state
files are created with modes `0700` and `0600`, respectively, subject to umask.
An existing UID directory must belong to the effective UID, must not be a symlink,
and must have no group or other access. The owner record must be a regular file.

| File | Purpose |
| --- | --- |
| `.lock` | Serializes discovery through API publication; concurrent starters may fail and retry |
| `.owner` | Holds the lifetime `flock` and records `version`, `mountpoint`, `image_digest`, `mount_dev`, and `session_id` |

The image digest is computed only when `--apiserver` or `--supervisor-socket` is
configured; otherwise the owner record stores `image_digest: null`. Both locks
remain in use without an API. Handoff and recovery require a present, matching
image digest in both identities and the owner record; transfer metadata always
carries a SHA-256 digest. `session_id` is the protected session's UUID, or `null`
for a standalone session.

Workers and teardown retain the owner guard independently of API availability.
Handoff releases it only after workers are parked and read/unmount rights are
released. Acquiring the lock alone does not authorize adoption: live handoff or
holder recovery, and a record matching the mount, image, and session ID, are also
required.

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
    |<----- metadata + descriptors ----|
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
| Connection, HTTP upgrade, or INFO interrupted | Recheck lifetime ownership and mount state before considering recovery |
| HANDOFF_BEGIN attempted, no complete transfer | Stand down, unless INFO advertised protection and pidfd confirms predecessor exit; then recheck ownership and fetch from the holder |
| Complete transfer received | Prepare the successor using that transfer; do not fetch a second copy |
| READY write incomplete, predecessor exit confirmed | Continue the prepared handoff after acquiring ownership, recovering a protected one |
| READY sent, ABORT received | Stand down without unmounting |
| READY sent, COMMITTED received | Acquire the owner lock, then activate the adopted session |
| READY sent, verdict missing or ambiguous | Stay parked, terminate the predecessor through pidfd, and confirm exit before activation |

A complete transfer is sent only after the predecessor parks its workers at
request boundaries. The successor may finish that already-prepared handoff after
confirmed predecessor exit; a protected session then runs inflight recovery, while
a standalone one activates directly. Direct handoff requires pidfd process control.

Discovery has a five-second budget. Handoff preparation, transfer, and READY have
a separate 30-second budget; verdict and exit waits are five seconds each.
An ambiguous verdict and the owner wait after it have no overall deadline, but
can be cancelled. A timeout never
grants read or unmount rights, and released ownership cannot be reclaimed.

## Session transfer

Hot upgrade and the holder carry the same transfer:

```text
SessionTransferMetadata {
    version = 1      // JSON format version, also used by the .owner record
    session_id       // UUID of a protected session; null for a standalone one
    mountpoint
    image_digest     // SHA-256 hex
    fuse_session_state {
        proto_major, proto_minor
        negotiated_init_flags, kernel_init_flags
    }
    inflight_journal // whether the fuser inflight journal follows the devices
}
standalone: fd[0]      = main FUSE device
protected:  fd[0..n-1] = main FUSE device, then every cloned worker device
            fd[n]      = fuser inflight journal, when inflight_journal is true
```

fuser keeps no journal where the kernel resends unanswered requests itself, so
`inflight_journal` is always `false` for a standalone session and reports what
fuser created for a protected one.

A request read on a cloned device can only be answered on that device, and
closing the device fails it. A protected session therefore keeps every device in
the holder and hands all of them over, and a protected successor keeps the
predecessor's worker count. A standalone successor clones devices of its own,
since its predecessor answered every dispatched request before handing over.

Before adoption, both transfer metadata and the ownership record are checked for
`"version": 1`. This is distinct from the daemon software version in INFO and the
kernel FUSE protocol version; no version negotiation is performed. The
descriptor layout must match `session_id` and `inflight_journal`, and the session
ID must match the one INFO advertised or the owner record holds, so no transfer
adds or drops protection. Nydus validates the mountpoint, image digest,
negotiated INIT state, FUSE devices and journal before adoption.

## Crash failover

### Holder transport

One holder socket retains one protected session. It uses raw framed JSON with
same-effective-UID authentication and a 30-second transaction deadline:

```text
daemon -> holder: {"type":"fetch"}
holder -> daemon: {"type":"empty"}
              or {"type":"transfer"} + metadata frame + descriptor copies
              or {"type":"error","message":"..."}

daemon -> holder: {"type":"retain","session_id":"<uuid>"} + metadata frame + descriptors
holder -> daemon: {"type":"retained"}
              or {"type":"error","message":"..."}

daemon -> holder: {"type":"release","session_id":"<uuid>"}
holder -> daemon: {"type":"released"}
              or {"type":"error","message":"..."}
```

The holder must keep its originals when returning copies, acknowledge only
complete retention, and reject replacement of a populated bundle. `release`
drops the bundle retained under the same session ID and closes its descriptors;
it also succeeds when nothing is retained, so a retry is safe, and fails without
dropping anything when another session is retained. The holder stores opaque
resources; it does not grant ownership or choose a startup mode. Hot
upgrade hands over the same devices and journal, so the retained bundle stays
valid across upgrades and recoveries.

### Protection and recovery

For a fresh protected mount, Nydus asks fuser for an inflight journal, parks
workers, records the session under the lifetime lock, then retains the bundle.
Workers start only after `retained`. If retention, activation, or API
publication fails, Nydus stops the workers, unmounts the new mount, and only then
releases the session, in case a lost acknowledgement left it retained; a failed
stop keeps the retention.

A protected session releases its retention when serving ends it: on shutdown
after it was unmounted, or when its connection closed. A handoff or a crash keeps
the retention for the successor. Release failures are logged and do not change
the exit status.

Recovery acquires lifetime ownership and validates the record before fetching.
The successor adopts the transfer with workers parked, rechecks the mounted
device, and recovers the requests the crashed daemon read but never answered
through fuser: where the kernel can resend them, they are delivered again,
possibly running an operation twice; otherwise every journaled request fails
with `EIO` for its caller to retry. Workers start after recovery. Healthy hot
upgrade avoids this by parking at request boundaries.

Failed adoption or recovery leaves the mount intact for retry. Confirm that the
unsuccessful process has exited before retrying with the same configuration.
Missing API readiness does not revoke ownership.

## Optional unified API endpoint

With `--apiserver`, FUSE publishes one `0600` Unix socket for `/metrics`, `/trace`,
and control. No API listener is created without the option. Control starts with:

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
connection before HANDOFF_BEGIN:

```text
request:  {"type":"info"}
response: {"type":"info","info":{"pid":1234,"version":"...",
          "mountpoint":"...","image_digest":"..."},"session_id":null}
```

Protected sessions report their UUID instead of `null`. Control and holder frames
have a four-byte little-endian length and a 1-byte to 4-MiB JSON payload.
Descriptors travel in one `SCM_RIGHTS` record with byte tag `F`, which the kernel
limits to 253 descriptors (`SCM_MAX_FD`); a protected session's worker devices and
journal must fit in it. Rejected descriptors are closed. TCP, HTTP/2, and proxies
are unsupported.

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
| Recovery | Stop without unmounting |
| Hot upgrade | Warn and continue serving without API or further direct upgrades |

If confirmed predecessor exit replaces COMMITTED in a protected handoff, startup
follows the recovery path. The control plane must observe readiness and health.
INFO verifies daemon identity and control responsiveness, not filesystem I/O
health. Without an API there is no explicit readiness signal. Process existence
or holder retention alone is insufficient.

The first termination signal requests cancellation at a safe startup boundary
or normal teardown while serving. A bounded protocol operation may finish before
cancellation is observed. A second signal forces immediate exit, including during
startup. Cancellation never authorizes ownership or worker activation.

### Cleanup

Changing API paths does not bypass lifetime ownership.

Normal shutdown unmounts only the recorded device while the daemon owns it.
A daemon that released its session never unmounts. Holder descriptors do not
prevent a clean unmount. A holder that was unreachable when a protected session
ended keeps a stale copy that rejects a fresh launch: after all readers exit,
clean up the holder retention explicitly. After a crash of a
standalone session, confirm the old readers have exited and clean up the
abandoned mount before starting fresh. Preserve the lock-file inodes.

Holder restart and replacement mounts are not supported. Socket and coordination
paths must remain under the control plane's management.

## Frontend integration

The handoff, ownership and holder logic lives in the frontend-independent
`continuity` module; `fuse::upgrade` adds FUSE identity, mount inspection,
resource validation and worker control. The adapter contracts and the design
rules are documented in `nydus/src/continuity/mod.rs`.

## Verification

Real-FUSE E2E covers upgrade, rollback, repeated recovery, concurrent starts,
lifetime-owner exclusion and operation without an API. Run it in a
root/FUSE-capable environment:

```sh
make test-fuse-continuity
```

To exercise hot upgrade from a different predecessor binary that implements the
same control protocol:

```sh
make test-fuse-continuity FUSE_CONTINUITY_PREDECESSOR=/absolute/path/to/nydus-before
```
