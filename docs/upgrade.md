# Nydus Service Continuity

## Status

This document is the home for frontend-native service continuity contracts.
The current sections specify the implemented FUSE hot-upgrade and opt-in crash
failover design. Other frontends will define their native continuity mechanisms
here as they are added.

---

## 1. Contract

Nydus preserves one kernel FUSE session in two ways:

- **Hot upgrade** is a direct predecessor/successor handoff on the live
  `/dev/fuse` connection.
- **Crash failover** is external resource escrow through a Recovery Holder that
  retains one Failover-Protected Session's Session Transfer.

Control and Holder exchanges use bounded local framing. The opaque Session
Transfer has no version field: its required metadata fields and descriptor
order are a frozen ABI, and evolution is additive only — optional unknown
metadata fields are the compatible evolution path, and old readers ignore
them. There is no version negotiation or versioned transfer envelope in the
wire protocol.

A fresh mount becomes a Failover-Protected Session only when started with
`--supervisor-socket`. Hot upgrade never creates or replaces that protection:
the successor inherits the existing Session Transfer. A Standalone Session
remains mountable but rejects hot upgrade and recovery. Converting a Standalone
Session requires stopping it, unmounting, and creating a new protected mount.

`--upgrade` and `--recover` are mutually exclusive, and `--recover` requires a
supervisor socket.

## 2. Usage

Start a Standalone Session:

```sh
nydus fuse --bootstrap boot.img --blob-dir blobs/ --mountpoint /mnt/img \
  --control-socket "${XDG_RUNTIME_DIR:?}/nydus/image.sock"
```

Create a Failover-Protected Session with a Holder-managed supervisor socket:

```sh
nydus fuse --bootstrap boot.img --blob-dir blobs/ --mountpoint /mnt/img \
  --control-socket "${XDG_RUNTIME_DIR:?}/nydus/image.sock" \
  --supervisor-socket /run/nydus/supervisor/image.sock
```

Hot-upgrade that Failover-Protected Session:

```sh
nydus-new fuse --bootstrap boot.img --blob-dir blobs/ --mountpoint /mnt/img \
  --control-socket "${XDG_RUNTIME_DIR:?}/nydus/image.sock" --upgrade
```

Recover that protected session after the previous daemon exits:

```sh
nydus fuse --bootstrap boot.img --blob-dir blobs/ --mountpoint /mnt/img \
  --control-socket "${XDG_RUNTIME_DIR:?}/nydus/image.sock" \
  --supervisor-socket /run/nydus/supervisor/image.sock \
  --recover
```

### Startup modes

Startup selects one of three modes:

| Mode | Selection | Behavior |
| --- | --- | --- |
| Fresh | Neither `--upgrade` nor `--recover` | Creates a new FUSE mount |
| Upgrade | `--upgrade` | Adopts a protected predecessor's live session |
| Recover | `--recover --supervisor-socket PATH` | Restores the Holder-retained session |

Fresh means a newly created mount, not a refresh of an existing daemon. It
creates a Standalone Session without `--supervisor-socket` and a
Failover-Protected Session with one. Fresh refuses to start while a live
instance or an unclaimed FUSE mount already exists at the mountpoint.

### Instance control endpoint

Every Fresh session publishes an owner-only Unix control socket before startup
completes. `INFO` reports the daemon PID, version, canonical mountpoint, image
digest, and optional Session Identity. A Standalone Session reports no Session
Identity and rejects `HANDOFF_BEGIN`; its control endpoint therefore provides
liveness and identity discovery rather than continuity handoff.

`--control-socket` requires an absolute path and has no default. Its sibling
`<control-socket>.lock` serializes startup from the initial ownership probe
through endpoint publication. Every generation serving one mountpoint must use
the same control path. Using different paths for one mountpoint is invalid: the
paths represent different coordination domains and can permit concurrent
ownership decisions.

A manager such as nydus-snapshotter may persist the control-socket path and
expected daemon identity, then issue `INFO` after the manager restarts and can
no longer wait on the original child process. Control messages are JSON
preceded by a four-byte little-endian payload length:

```text
request:  {"type":"info"}
response: {"type":"info","info":{"pid":1234,"version":"...",
          "mountpoint":"...","image_digest":"..."},"session_id":null}
```

A protected session returns its UUID string instead of `null`.
A successful query requires a bounded request and response, same-UID
`SO_PEERCRED` authentication, and agreement between the authenticated peer PID
and the PID in the response. Socket-path existence alone does not prove
liveness. `INFO` proves that the daemon and its control loop are responsive;
mount health should be checked separately against mountinfo.

Upgrade and Recover also publish a replacement control endpoint. Recovery
stands down if publication fails. An upgraded daemon may continue serving
without one, but cannot itself be upgraded again.

## 3. Hot upgrade

Hot upgrade keeps the same kernel mount and the same live FUSE connection. The
Holder is not involved. The successor requires pidfd process control so it can
retire the predecessor if cutover ownership becomes ambiguous.

```text
successor                   predecessor
    | prepare dependencies       |
    |------ HANDOFF_BEGIN ------>|
    |                       pause workers
    |<----- Session Transfer ----|
    | adopt, workers parked      |
    |------ READY -------------->|
    |                       stop workers
    |<----- COMMITTED -----------|
    | resume                     | retired
```

The predecessor pauses at a request boundary, so already-dispatched requests
finish before the handoff and new kernel requests queue on the unchanged
connection.

Hot-upgrade state carries the negotiated FUSE session fields:

```text
FuseInitState {
    proto_major
    proto_minor
    negotiated_init_flags
    kernel_init_flags
}
```

- Failover-Protected Sessions transfer the same Session Identity, live FUSE
  connection, and fuser recovery resource already retained by the Holder;
- Standalone Sessions reject the handoff before pausing workers;
- receiving complete `READY` is the irreversible cutover point: the predecessor
  stops its workers before replying `COMMITTED`;
- after sending `READY`, the successor rolls back only on explicit `ABORT`; an
  ambiguous result keeps it parked until pidfd confirms predecessor exit;
- before complete `READY`, the predecessor sends `ABORT` and resumes, or waits
  until the successor is confirmed exited;
- if `ABORT` cannot be delivered to a potentially live successor, the
  predecessor retires rather than risk concurrent readers.

Readers therefore see the same mount and existing handles remain valid across a
successful handoff.

## 4. Crash failover

### 4.1 Session Transfer

A Failover-Protected Session stores exactly one fixed two-fd Session Transfer:

```text
SessionTransferMetadata {
    session_id
    mountpoint      // canonical absolute path
    image_digest
    fuse_session_state
}

fd[0] = live FUSE connection
fd[1] = fuser recovery resource
```

Descriptor order is fixed by the transfer ABI. The Holder treats both descriptors
as opaque retained resources.

Transfer metadata may gain optional fields that old readers can safely ignore.
The required fields and the descriptor order never change.

### 4.2 Holder transport

The Holder owns one long-lived supervisor socket for one FUSE session, and each
nydusd incarnation connects to it as a client. Before launching the expected
child, the Supervisor configures whether the Holder will retain a fresh
transfer or provide its retained transfer for recovery.
Both the control and supervisor sockets are owner-only (`0600`) Unix sockets,
and each peer must authenticate through `SO_PEERCRED` with the same effective UID.

```text
fresh:    opaque metadata + [fuse_fd, fuser_recovery_fd] -> RETAINED

recovery: opaque metadata + [fuse_fd, fuser_recovery_fd] ->
```

The Holder retains metadata opaquely and acknowledges a fresh transfer only
after retaining the metadata and exactly two descriptor copies. Recovery sends
descriptor copies immediately while the Holder keeps its originals.

The Go E2E Holder is currently the reference implementation of this protocol.
This protocol documentation is normative; a production/shippable Holder can be
added later when a real deployment requirement exists.

### 4.3 Fresh Failover-Protected Session

A fresh Failover-Protected Session follows this order:

1. create a Session Identity;
2. create and attach the fuser recovery resource before workers start;
3. start the FUSE workers parked, before any request can be read;
4. send the Session Transfer through the Holder socket;
5. resume workers only after `RETAINED` succeeds;
6. start the instance control endpoint;
7. publish readiness only after `INFO` reports the retained Session Identity from
   the expected child PID.

If retention is not acknowledged, the daemon exits and explicitly unmounts.

### 4.4 Recovery flow

Crash recovery is Supervisor-owned. The Supervisor reaps the previous daemon,
grants one Recovery Lease, configures the Holder for the expected child, and
starts exactly one successor with boolean `--recover`.

```text
successor nydusd             Holder
    | prepare dependencies       |
    |-- connect ---------------->|
    |<- transfer + 2 fds --------|
    | adopt with workers parked  |
    | fuser inflight recovery    |
    | resume and serve           |
    |<-- INFO(session_id) -------|
```

There is no recovery hello, prepared, commit, or serving handshake. The Holder
accepts readiness only from the expected live child PID whose `INFO` response
reports the retained Session Identity.

Worker queues use per-worker cloned FUSE device fds (`FUSE_DEV_IOC_CLONE`); a
successor re-clones them from the single transferred fd. Only the transferred
fd's queue survives a crash, so requests in flight on worker clone queues at
that moment are ended by the kernel (callers observe `ECONNABORTED`), and
fuser inflight recovery resends or errors out only the requests that survived
on the retained queue. In-flight preservation across a crash is therefore
best-effort. Hot upgrade is unaffected: workers park at request boundaries
before the handoff, leaving the clone queues empty.

### 4.5 Retry rules

Recovery retry is intentionally narrow:

1. **Before a valid transfer:** the child exits without adopting resources;
   the Holder transfer is unchanged.
2. **After transfer but before readiness:** the Supervisor retries only after
   the child has been confirmed exited, or after terminating it and waiting
   for exit.
3. **If fuser recovery fails while workers are parked:** the child stands down
   without unmounting; the shared recovery resource remains reusable for retry.
4. **If workers resume but readiness never arrives:** the Holder still treats
   that child as the only reader and must terminate and reap it before retrying.

## 5. Readiness, teardown, and scope limits

For Failover-Protected Sessions, instance `INFO(session_id)` is the only serving
readiness signal. A clean serving-daemon shutdown still unmounts by path;
retained Holder descriptors do not keep the mount alive.

This contract does **not** cover Holder restart and rebinding, replacement
mount acceptance, cross-frontend sharing, backward-compatible version
negotiation, or exhaustive malformed-input guarantees. Continuity is defined by
same-host trust, the retained Session Identity, the canonical mountpoint, the
image digest, and the live FUSE resources.

## 6. Current verification surface

The maintained FUSE continuity acceptance surface contains exactly three
real-mount scenarios:

1. `TestFuseHotUpgrade` verifies Failover-Protected Session hot upgrade: the
   successor takes over the live FUSE session without remounting and service
   continues on the same kernel connection.
2. `TestFusePreReadyRollback` verifies hot-upgrade rollback: a pre-READY
   failure aborts the handoff and the predecessor resumes serving the unchanged
   live session.
3. `TestFuseFailoverMatrix` verifies combined continuity: a
   Failover-Protected Session retains its transfer, survives hot upgrade, then
   survives a crash, recovery, second crash, second recovery, content
   verification, and explicit shutdown.
