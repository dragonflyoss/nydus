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
Transfer carries one descriptor for a Standalone Session and two for a
Failover-Protected Session. It has no version field: its required metadata
fields and descriptor order are a frozen ABI, and evolution is additive only —
optional unknown metadata fields are the compatible evolution path, and old readers ignore
them. There is no version negotiation or versioned transfer envelope in the
wire protocol.

A fresh mount becomes a Failover-Protected Session only when started with
`--supervisor-socket`. Hot upgrade never creates or replaces that protection:
the successor inherits the existing Session Transfer. A Standalone Session
supports direct hot upgrade but not crash recovery. Converting it to a
Failover-Protected Session requires stopping it, unmounting, and creating a new
protected mount. Passing `--supervisor-socket` with `--upgrade` does not contact
the Holder or change the inherited protection.

| Fresh mount configuration | Hot upgrade | Crash failover |
| --- | --- | --- |
| `--control-socket` only | Direct predecessor/successor handoff | Not available |
| Also `--supervisor-socket` | The same direct handoff; protection is inherited | Coordinated by the external Supervisor and Holder |

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

Hot-upgrade either kind of session directly, without contacting a Holder:

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
| Upgrade | `--upgrade` | Adopts the predecessor's live session, preserving its protection |
| Recover | `--recover --supervisor-socket PATH` | Restores the Holder-retained session |

Fresh means a newly created mount, not a refresh of an existing daemon. It
creates a Standalone Session without `--supervisor-socket` and a
Failover-Protected Session with one. Fresh refuses to start while a live
instance or an unclaimed FUSE mount already exists at the mountpoint.

### Instance control endpoint

Every Fresh session publishes an owner-only Unix control socket before startup
completes. `INFO` reports the daemon PID, version, canonical mountpoint, image
digest, and optional Session Identity. A Standalone Session reports no protected
Session Identity. Both kinds accept `HANDOFF_BEGIN`; their control endpoints
provide liveness, instance discovery, and direct hot upgrade.

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

The control loop handles connections serially. A connection can occupy it
until close or its 30-second deadline, while an `INFO` client waits at most five
seconds for its exchange. An `INFO` timeout can therefore mean a busy control
loop, not a dead daemon. Failed discovery, including a missing endpoint, is
not a Recovery Lease: a manager must confirm the previous reader's exit before
starting recovery, as described below.

Upgrade and Recover also publish a replacement control endpoint. Recovery
stands down if publication fails. An upgraded daemon may continue serving
without one, but cannot itself be upgraded again. This is a degraded control
plane, not a failed takeover: file service can remain active while `INFO` and
further hot upgrades are unavailable. The daemon logs this explicitly; a
manager must not start another reader merely because it cannot discover this
instance through `INFO`.

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
- Standalone Sessions transfer only the live FUSE connection and negotiated
  INIT state; the successor remains standalone and creates no recovery resource;
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

### Deadlines and ownership

The pre-READY exchange has a 30-second preparation deadline. After sending
`READY`, the successor uses five-second verdict and process-exit waits, but an
ambiguous result has no overall completion deadline. It remains parked while
trying to retire the predecessor and confirm exit. Only `COMMITTED` or confirmed
predecessor exit permits it to resume; an explicit `ABORT` instead makes it
stand down. Expiry of a wait never grants read or unmount ownership.

The lifecycle state `Relinquished` means this process permanently gave up its
read and unmount rights. It covers both successful READY cutover and defensive
retirement after an undeliverable ABORT; it does not prove that the successor is
ready. Worker parking, session protection, and mount device identity are
separate from this ownership state.

| Stage | Who may read requests | Unmount and failure responsibility |
| --- | --- | --- |
| Fresh protected session awaiting `RETAINED` | Nobody; fresh workers are parked | The fresh daemon owns the new mount and unmounts if startup fails |
| Normal serving | Current owner | Clean shutdown may unmount only the recorded mount device |
| Handoff pause/adoption before READY | Dispatched predecessor requests finish, then both sides are parked | The coordinator resolves the handoff before teardown can claim ownership |
| Safe pre-READY abort | Predecessor resumes after sending ABORT or confirming successor exit | The adopted successor stands down without unmounting |
| ABORT cannot reach a potentially live successor | Predecessor exits its workers; successor follows its verdict/exit rules | Predecessor relinquishes ownership and must not unmount |
| READY sent, verdict ambiguous | Successor stays parked until COMMITTED or confirmed predecessor exit; explicit ABORT rolls back | A timeout alone authorizes neither resume nor unmount |
| Recovery preparation after the old reader exited | Nobody until fuser recovery succeeds; then the authorized successor | Failed adoption/recovery stands down without unmounting; a retry requires the child to have exited |

The [server tests](../nydus/src/fuse/upgrade/handoff/server.rs) cover committed
READY, explicit pre-READY abort, and undeliverable abort. The
[client tests](../nydus/src/fuse/upgrade/handoff/client.rs) cover READY write
failure and ambiguous cutover requiring predecessor retirement.
`relinquished_ownership_cannot_resume_or_claim_unmount` in the
[lifecycle tests](../nydus/src/fuse/upgrade/lifecycle.rs) and
`teardown_waits_for_the_handoff_coordinator_to_resolve` in the
[service tests](../nydus/src/fuse/service.rs) pin the ownership/teardown boundary.

## 4. Crash failover

### 4.1 Session Transfer

Hot upgrade and crash recovery share the Session Transfer representation.
A Standalone Session transfers one fd directly to its successor; a
Failover-Protected Session stores and transfers the fixed two-fd form:

```text
SessionTransferMetadata {
    session_id      // UUID for protected sessions; null or absent for standalone
    mountpoint      // canonical absolute path
    image_digest
    fuse_session_state
}

fd[0] = live FUSE connection
fd[1] = fuser recovery resource (protected sessions only)
```

Descriptor order is fixed by the transfer ABI. A hot-upgrade receiver derives
the expected count from `INFO` and requires metadata and descriptors to preserve
that protection and Session Identity. The Holder path always requires a
non-nil Session Identity and exactly two descriptors; a standalone transfer
cannot be retained or recovered. The Holder treats the protected descriptors
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
readiness signal accepted by the Supervisor for its expected child. It is not
a continuous filesystem-health guarantee, and its absence does not revoke a
running child's read ownership. A clean serving-daemon shutdown still unmounts
by path; retained Holder descriptors do not keep the mount alive.

This contract does **not** cover Holder restart and rebinding, replacement
mount acceptance, cross-frontend sharing, backward-compatible version
negotiation, or exhaustive malformed-input guarantees. Continuity is defined by
same-host trust, the retained Session Identity, the canonical mountpoint, the
image digest, and the live FUSE resources.

## 6. Current verification surface

The maintained FUSE continuity acceptance surface contains exactly three
real-mount scenarios:

1. `TestFuseHotUpgrade` verifies both Standalone and Failover-Protected Session
   hot upgrade: the successor takes over without remounting or contacting a
   Holder, and preserves the previous protection state.
2. `TestFusePreReadyRollback` verifies rollback for both kinds: a pre-READY
   failure aborts the handoff and the predecessor resumes the unchanged session.
3. `TestFuseFailoverMatrix` verifies combined continuity: a
   Failover-Protected Session retains its transfer, survives hot upgrade, then
   survives a crash, recovery, second crash, second recovery, content
   verification, and explicit shutdown.
