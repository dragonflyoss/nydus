# Nydus Snapshotter

`nydus-snapshotter` is a containerd proxy snapshotter for Nydus v3 images. It
skips downloading nydus data layers, starts one `nydus fuse` daemon per image,
and gives each container an overlay rootfs on top of the FUSE mount. Plain OCI
layers are downloaded and unpacked by containerd and mounted like containerd's
overlay snapshotter, so one Pod can mix nydus and OCI images.

This is a new implementation for the v3 format. The old
[containerd/nydus-snapshotter](https://github.com/containerd/nydus-snapshotter)
is a reference only; none of its compatibility paths (RAFS v5/v6, fscache,
tarfs, stargz, shared daemons, failover policies) carry over.

## Scope

| In scope | Not in scope |
| --- | --- |
| runc containers, `nydus fuse` mounts | Kata and other microVM runtimes |
| containerd 1.6 and 2.x, CRI local pull | Transfer-service pull without remote snapshot annotations |
| Nydus v3 images (`nydus-fs-version: "7"`) | Nydus v2 images (rejected until a v2 file system lands) |
| Plain OCI images (overlay) | FUSE failover and hot upgrade (separate work) |
| Registry credentials from Kubernetes secrets and docker config | CRI image-service proxy, registry mirrors |
| `PUT /api/v1/backend/auth/basic` in `nydus` | Repairing a cache after an unclean reboot (a `nydus` concern) |
| Per-image prefetch scope through a pull label | Preheat at pull time (start a daemon during pull) |
| Cache GC by TTL and disk watermarks | Summing daemon metrics across images |

Extension points exist for the parts expected to grow, each with one
implementation today:

- **FileSystem** — one per image format, selected by the bootstrap's
  `nydus-fs-version`. Only `7` (v3) is implemented; other nydus images fail
  `Prepare`. A v2 file system plugs in beside it.
- **Driver** — how a v3 daemon mounts an image. Only `fuse` is implemented;
  `fileio`, `ublk`, `fanotify` and `nbd` slot in behind the same interface.

## Architecture

```
 kube-system DaemonSet "nydus-snapshotter" (installer)
   └─ nydus-snapshotter install: copy binaries + unit files to the host,
      reload/restart over D-Bus, keep the service account token in sync

 host systemd
   ├─ nydus-snapshotter.socket   ─┐ gRPC socket held by systemd
   ├─ nydus-snapshotter.service  ◄┘ Before=containerd.service
   │    snapshot   overlay-style snapshotter on core/snapshots/storage
   │    fs         v3 file system: per-image instance, lock, render, start, wait,
   │               credential push
   │      └─ Driver: fuse
   │    systemd    units and slices over D-Bus
   │    nydusd     nydus daemon API client
   │    store      bbolt: instances, blob access times
   │    auth       kube_secret informer + docker config keyring
   │    registry   image reference, certs.d hosts.toml
   │    cache      blob cache GC
   │    metrics    /metrics
   └─ system-nydusd.slice/nydusd-<chainID>.service
        nydus fuse --bootstrap … --mountpoint …   (StartTransientUnit)
```

The snapshotter runs as a host unit ordered `Before=containerd.service`, like
stargz-snapshotter, soci-snapshotter, overlaybd and the old nydus-snapshotter's
DaemonSet (`ENABLE_SYSTEMD_SERVICE=true`). It must not run inside a Pod: with
the global snapshotter set to `nydus`, its own sandbox and rootfs would be
prepared through its own socket, so a node reboot, a new node or a rolling
update would leave nothing able to start it. The DaemonSet only installs and
upgrades it.

### cgroup layout

```
/sys/fs/cgroup
├── system.slice
│   ├── containerd.service
│   ├── nydus-snapshotter.service             snapshotter; no memory or CPU limit, OOMScoreAdjust=-999
│   └── system-nydusd.slice                   total for every nydusd: MemoryMax, MemoryHigh, CPUQuotaPerSecUSec
│       ├── nydusd-<chainID>.service          each: MemoryHigh, CPUQuotaPerSecUSec,
│       └── nydusd-<chainID>.service                OOMScoreAdjust=-999, LimitNOFILE
└── kubepods.slice/…                          installer Pod
```

Daemons are transient units forked by PID 1. They are never children of the
snapshotter, and their units carry no `PartOf=`, `BindsTo=` or `Requires=` on
`nydus-snapshotter.service`. So a snapshotter crash, OOM kill, restart or
upgrade leaves every daemon and mount running, and a daemon never shares the
snapshotter's cgroup budget. The snapshotter never forks a daemon itself; a
forked daemon would land in `nydus-snapshotter.service` and die with it.

The daemons run in one slice, `system-nydusd.slice`, which holds their total
budget. It is named as systemd names the slice of a service's instances
(`system-getty.slice` for `getty@`), and in systemd every `-` in a slice name
is a nesting level, so it sits under `system.slice`. Add its `memory_max` to
kubelet's `systemReserved`, or kubelet evicts Pods for memory they do not use.
The snapshotter itself carries no memory or CPU limit, as `containerd.service`
and `kubelet.service` carry none: a limit that kills it stalls every container
start on the node.

### Sizing the budget

By default every daemon together gets four CPUs (`cgroup.cpu_quota: 400%`) and
8GiB (`cgroup.memory_max`), is throttled from 6GiB (`cgroup.memory_high`), and
one daemon gets one CPU and is throttled from 1GiB (`cgroup.daemon`). `0`, or
`0%` for a CPU quota, lifts a limit.

Measured on a 36-CPU host with systemd 255 and 200 images of a few files each,
so the memory figures are a floor, not what a large image under load takes:

| What | Measured |
| --- | --- |
| One daemon start | 15 ms of CPU, 45 ms until ready |
| 200 daemons started at once, default limits | all ready within 1 s, none failed, 2.3 CPU seconds in total |
| 200 containers removed one after another, 30 a second | every daemon stopped within 6 s, as fast as the containers went |
| Idle daemon, default limits | 3 MiB, 12 threads |
| Idle daemon without a CPU quota | 6 MiB, 59 threads: nydus sizes its thread pools by the CPUs it may use |
| Snapshotter while it pulls 200 images and starts and stops 200 containers | 65 MiB at most, 7 CPU seconds |

- **CPU.** `cgroup.cpu_quota` is shared: the chunk decompression and
  verification of every image run inside it. Size it by how many containers
  read data they have not cached at the same time, as after a node restart,
  not by the number of daemons. A quota that runs out slows reads down and
  fails nothing.
- **Memory.** The slice accounts the daemons' own memory and the page cache of
  the blob cache files they write. The page cache is reclaimable:
  `memory_high` reclaims it and slows the daemons down. Memory that cannot be
  reclaimed reaching `memory_max` kills a daemon, which breaks the containers
  on its image, so keep `memory_max` well above the daemons' own memory and
  `memory_high` below it, so throttling always comes first.
- **Node.** Add `memory_max` to kubelet's `systemReserved`: the daemons run
  outside `kubepods.slice`.
- **Watching.** `systemctl status system-nydusd.slice` shows the slice's
  memory and CPU; its `memory.events` counts `high` and `oom_kill`, its
  `cpu.stat` counts `nr_throttled`; `nydus_snapshotter_running_daemons` is the
  number of daemons the budget is shared by.

Per-daemon memory uses `MemoryHigh` only. A `MemoryMax` hit is an OOM kill
(SIGKILL), and FUSE has no crash recovery: every container on that image would
read `ENOTCONN` until recreated. The total slice keeps `MemoryMax` as the node
backstop. Limits come from the snapshotter config and are hot-reloaded with
`SetUnitProperties`; a lower slice `MemoryMax` is applied only once the slice's
`memory.current` is below it, so a reload never triggers an OOM kill. A
snapshotter start applies them to the daemons that outlived it, and limits that
are deferred or fail to apply are retried by every teardown pass.

## Image detection

Layer annotations written by `nydusify` reach `Prepare` as labels through
`snapshots.FilterInheritedLabels` (see [Nydus Design](nydus.md#image-format)).

| At pull, per layer | Handling |
| --- | --- |
| `containerd.io/snapshot/nydus-blob: "true"` | Remote: commit an empty snapshot, return `AlreadyExists`; the blob is never downloaded |
| Anything else (OCI layers, the nydus bootstrap layer) | containerd downloads and unpacks it, exactly as with the overlay snapshotter |

| At container start, along the parent chain | Handling |
| --- | --- |
| No bootstrap and no nydus layer (OCI image) | Overlay over the layers' `fs` dirs, as containerd's overlay snapshotter |
| Bootstrap with `containerd.io/snapshot/nydus-fs-version: "7"` | Start or reuse the image's daemon; the FUSE mount is the lowest lower dir |
| Bootstrap with another version | Error until that format has a file system |
| A nydus layer but no labelled bootstrap | Error (see below) |

Each container resolves its own chain, so one Pod can run a nydus image and an
OCI image side by side.

These labels are honoured only on unpack keys (`extract-…`, the
`snapshots.UnpackKeyFormat` prefix), so container annotations cannot forge a
committed snapshot.

CRI adds `containerd.io/snapshot/cri.image-ref` (and the other `cri.*` labels)
only when `disable_snapshot_annotations = false`. The bootstrap snapshot keeps
the labels of its `Prepare`: the unpacker commits with the same label options and
`storage.CommitActive` stores them. A pull through containerd's API (for example
a preheat agent) must wrap its image handler with
`snapshotters.AppendInfoHandlerWrapper(ref)`, as CRI does, or its images cannot
run. Labels passed with `snapshots.WithLabels(…)` do not do: the unpacker adds
the layer annotations after them, so the image's own annotations would win.

Paths that pass no labels (`Image.Unpack`, the CRI fallback unpack in
`WithNewSnapshot`, 2.x image volumes) would commit a nydus bootstrap without its
label. A container `Prepare` that finds an ancestor with the `nydus-blob` label
but no labelled bootstrap fails instead of falling back to overlay. A pull
without any labels never gets that far: its data layers are downloaded and
applied as tar layers, which fails on the first `nydus.blob.v1` layer, as
`ctr image pull` on 1.6 does.

## Flows

### Pull

containerd's unpacker calls `Prepare("extract-<n> <chainID>", parent,
labels)` for each layer, with `containerd.io/snapshot.ref = chainID`.

- **nydus-blob**: create the active snapshot, `Commit(chainID, key, labels)`,
  return `errdefs.ErrAlreadyExists`. containerd's metadata layer finds the
  committed snapshot by `Walk` with the `snapshot.ref` and parent filter. If the
  commit loses a race (`storage.CommitActive` returns `AlreadyExists`), remove the
  temporary active snapshot and return `AlreadyExists` too.
- **bootstrap**: a normal unpack. Its parents are empty blob snapshots, so its
  mount is a read-write bind of its own `fs`.
- **OCI layer**: a normal unpack, as in containerd's overlay snapshotter.

A second pull of content already present never reaches the snapshotter: the
unpacker skips any chain ID whose snapshot exists.

### Container start

`Prepare` and `View` without `snapshot.ref`, and every `Mounts` call, resolve
the image the same way. All three must ensure the daemon. `Mounts` is called
again at task start and after a daemon death or reboot, and 2.x image volumes
mount the result of `Prepare` directly
(`internal/cri/server/container_image_mount.go`).

1. Walk the parents to the snapshot labelled `nydus-bootstrap`. None, and no
   unlabelled nydus layer: return overlay mounts.
2. Pick the file system by `nydus-fs-version` and require `cri.image-ref`.
   Either missing: fail with an error naming the setting to change.
3. `FileSystem.Mount` (below), keyed by the bootstrap's `snapshot.ref`.
4. Return the mounts:
   - Active: `overlay` with `lowerdir=<above…>:<nydusd mnt>`, `upperdir`,
     `workdir`, plus `userxattr` and `index=off` detected through `overlayutils`
     as containerd does.
   - View whose only lower is the nydusd mount: a read-only `bind`
     (`ro,rbind`). overlayfs refuses a read-only mount with a single lower and no
     upper.

containerd holds its per-snapshotter metadata read lock across backend
`Prepare` and `View`, and a waiting GC writer blocks new readers. A whole
`Mount`, the wait for another start or teardown of the image included, is
bounded by twice `mount_timeout` and the request context; stopping a daemon
whose start failed runs on a deadline of its own, twice `mount_timeout` again,
since the request may be done by then.

### Ensuring a daemon

`Mount(chainID)` runs under a per-chainID lock (a copy of containerd's
`internal/kmutex`, which v2 does not export); steps 2 and 3 also hold a read
lock on the cache GC.

1. Query the unit. `active` with a ready mount: upsert the record and return.
   `activating` or `deactivating`: wait for the job, then re-check.
2. Clean up: detach (`MNT_DETACH`) a stale FUSE mount on `mnt/`. Never remove
   the continuity lock files under `/run/nydus/fuse/`; ownership is an `flock`,
   so leftovers do not block.
3. Link `image/image.boot` into the instance directory, so a bootstrap removed
   from one containerd namespace cannot pull the file from under a daemon serving
   another. Seed the cache with each `image/<hex>.blob.meta`. `EEXIST` is
   success; `EXDEV` falls back to a streamed copy through a temporary file and
   `rename`, like `nydusify/internal/nydusfs/extract.go`. Layer content is
   untrusted: paths resolve within the layer (`continuity/fs.RootPath`) and only
   regular files are linked. Then write the instance record, so a secret
   change from now on reaches the daemon.
4. Render `config.yaml` (0600) under `/run` (see [Configuration](#configuration)).
5. `StartTransientUnit` with a buffered job
   channel and a bounded wait. On `UnitExists`, `ResetFailedUnit` and retry once,
   as runc's systemd driver does. The unit is `Type=notify`: nydus sends
   `READY=1` once its mount is in place and its API is published, so the start
   job ends when the daemon is ready, and fails when the daemon exits or
   `mount_timeout` passes (`TimeoutStartUSec`).
6. Check once what ready stands for: `mnt/` is a FUSE mount in mountinfo, and
   `GET /metrics` on the API socket answers 200. Then ask the daemon what it
   is with `GET /api/v1/daemon` and keep its version and capabilities in the
   instance record, as kubelet asks a CRI runtime for its version when it
   connects. The path carries the API version: a daemon answering `404` is of
   another API version, and its start fails with `FailedPrecondition`. Nothing
   compares version numbers, since daemons outlive snapshotter upgrades by
   design; an optional call is gated on its capability where it is made. Step 2 detached any leftover
   mount, so a FUSE mount here is the new daemon's. mountinfo lists resolved
   paths, so the mountpoint's parent is resolved first, as containerd's
   `mount.Lookup` does; the mountpoint itself is never stat'ed, which fails or
   hangs on a dead FUSE server.
7. On timeout or failure: `StopUnit`, wait for it, delete the record, return the
   error. The daemon's logs stay for diagnosis: no unit or record names them
   any longer, so a teardown pass removes them once they are a day old and the
   image is unused.

Two Pods on the same image share the daemon. The key is the bootstrap
**chain ID**, not the snapshot ID (which differs per containerd namespace) or a
random ID (which only a database can map back to an image). It is
content-addressed and stable across namespaces, tags and restarts, and the unit
name is derived from it, so reconcile needs no mapping table. Concurrent starts
serialise on the lock; a racing duplicate shows up as `UnitExists` instead of a
silent second daemon, which would try a FUSE takeover on the same mountpoint.

### Remove and teardown

containerd calls backend `Remove` from its garbage collector while holding the
per-snapshotter metadata write lock, and any error other than
`FailedPrecondition` aborts the whole GC pass. So `Remove` only changes the
metastore, removes directories asynchronously like containerd's overlay
snapshotter with `sync_remove = false`, and signals the teardown worker. It never
returns a teardown error.

The worker (on every `Remove` and `Cleanup`, coalesced into one pass while a
pass runs, at start and every minute; each pass bounded by that minute) walks
the metastore once to mark the images any active or view snapshot of any
namespace stands on, skips daemons both marked and running without a lock or a
D-Bus call, and for every other daemon of `system-nydusd.slice` walks the
metastore again under the per-chainID lock, as containerd's GC marks before it
sweeps. A daemon still unused gets `StopUnit` (wait for the job; `NoSuchUnit` is
success), `Driver.Unmount`, and its record, instance directory and log directory
deleted. Eight daemons are handled at a time, as kubelet kills the containers
of a pod together; one that fails to stop is logged and tried again by the
next pass, and does not hold up the others. Mount and teardown hold the same
lock, so no interleaving stops a daemon in use.
Driving it from the unit list means a teardown interrupted by a snapshotter
restart is picked up again.

Backend `Remove` runs on the next metadata GC, so a daemon can outlive its last
container by one GC interval.

### Snapshotter start and stop

1. Open both bbolt files with a timeout.
2. Take the gRPC listener from systemd socket activation
   (`activation.Listeners`, as soci-snapshotter does); without activation, dial
   the path first and remove it only when nothing answers, then listen. Message
   size limits match containerd's proxy client.
3. In the background, reconcile: records whose unit is gone are deleted, and the
   teardown worker runs once.
4. Serve the snapshots API and, on the same socket, the
   [gRPC health checking protocol](https://github.com/grpc/grpc/blob/master/doc/health-checking.md)
   with grpc-go's `health` server, as containerd (`plugins/services/healthcheck`)
   and BuildKit do. A `Check` that answers shows the process alive, which never
   depends on the API server; its status is `SERVING` once the secret informer,
   when enabled, is synced, and `NOT_SERVING` before that and while the
   snapshotter stops. Probe it with
   `grpc_health_probe -addr unix:///run/nydus-snapshotter/nydus-snapshotter.sock`.
   `READY=1` goes to systemd once gRPC serves (`Type=notify`, as
   `containerd.service`), so containerd, ordered after the unit, starts
   against a ready snapshotter.
5. Every teardown pass logs and counts, once, a daemon that exited while it
   still had users (`nydus_snapshotter_daemon_unexpected_exits_total`), keeping
   its record so its files are cleaned up once unused; the next `Mounts` starts
   a fresh one. A daemon gone with a reboot, whose tmpfs runtime dir is gone
   too, is not counted. The pass also sets `nydus_snapshotter_running_daemons`.
6. Every teardown pass probes the daemons in use, eight at a time: the mount
   is in mountinfo and `GET /metrics` answers. A daemon that stops answering
   is logged once, and once more when it answers again, as kubelet's prober
   reports a result that changed; `nydus_snapshotter_unresponsive_daemons` holds
   how many do not answer. Such a daemon may still serve its containers, so it
   is never stopped. A daemon whose whole process is stuck is caught by
   systemd instead: nydus sends `WATCHDOG=1` from a thread of its own, and a
   daemon silent for `nydusd.watchdog_timeout` is killed (`WatchdogUSec`). The
   keep-alive never depends on a FUSE request or the registry, so a slow
   backend cannot trip it.

On SIGTERM: `STOPPING=1`, then `GracefulStop` with a deadline, then `Stop`;
in-flight handlers finish before the bbolt files close (`WaitForHandlers`).
Units and mounts are left running.

### Credentials

Sources, in order:

1. **kube_secret** (optional): an informer over `kubernetes.io/dockerconfigjson`
   secrets in all namespaces, narrowed by a configured label selector (field
   selector `type=`, a transform keeps only the `managedFields` entries that own the data and drops annotations). The
   snapshotter authenticates with a kubeconfig whose `tokenFile` the installer
   keeps in sync with its projected service account token; client-go re-reads
   rotated tokens. Matching follows kubelet keyring semantics: the longest
   host-and-path prefix wins. Among equal keys, the secret updated most recently
   (its newest `managedFields` time, which survives a restart) wins (ties: `namespace/name` order); the ones it shadows are logged at debug level.
2. **docker config** (always on): the first file that reads and parses in
   kubelet's search order
   (`/var/lib/kubelet/config.json`, `/root/.docker/config.json`, then
   `/.docker/config.json`), or the configured path. Only `auths` is read; `credsStore` and `credHelpers` log a
   warning, because their helper binaries are not on the snapshotter's path.
   `docker.io` maps to the `https://index.docker.io/v1/` key.

Behaviour:

- At daemon start the credential is written into `config.yaml`. Only
  `username:password` is supported; `identitytoken` and `registrytoken` entries
  are skipped (the snapshotter renders `auth` only and calls the `basic`
  route only, and the `auth` docker stores beside a token is a placeholder),
  and only a lookup with no usable candidate is
  an error. An empty entry, as `docker login`
  with a credential store writes, means anonymous access, as containerd's
  `ParseAuth` reads it.
- Until the informer has synced, `Prepare`, `View` and `Mounts` that need a new
  daemon return `errdefs.ErrUnavailable` (fail fast). After the first sync the
  cache survives API-server outages.
- The snapshotter retries a missing or invalid kubeconfig every few seconds
  instead of failing to start: the installer keeps it on tmpfs, so after a
  reboot it appears only once the installer Pod runs again, and that Pod needs
  the snapshotter serving. Meanwhile the health status is `NOT_SERVING` and
  nydus images return `ErrUnavailable`; OCI images are unaffected.
- Once the secrets are synced, and then on every secret change, the chain ID
  of every recorded instance goes onto a rate-limited workqueue keyed by chain
  ID, as in sample-controller; the secrets listed at start are reported in one
  pass, not one per secret. Only a daemon listing the `backend_auth_basic` capability
  is pushed to: one that does not serve the call is skipped without it. A
  worker resolves the credential for that instance again and calls
  `PUT /api/v1/backend/auth/basic` only when it differs from the last one pushed, so
  a change to another registry's secret costs a lookup and no call.
  `404` means the daemon lacks the route or has no registry backend; `400`,
  `403`, `413` or a credential that is not UTF-8 `username:password` means it
  is refused: each is logged and counted once, and that credential is not sent
  to the daemon again, since a retry fails the same way. Other failures retry
  with backoff, and the retry is sent whatever was pushed before, because the
  daemon may or may not have taken the credential. A daemon that is not
  identified or does not listen yet while its start may still run, twice
  `nydusd.mount_timeout` from its record, resolved its credential before the
  change, so the push is retried until it listens; a stopped daemon gets the
  credential when it starts. A record written before its daemon's version was
  known tells no capability, so that daemon is asked.
- A secret delete keeps the daemon's last credential.
- The docker config is not watched: a daemon started later reads a changed
  file, a running one gets it with the next secret change or snapshotter
  restart, and never without kube_secret.

Credentials never go into unit properties (`ExecStart`, `Environment`), because
any user can read those through `systemctl show`, and never onto persistent
disk.

### Daemon auth API

Implemented in `nydus` (`nydus/src/api_server.rs`) on the `--apiserver` socket:

```http
PUT /api/v1/backend/auth/basic HTTP/1.1
Content-Type: application/json

{"username": "<username>", "password": "<password>"}
```

`PUT /api/v1/backend/auth/bearer` with `{"token": "<bearer token>"}` replaces
the bearer token the same way and answers alike. Each credential has a route
of its own, named after its HTTP authentication scheme, as Consul gives each
agent token one (`PUT /v1/agent/token/<kind>`), and the bodies name their
fields as the Docker Engine API and a Kubernetes secret do. The snapshotter
calls the `basic` route only, which keeps a `registry_token` the daemon was
given; it takes the user name and the password apart from the base64 `auth`
it renders into the daemon config.

| Answer | When |
| --- | --- |
| `204 No Content` | The registry backend's basic credential is replaced and the bearer tokens fetched with the old one are dropped; the same credential changes nothing |
| `400 Bad Request` | The body is not that JSON object or `username` holds a colon |
| `403 Forbidden` | The peer's UID differs from the daemon's (`SO_PEERCRED`, like the control route) |
| `404 Not Found` | The daemon has no registry backend |
| `405 Method Not Allowed` | The method is not `PUT`; the answer carries `Allow: PUT` (RFC 9110 §15.5.6) |
| `408 Request Timeout` | The body did not arrive within the API's request timeout |
| `413 Content Too Large` | The body is over 64 KiB |
| `500 Internal Server Error` | The backend failed to replace the credential for another reason |

Errors carry `{"message": "…"}`. The route is an idempotent full replacement of
a sub-resource, so it uses `PUT` (RFC 9110 §9.3.4); the credential is never
echoed back.

### Prefetch

The rendered `prefetch.scope` comes from, highest first:

1. Label `containerd.io/snapshot/nydus-prefetch` (`none|ondemand|all|auto`) on
   the bootstrap snapshot. A layer annotation of the image sets it on every pull
   path, CRI included, and it only takes effect on the first pull of the
   content.
2. `nydusd.config.prefetch.scope` in the snapshotter config (default `auto`).

The other `prefetch` keys come from `nydusd.config.prefetch`. An invalid label
value fails `Prepare`.

### Preheat

A preheat downloads every blob of an image to the node before a container
uses it. The client calls the `NydusSnapshotter` gRPC service on the
snapshotter's socket, where containerd calls the snapshots service; the proto
lives in [dragonflyoss/api](https://github.com/dragonflyoss/api)
(`pkg/apis/nydussnapshotter/v1`), with Go, Rust and Python bindings.

| RPC | What it does |
| --- | --- |
| `PreheatImage` | Resolves an image containerd has pulled and queues its preheat. A pending or running preheat of the same image keeps going and no second one is started. |
| `StatImage` | Resolves the image and returns the state of its preheat and of every blob of the image. |

Both name the image and return no ID, as `PreheatImage` and `StatImage` of
Dragonfly's scheduler do. There is no call to cancel or delete: a preheat
runs to its result, and the cache is left to its GC.

```text
client ─ PreheatImage(image, namespace, basic_auth | bearer_token)
   │
   ▼
snapshotter ── containerd: reference ─▶ image ─▶ diff IDs ─▶ chain IDs
   │           snapshots:  chain IDs ─▶ committed bootstrap layer
   │           queue:      pending until one of max_concurrent_images slots is free
   ▼
systemd ────── nydusd-preheat-<chainID>.service, Type=exec, in the daemons' slice
   │           nydus preheat --bootstrap … --config … --state-file …
   ▼
registry or Dragonfly ─▶ the shared blob cache
```

- **Image.** The request names a reference and a containerd namespace
  (`k8s.io` when empty). The snapshotter asks containerd for the image's
  layers, as `Image.IsUnpacked` does, and takes the bootstrap layer it
  unpacked among them, so any spelling containerd knows the image by works.
  A preheat is kept by the chain ID of that layer: one image has one
  preheat, whatever its references, and `StatImage` finds it by any of them.
- **Credential.** The request must carry one: a username and a password, or a
  bearer token. It is used by this preheat only. It is rendered into the
  process's `config.yaml` on tmpfs and removed when the process exits; it
  never reaches the keychain, a daemon, a unit property, a log or an API
  answer. A pending or running preheat ignores the credential of a second
  request.
- **Process.** One `nydus preheat` process per image, a transient unit with
  the cgroup limits of one daemon. It shares the cache directory with the
  daemons: a blob one of them is fetching is not fetched twice, and a running
  daemon of the image reads what the preheat downloads. It downloads
  `nydusd.config.prefetch.concurrent_blob_count` blobs at once, each bounded
  by `request_timeout`.
- **States.** `PENDING`, `RUNNING`, then `SUCCEEDED` or `FAILED`. The first
  blob that fails ends the preheat; `description` names the blob and the
  error. A new `PreheatImage` fetches only what is missing. A result shows
  once the process is gone and its config removed.
- **Progress.** `blobs` lists every blob of the image: its `digest`, as the
  registry and the image manifest name it, its `content_length` and
  `finished_content_length` in uncompressed bytes, and `is_finished`. An
  OCI descriptor carries a digest and a size the same way, and Dragonfly's
  `StatImage` lists its layers with `is_finished`; like it, the answer has
  no totals, which a client adds up. The list comes from the `state.json`
  the process rewrites, refer to [Preheat](nydus.md#preheat).
- **Restart.** Nothing is persisted. A running process outlives the
  snapshotter and is recovered when it starts; a pending preheat is
  lost, and a result is kept for 24 hours or until the node reboots.
- **Cache GC.** No rule is added: a blob being downloaded holds its prefetch
  lock, and a preheated blob ages from its download like any other.

Errors: `InvalidArgument` (no credential or a bad reference),
`NotFound` (containerd has no such image, or the image has no preheat: it
was never preheated or its result expired),
`FailedPrecondition` (not a nydus image this snapshotter unpacked) and
`Unavailable` (containerd cannot be reached).

### Cache GC

The scheme follows Dragonfly's dfdaemon GC (`dragonfly-client/src/gc`). The unit
is one blob: `<hex>.blob.data`, `.blob.meta`, `.group.map` and `.prefetch.lock`.

- A ticker (`gc.interval`) runs two passes:
  - **TTL**: blobs whose `updated_at` is older than `blob_ttl` are evicted.
  - **Disk watermark**: when usage reaches `disk_high_threshold_percent`, evict
    the least recently used blobs until usage would drop to
    `disk_low_threshold_percent`. With `disk_threshold` set, usage is the cache's
    own bytes against it, a logical quota as dragonfly-client's
    `content_linux.rs` computes. Without it, usage is `statfs` of the cache
    filesystem, so container upper dirs filling the disk can evict every unused
    blob each round; set `disk_threshold` to bound the cache by its own size.
- `updated_at` lives in the bbolt bucket `v1/blobs`, touched when a daemon
  referencing the blob starts or stops. File atime is unreliable under
  `relatime` and `noatime`.
- Never evicted: blobs referenced by a running daemon (its instance record,
  written before its unit starts and deleted after it stops; while a daemon
  runs without a record, as after `nydusd.db` was lost, a round evicts nothing
  until the daemon's next mount records it again),
  blobs whose files are all hard links held elsewhere, files modified in the
  last few minutes, and blobs whose `.prefetch.lock` cannot be `flock`ed
  non-blocking. Blobs of committed but idle images may be evicted; a daemon
  refetches data and `.blob.meta` on demand.
- Every round also removes blobs no committed bootstrap references and stale
  `.blob-meta-*.tmp` files. A bootstrap layer whose image dir cannot be read is
  skipped, never failing the round. Evicted blobs are forgotten in one bbolt
  transaction.
- GC takes the cache write lock with `TryLock`, a batch of 16 blobs at a time, so
  a starting daemon waits for one batch at most; a round a starting daemon
  interrupts retries after a few seconds.

## Daemon unit

```
Unit               nydusd-<chainID>.service   (79 chars; no escaping needed)
Slice              system-nydusd.slice
Type               notify                      # READY=1 once mounted and serving
NotifyAccess       main
TimeoutStartUSec   <mount_timeout>
WatchdogUSec       <nydusd.watchdog_timeout>   # off when 0
Restart            no
CollectMode        inactive-or-failed
KillSignal         SIGTERM                     # nydus unmounts on SIGTERM
TimeoutStopUSec    <mount_timeout>
Before             containerd.service kubelet.service
OOMScoreAdjust     -999
LimitNOFILE        1048576
MemoryHigh         <cgroup.daemon.memory_high>
CPUQuotaPerSecUSec <cgroup.daemon.cpu_quota>
StandardOutput     journal
SyslogIdentifier   nydusd
LogExtraFields     NYDUS_CHAIN_ID=sha256:<chainID>
ExecStart          /opt/nydus-snapshotter/bin/<ver>/nydus fuse
                     --bootstrap  /var/lib/nydus-snapshotter/nydusd/<chainID>/image.boot
                     --config     /run/nydus-snapshotter/nydusd/<chainID>/config.yaml
                     --mountpoint /var/lib/nydus-snapshotter/nydusd/<chainID>/mnt
                     --apiserver  unix:///run/nydus-snapshotter/nydusd/<chainID>.sock
                     --log-dir    /var/log/nydus-snapshotter/nydusd/<chainID>
                     --log-level  <nydusd.log_level>
                     --log-max-files <nydusd.log_max_files>
                     --fsname     nydus-<chainID[:12]>
```

D-Bus: connect with `dbus.NewWithContext`, which falls back to
`/run/systemd/private` as root, and reconnect on `dbus.ErrClosed` as runc's
systemd cgroup driver does. `CPUQuota` is not a D-Bus property;
`CPUQuotaPerSecUSec` is (1 CPU = 1 000 000), rounded to 10 ms like runc.

`ExecStart` is set without systemd's ignore-failure flag, the `-` prefix: a
daemon that exits with an error or is killed fails its unit, and the journal
records its exit status. The bool of go-systemd's `PropExecStart` is that
flag, despite its name `uncleanIsFailure`, so it is passed as `false`.

## Configuration

`/etc/nydus-snapshotter/config.yaml`, decoded with `gopkg.in/yaml.v3` as the Dragonfly
components and the nydus daemon config are: strict (`KnownFields`) at start,
while a reload that fails logs a warning and keeps the running config. Keys are
snake_case, as in nydus-config. Durations use a `UnmarshalText` type (`10s`);
sizes use `docker/go-units` (`1GiB`). `Validate()` runs after defaults are
applied. The `cgroup` and `nydusd.config` sections are reloaded by polling the
file and comparing bytes, as Dragonfly does (`cmd/dependency`), which survives
ConfigMap symlink swaps. A change of `nydusd.config` applies to newly started
daemons, except its `runtime_dir` and `storage.dir`; those and every other
change log a warning and need a restart.

The file below states the built-in defaults, which a missing key falls back
to, as containerd's `config default` prints its own; a test keeps the shipped
`config.yaml` equal to them. That includes the cgroup limits: a
daemon without a CPU quota sizes its thread pools by the CPUs of the node, so
running unlimited takes an explicit `0`. The file itself must exist and load:
every command ends with the error on a missing or invalid `config.yaml`, at
the default path too.

```yaml
# Persistent data: snapshots, the blob cache and daemon instances.
root_dir: /var/lib/nydus-snapshotter
# Transient data on tmpfs: daemon API sockets and rendered configs, which
# carry credentials.
runtime_dir: /run/nydus-snapshotter

grpc:
  # Unix socket containerd connects to, which also answers gRPC health checks.
  addr: /run/nydus-snapshotter/nydus-snapshotter.sock

log:
  # One of trace, debug, info, warn or error.
  level: info

metrics:
  # Address of /metrics, empty to disable.
  addr: 127.0.0.1:4010

registry:
  # containerd certs.d directory of <host>/hosts.toml and docker-style certificates.
  config_path: /etc/nydus-snapshotter/certs.d

auth:
  docker_config:
    # Docker config.json with registry credentials, empty for kubelet's search order.
    path: ''
  kube_secret:
    # Read credentials from kubernetes.io/dockerconfigjson secrets.
    enable: false
    kubeconfig: /run/nydus-snapshotter/kubernetes/kubeconfig
    label_selector: ''

nydusd:
  driver: fuse
  binary: /opt/nydus-snapshotter/bin/current/nydus
  log_dir: /var/log/nydus-snapshotter/nydusd
  # Log level of a daemon, one of trace, debug, info, warn or error.
  log_level: info
  # Log files a daemon keeps.
  log_max_files: 6
  mount_timeout: 10s
  # systemd kills a daemon that sent no keep-alive for this long, 0 to disable.
  watchdog_timeout: 3m
  # Config of each daemon, named and laid out as nydus-config. The backend type
  # is always registry; addr, repository and auth come from the image, and
  # http.tls from certs.d.
  config:
    # Runtime directory the daemons share: Dragonfly seed peers and FUSE hot
    # upgrade state.
    runtime_dir: /run/nydus
    backend:
      config:
        # Requests to the origin registry.
        http:
          # A whole request, its body included.
          request_timeout: 1m
          # The longest wait for the connection, the response and each part of
          # its body.
          request_read_timeout: 5s
          max_retries: 3
          proxy:
            # HTTP forward proxy of every registry request, with its scheme,
            # empty to connect to the origin. Not used with dragonfly.
            addr: ''
        # Requests through Dragonfly seed peers, set when scheduler_endpoint is
        # not empty.
        dragonfly:
          scheduler_endpoint: ''
          request_timeout: 1m
          request_read_timeout: 5s
          max_retries: 1
        # The client an on-demand read falls back to when Dragonfly or the
        # proxy cannot serve it.
        fallback:
          request_timeout: 1m
          request_read_timeout: 5s
          max_retries: 0
          # Origin requests per second, at least 1.
          rate_limit: 1
    storage:
      # Blob cache directory the daemons share, empty for <root_dir>/cache.
      dir: ''
      # Skip the crc32c check of decoded chunk groups.
      skip_verify_checksums: false
      # Compressed bytes one on-demand read covers, 0 for the missed chunk
      # group alone.
      fetch_size: 2097152
    prefetch:
      # Blobs prefetched at once.
      concurrent_blob_count: 10
      # Prefetching one whole blob.
      request_timeout: 1h
      # A failed prefetch read is sent once more after this long to twice it.
      retry_interval: 6h
      # One of none, ondemand, all or auto.
      scope: auto

cgroup:
  # Slice the daemons run in, which holds their total budget below.
  slice: system-nydusd.slice
  # Total of every daemon.
  memory_max: 8GiB
  memory_high: 6GiB
  cpu_quota: 400%
  daemon:
    memory_high: 1GiB
    cpu_quota: 100%

gc:
  interval: 15m
  policy:
    # An unused blob's cache is evicted this long after a daemon last used it.
    blob_ttl: 720h
    # Capacity the disk thresholds apply to, 0 for the whole filesystem.
    disk_threshold: '0'
    disk_high_threshold_percent: 80
    disk_low_threshold_percent: 60

# A preheat downloads every blob of an image containerd has pulled, started
# over the gRPC socket by PreheatImage.
preheat:
  # Images preheated at once, the rest wait. Each one downloads
  # nydusd.config.prefetch.concurrent_blob_count blobs at once.
  max_concurrent_images: 1
  # Socket of containerd, asked for the layers of the image a preheat names.
  containerd_addr: /run/containerd/containerd.sock

# Read only by the installer, nydus-snapshotter install, once when it starts;
# the snapshotter ignores it.
installer:
  # Where the Pod mounts the root filesystem of the host, the payload of the
  # image (bin/ and systemd/), its service account token and the certs.d of
  # the ConfigMap. They follow the volumeMounts of the DaemonSet.
  rootfs_dir: /host
  payload_dir: /opt/nydus-snapshotter/payload
  token_dir: /var/run/secrets/kubernetes.io/serviceaccount
  registry_config_path: /etc/nydus-snapshotter/certs.d
  # How often the token and the config are copied to the host and the node
  # label is checked.
  sync_interval: 1m
  node_label:
    # Label the node NODE_NAME names d7y.io/nydus-snapshotter=true while the
    # snapshotter serves and containerd has loaded it.
    enable: false
    # Socket of the host's containerd, asked whether it loaded the snapshotter.
    containerd_addr: /run/containerd/containerd.sock
```

The `installer` section holds every setting of `nydus-snapshotter install`,
which has no flag of its own: what is the same on every node belongs in the
config file the nodes share, and only what differs per node, the node name,
comes from the environment, as kubelet splits `KubeletConfiguration` from its
flags. The installer reads the section once, when it starts, so a change
takes a rollout of the DaemonSet. The snapshotter ignores it, also on a
reload.

`registry.config_path` is a containerd certs.d directory, or a list of them as
CRI's `config_path` is, read with containerd's lookup and its
[hosts.toml](https://github.com/containerd/containerd/blob/main/docs/hosts.md)
format, so it can share the files containerd uses. A daemon reads from one
registry, the `server`: `[host]` mirrors are ignored, a `server` of
`https://docker.io` means `registry-1.docker.io`, and a `_default/hosts.toml`
that names a `server` is skipped as a whole, because its TLS settings describe
that server and not the registry the daemon reaches.

`Validate()` also checks that each daemon API socket path stays under the
108-byte `sun_path` limit; the default is 99 bytes.

### Daemon config

A daemon's config is a [nydus-config](nydus.md#storage-config) file the
snapshotter writes when it starts the daemon:
`/run/nydus-snapshotter/nydusd/<chainID>/config.yaml` (0600, tmpfs). There is
no template file. What all daemons share is set in `nydusd.config` of
`config.yaml` with nydus-config's own key names and layout, beside the
settings the snapshotter runs a daemon with, as a containerd runtime entry
holds `runtime_type`, `runtime_path` and the runtime's own `options`; the rest
is filled per image:

```text
config.yaml      nydusd.config ─────────────────────┐
image reference  backend.config.{addr,repository} ──┤
keyring          backend.config.auth ───────────────┼─▶ <chainID>/config.yaml
certs.d          backend.config.http.tls ───────────┤
prefetch label   prefetch.scope ────────────────────┘
```

| Field | Source |
| --- | --- |
| `backend.config.addr` | Image reference host (`docker.io` → `https://registry-1.docker.io`); `server` from `hosts.toml`, parsed as containerd does (no scheme means `https`, a `/v2` API root is stripped because nydus appends it); `override_path` is rejected |
| `backend.config.repository` | Image reference path (`library/` for docker.io official images) |
| `backend.config.auth` | Keyring |
| `backend.config.http.tls` | `hosts.toml`: `skip_verify`, CA files concatenated into one PEM; `client` certificates are rejected (unsupported by nydus); `[host]` mirrors are ignored |
| `backend.config.http` | `nydusd.config.backend.config.http`, key for key; `proxy` when its `addr` is set |
| `backend.config.dragonfly` | `nydusd.config.backend.config.dragonfly`, key for key, when `scheduler_endpoint` is set (requires a `nydus` built with the `dragonfly` feature, as release builds are) |
| `backend.config.fallback` | `nydusd.config.backend.config.fallback`, key for key |
| `backend.type` | Always `registry` |
| `runtime_dir` | `nydusd.config.runtime_dir` |
| `storage` | `nydusd.config.storage`, key for key; `dir` is `<root_dir>/cache` when empty |
| `prefetch` | `nydusd.config.prefetch`, key for key; for `scope` see [Prefetch](#prefetch) |

## Paths

Every directory carries the program's name, `nydus-snapshotter`, under `/etc`,
`/run`, `/var/lib`, `/var/log` and `/opt`, as containerd, stargz-snapshotter
and soci-snapshotter name theirs and as systemd's `ConfigurationDirectory=`,
`RuntimeDirectory=`, `StateDirectory=` and `LogsDirectory=` lay a service out.
No path carries a format version: versions live in the data, the stores'
`v1` buckets. None of them is a path of the v2
snapshotter (`/etc/nydus`, `/run/containerd-nydus`, `/var/lib/containerd-nydus`).

| Path | Contents | Writer → reader |
| --- | --- | --- |
| `/usr/local/bin/nydus-snapshotter` | Snapshotter binary | Installer → systemd |
| `/etc/systemd/system/nydus-snapshotter.{service,socket}` | Snapshotter units | Installer → systemd |
| `/etc/nydus-snapshotter/config.yaml` | Snapshotter config | Installer (from ConfigMap) → snapshotter |
| `/etc/nydus-snapshotter/certs.d/<host>/hosts.toml` | Registry TLS and scheme | Installer → snapshotter |
| `/run/nydus-snapshotter/kubernetes/{kubeconfig,token,ca.crt}` | API access for kube_secret | Installer → snapshotter |
| `/run/nydus-snapshotter/nydus-snapshotter.sock` | gRPC socket | systemd / snapshotter → containerd |
| `/run/nydus-snapshotter/nydusd/<chainID>.sock` | Daemon API | nydusd → snapshotter |
| `/run/nydus-snapshotter/nydusd/<chainID>/{config.yaml,ca.pem}` | Rendered daemon config (holds the credential) | snapshotter → nydusd |
| `/run/nydus-snapshotter/preheat/<chainID>/config.yaml` | Rendered preheat config (holds the credential), removed when the process exits | snapshotter → nydus preheat |
| `/run/nydus-snapshotter/preheat/<chainID>/{preheat.json,state.json}` | Preheat record; progress and result | snapshotter; nydus preheat → snapshotter |
| `/var/lib/nydus-snapshotter/metadata.db` | Snapshot metastore (bbolt) | snapshotter |
| `/var/lib/nydus-snapshotter/nydusd.db` | Instances and blob access times (bbolt) | snapshotter |
| `/var/lib/nydus-snapshotter/snapshots/<id>/{fs,work}` | Overlay upper and work dirs; bootstrap `fs/image/` | snapshotter, containerd |
| `/var/lib/nydus-snapshotter/nydusd/<chainID>/{image.boot,mnt/}` | Linked bootstrap, FUSE mountpoint | snapshotter, nydusd |
| `/var/lib/nydus-snapshotter/cache/` | Shared blob cache | nydusd |
| `/var/log/nydus-snapshotter/nydusd/<chainID>/` | Daemon file logs, kept a day after a failed start; stderr goes to the journal | nydusd |
| `/var/log/nydus-snapshotter/nydusd/preheat/` | File logs of every preheat process | nydus preheat |
| `/opt/nydus-snapshotter/bin/<version>/nydus`, `/opt/nydus-snapshotter/bin/current` | Daemon binaries; a switch keeps the current and previous versions | Installer → systemd |
| `/run/nydus-snapshotter/restart-pending` | Units due a restart, until they restart | Installer |

`<chainID>` is the hex digest of the bootstrap layer's chain ID.

The cache sits under the same mount as the snapshots, so linking `.blob.meta`
and `image.boot` does not hit `EXDEV`.

The bbolt `nydusd.db` holds:

- `v1/version`: the count of compatible additions to the `v1` layout, as
  containerd's metadata store keeps one; an incompatible change moves to a
  `v2` bucket.
- `v1/instances`, keyed by chain ID, as JSON: `{chain_id, driver, image_ref,
  registry_host, bootstrap, blobs, mountpoint, api_socket, unit, version,
  capabilities, created_at}`. There is no PID; systemd is the source of truth
  for process state.
- `v1/blobs`, keyed by blob ID: the time a daemon referencing the blob last
  started or stopped (`time.MarshalBinary`).

Side effects (D-Bus, mount waits) never run inside a bbolt write transaction.

## Deployment

- **Host units**, installed by the DaemonSet (or baked into the node image):
  - `nydus-snapshotter.socket` (`ListenStream=` the gRPC path, `SocketMode=0600`)
    and `nydus-snapshotter.service` (`Before=containerd.service`,
    `OOMScoreAdjust=-999`, default `KillMode=control-group`).
- **Helm chart `nydus-snapshotter`** in
  [dragonflyoss/helm-charts](https://github.com/dragonflyoss/helm-charts/tree/main/charts/nydus-snapshotter),
  the only Kubernetes deployment. Its DaemonSet runs in `kube-system`,
  `system-node-critical`, `hostNetwork` with `dnsPolicy: Default`,
  `privileged`, `tolerations: [{operator: Exists}]`, with the host root at
  `/host` and `/run/dbus` and `/run/systemd` mounted at their own paths. It
  needs no host PID namespace: D-Bus authorizes root by uid.
  - Runs `nydus-snapshotter install` with no argument. The installer reads
    the config it installs at the path the snapshotter defaults to,
    `/etc/nydus-snapshotter/config.yaml` (`--config` names another), where
    the DaemonSet mounts the ConfigMap, as the charts of
    node-feature-discovery and Dragonfly's dfinit mount a ConfigMap at their
    binary's default config path. The image carries the default config there.
    The `certs.d` it installs is the directory
    `installer.registry_config_path` names, where the same mount puts the
    ConfigMap's, as Istio's CNI installer is told its source and target
    directories and derives neither.
    Its own settings are the `installer` section of that file. A file that
    cannot be loaded ends the installer with the error before it writes
    anything to the host, the service account token included.
  - The installer checks that the host's systemd answers before it writes
    anything to the host, as kubeadm runs its preflight checks first;
    validates `config.yaml` and every
    `hosts.toml` by the rules a daemon start applies, rejects a config whose
    `grpc.addr`, `nydusd.binary`, kubeconfig or certs.d directory is not the
    path it sets up, copies binaries, units and config from its image and
    ConfigMap to the host, then `EnableUnitFiles` over D-Bus. A file is
    compared by digest and copied as a stream to `<file>.tmp` beside it, synced
    and renamed, as the Calico and Cilium CNI installers do, so no binary is
    held in memory and a copy that died is overwritten by the next. Only a
    change the snapshotter reads at start restarts it: its binary, its unit
    files or `config.yaml`; otherwise both units are started, which a running
    unit ignores, as a package's `postinst` does. A socket change restarts the
    socket, which restarts the running service with it (`Requires=`); the
    installer then only starts the service, which waits for that restart
    instead of causing another. A start or restart is given five minutes,
    over the 90s systemd allows a stop and a start each by default. A new
    `nydus` lands in its own version directory behind the `current` link, read
    per daemon start. The units due a restart are recorded on tmpfs before any
    file is written, so a run that dies midway is finished by the next. Host
    paths resolve within `/host`, so an absolute symlink on the host is
    followed there (`continuity/fs.RootPath`).
  - Stays running to keep `/run/nydus-snapshotter/kubernetes/token` in sync with its
    service account token (mounted only with kube_secret or the node label enabled), and
    to copy ConfigMap changes to the host without a restart: the snapshotter
    reloads `cgroup` and `nydusd.config` itself and reads `certs.d` per daemon
    start; other keys apply on its next restart.
  - With `installer.node_label.enable`, labels the node the environment
    variable `NODE_NAME` names, the Pod's `spec.nodeName`,
    `d7y.io/nydus-snapshotter=true` for Pods and RuntimeClasses to select, see
    [Node label](#node-label). A post-delete hook Job then runs
    `nydus-snapshotter uninstall`, which removes the label from every node,
    with a ServiceAccount of its own.
  - Has no `preStop` hook that removes the snapshotter from the host:
    deleting the Pod must never do that, and `nydus-snapshotter uninstall`
    does not either, it only removes what the installers left in the
    cluster. Removing the snapshotter from a host is an explicit operation.
  - A dedicated ServiceAccount; with kube_secret enabled, a ClusterRole with
    `list` and `watch` on `secrets` (no `get`); with the node label, `get`
    and `patch` on `nodes`, and `list` and `patch` on `nodes` for the
    ServiceAccount of the post-delete hook, which exists only while the hook
    runs.
  - A node whose containerd already uses `nydus` as its snapshotter needs the
    units baked into its image: the installer Pod's own sandbox goes through the
    snapshotter.
- **A `version = 2` config**, of containerd 1.6 or of a 2.x still reading one:

  ```toml
  [proxy_plugins.nydus]
    type = "snapshot"
    address = "/run/nydus-snapshotter/nydus-snapshotter.sock"
    [proxy_plugins.nydus.exports]
      root = "/var/lib/nydus-snapshotter"

  [plugins."io.containerd.grpc.v1.cri".containerd]
    snapshotter = "nydus"
    disable_snapshot_annotations = false
  ```

- **A `version = 3` config**, containerd 2.x's own format:

  ```toml
  [proxy_plugins.nydus]
    type = "snapshot"
    address = "/run/nydus-snapshotter/nydus-snapshotter.sock"
    [proxy_plugins.nydus.exports]
      root = "/var/lib/nydus-snapshotter"
      enable_remote_snapshot_annotations = "true"

  [plugins."io.containerd.cri.v1.images"]
    snapshotter = "nydus"
    disable_snapshot_annotations = false   # also forces local pull on Linux
  ```

  `exports.root` lets CRI `ImageFsInfo` and kubelet imagefs eviction find the
  snapshotter's filesystem. containerd reads it since 1.6.32 and in every 2.x;
  older 1.6 releases report containerd's own snapshotter directory instead.
- **Tested containerd versions**: 1.6.39 and 2.3.x, the e2e matrix of
  `.github/workflows/e2e-snapshotter.yml`. containerd 2.1.3 with a version 2
  config, as kind's node image ships, was checked by hand.

### Node label

A Pod that needs Nydus images must land on a node where they work. With
`installer.node_label.enable` the installer keeps the label
`d7y.io/nydus-snapshotter=true` on its node, the one the environment variable
`NODE_NAME` names, while both conditions below hold. A Pod or a RuntimeClass
selects it, as a RuntimeClass of kata-deploy selects
`katacontainers.io/kata-runtime`:

```text
snapshotter SERVING ──┐
                      ├─▶ both ───────────────────▶ d7y.io/nydus-snapshotter=true
containerd loaded it ─┘   else, 3 checks in a row ─▶ label removed
installer stops ─────────────────────────────────▶ label kept
helm uninstall ──────────────────────────────────▶ label removed by a hook
```

```yaml
nodeSelector:
  d7y.io/nydus-snapshotter: "true"
```

- **The snapshotter serves**: its gRPC health check answers `SERVING`
  through the host socket, so with kube_secret the secrets are listed. The
  socket is the `grpc.addr` of the config the installer loaded when it
  started, the one it installs.
- **containerd has loaded it**: the installer never edits containerd's config,
  so a node is only usable once its containerd was restarted with the proxy
  plugin. containerd reads its config only when it starts, and the file a
  node uses may come from `imports` or from a distribution's own path, so the
  installer does not read or watch a config file. It asks the running
  containerd (`installer.node_label.containerd_addr`) for its loaded
  snapshotter plugins over the introspection API, as `ctr plugins ls`, nerdctl
  and BuildKit do, and looks for the proxy plugin whose exported `address` is
  the snapshotter's socket, compared as host paths, whatever its name.
  Whether CRI uses it by default
  or through a runtime handler is the node's choice and is not checked.
- **The node is reconciled**: both are checked after the install and on every
  `installer.sync_interval`. The installer then reads the node and patches it
  only when its label differs, so a label removed or changed by hand is put
  right within one interval.
- **A node that is right costs one cached read**: the read asks for resource
  version 0, which the API server answers from its watch cache without
  reaching etcd. At 5000 nodes that is about 83 reads a second, next to the
  500 Lease renewals a second their kubelets write, and API Priority and
  Fairness keeps the requests of a ServiceAccount apart from the kubelets'.
- **The label does not flap**: a Pod scheduled by its `nodeSelector` keeps
  running when the label goes away, but the DaemonSet controller deletes the
  Pods of a DaemonSet that selects the label from a node that lost it. So
  the label is set on the first check that passes and removed only after
  three checks in a row fail, the default `failureThreshold` of a probe,
  which a restart of containerd does not reach. And an installer that stops
  keeps the label: a rollout hands the node to the next installer Pod, which
  takes the label over.
- **`helm uninstall` removes it with a hook**: the installers keep the label
  when they stop, and helm deletes their ClusterRole before that anyway. The
  chart therefore runs `nydus-snapshotter uninstall` in a post-delete hook Job,
  as node-feature-discovery prunes its labels, which removes the label from
  every node that carries it:

  ```text
  installer stops ─▶ label kept, the next installer Pod takes it over
  helm uninstall ──▶ post-delete hook ─▶ nydus-snapshotter uninstall ─▶ label removed
  ```

  It lists the labeled nodes in pages and patches them at kubelet's default
  request rate, 50 a second, so 5000 nodes take under two minutes of the five
  helm gives a hook.
- **A label nobody keeps is removed by hand**: the `installer` section is
  read when the installer starts, so switching the label takes a rollout.
  With the label disabled the next installer Pod leaves the node alone, and
  no hook runs then; the same holds for a node the DaemonSet no longer
  covers, and for a DaemonSet deleted without helm. Remove the label with
  `kubectl label nodes --all d7y.io/nydus-snapshotter-`, or by running
  `nydus-snapshotter uninstall`.

## Known risks and limitations

- **The first pull decides the source repository.** Identical content in two
  repositories shares one chain ID. A later pull of the same content never reaches
  the snapshotter, and a container's `Prepare` carries no image reference, so the
  daemon reads from the repository of the first pull. If that repository later
  loses the image or its credentials, uncached reads fail. Recovery: remove the
  image from the node and pull again. v2 behaves the same.
- **A daemon crash is permanent for its containers.** There is no FUSE failover
  yet. A new container on the image gets a fresh daemon; existing ones must be
  recreated.
- **Plugin name.** containerd keys snapshot metadata by snapshotter name.
  Pointing an existing `nydus` plugin at this socket orphans v2 snapshots, so
  nodes are drained or reimaged, never reconfigured in place. v2 images fail on
  this snapshotter until the v2 file system lands.
- **User-namespace Pods** (`hostUsers: false` on 2.x): without the `remap-ids`
  capability, containerd chowns the whole rootfs, which reads and copies up the
  entire image.
- **Node patch.** With `installer.node_label.enable` the ServiceAccount can
  `get` and `patch` every node, as kata-deploy's and virt-handler's can: RBAC
  cannot narrow `nodes` to the Pod's own. Leave it disabled where that is not
  wanted. `helm uninstall --no-hooks` skips the hook that removes the label.
- **Cluster-wide secret read.** RBAC cannot narrow `secrets` by type or label, so
  a node holding the token can list every secret, and a tenant able to create a
  secret carrying the selected label can shadow another's credential. The role
  grants `list` and `watch` only and should be audited.
- **systemd 240 or newer.** Nothing checks the version. An older systemd
  rejects a unit carrying a property it does not know, and that start fails
  with systemd's error: `Type=exec` of a preheat before 240, `CollectMode` and
  `LogExtraFields` of every unit before 236.
- **nydus of the same release.** Daemon units are `Type=notify`, so a `nydus`
  that sends no `READY=1` fails every start after `mount_timeout`. The image
  and the installer ship both binaries together.
- **A watchdog kill breaks the image's containers**, as any daemon exit does
  until FUSE crash recovery exists. The keep-alive only proves the process
  still schedules, so it fires on a stuck process, not on a slow registry; set
  `nydusd.watchdog_timeout: 0` to turn it off.
- **One snapshotter per host.** Daemon unit names derive from chain IDs only, so
  two snapshotters with different slices on one host would share the unit of an
  image both run.
- **localhost registries on a port other than 443** are reached over plain
  HTTP, while containerd tries HTTPS first; a TLS registry there needs an
  explicit `hosts.toml` `server`.
- **Shared blob cache trusts blob metas.** Every daemon uses one cache, and a
  bootstrap layer seeds its own `<blob>.blob.meta` into it; an existing meta is
  kept. An image author can ship a crafted meta for another image's blob ID and
  serve matching data from a registry they control, which the victim's daemon
  then reads from the cache. Closing this needs the bootstrap to pin each blob
  meta's digest and nydus to check it on load, which is not planned. Admit
  images only from trusted registries.
- **Any namespace can shadow a registry credential.** kube_secret watches
  `dockerconfigjson` secrets of every namespace, the newest secret wins among
  equal keys and secrets rank above the node's docker config, and a change is
  pushed into running daemons. Anyone able to create a secret, with the
  selected label when one is set, can replace the credential daemons use for a
  registry. Grant secret creation accordingly, or keep kube_secret off.
- **Any image can claim a chain ID.** A remote layer's content is never checked
  against its diff ID, as with every remote snapshotter, so an image claiming
  another image's layer chain IDs as nydus layers makes that image fail on the
  node until the claiming image and its snapshots are removed.
- **Dragonfly peers see the registry credential.** With
  `nydusd.config.backend.config.dragonfly` set, requests carry the
  `Authorization` header through the seed peers; use a trusted, TLS-protected
  Dragonfly cluster.
- **A preheat needs a credential.** `PreheatImage` rejects a request without
  one, so an image of a registry that takes no credential cannot be
  preheated. A preheat cannot be cancelled over the API and waits without
  a bound for a blob a daemon is prefetching; stopping its unit,
  `nydusd-preheat-<chainID>.service`, ends it as failed.
- **Changing `root_dir` or `runtime_dir`** while daemons run loses track of
  them, as changing containerd's own root does; change them on a drained node.
- **Toolchain support windows.** The module builds with Go 1.25 against
  containerd v2.2 and client-go v0.34 to match the repository; Go 1.25 left
  upstream support in 2026-08 and containerd 2.2 on 2026-11-06.

## Code layout

```
nydus-snapshotter/                  module github.com/dragonflyoss/nydus/nydus-snapshotter, go 1.25
├── cmd/nydus-snapshotter/
│   ├── main.go                     cmd.Execute()
│   └── cmd/{root.go,install.go,uninstall.go}  serve; install (DaemonSet entrypoint); uninstall (post-delete hook)
├── internal/
│   ├── config/                     config.go (Config, New, Parse, Load, Validate), constants.go, types.go, watch.go; testdata/
│   ├── snapshot/                   snapshots.Snapshotter on core/snapshots/storage: snapshot.go, mount.go, label.go, blobs.go, image.go, release.go
│   ├── fs/                         FileSystem (fs.go), daemon.go, limits.go, pusher.go, preheat.go, render.go, bootstrap.go, gather.go, Driver and fuse
│   ├── preheat/                    NydusSnapshotter gRPC service (service.go), image resolver over containerd (resolver.go)
│   ├── systemd/                    Systemd (systemd.go), units and slices (unit.go) over systemd's D-Bus API (dbus.go)
│   ├── nydusd/                     nydus daemon API client
│   ├── store/                      bbolt instances and blobs
│   ├── auth/                       Keychain (keychain.go), keyring, kube_secret and docker config providers
│   ├── registry/                   image reference, hosts.toml
│   ├── cache/                      blob cache GC
│   ├── installer/                  host install: installer.go, payload.go, kubeconfig.go, version.go, label.go
│   ├── uninstaller/                the post-delete hook: removes the node label from every node
│   ├── server/                     wiring, gRPC serving, socket activation, workers
│   ├── version/                    -ldflags build information
│   ├── kmutex/                     keyed mutex (from containerd internal/kmutex)
│   ├── metrics/                    Prometheus collectors, /metrics server
│   └── util/                       kubeutil/ (API server client of a Pod, for installer and uninstaller), testutil/ (helpers tests share)
├── deploy/                         systemd units, default config, containerd snippets
├── Dockerfile                      installer image: nydus-snapshotter and nydus
├── Makefile                        build, test, lint, generate
├── .golangci.yml
└── README.md
```

Placement follows [Organizing a Go module](https://go.dev/doc/modules/layout):
`cmd/` and `internal/` only; nothing is meant to be imported. The
`cmd/<bin>/cmd/root.go` split, `Config` defaults and validation, testify table
tests and mockgen mocks follow Dragonfly; the commands are written as
dragonflyoss/perf-tests writes its own (`cmd/dfbench/cmd`): a package-level
command per file, its flags registered in `init` and its work in a `run`
function. golangci-lint v2 runs Dragonfly's linters plus containerd's. Logging
(`containerd/log`) and errors (`containerd/errdefs`, `%w`) follow containerd.
Behaviour lives in methods: a package-level function is a constructor
(`New`, `newX`, `ParseX`, `xFromY`), and a string with rules of its own gets a
small named type to hang them on (`registryKey.matches`, `cacheFile.blobID`,
`dbusError.is`). A helper that several packages share goes into
`internal/util/<topic>`, as Kubernetes keeps `pkg/util/<topic>` and stargz
and soci keep `util/<topic>util`.
It is released with the repository's `v*` tags: the release tarball carries a
static `nydus-snapshotter` next to `nydus` and `nydusify`, the version is
injected with `-ldflags` like `nydusify`, and
`ghcr.io/dragonflyoss/nydus-snapshotter` is a multi-arch image holding the
`nydus` binary of the same tag, built natively per architecture and carrying a
build provenance attestation.

Metrics use the `nydus_snapshotter_` prefix, base units and `_total` counters
(prometheus.io naming practices), with no per-image labels:

| Metric | Type | Labels |
| --- | --- | --- |
| `nydus_snapshotter_daemon_start_duration_seconds` | histogram | |
| `nydus_snapshotter_daemon_starts_total` | counter | |
| `nydus_snapshotter_daemon_start_failures_total` | counter | |
| `nydus_snapshotter_daemon_unexpected_exits_total` | counter | |
| `nydus_snapshotter_running_daemons` | gauge | |
| `nydus_snapshotter_unresponsive_daemons` | gauge | |
| `nydus_snapshotter_preheats_total` | counter | `result`: `success`, `failure` |
| `nydus_snapshotter_running_preheats` | gauge | |
| `nydus_snapshotter_auth_updates_total` | counter | `result`: `success`, `failure`, `unsupported` |
| `nydus_snapshotter_cache_evicted_bytes_total` | counter | `reason`: `orphan`, `ttl`, `watermark` |

Every start attempted counts in `daemon_starts_total`, so the failures are a
share of it, and the labelled counters report each known label value from 0,
so a rate over one that has not counted yet is 0 and not absent
(prometheus.io instrumentation practices).

`/metrics` also serves the metrics of every daemon (`nydus_backend_*`,
`nydus_cache_*`, `nydus_storage_*`, refer to [Metrics](nydus.md#metrics)),
which Prometheus cannot scrape from the daemons' `0600` unix sockets. Each
scrape reads them from the daemons' APIs, eight at a time and within 8s, and
adds the labels `chain_id` and `image`, as cAdvisor serves container metrics;
`chain_id` tells apart two daemons of one image reference. A daemon that does
not answer is left out, and a family two nydus versions define differently
keeps the first definition read, so one daemon never costs the scrape.

## Testing

- **Unit**: table-driven tests with testify, one `x_test.go` beside each
  `x.go`; systemd and the daemon API faked behind interfaces. Statement
  coverage is 94% from unit tests alone; what is left is failures that need
  a fault no test can make (a `fsync` or `close` that fails, systemd gone
  mid-call) and socket activation, which the e2e suite runs. Failure
  branches are reached with real faults, not mocks of the standard library:
  a file in place of a directory, a symlink loop under the host root, a
  directory under a file's name, a tmpfs that is full or has no free inode,
  a mount point that cannot be removed, a closed D-Bus connection and a
  canceled context. As root, tests also drive the host's systemd over D-Bus
  (units, slices, the version check, a connection outliving its dial context)
  and mount FUSE without a server and tmpfs.
- **Conformance**: containerd's `core/snapshots/testsuite` for overlay behaviour.
- **Targeted**: concurrent `Mount`s of one chain ID start one unit; a teardown
  pass racing a starting `Mount` keeps the daemon; a daemon that never gets ready
  and a `Mount` waiting on another start are bounded; a stale mount is detached
  before start and a symlinked root still matches mountinfo; references count
  across namespaces; teardown forgets daemons gone with a reboot and counts an
  exit once; cache GC skips running daemons, recent files and busy rounds, keeps
  to `disk_threshold` and caps eviction by cache bytes; `EXDEV` falls back to a
  streamed copy; layer paths stay in the layer; socket path length; unlabelled
  nydus layers and nydus labels on non-`extract-` keys, a commit included, are
  ignored or rejected; credentials stay out of unit properties and are pushed
  only on change; installer restarts follow what changed.
- **e2e**: `tests/e2e/snapshotter/` on the existing Go e2e framework, against
  containerd 1.6 and 2.x through the client unpacker: nydus and OCI images side
  by side, a shared daemon, a killed daemon, a snapshotter restart, a foreign
  slice, a private registry, the prefetch label, an unlabelled pull, many
  daemons started at once, daemon metrics served by the snapshotter, the
  gRPC health check, and a changed `cgroup.daemon.memory_high` reaching a
  running daemon without a restart, a `hosts.toml` that sends a registry
  host to another server, and a container in a user namespace that owns its
  root file system. Five cases go beyond the client: a pod pulled and run over CRI with the shipped
  containerd snippet, as containerd's own integration tests drive it; the
  shipped socket and service units, where a stopped service is started again
  by the next request; one daemon shared by two containerd namespaces, kept
  when the first removes its image; and a registry credential rotated through
  a Kubernetes secret, read with an account that may only list and watch
  secrets and pushed into the running daemon; and the installer on a Kind
  node image booted as a systemd host, where it installs and starts the
  shipped units, changes nothing on a rerun, survives a reboot, switches the
  nydus version and restarts the service on an upgrade, and keeps the
  kubeconfig and the service account token in sync. A preheat runs against a
  private registry the snapshotter has no credential for: a wrong password
  fails without echoing it, the right one downloads every blob, and the
  container then starts and reads its files with no request to the registry. A failed case dumps the daemons'
  logs and journal. Do not assert an immediate daemon stop after container
  removal, because backend `Remove` waits for containerd GC.

## References

- containerd: `core/snapshots/{snapshotter.go,storage}`, `contrib/snapshotservice`,
  `plugins/snapshots/overlay`, `core/metadata/snapshot.go` (remote snapshot
  adoption, GC lock), `core/unpack/unpacker.go`,
  `docs/snapshotters/remote-snapshotter.md`, `RELEASES.md`.
- stargz-snapshotter: `snapshot/snapshot.go` (FileSystem port, async removal),
  `cmd/containerd-stargz-grpc/main.go`, systemd unit.
- soci-snapshotter: socket activation, systemd unit, CRI config handling.
- accelerated-container-image (overlaybd): host unit, restore on start.
- runc / opencontainers cgroups: `cgroups/systemd` (D-Bus, transient units,
  retries, slice naming).
- kubernetes: sample-controller (informer and workqueue), kubelet
  `credentialprovider` keyring and config search order.
- Node label: kata-deploy (`katacontainers.io/kata-runtime` set after the
  install and selected by its RuntimeClasses, `nodes: get, patch`), KubeVirt
  `pkg/virt-handler/heartbeat` (the node's own agent patches
  `kubevirt.io/schedulable`), node-feature-discovery
  (a post-delete hook Job runs `nfd-master -prune`, with a ServiceAccount
  and a ClusterRole that are hooks too); nerdctl `pkg/infoutil`, `ctr plugins`
  and BuildKit's containerd worker (asking the running containerd for its
  plugins through the introspection API); client-go `tools/pager`; kubelet's
  `kubeAPIQPS` and `kubeAPIBurst` defaults and the `failureThreshold` of a
  probe; the DaemonSet controller, which deletes its Pods from a node that
  no longer matches the `nodeSelector`.
- Installer config: kubelet `cmd/kubelet/app/options` (`KubeletFlags` keeps
  only what nodes cannot share, the rest is `KubeletConfiguration`, which
  holds `containerRuntimeEndpoint`), Cilium (agent and operator read one
  ConfigMap through `--config-dir`), node-feature-discovery, kube-proxy and
  Dragonfly's dfinit (a ConfigMap mounted at the binary's `--config` path),
  node-problem-detector (`NODE_NAME` from the Downward API).
- Preheat: CRI `PullImage` and dfdaemon (one node-level socket, the
  request names the image); Dragonfly's Scheduler `PreheatImage` and
  `StatImage` (the two calls, both by image and without an ID, the first
  answering `Empty` once the work is queued); containerd `client/image.go`
  `IsUnpacked` (reference to chain ID) and `images.Dispatch` (the first
  failure cancels the rest); kubelet `serializeImagePulls` and containerd
  `max_concurrent_downloads` (the limit and its name); client-go
  `BearerToken`, Prometheus `BasicAuth` and Envoy `CallCredentials` (the
  credential `oneof`); containerd's `Descriptor` and content `Info`
  (`digest`, `size`) and Dragonfly's `Layer` (`is_finished`) for the blob
  list; runc `state.json` under `/run` and the Kubernetes
  termination message (exit code plus a file); AIP-216 (state names) and
  AIP-151 (records expire); Kubernetes mount-utils (`systemd-run --scope`
  for work that outlives the daemon).
- gRPC health checking protocol (`grpc.health.v1`) with grpc-go's `health`
  server, as containerd `plugins/services/healthcheck` and BuildKit
  `cmd/buildkitd` register it.
- go-containerregistry `pkg/authn/kubernetes` (keyring from secrets).
- Dragonfly: Go layout and config reload (`cmd/dependency`), dfdaemon GC
  (`dragonfly-client/src/gc`).
- Calico `cni-plugin/pkg/install` and Cilium `plugins/cilium-cni/install-plugin.sh`:
  a DaemonSet installing a host binary (compare, copy beside, rename) and its
  kubeconfig; debhelper `postinst-systemd-restart` (start or restart a unit).
- containerd/nydus-snapshotter: DaemonSet installer (`misc/snapshotter`) and
  fixed issues #288, #631, #673, #688, #771, #791, #796.
