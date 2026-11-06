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
| `PUT /api/v1/backend/auth` in `nydus` | Repairing a cache after an unclean reboot (a `nydus` concern) |
| Per-image prefetch scope through a pull label | Preheat at pull time (start a daemon during pull) |
| Cache GC by TTL and disk watermarks | Aggregating daemon metrics |

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
   │    fs         v3 file system: per-image instance, lock, render, start, wait
   │      └─ Driver: fuse
   │    systemd    units and slices over D-Bus
   │    nydusd     nydus daemon API client
   │    store      bbolt: instances, blob access times
   │    auth       kubesecret informer + docker config keyring, auth pusher
   │    registry   image reference, certs.d hosts.toml
   │    cache      blob cache GC
   │    metrics    /metrics /livez /readyz
   └─ system-nydus.slice/system-nydus-v3.slice/nydusd-<chainID>.service
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
│   ├── nydus-snapshotter.service             snapshotter; its own limits in the unit file
│   └── system-nydus.slice                    total for every nydusd: MemoryMax, MemoryHigh, CPUQuotaPerSecUSec
│       └── system-nydus-v3.slice
│           ├── nydusd-<chainID>.service      each: MemoryHigh, CPUQuotaPerSecUSec,
│           └── nydusd-<chainID>.service            OOMScoreAdjust=-999, LimitNOFILE
└── kubepods.slice/…                          installer Pod
```

Daemons are transient units forked by PID 1. They are never children of the
snapshotter, and their units carry no `PartOf=`, `BindsTo=` or `Requires=` on
`nydus-snapshotter.service`. So a snapshotter crash, OOM kill, restart or
upgrade leaves every daemon and mount running, and a daemon never shares the
snapshotter's cgroup budget. The snapshotter never forks a daemon itself; a
forked daemon would land in `nydus-snapshotter.service` and die with it.

In systemd every `-` in a slice name is a nesting level, so
`system-nydus-v3.slice` sits under `system-nydus.slice`. The total budget lives
on `system-nydus.slice`, which a future `system-nydus-v2.slice` shares. Add its
`memory_max` to kubelet's `systemReserved`, or kubelet evicts Pods for memory
they do not use.

Per-daemon memory uses `MemoryHigh` only. A `MemoryMax` hit is an OOM kill
(SIGKILL), and FUSE has no crash recovery: every container on that image would
read `ENOTCONN` until recreated. The total slice keeps `MemoryMax` as the node
backstop. Limits come from the snapshotter config and are hot-reloaded with
`SetUnitProperties`; a lower slice `MemoryMax` is applied only once the slice's
`memory.current` is below it, so a reload never triggers an OOM kill.

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
bounded by twice `mount_timeout` and the request context, as stargz-snapshotter
bounds its `Mount` during `Prepare`; stopping a daemon whose start failed is
bounded by the systemd job timeout.

### Ensuring a daemon

`Mount(chainID)` runs under a per-chainID lock (a copy of containerd's
`internal/kmutex`, which v2 does not export) and a read lock on the cache GC.

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
   regular files are linked.
4. Render `config.yaml` (0600) under `/run` (see [Configuration](#configuration)).
5. Write the instance record, then `StartTransientUnit` with a buffered job
   channel and a bounded wait. On `UnitExists`, `ResetFailedUnit` and retry once,
   as runc's systemd driver does.
6. Wait for readiness: the unit is `active`, `mnt/` is a FUSE mount in
   mountinfo, and `GET /metrics` on the API socket answers 200. Step 2 detached
   any leftover mount, so a FUSE mount here is the new daemon's; it exists before
   request workers start, so the mount alone is not a readiness signal.
   mountinfo lists resolved paths, so the mountpoint's parent is resolved first,
   as containerd's `mount.Lookup` does; the mountpoint itself is never stat'ed,
   which fails or hangs on a dead FUSE server.
7. On timeout or failure: `StopUnit`, wait for it, delete the record, return the
   error. The daemon's logs stay for diagnosis until teardown.

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
D-Bus call, and for every other daemon of `system-nydus-v3.slice` walks the
metastore again under the per-chainID lock, as containerd's GC marks before it
sweeps. A daemon still unused gets `StopUnit` (wait for the job; `NoSuchUnit` is
success), `Driver.Unmount`, and its record, instance directory and log directory
deleted. Mount and teardown hold the same lock, so no interleaving stops a
daemon in use.
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
4. Serve `/livez` (process alive) and `/readyz` (gRPC serving and, when enabled,
   the secret informer synced). Liveness never depends on the API server.
   `READY=1` goes to systemd once gRPC serves (`Type=notify`, as
   `containerd.service`), so containerd, ordered after the unit, starts
   against a ready snapshotter.
5. Every teardown pass logs and counts, once, a daemon that exited while it
   still had users (`nydus_snapshotter_daemon_unexpected_exit_total`), keeping
   its record so its files are cleaned up once unused; the next `Mounts` starts
   a fresh one. A daemon gone with a reboot, whose tmpfs runtime dir is gone
   too, is not counted. The pass also sets `nydus_snapshotter_daemon_running`.

On SIGTERM: `STOPPING=1`, then `GracefulStop` with a deadline, then `Stop`;
in-flight handlers finish before the bbolt files close (`WaitForHandlers`).
Units and mounts are left running.

### Credentials

Sources, in order:

1. **kubesecret** (optional): an informer over `kubernetes.io/dockerconfigjson`
   secrets in all namespaces, narrowed by a configured label selector (field
   selector `type=`, a transform drops `managedFields` and annotations). The
   snapshotter authenticates with a kubeconfig whose `tokenFile` the installer
   keeps in sync with its projected service account token; client-go re-reads
   rotated tokens. Matching follows kubelet keyring semantics: the longest
   host-and-path prefix wins. Among equal keys, the secret updated most recently
   (its newest `managedFields` time, which survives a restart) wins (ties: `namespace/name` order), with a warning.
2. **docker config** (always on): the first file that reads and parses in
   kubelet's search order
   (`/var/lib/kubelet/config.json`, then `/root/.docker/config.json`), or the
   configured path. Only `auths` is read; `credsStore` and `credHelpers` log a
   warning, because their helper binaries are not on the snapshotter's path.
   `docker.io` maps to the `https://index.docker.io/v1/` key.

Behaviour:

- At daemon start the credential is written into `config.yaml`. Only
  `username:password` is supported; `identitytoken` and `registrytoken` entries
  are skipped (kubelet reads only `username`, `password` and `auth`), and only a
  lookup with no usable candidate is an error. An empty entry, as `docker login`
  with a credential store writes, means anonymous access, as containerd's
  `ParseAuth` reads it.
- Until the informer has synced, `Prepare`, `View` and `Mounts` that need a new
  daemon return `errdefs.ErrUnavailable` (fail fast). After the first sync the
  cache survives API-server outages.
- The snapshotter retries a missing or invalid kubeconfig every few seconds
  instead of failing to start: the installer keeps it on tmpfs, so after a
  reboot it appears only once the installer Pod runs again, and that Pod needs
  the snapshotter serving. Meanwhile `/readyz` fails and nydus images return
  `ErrUnavailable`; OCI images are unaffected.
- On a secret change, the chain IDs of running instances whose registry host
  matches go onto a rate-limited workqueue keyed by chain ID, as in
  sample-controller. A worker resolves the credential for that instance again and
  calls `PUT /api/v1/backend/auth` only when it differs from the last one pushed.
  `404` means the daemon lacks the route: log an error, count it, forget. `400`
  and `403` are logged, counted and dropped, since a retry sends the same
  credential. Other failures retry with backoff.
- A secret delete keeps the daemon's last credential.

Credentials never go into unit properties (`ExecStart`, `Environment`), because
any user can read those through `systemctl show`, and never onto persistent
disk.

### Daemon auth API

Implemented in `nydus` (`nydus/src/api_server.rs`) on the `--apiserver` socket:

```http
PUT /api/v1/backend/auth HTTP/1.1
Content-Type: application/json

{"auth": "<base64 username:password>"}
```

| Answer | When |
| --- | --- |
| `204 No Content` | The registry backend's basic credential is replaced and cached bearer tokens are dropped |
| `400 Bad Request` | The body is not that JSON object or `auth` is not base64 `user:pass` |
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
2. `nydusd.prefetch_scope` in the snapshotter config (default `auto`).

Other template `prefetch` fields are kept. An invalid label value fails
`Prepare`.

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
  referencing the blob starts or stops; a time in the future counts as now. File
  atime is unreliable under `relatime` and `noatime`.
- Never evicted: blobs referenced by a running daemon (the units of
  `system-nydus-v3.slice`, mapped to their bootstraps), files modified in the
  last few minutes, and blobs whose `.prefetch.lock` cannot be `flock`ed
  non-blocking. Blobs of committed but idle images may be evicted; a daemon
  refetches data and `.blob.meta` on demand.
- Every round also removes blobs no committed bootstrap references and stale
  `.blob-meta-*.tmp` files. A bootstrap layer whose image dir cannot be read is
  skipped, never failing the round. Evicted blobs are forgotten in one bbolt
  transaction.
- GC takes the cache write lock with `TryLock`; a skipped round retries after a
  few seconds.

## Daemon unit

```
Unit               nydusd-<chainID>.service   (79 chars; no escaping needed)
Slice              system-nydus-v3.slice
Type               exec
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
LogExtraFields     NYDUS_CHAIN_ID=<chainID>
ExecStart          /opt/nydus-v3/bin/<ver>/nydus fuse
                     --bootstrap  /var/lib/containerd-nydus-v3/nydusd/<chainID>/image.boot
                     --config     /run/containerd-nydus-v3/nydusd/<chainID>/config.yaml
                     --mountpoint /var/lib/containerd-nydus-v3/nydusd/<chainID>/mnt
                     --apiserver  unix:///run/containerd-nydus-v3/nydusd/<chainID>.sock
                     --log-dir    /var/log/nydus-v3/nydusd/<chainID>
                     --fsname     nydus-<chainID[:12]>
```

D-Bus: connect with `dbus.NewWithContext`, which falls back to
`/run/systemd/private` as root, and reconnect on `dbus.ErrClosed` as runc's
systemd cgroup driver does. `CPUQuota` is not a D-Bus property;
`CPUQuotaPerSecUSec` is (1 CPU = 1 000 000), rounded to 10 ms like runc.

## Configuration

`/etc/nydus-v3/config.yaml`, decoded with `gopkg.in/yaml.v3` as the Dragonfly
components and the nydus daemon config are: strict (`KnownFields`) at start,
while a reload that fails logs a warning and keeps the running config. Keys are
snake_case, as in nydus-config. Durations use a `UnmarshalText` type (`10s`);
sizes use `docker/go-units` (`1GiB`). `Validate()` runs after defaults are
applied. The `cgroup` and `nydusd.dragonfly` sections are reloaded by polling
the file and comparing bytes, as Dragonfly does (`cmd/dependency`), which
survives ConfigMap symlink swaps. A dragonfly change applies to newly started
daemons; other changes log a warning and need a restart.

```yaml
version: 1
root: /var/lib/containerd-nydus-v3
address: /run/containerd-nydus-v3/containerd-nydus-grpc.sock

log:
  level: info

metrics:
  # /metrics, /livez and /readyz, empty to disable.
  address: 127.0.0.1:4010

registry:
  config_path: /etc/nydus-v3/certs.d

auth:
  docker_config:
    # Empty follows kubelet's search order.
    path: ''
  kubesecret:
    enable: false
    kubeconfig: /run/containerd-nydus-v3/kubernetes/kubeconfig
    label_selector: ''

nydusd:
  driver: fuse
  binary: /opt/nydus-v3/bin/current/nydus
  template: /etc/nydus-v3/nydusd.template.yaml
  log_dir: /var/log/nydus-v3/nydusd
  mount_timeout: 10s
  prefetch_scope: auto
  # Copied into backend.config.dragonfly when scheduler_endpoint is set.
  dragonfly:
    scheduler_endpoint: ''
    request_timeout: 5s
    max_retries: 1
    fallback_rate_limit: 1

cgroup:
  slice: system-nydus-v3.slice
  # On system-nydus.slice.
  memory_max: 8GiB
  memory_high: 6GiB
  cpu_quota: 400%
  daemon:
    memory_high: 1GiB
    cpu_quota: 100%

gc:
  interval: 15m
  policy:
    blob_ttl: 720h
    # 0 is the whole filesystem.
    disk_threshold: '0'
    disk_high_threshold_percent: 80
    disk_low_threshold_percent: 60
```

`registry.config_path` is a containerd certs.d directory, read with containerd's
lookup and its [hosts.toml](https://github.com/containerd/containerd/blob/main/docs/hosts.md)
format, so it can share the files containerd uses.

`Validate()` also checks that each daemon API socket path stays under the
108-byte `sun_path` limit; the default is 101 bytes.

### nydusd template and rendered config

`/etc/nydus-v3/nydusd.template.yaml` is a [nydus-config](nydus.md#storage-config)
file holding what all daemons share. The snapshotter does not interpret it;
`nydus` rejects unknown fields when the daemon starts.

```yaml
storage:
  dir: /var/lib/containerd-nydus-v3/cache
prefetch:
  concurrent_blob_count: 10
backend:
  type: registry
  config:
    http:
      request_timeout: 5s
      max_retries: 3
```

For each daemon the snapshotter writes
`/run/containerd-nydus-v3/nydusd/<chainID>/config.yaml` (0600, tmpfs). It fills
in:

| Field | Source |
| --- | --- |
| `backend.config.addr` | Image reference host (`docker.io` → `https://registry-1.docker.io`); `server` from `hosts.toml`, parsed as containerd does (no scheme means `https`, a `/v2` API root is stripped because nydus appends it); `override_path` is rejected |
| `backend.config.repository` | Image reference path (`library/` for docker.io official images) |
| `backend.config.auth` | Keyring |
| `backend.config.http.tls` | `hosts.toml`: `skip_verify`, CA files concatenated into one PEM; `client` certificates are rejected (unsupported by nydus); `[host]` mirrors are ignored |
| `backend.config.dragonfly` | `nydusd.dragonfly` (requires a `nydus` built with the `dragonfly` feature, as release builds are) |
| `prefetch.scope` | See [Prefetch](#prefetch) |

## Paths

| Path | Contents | Writer → reader |
| --- | --- | --- |
| `/usr/local/bin/nydus-snapshotter` | Snapshotter binary | Installer → systemd |
| `/etc/systemd/system/nydus-snapshotter.{service,socket}` | Snapshotter units | Installer → systemd |
| `/etc/nydus-v3/config.yaml` | Snapshotter config | Installer (from ConfigMap) → snapshotter |
| `/etc/nydus-v3/nydusd.template.yaml` | nydusd config template | Installer (from ConfigMap) → snapshotter |
| `/etc/nydus-v3/certs.d/<host>/hosts.toml` | Registry TLS and scheme | Installer → snapshotter |
| `/run/containerd-nydus-v3/kubernetes/{kubeconfig,token,ca.crt}` | API access for kubesecret | Installer → snapshotter |
| `/run/containerd-nydus-v3/containerd-nydus-grpc.sock` | gRPC socket | systemd / snapshotter → containerd |
| `/run/containerd-nydus-v3/nydusd/<chainID>.sock` | Daemon API | nydusd → snapshotter |
| `/run/containerd-nydus-v3/nydusd/<chainID>/{config.yaml,ca.pem}` | Rendered daemon config (holds the credential) | snapshotter → nydusd |
| `/var/lib/containerd-nydus-v3/metadata.db` | Snapshot metastore (bbolt) | snapshotter |
| `/var/lib/containerd-nydus-v3/nydusd.db` | Instances and blob access times (bbolt) | snapshotter |
| `/var/lib/containerd-nydus-v3/snapshots/<id>/{fs,work}` | Overlay upper and work dirs; bootstrap `fs/image/` | snapshotter, containerd |
| `/var/lib/containerd-nydus-v3/nydusd/<chainID>/{image.boot,mnt/}` | Linked bootstrap, FUSE mountpoint | snapshotter, nydusd |
| `/var/lib/containerd-nydus-v3/cache/` | Shared blob cache | nydusd |
| `/var/log/nydus-v3/nydusd/<chainID>/` | Daemon file logs, kept after a failed start until teardown; stderr goes to the journal | nydusd |
| `/opt/nydus-v3/bin/<version>/nydus`, `/opt/nydus-v3/bin/current` | Daemon binaries; a switch keeps the current and previous versions | Installer → systemd |
| `/run/nydus-v3/restart-pending` | Units due a restart, until they restart | Installer |

`<chainID>` is the hex digest of the bootstrap layer's chain ID.

The cache sits under the same mount as the snapshots, so linking `.blob.meta`
and `image.boot` does not hit `EXDEV`.

The bbolt `nydusd.db` holds:

- `v1/version`: schema version, for future migrations as containerd's metadata
  store does.
- `v1/instances`, keyed by chain ID, as JSON: `{chain_id, driver, image_ref,
  registry_host, bootstrap, blobs, mountpoint, api_socket, unit,
  created_at}`. There is no PID; systemd is the source of truth for process
  state.
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
  - Runs `nydus-snapshotter install`: validates `config.yaml`, the template and
    every `hosts.toml`, copies binaries, units and config from its image and
    ConfigMap to the host, then `EnableUnitFiles` over D-Bus. Only a change the
    snapshotter reads at start restarts it: its binary, its unit files or
    `config.yaml`; a socket change restarts the socket too. A new `nydus` lands
    in its own version directory behind the `current` link, read per daemon
    start. The units due a restart are recorded on tmpfs before any file is
    written, so a run that dies midway is finished by the next. Host paths
    resolve within `/host`, so an absolute symlink on the host is followed
    there (`continuity/fs.RootPath`).
  - Stays running to keep `/run/containerd-nydus-v3/kubernetes/token` in sync with its
    projected service account token (mounted only with kubesecret enabled), and
    to copy ConfigMap changes to the host without a restart: the snapshotter
    reloads `cgroup` and `nydusd.dragonfly` itself and reads the template
    and `certs.d` per daemon start; other keys apply on its next restart.
  - Has no `preStop` uninstall: deleting the Pod must never remove the
    snapshotter. Uninstalling is an explicit operation.
  - A dedicated ServiceAccount; with kubesecret enabled, a ClusterRole with
    `list` and `watch` on `secrets` (no `get`).
  - A node whose containerd already uses `nydus` as its snapshotter needs the
    units baked into its image: the installer Pod's own sandbox goes through the
    snapshotter.
- **containerd 1.6**:

  ```toml
  [proxy_plugins.nydus]
    type = "snapshot"
    address = "/run/containerd-nydus-v3/containerd-nydus-grpc.sock"
    [proxy_plugins.nydus.exports]
      root = "/var/lib/containerd-nydus-v3"

  [plugins."io.containerd.grpc.v1.cri".containerd]
    snapshotter = "nydus"
    disable_snapshot_annotations = false
  ```

- **containerd 2.x**:

  ```toml
  [proxy_plugins.nydus]
    type = "snapshot"
    address = "/run/containerd-nydus-v3/containerd-nydus-grpc.sock"
    [proxy_plugins.nydus.exports]
      root = "/var/lib/containerd-nydus-v3"
      enable_remote_snapshot_annotations = "true"

  [plugins."io.containerd.cri.v1.images"]
    snapshotter = "nydus"
    disable_snapshot_annotations = false   # also forces local pull on Linux
  ```

  `exports.root` lets CRI `ImageFsInfo` and kubelet imagefs eviction find the
  snapshotter's filesystem. containerd reads it since 1.6.32 and in every 2.x;
  older 1.6 releases report containerd's own snapshotter directory instead.
- **Tested containerd versions**: 1.6.39 and 2.3.x, the e2e matrix of
  `.github/workflows/e2e-snapshotter.yml`.

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
- **Cluster-wide secret read.** RBAC cannot narrow `secrets` by type or label, so
  a node holding the token can list every secret, and a tenant able to create a
  secret carrying the selected label can shadow another's credential. The role
  grants `list` and `watch` only and should be audited.
- **systemd 240 or newer.** Daemon units use `Type=exec`; the snapshotter and
  the installer refuse to start against an older systemd instead of failing
  every daemon start.
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
  meta's digest and nydus to check it on load. Until then, admit images only
  from trusted registries.
- **Any namespace can shadow a registry credential.** kubesecret watches
  `dockerconfigjson` secrets of every namespace, the newest secret wins among
  equal keys and secrets rank above the node's docker config, and a change is
  pushed into running daemons. Anyone able to create a secret, with the
  selected label when one is set, can replace the credential daemons use for a
  registry. Grant secret creation accordingly, or keep kubesecret off.
- **Any image can claim a chain ID.** A remote layer's content is never checked
  against its diff ID, as with every remote snapshotter, so an image claiming
  another image's layer chain IDs as nydus layers makes that image fail on the
  node until the claiming image and its snapshots are removed.
- **Dragonfly peers see the registry credential.** With `nydusd.dragonfly`
  set, requests carry the `Authorization` header through the seed peers; use a
  trusted, TLS-protected Dragonfly cluster.
- **Changing `root` or `run_dir`** while daemons run loses track of them, as
  changing containerd's own root does; change them on a drained node.
- **Toolchain support windows.** The module builds with Go 1.25 against
  containerd v2.2 and client-go v0.34 to match the repository; Go 1.25 left
  upstream support in 2026-08 and containerd 2.2 does on 2026-11-06.

## Code layout

```
nydus-snapshotter/                  module github.com/dragonflyoss/nydus/nydus-snapshotter, go 1.25
├── cmd/nydus-snapshotter/
│   ├── main.go                     cmd.Execute()
│   └── cmd/{root.go,install.go}    serve; install (DaemonSet entrypoint)
├── internal/
│   ├── config/                     Config, New(), Load(), Validate(), Watcher; testdata/
│   ├── snapshot/                   snapshots.Snapshotter on core/snapshots/storage, teardown worker
│   ├── fs/                         FileSystem (fs.go), daemon lifecycle (daemon.go), slices, Driver and fuse, config render
│   ├── systemd/                    units and slices over systemd's D-Bus API
│   ├── nydusd/                     nydus daemon API client
│   ├── store/                      bbolt instances and blobs
│   ├── auth/                       keyring, kubesecret informer, docker config, auth pusher
│   ├── registry/                   image reference, hosts.toml
│   ├── cache/                      blob cache GC
│   ├── installer/                  host install, config and token sync
│   ├── server/                     wiring, gRPC serving, socket activation, workers
│   ├── version/                    -ldflags build information
│   ├── kmutex/                     keyed mutex (from containerd internal/kmutex)
│   └── metrics/                    Prometheus collectors, health endpoints
├── deploy/                         systemd units, default config, containerd snippets
├── Dockerfile                      installer image: nydus-snapshotter and nydus
├── Makefile                        build, test, lint, generate
├── .golangci.yml
└── README.md
```

Placement follows [Organizing a Go module](https://go.dev/doc/modules/layout):
`cmd/` and `internal/` only; nothing is meant to be imported. The
`cmd/<bin>/cmd/root.go` split, `Config` defaults and validation, testify table
tests and mockgen mocks follow Dragonfly; golangci-lint v2 runs Dragonfly's
linters plus containerd's. Logging
(`containerd/log`) and errors (`containerd/errdefs`, `%w`) follow containerd.
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
| `nydus_snapshotter_daemon_start_failure_total` | counter | |
| `nydus_snapshotter_daemon_unexpected_exit_total` | counter | |
| `nydus_snapshotter_daemon_running` | gauge | |
| `nydus_snapshotter_auth_update_total` | counter | `result`: `success`, `failure`, `unsupported` |
| `nydus_snapshotter_cache_evicted_bytes_total` | counter | `reason`: `orphan`, `ttl`, `watermark` |

## Testing

- **Unit**: table-driven tests with testify; systemd and the daemon API faked
  behind interfaces. As root, tests also drive the host's systemd over D-Bus
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
  slice, a private registry, the prefetch label and an unlabelled pull. A failed
  case dumps the daemons' logs and journal. Do not assert an immediate daemon
  stop after container removal, because backend `Remove` waits for containerd
  GC. Not yet covered end to end: the CRI pull path with the shipped containerd
  snippets, systemd socket activation, and secret rotation.

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
  `credentialprovider` keyring and config search order, health check endpoints.
- go-containerregistry `pkg/authn/kubernetes` (keyring from secrets).
- Dragonfly: Go layout and config reload (`cmd/dependency`), dfdaemon GC
  (`dragonfly-client/src/gc`).
- containerd/nydus-snapshotter: DaemonSet installer (`misc/snapshotter`) and
  fixed issues #288, #631, #673, #688, #771, #791, #796.
