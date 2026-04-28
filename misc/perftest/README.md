# nydus perftest image (Dragonfly proxy SDK mode)

A self-contained container image that mounts a Nydus image via FUSE and
benchmarks cold-cache parallel reads through **Dragonfly proxy SDK mode**.

Dragonfly itself (dfdaemon + scheduler) is expected to run **outside** this
container. The proxy and scheduler endpoints are passed in via environment
variables. The image bundles a static nydusd by default; bind-mount a locally
built nydusd over `/usr/local/bin/nydusd` when comparing daemon changes without
rebuilding the image.

## What it measures

The benchmark performs a single cold-cache pass:

1. nydusd is started with the supplied config and a freshly-fetched bootstrap.
2. The harness waits until FUSE is mounted *and* `nydusctl info` reports
   `state == RUNNING`. The elapsed time is recorded as **mount_ready_sec**.
3. A thread pool reads every regular file under the mountpoint in parallel
   chunks. The harness records:
   - `files_read`, `bytes_read`, `wall_clock_sec`
   - `throughput_mbps = bytes_read / wall_clock`
   - per-file read `latency_ms` (mean, p50, p90, p95, p99)
4. `nydusctl info` and `nydusctl metrics` (backend, blobcache, fs) are scraped
   at the end and embedded in the JSON summary so you can confirm requests
   actually went through the SDK proxy path.

> **Cold-cache caveat.** Each container run starts with an empty local
> blobcache (`BLOB_CACHE_DIR`, default `/var/lib/nydus/cache`). However, the
> external dfdaemon's own cache persists across runs. For a true cold pass:
> either flush the dfdaemon cache between runs, or use a unique image per run.

## Building

From the repo root:

```bash
make perftest-image                                # builds nydus-perftest:latest
# or directly:
docker build -f misc/perftest/Dockerfile -t nydus-perftest:latest .
```

The Dockerfile has three stages:

1. A musl Rust builder (`clux/muslrust`) that runs
   `cargo build --release --target $RUST_TARGET --bin nydusd --bin nydusctl --features=virtiofs`.
   The `backend-dragonfly-proxy` storage feature is target-gated for x86_64 /
   aarch64 in the workspace `Cargo.toml`, so it is automatically enabled on
   supported arches. `protoc` + `cmake` are pre-installed for the tonic /
   dragonfly-api build scripts.
2. A Go builder (`golang:1.22-alpine`) that produces a static `crane` binary
   (for image manifest / bootstrap resolution) and a static `workload` binary
   built from `misc/perftest/workload/`.
3. An Ubuntu runtime containing `nydusd`, `nydusctl`, `crane`, `workload`,
   plus `bash`, `fuse3`, `jq`, `gettext-base`, `tar`, `tini`, and the
   libraries needed by normal glibc-linked local nydusd builds.

For arm64 hosts, set `--build-arg RUST_TARGET=aarch64-unknown-linux-musl`
(or `make perftest-image RUST_TARGET_STATIC=aarch64-unknown-linux-musl`).

## Running

Minimum invocation against an external Dragonfly (dfdaemon listening on the
host at `:4001`, scheduler at `:8002`):

```bash
docker run --rm \
    --cap-add SYS_ADMIN \
    --device /dev/fuse \
    --security-opt apparmor=unconfined \
    --security-opt seccomp=unconfined \
    --add-host host.docker.internal:host-gateway \
    -e NYDUS_IMAGE=ghcr.io/dragonflyoss/image-service/nginx:nydus-latest \
    -e DRAGONFLY_PROXY_URL=http://host.docker.internal:4001 \
    -e DRAGONFLY_SCHEDULER_ENDPOINT=http://host.docker.internal:8002 \
    -v "$PWD/results:/results" \
    nydus-perftest:latest
```

If FUSE inside the container fails on your host, fall back to `--privileged`
(rootless Docker / Podman often need this). The `--add-host` flag is only
needed on Linux to make `host.docker.internal` resolve to the host gateway.

The summary is written to `./results/result.json` and printed to stderr.

## Configuration

### Using a locally built nydusd

By default the harness runs the bundled `/usr/local/bin/nydusd`. To test a
locally built daemon without rebuilding the perftest image, bind-mount it over
that path:

```bash
docker run --rm \
    --privileged \
    --device /dev/fuse \
    --security-opt apparmor=unconfined \
    --security-opt seccomp=unconfined \
    --add-host host.docker.internal:host-gateway \
    -e NYDUS_IMAGE=ghcr.io/dragonflyoss/image-service/nginx:nydus-latest \
    -v "$PWD/target/release/nydusd:/usr/local/bin/nydusd:ro" \
    -v "$PWD/results:/results" \
    nydus-perftest:latest
```

The entrypoint validates `/usr/local/bin/nydusd` before fetching the bootstrap,
logs `nydusd --version`, and records the selected binary and version in
`result.json` and the printed summary.

### Option A: bring your own nydusd config (recommended for real workloads)

```bash
-v /path/to/nydusd.json:/etc/nydus/user.json:ro \
-e NYDUSD_CONFIG=/etc/nydus/user.json
```

When `NYDUSD_CONFIG` is set and points to an existing file, the harness uses
it verbatim. You are responsible for setting `host`/`repo`/`proxy.url`/
`proxy.dragonfly_scheduler_endpoint` correctly. You may also pre-supply a
bootstrap file with `-v ...:/path/bootstrap -e BOOTSTRAP_PATH=/path/bootstrap`
to skip the registry fetch.

### Option B: render config from template

When `NYDUSD_CONFIG` is unset, `config.template.json` is rendered with these
env vars (defaults shown):

| Variable                       | Default                                                      | Notes |
|--------------------------------|--------------------------------------------------------------|-------|
| `NYDUS_IMAGE`                  | `ghcr.io/dragonflyoss/image-service/nginx:nydus-latest`      | Full image ref. Parsed into REGISTRY_HOST/REPO. |
| `REGISTRY_HOST`                | (parsed from NYDUS_IMAGE)                                    | Override if the parser guesses wrong. |
| `REGISTRY_REPO`                | (parsed from NYDUS_IMAGE)                                    | |
| `REGISTRY_SCHEME`              | `https`                                                      | |
| `REGISTRY_AUTH`                | empty                                                        | base64(user:pass) for basic auth. |
| `REGISTRY_SKIP_VERIFY`         | `false`                                                      | |
| `DRAGONFLY_PROXY_URL`          | `http://host.docker.internal:4001`                           | dfdaemon proxy listen URL. |
| `DRAGONFLY_SCHEDULER_ENDPOINT` | `http://host.docker.internal:8002`                           | Non-empty value enables SDK mode. |
| `PROXY_FALLBACK`               | `true`                                                       | Fall back to direct registry if proxy is unhealthy. |
| `BLOB_CACHE_DIR`               | `/var/lib/nydus/cache`                                       | nydusd blobcache work_dir. |
| `PREFETCH_ENABLE`              | `false`                                                      | Background prefetch threads. |
| `PREFETCH_THREADS`             | `8`                                                          | |

### Workload knobs

| Variable             | Default | Notes |
|----------------------|---------|-------|
| `READ_PARALLELISM`   | `16`    | Concurrent file readers. |
| `READ_CHUNK_SIZE`    | `1048576` | Bytes per `read()` call. |
| `MAX_FILES`          | `0`     | Cap files read; 0 = no cap. |
| `MOUNT_READY_TIMEOUT`| `60`    | Seconds to wait for FUSE + RUNNING. |
| `NYDUSD_LOG_LEVEL`   | `info`  | trace/debug/info/warn/error. |
| `PLATFORM`           | `linux/amd64` | OCI platform for multi-arch images. |
| `RESULTS_DIR`        | `/results` | Where `result.json` is written. |

### Bootstrap

The bootstrap (image metadata) is required by nydusd. By default the harness
fetches it from `NYDUS_IMAGE` using `crane` (manifest -> bootstrap layer ->
untar to extract `image.boot`). To skip this step, mount a pre-extracted
bootstrap file and set `BOOTSTRAP_PATH=/path/to/bootstrap`.

## Output

`$RESULTS_DIR/result.json` has the shape:

```jsonc
{
  "image":        "ghcr.io/.../nginx:nydus-latest",
  "platform":     "linux/amd64",
  "bootstrap_path": "/tmp/nydus/bootstrap",
  "config_path":  "/tmp/nydus/nydusd.json",
  "dragonfly": { "proxy_url": "...", "scheduler_endpoint": "...", "proxy_fallback": true },
  "timing_sec":   { "mount_ready": 0.643, "workload": 12.518 },
  "workload":     { "files_read": 1213, "bytes_read": 142860288, "throughput_mbps": 11.42,
                    "latency_ms": { "mean": 18.4, "p50": 9.1, "p90": 41.7, "p95": 63.2, "p99": 121.0 } },
  "workload_rc":  0,
  "nydusd": {
    "binary":    "/usr/local/bin/nydusd",
    "version":   "Version: ...",
    "info":      { ... },   // nydusctl info
    "backend":   { ... },   // backend metrics: bytes pulled, request count
    "blobcache": { ... },   // cache hit/miss
    "fs":        { ... }    // fs-level counters
  }
}
```

Inspect `nydusd.backend` to confirm requests actually went through the SDK
proxy path; the request counters there are what tells you the SDK was used.

## Limitations / known gotchas

- **External dfdaemon cache is not flushed by this image.** If you want
  cold-from-Dragonfly results, drop the dfdaemon cache between runs or
  rotate the test image.
- **Bootstrap fetch goes direct (not through the proxy).** This is setup,
  not the measured path; the data-blob reads are what's actually being
  benchmarked through the SDK.
- **Single cold-pass only.** No warm-cache or baseline modes — keep this
  image focused. If you need them, run twice with different cache dirs.
- **FUSE in containers** is fragile: rootless runtimes, locked-down seccomp
  profiles, or AppArmor policies can all block the mount. Use
  `--privileged` if the documented `--cap-add SYS_ADMIN --device /dev/fuse`
  combination doesn't work on your host.
