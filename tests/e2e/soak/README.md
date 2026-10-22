# Stability tiers

`TestLeak` and `TestRemote` run in the PR cache shard. Defaults remain 30s,
20 mount cycles spread across the duration and 16 verified random-read workers
**per transport**. Both
FUSE and fileio run, so the host needs file-backed EROFS (Linux >=6.12,
CONFIG_EROFS_FS_BACKED_BY_FILE) as well as FUSE.

`TestRemote` serves a real registry with prefetch enabled, injects one 503
and asserts it was hit and recovered, then shares the populated cache
between the reading daemon and mount cycles. This is startup retry plus
long-running shared-cache stability, not a continuous outage/eviction test.
Prefetch and reads overlap during startup; the remote baseline is sampled
only after prefetch completion and the warmup period, avoiding false FD/RSS
growth from a late-initializing HTTP pool.

Manually dispatching Nightly runs `make e2e-soak`: default 1h and 120 cycles,
in parallel for
local/remote and FUSE/fileio. Configure repository variables
`E2E_SOAK_DURATION`, `E2E_SOAK_CYCLES`, `E2E_SOAK_RSS_MIB`, or locally.
The hour-scale job does not run on PRs or scheduled Nightly runs:

```sh
make e2e-soak SOAK_DURATION=1h SOAK_CYCLES=120 SOAK_RSS_MIB=64 E2E_REQUIRE=1
```

The 64MiB above is an example, **not a universal default**. The optional
budget fails on sampled peak RSS growth above the warmed baseline. Without
it, >10% final RSS growth is reported, not gated. FDs, threads, surviving
processes/mounts, forced shutdowns, blocked reads and wrong bytes always gate.

The underlying `NYDUS_E2E_SOAK_DURATION` accepts Go durations from 10s to
24h, `NYDUS_E2E_SOAK_CYCLES` integers 1–100000, and
`NYDUS_E2E_SOAK_RSS_MIB` positive integer MiB up to 1048576. Invalid
configuration fails, never silently falls back. Longer-than-default runs
also require increasing the Go/job timeout (the nightly job is 90 minutes).
No hour-scale run is needed for unit validation: `go test ./internal/soakconfig -run
TestSettings` validates the parser; a capability-matched host can run a
10s/one-cycle smoke with the same workload.

## Runner contract

Workflows default to GitHub-hosted Ubuntu, so no unregistered self-hosted
label leaves a job queued indefinitely. The suite checks actual capabilities;
an inadequate kernel is an explicit failure, not a skip. JSON runner-label
arrays can override those defaults:
`E2E_FILEIO_RUNNER`, `E2E_RELEASE_AMD64_RUNNER`,
`E2E_RELEASE_ARM64_RUNNER`, `E2E_FANOTIFY_RUNNER`,
`E2E_UFFD_RUNNER`, `E2E_NBD_RUNNER`, `E2E_UBLK_RUNNER`,
`E2E_BENCH_RUNNER`, `E2E_TOP_IMAGES_RUNNER`, and
`E2E_RUST_PRIVILEGED_RUNNER`.
For example `["self-hosted","linux","x64","nydus-fileio-6.12"]`.
Release architecture labels must actually match the downloaded artifact.
Fanotify requires Linux >=6.15 with FAN_PRE_ACCESS and ext4 cache storage;
UFFD needs permitted userfaultfd; ublk/NBD need their devices/modules.
All mandatory lanes set `E2E_REQUIRE=1`; capability labels do not replace
runtime checks. Use isolated, ephemeral runners for untrusted PRs.
The privileged Rust lane needs x86_64 Linux, sudo, permitted ptrace, and
network namespace creation/setns; it sets `NYDUS_TEST_REQUIRE_NETNS=1`
and `NYDUS_TEST_REQUIRE_PTRACE=1`, so an EPERM cannot pass as absent coverage.

ublk is built independently by its reusable Manual job, including on PRs,
not by the nightly shared binary.
Its existing libublk build incompatibility must be fixed independently;
unrelated transport, fuzz, and soak jobs must not depend on that build.
