# Stability tiers

`TestLeak` and `TestRemote` run in the PR cache shard. Defaults remain 30s,
6 mount cycles spread across the duration and 16 verified random-read workers
**per transport**. The `e2e.yml` matrix's `soak` row runs each workload for 2m with
6 cycles and two in-package tests, so FUSE and fileio run concurrently
instead of putting four two-minute workloads through two slots, under a
four-minute Go timeout. Both
FUSE and fileio run, so the host needs file-backed EROFS (Linux >=6.12,
CONFIG_EROFS_FS_BACKED_BY_FILE) as well as FUSE.

`TestRemote` serves a real registry with prefetch enabled, injects one 503
and asserts it was hit and recovered, then shares the populated cache
between the reading daemon and mount cycles. This is startup retry plus
long-running shared-cache stability, not a continuous outage/eviction test.
Prefetch and reads overlap during startup; the remote baseline is sampled
only after prefetch completion and the warmup period, avoiding false FD/RSS
growth from a late-initializing HTTP pool.

Nightly E2E Test runs the full `make e2e-soak` on schedule or by dispatch:
default 1h and 120 cycles for local/remote and FUSE/fileio. The PR soak is
deliberately bounded. Set the `NYDUS_E2E_SOAK_*` variables to run other
settings locally:

```sh
CI=1 NYDUS_E2E_SOAK_RSS_MIB=64 make e2e-soak
```

The 64MiB above is an example, **not a universal default**. The optional
budget fails on sampled peak RSS growth above the warmed baseline. Without
it, >10% final RSS growth is reported, not gated. FDs, threads, surviving
processes/mounts, forced shutdowns, blocked reads and wrong bytes always gate.

The underlying `NYDUS_E2E_SOAK_DURATION` accepts Go durations from 10s to
24h, `NYDUS_E2E_SOAK_CYCLES` integers 1–100000, and
`NYDUS_E2E_SOAK_RSS_MIB` positive integer MiB up to 1048576. Invalid
configuration fails, never silently falls back. Longer-than-default runs
also require increasing the Go/job timeout (the nightly soak job is 90 minutes).
No hour-scale run is needed for unit validation: `go test ./internal/soakconfig -run
TestSettings` validates the parser; a capability-matched host can run a
10s/one-cycle smoke with the same workload.

## Runner contract

Workflows run on GitHub-hosted `ubuntu-24.04` (and `ubuntu-24.04-arm` for
release arm64), written directly into `runs-on`. The suite checks actual
capabilities; an inadequate kernel is an explicit failure, not a skip. To move
a job to a self-hosted runner, edit its `runs-on` label; release architecture
labels must actually match the downloaded artifact.
Fanotify requires Linux >=6.15 with FAN_PRE_ACCESS and ext4 cache storage;
UFFD needs permitted userfaultfd; ublk/NBD need their devices/modules.
Under CI every lane is strict; capability labels do not replace runtime
checks. Use isolated, ephemeral runners for untrusted PRs. The main Rust test
job needs x86_64 Linux, sudo, permitted ptrace, and network namespace
creation/setns, so an EPERM cannot pass as absent coverage.

ublk shares the experimental binary build and has one E2E matrix job.
Its Rust tests run in the main Rust test job; neither suite is compiled
again inside the ublk E2E job.
