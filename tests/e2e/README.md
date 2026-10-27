# nydus end-to-end tests

Every product suite is a Go package under this directory. The suites run real
`nydus`/`nydusify` binaries as root against real mounts. Product unit tests
live with their crates; harness unit tests live under `internal/` and are
not counted as product E2E cases.

```sh
make e2e PKG=./contract/...            # one suite
make e2e PKG='./build/... ./export/...' E2E_RUN=TestMerge
make e2e-ga E2E_REQUIRE=1              # every GA suite, as CI runs them
make e2e-experimental                  # nbd, fanotify, ublk, uffd
```

The targets build `nydus` with `--profile ci` and point the tests at it
through `NYDUS_BIN`/`NYDUSIFY_BIN`; the test binaries are compiled as you
and run through `sudo -E`.

## Layout

| Package                     | What it proves                                                                                                                          |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `contract/`                 | The filesystem contract (cases C01-C15 in `internal/contract`) through FUSE and fileio.                                                 |
| `api/`                      | Per-daemon metrics/trace isolation, HTTP method/path errors, disconnected clients, shutdown and stale Unix socket replacement.         |
| `continuity/`               | FUSE hot upgrade with open handles, pre-ready rollback, live-owner exclusion, no-API operation and exact FD transfer.                  |
| `build/`                    | `nydus build/merge/check/optimize` across every GA layout: output contract, fsck.erofs, reproducibility.                                |
| `tar/`                      | OCI layer tarballs (Go and containerd corpora, generated and mutated layers, large files) convert to the tree `archive.Apply` produces. |
| `export/`                   | `nydus export` reproduces the layer; build -> export -> build is a fixed point.                                                         |
| `nydusify/`                 | `nydusify convert/check/optimize/mount/tooci` against an in-process registry.                                                           |
| `golden/`                   | Images built by released versions (`testdata/<version>/`) still read back exactly.                                                      |
| `kernel/`                   | The kernel EROFS driver reads native images the same way the FUSE reader does.                                                          |
| `cache/`                    | Several FUSE daemons sharing one cache directory, including crashes and corruption.                                                     |
| `fault/`                    | Backend errors, short reads, bit flips, daemon crashes, ENOSPC, signals: never wrong bytes.                                             |
| `soak/`                     | Long parallel reads and mount cycles leak no fd, thread, mount or process.                                                              |
| `dragonfly/`                | Reads through Dragonfly P2P, and fallback to the origin when it fails.                                                                  |
| `registry/`                 | Origin reads, Basic/Bearer auth, redirects, HTTP retries/proxies, TLS trust and prefetch retries. |
| `experimental/<transport>/` | The contract plus transport specifics for nbd, fanotify, ublk and uffd.                                                                 |
| `manual/`                   | Benchmarks and the top-images sweep (`//go:build manual`).                                                                              |

### Case boundaries and inventory

Group cases by their observable contract, not merely by the injected status:

- `registry` owns HTTP/auth/redirect/range policy; `dragonfly` owns P2P
  versus origin selection and its distinct prefetch/on-demand policy.
- `fault` owns mounted read failures, shutdown and recovery. ENOSPC must
  hit the write-failure counter, while still serving a fully cached file.
- `cache` owns sharing, persistence and eviction. Diskless FUSE reads exceed
  the shared 32MiB decoded-data budget across blobs, refetch an evicted blob,
  recover from a real registry fault and create no persistent files.
  32MiB is **not** a total process RSS limit.
- `build`/`export` own CLI and format contracts, including bounded failure.
  `nydusify` owns publication and consumption of OCI images. Its artifact
  case runs the Rust `writer-fixture` example, publishes parent/child images,
  proves descriptor-only parent reuse, then pulls and mounts the child.
- `api` owns service behavior, independent of the optimizer that consumes
  its trace. `soak` owns duration/resource growth, not another correctness
  matrix. Benchmarks own performance only.
- Pure log-pattern, settings, baseline-comparison and golden-selection tests
  belong in `internal/`. NBD/fanotify share the tested transport-log oracle.
  Subtests express input variants of one contract instead of multiplying
  packages or duplicating whole test bodies.

This refactor has **111 product entry points** (`Test` and `Fuzz`, excluding
`TestMain` and `internal`): 88 GA including the separately provisioned
Dragonfly lane, 20 experimental and three manual.
These are not counts of expanded subtests: the filesystem contract expands
C01-C15 over adapters/layouts/modes, and table-driven cases add more variants.

| Group | Entry points |
| --- | ---: |
| Filesystem: `contract`, `kernel`, `api` | 2 + 2 + 2 |
| FUSE process continuity: `continuity` | 5 |
| Image CLI: `build`, `tar`, `export` | 10 + 7 + 3 |
| Image distribution: `nydusify`, `registry`, `dragonfly` | 10 + 16 + 6 |
| Storage/lifecycle: `cache`, `fault`, `soak` | 13 + 9 + 2 |
| Historical images: `golden` | 1 |
| Experimental: fanotify, NBD, ublk, UFFD | 5 + 4 + 2 + 9 |
| Manual: bench, hugetar, topimages | 1 + 1 + 1 |

Rust external integration targets add **92 `#[test]` cases** (68 in
`nydus`, 2 backend, 10 core, 12 storage), plus the harnessless cross-process
KI-3 reproducer. They exercise in-process APIs and deterministic lifetime/
state-machine boundaries; they do not replace mounted CLI E2E. The
nydusify builder-backed integrations remain in its own Go module.

The writer integration cases also cover empty-file commits, no-op/rejected writes
without output artifacts, and parent-image preservation on deferred read
failure. Fast Go tests in `nydusify/internal/checker` and
`nydusify/internal/nydusfs` cover individual metadata/config mismatches,
truncated bootstrap extraction, concurrent blob-meta linking, and copy-failure
cleanup. These run in the existing Rust and `make test-nydusify` jobs, not as
additional E2E checks.

The Go SDK build/merge integrations verify streamed directory contents, sparse
metadata-only reads, native versus chunked sidecars, layer order, and output
failure cleanup. Multi-platform reverse conversion checks both architectures'
payloads, DiffIDs, platform markers and GC references, passes through ordinary
and attestation manifests, and rejects unreadable index children. These reuse
`make test-nydusify`; set `NYDUS_TEST_BUILDER` locally to exercise the real builder.
`TestCheck/ForcedUnmount` stops a real FUSE daemon, waits the unchanged 10-second
cleanup deadline, and forces both FUSE helpers to fail before real `umount`.
It verifies child reaping and absence of mounts/scratch before harness cleanup.

### Execution tiers

Only fanotify, NBD, ublk and UFFD are experimental. Fuzzing and stability
soaks validate GA behavior; they are execution modes, not experimental
features. The neutral `Extended E2E` workflow groups these checks to share
a build and schedule, without changing their classification.

- PR: GA suites, harness checks, Rust integration tests, all four experimental
  transports, and one 150-second fuzz run per target with four Go workers.
  This is a smaller PR search budget than four independent 150-second shards,
  not an equivalent amount of exploration. CI calls the extended E2E
  workflow and includes it in its gate. FUSE runs its complete contract in
  one job; Fileio keeps semantics/lifecycle, zstd data and other-layout data separate,
  retaining every case and mount mode. Workflow
  convention tests enforce that each contract branch is selected exactly
  once. Backend faults and API/registry tests run separately; FUSE continuity
  shares the image/tools/services check. `make test-fuse-continuity` runs it locally;
  `FUSE_CONTINUITY_PREDECESSOR=/absolute/path/to/nydus` selects a separate
  hot-upgrade-capable predecessor (not the older image-format baseline).
  The image-tools job checks that the real GA CLI includes all required
  commands; registry/Dragonfly E2E exercise their compiled backends. Arbitrary
  reduced-feature binaries are no longer a PR matrix. The main Rust job
  includes ublk, the ptrace cross-process test and real netns HTTP tests once;
  ublk E2E shares the extended build. If the runner lacks `ublk_drv`,
  its job installs `linux-modules-extra-$(uname -r)` before loading the driver;
  an unavailable package or driver remains a failure, never a skipped suite.
- PR and release: static amd64 **and** arm64 binaries are packaged and tested
  in one verification job per architecture, after a shared Rust/Go build job
  for that architecture. Verification downloads the checksum-verified
  `v3.0.0-beta.3` release, builds historical images with that binary, and
  requires the current binary to read them. The released reader also reads
  current images through its supported FUSE/check/export commands (the beta.3
  artifact has no Fileio). Current-reader checks include Fileio, GA CLI
  availability and current-image round trips. Empty compatibility inventories
  fail; today's builder never substitutes for the released baseline.
  The baseline intentionally uses the current group-digest format; beta.1's
  old digest representation is not part of the supported compatibility window.
  Full shipped-binary contract shards run on tags/manual releases, not again
  on PRs. PR runs never publish a release.
- Nightly: all experimental transports and continuous ten-minute fuzz runs
  per target run on schedule. UFFD additionally repeats each real-fault
  copy/zeropage/zerocopy case 34 times, also on manual Nightly runs.
  Dragonfly has its own daily schedule and shares the same reusable workflow
  with PR CI; it runs real services, not a Kind/Helm deployment test.
- Manual: dispatch Nightly for the one-hour local/remote shared-cache soak;
  dispatch Manual for benchmarks or hugetar, and the top-images workflow
  for the large image sweep. These heavy workloads do not run on PRs.
  Ordinary GA soak defaults remain a 30-second smoke.
- Manual performance: cold large-directory lookups and existing I/O/metadata
  workloads can gate against an explicitly accepted, host/workload-matched
  baseline. No uncalibrated universal performance or RSS threshold is used.

### PR check groups

| Prefix/group | Coverage |
| --- | --- |
| `lint / workspace / rust-go` | Formatting/Clippy; both Go modules, harness tests and manual-suite compilation |
| `build / binaries / ga`, `test / rust / unit-integration` | Shared GA binaries; workspace unit/integration tests and coverage |
| `test / image / tools-services` | Build, tar, export, kernel, nydusify, API, registry and FUSE hot upgrade |
| `test / fuse / contract`, `test / fileio / *` | One complete FUSE contract; Fileio semantics and two data-layout groups |
| `test / storage / *` | Isolated fault recovery and cache/resource-leak smoke |
| `distribution / dragonfly / read-recovery` | Real Dragonfly services, seed-cache reads and origin fallback in one cluster |
| `extended / * / *` | One shared build, four experimental transports, one two-target fuzz job, one stability job |
| `build / static / *`, `release / verify / *` | Static Rust/Go build and packaged-binary compatibility, each on amd64 and arm64 |

PR checks use `category / module / scenario`. Reusable workflows supply the
module/scenario name, while their caller supplies `extended` or `distribution`;
GitHub inserts the slash. Their standalone scheduled/manual runs display the
module/scenario name without the caller prefix. Matrix display labels do not
change suite selectors or artifact names. `Classify PR` retains its name because
upstream branch protection requires it; external DCO and Codecov names are unchanged.

Related packages run concurrently with bounded Go package/test parallelism.
Both fuzz targets run concurrently, each retaining four workers and its full
150-second PR (ten-minute scheduled/manual) duration. The job waits for both
and fails if either fails. Sharing a runner reduces checks, not the configured
time budget; CPU contention can still reduce executions per target.
The stability job runs all four local/remote x FUSE/Fileio leaves together,
preserving two minutes per leaf on PRs instead of serializing two waves.
No test cases or fuzz duration are removed by grouping checks.
Fileio data and storage recovery retain their original isolation: trial
consolidation exceeded the data-test budget and caused recovery-read timeouts.

Grouped GA E2E, release verification, PR fuzz and short-soak jobs have a five-minute
execution budget, including setup (not queue/dependency wait time). Test
deadlines leave time for timeout diagnostics. Cold compiler caches and
runner provisioning still affect build checks; their runtime must be
measured rather than inferred from the warm-cache test timings.
CI package installation uses Ubuntu's canonical archive on hosted x86
runners and bounded network retries; self-hosted package sources are retained.
Only benchmarks install `fio`. Release pins the default Rust toolchain
before restoring its cache, avoiding cache invalidation by runner image updates.
Rust and Go release binaries build in parallel; release verification includes
packaging, static-linking checks and executable startup.
The NBD demand-paging test requires `udevadm` to finish asynchronous device
probes before measuring metadata-only cache growth. ublk waits for its control
device after module loading and reports module-loading errors explicitly.

### Product coverage in existing checks

The three CI workflows explicitly set `CI_COVERAGE=1`; ordinary `make` builds
and release artifacts remain uninstrumented. The existing shared builds use
Rust `-C instrument-coverage` through `RUSTC_WORKSPACE_WRAPPER` (workspace crates
only, avoiding instrumentation overhead in third-party checksum loops) and
override the CI profile's inherited symbol
stripping (`CARGO_PROFILE_CI_STRIP=none`). They bundle the matching Rust 1.88.0
LLVM tools, compiler version and binary checksums with the instrumented binaries.
Export verifies these checksums; Ubuntu's unrelated LLVM version is not used.
The writer fixture remains an uninstrumented test helper, not product coverage.
Go products use `go build -cover -covermode=atomic -coverpkg=./...`.
`make test-nydusify` keeps `-race` and adds a module-wide `-coverpkg` profile.
Its Linux cross-filesystem link tests require writable `/dev/shm` on a different
filesystem from the test work directory and assert `EXDEV`; unavailable
prerequisites fail instead of skipping the case.
Checker tests cover cleanup when target mounting fails after the source is
mounted, filesystem walking fails, or source/target contents mismatch.
The Rust unit/integration check accumulates both the workspace and dual-TLS
runs before exporting one report.

Each existing E2E job exports and uploads `coverage/`, including on test failure:

| File | Contents |
| --- | --- |
| `raw/rust/*.profraw`, `rust-e2e.profdata` | Raw pooled subprocess counters and their merge |
| `raw/go/covmeta.*`, `raw/go/covcounters.*` | Go product subprocess metadata and counters |
| `rust-e2e.lcov`, `go-e2e.out` | Product-subprocess Rust LCOV (also Go builder-backed integrations) and Go E2E coverage, not Go harness coverage |
| `go-unit-integration.out` | nydusify unit/integration coverage in the image/tools job |
| `go-combined.out` | Deduplicated Go unit/integration + product E2E statement coverage in that same job |
| `status.txt` | Test outcome, profile counts and collection limitations |

The Rust test artifact instead contains `raw/rust/` and
`rust-unit-integration.lcov`. The post-CI
[coverage reporter](../../.github/workflows/coverage-comment.yml) merges hits
across the 15 expected artifacts and updates one bot comment on the current PR
head. Rust lines and Go statements stay separate; missing/failed shards are
listed explicitly, not counted as zero. No baseline delta is claimed without a
comparable base-commit report. Rust includes test code and does not
represent production-only or branch coverage.

The existing `gate / ci / required` check reads those same artifacts and
requires **Rust line coverage >= 90% and Go statement coverage >= 90%** separately.
It unions hits rather than averaging shard percentages and compares exact counts,
not rounded percentages. Missing/invalid reports or unsuccessful shards also
fail the gate, even when the available reports exceed 90%. No new test check is
added, and enforcement does not depend on the default-branch reporter deployment.
It reuses the reporter's newest-artifact selection so reruns cannot mix old
failed shards with their successful replacements.
To run the same gate locally after downloading artifacts into separate
subdirectories, use
`python3 tests/scripts/coverage_comment.py --check-dir coverage-input`.

The reporter checks out only the trusted default branch, parses allowlisted
reports without extracting or executing artifacts, and rechecks the PR head
before posting. Older runs/rerun attempts cannot replace newer comments.
Codecov uploads use `rust_combined` and `go_combined` flags in this separate
reporting job, with one-minute per-upload limits. PR test jobs only export and
retain artifacts, so upload-service delays cannot exhaust their five-minute
budgets. Standalone scheduled/manual extended and Dragonfly runs keep their
bounded Codecov uploads.

**Deployment:** `workflow_run` requires the workflow and its reporter script on
the repository's default branch (`master` upstream), not just `v3`. Until those
files are deployed there, CI artifacts remain available, but automatic comments
and post-CI Codecov uploads are not active. This PR does not modify `master`.

Upload-service failures do not gate tests, but
missing expected profiles and export failures do. A shard that never runs
nydusify records `go_report=no-profile`, not synthetic zero coverage;
image/tools requires Go subprocess profiles. Skipped/cancelled suites are
explicitly marked when the finalizer runs; a cancelled job may not upload an
artifact and its absent report must not be interpreted as zero coverage.
For a local statement-coverage union, run
`bash tests/scripts/e2e_coverage.sh merge-go UNIT.out E2E.out`.
It writes `coverage/go-combined.out` (or `$COVERAGE_DIR/go-combined.out`),
deduplicates source blocks and normalizes counter modes to boolean `set`;
it rejects incompatible source layouts from different builds instead of
adding percentages or claiming merged execution frequencies.

`LLVM_PROFILE_FILE` uses `%8m`, bounding files to eight per instrumented
module rather than one per short-lived fuzz process. Normal exits merge
counters into this pool. **SIGKILL, abort and forced timeouts cannot flush
counters**: recovery/crash-path coverage is therefore explicitly partial,
not evidence that those paths were untested. Raw profiles and final reports
are retained for diagnosis. No test, fuzz/soak duration, Kind/Helm deployment,
check name or five-minute PR timeout is changed. Instrumentation, larger
binary/tool artifacts and export add overhead; full CI budget compliance
requires a rerun and cannot be inferred from a local CLI smoke test.

Runners default to GitHub-hosted Ubuntu (arm64 for arm64 release validation).
`E2E_*_RUNNER` variables can override them, but no unregistered self-hosted
label is assumed. Missing kernel capabilities/tools fail through
`E2E_REQUIRE=1`; they do not skip. Rust tests also require netns/setns and
ptrace, and run privileged test executables without compiling as root.
`NYDUS_TEST_FAIL_KNOWN_ISSUES=1` makes both Go and Rust enforce the intended
behavior of known issues: known bugs fail, fixed behavior passes. Expect
red checks for the documented unresolved bugs rather than an all-green
result obtained by suppressing them.

See [capabilities and soak settings](soak/README.md),
[golden retention](golden/testdata/README.md), and
[performance baseline policy](manual/bench/README.md). Runner provisioning,
historical release fixtures and calibrated performance budgets remain
external prerequisites, not successful tests when absent.

Shared code lives in `internal/`:

| Package       | Role                                                                      |
| ------------- | ------------------------------------------------------------------------- |
| `env`         | Binaries under test, preconditions (`Require*`), known issues.            |
| `corpus`      | Source tree generators.                                                   |
| `fixture`     | Named corpora and GA layouts, built once and cached across test binaries. |
| `mount`       | Daemons, the FUSE/fileio adapters, configs, the apiserver client.         |
| `oracle`      | The judges: tree diff, manifest trees, extents, tar views, fsck.erofs.    |
| `contract`    | The contract cases, run by every adapter.                                 |
| `registry`    | In-process OCI registry behind a fault-injecting proxy.                   |
| `proc`        | fd/thread/RSS/mount sampling for leak checks.                             |
| `conventions` | Enforces the rules below.                                                 |

## Conventions

`internal/conventions` fails the build when these are broken:

- A `_test.go` file holds exactly one top-level `Test` or `Fuzz` function,
  named after the file: `TestFUSE` lives in `fuse_test.go`, `FuzzTarHeader`
  in `fuzz_tar_header_test.go`. `main_test.go` holds only `TestMain`; shared
  test code goes in `*_helpers_test.go`, which holds no tests.
- A top-level test starts with `t.Parallel()`. A test that must not overlap
  others says why with a `//e2e:serial <reason>` comment in its file.
- Nothing calls `t.Skip*`. A missing precondition goes through
  `env.Require` (or `RequireRoot`, `RequireKernel`, `RequireTool`, ...):
  locally it skips, with `NYDUS_E2E_REQUIRE=1` (CI) it fails.

And by agreement:

- Build images through `fixture` (`fixture.Get`, `fixture.Build`,
  `fixture.Merged`), never in a test's own temp dir unless the build itself
  is under test (`fixture.BuildInto`). Cached images are shared and
  read-only; `fixture.Copy` one before damaging it.
- Mount through `mount.Mount` with an adapter; judge with `oracle`.
- A test that reproduces a known bug is wrapped in
  `env.KnownIssue(t, "KI-N", func(t env.TB) {...})` (see KNOWN_ISSUES.md;
  keep setup outside the body). Locally, the default reports a reproduced
  bug as skipped and fails when the marker becomes stale. CI sets
  `NYDUS_TEST_FAIL_KNOWN_ISSUES=1`, so the same body is an ordinary assertion
  of correct behavior: a reproduced bug fails. Remove the marker when fixing it.
- Invariant for every fault test: a read either returns the right bytes or
  fails; it never returns wrong bytes.
  `TestBlobIntegrity/skip-checksums` deliberately opts out of validation to
  verify the documented configuration behavior.

## Backend and storage contracts

Dragonfly retains upstream's **Kind v0.32.0 + Helm chart 1.8.2** deployment,
using the unchanged files in `tests/testdata/{kind,charts,k8s}`. The chart
runs one scheduler and one seed client; manager and ordinary clients are
disabled. The origin is Docker `registry:2`. There is no separate local
manager, MySQL, Redis, or private cluster-control script.

To run it locally, follow the setup steps in
`.github/workflows/e2e-dragonfly.yml`, export
`KUBECONFIG` and `NYDUS_E2E_DRAGONFLY_SCHEDULER=http://127.0.0.1:8002`, then run
`make e2e-dragonfly E2E_REQUIRE=1`. The Kind network must use
`172.30.0.0/16`, with gateway `172.30.0.1`, so seed peers can reach the
registry and the source-IP-selective fault proxies on the host.

The combined Dragonfly job preserves upstream's reads, seed-cache hits,
prefetch/retry, 403/429/503 policy, fallback, fallback rate limit and failed
origin coverage. Existing startup-outage, transport-error and concurrent
recovery regressions remain enabled, using `kubectl scale` instead of
killing local processes. Outage assertions share one staged cluster cycle
(`TestOutageRecovery`) rather than repeatedly restarting the same pods:
seed failure, rate limiting, scheduler failure, origin errors, live-mount
recovery and prefetch recovery retain separate subtests. Every Dragonfly
entry point runs once without a test-name filter, enforced by a convention test.
The rate-limit case reads its complete payload in chunk-group-sized requests
with kernel read-ahead disabled, so coalescing cannot turn it into a single GET.

- Build the GA binary with `cli,fuse,fileio,dragonfly`. Registry timeouts
  use `http.request_timeout`; Dragonfly uses `request_timeout`,
  `max_retries` and `fallback_rate_limit`. Prefetch retries use
  `prefetch.retry_interval`, not the old min/max delay pair.
- Dragonfly prefetch retries transient HTTP statuses once, but transport
  errors terminate the task without origin fallback. Recovery after a
  terminal failure starts a new mount/prefetch. Completion requires a
  successful task for every blob and no uncached bytes, not a quiet request
  counter (failed requests also increment that counter).
- Run registry and soak regressions with a small CPU affinity as well as
  on large hosts. FUSE polling must return `ENOSYS` so the kernel handles
  subsequent polls without waiting behind reads; otherwise a Go process
  reading the mount and serving its registry can deadlock its network loop.
- Metrics use `nydus_*` names and labels. `Metrics.Sum` selects labels
  independently of their ordering. Successful backend reads identify
  `source="dragonfly"` or `source="fallback"`; failed reads identify the
  configured transport, so a failed fallback is counted under Dragonfly,
  not under a separate fallback-error counter. Retry/fallback decisions
  are checked through requests and logs, not removed per-attempt counters.
- Labeled counters may be absent before the first event. Positive control
  reads and cache gauges keep a renamed metric from turning an assertion
  into a vacuous zero-equals-zero check.
- The in-process registry supports suffix ranges for footer discovery,
  while retaining the original request in its fault log.
- Checksum verification is enabled by default and checks CRC32C, not the
  stored group digests. Cache options are per image; the former KI-5 is
  now an ordinary Rust regression test. Terminal Dragonfly 404 and auth
  401 handling likewise no longer carry the KI-11 marker.

Upstream's new registry scenarios live in `registry/`, prefetch scope
coverage in `cache/prefetch_scope_test.go`, exclusion coverage in
`build/build_exclude_test.go`, and checksum opt-out coverage in
`fault/blob_integrity_test.go`. They use the same fixtures, adapters and
precondition checks as the other categorized suites.
