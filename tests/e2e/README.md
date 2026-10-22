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
| `compat/`                   | Explicit feature-disabled binary variants; a separate CI lane, not a test against the GA binary.                                      |

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

This refactor has **109 product entry points** (`Test` and `Fuzz`, excluding
`TestMain` and `internal`): 85 GA including the separately provisioned
Dragonfly lane, 20 experimental, one feature-compat entry and three manual.
These are not counts of expanded subtests: the filesystem contract expands
C01-C15 over adapters/layouts/modes, and table-driven cases add more variants.

| Group | Entry points |
| --- | ---: |
| Filesystem: `contract`, `kernel`, `api` | 2 + 2 + 2 |
| Image CLI: `build`, `tar`, `export` | 9 + 7 + 3 |
| Image distribution: `nydusify`, `registry`, `dragonfly` | 10 + 16 + 9 |
| Storage/lifecycle: `cache`, `fault`, `soak` | 13 + 9 + 2 |
| Historical images: `golden` | 1 |
| Reduced feature binaries: `compat` | 1 |
| Experimental: fanotify, NBD, ublk, UFFD | 5 + 4 + 2 + 9 |
| Manual: bench, hugetar, topimages | 1 + 1 + 1 |

Rust external integration targets add **85 `#[test]` cases** (61 in
`nydus`, 2 backend, 10 core, 12 storage), plus the harnessless cross-process
KI-3 reproducer. They exercise in-process APIs and deterministic lifetime/
state-machine boundaries; they do not replace mounted CLI E2E. The two
nydusify builder-backed integration entry points remain in its own Go module.

### Execution tiers

- PR: GA suites, harness checks, real feature-disabled binaries, Rust
  integration tests, all four experimental transports, and ten aggregate
  minutes of tar/structured footer-meta fuzzing per target (four independent
  150-second shards). CI calls the experimental and ublk
  workflows and includes them in its gate. FUSE and fileio contract matrices
  run as separate jobs by adapter and image group (semantics/lifecycle,
  zstd, other layouts), retaining every case and mount mode. Workflow
  convention tests enforce that each contract branch is selected exactly
  once. Backend faults and API/registry tests run separately.
  ublk's build/Rust tests and E2E run in separate jobs; its independent
  build cannot prevent the other transports from running.
- PR and release: the separate Release workflow runs the shipped amd64
  **and** arm64 binaries, generates golden
  images with each artifact and read/export those exact images before
  publication. Required historical versions cannot silently disappear;
  generating today's images does not fabricate a historical baseline.
  An empty historical corpus now fails CI. PR runs never publish a release.
  Shipped-binary contracts use the same image-group partitions; golden
  verification and generation have their own jobs on each architecture.
- Nightly: experimental transports and fuzzing also run on schedule.
- Manual: dispatch Nightly for the one-hour local/remote shared-cache soak;
  dispatch Manual for benchmarks or hugetar, and the top-images workflow
  for the large image sweep. These heavy workloads do not run on PRs.
  Ordinary GA soak defaults remain a 30-second smoke.
- Manual performance: cold large-directory lookups and existing I/O/metadata
  workloads can gate against an explicitly accepted, host/workload-matched
  baseline. No uncalibrated universal performance or RSS threshold is used.

Sharded GA E2E, release verification, fuzz and short-soak jobs have a five-minute
execution budget, including setup (not queue/dependency wait time). Test
deadlines leave time for timeout diagnostics. Cold compiler caches and
runner provisioning still affect build checks; their runtime must be
measured rather than inferred from the warm-cache test timings.
CI package installation uses Ubuntu's canonical archive on hosted x86
runners and bounded network retries; self-hosted package sources are retained.
Only benchmarks install `fio`. Release pins the default Rust toolchain
before restoring its cache, avoiding cache invalidation by runner image updates.
Rust and Go release binaries build in parallel; a separate packaging job
checks both downloaded binaries for static linking and executable startup.
The NBD demand-paging test requires `udevadm` to finish asynchronous device
probes before measuring metadata-only cache growth. ublk waits for its control
device after module loading and reports module-loading errors explicitly.

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
[feature variants](compat/README.md),
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
