# nydus end-to-end tests

Every product suite is a Go package under this directory. The suites run real
`nydus`/`nydusify` binaries as root against real mounts. Product unit tests
live with their crates; `util/` holds helpers only and has no tests of its
own: the suites that use a helper are what exercise it.

```sh
make e2e PKG=./conformance/...         # one suite
make e2e PKG='./build/... ./export/...' E2E_RUN=TestMerge
CI=1 make e2e-ga                       # every GA suite but dragonfly and compatibility
make e2e-experimental                  # nbd, fanotify, ublk, uffd
```

The targets build `nydus` with `--profile ci` and point the tests at it
through `NYDUS_BIN`/`NYDUSIFY_BIN`; the test binaries are compiled as you
and run through `sudo -E`.

## Layout

| Package                     | What it proves                                                                                                                          |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `conformance/`              | Filesystem conformance, run against every adapter: `TestFUSE`, `TestFileio`, `TestNBD`, `TestUblk`, `TestFanotify`.              |
| `api/`                      | Per-daemon metrics/trace isolation, HTTP method/path errors, disconnected clients, shutdown and stale Unix socket replacement.         |
| `continuity/`               | FUSE hot upgrade with open handles, pre-ready rollback, live-owner exclusion, no-API operation and exact FD transfer.                  |
| `build/`                    | `nydus build/merge/check/optimize` across every GA layout: output contract, fsck.erofs, reproducibility.                                |
| `tar/`                      | OCI layer tarballs (Go and containerd corpora, generated and mutated layers, large files) convert to the tree `archive.Apply` produces. |
| `export/`                   | `nydus export` reproduces the layer; build -> export -> build is a fixed point.                                                         |
| `nydusify/`                 | `nydusify convert/check/optimize/mount/tooci` against an in-process registry.                                                           |
| `compatibility/`            | Images built by a released version still read back exactly with the nydus under test.                                                  |
| `kernel/`                   | The kernel EROFS driver reads native images the same way the FUSE reader does.                                                          |
| `cache/`                    | Several FUSE daemons sharing one cache directory, including crashes and corruption.                                                     |
| `fault/`                    | Backend errors, short reads, bit flips, daemon crashes, ENOSPC, signals: never wrong bytes.                                             |
| `soak/`                     | Long parallel reads and mount cycles leak no fd, thread, mount or process.                                                              |
| `dragonfly/`                | Reads through Dragonfly P2P, and fallback to the origin when it fails.                                                                  |
| `registry/`                 | Origin reads, Basic/Bearer auth, redirects, HTTP retries/proxies, TLS trust and prefetch retries. |
| `experimental/<transport>/` | The nbd, fanotify and ublk adapters and their transport specifics; the uffd page-fault protocol.                                        |
| `bench/`                    | Go benchmarks (`BenchmarkMount/<mode>`); they run only with `-bench`, as `make benchmark` does.                                                                    |

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
- NBD/fanotify share the transport-log checks in `experimental/transport`.
  Subtests express input variants of one contract instead of multiplying
  packages or duplicating whole test bodies.

### Execution tiers

Only fanotify, NBD, ublk and UFFD are experimental. Fuzzing and stability
soaks validate GA behavior; they are execution modes, not experimental
features. Fuzzing has its own `fuzz.yml` on the GA binaries. The soak
package is a GA E2E suite: a two-minute row of the `e2e.yml` matrix on PRs, and
the one-hour run in `e2e-nightly.yml` next to the huge sparse tar corpus.
`e2e-experimental.yml` runs only the experimental transports with its own build.

Workflows are split by test type, as in dragonfly: `ci.yml` runs the Rust and
nydusify unit/integration tests, `e2e.yml` the GA E2E matrix, `e2e-<variant>.yml`
one variant each, `fuzz.yml` the fuzz targets. Each triggers on push and pull
requests by itself; nothing is called from `ci.yml`.

- PR: GA suites, convention checks, Rust integration tests, all four experimental
  transports, and one 150-second fuzz run per target with four Go workers.
  This is a smaller PR search budget than four independent 150-second shards,
  not an equivalent amount of exploration. FUSE runs its complete conformance suite in
  one job; Fileio keeps semantics/lifecycle, zstd data and other-layout data separate,
  retaining every case and mount mode. Backend faults run separately; API, registry and FUSE continuity
  share the image-tools job. `make e2e-continuity` runs it locally;
  `NYDUS_E2E_FUSE_PREDECESSOR=/absolute/path/to/nydus` selects a separate
  hot-upgrade-capable predecessor (not the older image-format baseline).
  The image-tools job checks that the real GA CLI includes all required
  commands; registry/Dragonfly E2E exercise their compiled backends. Arbitrary
  reduced-feature binaries are no longer a PR matrix. The main Rust job
  includes ublk, the ptrace cross-process test and real netns HTTP tests once;
  ublk E2E shares the experimental build. If the runner lacks `ublk_drv`,
  its job installs `linux-modules-extra-$(uname -r)` before loading the driver;
  an unavailable package or driver remains a failure, never a skipped suite.
- Compatibility: `make e2e-compatibility` downloads the checksum-verified
  `v3.0.0-beta.3` release, builds historical images with that binary, and
  requires the current binary to read them. The released reader also reads
  current images through its supported FUSE/check/export commands (the beta.3
  artifact has no Fileio). Current-reader checks include Fileio and
  current-image round trips. Empty compatibility inventories
  fail; today's builder never substitutes for the released baseline.
  The baseline intentionally uses the current group-digest format; beta.1's
  old digest representation is not part of the supported compatibility window.
- Release: static amd64 and arm64 binaries are built, checked for static
  linking and a working `--help`, packaged with checksums, and published on
  tags. Release runs only on tags and runs no test suites.
- Scheduled: the experimental transports and continuous ten-minute fuzz runs
  per target run on schedule. UFFD additionally repeats each real-fault
  copy/zeropage/zerocopy case 34 times. Dragonfly has its own daily schedule.
- Nightly E2E: the one-hour local/remote shared-cache soak and the huge
  sparse tar corpus run on schedule.
- Weekly: Benchmark runs the cold-start benchmark and keeps `bench.txt` as
  an artifact; E2E Test With Image Conversion runs
  the nydusify convert/check sweep over popular images. Neither runs on PRs.
  Ordinary GA soak defaults remain a 30-second smoke.
### PR check groups

| Check | Coverage |
| --- | --- |
| `Lint / Lint` | Formatting/Clippy; golangci-lint over both Go modules, `manual`-tagged files included |
| `CI / Test`, `CI / Test Nydusify` | Workspace unit/integration tests; nydusify unit/integration tests against the real builder |
| `E2E Test / Build` | Shared GA binaries and coverage tools |
| `E2E Test / e2e (image-tools)` | Build, tar, export, kernel, nydusify, API, registry and FUSE hot upgrade |
| `E2E Test / e2e (fuse)`, `e2e (fileio-*)` | One complete FUSE conformance run; Fileio semantics and two data-layout groups |
| `E2E Test / e2e (storage-*)`, `e2e (soak)` | Isolated fault recovery, cache smoke and the two-minute stability soak |
| `E2E Test With Dragonfly / Test` | Real Dragonfly services, seed-cache reads, origin fallback and `nydusify --dragonfly-scheduler` in one cluster |
| `E2E Test With Experimental Transports / test (*)` | One shared experimental-feature build and four transports |
| `Fuzz / Fuzz` | One two-target fuzz job |
| `E2E Test With Compatibility / Test` | Historical and current images read by the current and the released reader |
| `codecov/project/rust`, `codecov/project/go` | Codecov's union of every flag for the commit; each fails below 90% |

Checks follow the dragonfly workflows: single-word job names, and matrix jobs
named `<job> (<matrix key>)`. Display labels do not
change suite selectors or artifact names. `Classify PR` retains its name because
upstream branch protection requires it; external DCO and Codecov names are unchanged.

Related packages run concurrently with bounded Go package/test parallelism.
Both fuzz targets run concurrently, each retaining four workers and its full
150-second PR (ten-minute scheduled) duration. The job waits for both
and fails if either fails. Sharing a runner reduces checks, not the configured
time budget; CPU contention can still reduce executions per target.
The soak row runs all four local/remote x FUSE/Fileio leaves together,
preserving two minutes per leaf on PRs instead of serializing two waves.
No test cases or fuzz duration are removed by grouping checks.
Fileio data and storage recovery retain their original isolation: trial
consolidation exceeded the data-test budget and caused recovery-read timeouts.

Grouped GA E2E jobs have an eight-minute execution
budget, including setup (not queue/dependency wait time). On push and pull
requests the fuzz workflow uses a four-minute Go timeout with the 150-second
fuzz duration; scheduled runs fuzz for ten minutes. Test
deadlines leave time for timeout diagnostics. Cold compiler caches and
runner provisioning still affect build checks; their runtime must be
measured rather than inferred from the warm-cache test timings.
Only benchmarks install `fio`. Release packaging checks static linking and
executable startup before creating the tarball.
The NBD demand-paging test requires `udevadm` to finish asynchronous device
probes before measuring metadata-only cache growth. ublk waits for its control
device after module loading and reports module-loading errors explicitly.

### Product coverage in existing checks

Coverage uses [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov), as
dragonflyoss/client does. `make build-coverage` builds under `cargo llvm-cov
show-env`, which instruments the workspace crates only, and builds nydusify
with `-cover`; with `COVERAGE=1`, `make e2e-run` and `make test-nydusify`
write raw profiles under `coverage/`. `make coverage-report` merges every raw
profile under `coverage/` into `coverage/rust-e2e.lcov` (`cargo llvm-cov
report`) and `coverage/go-e2e.out` (`go tool covdata`). Every job, including
each shard of `e2e.yml` and `e2e-experimental.yml`, runs `make coverage-report`
and uploads its own report with the `e2etests` flag; Codecov merges the uploads
of a commit.
The benchmark, image conversion and huge tar jobs, ordinary
`make` builds and release artifacts stay uninstrumented.
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

Single-job workflows export `coverage/` and upload it to Codecov after their
tests pass; `e2e.yml` and `e2e-experimental.yml` upload from their final
`Coverage` job, which runs even when tests fail:

| File | Contents |
| --- | --- |
| `raw/rust/*.profraw`, `rust-e2e.profdata` | Raw pooled subprocess counters and their merge |
| `raw/go/covmeta.*`, `raw/go/covcounters.*` | Go product subprocess metadata and counters |
| `rust-e2e.lcov`, `go-e2e.out` | Product-subprocess Rust LCOV (also Go builder-backed integrations) and Go E2E coverage, not Go harness coverage |

Coverage reporting follows dragonfly: every test job uploads its own report to
Codecov with a flag (`unittests` from `ci.yml`, `e2etests` from the E2E
workflows, `fuzz` from `fuzz.yml`), and Codecov merges the flags per commit,
posts the PR comment and sets the status checks. There is no coverage workflow
or merge script in this repository. `codecov.yml` gates **Rust (`nydus/`,
`nydus-*/`) and Go (`nydusify/`) separately at 90%** and ignores the test
harness and examples. Rust includes test code and does not represent
production-only or branch coverage. Uploads are capped at one minute and never
fail a test job; a missing upload shows up as a missing flag on Codecov, not
as zero coverage.

Missing expected profiles and export failures do fail the test job. A shard
that never runs nydusify uploads no Go report rather than synthetic zero
coverage.

`LLVM_PROFILE_FILE` uses `%8m`, bounding files to eight per instrumented
module rather than one per short-lived fuzz process. Normal exits merge
counters into this pool. **SIGKILL, abort and forced timeouts cannot flush
counters**: recovery/crash-path coverage is therefore explicitly partial,
not evidence that those paths were untested. Raw profiles and final reports
are retained for diagnosis. No test, fuzz/soak duration, Kind/Helm deployment,
check name or eight-minute PR timeout is changed. Instrumentation, larger
binary/tool artifacts and export add overhead; full CI budget compliance
requires a rerun and cannot be inferred from a local CLI smoke test.

Runners are GitHub-hosted Ubuntu (arm64 for arm64 release validation).
GitHub Actions sets `CI=true`, and that one variable makes every suite
strict: missing kernel capabilities/tools fail, they do not skip. Rust tests
also require netns/setns and ptrace, and run privileged test executables
without compiling as root; netns tests are `#[ignore]` and run with
`--include-ignored`. The Go suites carry no known-issue markers: a
reproduced bug is a red check until it is fixed.

Runner provisioning and the historical release binary remain external
prerequisites, not successful tests when absent; see the soak and
compatibility sections below.

Shared code lives in `util/`, as dragonfly's `test/e2e/util`, split by concern like
kubernetes' `test/e2e/framework/*`:

| Package       | Role                                                                      |
| ------------- | ------------------------------------------------------------------------- |
| `env`         | Binaries under test, preconditions (`Require*`), `NYDUS_E2E_*` knobs.     |
| `corpus`      | Source tree generators.                                                   |
| `fixture`     | Named corpora and GA layouts, built once and cached across test binaries. |
| `mount`       | Daemons, the FUSE/fileio adapters, configs, the apiserver client.         |
| `fstest`      | The judges: tree diff, manifest trees, extents, tar views, dirents.       |
| `erofs`       | EROFS device table and fsck.erofs.                                        |
| `registry`    | In-process OCI registry behind a fault-injecting proxy.                   |
| `proc`        | fd/thread/RSS/mount sampling for leak checks.                             |

`util/` holds helpers only, never test bodies. `conformance/` is an ordinary
test package, as `net/conn_test.go` runs the same checks over every network:
one `TestXxx` per adapter runs the same cases, so the experimental transports
keep only their adapters and transport-specific tests;
`experimental/transport` holds the checks the nbd and fanotify suites share.

Test kinds follow Go's conventions rather than directories: fuzz targets
(`FuzzXxx`) sit beside the tests of what they fuzz (`build/fuzz_test.go`,
`tar/fuzz_test.go`), benchmarks (`BenchmarkXxx`) run only under `-bench`, and
opt-in heavy tests carry `//go:build manual` in the package they test:
`tar/huge_test.go` (`make e2e-hugetar`) and `nydusify/public_images_test.go`
(`make e2e-convert`).

## Conventions

- A top-level test starts with `t.Parallel()`, except the dragonfly suite,
  whose tests share one Kind cluster.
- Nothing calls `t.Skip*`. A missing precondition goes through `env.Skipf`
  (or `MustHaveRoot`, `MustHaveKernel`, `LookPath`, ...): locally it skips,
  under CI it fails.
- Assertions use testify's `assert`, never `require`, in the specific form
  `testifylint` checks.
- A file is named after what it holds (`cache/peer_test.go`,
  `fault/readers_test.go`), never `util`, `helpers` or `common`.
  `main_test.go` holds only `TestMain`. `util/` holds helpers, not tests.
- Assertions take no message arguments.
- Test files are grouped by topic, several `Test` functions each, as in the
  standard library and containerd (`registry/auth_test.go` holds the Basic,
  Bearer and token-service tests). A helper used by one test lives in that
  test's file; shared helpers live in a file named after what they hold.
- Where later code depends on a check, guard it with
  `if !assert.X(t, ...) { t.FailNow() }`. `t.Fatal` is for `select` timeout
  arms, not-found fallthroughs and setup errors that have no assert form.
- `_test.go` files carry no comments beyond `//go:build`, `//nolint` and
  license attribution.
- Knobs are `NYDUS_E2E_*` variables read through `env.Int`, `env.Bool` and
  `env.Duration`; an invalid value fails.
- Build images through `fixture` (`fixture.Get`, `fixture.Build`,
  `fixture.Merged`), never in a test's own temp dir unless the test generates
  the dataset itself (`fixture.BuildImage`) or the build itself is under test
  (`fixture.BuildInto`). Cached images are shared and
  read-only; `fixture.Copy` one before damaging it.
- Mount through `mount.Mount` with an adapter; judge with `fstest`.
- Invariant for every fault test: a read either returns the right bytes or
  fails; it never returns wrong bytes.
  `TestBlobIntegrity/SkipChecksums` deliberately opts out of validation to
  verify the documented configuration behavior.

### Knobs

| Variable | Effect |
| --- | --- |
| `NYDUS_WRITER_BIN` | `writer-fixture` example for the nydusify artifact case (default the newest `target/*/examples/writer-fixture`). |
| `NYDUS_E2E_CACHE` | Directory of the cross-binary fixture image cache. |
| `NYDUS_E2E_GO_TAR_TESTDATA` | Go `archive/tar` testdata directory for the tar corpora. |
| `NYDUS_E2E_TAR_SEEDS` | Number of `TestRandomTars` seeds (default 200). |
| `NYDUS_E2E_COMPATIBILITY_DIR` | Compatibility image directory (default `compatibility/testdata`). |
| `NYDUS_E2E_COMPATIBILITY_VERSIONS` | Space-separated versions that must be present. |
| `NYDUS_E2E_FUSE_PREDECESSOR` | Older hot-upgrade-capable nydus for the continuity suite. |
| `NYDUS_E2E_DRAGONFLY_SCHEDULER` | Dragonfly scheduler address for the dragonfly suite. |
| `NYDUS_E2E_SOAK_DURATION` | Soak duration per workload (default 30s). |
| `NYDUS_E2E_SOAK_CYCLES` | Mount cycles per soak workload (default 6). |
| `NYDUS_E2E_SOAK_RSS_MIB` | Optional peak RSS growth budget in MiB. |
| `NYDUS_E2E_CONVERT_REGISTRY` | Target registry of the conversion sweep (default `localhost:5000`). |
| `NYDUS_E2E_CONVERT_PLAIN_HTTP` | Push to the target registry over plain HTTP (default for local registries). |
| `NYDUS_E2E_CONVERT_PLATFORM` | Platform to convert (default `linux/amd64`, `all` for every one). |
| `NYDUS_E2E_CONVERT_LIST` | Image list file (default `nydusify/testdata/images.txt`). |
| `NYDUS_E2E_CONVERT_CONCURRENCY` | Images converted at once (default 5). |
| `NYDUS_E2E_CONVERT_RETRIES` | Retries of a transient registry failure (default 5). |
| `NYDUS_E2E_CONVERT_RETRY_INTERVAL` | Base delay between retries (default 30s). |
| `NYDUS_E2E_BENCH_WARM` | Add the warm fio and metadata metrics. |
| `NYDUS_E2E_BENCH_FILEIO_NOWARM` | Add the `fileio-nowarm` mode. |
| `NYDUS_E2E_BENCH_EROFSFUSE` | `erofsfuse` binary for the `erofsfuse` mode. |
| `NYDUS_E2E_BENCH_V2_NYDUSD`, `NYDUS_E2E_BENCH_V2_IMAGE_BIN` | nydus v2 `nydusd` and `nydus-image` for the `v2-fuse` mode. |
| `NYDUS_E2E_BENCH_LARGE_FILE_COUNT`, `NYDUS_E2E_BENCH_LARGE_FILE_SIZE` | Large files in the benchmark corpus (default 8 of 64MiB). |
| `NYDUS_E2E_BENCH_MEDIUM_FILE_COUNT`, `NYDUS_E2E_BENCH_MEDIUM_FILE_SIZE` | Medium files in the benchmark corpus (default 256 of 1MiB). |
| `NYDUS_E2E_BENCH_SMALL_FILE_COUNT` | Small files in `small/` (default 10000). |
| `NYDUS_E2E_BENCH_READDIR_DIRS`, `NYDUS_E2E_BENCH_READDIR_FILES_PER_DIR` | Readdir tree shape (default 128 x 256). |
| `NYDUS_E2E_BENCH_READDIR_PASSES_PER_DIR` | Readdir passes per directory (default 8). |
| `NYDUS_E2E_BENCH_COLD_RAND_IO_SIZE` | Bytes of the cold random read (default 16MiB). |
| `NYDUS_E2E_BENCH_FIO_RUNTIME` | Seconds per warm fio job (default 8). |
| `NYDUS_E2E_BENCH_FIO_SEQ_NUMJOBS`, `NYDUS_E2E_BENCH_FIO_RAND_NUMJOBS` | Warm fio job counts (default 4). |
| `NYDUS_E2E_BENCH_META_SECS`, `NYDUS_E2E_BENCH_READDIR_META_SECS` | Seconds per warm metadata measurement (default 3). |

## Compatibility images

`TestRead` reads back the images one nydus release built, one
`<version>/` directory each, with the nydus under test. The directory
defaults to `compatibility/testdata/`, which is empty in the repository;
CI generates both versions into `.test-tmp/compatibility/` instead:

```
<version>/                    e.g. v3.0.0
  manifest.json               schema, version, builder (`nydus --version`),
                              expected trees, image list
  <layout>/                   the compatibility corpus, one per GA layout
    image.bootstrap
    blobs/<sha256>[.blob.meta]
  huge-<layout>/              the files past 4GiB (zstd, zstd-8m, tar-zstd)
  merged-<layout>/            the three compatibility layers merged
```

`manifest.json` records every tree an image must reproduce as
`fstest.Entry` lists, so the reader never rebuilds a corpus and later
changes to `util/corpus` do not invalidate generated versions. A
version takes about 10 MB; the corpora are `corpus.MakeCompatibility`,
`MakeCompatibilityHuge` and `MakeCompatibilityLayers`.

Images are regenerated the way golden files are: `TestRead` with `-update`
builds them with `NYDUS_BIN` into `NYDUS_E2E_COMPATIBILITY_DIR` (default
`testdata`), named after `nydus --version`:

```sh
NYDUS_BIN=/path/to/release/nydus make e2e-run PKG=./compatibility/... E2E_RUN='^TestRead$$' E2E_GO_TEST_ARGS=-update
```

`make e2e-compatibility` is the CI form: it downloads the checksum-verified
`v3.0.0-beta.3` release, writes a historical corpus with that binary and a
current one with the binary under test into `.test-tmp/compatibility/`, and
reads both. Under CI every read requires versions, and the historical
version is required with `NYDUS_E2E_COMPATIBILITY_VERSIONS`; an empty
corpus, failed download or missing version fails. The beta.3 binary reads
the current corpus through check/FUSE/export only, as it has no Fileio.

## Soak

`TestLeak` and `TestRemote` run in the `soak` row of the `e2e.yml` matrix. Defaults remain 30s,
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

Nightly E2E Test runs the full `make e2e-soak` on schedule:
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
A capability-matched host can run a 10s/one-cycle smoke with the same
workload.

### Runner contract

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

## Benchmarks

`bench` is a standard Go benchmark: `BenchmarkMount/<mode>` mounts
the corpus three times per iteration (the cold reads, the cold xattr walk
and the big-directory lookups each start on a fresh mount) and reports
every measurement with `b.ReportMetric` (`mount-sec`, `cold-walk-sec`,
`cold-seq-read-MiB/s`, `big-dir-lookups/s`, ...), so the output is the Go
benchmark format and
[benchstat](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat) compares
runs. No machine-independent threshold is imposed. Use a dedicated idle
host, select modes with `BENCH` and repeat with `E2E_COUNT` so benchstat can
tell noise from change:

```sh
make benchmark BENCH='Mount/^(fuse|fileio)$$' E2E_COUNT=10 | tee new.txt
benchstat old.txt new.txt
```

To see where a mode spends its time, attach perf to its daemon while the
benchmark runs and render the samples, e.g. with
[inferno](https://github.com/jonhoo/inferno):

```sh
perf record -g -p "$(pgrep -n nydus)" -o perf.data -- sleep 15
perf script -i perf.data | inferno-collapse-perf | inferno-flamegraph > flame.svg
```

A selected mode the host or binary cannot serve fails through the normal
precondition policy. `NYDUS_E2E_BENCH_WARM=1` adds the warm fio and
metadata metrics; the other `NYDUS_E2E_BENCH_*` knobs size the corpus. The
Benchmark workflow runs `fuse` and `fileio` six times (the fewest benchstat needs for a
confidence interval) on a GitHub-hosted
runner and uploads `bench.txt`.

`big-dir-lookups/s` is a single positive-lookup pass over the `small/`
directory (10,000 entries by default) on a **fresh mount**, without readdir
or a preceding metadata walk. It complements `negative-lookups/s` and
detects large-directory lookup regressions instead of measuring repeated
warm dcache hits. `NYDUS_E2E_BENCH_SMALL_FILE_COUNT` changes its size.

`make benchmark` builds GA features only. Experimental modes require an
explicitly built binary and a capability-matched host; ublk is not an
incidental dependency of a GA performance run.

## Backend and storage contracts

Dragonfly retains upstream's **Kind v0.32.0 + Helm chart 1.8.2** deployment,
using the unchanged files in `tests/testdata/{kind,charts,k8s}`. The chart
runs one scheduler and one seed client; manager and ordinary clients are
disabled. The origin is Docker `registry:2`. There is no separate local
manager, MySQL, Redis, or private cluster-control script.

To run it locally, follow the setup steps in
`.github/workflows/e2e-dragonfly.yml`, export
`KUBECONFIG` and `NYDUS_E2E_DRAGONFLY_SCHEDULER=http://127.0.0.1:8002`, then run
`CI=1 make e2e-dragonfly`. The Kind network must use
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
entry point runs once without a test-name filter.
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
  independently of their ordering. Backend reads identify the configured
  backend: `source="dragonfly"` on a Dragonfly daemon, also for a read
  that fell back to the origin, and `source="http"` otherwise. Retry and
  fallback decisions are checked through requests and logs, such as
  `falling back to the origin`, not through per-attempt counters.
- Labeled counters may be absent before the first event. Positive control
  reads and cache gauges keep a renamed metric from turning an assertion
  into a vacuous zero-equals-zero check.
- The in-process registry supports suffix ranges for footer discovery,
  while retaining the original request in its fault log.
- Checksum verification is enabled by default and checks CRC32C, not the
  stored group digests. Cache options are per image.
