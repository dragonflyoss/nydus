# nydus

Nydus is a Rust implementation of EROFS-oriented image tooling. This README is
kept as a development entrypoint for building and testing the repository.

For CLI behavior, artifact layout, blob meta format and runtime read-path
details, see [docs/nydus.md](docs/nydus.md). For EROFS structure notes, see
[docs/erofs.md](docs/erofs.md).

## Prerequisites

- Rust toolchain with `cargo`.
- Go for integration tests under `tests/integration/`.
- `sudo` and FUSE support for e2e, xfstests and perf runs.
- `fio` for `make test-perf`.
- Optional erofs-utils binaries for compatibility checks:
	`EROFS_C_FUSE=/path/to/erofsfuse` and `EROFS_MKFS=/path/to/mkfs.erofs`.

## Build

Debug build:

```bash
make build
```

Release build:

```bash
make release
```

Equivalent direct Cargo commands:

```bash
cargo build
cargo build --release
```

The release binary is written to:

```bash
./target/release/nydus
```

## Rust Validation

Run the full Rust test suite:

```bash
make test
```

Useful focused checks while developing:

```bash
cargo check --workspace
cargo test blob_meta --workspace
cargo test cache --workspace
cargo test local_backend --workspace
```

Format and diff hygiene:

```bash
cargo fmt
git diff --check
```

## Integration Tests

End-to-end tests require root because they mount FUSE filesystems:

```bash
make test-e2e
```

Run one e2e test by name:

```bash
make test-e2e E2E_TEST=TestMergedMountE2E
```

Run e2e with erofs-utils compatibility enabled:

```bash
EROFS_C_FUSE=/path/to/erofsfuse \
EROFS_MKFS=/path/to/mkfs.erofs \
NYDUSFS_RUN_EROFS_COMPAT=1 \
make test-e2e
```

xfstests regression, also requiring root:

```bash
make test-xfstests
```

Performance benchmark, requiring root and `fio`:

```bash
make test-perf
```

With C erofsfuse comparison:

```bash
EROFS_C_FUSE=/path/to/erofsfuse make test-perf
```

The Go integration tests live under `tests/integration/`. xfstests setup uses
`tests/scripts/setup_xfstests.sh`, and the exclusion list lives at
`tests/scripts/xfstests_nydusfs.exclude`.

## Test Knobs

- `E2E_TEST=<regex>` selects a single e2e test.
- `E2E_TIMEOUT=<duration>` changes the e2e timeout, defaulting to `600s`.
- `E2E_COUNT=<n>` changes the e2e repeat count.
- `E2E_GO_TEST_ARGS='...'` appends extra `go test` arguments for e2e runs.
- `NYDUSFS_RUN_EROFS_COMPAT=1` enables erofs-utils compatibility checks.
- `EROFS_C_FUSE=/abs/path/to/erofsfuse` selects the C erofsfuse binary.
- `EROFS_MKFS=/abs/path/to/mkfs.erofs` selects the mkfs.erofs binary.
- `XFSTESTS_GO_TEST_ARGS='...'` appends extra `go test` arguments for xfstests.
- `PERF_GO_TEST_ARGS='...'` appends extra `go test` arguments for perf runs.
- `SUDO=` disables `sudo` when you only want compile-level verification.
- `GO_BIN=/abs/path/to/go` forces a specific Go binary.

## Clean

```bash
make clean
```
