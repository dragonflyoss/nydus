# lepton

Lepton is a minimal Rust implementation of EROFS tooling. It ships as a single
`lepton` binary with four user-facing subcommands:

- `lepton build`
- `lepton check`
- `lepton merge`
- `lepton fuse`

The current artifact model centers around a full blob file that contains EROFS
metadata plus appended chunk data. Build can also emit a standalone bootstrap
for metadata-only distribution, and always emits a companion `.blob.meta`
sidecar for each full blob.

For lower-level design and on-disk format notes, see [docs/lepton.md](docs/lepton.md)
and [docs/erofs.md](docs/erofs.md).

## Build

```bash
cargo build --release
```

The repository produces one binary:

```bash
./target/release/lepton
```

## Commands

### lepton build

Build a source directory into a lepton layer.

```bash
./target/release/lepton build --blob /tmp/layer.blob --bootstrap /tmp/layer.bootstrap ./rootfs
```

```bash
./target/release/lepton build --blob-dir /tmp/blobs ./rootfs
```

Key points:

- Exactly one of `--blob` or `--blob-dir` is required.
- `--bootstrap` is optional and writes a standalone metadata-only bootstrap.
- `--chunk-size` defaults to `1048576` (1 MiB).
- A `.blob.meta` sidecar is always emitted for the full blob.
- `--compressor zstd` is accepted by the CLI, but chunk data is still written
	uncompressed in the current implementation.

Output shapes:

- `--blob /tmp/layer.blob` writes `/tmp/layer.blob` and `/tmp/layer.blob.blob.meta`.
- `--blob-dir /tmp/blobs` writes `/tmp/blobs/<full_blob_sha256>` and
	`/tmp/blobs/<full_blob_sha256>.blob.meta`.

### lepton check

Statically inspect a full blob or a standalone bootstrap.

```bash
./target/release/lepton check --blob /tmp/layer.blob
```

```bash
./target/release/lepton check --bootstrap /tmp/layer.bootstrap --blob-dir /tmp/blobs
```

Use `check` to inspect superblock, inode, blob, and chunk layout information
without mounting the filesystem.

### lepton merge

Merge multiple previously built layer blobs into one overlaid bootstrap.

```bash
./target/release/lepton merge \
	--bootstrap /tmp/merged.bootstrap \
	/tmp/blobs/<layer1_sha256> \
	/tmp/blobs/<layer2_sha256>
```

Key points:

- Source paths must be full blob files.
- Current merge behavior focuses on metadata overlay and OCI whiteout handling.
- The output is a merged bootstrap, not a rewritten merged full blob.

### lepton fuse

Mount a lepton image through FUSE.

Supported forms:

```bash
sudo ./target/release/lepton fuse --blob /tmp/layer.blob --mountpoint /mnt/lepton
```

```bash
sudo ./target/release/lepton fuse \
	--bootstrap /tmp/layer.bootstrap \
	--blob-dir /tmp/blobs \
	--mountpoint /mnt/lepton
```

Optional runtime knobs include:

- `--cache-dir` to enable persistent local chunk cache files.
- `--threads` to set the FUSE worker thread count.
- `--log-dir`, `--log-level`, and `--log-max-files` for runtime logging.

Lepton installs signal handlers for `SIGINT`, `SIGTERM`, `SIGQUIT`, and
`SIGHUP`, and performs a best-effort unmount before exiting.

## Artifact Model

Lepton currently works with three artifact types:

1. Full blob: the primary layer artifact.
2. Standalone bootstrap: optional metadata-only artifact.
3. Blobmeta sidecar: companion `.blob.meta` file for the full blob.

The full blob layout is:

```text
+------------------------------+
| bootstrap metadata           |
+------------------------------+
| appended chunk data region   |
+------------------------------+
```

When a standalone bootstrap is emitted, it stores the blob identifier needed to
resolve the corresponding data blob later under `--blob-dir`.

## Repository Layout

```text
src/
├── bin/
│   └── lepton/
│       ├── main.rs            # CLI entrypoint
│       ├── build.rs           # `lepton build`
│       ├── check.rs           # `lepton check`
│       ├── merge.rs           # `lepton merge`
│       └── fuse.rs            # `lepton fuse`
├── build/                     # Build-time layer construction
├── fs/                        # Runtime EROFS reader and FUSE filesystem
├── merge.rs                   # Merge engine
├── metadata/                  # On-disk EROFS and blobmeta structures
├── storage/
│   ├── backend/
│   │   ├── mod.rs
│   │   └── local.rs          # Local blob backend
│   ├── cache.rs              # Persistent blob cache device
│   └── chunkmap.rs           # Local chunk readiness bitmap
├── tracing/                   # Runtime and command logging setup
├── utils/                     # Hashing and helper utilities
└── lib.rs                     # Library crate root
```

## Current Scope

Supported today:

- Build chunk-based layers from a source directory.
- Emit a full blob plus optional standalone bootstrap.
- Emit and consume `.blob.meta` sidecars.
- Inspect blobs and bootstraps with `lepton check`.
- Merge multiple layers into one overlaid bootstrap with OCI whiteouts.
- Mount either a direct blob or a bootstrap plus blob-dir with `lepton fuse`.
- Preserve hardlinks, xattrs, symlinks, device nodes, FIFOs, and sockets.
- Use a local persistent chunk cache via `--cache-dir`.

Not yet supported or still evolving:

- tar, OCI registry, or S3 input sources.
- Actual chunk compression output despite the `--compressor` CLI.
- SELinux label handling.
- Incremental builds.
- Broader EROFS compatibility beyond the current in-tree target workflow.

## Testing

Unit tests:

```bash
make test
```

End-to-end integration tests (requires root):

```bash
make test-e2e
make test-e2e E2E_TEST=TestMergedMountE2E
```

xfstests regression (requires root):

```bash
make test-xfstests
```

Performance benchmark (requires root and `fio`):

```bash
make test-perf
EROFS_C_FUSE=/path/to/erofsfuse make test-perf
```

The Go integration tests live under `tests/integration/`. xfstests setup uses
`tests/scripts/setup_xfstests.sh`, and the exclusion list lives at
`tests/scripts/xfstests_leptonfs.exclude`.

Useful knobs:

- `E2E_TEST=<regex>` selects a single e2e test.
- `E2E_GO_TEST_ARGS='...'` appends extra `go test` arguments for e2e runs.
- `XFSTESTS_GO_TEST_ARGS='...'` appends extra `go test` arguments for xfstests.
- `PERF_GO_TEST_ARGS='...'` appends extra `go test` arguments for perf runs.
- `SUDO=` disables `sudo` when you only want compile-level verification.
- `GO_BIN=/abs/path/to/go` forces a specific Go binary.
