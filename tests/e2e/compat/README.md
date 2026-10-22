# Reduced-feature binary contracts

This is a separate CI matrix, not another GA mount suite. Each job builds a
real `nydus` with `--no-default-features` and an exact feature set:

| `NYDUS_E2E_FEATURE_VARIANT` | Cargo features | Config rejected |
| --- | --- | --- |
| `minimal` | `cli` | registry backend |
| `registry` | `cli,registry` | Dragonfly config |
| `fileio` | `cli,registry,fileio` | Dragonfly config |

The matrix asserts supported CLI help and unsupported subcommand failures.
It also executes `fuse --config` and requires a feature-specific diagnostic
before opening an image, contacting a backend, or mounting. Thus an early
unrelated parser/network error cannot satisfy the config contract. `cli`
implies FUSE today, so a no-FUSE CLI build is not a supported combination.

Use an isolated cargo target directory if other tests use the default
binary concurrently:

```sh
CARGO_TARGET_DIR=target/compat cargo build -p nydus --profile ci \
  --no-default-features --features cli,registry
NYDUS_E2E_FEATURE_VARIANT=registry make e2e-run PKG=./compat \
  NYDUS_BIN="$PWD/target/compat/ci/nydus" E2E_REQUIRE=1
```

The pure policy tests supporting the execution lanes are classified as
harness unit tests under `internal/benchgate`, `internal/soakconfig`, and
`internal/goldenpolicy`, not as product E2E cases.
