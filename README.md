# lepton

A minimal Rust implementation of EROFS filesystem tools, providing image creation and FUSE mounting through a single `lepton` binary with subcommands.

## Build

```bash
cargo build --release
```

A single binary is produced:

```bash
./target/release/lepton   # EROFS tools (`build` + `mount` subcommands)
```

## Usage

### lepton build

Create an EROFS filesystem image from a source directory:

```bash
./target/release/lepton build IMAGE --blobdev BLOB --chunksize BYTES SOURCE
```

Arguments:

- `IMAGE`: output EROFS metadata image
- `--blobdev BLOB`: output blob data file (chunk-based data)
- `--chunksize BYTES`: chunk size in bytes, must be a power of two and >= 4096
- `SOURCE`: source directory

### lepton mount

Mount an EROFS image (the default driver is `fuse`):

```bash
sudo ./target/release/lepton mount IMAGE MOUNTPOINT [--driver fuse] [--blobdev BLOB] [--threads N]
```

Arguments:

- `IMAGE`: EROFS metadata image file
- `MOUNTPOINT`: mount point directory
- `--driver`: mount driver (default: `fuse`)
- `--blobdev BLOB`: blob data file for chunk-based files
- `--threads N`: number of FUSE worker threads (default: 4)

### Example

```bash
# Build image
./target/release/lepton build /tmp/erofs.meta.img \
	--blobdev /tmp/erofs.blob.img \
	--chunksize 1048576 \
	~/code/linux

# Mount image (driver defaults to fuse)
sudo ./target/release/lepton mount /tmp/erofs.meta.img ~/mnt \
	--blobdev /tmp/erofs.blob.img \
	--threads 10
```

## Architecture

```
src/
├── bin/
│   └── lepton.rs               # Single CLI binary with `build` and `mount` subcommands
├── lib.rs                       # Library crate root
├── metadata/                    # EROFS on-disk format definitions (shared)
│   ├── mod.rs                  # Constants, LE helpers, cast_ref/cast_mut
│   ├── superblock.rs           # ErofsSuperblock (128B)
│   ├── inode.rs                # ErofsInodeCompact/Extended, ErofsInode enum
│   ├── dir.rs                  # ErofsDirent (12B)
│   ├── chunk.rs                # ErofsChunkIndex (8B), ErofsDeviceSlot (128B)
│   └── layout.rs               # MetadataLayout allocator
├── build/                       # Build-time code (image creation)
│   ├── mod.rs
│   ├── image.rs                # write_image — assemble final EROFS image
│   ├── inode.rs                # InodeInfo, build_tree, serialize_inode
│   ├── dir.rs                  # DirChild, serialize_directory
│   └── blobchunk.rs            # BlobWriter — chunk dedup + blob writing
└── fs/                          # Runtime code (image reading + FUSE)
    ├── mod.rs                  # ErofsReader — mmap + open + common helpers
    ├── meta.rs                 # Metadata ops: inode, read_dir, read_symlink
    ├── data.rs                 # Data ops: read_file_data, chunk read, blob pread
    └── fuse.rs                 # ErofsFs — FileSystem + AsyncFileSystem impl
```

### Design

- **Zero-copy metadata**: All on-disk structs are `#[repr(C, packed)]` and cast directly from mmap (no parsing/copying)
- **Lock-free runtime**: `Mmap` (Send+Sync) for metadata, `pread` (POSIX thread-safe) for blob data
- **Async I/O**: Blob reads offloaded via `tokio::task::spawn_blocking`
- **Chunk dedup**: BLAKE3-based content-addressed deduplication during image creation

## Current Scope

Supported features:

- Chunk-based image creation with `--blobdev` and `--chunksize`
- Directory tree as input source
- Regular files, directories, symlinks, device nodes, FIFOs, sockets
- Hardlink detection and dedup
- Extended attributes (xattr) preservation
- FUSE mount with async I/O and multi-threaded workers

Not yet supported:

- tar/OCI/S3 inputs
- Compression (LZ4, ZSTD, etc.)
- SELinux labels
- Incremental builds

## Testing

Unit tests:

```bash
make test
```

Integration tests (requires root):

```bash
# Runs verification (~1s) + xfstests regression (~90s).
# First run installs xfstests dependencies automatically.
make test-integration
```

The integration tests live under `tests/integration/` (Go) and reuse
`tests/scripts/setup_xfstests.sh` for environment setup and
`tests/scripts/xfstests_erofs.exclude` for the xfstests exclusion list.

Performance benchmark (requires root, fio):

```bash
# Benchmark Rust `lepton mount` (~2min, needs fio: apt-get install fio)
make test-perf

# Compare against C erofsfuse
EROFS_C_FUSE=/path/to/erofsfuse make test-perf
```

```
Benchmark                     Unit          Rust             C     Ratio
------------------------------------------------------------------------
Sequential Read (128K)        MB/s        3005.6        2691.3     1.12x
Random Read (4K)              IOPS       19168.1       22605.5     0.85x
Random Read (4K) Lat            µs          51.1          43.3     0.85x
Seq Read 4-thread             MB/s        6575.8        5694.9     1.15x
Stat                          IOPS     1067967.0      841824.6     1.27x
Stat Latency                    µs           0.9           1.2     1.27x
Readdir                       IOPS       10398.9        3907.8     2.66x
Readdir Latency                 µs          96.2         255.9     2.66x
```
