# Nydus V3 Proposal

## Overall Improvements

- Consolidate and simplify command-line arguments, APIs, and configuration formats.
- Remove features that are no longer needed or have been effectively unmaintained.
- Drop RAFS v5 support on the build side and standardize image creation on the EROFS-based format, while preserving RAFS v5 compatibility at runtime.

## Build Side

### Functional Changes

- Embed CRC32 into chunk metadata by default.
- Support build-time deduplication based on chunk dictionaries.
- Make `nydusify` depend only on the containerd converter, removing the acceleration service dependency.
- [Performance] Simplify the build pipeline to improve build speed and reduce memory consumption.

## Runtime Side

### Functional Changes

- Simplify the API surface and adopt a more mature HTTP server framework to improve concurrency.
- Switch to YAML as the configuration format and simplify the configuration model.
- Stop persisting runtime configuration to disk to avoid leaking sensitive information, while supporting hot configuration updates.
- Support mounting individual image layers independently.
- Use CRC32 as the default data integrity check.
- Expose HTTP `/metrics` in standard Prometheus format.
- Provide native live upgrade and failover support for FUSE deployments.
- Remain compatible with direct kernel EROFS mounts.
- Support a higher-performance `pmem + uffd + nydusd` solution for Kata scenarios.
- [Performance] Replace chunk-level prefetching with blob-stream prefetching.
- [Performance] Support runtime ondemand-pattern collection to optimize chunk layout in images.
- [Performance] Make the full I/O stack asynchronous across `fuse-backend-rs` and `nydusd` storage.
- [Performance] Optimize storage-layer requests and improve deep integration with the Dragonfly SDK.

### Quality

- Achieve at least 80% test coverage for core functionality.
- Introduce a stricter filesystem test suite.
- Reduce CI runtime for integration tests.

## Nydus Build Tool (nydus-image)

### nydus-image create

``` shell
nydus-image create -h
Create nydus filesystems from layer directories or tar files

Usage: nydus-image create [OPTIONS] <SOURCE> <TARGET>

Arguments:
  <SOURCE>  source from which to build the nydus filesystem
  <TARGET>  path to generated nydus bootstrap blob

Options:
  --log-level <log-level>
    Log level: [default: info] [possible values: trace, debug, info, warn, error]
  --type <type>
    Conversion type: [default: dir-nydus] [possible values: dir-nydus, tar-nydus]
  --blob <blob>
    File path to save the generated nydus data blob
  --chunk-size <chunk-size>
    Set the size of data chunks, must be power of two and between 0x1000-0x1000000:
  --compressor <compressor>
    Algorithm to compress data chunks: [default: zstd] [possible values: none, lz4_block, zstd]
  --digester <digester>
    Algorithm to digest data chunks: [default: blake3] [possible values: blake3, sha256]
  --output-json <output-json>
    File path to save operation result in JSON format
```

### nydus-image merge

``` shell
nydus-image merge -h
Merge multiple nydus bootstraps into a overlaid bootstrap

Usage: nydus-image merge [OPTIONS] <SOURCE>... <TARGET>

Arguments:
  <SOURCE>...  bootstrap paths (allow one or more)
  <TARGET>...  overlaid bootstrap path

Options:
  --log-level <log-level>
    Log level: [default: info] [possible values: trace, debug, info, warn, error]
```

### nydus-image check

``` shell
nydus-image check -h
Check nydus layout from bootstrap file.

Usage: nydus-image check [OPTIONS] <SOURCE>

Arguments:
  <SOURCE>...  bootstrap path

Options:
  --log-level <log-level>
    Log level: [default: info] [possible values: trace, debug, info, warn, error]
```

### nydus-image mount

``` shell
nydus-image mount -h
Mount nydus layout from bootstrap file.

Usage: nydus-image mount [OPTIONS] <SOURCE> <TARGET>

Arguments:
  <SOURCE>...  bootstrap path
  <TARGET>...  mountpoint directory path

Options:
  --log-level <log-level>
    Log level: [default: info] [possible values: trace, debug, info, warn, error]
```

## Nydus Runtime Tool (nydusd)

``` shell
nydusd -h
Nydus daemon to provide nydus image mount

Usage: nydusd <COMMAND> [OPTIONS]

Commands:
  fuse [default]  Run as a FUSE daemon to mount nydus image
  prefetch        Load a nydus bootstrap and prefetch all blobs to cache
  help            Print this message or the help of the given subcommand(s)

Options:
  --log-level <log-level>
    Log level: [default: info] [possible values: trace, debug, info, warn, error]

  # For fuse, prefetch subcommand
  --apisock <apisock>
    Path to the nydus daemon administration API socket
  --config <config>
    Path to the nydus daemon configuration file (.yaml format)
  --bootstrap <bootstrap>
    Path to the nydus filesystem metadata file

  # For fuse subcommand
  --mountpoint <mountpoint>
    Mountpoint for the FUSE filesystem, target for `mount.fuse`
  --failover-policy <failover-policy>
    FUSE server failover policy [default: resend] [possible values: none, resend, flush]
  --fuse-threads <fuse-threads>
    Number of worker threads to serve FUSE I/O requests [default: 4]
  --supervisor <supervisor>
    Path to the nydus daemon supervisor API socket
  --upgrade
    Start nydus daemon in upgrade mode
```

### Configuration

``` yaml
# Nydusd configuration

backend:
  # Type: registry | localfs | oss
  type: registry
  config:
    # Drop the read request once http request timeout, in seconds
    timeout: 5
    # Drop the read request once http connection timeout, in seconds
    connect_timeout: 5
    # Retry count when read request failed
    retry_limit: 0
  proxy:
    url:

cache:
  # Type: blobcache | dummy
  type: blobcache
  config:
    # Directory of cache files, only for local
    work_dir: /cache

prefetch:
  # Enable blob prefetch
  enable: false
  # Prefetch thread count
  threads_count: 10
  # Limit prefetch bandwidth to 1MiB/s
  bandwidth_rate: 1048576
```

### API

``` shell
GET /daemon
  Returns general information about the nydus daemon

GET /metrics
  Returns daemon metrics: files, pattern, backend, cache, prefetch

POST /mount
  Mount an image instance or an individual layer

DELETE /mount
  Unmount a mounted image instance or layer

POST /exit
  Let nydus daemon exit

PUT /fuse/sendfd
PUT /fuse/takeover
  For FUSE daemon live upgrade / failover
```

## Nydusify

```shell
nydusify -h
NAME:
  Nydusify - Nydus utility tool to convert, check and mount nydus image

USAGE:
  Nydusify [global options] command [command options]

COMMANDS:
  convert      Generate a Nydus image from an OCI image
  check        Verify nydus image format and content
  mount        Mount the nydus image as a filesystem
  copy         Copy an image from source to target

GLOBAL OPTIONS:
   --log-level value, -l value  Set log level (trace, debug, info, warn, error) (default: "info") [$LOG_LEVEL]
```

## Kata Support

### Current Approaches

Nydus images can be used with Kata through several methods:

| Approach | Description | Limitations |
|----------|-------------|------------|
| FUSE + Virtiofs | Mount meta and blob files as FUSE, expose through Virtiofs to guest | Frequent kernel/user context switches, high file operation overhead |
| Virtiofs + Blobs | Expose blob directory via Virtiofs, guest mounts meta + blobs as EROFS | EROFS DAX integration causes compatibility issues |
| Virtio-blk + Blobs | Build meta + blobs into virtio-blk device, guest mounts as EROFS | No DAX support, causes guest/host double page cache waste |
| Virtio-pmem + Local Blobs | Map local meta + blob files to mmap region as virtio-pmem device | Requires pre-downloaded blobs, no on-demand fetching |

### Proposed Solution: pmem + uffd + nydusd

This proposal implements a hybrid approach combining pmem, userfaultfd, and nydusd to achieve:

- Improved runtime performance
- Full feature compatibility
- Shared page cache between host and guest
- Complete DAX support
- On-demand blob fetching for faster startup

```
+---------------------------------------+
| +-----------VMM event loop----------+ |
| |recv [blobfd, off, len, fdoff]     | |
| |  * mmap fd range into pmem backend| |
| |  * UFFDIO_WAKE vcpu on the range  | |
| +-----------------A-----------------+ |
|                   |sock(json+fd in FC)|
|                   V                   |
| +------Runtime (uffd and proxy?)----+ |      +-------------Nydusd-----------+
| |handle userfaultfd event on fault  | |      |recv block request            |
| |  * send block request to nydusd   |<-sock->|pull chunk from remote/local  |
| |recv [blobfd, off, len, fdoff]     | |(nbd) |send [blobfd, off, len, fdoff]|
| |  * transfer to VMM                | |      +------------------------------+  
| |  * trap UFFD_EVENT_UNMAP          | |
| +-----------------------------------+ |
+---------------------------------------+
```
