# Nydus UFFD Block Device

Export a RAFS v6 image as a block device through [userfaultfd](https://www.kernel.org/doc/html/latest/admin-guide/mm/userfaultfd.html), enabling on-demand paging via `mmap`.

## Overview

The UFFD block device service (`nydusd uffd`) provides an `mmap`-based access mode for RAFS images, designed for clients that map the image as a contiguous virtual address space and handle page faults on demand.

When a client accesses an unmapped page, the kernel delivers a page fault via userfaultfd to `nydusd`, which resolves it through one of two modes:

- **Zerocopy mode**: Returns a blob file descriptor; the client `mmap`s it directly to the faulting address (zero-copy).
- **Copy mode**: Writes data to the faulting address via `UFFDIO_COPY`.

**Benefits**:
- In VM scenarios, zerocopy mode combined with guest-side DAX avoids memory duplication, reducing host memory pressure.
- The UFFD protocol is stateless; clients can reconnect after a server restart without losing state.

```
Client                          nydusd (UFFD service)            RAFS Image
--------                        ---------------------            ----------
page fault → userfaultfd ──→ resolve fault
                                  │
                                  ├─ Zerocopy: mmap blob fd ──→ read blob
                                  │              ← send fd
                                  │
                                  └─ Copy: UFFDIO_COPY ──→ read blob
                                            ← write data
```

## Requirements

- Linux kernel with `CONFIG_USERFAULTFD=y` (5.10+ recommended)
- RAFS v6 filesystem image (built with `nydus-image create --fs-version 6`)
- `nydusd` compiled with `--features block-uffd`

## Quick Start

```bash
# Build nydusd with UFFD support
cargo build --bin nydusd --features block-uffd

# Start UFFD service (localfs backend)
nydusd uffd \
  --sock /tmp/uffd.sock \
  --bootstrap /path/to/image.boot \
  --localfs-dir /path/to/blobs \
  --threads 4

# Start UFFD service (config file backend)
nydusd uffd \
  --sock /tmp/uffd.sock \
  --bootstrap /path/to/image.boot \
  --config /path/to/config.json
```

## Command Line Options

| Option | Short | Required | Description |
|--------|-------|----------|-------------|
| `--sock` | `-S` | Yes | Path to the UFFD service Unix socket |
| `--bootstrap` | `-B` | Yes | Path to the RAFS v6 bootstrap file |
| `--config` | `-C` | No | Path to ConfigV2 JSON file (mutually exclusive with `--localfs-dir`) |
| `--localfs-dir` | `-D` | No | Path to localfs working directory (mutually exclusive with `--config`) |
| `--threads` | | No | Number of worker threads (default: 4) |

## Protocol

The UFFD service communicates with clients over a Unix domain socket using JSON messages, with file descriptors passed via `SCM_RIGHTS`. The protocol is compatible with [Firecracker's UFFD handler](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/handling-page-faults-on-snapshot-resume.md).

### Message Types

| Message | Direction | Description |
|---------|-----------|-------------|
| `HandshakeRequest` + uffd fd | Client → Server | Register VMA regions, set fault policy |
| `StatRequest` | Client → Server | Query device size and block size |
| `StatResponse` | Server → Client | Returns size, block_size, version |
| `PageFaultResponse` + fd(s) | Server → Client | Provide data for faulting pages |

### Handshake

The client connects to the Unix socket and sends a `HandshakeRequest` JSON message along with the userfaultfd file descriptor via `SCM_RIGHTS`:

```json
{
  "type": 0,
  "regions": [
    {
      "base_host_virt_addr": 140737488351232,
      "size": 8589934592,
      "offset": 0,
      "page_size": 2097152,
      "page_size_kib": 2048,
      "prot": 1,
      "flags": 34
    }
  ],
  "policy": 0,
  "enable_prefault": false
}
```

**Field Descriptions**:
- `type`: Message type, 0 = Handshake
- `regions`: Array of VMA regions, each describing a contiguous virtual address range
- `policy`: Fault handling policy, 0 = Zerocopy, 1 = Copy
- `enable_prefault`: If true, the server asynchronously sends blob fds for locally cached block ranges immediately after handshake, bypassing the page fault round-trip for those ranges. This reduces UFFD overhead for data already present in the cache (default: false).
- `prot`, `flags`: Protection and flags for `mmap`. These fields are reserved for future kernel support of cross-process `mmap`, allowing the server to perform the mapping directly on behalf of the client.

**Firecracker Compatibility**: The server also accepts a bare JSON array (without the wrapper object), which is the format Firecracker uses:

```json
[
  {
    "base_host_virt_addr": 140737488351232,
    "size": 8589934592,
    "offset": 0,
    "page_size": 2097152,
    "page_size_kib": 2048
  }
]
```

### Fault Policies

| Policy | Value | Description |
|--------|-------|-------------|
| `Zerocopy` | 0 | Server sends blob file descriptors; client maps them directly to the faulting address via `mmap(MAP_FIXED)` |
| `Copy` | 1 | Server writes data directly to client memory via `UFFDIO_COPY` or `UFFDIO_ZEROPAGE` |

**Note on Zerocopy Mode**: The current Linux kernel does not support mapping files from another process directly. Therefore, zerocopy mode requires client cooperation: the server sends blob fds via `SCM_RIGHTS`, and the client performs the `mmap` call. If future kernels add cross-process `mmap` support, the client implementation can be further simplified.

### Page Fault Response

When a page fault occurs, the server responds with a `PageFaultResponse` containing one or more blob ranges with associated file descriptors:

```json
{
  "type": 1,
  "ranges": [
    { "len": 2097152, "blob_offset": 4096, "block_offset": 0 }
  ]
}
```

In zerocopy mode, the client `mmap`s each range using the returned file descriptor. In copy mode, the server calls `UFFDIO_COPY` or `UFFDIO_ZEROPAGE` directly.

### Stat Request

The client can query device information at any time:

```json
{ "type": 2 }
```

Response:

```json
{
  "type": 3,
  "size": 8589934592,
  "block_size": 4096,
  "flags": 0,
  "version": 1
}
```

## Configuration

### Localfs Backend

The simplest configuration uses `--bootstrap` with `--localfs-dir`:

```bash
nydusd uffd \
  --sock /tmp/uffd.sock \
  --bootstrap /path/to/image.boot \
  --localfs-dir /path/to/blobs
```

### Config File Backend

For more complex backends (registry, OSS, etc.), use a ConfigV2 JSON file:

```bash
nydusd uffd \
  --sock /tmp/uffd.sock \
  --bootstrap /path/to/image.boot \
  --config /path/to/config.json
```

The config file format is the same as the [FUSE mode configuration](nydusd.md), with `backend` and `cache` sections.

## Architecture

```
┌────────────────────────────────────────────────────┐
│                 nydusd uffd service                │
│                                                    │
│ ┌───────────────────────────────────────────────┐  │
│ │             Unix Socket Listener              │  │
│ └─────────────────────┬─────────────────────────┘  │
│                       │                            │
│        ┌──────────────┬──────────────┐             │
│        │              │              │             │
│  ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐       │
│  │ Worker 0  │  │ Worker 1  │  │ Worker N  │       │
│  │  (tokio)  │  │  (tokio)  │  │  (tokio)  │       │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘       │
│        │              │              │             │
│        └──────────────┼──────────────┘             │
│                       │                            │
│        ┌──────────────▼───────────────────┐        │
│        │           BlockDevice            │        │
│        │ ┌──────────┐    ┌──────────┐     │        │
│        │ │ MetaBlob │    │ DataBlob │ ... │        │
│        │ └──────────┘    └──────────┘     │        │
│        └──────────────────────────────────┘        │
└────────────────────────────────────────────────────┘
```

- **Unix Socket Listener**: Accepts client connections and dispatches to workers
- **Workers**: Each worker handles multiple client connections, asynchronously reading uffd events and resolving page faults
- **BlockDevice**: Reads blob data from the RAFS v6 image, mapping block ranges to blob files

## Integration with Hypervisors

### Firecracker (Protocol Compatible)

Firecracker's UFFD handler uses a bare JSON array format to send VMA region information, which the nydusd UFFD service accepts natively. A pull request is being prepared to add UFFD block device support to Firecracker.

### Cloud Hypervisor (Planned Support)

Support for Cloud Hypervisor via `--pmem` with UFFD backend is planned for future development. The expected usage pattern is:

```bash
cloud-hypervisor \
  --pmem file=/tmp/uffd.sock,size=8G,backend_type=uffd \
  --kernel /path/to/vmlinux \
  ...
```

## Example Client

The following is a minimal Rust client pseudocode demonstrating how to connect to the UFFD service:

```rust
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use sendfd::SendWithFd;

// 1. Create userfaultfd
let uffd_fd = unsafe { libc::userfaultfd(libc::O_CLOEXEC | libc::O_NONBLOCK) };

// 2. UFFD_API handshake (ioctl UFFDIO_API)
// ... set up api struct and call ioctl ...

// 3. mmap a contiguous region for the block device (anonymous, no backing file)
let block_base = unsafe {
    libc::mmap(
        std::ptr::null_mut(),  // Let kernel choose address
        block_size,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    )
};

// 4. Register the region with userfaultfd (UFFDIO_REGISTER)
// ... set up uffdio_register struct and call ioctl ...

// 5. Connect to UFFD service
let mut stream = UnixStream::connect("/tmp/uffd.sock")?;

// 6. Send handshake request (with uffd fd)
let handshake = serde_json::json!({
    "type": 0,
    "regions": [{
        "base_host_virt_addr": block_base as u64,
        "size": block_size,
        "offset": 0,
        "page_size": 4096,
    }],
    "policy": 0,  // Zerocopy
    "enable_prefault": false,
});
let mut buf = serde_json::to_vec(&handshake)?;
stream.send_with_fd(&mut buf, &[OwnedFd::from_raw_fd(uffd_fd)])?;

// 7. Listen for and handle page fault events
loop {
    let mut len_buf = [0u8; 4];
    stream.recv_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;

    let mut msg_buf = vec![0u8; len];
    let mut fds = Vec::new();
    stream.recv_with_fd(&mut msg_buf, &mut fds)?;

    let response: PageFaultResponse = serde_json::from_slice(&msg_buf)?;

    // Zerocopy mode: mmap blob fd to faulting address
    for (range, blob_fd) in response.ranges.iter().zip(fds.iter()) {
        // Calculate the faulting address:
        // fault_addr = block_base + (block_offset - client_region_offset)
        // where client_region_offset is typically 0 if the region was registered with offset=0
        let fault_offset = range.block_offset - client_region_offset;
        let fault_addr = (block_base as u64).wrapping_add(fault_offset);

        unsafe {
            libc::mmap(
                fault_addr as *mut _,
                range.len,
                libc::PROT_READ,
                libc::MAP_FIXED | libc::MAP_SHARED,
                blob_fd.as_raw_fd(),
                range.blob_offset as _,
            );
        }
    }
}
```

**Note**: The `block_offset` in the response represents the absolute position within the block device. To calculate the target address for `mmap`:
1. Compute the relative offset: `fault_offset = block_offset - client_region_offset`
2. Add to the client's base address: `fault_addr = block_base + fault_offset`

For clients that register their region with `offset=0` (the common case), `fault_offset` equals `block_offset` directly.

## Build

```bash
# Build with UFFD support
cargo build --release --bin nydusd --features block-uffd

# Build with both virtiofs and UFFD support
cargo build --release --bin nydusd --features virtiofs,block-uffd
```

## Testing

### Smoke Tests

```bash
cd smoke && go test -v -run TestUffd ./tests/
```

## See Also

- [nydusd](nydusd.md) — FUSE and virtiofs daemon modes
- [nydus-image](nydus-image.md) — Building RAFS images