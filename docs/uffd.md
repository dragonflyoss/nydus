# Nydus UFFD Service and Wire Protocol

## Status

This document describes the current device-level userfaultfd (UFFD) service,
its Unix-socket wire protocol, and the responsibilities of clients that expose
a Nydus image to a guest through virtio-pmem.

The protocol version described here is version `1`. The protocol is local to a
host: it uses an `AF_UNIX` stream socket and passes file descriptors with
`SCM_RIGHTS`.

## Overview

The UFFD service supports microVMs that mount EROFS inside the guest. The
microVM process reserves an anonymous virtio-pmem mapping, registers it with
userfaultfd, and sends the userfaultfd to Nydus. Nydus resolves the flattened
image address space on demand.

```text
microVM process -- SCM_RIGHTS(userfaultfd) --> nydus uffd

guest EROFS read
      |
      v
anonymous virtio-pmem mapping
      |
      | page-fault event on the transferred userfaultfd
      +-------------------------------------------> nydus uffd
                                                          |
                                                 fetch/decode ranges
                                                          |
                                                          v
                                                   local cache files

Customized (zero-copy): nydus uffd -- FD ranges --> microVM process
                                                    |
                                             mmap(MAP_FIXED) + UFFD wake
                                                    |
                                                    v
                                             guest thread resumes

Managed (copy): nydus uffd -- UFFDIO_COPY / UFFDIO_ZEROPAGE --> guest thread resumes
```

Two fault policies are supported:

- **Customized**: Nydus returns file descriptors and byte ranges for the
  zero-copy path. The microVM maps those ranges over the anonymous
  virtio-pmem VMA and wakes the faulting thread.
- **Managed**: Nydus reads the resolved bytes and completes the fault itself
  through the copy path with `UFFDIO_COPY` or `UFFDIO_ZEROPAGE`. No range
  response is sent.

The service also supports stateless `STAT`, `FETCH`, and `PROBE` requests for a
client that monitors its own userfaultfd.

## Flattened Device Layout

Nydus presents one byte-addressed device assembled from the bootstrap, blob
cache files, and zero-filled holes:

```text
device offset 0
    |
    v
+-----------+------+--------+------+--------+------+-----+
| bootstrap | hole | blob 0 | hole | blob 1 | hole | ... |
+-----------+------+--------+------+--------+------+-----+
```

Layout rules:

- The bootstrap starts at device offset `0` and occupies its file size.
- Every non-redirect blob starts at the `mapped_offset` recorded by its EROFS
  device slot. Blob order is not used to infer offsets.
- Blob length is the decoded cache file size.
- Gaps between mapped parts are holes backed by `/dev/zero`.
- Parts must not overlap.
- The final device size is the maximum part end rounded up to the service's
  device-size alignment.
- Device offsets and request lengths are byte counts. `FETCH` ranges must be
  non-empty, aligned to the block size reported by `STAT`, and contained in
  the device.

The bootstrap and blob cache files are read-only backing files. A blob range is
fetched, decoded, and validated before its file descriptor is returned.

## Transport and Framing

The server listens on an `AF_UNIX`, `SOCK_STREAM` socket. Every frame consists
of a fixed 16-byte header followed by `len` payload bytes. All integer fields
are little-endian.

Because the transport is a stream, clients must not assume that one `sendmsg`
or `recvmsg` call corresponds to one complete frame. The header and payload
must be read to their declared lengths.

File descriptors are attached to the frame header with `SCM_RIGHTS`. They are
not included in `header.len`. A receiver owns every received descriptor and
must close it after use.

### Request header

| Offset | Size | Type | Field | Meaning |
|---:|---:|---|---|---|
| 0 | 2 | `u16` | `command` | Request command |
| 2 | 6 | `u8[6]` | `command_headers` | Command-specific fields |
| 8 | 8 | `u64` | `len` | Payload length, excluding header and FDs |

Commands that do not currently define command-specific fields send these
bytes as zero. The server ignores unused bytes so future extensions remain
backward compatible.

### Response header

| Offset | Size | Type | Field | Meaning |
|---:|---:|---|---|---|
| 0 | 2 | `u16` | `status` | `OK=1`, `ERROR=2` |
| 2 | 2 | `u16` | `reply_type` | Response payload type |
| 4 | 4 | `u8[4]` | `reply_headers` | Reply-specific fields |
| 8 | 8 | `u64` | `len` | Payload length, excluding header and FDs |

The implementation bounds accepted payload lengths. A malformed payload,
invalid FD count, or payload exceeding that bound terminates the connection.
Unknown commands are logged and ignored.

## Commands and Reply Types

| Value | Command | Connection state |
|---:|---|---|
| `0x0a` | `HANDSHAKE` | Establishes UFFD state |
| `0x0b` | `ADD_REGION` | Not implemented by this service |
| `0x0c` | `REMOVE_REGION` | Not implemented by this service |
| `0x20` | `STAT` | Stateless |
| `0x21` | `FETCH` | Stateless |
| `0x22` | `PROBE` | Stateless |

| Value | Reply type | Meaning |
|---:|---|---|
| `0` | `LEGACY` | Legacy inline or empty response |
| `1` | `FD_RANGES` | Backing file ranges |
| `0x20` | `STAT` | Device metadata |

Nydus does not currently implement dynamic add-region or remove-region
requests. A connection sends its complete region list in `HANDSHAKE`, which may
occur at most once.

## HANDSHAKE

`HANDSHAKE` registers one userfaultfd and the VMAs backed by the flattened
device.

The first FD attached with `SCM_RIGHTS` is the userfaultfd. Optional backing
FDs are accepted and closed without use, as described below.

### Command header

| Offset | Size | Type | Field | Meaning |
|---:|---:|---|---|---|
| 0 | 2 | `u16` | `version` | Must be `1` |
| 2 | 1 | `u8` | `flags` | Handshake behavior flags |
| 3 | 1 | `u8` | `uffd_modes` | Effective client UFFD registration modes |
| 4 | 2 | `u16` | `region_count` | Number of payload regions |

Handshake flags:

| Bit | Name | Meaning |
|---:|---|---|
| 0 | `MANAGED` | Nydus handles faults using the copy path; clear selects the Customized zero-copy path |
| 1 | `PREFAULT` | Send locally ready ranges during handshake |
| 2 | `ACK_REQUIRED` | Return an empty Legacy response after acceptance |
| 3 | `BACKING_FDS` | One backing FD follows the userfaultfd per region |

Other flag bits are currently ignored.

UFFD modes:

| Bit | Name | Meaning |
|---:|---|---|
| 0 | `MISSING` | Regions use UFFD missing mode |
| 1 | `WP` | Regions use UFFD write-protect mode |
| 2 | `WP_ASYNC` | UFFD write protection is asynchronous |

Nydus currently ignores `uffd_modes`, including unknown mode bits.

### Region entry

Each region is 48 bytes.

| Offset | Size | Type | Field | Meaning |
|---:|---:|---|---|---|
| 0 | 8 | `u64` | `virt_addr` | Region base in the microVM process |
| 8 | 8 | `u64` | `size` | Region length in bytes |
| 16 | 8 | `u64` | `offset` | Corresponding flattened-device offset |
| 24 | 8 | `u64` | `fault_size` | Fault resolution window |
| 32 | 4 | `i32` | `prot` | Mapping protection flags |
| 36 | 4 | `i32` | `flags` | Mapping flags |
| 40 | 8 | `u64` | `backing_offset` | Region offset in its backing FD |

Region entries start at the beginning of the payload. Payload length is:

```text
region_count * 48
```

Without `BACKING_FDS`, the request carries only the userfaultfd. With
`BACKING_FDS`, it carries the userfaultfd followed by one backing FD per region.
Nydus validates this ordering and count, retains the userfaultfd, and
immediately closes the backing FDs because its current fault paths do not use
them. `backing_offset` is parsed but otherwise ignored.

The service makes the received userfaultfd nonblocking and monitors it for
page-fault events. A duplicate handshake is rejected.

When `ACK_REQUIRED` is set, Nydus sends an empty Legacy `OK` response after
accepting the session and before sending any prefault `FD_RANGES`. Without the
flag, a successful handshake has no response. Handshake failure may close the
connection without an error response.

When Customized prefault is enabled, Nydus probes the registered regions and
sends their currently ready ranges as `FD_RANGES` responses. Prefault does not
download missing blob data. It is processed synchronously so range frames are
not written concurrently on the stream. Managed policy ignores the prefault
flag.

## FD_RANGES

`FD_RANGES` returns backing file ranges for Customized faults, prefault,
`FETCH`, and `PROBE`.

### Reply header

| Offset | Size | Type | Field | Meaning |
|---:|---:|---|---|---|
| 0 | 2 | `u16` | `flags` | Bit zero is `MORE` |
| 2 | 2 | `u16` | `fd_count` | Number of payload entries and attached FDs |

### Payload

The payload contains exactly `fd_count` consecutive 24-byte range entries.

Each range entry is:

| Offset | Size | Type | Field | Meaning |
|---:|---:|---|---|---|
| 0 | 8 | `u64` | `device_offset` | Byte offset in the flattened device |
| 8 | 8 | `u64` | `file_offset` | Byte offset in the attached file |
| 16 | 8 | `u64` | `len` | Range length in bytes |

One FD is attached for every range, in the same order as the entries. The
implementation limits the number of ranges and FDs in one frame. Larger
results are split across multiple `FD_RANGES` frames, so clients must not
assume a fixed batch size.

Bit zero of the reply-specific `flags` field is `MORE`:

- `MORE=1` means another `FD_RANGES` batch for the same logical result follows.
- `MORE=0` means the current frame is the final batch.
- A single-batch result has `MORE=0`.
- An empty result is one `FD_RANGES` response with `fd_count=0`, no FDs, and
  `MORE=0`.

These rules apply to Customized faults, handshake prefault, `FETCH`, and
`PROBE`. All batches for one result are sent contiguously and are not
interleaved with another result on the same connection.

Data ranges reference either the bootstrap or a decoded blob cache file. Hole
ranges reference `/dev/zero` with `file_offset == 0`. Adjacent ranges are
merged when they use the same FD and contiguous device/file offsets; adjacent
hole ranges may also be merged.

For a Customized fault, the client maps each range at:

```text
host_address = region.virt_addr
             + (range.device_offset - region.offset)
```

The mapping uses the attached FD, `range.file_offset`, and `range.len`. After
all ranges covering the fault window are installed, the client wakes the UFFD
range and closes the received FDs.

## STAT

`STAT` currently sends zeroed command-specific headers, an empty payload, and
no FDs. It may be sent on a connection without a handshake.

The server replies with one `STAT` response and no FDs. Its reply-specific
headers are zero and its payload is:

| Offset | Size | Type | Field | Meaning |
|---:|---:|---|---|---|
| 0 | 8 | `u64` | `size` | Flattened device size in bytes |
| 8 | 4 | `u32` | `block_size` | Required request/range alignment |
| 12 | 4 | `u32` | `flags` | Currently `0` |

## FETCH

`FETCH` asks Nydus to make one device range locally available and return its
complete FD mapping. Its command-specific headers are currently zero, it has
no connection state, and it carries no FDs.

| Offset | Size | Type | Field | Meaning |
|---:|---:|---|---|---|
| 0 | 8 | `u64` | `offset` | Block-aligned device byte offset |
| 8 | 8 | `u64` | `len` | Nonzero, block-aligned byte length |

Nydus downloads and decodes missing blob groups, then returns one or more
`FD_RANGES` frames. The returned ranges cover the complete requested
interval without gaps; holes are represented by `/dev/zero` ranges. The client
receives through the `FD_RANGES` response with `MORE=0`, then verifies that the
accumulated ranges cover `[offset, offset + len)`.

## PROBE

`PROBE` currently sends zeroed command-specific headers and an empty payload,
carries no FDs, and requires no handshake. It checks the entire flattened
device without downloading missing blob data.

The server emits one or more `FD_RANGES` frames containing:

- the bootstrap range;
- hole ranges backed by `/dev/zero`;
- blob subranges already present in the local cache.

Missing blob ranges are omitted. The `FD_RANGES` response with `MORE=0`
completes the probe. If no ranges are ready, that final response has zero
ranges and no FDs.

## Fault Handling

For each page-fault event, Nydus finds the registered region containing the
fault address. It aligns the fault offset down to the region's `fault_size`
(with a minimum of the service block size) and clips the resolution window to
the region end.

### Customized policy (zero-copy)

1. Fetch and validate every blob range in the fault window.
2. Resolve the window into bootstrap/blob/zero FD ranges.
3. Send one or more `FD_RANGES` frames.
4. The client installs fixed mappings and wakes the faulting thread.

### Managed policy (copy)

1. Fetch and validate every blob range in the fault window.
2. Read data ranges from their backing FDs.
3. Resolve data with `UFFDIO_COPY` and holes with `UFFDIO_ZEROPAGE`.
4. Return to the connection loop without sending `FD_RANGES`.

Faults are processed serially within one connection. Separate connections run
in independent Tokio tasks and may process faults concurrently. Potentially
blocking fetch and UFFD copy work runs through Tokio's blocking pool.

## Service Lifecycle

One `nydus uffd` process accepts multiple client connections. Each connection
has its own protocol reader, optional handshake state, and UFFD event loop.

Interactive and service-manager termination signals trigger graceful shutdown:

1. Stop accepting new connections.
2. Notify every connection and protocol reader.
3. Wait for in-flight connection work to finish.
4. Remove the Unix socket path.
5. Exit the Tokio runtime.

An in-progress blocking fetch or copy is allowed to finish; shutdown does not
cancel it halfway through.

## Running the Service

Build the CLI with both feature gates:

```bash
cargo build --release --features cli,uffd --bin nydus
```

Start the service:

```bash
nydus uffd \
  --bootstrap /var/lib/nydus/image/image.boot \
  --config /etc/nydus/config.yaml \
  --socket /run/nydus/uffd.sock
```

Options:

- `--bootstrap` is the EROFS bootstrap used as the primary device.
- `--config` is the regular Nydus storage configuration. It selects the blob
  backend, local cache, and prefetch settings.
- `--socket` is the Unix stream socket exposed to microVM processes.
- `--threads` optionally sets the Tokio worker count. If omitted, Tokio uses
  the host's available CPU count.
- `--log-level`, `--log-dir`, and `--log-max-files` control logging.

Example registry configuration:

```yaml
backend:
  type: registry
  config:
    host: 127.0.0.1:5000
    repo: nydus/example
    insecure: true
cache:
  type: local
  config:
    dir: /var/lib/nydus/cache
prefetch:
  enable: false
```

The UFFD feature is optional and does not affect default library or builtin
accessor builds unless explicitly enabled.

## Protocol Constraints

- The transport is local Unix stream plus `SCM_RIGHTS`; TCP is not supported.
- Wire integers are little-endian.
- Device and file offsets are byte offsets, not block numbers.
- An `FD_RANGES` response's `fd_count`, payload entry count, and attached FD
  count must match.
- The client must keep its registered VMAs and userfaultfd alive for the
  connection lifetime.
- Concurrent writers on one protocol connection are not currently supported;
  responses are serialized by the connection task.
- `FD_RANGES` batches belonging to one logical result are contiguous.
