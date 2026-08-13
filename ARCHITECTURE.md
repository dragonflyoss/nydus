# Architecture

This document is the map for reading the code: how the workspace is layered,
and how the same domain words are kept apart across layers. It follows the
[rust-analyzer ARCHITECTURE.md](https://matklad.github.io/2021/02/06/ARCHITECTURE.md.html)
convention: read this once before your first non-trivial change.

## Workspace layout

Eight crates; dependencies only point down. The two data-plane crates never
depend on `nydus-error`, so the control-plane error type is unnameable there
— data-plane APIs return `io::Result` and the OS errno survives to the
service edges that answer the kernel.

```text
nydus            services (fuse / fanotify / nbd / ublk / uffd) + CLI + build/optimize
  │
nydus-core       image runtime: ErofsReader (reader/), path walk (entry),
  │              extents (extent), blob handles (blob), NydusCore (lib)
nydus-config     YAML storage config: schema, loading, validation
  │
nydus-storage    local data plane: decoded blob caches, prefetch, access trace
  │
nydus-backend    remote data plane: local dir / OCI registry / Dragonfly proxy
  │
nydus-format     on-disk formats: EROFS definitions (erofs/) and the nydus
                 blob container (blob/: footer, metadata, validate)

nydus-error      control-plane error contract (Error / Result / Context)
nydus-telemetry  Prometheus metrics; tracing-subscriber install behind the
                 `logging` feature (binaries only)
```

Error planes: the data plane (`nydus-backend`, `nydus-storage`, read paths)
keeps `std::io::Result` end to end; everything else uses
`nydus_error::Error`, printed at the edges with `err.report()` (Display
prints only the outermost layer). `nydus-format` is consumed by both planes
and has its own `FormatError`, converted at each plane's boundary.

## Vocabulary map

The same domain words appear at several layers **on purpose**: each crate
names what the concept *is at that layer*. Three rules keep them apart:

1. **Layer = crate, word = role.** A type never uses a bare domain noun; it
   is always domain + role (`BlobFooter`, `BlobBackend`, `BlobCache`,
   `BlobId`, `BlobDevice`). The crate tells you the layer, the role suffix
   tells you the job.
2. **Naming gradient** for one concept crossing layers: `Erofs*` / `Blob*`
   types in `nydus-format` are zero-copy views of on-disk bytes; `Raw*`
   types in `nydus-core::reader` are their minimally-parsed, lifetime-free
   forms; bare names in `nydus-core` are the owned, user-facing API; service
   crates qualify their own views by domain.
3. **One word, one meaning per crate.** When a word must mean different
   things, the modules get distinct names (see *metadata* below).

### blob

| layer | names | meaning |
|---|---|---|
| nydus-format | `BlobFooter`, `BlobMetadata*` | the nydus blob **container format** on disk (`.blob.meta` sidecar keeps its historical suffix) |
| nydus-backend | `BlobBackend` | how blob bytes are **fetched** (local dir, registry, proxy) |
| nydus-storage | `BlobCache`, `BlobCaches`, `BlobSlot`, `BlobPrefetcher` | the **decoded local caches**; `BlobSlot` is the lazy per-blob slot inside the set, keyed by device-table index |
| nydus-core | `BlobId`, `RawBlobInfo`, `BlobInfo`, `Blobs` | **runtime handles**: digest identity, parsed device-table entry, prepared entry, and the blob-table API |
| nydus (services) | `BlobDevice` (fanotify), `BlobWriter` (build), `BlobSummary` (check) | per-service views |

### dirent / entry

`ErofsDirent` (on-disk) → `RawDirEntry` (parsed, lifetime-free) →
`DirEntry` (owned, user-facing). `TraceEntry` is an unrelated family: one
access-trace record, always `Trace`-qualified.

### metadata

Four meanings, four names: `nydus_format::erofs` holds the **EROFS on-disk
definitions** (the kernel's `erofs_fs.h` counterpart);
`nydus_format::blob::metadata` is the **nydus blob metadata table**
(`BlobMetadata`, groups/chunks/digests — nydus's own format, not EROFS);
`nydus-core/src/reader/metadata.rs` is the **runtime metadata-reading** half
of `ErofsReader`; `nydus_core::entry::Metadata` is the **owned stat-like
info**, mirroring `std::fs::Metadata`.

### chunk

Two different tables share the word: `ErofsChunkIndex` / `ErofsChunkAddr`
describe **EROFS file chunking** (where file bytes live in the flattened
address space); `BlobMetadataChunk` is the **digest entry** in the nydus
blob metadata. `ChunkSpan` / `ChunkLocation` in `nydus-core::reader` are
runtime walk helpers over the former.

### slot

`ErofsDeviceSlot` is the **on-disk device-table entry**; `BlobSlot`
(nydus-storage) is the **runtime lazy cache slot** keyed by that same
device-table index.

### cache

`BlobCache` (nydus-storage) caches **decoded blob data** on disk;
`MmapCache` (nydus-core) caches **fd → shared-mapping handles** in memory
for the copy path.

## Verb vocabulary

One operation, one verb, project-wide. The table is derived from the verbs
the codebase already uses consistently; new code picks from it:

| verb | meaning | signature shape | examples |
|---|---|---|---|
| `open_*` | acquire a readable handle | takes a path/source | `open_blob`, `open_bootstrap`, `open_file` |
| `parse*` | bytes → structure, no I/O | takes `&[u8]` | `BlobFooter::parse`, `ErofsInode::parse` |
| `read_*` | obtain bytes/values through a handle | `read_into` fills a `&mut [u8]` | `read_at`, `read_dir`, `read_xattrs`, `read_into` |
| `write_*` | stream into an `io::Write` sink | takes `&mut dyn Write` | `write_to`, `write_file_data_to` |
| `save*` | persist to a filesystem path | takes `&Path` | `BlobMetadata::save`, `save_blob_metadata` |
| `set_*` | in-memory mutation (setter) | | `set_redirect_url` |
| `to_*` / `as_*` / `into_*` | conversions only (C-CONV) — never "write to" | | `to_hex`, `as_bytes`, `into_bytes` |
| `fetch_*` | retrieval over the network | | `fetch_token`, `fetch_blob_size`, `Blobs::fetch` |
| `load_*` (`load_or_fetch_*`) | read from local disk, optionally populating | | `load_or_fetch_blob_metadata` |
| `probe_*` | side-effect-free readiness/lookup, `Option`/partial result | | `probe_flat_ranges`, `probe_full_blob_source` |
| `ensure_*` | idempotent make-it-so | | `ensure_range` |
| `prepare*` | idempotent first-use setup | | `BlobCache::prepare`, `Blobs::prepare_all` |
| `for_each_*` | internal iteration with a callback | | `for_each_dir_entry`, `for_each_redirect_group` |
| `is_*` / `has_*` | predicates | returns `bool` | `is_all_ready`, `has_magic` |
| `resolve*` | name/id → concrete location | | `resolve_path`, `ExtentResolver` |
| `plan_*` | pure computation producing a plan | no I/O | `plan_prefetch_batches` |
| `record_*` / `inc_*` / `track_*` | telemetry emission | | `record_backend_read` |

## Naming checklist for new code

- Never a bare domain noun — pick domain + role — **except when the crate or
  module path already states the role**: inside `nydus-backend`, the
  implementations are `Registry` and `Local`, resolved by
  the crate (`io::Error`, `runtime::Runtime`, opendal's `services::S3`
  anti-stutter rule); a `RegistryBackend` there would repeat the crate name.
  The exception's exception: a flagship type named after the crate concept
  itself is sanctioned (`regex::Regex`, `runtime::Runtime` — hence
  `NydusCore` and the `BlobBackend` trait keep their names), and a qualifier
  suffix stays when types from sibling crates routinely meet in one scope
  (`BackendConfig` / `PrefetchConfig` inside `nydus-config`).
- On-disk view → `Erofs*`/`Blob*` in nydus-format; minimally parsed →
  `Raw*` in nydus-core::reader; owned user API → bare name.
- Mutually exclusive constructor modes → separate constructors
  (`open_blob` / `open_bootstrap`), not an `Option` parade.
- Multi-value returns → named structs (`PrefetchPlan`), not tuples.
- Free functions only for pure algorithms; recurring argument clusters
  become a type (`ExtentResolver`).
- Filesystem-native words win: `Extent` (fiemap sense), not `FdRange`.
