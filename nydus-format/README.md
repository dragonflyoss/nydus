# nydus-format

On-disk format layer for [Nydus](https://github.com/dragonflyoss/nydus)
images: blob layout (footer, blob meta), EROFS metadata structures, and the
byte-level utilities they share.

- `blob`: the blob-level layout — footer, blob metadata, feature flags.
  `BlobMetadata::from_bytes` is the one parser of a blob meta, from bytes in
  memory (`Vec<u8>`) or a sidecar the caller mapped (`memmap2::Mmap`);
  `from_path` reads a sidecar and parses it.
- `erofs`: zero-copy views of EROFS on-disk metadata (superblock, inodes,
  dirents).
- `utils`: digests, alignment and other byte-level helpers.

This crate sits below both of nydus's error planes: the data plane
(`io::Result`) and the control plane consume the same parsers here and
convert errors at their own boundaries.

## License

Apache-2.0. This crate is part of the
[Nydus](https://github.com/dragonflyoss/nydus) project.
