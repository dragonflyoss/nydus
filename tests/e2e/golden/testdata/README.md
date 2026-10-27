# Golden images

Each directory here holds the images one nydus release built, which
`TestRead` (`../read_test.go`) reads back with the nydus under test. Nothing
here is ever regenerated: a directory is written once, at its release, and
stays as long as its version is supported.

```
<version>/                    e.g. v3.0.0
  manifest.json               schema, version, builder (`nydus --version`),
                              expected trees, image list
  <layout>/                   the golden corpus, one per GA layout
    image.bootstrap
    blobs/<sha256>[.blob.meta]
  huge-<layout>/              the files past 4GiB (zstd, zstd-8m, tar-zstd)
  merged-<layout>/            the three golden layers merged
    image.bootstrap           the merged bootstrap
    blobs/<sha256>...         one blob per layer
```

`manifest.json` records every tree an image must reproduce as
`oracle.Entry` lists (`corpus`, `corpus-tar`, `huge`, `huge-tar`, `merged`,
`merged-tar`), so the reader never rebuilds a corpus and later changes to
`internal/corpus` do not invalidate committed versions. Paths in it are
relative to the version directory.

A version takes about 10 MB (3.5 MB compressed). The corpora are
`corpus.MakeGolden`, `MakeGoldenHuge` and `MakeGoldenLayers`, sized for
that: see `internal/corpus/golden.go`.

## Adding a release

At each release, with that release's `nydus` (as root, for device nodes,
foreign owners and trusted xattrs):

```sh
cd tests/e2e
mkdir -p ../../.test-tmp
go build -o ../../.test-tmp/golden-gen ./cmd/golden-gen
sudo env TMPDIR="$PWD/../../.test-tmp" ../../.test-tmp/golden-gen -nydus /path/to/release/nydus -out golden/testdata
git add golden/testdata/v3.0.0
```

The version directory is named after `nydus --version` (`-version`
overrides it); an existing one is kept unless `-force` is given. Under
sudo the result is handed back to the invoking user.

## First release and required compatibility

The committed directory currently has no historical images. CI does not
count reading this empty directory as compatibility coverage: Release downloads
the published `v3.0.0-beta.3` binary and checksum on each architecture and
generates a nonempty historical corpus with that actual released builder.
It sets `NYDUS_E2E_GOLDEN_REQUIRED=1` for every read and requires the historical
version with `NYDUS_E2E_GOLDEN_VERSIONS`. A missing baseline, failed download,
empty corpus or missing supported version fails; there is no current-builder
fallback. Future immutable release corpora can still be committed using the
instructions above. Local exploratory runs may leave the required flag unset.

`NYDUS_E2E_GOLDEN_DIR` selects another image directory and always requires
at least one version, even when the required flag is unset. Release jobs
run on PRs as well as releases and verify both shipped amd64 and arm64 tarballs.
Historical and current corpora are generated into separate clean directories.
The current binary reads both corpora through check/FUSE/Fileio/export.
The beta.3 binary additionally reads the current corpus through check/FUSE/export:
its published binary has no Fileio, so that direction has an explicit selector
rather than runtime skip logic. Both corpora are uploaded as architecture-specific
artifacts. All directions must pass before a tag can publish.
