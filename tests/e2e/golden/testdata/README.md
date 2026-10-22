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

This README-only directory is deliberate until the first supported release.
Do not fabricate historical fixtures with today's builder. PR and release
verification require a nonempty corpus (`NYDUS_E2E_GOLDEN_REQUIRED=1`),
so the currently empty historical corpus is an explicit failing check,
not compatibility coverage. Commit the actual released-builder images and
configure `E2E_GOLDEN_VERSIONS` (space-separated supported directory names,
for example `v3.0.0 v3.1.0`), forwarded as `NYDUS_E2E_GOLDEN_VERSIONS`.
Required empty sets and missing supported versions fail. Local exploratory
runs can still leave `NYDUS_E2E_GOLDEN_REQUIRED` unset.

`NYDUS_E2E_GOLDEN_DIR` selects another image directory and always requires
at least one version, even when the required flag is unset. Release jobs
run on PRs as well as releases, verify both shipped amd64 and arm64 tarballs,
generate into separate clean
directories, and **read back those exact generated images** before uploading
architecture-specific golden artifacts or publishing the release. Existing
historical fixtures are read separately; generating current images is not
a substitute for retaining supported historical versions.
