package nydusify

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

// TestToOCI converts multi-layer images OCI -> nydus -> OCI with every OCI
// layer compression. The rebuilt image passes `nydusify check` against the
// nydus one, extracts to the source tree, and is a plain OCI image: one
// layer of the requested media type per source layer, no bootstrap layer,
// and nothing nydus-specific left in annotations, diff IDs or history.
func TestToOCI(t *testing.T) {
	t.Parallel()
	env.RequireRoot(t)
	reg := registry.Start(t)
	srcs := []source{
		newSource(t, "files", makeToOCILayers(t, env.WorkDir(t))...),
		newSource(t, "whiteouts", fixture.LayerDirs(t)...),
	}
	for _, src := range srcs {
		t.Run(src.name, func(t *testing.T) {
			t.Parallel()
			srcRef := reg.Ref("tooci-"+src.name, "oci")
			nydusRef := reg.Ref("tooci-"+src.name, "nydus")
			reg.PushDirs(t, srcRef, src.dirs...)
			nydusify(t, "convert", "--source", srcRef, "--target", nydusRef)
			nydusify(t, "check", "--source", srcRef, "--target", nydusRef)

			for _, compressor := range []string{"oci-gzip", "oci-zstd", "oci-tar"} {
				t.Run(compressor, func(t *testing.T) {
					t.Parallel()
					ociRef := reg.Ref("tooci-"+src.name, compressor)
					nydusify(t, "convert", "--compressor", compressor, "--source", nydusRef, "--target", ociRef)
					nydusify(t, "check", "--source", nydusRef, "--target", ociRef)

					img := remoteImage(t, ociRef)
					manifest, err := img.Manifest()
					require.NoError(t, err)
					require.Len(t, manifest.Layers, len(src.dirs), "one layer per source layer and no bootstrap layer")
					for _, layer := range manifest.Layers {
						require.Equal(t, layerMediaType(compressor), string(layer.MediaType))
						for key := range layer.Annotations {
							require.NotContains(t, key, "nydus", "layer %s still carries %q", layer.Digest, key)
						}
					}
					config, err := img.ConfigFile()
					require.NoError(t, err)
					require.Len(t, config.RootFS.DiffIDs, len(src.dirs))
					for _, entry := range config.History {
						require.NotContains(t, entry.Comment, "Nydus")
					}

					oracle.VerifyMount(t, extractOCI(t, ociRef), src.want, src.compare())
				})
			}
		})
	}
}

func layerMediaType(compressor string) string {
	switch compressor {
	case "oci-zstd":
		return ocispec.MediaTypeImageLayerZstd
	case "oci-tar":
		return ocispec.MediaTypeImageLayer
	default:
		return ocispec.MediaTypeImageLayerGzip
	}
}

// makeToOCILayers stages three layers under dir: assorted files and
// permission bits, then symlinks (targets past the 100-byte ustar limit up
// to PATH_MAX) and hardlinks, then a wide directory and an overridden file.
func makeToOCILayers(t *testing.T, dir string) []string {
	t.Helper()
	dirs := []string{filepath.Join(dir, "layer1"), filepath.Join(dir, "layer2"), filepath.Join(dir, "layer3")}

	base := corpus.NewCorpus(t, dirs[0])
	base.CreateFile(t, "files/empty", nil)
	base.CreateFile(t, "files/tiny", []byte("hi"))
	base.CreateFile(t, "files/just_under_block", []byte(strings.Repeat("A", 4095)))
	base.CreateRandomFile(t, "files/exact_block", 4096)
	base.CreateRandomFile(t, "files/one_over_block", 4097)
	base.CreateRandomFile(t, "files/large_256k", 256*1024)
	base.CreateZeroFile(t, "files/all_zeros", 4096*4)
	base.CreateFile(t, "files/overridden", []byte("from layer1"))
	base.CreateDir(t, "dirs/empty_dir")
	base.CreateDir(t, "dirs/a/b/c/d/e/f")
	base.CreateFile(t, "dirs/a/b/c/d/e/f/deep_file", []byte("deep"))
	for name, mode := range map[string]uint32{"r_only": 0o444, "setuid": 0o4755, "setgid": 0o2755, "sticky": 0o1755} {
		base.CreateFile(t, "perms/"+name, []byte(name))
		base.Chmod(t, "perms/"+name, mode)
	}

	links := corpus.NewCorpus(t, dirs[1])
	links.CreateFile(t, "symlinks/target_file", []byte("target"))
	links.CreateSymlink(t, "symlinks/link_to_file", "target_file")
	links.CreateSymlink(t, "symlinks/relative_link", "../files/tiny")
	links.CreateSymlink(t, "symlinks/dangling", "nonexistent_target")
	longName := corpus.LongName('x', 200)
	links.CreateFile(t, "symlinks/"+longName, []byte("long"))
	links.CreateSymlink(t, "symlinks/link_to_long_name", longName)
	for _, n := range []int{99, 100, 101, 255, 1024, 4095} {
		links.CreateSymlink(t, fmt.Sprintf("symlinks/long_target_%04d", n), corpus.LongName('t', n))
	}
	links.CreateFile(t, "hardlinks/original", []byte("shared content"))
	links.CreateHardlink(t, "hardlinks/link1", "hardlinks/original")
	links.CreateDir(t, "hardlinks/subdir")
	links.CreateHardlink(t, "hardlinks/subdir/link2", "hardlinks/original")

	top := corpus.NewCorpus(t, dirs[2])
	top.CreateFile(t, "files/overridden", []byte("from layer3"))
	top.CreateDir(t, "dirs/many_entries")
	for i := 1; i <= 200; i++ {
		top.CreateFile(t, fmt.Sprintf("dirs/many_entries/file_%04d", i), fmt.Appendf(nil, "entry_%d", i))
	}
	return dirs
}
