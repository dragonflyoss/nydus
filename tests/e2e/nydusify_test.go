package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

// sourceLayers are the build-context subdirectories turned into one OCI layer
// each, so the reverse conversion is exercised across several layers.
var sourceLayers = []string{"layer1", "layer2", "layer3"}

// TestNydusifyToOCI exercises the round trip OCI -> nydus -> OCI against a
// local registry:
//
//  1. docker build/push a multi-layer source OCI image and convert it with
//     `nydusify convert`, validating the result with `nydusify check`.
//  2. Convert the nydus image back with `nydusify convert --to-oci` for every
//     supported layer compression, and validate each result with `nydusify
//     check --source <nydus> --target <oci>`, which mounts the nydus image
//     through FUSE and diffs it against the rebuilt OCI rootfs.
//  3. Assert the rebuilt image is a plain OCI image: ordinary layer media
//     types, no bootstrap layer and no nydus annotations left behind.
func TestNydusifyToOCI(t *testing.T) {
	util.SkipUnlessRoot(t, "mounting FUSE")
	util.SkipUnlessDocker(t)
	registry := util.SkipUnlessRegistry(t)

	root := t.TempDir()
	contextDir := filepath.Join(root, "context")
	makeSourceLayers(t, contextDir)
	repository := registry + "/nydus-e2e/tooci"
	sourceRef := repository + ":source"
	nydusRef := repository + ":nydus"

	// Build a `FROM scratch` image with one COPY, and therefore one layer, per
	// entry of sourceLayers, and push it.
	t.Log("Building and pushing the multi-layer source OCI image...")
	var body strings.Builder
	body.WriteString("FROM scratch\n")
	for _, layer := range sourceLayers {
		fmt.Fprintf(&body, "COPY %s /\n", layer)
	}
	util.DockerBuildAndPush(t, contextDir, sourceRef, body.String())

	t.Log("Converting OCI to nydus...")
	util.RunNydusify(t, nydusifyBin, nydusBin, "convert",
		"--source", sourceRef, "--target", nydusRef,
		"--work-dir", filepath.Join(root, "convert"))

	t.Log("Checking the nydus image against its OCI source...")
	util.RunNydusify(t, nydusifyBin, nydusBin, "check",
		"--source", sourceRef, "--target", nydusRef,
		"--work-dir", filepath.Join(root, "check-nydus"))

	for _, tc := range []struct {
		compressor string
		mediaType  string
	}{
		{compressor: "oci-gzip", mediaType: ocispec.MediaTypeImageLayerGzip},
		{compressor: "oci-zstd", mediaType: ocispec.MediaTypeImageLayerZstd},
		{compressor: "oci-tar", mediaType: ocispec.MediaTypeImageLayer},
	} {
		t.Run(tc.compressor, func(t *testing.T) {
			assert := assert.New(t)
			ociRef := repository + ":" + tc.compressor

			t.Logf("Converting nydus back to OCI (%s)...", tc.compressor)
			util.RunNydusify(t, nydusifyBin, nydusBin, "convert",
				"--compressor", tc.compressor,
				"--source", nydusRef, "--target", ociRef,
				"--work-dir", filepath.Join(root, "tooci-"+tc.compressor))

			t.Log("Checking the rebuilt OCI image against the nydus image...")
			util.RunNydusify(t, nydusifyBin, nydusBin, "check",
				"--source", nydusRef, "--target", ociRef,
				"--work-dir", filepath.Join(root, "check-oci-"+tc.compressor))

			// Export the image metadata through `nydusify check` and assert
			// nothing nydus-specific survived the reverse conversion.
			workDir := filepath.Join(root, "export-"+tc.compressor)
			util.RunNydusify(t, nydusifyBin, nydusBin, "check", "--target", ociRef, "--work-dir", workDir)

			rawManifest, err := os.ReadFile(filepath.Join(workDir, "target", "manifest.json"))
			assert.NoError(err)
			var manifest ocispec.Manifest
			assert.NoError(json.Unmarshal(rawManifest, &manifest))
			assert.Len(manifest.Layers, len(sourceLayers), "the rebuilt image must have one layer per source layer and no bootstrap layer")
			for _, layer := range manifest.Layers {
				assert.Equal(tc.mediaType, layer.MediaType)
				for name := range layer.Annotations {
					assert.NotContains(name, "nydus", "layer %s still carries %q", layer.Digest, name)
				}
			}

			rawConfig, err := os.ReadFile(filepath.Join(workDir, "target", "config.json"))
			assert.NoError(err)
			var config ocispec.Image
			assert.NoError(json.Unmarshal(rawConfig, &config))
			assert.Len(config.RootFS.DiffIDs, len(sourceLayers))
			for _, entry := range config.History {
				assert.NotContains(entry.Comment, "Nydus")
			}
		})
	}
}

// makeSourceLayers fills contextDir with one subdirectory per OCI layer out of
// the standard corpus. Device nodes and xattrs do not survive a docker build
// context, so those subtrees stay out and are covered by the unit-level round
// trip instead.
func makeSourceLayers(t *testing.T, contextDir string) {
	t.Helper()
	base := corpus.MakeStandardCorpus(t, filepath.Join(contextDir, sourceLayers[0]))
	for _, subtree := range []string{"special", "xattrs"} {
		assert.NoError(t, os.RemoveAll(filepath.Join(base.Dir, subtree)))
	}

	// Deal the links out to the second layer, so the conversion crosses
	// layers.
	links := filepath.Join(contextDir, sourceLayers[1])
	assert.NoError(t, os.MkdirAll(links, 0o755))
	for _, subtree := range []string{"symlinks", "hardlinks"} {
		assert.NoError(t, os.Rename(filepath.Join(base.Dir, subtree), filepath.Join(links, subtree)))
	}

	// The top layer overrides a file of the base and adds symlink targets a
	// ustar header has no room for: past 100 bytes they have to be encoded
	// as a GNU long link, and they run to PATH_MAX.
	top := corpus.NewCorpus(t, filepath.Join(contextDir, sourceLayers[2]))
	top.CreateFile(t, "files/tiny_2b", []byte("from layer3"))
	for _, n := range []int{99, 100, 101, 255, 1024, 4095} {
		top.CreateSymlink(t, fmt.Sprintf("symlinks/long_target_%04d", n), corpus.LongName('t', n))
	}
}
