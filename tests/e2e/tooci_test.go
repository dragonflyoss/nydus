package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/corpus"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

// toOCILayers are the build-context subdirectories turned into one OCI layer
// each, so the reverse conversion is exercised across several layers.
var toOCILayers = []string{"layer1", "layer2", "layer3"}

// TestNydusifyToOCIE2E exercises the round trip OCI -> nydus -> OCI against a
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
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	skipUnlessDocker(t)
	registry := skipUnlessTestRegistry(t)

	nydusBin := mustLookupExecutable(t, "nydus")
	nydusifyBin := mustLookupExecutable(t, "nydusify")

	tmpDir := t.TempDir()
	contextDir := filepath.Join(tmpDir, "context")
	makeToOCICorpus(t, contextDir)

	srcRef := uniqueImageRef(registry, "nydus-e2e/tooci-src")
	nydusRef := srcRef + "-nydus"

	t.Log("Building and pushing the multi-layer source OCI image...")
	dockerBuildAndPushLayers(t, contextDir, srcRef, toOCILayers)

	t.Log("Converting OCI to nydus...")
	runNydusifyCommand(t, nydusifyBin, nydusBin, "convert",
		"--source", srcRef, "--target", nydusRef,
		"--work-dir", filepath.Join(tmpDir, "convert"))

	t.Log("Checking the nydus image against its OCI source...")
	runNydusifyCommand(t, nydusifyBin, nydusBin, "check",
		"--source", srcRef, "--target", nydusRef,
		"--work-dir", filepath.Join(tmpDir, "check-nydus"))

	for _, compressor := range []string{"oci-gzip", "oci-zstd", "oci-tar"} {
		t.Run(compressor, func(t *testing.T) {
			ociRef := fmt.Sprintf("%s-%s", srcRef, compressor)

			t.Logf("Converting nydus back to OCI (%s)...", compressor)
			runNydusifyCommand(t, nydusifyBin, nydusBin, "convert",
				"--compressor", compressor,
				"--source", nydusRef, "--target", ociRef,
				"--work-dir", filepath.Join(tmpDir, "tooci-"+compressor))

			t.Log("Checking the rebuilt OCI image against the nydus image...")
			checkDir := filepath.Join(tmpDir, "check-oci-"+compressor)
			runNydusifyCommand(t, nydusifyBin, nydusBin, "check",
				"--source", nydusRef, "--target", ociRef,
				"--work-dir", checkDir)

			verifyPlainOCIImage(t, nydusifyBin, nydusBin, ociRef,
				filepath.Join(tmpDir, "export-"+compressor), expectedLayerMediaType(compressor))
		})
	}
}

// verifyPlainOCIImage exports the image metadata through `nydusify check` and
// asserts nothing nydus-specific survived the reverse conversion.
func verifyPlainOCIImage(t *testing.T, nydusifyBin, nydusBin, ref, workDir, mediaType string) {
	t.Helper()

	runNydusifyCommand(t, nydusifyBin, nydusBin, "check", "--target", ref, "--work-dir", workDir)

	raw, err := os.ReadFile(filepath.Join(workDir, "target", "manifest.json"))
	require.NoError(t, err)
	var manifest ocispec.Manifest
	require.NoError(t, json.Unmarshal(raw, &manifest))

	require.Len(t, manifest.Layers, len(toOCILayers),
		"the rebuilt image must have one layer per source layer and no bootstrap layer")
	for _, layer := range manifest.Layers {
		require.Equal(t, mediaType, layer.MediaType)
		for name := range layer.Annotations {
			require.NotContains(t, name, "nydus", "layer %s still carries %q", layer.Digest, name)
		}
	}

	rawConfig, err := os.ReadFile(filepath.Join(workDir, "target", "config.json"))
	require.NoError(t, err)
	var config ocispec.Image
	require.NoError(t, json.Unmarshal(rawConfig, &config))
	require.Len(t, config.RootFS.DiffIDs, len(toOCILayers))
	for _, entry := range config.History {
		require.NotContains(t, entry.Comment, "Nydus")
	}
}

func expectedLayerMediaType(compressor string) string {
	switch compressor {
	case "oci-zstd":
		return ocispec.MediaTypeImageLayerZstd
	case "oci-tar":
		return ocispec.MediaTypeImageLayer
	default:
		return ocispec.MediaTypeImageLayerGzip
	}
}

// makeToOCICorpus fills contextDir with one subdirectory per OCI layer. The
// content is restricted to what a docker build context carries faithfully:
// device nodes, sockets and xattrs are covered by the unit-level round trip
// instead.
func makeToOCICorpus(t *testing.T, contextDir string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(contextDir, 0755))

	base := corpus.NewCorpus(t, filepath.Join(contextDir, "layer1"))
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
	base.CreateFile(t, "perms/r_only", []byte("readable"))
	base.Chmod(t, "perms/r_only", 0444)
	base.CreateFile(t, "perms/setuid", []byte("setuid"))
	base.Chmod(t, "perms/setuid", 04755)
	base.CreateFile(t, "perms/setgid", []byte("setgid"))
	base.Chmod(t, "perms/setgid", 02755)
	base.CreateFile(t, "perms/sticky", []byte("sticky"))
	base.Chmod(t, "perms/sticky", 01755)

	links := corpus.NewCorpus(t, filepath.Join(contextDir, "layer2"))
	links.CreateFile(t, "symlinks/target_file", []byte("target"))
	links.CreateSymlink(t, "symlinks/link_to_file", "target_file")
	links.CreateSymlink(t, "symlinks/relative_link", "../files/tiny")
	links.CreateSymlink(t, "symlinks/dangling", "nonexistent_target")
	longName := corpus.LongName('x', 200)
	links.CreateFile(t, "symlinks/"+longName, []byte("long"))
	links.CreateSymlink(t, "symlinks/link_to_long_name", longName)
	// A ustar header has room for a 100-byte link target, so anything past
	// that has to be encoded as a GNU long link. Symlink targets run to
	// PATH_MAX, so straddle the boundary and go well beyond it.
	for _, n := range []int{99, 100, 101, 255, 1024, 4095} {
		links.CreateSymlink(t, fmt.Sprintf("symlinks/long_target_%04d", n),
			corpus.LongName('t', n))
	}
	links.CreateFile(t, "hardlinks/original", []byte("shared content"))
	links.CreateHardlink(t, "hardlinks/link1", "hardlinks/original")
	links.CreateDir(t, "hardlinks/subdir")
	links.CreateHardlink(t, "hardlinks/subdir/link2", "hardlinks/original")

	top := corpus.NewCorpus(t, filepath.Join(contextDir, "layer3"))
	top.CreateFile(t, "files/overridden", []byte("from layer3"))
	top.CreateDir(t, "dirs/many_entries")
	for i := 1; i <= 200; i++ {
		top.CreateFile(t, fmt.Sprintf("dirs/many_entries/file_%04d", i), fmt.Appendf(nil, "entry_%d", i))
	}
}

// dockerBuildAndPushLayers builds a `FROM scratch` image with one COPY — and
// therefore one layer — per entry in layers, and pushes it to ref.
func dockerBuildAndPushLayers(t *testing.T, contextDir, ref string, layers []string) {
	t.Helper()

	var body strings.Builder
	body.WriteString("FROM scratch\n")
	for _, layer := range layers {
		fmt.Fprintf(&body, "COPY %s /\n", layer)
	}
	dockerfile := filepath.Join(t.TempDir(), "Dockerfile")
	require.NoError(t, os.WriteFile(dockerfile, []byte(body.String()), 0644))

	out, err := exec.Command("docker", "build", "-f", dockerfile, "-t", ref, contextDir).CombinedOutput()
	require.NoError(t, err, "docker build failed: %s", string(out))
	out, err = exec.Command("docker", "push", ref).CombinedOutput()
	require.NoError(t, err, "docker push failed: %s", string(out))
}
