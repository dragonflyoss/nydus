package integration

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTopImages converts and validates the most popular Docker Hub images with
// leptonify, exercising the full convert + check pipeline against a local
// registry.
//
// Activation:
//
//	LEPTONFS_RUN_TOP_IMAGES=1   enable the test (off by default).
//
// Tuning knobs (all optional):
//
//	LEPTONFS_TOP_IMAGES_REGISTRY     Target registry (default "localhost:5000").
//	LEPTONFS_TOP_IMAGES_CONCURRENCY  Number of images processed in parallel (default 5).
//	LEPTONFS_TOP_IMAGES_LIST         Path to the image list (default texture/top-images.txt).
//
// The test requires root because `leptonify convert` preserves file ownership
// and `leptonify check` mounts the converted image through FUSE.
func TestTopImages(t *testing.T) {
	if os.Getenv("LEPTONFS_RUN_TOP_IMAGES") == "" {
		t.Skip("set LEPTONFS_RUN_TOP_IMAGES=1 to run the top-images e2e test")
	}
	if os.Getuid() != 0 {
		t.Skip("requires root (convert preserves ownership, check mounts via FUSE)")
	}

	registry := os.Getenv("LEPTONFS_TOP_IMAGES_REGISTRY")
	if registry == "" {
		registry = "localhost:5000"
	}

	concurrency := 5
	if v := os.Getenv("LEPTONFS_TOP_IMAGES_CONCURRENCY"); v != "" {
		n, err := fmt.Sscanf(v, "%d", &concurrency)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		require.Greater(t, concurrency, 0, "concurrency must be positive")
	}

	listPath := os.Getenv("LEPTONFS_TOP_IMAGES_LIST")
	if listPath == "" {
		listPath = filepath.Join("texture", "top-images.txt")
	}
	images := readImageList(t, listPath)
	require.NotEmpty(t, images, "image list %q is empty", listPath)

	leptonifyBin := mustLookupLeptonify(t)

	// Cap parallelism at `concurrency` while still running each image as an
	// independent subtest so failures are reported per image.
	sem := make(chan struct{}, concurrency)
	for _, image := range images {
		image := image
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			sem <- struct{}{}
			defer func() { <-sem }()

			target := fmt.Sprintf("%s/%s-nydus", registry, image)
			workDir := t.TempDir()

			convert := exec.Command(leptonifyBin, "convert",
				"--source", image,
				"--target", target,
				"--work-dir", filepath.Join(workDir, "convert"),
				"--plain-http", "--insecure",
			)
			runLeptonify(t, convert, "convert "+image)

			check := exec.Command(leptonifyBin, "check",
				"--source", image,
				"--target", target,
				"--work-dir", filepath.Join(workDir, "check"),
				"--plain-http", "--insecure",
			)
			runLeptonify(t, check, "check "+image)
		})
	}
}

// runLeptonify executes a leptonify command, streaming its combined output into
// the test log and failing the test on a non-zero exit.
func runLeptonify(t *testing.T, cmd *exec.Cmd, label string) {
	t.Helper()
	out, err := cmd.CombinedOutput()
	t.Logf("[%s] %s\n%s", label, strings.Join(cmd.Args, " "), out)
	require.NoError(t, err, "%s failed", label)
}

// readImageList reads a newline-delimited image list, skipping blank lines and
// "#"-prefixed comments.
func readImageList(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	var images []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		images = append(images, line)
	}
	require.NoError(t, scanner.Err())
	return images
}

// mustLookupLeptonify locates the leptonify binary on PATH or under the
// leptonify module directory, building it on demand if necessary.
func mustLookupLeptonify(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("leptonify"); err == nil {
		return p
	}

	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	moduleDir := filepath.Join(root, "leptonify")

	// Already-built binary inside the module directory.
	built := filepath.Join(moduleDir, "leptonify")
	if info, err := os.Stat(built); err == nil && !info.IsDir() {
		return built
	}

	// Build it once for the whole test run.
	buildLeptonifyOnce.Do(func() {
		cmd := exec.Command("go", "build", "-o", built, ".")
		cmd.Dir = moduleDir
		out, berr := cmd.CombinedOutput()
		buildLeptonifyErr = berr
		if berr != nil {
			buildLeptonifyErr = fmt.Errorf("build leptonify: %w\n%s", berr, out)
		}
	})
	require.NoError(t, buildLeptonifyErr)
	return built
}

var (
	buildLeptonifyOnce sync.Once
	buildLeptonifyErr  error
)
