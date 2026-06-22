package integration

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
//	LEPTONFS_TOP_IMAGES_REGISTRY     Target registry/namespace for the converted
//	                                 lepton images (default "localhost:5000"). On
//	                                 CI this points at the GHCR namespace
//	                                 (e.g. "ghcr.io/dragonflyoss/lepton") so the
//	                                 converted images are pushed straight to GHCR
//	                                 instead of a local registry, which keeps the
//	                                 runner's root volume from filling up.
//	LEPTONFS_TOP_IMAGES_PLAIN_HTTP   Whether convert/check talk to the target
//	                                 registry over plain HTTP without TLS
//	                                 verification ("1"/"true" to enable). Defaults
//	                                 to true only for localhost registries; for a
//	                                 real registry such as GHCR it defaults to
//	                                 false so the pipeline uses HTTPS.
//	LEPTONFS_TOP_IMAGES_PLATFORM     Platform to convert/check (default
//	                                 "linux/amd64"). Multi-arch images include a
//	                                 Windows manifest whose layers cannot be
//	                                 extracted on Linux, so the suite pins to a
//	                                 single Linux platform. Set to "all" (or empty)
//	                                 to convert every platform.
//	LEPTONFS_TOP_IMAGES_CONCURRENCY  Number of images processed in parallel (default 5).
//	LEPTONFS_TOP_IMAGES_LIST         Path to the image list (default texture/top-images.txt).
//	LEPTONFS_TOP_IMAGES_WORKDIR      Base directory for the per-image convert/check
//	                                 scratch work directories. Point this at a mount
//	                                 with ample free space (e.g. /mnt on GitHub
//	                                 runners) to avoid "no space left on device".
//	                                 Defaults to the test's temp dir.
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

	// Decide whether to talk to the target registry over plain HTTP without TLS
	// verification. Local registries (localhost) are served over plain HTTP,
	// while a real registry such as GHCR speaks HTTPS, so default accordingly
	// and allow an explicit override.
	plainHTTP := registryIsLocal(registry)
	if v := os.Getenv("LEPTONFS_TOP_IMAGES_PLAIN_HTTP"); v != "" {
		b, err := strconv.ParseBool(v)
		require.NoError(t, err, "invalid LEPTONFS_TOP_IMAGES_PLAIN_HTTP %q", v)
		plainHTTP = b
	}

	// Convert defaults to converting every platform in a multi-arch image, which
	// includes the Windows manifest for images such as golang/python/openjdk.
	// Extracting a Windows layer on Linux fails because its hardlinks (e.g.
	// "Program Files" -> "Program Files (x86)") reference files in lower layers
	// that the per-layer extraction never sees. Pin to a single platform so only
	// the Linux rootfs is converted/checked. An empty value (or "all") restores
	// the convert-all behaviour.
	platform := "linux/amd64"
	if v, ok := os.LookupEnv("LEPTONFS_TOP_IMAGES_PLATFORM"); ok {
		platform = v
	}
	if platform == "all" {
		platform = ""
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

	// Base directory for the per-image scratch work directories. Convert/check
	// stage multi-gigabyte blobs and rootfs trees, so when LEPTONFS_TOP_IMAGES_WORKDIR
	// is set we place the work directories on that (larger) mount instead of the
	// default temp filesystem, which on CI runners is the small root volume.
	workBase := os.Getenv("LEPTONFS_TOP_IMAGES_WORKDIR")
	if workBase != "" {
		require.NoError(t, os.MkdirAll(workBase, 0o755))
	}

	leptonifyBin := mustLookupLeptonify(t)
	leptonBin := mustLookupExecutable(t, "lepton")

	// Cap parallelism at `concurrency` while still running each image as an
	// independent subtest so failures are reported per image.
	sem := make(chan struct{}, concurrency)
	for _, image := range images {
		image := image
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Push the converted lepton image alongside its source in the target
			// registry/namespace, suffixing the repository with "-lepton" so it
			// does not collide with the source image (e.g.
			// ghcr.io/dragonflyoss/lepton/nginx -> .../nginx-lepton).
			target := fmt.Sprintf("%s/%s-lepton", registry, imageBaseName(image))

			// Create the work directory under the (optionally larger) work base
			// and remove it as soon as this image finishes. The explicit cleanup
			// runs on success, failure, or skip — deferred functions execute even
			// when require.* or t.Skip* abort the goroutine via runtime.Goexit —
			// so scratch data never accumulates across the parallel run and fills
			// up the disk.
			workDir, err := os.MkdirTemp(workBase, "leptonify-top-images-")
			require.NoError(t, err)
			defer func() { _ = os.RemoveAll(workDir) }()

			convertArgs := []string{"convert",
				"--source", image,
				"--target", target,
				"--builder", leptonBin,
				"--work-dir", filepath.Join(workDir, "convert"),
			}
			convertArgs = append(convertArgs, platformArgs(platform)...)
			convertArgs = append(convertArgs, registryTLSArgs(plainHTTP)...)
			convert := exec.Command(leptonifyBin, convertArgs...)
			out, err := convert.CombinedOutput()
			t.Logf("[convert %s] %s\n%s", image, strings.Join(convert.Args, " "), out)
			if err != nil {
				// Some entries in the popular-image list are no longer published
				// on Docker Hub (e.g. the deprecated `java` image). Treat a pull
				// "not found" as a skip with a warning instead of a failure so a
				// missing upstream image does not break the suite.
				if isImageNotFound(out) {
					t.Skipf("WARNING: skipping %q: image not found in registry (pull 404)", image)
				}
				require.NoError(t, err, "convert %s failed", image)
			}

			checkArgs := []string{"check",
				"--source", image,
				"--target", target,
				"--builder", leptonBin,
				"--work-dir", filepath.Join(workDir, "check"),
			}
			checkArgs = append(checkArgs, platformArgs(platform)...)
			checkArgs = append(checkArgs, registryTLSArgs(plainHTTP)...)
			check := exec.Command(leptonifyBin, checkArgs...)
			runLeptonify(t, check, "check "+image)
		})
	}
}

// imageBaseName returns the last path component of an image reference so a
// fully-qualified mirror ref (e.g. "ghcr.io/dragonflyoss/lepton/nginx") maps
// to a flat repository name in the target registry.
func imageBaseName(image string) string {
	if i := strings.LastIndex(image, "/"); i >= 0 {
		return image[i+1:]
	}
	return image
}

// registryIsLocal reports whether the registry/namespace points at a local
// registry served over plain HTTP (e.g. "localhost:5000" or "127.0.0.1:5000")
// rather than a real HTTPS registry such as GHCR.
func registryIsLocal(registry string) bool {
	host := registry
	if i := strings.IndexAny(host, "/"); i >= 0 {
		host = host[:i]
	}
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// registryTLSArgs returns the leptonify flags controlling transport security.
// For a local registry it enables plain HTTP and skips TLS verification; for a
// real registry such as GHCR it returns no extra flags so HTTPS is used.
func registryTLSArgs(plainHTTP bool) []string {
	if plainHTTP {
		return []string{"--plain-http", "--insecure"}
	}
	return nil
}

// platformArgs returns the leptonify "--platform" flag pinning convert/check to
// a single platform, or no flag when platform is empty (convert every platform).
func platformArgs(platform string) []string {
	if platform == "" {
		return nil
	}
	return []string{"--platform", platform}
}

// isImageNotFound reports whether leptonify output indicates the source image
// could not be resolved (e.g. a deprecated Docker Hub image returning HTTP 404,
// or a GHCR mirror that was never created because the upstream image is gone).
func isImageNotFound(output []byte) bool {
	text := string(output)
	return strings.Contains(text, "404 Not Found") ||
		strings.Contains(text, ": not found") ||
		strings.Contains(text, "manifest unknown") ||
		strings.Contains(text, "name unknown")
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
