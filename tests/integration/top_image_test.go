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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestTopImages converts and validates the most popular Docker Hub images with
// nydusify, exercising the full convert + check pipeline against a local
// registry.
//
// Activation:
//
//	NYDUSFS_RUN_TOP_IMAGES=1   enable the test (off by default).
//
// Tuning knobs (all optional):
//
//	NYDUSFS_TOP_IMAGES_REGISTRY     Target registry/namespace for the converted
//	                                 nydus images (default "localhost:5000"). On
//	                                 CI this points at the GHCR namespace
//	                                 (e.g. "ghcr.io/dragonflyoss/nydus") so the
//	                                 converted images are pushed straight to GHCR
//	                                 instead of a local registry, which keeps the
//	                                 runner's root volume from filling up.
//	NYDUSFS_TOP_IMAGES_PLAIN_HTTP   Whether convert/check talk to the target
//	                                 registry over plain HTTP without TLS
//	                                 verification ("1"/"true" to enable). Defaults
//	                                 to true only for localhost registries; for a
//	                                 real registry such as GHCR it defaults to
//	                                 false so the pipeline uses HTTPS.
//	NYDUSFS_TOP_IMAGES_PLATFORM     Platform to convert/check (default
//	                                 "linux/amd64"). Multi-arch images include a
//	                                 Windows manifest whose layers cannot be
//	                                 extracted on Linux, so the suite pins to a
//	                                 single Linux platform. Set to "all" (or empty)
//	                                 to convert every platform.
//	NYDUSFS_TOP_IMAGES_CONCURRENCY  Number of images processed in parallel (default 5).
//	NYDUSFS_TOP_IMAGES_RETRIES      Number of times convert/check are retried when
//	                                 they hit a transient registry failure such as
//	                                 ghcr.io returning HTTP 5xx or rate limiting
//	                                 (default 5). Set to 0 to disable retries.
//	NYDUSFS_TOP_IMAGES_RETRY_INTERVAL
//	                                 Base wait between retries; the delay grows
//	                                 linearly with each attempt to give an unstable
//	                                 registry more room to recover (default 30s).
//	NYDUSFS_TOP_IMAGES_LIST         Path to the image list (default texture/top-images.txt).
//	NYDUSFS_TOP_IMAGES_WORKDIR      Base directory for the per-image convert/check
//	                                 scratch work directories. Point this at a mount
//	                                 with ample free space (e.g. /mnt on GitHub
//	                                 runners) to avoid "no space left on device".
//	                                 Defaults to the test's temp dir.
//
// The test requires root because `nydusify convert` preserves file ownership
// and `nydusify check` mounts the converted image through FUSE.
func TestTopImages(t *testing.T) {
	if os.Getenv("NYDUSFS_RUN_TOP_IMAGES") == "" {
		t.Skip("set NYDUSFS_RUN_TOP_IMAGES=1 to run the top-images e2e test")
	}
	if os.Getuid() != 0 {
		t.Skip("requires root (convert preserves ownership, check mounts via FUSE)")
	}

	registry := os.Getenv("NYDUSFS_TOP_IMAGES_REGISTRY")
	if registry == "" {
		registry = "localhost:5000"
	}

	// Decide whether to talk to the target registry over plain HTTP without TLS
	// verification. Local registries (localhost) are served over plain HTTP,
	// while a real registry such as GHCR speaks HTTPS, so default accordingly
	// and allow an explicit override.
	plainHTTP := registryIsLocal(registry)
	if v := os.Getenv("NYDUSFS_TOP_IMAGES_PLAIN_HTTP"); v != "" {
		b, err := strconv.ParseBool(v)
		require.NoError(t, err, "invalid NYDUSFS_TOP_IMAGES_PLAIN_HTTP %q", v)
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
	if v, ok := os.LookupEnv("NYDUSFS_TOP_IMAGES_PLATFORM"); ok {
		platform = v
	}
	if platform == "all" {
		platform = ""
	}

	concurrency := 5
	if v := os.Getenv("NYDUSFS_TOP_IMAGES_CONCURRENCY"); v != "" {
		n, err := fmt.Sscanf(v, "%d", &concurrency)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		require.Greater(t, concurrency, 0, "concurrency must be positive")
	}

	// ghcr.io intermittently returns HTTP 5xx / rate-limit responses under load,
	// which surface as convert/check failures. Retry those transient errors a few
	// times, spacing the attempts out, so a flaky registry does not fail the whole
	// suite. Both the retry count and the base interval are tunable.
	retries := 5
	if v := os.Getenv("NYDUSFS_TOP_IMAGES_RETRIES"); v != "" {
		n, err := strconv.Atoi(v)
		require.NoError(t, err, "invalid NYDUSFS_TOP_IMAGES_RETRIES %q", v)
		require.GreaterOrEqual(t, n, 0, "retries must be non-negative")
		retries = n
	}

	retryInterval := 30 * time.Second
	if v := os.Getenv("NYDUSFS_TOP_IMAGES_RETRY_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		require.NoError(t, err, "invalid NYDUSFS_TOP_IMAGES_RETRY_INTERVAL %q", v)
		require.Greater(t, d, time.Duration(0), "retry interval must be positive")
		retryInterval = d
	}

	listPath := os.Getenv("NYDUSFS_TOP_IMAGES_LIST")
	if listPath == "" {
		listPath = filepath.Join("texture", "top-images.txt")
	}
	images := readImageList(t, listPath)
	require.NotEmpty(t, images, "image list %q is empty", listPath)

	// Base directory for the per-image scratch work directories. Convert/check
	// stage multi-gigabyte blobs and rootfs trees, so when NYDUSFS_TOP_IMAGES_WORKDIR
	// is set we place the work directories on that (larger) mount instead of the
	// default temp filesystem, which on CI runners is the small root volume.
	workBase := os.Getenv("NYDUSFS_TOP_IMAGES_WORKDIR")
	if workBase != "" {
		require.NoError(t, os.MkdirAll(workBase, 0o755))
	}

	nydusifyBin := mustLookupNydusify(t)
	nydusBin := mustLookupExecutable(t, "nydus")

	// Cap parallelism at `concurrency` while still running each image as an
	// independent subtest so failures are reported per image.
	sem := make(chan struct{}, concurrency)
	// Track success/total progress across the parallel subtests so the log shows
	// how far along the (long-running) suite is.
	total := len(images)
	var processed, succeeded int64
	for _, image := range images {
		image := image
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Emit a success/total progress line once this image finishes,
			// regardless of whether it passed, failed, or was skipped. The
			// deferred call runs even when require.* or t.Skip* abort the
			// goroutine via runtime.Goexit.
			defer func() {
				done := atomic.AddInt64(&processed, 1)
				t.Logf("[progress] %d/%d images processed, %d succeeded",
					done, total, atomic.LoadInt64(&succeeded))
			}()

			// Push the converted nydus image alongside its source in the target
			// registry/namespace, suffixing the repository with "-nydus" so it
			// does not collide with the source image (e.g.
			// ghcr.io/dragonflyoss/nydus/nginx -> .../nginx-nydus).
			target := fmt.Sprintf("%s/%s-nydus", registry, imageBaseName(image))

			// Create the work directory under the (optionally larger) work base
			// and remove it as soon as this image finishes. The explicit cleanup
			// runs on success, failure, or skip — deferred functions execute even
			// when require.* or t.Skip* abort the goroutine via runtime.Goexit —
			// so scratch data never accumulates across the parallel run and fills
			// up the disk.
			workDir, err := os.MkdirTemp(workBase, "nydusify-top-images-")
			require.NoError(t, err)
			defer func() { _ = os.RemoveAll(workDir) }()

			convertArgs := []string{"convert",
				"--source", image,
				"--target", target,
				"--builder", nydusBin,
				"--work-dir", filepath.Join(workDir, "convert"),
			}
			convertArgs = append(convertArgs, platformArgs(platform)...)
			convertArgs = append(convertArgs, registryTLSArgs(plainHTTP)...)
			out, err := runNydusifyWithRetry(t, "convert "+image, retries, retryInterval,
				func() *exec.Cmd { return exec.Command(nydusifyBin, convertArgs...) })
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
				"--builder", nydusBin,
				"--work-dir", filepath.Join(workDir, "check"),
			}
			checkArgs = append(checkArgs, platformArgs(platform)...)
			checkArgs = append(checkArgs, registryTLSArgs(plainHTTP)...)
			_, err = runNydusifyWithRetry(t, "check "+image, retries, retryInterval,
				func() *exec.Cmd { return exec.Command(nydusifyBin, checkArgs...) })
			require.NoError(t, err, "check %s failed", image)

			atomic.AddInt64(&succeeded, 1)
		})
	}
}

// imageBaseName returns the last path component of an image reference so a
// fully-qualified mirror ref (e.g. "ghcr.io/dragonflyoss/nydus/nginx") maps
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

// registryTLSArgs returns the nydusify flags controlling transport security
// for the target registry (where converted images are pushed). For a local
// registry it enables plain HTTP and skips TLS verification; for a real
// registry such as GHCR it returns no extra flags so HTTPS is used. The
// source registry is always a public HTTPS registry and needs no flags.
func registryTLSArgs(plainHTTP bool) []string {
	if plainHTTP {
		return []string{"--target-plain-http", "--target-insecure"}
	}
	return nil
}

// platformArgs returns the nydusify "--platform" flag pinning convert/check to
// a single platform, or no flag when platform is empty (convert every platform).
func platformArgs(platform string) []string {
	if platform == "" {
		return nil
	}
	return []string{"--platform", platform}
}

// isImageNotFound reports whether nydusify output indicates the source image
// could not be resolved (e.g. a deprecated Docker Hub image returning HTTP 404,
// or a GHCR mirror that was never created because the upstream image is gone).
func isImageNotFound(output []byte) bool {
	text := string(output)
	return strings.Contains(text, "404 Not Found") ||
		strings.Contains(text, ": not found") ||
		strings.Contains(text, "manifest unknown") ||
		strings.Contains(text, "name unknown")
}

// runNydusifyWithRetry runs a nydusify command, streaming its combined output
// into the test log, and retries on transient registry failures (e.g. ghcr.io
// returning HTTP 5xx or rate limiting). The command is rebuilt for each attempt
// via build because an *exec.Cmd cannot be reused. The wait between attempts
// grows linearly (interval, 2*interval, ...) to give an unstable registry more
// time to recover. It returns the output and error of the final attempt.
func runNydusifyWithRetry(t *testing.T, label string, retries int, interval time.Duration, build func() *exec.Cmd) ([]byte, error) {
	t.Helper()
	attempts := retries + 1
	var out []byte
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		cmd := build()
		out, err = cmd.CombinedOutput()
		t.Logf("[%s] attempt %d/%d: %s\n%s", label, attempt, attempts, strings.Join(cmd.Args, " "), out)
		if err == nil {
			return out, nil
		}
		// A missing upstream image is not transient; let the caller turn it into
		// a skip instead of burning retries on a 404.
		if isImageNotFound(out) {
			return out, err
		}
		// Only retry failures that look like a flaky registry; a genuine
		// conversion bug fails fast.
		if attempt < attempts && isTransientRegistryError(out) {
			wait := interval * time.Duration(attempt)
			t.Logf("[%s] transient registry failure, retrying in %s (attempt %d/%d)",
				label, wait, attempt+1, attempts)
			time.Sleep(wait)
			continue
		}
		break
	}
	return out, err
}

// isTransientRegistryError reports whether nydusify output indicates a transient
// registry failure (e.g. ghcr.io returning HTTP 5xx, rate limiting, or a dropped
// connection) that is worth retrying.
func isTransientRegistryError(output []byte) bool {
	text := string(output)
	for _, marker := range []string{
		"500 Internal Server Error",
		"Internal Server Error",
		"501 Not Implemented",
		"502 Bad Gateway",
		"503 Service Unavailable",
		"504 Gateway Timeout",
		"429 Too Many Requests",
		"too many requests",
		"toomanyrequests",
		"TOOMANYREQUESTS",
		"connection reset by peer",
		"connection refused",
		"unexpected EOF",
		"i/o timeout",
		"TLS handshake timeout",
		"timeout awaiting response headers",
		"server misbehaving",
		"no such host",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
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

// mustLookupNydusify locates the nydusify binary on PATH or under the
// nydusify module directory, building it on demand if necessary.
func mustLookupNydusify(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("nydusify"); err == nil {
		return p
	}

	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	moduleDir := filepath.Join(root, "nydusify")

	// Already-built binary inside the module directory.
	built := filepath.Join(moduleDir, "nydusify")
	if info, err := os.Stat(built); err == nil && !info.IsDir() {
		return built
	}

	// Build it once for the whole test run.
	buildNydusifyOnce.Do(func() {
		cmd := exec.Command("go", "build", "-o", built, ".")
		cmd.Dir = moduleDir
		out, berr := cmd.CombinedOutput()
		buildNydusifyErr = berr
		if berr != nil {
			buildNydusifyErr = fmt.Errorf("build nydusify: %w\n%s", berr, out)
		}
	})
	require.NoError(t, buildNydusifyErr)
	return built
}

var (
	buildNydusifyOnce sync.Once
	buildNydusifyErr  error
)
