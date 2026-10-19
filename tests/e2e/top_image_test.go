package e2e

import (
	"cmp"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
)

// TestTopImages converts and validates the most popular Docker Hub images with
// nydusify, exercising the full convert + check pipeline against a local
// registry.
//
// Activation:
//
//	NYDUS_E2E_RUN_TOP_IMAGES=1   enable the test (off by default).
//
// Tuning knobs (all optional):
//
//	NYDUS_E2E_TOP_IMAGES_REGISTRY     Target registry/namespace for the converted
//	                                 nydus images (default "localhost:5000"). On
//	                                 CI this points at the GHCR namespace
//	                                 (e.g. "ghcr.io/dragonflyoss/nydus") so the
//	                                 converted images are pushed straight to GHCR
//	                                 instead of a local registry, which keeps the
//	                                 runner's root volume from filling up.
//	NYDUS_E2E_TOP_IMAGES_PLAIN_HTTP   Whether convert/check talk to the target
//	                                 registry over plain HTTP without TLS
//	                                 verification ("1"/"true" to enable). Defaults
//	                                 to true only for localhost registries; for a
//	                                 real registry such as GHCR it defaults to
//	                                 false so the pipeline uses HTTPS.
//	NYDUS_E2E_TOP_IMAGES_PLATFORM     Platform to convert/check (default
//	                                 "linux/amd64"). Multi-arch images include a
//	                                 Windows manifest whose layers cannot be
//	                                 extracted on Linux, so the suite pins to a
//	                                 single Linux platform. Set to "all" (or empty)
//	                                 to convert every platform.
//	NYDUS_E2E_TOP_IMAGES_CONCURRENCY  Number of images processed in parallel (default 5).
//	NYDUS_E2E_TOP_IMAGES_RETRIES      Number of times convert/check are retried when
//	                                 they hit a transient registry failure such as
//	                                 ghcr.io returning HTTP 5xx or rate limiting
//	                                 (default 5). Set to 0 to disable retries.
//	NYDUS_E2E_TOP_IMAGES_RETRY_INTERVAL
//	                                 Base wait between retries; the delay grows
//	                                 linearly with each attempt to give an unstable
//	                                 registry more room to recover (default 30s).
//	NYDUS_E2E_TOP_IMAGES_LIST         Path to the image list (default corpus/top-images.txt).
//	NYDUS_E2E_TOP_IMAGES_WORKDIR      Base directory for the per-image convert/check
//	                                 scratch work directories. Point this at a mount
//	                                 with ample free space (e.g. /mnt on GitHub
//	                                 runners) to avoid "no space left on device".
//	                                 Defaults to the test's temp dir.
//
// The test requires root because `nydusify convert` preserves file ownership
// and `nydusify check` mounts the converted image through FUSE.
func TestTopImages(t *testing.T) {
	if os.Getenv("NYDUS_E2E_RUN_TOP_IMAGES") == "" {
		t.Skip("set NYDUS_E2E_RUN_TOP_IMAGES=1 to run the top-images e2e test")
	}
	util.SkipUnlessRoot(t, "convert preserves ownership, check mounts via FUSE")

	// Default to plain HTTP for a local registry only; a real registry such
	// as GHCR speaks HTTPS.
	registry := cmp.Or(os.Getenv("NYDUS_E2E_TOP_IMAGES_REGISTRY"), "localhost:5000")
	host, _, _ := strings.Cut(registry, "/")
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		host = hostname
	}
	plainHTTP := host == "localhost" || host == "127.0.0.1" || host == "::1"

	if v := os.Getenv("NYDUS_E2E_TOP_IMAGES_PLAIN_HTTP"); v != "" {
		b, err := strconv.ParseBool(v)
		if !assert.NoError(t, err, "invalid NYDUS_E2E_TOP_IMAGES_PLAIN_HTTP %q", v) {
			t.FailNow()
		}
		plainHTTP = b
	}

	// Pin a single platform: extracting a Windows layer on Linux fails because
	// its hardlinks (e.g. "Program Files" -> "Program Files (x86)") reference
	// files in lower layers that the per-layer extraction never sees.
	platform := "linux/amd64"
	if v, ok := os.LookupEnv("NYDUS_E2E_TOP_IMAGES_PLATFORM"); ok {
		platform = v
	}
	if platform == "all" {
		platform = ""
	}

	var commonArgs []string
	if platform != "" {
		commonArgs = append(commonArgs, "--platform", platform)
	}
	if plainHTTP {
		commonArgs = append(commonArgs, "--target-plain-http", "--target-insecure")
	}

	// Read the concurrency and the retry policy; a bad knob must stop the
	// test rather than run it with a value nobody asked for.
	concurrency := 5
	if v := os.Getenv("NYDUS_E2E_TOP_IMAGES_CONCURRENCY"); v != "" {
		n, err := strconv.Atoi(v)
		if !assert.NoError(t, err, "invalid NYDUS_E2E_TOP_IMAGES_CONCURRENCY %q", v) || !assert.Greater(t, n, 0, "concurrency must be positive") {
			t.FailNow()
		}
		concurrency = n
	}

	retries := 5
	if v := os.Getenv("NYDUS_E2E_TOP_IMAGES_RETRIES"); v != "" {
		n, err := strconv.Atoi(v)
		if !assert.NoError(t, err, "invalid NYDUS_E2E_TOP_IMAGES_RETRIES %q", v) || !assert.GreaterOrEqual(t, n, 0, "retries must be non-negative") {
			t.FailNow()
		}
		retries = n
	}

	retryInterval := 30 * time.Second
	if v := os.Getenv("NYDUS_E2E_TOP_IMAGES_RETRY_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if !assert.NoError(t, err, "invalid NYDUS_E2E_TOP_IMAGES_RETRY_INTERVAL %q", v) || !assert.Greater(t, d, time.Duration(0), "retry interval must be positive") {
			t.FailNow()
		}
		retryInterval = d
	}

	// Read the image list, skipping blank lines and "#" comments.
	imageListPath := cmp.Or(os.Getenv("NYDUS_E2E_TOP_IMAGES_LIST"), filepath.Join("corpus", "top-images.txt"))
	imageList, err := os.ReadFile(imageListPath)
	assert.NoError(t, err)

	var images []string
	for line := range strings.Lines(string(imageList)) {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			images = append(images, line)
		}
	}
	assert.NotEmpty(t, images, "image list %q is empty", imageListPath)

	// Convert and check stage multi-gigabyte blobs and rootfs trees, so the
	// work directories go on the (larger) mount named by the work base.
	workBase := os.Getenv("NYDUS_E2E_TOP_IMAGES_WORKDIR")
	if workBase != "" {
		assert.NoError(t, os.MkdirAll(workBase, 0o755))
	}

	// Run each image as an independent subtest so failures are reported per
	// image, at most concurrency of them at a time, and log the progress of
	// the long run as each one finishes.
	sem := make(chan struct{}, concurrency)
	total := len(images)
	var processed, succeeded atomic.Int64
	for _, image := range images {
		t.Run(image, func(t *testing.T) {
			assert := assert.New(t)
			t.Parallel()
			sem <- struct{}{}
			defer func() { <-sem }()
			defer func() {
				t.Logf("[progress] %d/%d images processed, %d succeeded", processed.Add(1), total, succeeded.Load())
			}()

			// Push the converted image beside its source in the target
			// namespace, suffixed with -nydus so it does not collide with the
			// source (e.g. ghcr.io/dragonflyoss/nydus/nginx -> .../nginx-nydus).
			// The work directory is removed as soon as the image finishes, so
			// scratch data never accumulates across the parallel run.
			target := fmt.Sprintf("%s/%s-nydus", registry, path.Base(image))
			workDir, err := os.MkdirTemp(workBase, "nydusify-top-images-")
			if !assert.NoError(err) {
				return
			}
			defer func() { _ = os.RemoveAll(workDir) }()

			// Convert, skipping an entry of the list that is no longer
			// published (e.g. the deprecated `java` image) instead of failing.
			convertArgs := []string{"convert",
				"--source", image,
				"--target", target,
				"--builder", nydusBin,
				"--work-dir", filepath.Join(workDir, "convert"),
			}
			convertArgs = append(convertArgs, commonArgs...)
			out, err := runNydusifyWithRetry(t, "convert "+image, retries, retryInterval,
				func() *exec.Cmd { return exec.Command(nydusifyBin, convertArgs...) })
			if err != nil {
				if isImageNotFound(out) {
					t.Skipf("skipping %q: image not found in registry (pull 404)", image)
				}

				assert.NoError(err, "convert %s failed", image)
			}

			// Check the converted image against the source.
			checkArgs := []string{"check",
				"--source", image,
				"--target", target,
				"--builder", nydusBin,
				"--work-dir", filepath.Join(workDir, "check"),
			}
			checkArgs = append(checkArgs, commonArgs...)
			_, err = runNydusifyWithRetry(t, "check "+image, retries, retryInterval,
				func() *exec.Cmd { return exec.Command(nydusifyBin, checkArgs...) })
			assert.NoError(err, "check %s failed", image)
			succeeded.Add(1)
		})
	}
}

// isImageNotFound reports whether nydusify output says the source image could
// not be resolved: a deprecated Docker Hub image returning HTTP 404, or a GHCR
// mirror never created because the upstream image is gone.
func isImageNotFound(output []byte) bool {
	text := string(output)
	return slices.ContainsFunc([]string{"404 Not Found", ": not found", "manifest unknown", "name unknown"}, func(marker string) bool {
		return strings.Contains(text, marker)
	})
}

// isTransientRegistryError reports whether nydusify output says a registry
// failed in a way worth retrying: ghcr.io returning HTTP 5xx, rate limiting
// or a dropped connection.
func isTransientRegistryError(output []byte) bool {
	text := string(output)
	return slices.ContainsFunc([]string{
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
	}, func(marker string) bool {
		return strings.Contains(text, marker)
	})
}

// runNydusifyWithRetry runs a nydusify command, logging its combined output,
// and retries transient registry failures up to retries times, waiting
// interval, then 2*interval and so on between attempts to give an unstable
// registry room to recover. The command is rebuilt for each attempt through
// newCmd, since an *exec.Cmd cannot be reused. It returns the output and error
// of the final attempt.
func runNydusifyWithRetry(t *testing.T, label string, retries int, interval time.Duration, newCmd func() *exec.Cmd) ([]byte, error) {
	t.Helper()
	attempts := retries + 1

	var out []byte
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		cmd := newCmd()
		out, err = cmd.CombinedOutput()
		t.Logf("[%s] attempt %d/%d: %s\n%s", label, attempt, attempts, strings.Join(cmd.Args, " "), out)
		if err == nil {
			return out, nil
		}

		// A missing image is not transient, and a genuine conversion bug
		// fails fast: only a flaky registry is worth another attempt.
		if isImageNotFound(out) || attempt == attempts || !isTransientRegistryError(out) {
			break
		}

		wait := interval * time.Duration(attempt)
		t.Logf("[%s] transient registry failure, retrying in %s (attempt %d/%d)", label, wait, attempt+1, attempts)
		time.Sleep(wait)
	}

	return out, err
}
