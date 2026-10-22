//go:build manual

package topimages

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/stretchr/testify/require"
)

// config is the run's knobs; see TestTopImages.
type config struct {
	registry      string
	plainHTTP     bool
	platform      string
	concurrency   int
	retries       int
	retryInterval time.Duration
	list          string
	workBase      string
}

func loadConfig(t *testing.T) config {
	t.Helper()
	cfg := config{
		registry:      "localhost:5000",
		platform:      "linux/amd64",
		concurrency:   5,
		retries:       5,
		retryInterval: 30 * time.Second,
		list:          os.Getenv("NYDUSFS_TOP_IMAGES_LIST"),
		workBase:      os.Getenv("NYDUSFS_TOP_IMAGES_WORKDIR"),
	}
	if v := os.Getenv("NYDUSFS_TOP_IMAGES_REGISTRY"); v != "" {
		cfg.registry = v
	}
	// A local registry speaks plain HTTP, a real one such as GHCR HTTPS.
	cfg.plainHTTP = registryIsLocal(cfg.registry)
	if v := os.Getenv("NYDUSFS_TOP_IMAGES_PLAIN_HTTP"); v != "" {
		b, err := strconv.ParseBool(v)
		require.NoError(t, err, "invalid NYDUSFS_TOP_IMAGES_PLAIN_HTTP %q", v)
		cfg.plainHTTP = b
	}
	if v, ok := os.LookupEnv("NYDUSFS_TOP_IMAGES_PLATFORM"); ok {
		cfg.platform = v
	}
	if cfg.platform == "all" {
		cfg.platform = ""
	}
	if v := os.Getenv("NYDUSFS_TOP_IMAGES_CONCURRENCY"); v != "" {
		n, err := strconv.Atoi(v)
		require.NoError(t, err, "invalid NYDUSFS_TOP_IMAGES_CONCURRENCY %q", v)
		require.Greater(t, n, 0, "concurrency must be positive")
		cfg.concurrency = n
	}
	// ghcr.io intermittently answers 5xx or rate-limits under load.
	if v := os.Getenv("NYDUSFS_TOP_IMAGES_RETRIES"); v != "" {
		n, err := strconv.Atoi(v)
		require.NoError(t, err, "invalid NYDUSFS_TOP_IMAGES_RETRIES %q", v)
		require.GreaterOrEqual(t, n, 0, "retries must be non-negative")
		cfg.retries = n
	}
	if v := os.Getenv("NYDUSFS_TOP_IMAGES_RETRY_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		require.NoError(t, err, "invalid NYDUSFS_TOP_IMAGES_RETRY_INTERVAL %q", v)
		require.Greater(t, d, time.Duration(0), "retry interval must be positive")
		cfg.retryInterval = d
	}
	if cfg.list == "" {
		root, err := env.RepoRoot()
		require.NoError(t, err)
		cfg.list = filepath.Join(root, "tests", "e2e", "internal", "corpus", "top-images.txt")
	}
	if cfg.workBase != "" {
		require.NoError(t, os.MkdirAll(cfg.workBase, 0o755))
	}
	return cfg
}

// readImageList reads a newline-delimited image list, skipping blank lines
// and "#" comments.
func readImageList(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	var images []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" && !strings.HasPrefix(line, "#") {
			images = append(images, line)
		}
	}
	require.NoError(t, scanner.Err())
	return images
}

// imageBaseName returns the last path component of an image reference, so a
// mirror such as ghcr.io/dragonflyoss/nydus/nginx maps to a flat repository.
func imageBaseName(image string) string {
	if i := strings.LastIndex(image, "/"); i >= 0 {
		return image[i+1:]
	}
	return image
}

// registryIsLocal reports whether registry (a host with an optional
// namespace) is a local one, served over plain HTTP.
func registryIsLocal(registry string) bool {
	host, _, _ := strings.Cut(registry, "/")
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// isImageNotFound reports whether nydusify failed because the source image
// does not exist (a deprecated Docker Hub image, or a mirror never created).
func isImageNotFound(output []byte) bool {
	text := string(output)
	for _, marker := range []string{"404 Not Found", ": not found", "manifest unknown", "name unknown"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

// isTransientRegistryError reports whether nydusify failed on a flaky
// registry (5xx, rate limiting, a dropped connection), which is worth a
// retry.
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

// runWithRetry runs the command build returns, logging its output, and
// reruns it after a transient registry failure, waiting longer each time. A
// genuine failure, or a missing source image, returns at once. It returns the
// output and error of the last attempt.
func runWithRetry(t *testing.T, label string, cfg config, build func() *exec.Cmd) ([]byte, error) {
	t.Helper()
	attempts := cfg.retries + 1
	var out []byte
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		cmd := build()
		out, err = cmd.CombinedOutput()
		t.Logf("[%s] attempt %d/%d: %s\n%s", label, attempt, attempts, strings.Join(cmd.Args, " "), out)
		if err == nil || isImageNotFound(out) || attempt == attempts || !isTransientRegistryError(out) {
			return out, err
		}
		wait := cfg.retryInterval * time.Duration(attempt)
		t.Logf("[%s] transient registry failure, retrying in %s (attempt %d/%d)", label, wait, attempt+1, attempts)
		time.Sleep(wait)
	}
	return out, err
}
