//go:build manual

package nydusify

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/stretchr/testify/assert"
)

func TestConvertPublicImages(t *testing.T) {
	t.Parallel()
	env.MustHaveRoot(t)
	cfg := loadConfig(t)
	images := readImageList(t, cfg.list)
	if !assert.NotEmpty(t, images) {
		t.FailNow()
	}

	nydusify := env.Nydusify(t)
	nydus := env.Nydus(t)

	sem := make(chan struct{}, cfg.concurrency)
	total := len(images)
	var processed, succeeded atomic.Int64

	for _, image := range images {
		t.Run(imageBaseName(image), func(t *testing.T) {
			t.Parallel()
			sem <- struct{}{}
			defer func() { <-sem }()

			defer func() {
				t.Logf("[progress] %d/%d images processed, %d succeeded",
					processed.Add(1), total, succeeded.Load())
			}()

			target := fmt.Sprintf("%s/%s-nydus", cfg.registry, imageBaseName(image))

			work := env.WorkDir(t)

			args := func(sub string) []string {
				args := []string{sub,
					"--source", image,
					"--target", target,
					"--builder", nydus,
					"--work-dir", filepath.Join(work, sub),
				}

				if cfg.platform != "" {
					args = append(args, "--platform", cfg.platform)
				}

				if cfg.plainHTTP {
					args = append(args, "--target-plain-http", "--target-insecure")
				}

				return args
			}

			out, err := cfg.runWithRetry(t, "convert "+image, func() *exec.Cmd { return exec.Command(nydusify, args("convert")...) })
			if err != nil && isImageNotFound(out) {
				env.Skipf(t, "%s is not in its registry", image)
			}

			if !assert.NoError(t, err) {
				t.FailNow()
			}

			_, err = cfg.runWithRetry(t, "check "+image, func() *exec.Cmd { return exec.Command(nydusify, args("check")...) })
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			succeeded.Add(1)
		})
	}
}

type config struct {
	registry      string
	plainHTTP     bool
	platform      string
	concurrency   int
	retries       int
	retryInterval time.Duration
	list          string
}

func loadConfig(t *testing.T) config {
	t.Helper()
	cfg := config{
		registry:      "localhost:5000",
		platform:      "linux/amd64",
		concurrency:   env.Int(t, "NYDUS_E2E_CONVERT_CONCURRENCY", 5),
		retries:       env.Int(t, "NYDUS_E2E_CONVERT_RETRIES", 5),
		retryInterval: env.Duration(t, "NYDUS_E2E_CONVERT_RETRY_INTERVAL", 30*time.Second),
		list:          filepath.Join("testdata", "images.txt"),
	}

	if v := os.Getenv("NYDUS_E2E_CONVERT_REGISTRY"); v != "" {
		cfg.registry = v
	}

	cfg.plainHTTP = env.Bool(t, "NYDUS_E2E_CONVERT_PLAIN_HTTP", isLocalRegistry(cfg.registry))

	if v, ok := os.LookupEnv("NYDUS_E2E_CONVERT_PLATFORM"); ok {
		cfg.platform = v
	}

	if cfg.platform == "all" {
		cfg.platform = ""
	}

	if v := os.Getenv("NYDUS_E2E_CONVERT_LIST"); v != "" {
		cfg.list = v
	}

	if !assert.Positive(t, cfg.concurrency) || !assert.GreaterOrEqual(t, cfg.retries, 0) || !assert.Positive(t, cfg.retryInterval) {
		t.FailNow()
	}

	return cfg
}

func readImageList(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = f.Close() }()
	var images []string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" && !strings.HasPrefix(line, "#") {
			images = append(images, line)
		}
	}

	assert.NoError(t, scanner.Err())

	return images
}

func imageBaseName(image string) string {
	if i := strings.LastIndex(image, "/"); i >= 0 {
		return image[i+1:]
	}

	return image
}

func isLocalRegistry(registry string) bool {
	host, _, _ := strings.Cut(registry, "/")
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}

	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func isImageNotFound(output []byte) bool {
	text := strings.ToLower(string(output))

	for _, marker := range []string{"404 not found", ": not found", "manifest unknown", "name unknown"} {
		if strings.Contains(text, marker) {
			return true
		}
	}

	return false
}

func isTransientRegistryError(output []byte) bool {
	text := strings.ToLower(string(output))

	for _, marker := range []string{
		"internal server error",
		"501 not implemented",
		"502 bad gateway",
		"503 service unavailable",
		"504 gateway timeout",
		"too many requests",
		"toomanyrequests",
		"connection reset by peer",
		"connection refused",
		"unexpected eof",
		"i/o timeout",
		"tls handshake timeout",
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

func (cfg config) runWithRetry(t *testing.T, label string, build func() *exec.Cmd) ([]byte, error) {
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
