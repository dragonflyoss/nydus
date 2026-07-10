package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// nydusTestRegistryEnv overrides the registry endpoint used by the optimize
// e2e test. Defaults to localhost:5000 (e.g. a `docker run registry:2`).
const nydusTestRegistryEnv = "NYDUS_TEST_REGISTRY"

func testRegistryEndpoint() string {
	if endpoint := os.Getenv(nydusTestRegistryEnv); endpoint != "" {
		return endpoint
	}
	return "localhost:5000"
}

// requireTestRegistry skips the test when no registry responds on the
// configured endpoint.
func requireTestRegistry(t *testing.T) string {
	t.Helper()
	endpoint := testRegistryEndpoint()
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + endpoint + "/v2/")
	if err != nil {
		t.Skipf("no registry at %s (set %s or run `docker run -d -p 5000:5000 registry:2`): %v",
			endpoint, nydusTestRegistryEnv, err)
	}
	_ = resp.Body.Close()
	return endpoint
}

// requireDocker skips the test when the docker CLI or daemon is unavailable.
func requireDocker(t *testing.T) {
	t.Helper()
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skipf("docker is not available: %v", err)
	}
}

// dockerBuildAndPush builds a single-layer image from contextDir (FROM scratch,
// COPY . /data) and pushes it to ref. The Dockerfile is kept outside the build
// context so it does not end up in the image.
func dockerBuildAndPush(t *testing.T, contextDir, ref string) {
	t.Helper()

	dockerfile := filepath.Join(t.TempDir(), "Dockerfile")
	require.NoError(t, os.WriteFile(dockerfile, []byte("FROM scratch\nCOPY . /data\n"), 0644))

	out, err := exec.Command("docker", "build", "-f", dockerfile, "-t", ref, contextDir).CombinedOutput()
	require.NoError(t, err, "docker build failed: %s", string(out))
	out, err = exec.Command("docker", "push", ref).CombinedOutput()
	require.NoError(t, err, "docker push failed: %s", string(out))
}

// runNydusifyCommand runs a nydusify subcommand to completion and returns
// its combined output.
func runNydusifyCommand(t *testing.T, nydusifyBin, nydusBin string, args ...string) string {
	t.Helper()
	full := append(args, "--builder", nydusBin, "--source-plain-http", "--target-plain-http")
	cmd := exec.Command(nydusifyBin, full...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "nydusify %s failed: %s", strings.Join(args, " "), string(out))
	return string(out)
}

// startNydusifyMount runs `nydusify mount` in the background, waits for the
// mountpoint, and returns a cleanup function. The apiserver socket is exposed
// at workDir/apiserver.sock.
func startNydusifyMount(
	t *testing.T,
	nydusifyBin, nydusBin, ref, mountpoint, workDir string,
	prefetch bool,
) (cleanup func()) {
	t.Helper()
	_ = exec.Command("fusermount", "-u", mountpoint).Run()
	require.NoError(t, os.MkdirAll(mountpoint, 0755))
	require.NoError(t, os.MkdirAll(workDir, 0755))

	args := []string{
		"mount",
		"--target", ref,
		"--mountpoint", mountpoint,
		"--work-dir", workDir,
		"--builder", nydusBin,
		"--target-plain-http",
	}
	if prefetch {
		args = append(args, "--prefetch")
	}
	cmd := exec.Command(nydusifyBin, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())

	require.Eventually(t, func() bool {
		return isMountpoint(mountpoint)
	}, 30*time.Second, 200*time.Millisecond, "nydusify mount failed to mount within 30s")

	return func() {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			done := make(chan struct{})
			go func() { _ = cmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				_ = exec.Command("fusermount", "-u", mountpoint).Run()
				_ = cmd.Process.Kill()
				<-done
			}
		}
	}
}

// fetchMetrics GETs the Prometheus exposition from the mount's apiserver Unix
// socket and parses it into a name -> value map (histogram series are skipped).
func fetchMetrics(t *testing.T, socketPath string) map[string]float64 {
	t.Helper()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("http://localhost/metrics")
	require.NoError(t, err, "fetch /metrics from %s", socketPath)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	metrics := make(map[string]float64)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}
		metrics[fields[0]] = value
	}
	require.NoError(t, scanner.Err())
	return metrics
}

// metricValue returns the metric's value, or 0 when absent.
func metricValue(metrics map[string]float64, name string) float64 {
	return metrics[name]
}

// waitPrefetchQuiesce polls the prefetch read counter until it is non-zero and
// stable across three consecutive samples, i.e. background prefetch has
// finished issuing backend reads.
func waitPrefetchQuiesce(t *testing.T, socketPath string) {
	t.Helper()

	var last float64
	stable := 0
	require.Eventually(t, func() bool {
		current := metricValue(fetchMetrics(t, socketPath), "backend_prefetch_read_count")
		if current > 0 && current == last {
			stable++
		} else {
			stable = 0
		}
		last = current
		return stable >= 3
	}, 60*time.Second, 300*time.Millisecond, "prefetch did not quiesce within 60s")
}

// fetchTraceCount GETs the /trace endpoint from the mount's apiserver socket
// and returns the number of recorded (blob, group) access patterns.
func fetchTraceCount(t *testing.T, socketPath string) int {
	t.Helper()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("http://localhost/trace")
	require.NoError(t, err, "fetch /trace from %s", socketPath)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var trace struct {
		Patterns []struct {
			BlobIndex  uint32 `json:"blob_index"`
			GroupIndex uint32 `json:"group_index"`
		} `json:"patterns"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&trace))
	return len(trace.Patterns)
}

// readFilesInOrder reads the given files (relative to root) sequentially,
// failing the test on any error, and returns the total bytes read.
func readFilesInOrder(t *testing.T, root string, files ...string) int {
	t.Helper()
	total := 0
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(root, file))
		require.NoError(t, err, "read %s", file)
		total += len(data)
	}
	return total
}

// optimizedRef derives the optimized image reference from ref by appending
// "-optimized" to its tag.
func optimizedRef(ref string) string {
	return ref + "-optimized"
}

// uniqueImageTag builds a per-run image tag so repeated test runs do not
// collide in the registry.
func uniqueImageTag(endpoint, repo string) string {
	return fmt.Sprintf("%s/%s:%d", endpoint, repo, time.Now().UnixNano())
}
