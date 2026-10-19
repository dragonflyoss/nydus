package util

import (
	"cmp"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// RunNydusify runs a nydusify subcommand to completion and returns
// its combined output.
func RunNydusify(t *testing.T, nydusifyBin, nydusBin string, args ...string) string {
	t.Helper()
	full := slices.Concat(args, []string{"--builder", nydusBin, "--source-plain-http", "--target-plain-http"})
	out, err := exec.Command(nydusifyBin, full...).CombinedOutput()
	assert.NoError(t, err, "nydusify %s failed: %s", strings.Join(args, " "), out)

	return string(out)
}

// MountNydusify runs `nydusify mount` on ref in the background, waits for the
// mountpoint and returns the cleanup that unmounts it. The apiserver socket
// is workDir/apiserver.sock.
func MountNydusify(t *testing.T, nydusifyBin, nydusBin, ref, mountpoint, workDir string, prefetch bool) func() {
	t.Helper()
	Unmount(mountpoint)
	assert.NoError(t, os.MkdirAll(mountpoint, 0o755))
	assert.NoError(t, os.MkdirAll(workDir, 0o755))

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

	return MountFuse(t, exec.Command(nydusifyBin, args...), mountpoint, "nydusify mount")
}

// ConvertImage converts the source directory to the nydus image ref,
// verifies it with `nydusify check` under workDir and returns the path of
// the bootstrap the check exported.
func ConvertImage(t *testing.T, nydusifyBin, nydusBin, source, ref, workDir string) string {
	t.Helper()
	RunNydusify(t, nydusifyBin, nydusBin, "convert", "--source", source, "--target", ref, "--target-insecure")
	RunNydusify(t, nydusifyBin, nydusBin, "check", "--target", ref, "--work-dir", workDir, "--target-insecure")

	return filepath.Join(workDir, "target", "bootstrap", "image", "image.boot")
}

// DockerBuildAndPush builds the image ref from contextDir with the given
// Dockerfile body and pushes it, removing the local copy when the test ends.
// The Dockerfile is written outside the build context so it does not end up
// in the image.
func DockerBuildAndPush(t *testing.T, contextDir, ref, dockerfile string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Dockerfile")
	assert.NoError(t, os.WriteFile(path, []byte(dockerfile), 0o644))

	out, err := exec.Command("docker", "build", "-f", path, "-t", ref, contextDir).CombinedOutput()
	if !assert.NoError(t, err, "docker build failed: %s", out) {
		return
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", ref).Run() })

	out, err = exec.Command("docker", "push", ref).CombinedOutput()
	assert.NoError(t, err, "docker push failed: %s", out)
}

// RegistryReady reports whether an OCI registry answers on host over plain
// HTTP.
func RegistryReady(host string) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + host + "/v2/")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()

	return true
}

// registryEnv names the environment variable that points the tests at a
// registry other than the local one.
const registryEnv = "NYDUS_E2E_REGISTRY"

// SkipUnlessRegistry skips the test when no registry answers at
// NYDUS_E2E_REGISTRY or localhost:5000, and returns the address of the one
// that does.
func SkipUnlessRegistry(t *testing.T) string {
	t.Helper()
	host := cmp.Or(os.Getenv(registryEnv), "localhost:5000")
	if !RegistryReady(host) {
		t.Skipf("no registry at %s (set %s or run `docker run -d -p 5000:5000 registry:2`)", host, registryEnv)
	}

	return host
}

// SkipUnlessDocker skips the test when the docker CLI or daemon is unavailable.
func SkipUnlessDocker(t *testing.T) {
	t.Helper()
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skipf("docker is not available: %v", err)
	}
}
