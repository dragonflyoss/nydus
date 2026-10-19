package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
)

// TestPrefetchScope mounts a plain image, one without an ondemand blob, under
// every prefetch scope and checks which ones pull blobs in the background:
// `all` and `auto` do, since `auto` falls back to `all` on such an image,
// while `none` and `ondemand` leave the backend to the on-demand reads.
func TestPrefetchScope(t *testing.T) {
	util.SkipUnlessRoot(t, "mounting FUSE")
	workDir := t.TempDir()
	source := filepath.Join(workDir, "source")
	blobDir := filepath.Join(workDir, "blobs")
	bootstrap := filepath.Join(workDir, "image.boot")
	corpus.MakeStandardCorpus(t, source)
	util.BuildImage(t, nydusBin, bootstrap, blobDir, source, 1<<20)

	tests := []struct {
		name       string
		scope      string
		prefetches bool
		logs       string
	}{
		{name: "none leaves the backend to on-demand reads", scope: "none", logs: "blob prefetch disabled"},
		{name: "ondemand finds no ondemand blob to pull", scope: "ondemand"},
		{name: "all pulls every blob", scope: "all", prefetches: true, logs: "prefetched "},
		{name: "auto pulls every blob of a plain image", scope: "auto", prefetches: true, logs: "prefetch scope auto resolved to All"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			dir := t.TempDir()
			configPath := filepath.Join(dir, "nydus.yaml")
			util.WriteLocalBackendConfig(t, configPath, blobDir, filepath.Join(dir, "cache"), tc.scope)
			mountpoint := filepath.Join(dir, "mnt")
			apiserver := filepath.Join(dir, "api.sock")
			logDir := filepath.Join(dir, "logs")
			assert.NoError(os.MkdirAll(mountpoint, 0o755))
			cmd := exec.Command(nydusBin, "fuse", "--bootstrap", bootstrap, "--config", configPath, "--mountpoint", mountpoint, "--apiserver", "unix://"+apiserver, "--log-dir", logDir)
			t.Cleanup(util.MountFuse(t, cmd, mountpoint, "nydus fuse"))
			util.WaitAPIServer(t, apiserver)

			if tc.prefetches {
				assert.Positive(util.WaitMetricSettled(t, apiserver, "nydus_read_backend_total", `type="prefetch"`))
			} else {
				// An on-demand read is the only backend traffic there is.
				_, err := os.ReadFile(filepath.Join(mountpoint, "files", "large_256k"))
				assert.NoError(err)
				assert.Positive(util.SumMetric(util.FetchMetrics(t, apiserver), "nydus_read_backend_total", `type="ondemand"`))
				assert.Zero(util.SumMetric(util.FetchMetrics(t, apiserver), "nydus_read_backend_total", `type="prefetch"`))
			}

			if tc.logs != "" {
				assert.Eventually(func() bool {
					return strings.Contains(util.ReadLogs(logDir), tc.logs)
				}, 10*time.Second, 200*time.Millisecond, "the daemon never logged %q", tc.logs)
			}
		})
	}
}
