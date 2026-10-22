package soak

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/soakconfig"
	"github.com/stretchr/testify/require"
)

// TestRemote combines retry recovery, background prefetch, concurrent reads
// and mount churn sharing the same cache, rather than soaking local reads only.
func TestRemote(t *testing.T) {
	t.Parallel()
	settings, err := soakconfig.Parse(os.Getenv)
	require.NoError(t, err)
	img := fixture.Get(t, "zstd-4k")
	for _, a := range []mount.Adapter{mount.FUSE{}, mount.Fileio{}} {
		t.Run(a.Name(), func(t *testing.T) {
			t.Parallel()
			reg := registry.Start(t)
			reg.PushBlobs(t, "soak", img.Blobs)
			reg.Faults.Set(registry.Fault{Status: http.StatusServiceUnavailable, Times: 1})
			opts := mount.Options{
				CacheDir: filepath.Join(env.WorkDir(t), "shared-cache"),
				Config: func(c *mount.Config) {
					c.Backend = mount.RegistryBackend(mount.Registry{
						Addr: reg.URL, Repository: "soak",
						HTTP: &mount.HTTP{MaxRetries: mount.Ptr(3)},
					})
					c.Prefetch = &mount.Prefetch{Scope: "all", RetryInterval: "100ms"}
				},
			}
			leak(t, a, img, settings, opts, func(m *mount.Mounted) {
				// A wall-clock sleep alone can capture an uninitialized
				// HTTP pool under concurrent load and falsely call its
				// subsequent initialization an FD/RSS leak.
				m.Daemon.WaitFor(t, time.Minute, "prefetch completion before resource baseline", func() bool {
					metrics := m.API.Metrics(t)
					return metrics.Sum("nydus_storage_prefetch_task_total") > 0 &&
						metrics.Sum("nydus_cache_bytes", `status="uncached"`) == 0
				})
			})
			require.Positive(t, reg.Faults.Hits(), "remote retry fault must have been exercised")
			require.Greater(t, len(reg.Faults.Requests()), 1, "must recover and fetch real data")
		})
	}
}
