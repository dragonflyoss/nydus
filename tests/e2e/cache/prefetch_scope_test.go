package cache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

func TestPrefetchScope(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	image := fixture.Get(t, "zstd-4k")
	for _, scope := range []string{"none", "ondemand", "all", "auto"} {
		t.Run(scope, func(t *testing.T) {
			t.Parallel()
			m := mount.Mount(t, mount.FUSE{}, image, mount.Options{Config: func(c *mount.Config) {
				c.Prefetch = &mount.Prefetch{Scope: scope}
			}})
			if scope == "all" || scope == "auto" {
				m.Daemon.WaitFor(t, 30*time.Second, "completed prefetch", func() bool {
					metrics := m.API.Metrics(t)
					return metrics.Sum("nydus_storage_prefetch_task_total") > 0 &&
						metrics.Sum("nydus_cache_bytes", `status="uncached"`) == 0
				})
				require.Positive(t, m.API.Metrics(t).Sum("nydus_backend_read_total", `type="prefetch"`))
			} else {
				_, err := os.ReadFile(filepath.Join(m.Root, "data/size/02097153"))
				require.NoError(t, err)
				require.Positive(t, m.API.Metrics(t).Sum("nydus_backend_read_total", `type="ondemand"`))
				require.Zero(t, m.API.Metrics(t).Sum("nydus_backend_read_total", `type="prefetch"`))
			}
			log := map[string]string{"none": "blob prefetch disabled", "all": "prefetched ", "auto": "prefetch scope auto resolved to All"}[scope]
			if log != "" {
				m.Daemon.WaitFor(t, 5*time.Second, log, func() bool { return strings.Contains(m.Daemon.FileLog(), log) })
			}
		})
	}
}
