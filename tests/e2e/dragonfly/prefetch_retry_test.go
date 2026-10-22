package dragonfly

//e2e:serial shares the Dragonfly cluster with outage tests.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/stretchr/testify/require"
)

func TestPrefetchRetry(t *testing.T) {
	c := newCluster(t)
	for _, status := range []int{http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			img := uniqueImage(t)
			origin := startOrigin(t, img)
			origin.Faults.Set(registry.Fault{Status: status})
			o := policyOptions
			o.Prefetch = &mount.Prefetch{Scope: "all", RetryInterval: "1s"}
			m := mountDragonfly(t, c, img, origin.URL, o)
			require.Eventually(t, func() bool {
				return origin.Faults.Hits() > 0 && strings.Contains(m.Daemon.FileLog(), "dragonfly request failed, retrying in")
			}, policyBound, 100*time.Millisecond, "prefetch must retry the transient Dragonfly response")
			require.LessOrEqual(t, origin.Faults.Hits(), 64, "faulted prefetch must have a bounded request rate")
			origin.Faults.Clear()
			waitPrefetch(t, m)
			before := m.API.Metrics(t).Sum("nydus_backend_read_total", `type="ondemand"`)
			within(t, m, imageBound, "reading prefetched data", func() {
				require.NoError(t, readData(t, m))
			})
			require.Equal(t, before, m.API.Metrics(t).Sum("nydus_backend_read_total", `type="ondemand"`), "prefetch must warm all data")
			require.Zero(t, before)
			assertNoDirectOrigin(t, m)
		})
	}
}

func assertNoDirectOrigin(t *testing.T, m *mount.Mounted) {
	t.Helper()
	metrics := m.API.Metrics(t)
	require.Zero(t, metrics.Sum("nydus_backend_read_total", `source="fallback"`))
	require.Zero(t, metrics.Sum("nydus_backend_read_total", `source="origin"`))
	require.NotContains(t, m.Daemon.FileLog(), "falling back to the origin")
}

func waitPrefetch(t *testing.T, m *mount.Mounted) {
	t.Helper()
	require.Eventually(t, func() bool {
		metrics := m.API.Metrics(t)
		finished := metrics.Sum("nydus_storage_prefetch_task_total") -
			metrics.Sum("nydus_storage_prefetch_task_failure_total")
		return finished >= float64(len(m.Image.Blobs)) &&
			metrics.Sum("nydus_backend_read_total", `type="prefetch"`, `source="dragonfly"`) > 0 &&
			metrics.Sum("nydus_cache_bytes", `status="cached"`) > 0 &&
			metrics.Sum("nydus_cache_bytes", `status="uncached"`) == 0
	}, recoveryBound+imageBound, 300*time.Millisecond, "all blobs must finish prefetching successfully")
	assertNoDirectOrigin(t, m)
}
