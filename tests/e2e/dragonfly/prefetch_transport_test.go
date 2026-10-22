package dragonfly

//e2e:serial stops the shared Dragonfly seed peer to inject transport failure.

import (
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

func TestPrefetchTransport(t *testing.T) {
	c := newCluster(t)
	img := uniqueImage(t)
	origin := startOrigin(t, img)
	// Keep the scheduler alive: this exercises requests, not SDK construction
	// with an unreachable scheduler (the separate KI-9 test).
	c.stop(t, "dfdaemon")
	m := mountDragonfly(t, c, img, origin.URL, options{
		Prefetch: &mount.Prefetch{Scope: "all", RetryInterval: "1s"},
	})
	require.Eventually(t, func() bool {
		return strings.Contains(m.Daemon.FileLog(), "failed to prefetch priority blob")
	}, policyBound, 100*time.Millisecond, "prefetch must report the unavailable seed peer")
	assertNoDirectOrigin(t, m)
	for _, request := range origin.Faults.Requests() {
		require.False(t, request.Method == "GET" && strings.Contains(request.Path, "/blobs/"),
			"prefetch must not contact origin directly while seed peer is unavailable")
	}
	require.Positive(t, m.API.Metrics(t).Sum("nydus_storage_prefetch_task_failure_total"))
	require.Zero(t, m.API.Metrics(t).Sum("nydus_backend_read_total", `type="ondemand"`))
	m.Unmount()
	c.restore(t)
	// Transport errors terminate the prefetch task; unlike transient HTTP
	// statuses, they are not retried. A new mount starts a new prefetch.
	m = mountDragonfly(t, c, img, origin.URL, options{
		Prefetch: &mount.Prefetch{Scope: "all", RetryInterval: "1s"},
	})
	waitPrefetch(t, m)
	within(t, m, imageBound, "reading prefetched data after transport recovery", func() {
		require.NoError(t, readData(t, m))
	})
	require.Zero(t, m.API.Metrics(t).Sum("nydus_backend_read_total", `type="ondemand"`))
}
