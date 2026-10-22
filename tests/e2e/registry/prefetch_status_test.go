package registry

import (
	"net/http"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

func TestPrefetchStatus(t *testing.T) {
	t.Parallel()
	// 503 is covered by TestPrefetchRetry; cover the two non-5xx retry statuses.
	for _, status := range []int{http.StatusRequestTimeout, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			image, proxy, addr := newRegistrySuite(t)
			proxy.Inject(status, -1)
			config := image.config("http://" + addr)
			config.HTTP.MaxRetries = mount.Ptr(0)
			config.Prefetch.Scope = "all"
			config.Prefetch.RetryInterval = "1s"
			m := image.mount(t, config)
			m.waitLogs(t, "origin request failed, retrying in")
			require.Positive(t, proxy.Injected())
			require.LessOrEqual(t, proxy.Injected(), 4)
			proxy.Inject(0, 0)
			waitMetricSettled(t, m.API, "nydus_backend_read_total", `type="prefetch"`)
			require.Positive(t, m.backendReads(t, "prefetch", "origin"))
			require.Zero(t, m.backendReads(t, "ondemand", "origin"))
			require.NoError(t, m.read(t, image, "data/size/08392705"))
			require.Zero(t, m.backendReads(t, "ondemand", "origin"), "recovered prefetch must warm data")
		})
	}
}
