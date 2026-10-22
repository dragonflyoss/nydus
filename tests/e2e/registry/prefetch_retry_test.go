package registry

import (
	"net/http"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

func TestPrefetchRetry(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	image, proxy, addr := newRegistrySuite(t)

	// Every blob GET fails until the prefetch has been answered once, then
	// the origin recovers; with the retry interval cut to a second, the
	// prefetch is sent once more and completes without touching the
	// on-demand path.
	proxy.Inject(http.StatusServiceUnavailable, -1)
	config := image.config("http://" + addr)
	config.HTTP.MaxRetries = mount.Ptr(0)
	config.Prefetch.RetryInterval = "1s"
	config.Prefetch.Scope = "all"
	m := image.mount(t, config)
	require.Eventually(func() bool { return proxy.Injected() > 0 }, 30*time.Second, 100*time.Millisecond, "the prefetch never reached the origin")
	proxy.Inject(0, 0)

	waitMetricSettled(t, m.API, "nydus_backend_read_total", `type="prefetch"`)
	m.waitLogs(t, "retrying in")
	require.Positive(m.backendReads(t, "prefetch", "origin"))
	require.Zero(m.backendReads(t, "ondemand", "origin"))
	require.NoError(m.read(t, image, "data/size/08392705"))
	require.Zero(m.backendReads(t, "ondemand", "origin"), "prefetch must have warmed the file")
}
