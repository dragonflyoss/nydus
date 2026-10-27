package registry

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/stretchr/testify/require"
)

func TestBearerPrefetchRefresh(t *testing.T) {
	t.Parallel()
	image, proxy, addr := newRegistrySuite(t)
	proxy.RequireBearer("prefetch-expiring-token")
	proxy.tokenResponse(22, 0, nil, 0)
	// Delay metadata after the footer authenticated. The next prefetch GET
	// must refresh within the expiry margin even though the origin continues
	// accepting the old token.
	proxy.faults.Set(registry.Fault{Times: 1, Delay: 3 * time.Second, Match: func(r *http.Request) bool {
		return registry.IsBlobGet(r) && !strings.HasPrefix(r.Header.Get("Range"), "bytes=-")
	}})
	config := image.config("http://" + addr)
	config.Prefetch.Scope = "all"
	m := image.mount(t, config)
	waitMetricSettled(t, m.API, "nydus_backend_read_total", `type="prefetch"`)
	require.Equal(t, 1, proxy.faults.Hits())
	require.EqualValues(t, 2, proxy.tokens.Load(), "prefetch must replace its expired token")
	require.Greater(t, proxy.Challenges(), 1, "the expired token must be omitted")
	require.LessOrEqual(t, proxy.Challenges(), 16, "concurrent prefetch may challenge, but must share one refresh")
	require.Zero(t, m.backendFailures(t, "prefetch", "origin"))
	require.NoError(t, m.read(t, image, "data/size/08392705"))
	require.Zero(t, m.backendReads(t, "ondemand", "origin"))
}
