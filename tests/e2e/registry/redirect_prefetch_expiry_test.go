package registry

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedirectPrefetchExpiry(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			image, proxy, addr := newRegistrySuite(t)
			proxy.RedirectBlobs(true)
			proxy.expireFirstCachedRedirect(status)
			config := image.config("http://" + addr)
			config.Prefetch.Scope = "all"
			m := image.mount(t, config)
			waitMetricSettled(t, m.API, "nydus_backend_read_total", `type="prefetch"`)
			require.EqualValues(t, 1, proxy.staleRedirects.Load())
			require.Equal(t, 2, proxy.Redirects(), "prefetch must evict the expired location and cache its replacement")
			require.NoError(t, m.read(t, image, "data/size/08392705"))
			require.Zero(t, m.backendReads(t, "ondemand", "origin"))
			require.Zero(t, m.backendFailures(t, "prefetch", "origin"))
			require.Equal(t, 2, proxy.Redirects())
		})
	}
}
