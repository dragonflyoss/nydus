package registry

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedirectExpiry(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			image, proxy, addr := newRegistrySuite(t)
			proxy.RedirectBlobs(true)
			m := image.mount(t, image.config("http://"+addr))
			readWindows(t, m, image, 0)
			require.Equal(t, 1, proxy.Redirects())
			proxy.expireRedirect(status)
			readWindows(t, m, image, 2<<20)
			require.EqualValues(t, 1, proxy.staleRedirects.Load(), "stale signed URL must be tried once then evicted")
			require.Equal(t, 2, proxy.Redirects(), "registry must resolve a new signed URL")
			readWindows(t, m, image, 4<<20)
			require.Equal(t, 2, proxy.Redirects(), "replacement URL must be cached")
			require.EqualValues(t, 1, proxy.staleRedirects.Load())
			require.Zero(t, m.backendFailures(t, "ondemand", "origin"))
		})
	}
}
