package registry

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedirect(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	image, proxy, addr := newRegistrySuite(t)
	proxy.RedirectBlobs(true)
	m := image.mount(t, image.config("http://"+addr))

	// The image holds one blob: its first GET is redirected, the location
	// cached for the blob, and every later GET of it, the second file's
	// included, goes straight to the location.
	require.NoError(m.read(t, image, "data/size/02097153"))
	require.NoError(m.read(t, image, "data/size/08392705"))
	require.Equal(1, proxy.Redirects())
	require.Greater(proxy.BlobGets(), 1)
	require.Zero(m.backendFailures(t, "ondemand", "origin"))
}
