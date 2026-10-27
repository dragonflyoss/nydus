package registry

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadThroughOrigin(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	image, proxy, addr := newRegistrySuite(t)
	m := image.mount(t, image.config("http://"+addr))

	require.NoError(m.read(t, image, "data/content/text"))
	require.NoError(m.read(t, image, "data/size/08392705"))
	require.Positive(m.backendReads(t, "ondemand", "origin"))
	require.Zero(m.backendFailures(t, "ondemand", "origin"))
	require.Positive(proxy.BlobGets())
}
