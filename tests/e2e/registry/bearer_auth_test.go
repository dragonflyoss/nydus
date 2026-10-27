package registry

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBearerAuth(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	image, proxy, addr := newRegistrySuite(t)
	proxy.RequireBearer("e2e-token")
	m := image.mount(t, image.config("http://"+addr))

	// The first blob GET is challenged, the token fetched from the realm
	// the challenge names, and the request sent again; the token then
	// serves every following read without another challenge.
	require.NoError(m.read(t, image, "data/size/02097153"))
	challenges := proxy.Challenges()
	require.Positive(challenges)
	require.NoError(m.read(t, image, "data/size/08392705"))
	require.Equal(challenges, proxy.Challenges())
	require.Zero(m.backendFailures(t, "ondemand", "origin"))
}
