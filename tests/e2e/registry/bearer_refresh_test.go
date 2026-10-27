package registry

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBearerRefresh(t *testing.T) {
	t.Parallel()
	image, proxy, addr := newRegistrySuite(t)
	proxy.RequireBearer("expiring-token")
	// The backend's 20s safety margin expires this token after two seconds.
	proxy.tokenResponse(22, 0, nil, 0)
	m := image.mount(t, image.config("http://"+addr))
	readWindows(t, m, image, 0)
	require.EqualValues(t, 1, proxy.tokens.Load())
	challenges := proxy.Challenges()

	// Keep accepting the old value: a refresh cannot be caused by revocation.
	// Delay the new token so all cold reads contend for the same handshake.
	proxy.tokenResponse(300, 0, nil, 200*time.Millisecond)
	time.Sleep(3 * time.Second)
	readWindows(t, m, image, 1<<20, 2<<20, 3<<20, 4<<20, 5<<20, 6<<20)
	require.EqualValues(t, 2, proxy.tokens.Load(), "concurrent expiry must fetch just one replacement")
	require.Greater(t, proxy.Challenges()-challenges, 1, "multiple cold readers must contend for refresh without sending expired credentials")
	require.LessOrEqual(t, proxy.Challenges()-challenges, 12, "refresh handshake must be bounded")
	require.Zero(t, m.backendFailures(t, "ondemand", "origin"))
}
