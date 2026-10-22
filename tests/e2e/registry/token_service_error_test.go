package registry

import (
	"net/http"
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

func TestTokenServiceError(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		status int
		body   *string
		delay  time.Duration
	}{
		{"unavailable", http.StatusServiceUnavailable, nil, 0},
		{"denied", http.StatusForbidden, nil, 0},
		{"malformed_json", http.StatusOK, mount.Ptr("{"), 0},
		{"empty_token", http.StatusOK, mount.Ptr(`{"token":"","expires_in":300}`), 0},
		{"timeout", http.StatusOK, nil, 500 * time.Millisecond},
	} {
		for _, scope := range []string{"none", "all"} {
			t.Run(tc.name+"/"+scope, func(t *testing.T) {
				image, proxy, addr := newRegistrySuite(t)
				proxy.RequireBearer("recovered-token")
				proxy.tokenResponse(300, tc.status, tc.body, tc.delay)
				config := image.config("http://" + addr)
				config.HTTP.MaxRetries = mount.Ptr(0)
				config.Prefetch.Scope = scope
				if tc.delay > 0 {
					config.HTTP.RequestTimeout = "100ms"
				}
				m := image.mount(t, config)
				start := time.Now()
				if scope == "all" {
					m.waitLogs(t, "failed to prefetch priority blob")
					require.Zero(t, m.backendReads(t, "ondemand", "origin"))
				} else {
					_, err := readWindow(m.Path("data/size/08392705"), 0)
					require.ErrorIs(t, err, syscall.EIO)
				}
				require.Less(t, time.Since(start), 10*time.Second)
				require.Positive(t, proxy.tokens.Load())
				require.LessOrEqual(t, proxy.tokens.Load(), int32(4), "token-service failure must not spin")
				require.Zero(t, proxy.BlobGets(), "no data request may bypass authentication")
				require.True(t, m.Daemon.Alive())
				proxy.tokenResponse(300, 0, nil, 0)
				before := proxy.tokens.Load()
				readWindows(t, m, image, 1<<20, 2<<20, 3<<20)
				require.Equal(t, before+1, proxy.tokens.Load(), "recovery must share the new token")
			})
		}
	}
}
