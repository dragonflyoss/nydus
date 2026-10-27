package registry

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRetry(t *testing.T) {
	t.Parallel()
	image, proxy, addr := newRegistrySuite(t)

	tests := []struct {
		name   string
		status int
		count  int
		expect func(t *testing.T, m *registryMount, err error)
	}{
		{
			name:   "403 fails every read without a retry",
			status: http.StatusForbidden,
			count:  -1,
			expect: func(t *testing.T, m *registryMount, err error) {
				require := require.New(t)
				require.Error(err)
				require.Equal(m.failedReads(t, "403 Forbidden"), proxy.Injected())
			},
		},
		{
			name:   "503 on two GETs is outlasted by three retries",
			status: http.StatusServiceUnavailable,
			count:  2,
			expect: func(t *testing.T, m *registryMount, err error) {
				require := require.New(t)
				require.NoError(err)
				require.Equal(2, proxy.Injected())
				require.Zero(m.backendFailures(t, "ondemand", "origin"))
			},
		},
		{
			name:   "503 on every GET exhausts the three retries of every read",
			status: http.StatusServiceUnavailable,
			count:  -1,
			expect: func(t *testing.T, m *registryMount, err error) {
				require := require.New(t)
				require.Error(err)
				require.Equal(4*m.failedReads(t, "503 Service Unavailable"), proxy.Injected())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proxy.Inject(tc.status, tc.count)
			defer proxy.Inject(0, 0)

			m := image.mount(t, image.config("http://"+addr))
			tc.expect(t, m, m.read(t, image, "data/size/02097153"))
		})
	}
}
