package dragonfly

//e2e:serial injects source-IP-selective faults into the shared seed client.

import (
	"net/http"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/stretchr/testify/require"
)

func TestSeedPeerErrors(t *testing.T) {
	c := newCluster(t)
	for _, tc := range []struct {
		status, times int
		fallback      bool
	}{
		{http.StatusForbidden, 0, false},
		{http.StatusTooManyRequests, 1, false},
		{http.StatusServiceUnavailable, 0, true},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			img := uniqueImage(t)
			origin := startOrigin(t, img)
			origin.Faults.Set(registry.Fault{
				Match: fromSeedPeer, Status: tc.status, Times: tc.times,
			})
			m := mountDragonfly(t, c, img, origin.URL, policyOptions)
			err := readData(t, m)
			if tc.status == http.StatusForbidden {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Positive(t, origin.Faults.Hits())
			metrics := m.API.Metrics(t)
			if tc.fallback {
				require.Positive(t, metrics.Sum("nydus_backend_read_total", `source="fallback"`))
			} else {
				require.Zero(t, metrics.Sum("nydus_backend_read_total", `source="fallback"`))
				if tc.status == http.StatusTooManyRequests {
					require.Positive(t, metrics.Sum("nydus_backend_read_total", `source="dragonfly"`))
				}
			}
		})
	}
}
